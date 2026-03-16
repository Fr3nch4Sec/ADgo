// cmd/adgo/commands/acl_cmd.go
//
// Commande : adgo ldap acl
//
// Enumère les ACLs dangereuses dans le domaine (GenericAll, WriteDACL,
// WriteOwner, DCSync, ForceChangePassword...) — équivalent de ce que
// BloodHound visualise graphiquement mais en mode CLI.
//
// Exemples :
//   adgo ldap acl --dc-ip 192.168.1.10 -u admin -p pass -d LAB
//   adgo ldap acl --dc-ip 192.168.1.10 -u admin -p pass -d LAB --target john
//   adgo ldap acl --dc-ip 192.168.1.10 -u admin -p pass -d LAB --json > acls.json

package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"adgo/pkg/adattack"
	"adgo/pkg/common"
	"adgo/pkg/ldap"

	"github.com/spf13/cobra"
)

var ACLCmd = &cobra.Command{
	Use:   "acl",
	Short: "Find dangerous ACL rights (GenericAll, WriteDACL, DCSync...)",
	Long: `Enumerate dangerous ACL rights in the domain.

Detected rights:
  GenericAll          — Full control over the object
  WriteDACL           — Can modify permissions (→ GenericAll)
  WriteOwner          — Can become owner (→ WriteDACL → GenericAll)
  GenericWrite        — Can write attributes (Shadow Creds, RBCD)
  ForceChangePassword — Can reset password without knowing current one
  DCSync              — Can replicate domain secrets (DS-Replication-Get-Changes)
  AllExtendedRights   — All extended rights (includes ForceChangePassword)
  AddMember           — Can add members to the group

Examples:
  # Enumerate all dangerous ACLs in the domain
  adgo ldap acl --dc-ip 192.168.1.10 -u admin -p pass -d LAB

  # Enumerate ACLs on a specific object
  adgo ldap acl --dc-ip 192.168.1.10 -u admin -p pass -d LAB --target "john"
  adgo ldap acl --dc-ip 192.168.1.10 -u admin -p pass -d LAB --target "Domain Admins"

  # JSON output (for BloodHound or further processing)
  adgo ldap acl --dc-ip 192.168.1.10 -u admin -p pass -d LAB --json > acls.json

  # Filter by right type
  adgo ldap acl --dc-ip 192.168.1.10 -u admin -p pass -d LAB --filter GenericAll`,
	RunE: runACLEnum,
}

var (
	aclTarget    string
	aclFilterStr string
	aclJSON      bool
	aclAbuse     bool
)

func init() {
	ACLCmd.Flags().String("dc-ip", "", "Domain Controller IP (required)")
	ACLCmd.Flags().StringVar(&aclTarget, "target", "", "Enumerate ACLs on a specific object (sAMAccountName or DN)")
	ACLCmd.Flags().StringVar(&aclFilterStr, "filter", "", "Filter results by right name (e.g. GenericAll, DCSync)")
	ACLCmd.Flags().BoolVar(&aclJSON, "json", false, "Output in JSON format")
	ACLCmd.Flags().BoolVar(&aclAbuse, "show-abuse", false, "Show abuse information for each right")

	// Enregistrer dans LDAPCmd
	LDAPCmd.AddCommand(ACLCmd)
}

func runACLEnum(cmd *cobra.Command, args []string) error {
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

	common.PrintInfo(fmt.Sprintf("ACL enumeration → %s as %s\\%s", server, strings.ToUpper(creds.SMBDomain), creds.SMBUsername))

	if aclTarget == "" {
		common.PrintInfo("Mode: full domain scan (this may take a few minutes on large domains)")
	} else {
		common.PrintInfo(fmt.Sprintf("Mode: target object '%s'", aclTarget))
	}

	// Connexion LDAP
	ldapClient, err := ldap.NewClientNTLM(ctx, server, creds.SMBDomain, creds.SMBUsername, creds.Password, creds.NTLMHash, false)
	if err != nil {
		return fmt.Errorf("LDAP connection failed: %v", err)
	}
	defer ldapClient.Close()

	baseDN := buildBaseDN(creds)

	// Créer le client ACL en passant le *ldap.Conn sous-jacent
	aclClient := adattack.NewACLClient(ldapClient.Conn(), baseDN)

	// Lancer l'énumération
	spinner := common.NewSpinner("Enumerating ACLs")
	spinner.Start()

	var rights []adattack.ACLRight
	if aclTarget != "" {
		rights, err = aclClient.FindACLsOnTarget(aclTarget)
	} else {
		rights, err = aclClient.FindDangerousACLs()
	}

	spinner.Stop()

	if err != nil {
		return fmt.Errorf("ACL enumeration failed: %v", err)
	}

	// Appliquer le filtre si demandé
	if aclFilterStr != "" {
		var filtered []adattack.ACLRight
		for _, r := range rights {
			if strings.Contains(strings.ToLower(r.Right), strings.ToLower(aclFilterStr)) {
				filtered = append(filtered, r)
			}
		}
		rights = filtered
	}

	if len(rights) == 0 {
		common.PrintWarning("No dangerous ACLs found")
		return nil
	}

	// Output JSON
	if aclJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rights)
	}

	// Output tableau
	common.PrintSuccess(fmt.Sprintf("Found %d dangerous ACL right(s)", len(rights)))

	// Grouper par type de droit pour une meilleure lisibilité
	byRight := make(map[string][]adattack.ACLRight)
	for _, r := range rights {
		byRight[r.Right] = append(byRight[r.Right], r)
	}

	// Ordre de priorité
	priority := []string{
		"GenericAll", "DCSync", "WriteDACL", "WriteOwner",
		"GenericWrite", "ForceChangePassword", "AllExtendedRights",
		"Self-Membership (AddMember)", "WriteProperty",
	}

	for _, rightName := range priority {
		group, ok := byRight[rightName]
		if !ok {
			continue
		}
		printACLGroup(rightName, group)
		delete(byRight, rightName)
	}
	// Droits restants non dans la liste de priorité
	for rightName, group := range byRight {
		printACLGroup(rightName, group)
	}

	return nil
}

func printACLGroup(rightName string, rights []adattack.ACLRight) {
	// En-tête du groupe
	fmt.Fprintf(os.Stdout, "\n  ")
	common.PrintWarning(fmt.Sprintf("[%s] — %d instance(s)", rightName, len(rights)))

	rows := make([][]string, 0, len(rights))
	for _, r := range rights {
		abuse := ""
		if aclAbuse {
			abuse = r.AbuseInfo
		}
		inherited := ""
		if r.Inherited {
			inherited = "inherited"
		}
		rows = append(rows, []string{
			r.ObjectName, // qui a le droit
			r.ObjectType, // type
			r.TargetName, // sur quel objet
			inherited,
			abuse,
		})
	}

	headers := []string{"PRINCIPAL", "TYPE", "TARGET", "INHERITED", ""}
	if aclAbuse {
		headers[4] = "ABUSE"
	}
	common.PrintTable(headers, rows)
}
