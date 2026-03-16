// cmd/adgo/commands/trusts_cmd.go
//
// adgo ldap trusts — Énumération des relations de confiance inter-domaines
//
// Exemple :
//   adgo ldap trusts --dc-ip 192.168.1.10 -u admin -p pass -d LAB

package commands

import (
	"context"
	"fmt"
	"strings"

	"adgo/pkg/common"
	"adgo/pkg/ldap"

	"github.com/spf13/cobra"
)

var TrustsCmd = &cobra.Command{
	Use:   "trusts",
	Short: "Enumerate domain trust relationships (inter-domain/forest)",
	Long: `Enumerate Active Directory trust relationships.

Shows trust type, direction, and whether SID filtering is enabled.
Highlights potentially exploitable trusts (outbound/bidirectional without SID filtering).

Attack paths detected:
  • Bidirectional unfiltered → compromise remote domain to pivot back
  • Outbound to forest → SID history attack if no SID filtering
  • Transitive trusts → access to entire forest

Examples:
  adgo ldap trusts --dc-ip 192.168.1.10 -u admin -p pass -d LAB
  adgo ldap trusts --dc-ip 192.168.1.10 -u admin --hash aad3b435... -d LAB`,
	RunE: func(cmd *cobra.Command, args []string) error {
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

		common.PrintInfo(fmt.Sprintf("Trust enumeration → %s as %s\\%s",
			server, strings.ToUpper(creds.SMBDomain), creds.SMBUsername))

		client, err := ldap.NewClientNTLM(ctx, server, creds.SMBDomain, creds.SMBUsername,
			creds.Password, creds.NTLMHash, false)
		if err != nil {
			return fmt.Errorf("LDAP connection failed: %v", err)
		}
		defer client.Close()

		baseDN := buildBaseDN(creds)
		trusts, err := client.EnumerateTrusts(baseDN)
		if err != nil {
			return fmt.Errorf("trust enumeration failed: %v", err)
		}

		if len(trusts) == 0 {
			common.PrintWarning("No domain trusts found")
			return nil
		}

		common.PrintSuccess(fmt.Sprintf("Found %d trust relationship(s)", len(trusts)))
		fmt.Println()

		common.PrintTable(
			[]string{"DOMAIN", "TYPE", "DIRECTION", "SCOPE", "SID FILTER", "TRANSITIVE", "RISK"},
			ldap.FormatTrustsTable(trusts),
		)

		// Analyse des exploitations possibles
		ldap.PrintTrustAnalysis(trusts)

		return nil
	},
}

func init() {
	TrustsCmd.Flags().String("dc-ip", "", "Domain Controller IP (required)")
	LDAPCmd.AddCommand(TrustsCmd)
}
