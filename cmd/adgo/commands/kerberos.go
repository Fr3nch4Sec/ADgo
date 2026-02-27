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
			common.PrintError(err)
			return err
		}

		results, err := exploits.Kerberoast(ctx, *creds)
		if err != nil {
			common.PrintError(fmt.Errorf("failed to perform Kerberoast: %v", err))
			return err
		}

		common.PrintOutput(results, false, false, false)
		common.PrintSuccess("Kerberoasting performed successfully")
		return nil
	},
}

var GoldenTicketCmd = &cobra.Command{
	Use:   "goldenticket",
	Short: "Create a Golden Ticket",
	RunE: func(cmd *cobra.Command, args []string) error {
		domain, _ := cmd.Flags().GetString("domain")
		username, _ := cmd.Flags().GetString("username")
		sid, _ := cmd.Flags().GetString("sid")
		krbtgthash, _ := cmd.Flags().GetString("krbtgthash")
		targetspn, _ := cmd.Flags().GetString("targetspn")

		goldenTicket := exploits.NewGoldenTicket(domain, username, sid, krbtgthash, targetspn)
		err := goldenTicket.Create()
		if err != nil {
			common.PrintError(fmt.Errorf("failed to create Golden Ticket: %v", err))
			return err
		}

		common.PrintSuccess("Golden Ticket created successfully")
		return nil
	},
}

var SilverTicketCmd = &cobra.Command{
	Use:   "silverticket",
	Short: "Create a Silver Ticket",
	RunE: func(cmd *cobra.Command, args []string) error {
		username, _ := cmd.Flags().GetString("username")
		domain, _ := cmd.Flags().GetString("domain")
		target, _ := cmd.Flags().GetString("target")
		nthash, _ := cmd.Flags().GetString("nthash")

		result, err := exploits.SilverTicket(username, domain, target, nthash)
		if err != nil {
			common.PrintError(fmt.Errorf("failed to create Silver Ticket: %v", err))
			return err
		}

		common.PrintSuccess(result.Status)
		return nil
	},
}

func init() {
	KerberosCmd.AddCommand(KerberoastCmd)
	KerberosCmd.AddCommand(GoldenTicketCmd)
	KerberosCmd.AddCommand(SilverTicketCmd)

	GoldenTicketCmd.Flags().String("domain", "", "Domain name")
	GoldenTicketCmd.Flags().String("username", "", "Username")
	GoldenTicketCmd.Flags().String("sid", "", "SID of the domain")
	GoldenTicketCmd.Flags().String("krbtgthash", "", "KRBTGT hash")
	GoldenTicketCmd.Flags().String("targetspn", "", "Target SPN")

	SilverTicketCmd.Flags().String("username", "", "Username")
	SilverTicketCmd.Flags().String("domain", "", "Domain name")
	SilverTicketCmd.Flags().String("target", "", "Target service")
	SilverTicketCmd.Flags().String("nthash", "", "NT hash of the user")
}

// KerberosCmd est la commande racine pour les opérations Kerberos.
var KerberosCmd = &cobra.Command{
	Use:   "kerberos",
	Short: "Kerberos operations",
}
