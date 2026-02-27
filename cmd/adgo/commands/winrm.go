// cmd/adgo/commands/winrm.go
package commands

import (
	"fmt"

	"adgo/pkg/common"
	"adgo/pkg/winrm"

	"github.com/spf13/cobra"
)

// WinRMExecCmd exécute une commande via WinRM.
var WinRMExecCmd = &cobra.Command{
	Use:   "exec",
	Short: "Execute a command via WinRM",
	RunE: func(cmd *cobra.Command, args []string) error {
		host, _ := cmd.Flags().GetString("host")
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		command, _ := cmd.Flags().GetString("command")

		output, err := winrm.RunCommand(host, username, password, command)
		if err != nil {
			common.PrintError(fmt.Errorf("failed to run command: %v", err))
			return err
		}

		fmt.Println(output)
		common.PrintSuccess("Command executed successfully")
		return nil
	},
}

func init() {
	WinRMExecCmd.Flags().String("host", "", "Host address (e.g., 192.168.1.10)")
	WinRMExecCmd.Flags().String("username", "", "Username for WinRM")
	WinRMExecCmd.Flags().String("password", "", "Password for WinRM")
	WinRMExecCmd.Flags().String("command", "", "Command to execute")

	WinRMCmd.AddCommand(WinRMExecCmd)
}

// WinRMCmd est la commande racine pour les opérations WinRM.
var WinRMCmd = &cobra.Command{
	Use:   "winrm",
	Short: "WinRM operations",
}
