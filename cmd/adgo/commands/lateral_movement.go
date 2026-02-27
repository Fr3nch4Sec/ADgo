// cmd/adgo/commands/lateral_movement.go
package commands

import (
	"fmt"

	"adgo/pkg/common"
	"adgo/pkg/exploits"

	"github.com/spf13/cobra"
)

// PTHCmd effectue une attaque Pass-the-Hash.
var PTHCmd = &cobra.Command{
	Use:   "pth",
	Short: "Perform Pass-the-Hash attack",
	RunE: func(cmd *cobra.Command, args []string) error {
		target, _ := cmd.Flags().GetString("target")
		username, _ := cmd.Flags().GetString("username")
		nthash, _ := cmd.Flags().GetString("nthash")

		pth := exploits.NewPassTheHash(target, username, nthash)
		return pth.Execute()
	},
}

// PSExecCmd exécute une commande sur une machine distante en utilisant PSExec.
var PSExecCmd = &cobra.Command{
	Use:   "psexec",
	Short: "Execute command on remote machine using PSExec",
	RunE: func(cmd *cobra.Command, args []string) error {
		target, _ := cmd.Flags().GetString("target")
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		command, _ := cmd.Flags().GetString("command")

		output, err := exploits.PSExec(target, username, password, command)
		if err != nil {
			common.PrintError(fmt.Errorf("failed to execute PSExec: %v", err))
			return err
		}

		fmt.Printf("Output:\n%s\n", output)
		common.PrintSuccess("PSExec executed successfully")
		return nil
	},
}

func init() {
	PTHCmd.Flags().String("target", "", "Target in format domain\\ip or ip")
	PTHCmd.Flags().String("username", "", "Username (format: user or user@domain)")
	PTHCmd.Flags().String("nthash", "", "NT hash")

	PSExecCmd.Flags().String("target", "", "Target machine")
	PSExecCmd.Flags().String("username", "", "Username")
	PSExecCmd.Flags().String("password", "", "Password")
	PSExecCmd.Flags().String("command", "", "Command to execute")

	LateralMovementCmd.AddCommand(PTHCmd)
	LateralMovementCmd.AddCommand(PSExecCmd)
}

// LateralMovementCmd est la commande racine pour les mouvements latéraux.
var LateralMovementCmd = &cobra.Command{
	Use:   "lateral-movement",
	Short: "Lateral movement operations",
}
