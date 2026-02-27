// cmd/adgo/commands/rpc.go
package commands

import (
	"fmt"

	"adgo/pkg/common"
	"adgo/pkg/rpc"

	"github.com/spf13/cobra"
)

// RPCEnumerateCmd énumère les services RPC.
var RPCEnumerateCmd = &cobra.Command{
	Use:   "enumerate",
	Short: "Enumerate RPC services",
	RunE: func(cmd *cobra.Command, args []string) error {
		host, _ := cmd.Flags().GetString("host")

		services, err := rpc.EnumerateRPC(host)
		if err != nil {
			common.PrintError(fmt.Errorf("failed to enumerate RPC services: %v", err))
			return err
		}

		for _, service := range services {
			fmt.Printf("Service: %s, Port: %d\n", service.Service, service.Port)
		}

		common.PrintSuccess("RPC services enumerated successfully")
		return nil
	},
}

// RPCScriptCmd exécute un script RPC.
var RPCScriptCmd = &cobra.Command{
	Use:   "script",
	Short: "Execute an embedded RPC script",
	RunE: func(cmd *cobra.Command, args []string) error {
		host, _ := cmd.Flags().GetString("host")
		script, _ := cmd.Flags().GetString("script")

		client := rpc.NewRPCClient(host)
		output, err := client.ExecuteScript(script)
		if err != nil {
			common.PrintError(fmt.Errorf("failed to execute script: %v", err))
			return err
		}

		fmt.Println(output)
		common.PrintSuccess("Script executed successfully")
		return nil
	},
}

func init() {
	RPCEnumerateCmd.Flags().String("host", "", "Host address (e.g., 192.168.1.10)")
	RPCScriptCmd.Flags().String("host", "", "Host address (e.g., 192.168.1.10)")
	RPCScriptCmd.Flags().String("script", "enum_rpc.ps1", "Script name to execute")

	RPCCmd.AddCommand(RPCEnumerateCmd)
	RPCCmd.AddCommand(RPCScriptCmd)
}

// RPCCmd est la commande racine pour les opérations RPC.
var RPCCmd = &cobra.Command{
	Use:   "rpc",
	Short: "RPC operations",
}
