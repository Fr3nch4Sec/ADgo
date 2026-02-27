// cmd/adgo/commands/wmi.go
package commands

import (
	"fmt"

	"adgo/pkg/common"
	"adgo/pkg/wmi"

	"github.com/spf13/cobra"
)

// WMIQueryCmd interroge WMI.
var WMIQueryCmd = &cobra.Command{
	Use:   "query",
	Short: "Query WMI information",
	RunE: func(cmd *cobra.Command, args []string) error {
		host, _ := cmd.Flags().GetString("host")
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		query, _ := cmd.Flags().GetString("query")

		output, err := wmi.QueryWMI(host, username, password, query)
		if err != nil {
			common.PrintError(fmt.Errorf("failed to query WMI: %v", err))
			return err
		}

		fmt.Println(output)
		common.PrintSuccess("WMI query executed successfully")
		return nil
	},
}

func init() {
	WMIQueryCmd.Flags().String("host", "", "Host address (e.g., 192.168.1.10)")
	WMIQueryCmd.Flags().String("username", "", "Username for WMI")
	WMIQueryCmd.Flags().String("password", "", "Password for WMI")
	WMIQueryCmd.Flags().String("query", "SELECT * FROM Win32_OperatingSystem", "WMI query")

	WMICmd.AddCommand(WMIQueryCmd)
}

// WMICmd est la commande racine pour les opérations WMI.
var WMICmd = &cobra.Command{
	Use:   "wmi",
	Short: "WMI operations",
}
