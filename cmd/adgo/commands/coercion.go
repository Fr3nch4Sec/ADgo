// cmd/adgo/commands/coercion.go
package commands

import (
	"fmt"

	"adgo/pkg/coercion"

	"github.com/spf13/cobra"
)

// CoercionCmd démarre un serveur de coercion NTLM.
var CoercionCmd = &cobra.Command{
	Use:   "coercion",
	Short: "Start an NTLM coercion server",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, _ := cmd.Flags().GetString("addr")
		cs := coercion.NewCoerceServer(addr)
		fmt.Printf("Starting NTLM coercion server on %s\n", addr)
		return cs.Start()
	},
}

func init() {
	CoercionCmd.Flags().String("addr", ":8080", "Address to listen on")

	CoercionCmdCmd.AddCommand(CoercionCmd)
}

// CoercionCmdCmd est la commande racine pour les opérations de coercion NTLM.
var CoercionCmdCmd = &cobra.Command{
	Use:   "coercion",
	Short: "NTLM coercion operations",
}
