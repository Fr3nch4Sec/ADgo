// cmd/adgo/main.go
package main

import (
	"adgo/cmd/adgo/commands"
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

var (
	configFile string
	debug      bool
	jsonOut    bool
	bloodhound bool
)

var rootCmd = &cobra.Command{
	Use:   "adgo",
	Short: "ADgo - Active Directory tooling in Go",
}

func printBanner() {
	colors := []string{
		"\033[31m", // rouge
		"\033[33m", // jaune
		"\033[32m", // vert
		"\033[36m", // cyan
		"\033[34m", // bleu
		"\033[35m", // magenta
	}

	reset := "\033[0m"

	banner := `
    █████╗ ██████╗  ██████╗  ██████╗ 
   ██╔══██╗██╔══██╗██╔════╝ ██╔═══██╗
   ███████║██║  ██║██║  ███╗██║   ██║
   ██╔══██║██║  ██║██║   ██║██║   ██║
   ██║  ██║██████╔╝╚██████╔╝╚██████╔╝
   ╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚═════╝ 
`

	i := 0
	for _, char := range banner {
		if char == '\n' {
			fmt.Print("\n")
			continue
		}
		color := colors[i%len(colors)]
		fmt.Print(color + string(char) + reset)
		i++
	}
}

func main() {
	printBanner()

	// Flags persistants
	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "Configuration file (e.g., configs/config.yaml)")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug mode")
	rootCmd.PersistentFlags().BoolVar(&jsonOut, "json", false, "Output in JSON format")
	rootCmd.PersistentFlags().BoolVar(&bloodhound, "bloodhound", false, "Output in BloodHound format")

	// Ajout des commandes
	rootCmd.AddCommand(
		commands.LDAPCmd,
		commands.SMBCmd,
		commands.KerberosCmd,
		commands.ExploitsCmd,
		commands.PersistenceCmd,
		commands.LateralMovementCmd,
		commands.WinRMCmd,
		commands.WMICmd,
		commands.RPCCmd,
		commands.NTLMCmd,
		commands.CoercionCmdCmd,
	)

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
