// cmd/adgo/ntlm/adcs.go
package ntlm

import (
	"log"

	"adgo/pkg/configuration"
	"adgo/pkg/ntlm/relay"

	"github.com/spf13/cobra"
)

// ADCSCommand représente la sous-commande `ntlm adcs`
var ADCSCommand = &cobra.Command{
	Use:   "adcs",
	Short: "NTLM relay to an AD CS server",
	Run: func(cmd *cobra.Command, args []string) {
		// Charger la configuration
		cfg, err := configuration.Load()
		if err != nil {
			log.Fatalf("Configuration loading error : %v", err)
		}

		// Scanner le serveur AD CS
		err = relay.ScanADCS(cfg.NTLM.ADCS)
		if err != nil {
			log.Fatalf("Error during AD CS scan: %v", err)
		}

		// Exploiter le relay
		err = relay.ExploitADCS(cfg.NTLM.ADCS)
		if err != nil {
			log.Fatalf("Error during operation : %v", err)
		}
	},
}
