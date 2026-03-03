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
	Short: "Relay NTLM vers un serveur AD CS",
	Run: func(cmd *cobra.Command, args []string) {
		// Charger la configuration
		cfg, err := configuration.Load()
		if err != nil {
			log.Fatalf("Erreur de chargement de la configuration : %v", err)
		}

		// Scanner le serveur AD CS
		err = relay.ScanADCS(cfg.NTLM.ADCS)
		if err != nil {
			log.Fatalf("Erreur lors du scan AD CS : %v", err)
		}

		// Exploiter le relay
		err = relay.ExploitADCS(cfg.NTLM.ADCS)
		if err != nil {
			log.Fatalf("Erreur lors de l'exploitation : %v", err)
		}
	},
}
