// cmd/adgo/commands/ntlm.go
package commands

import (
	"fmt"

	"adgo/pkg/configuration"
	"adgo/pkg/ntlm/ntlmv1"
	"adgo/pkg/ntlm/ntlmv2"
	"adgo/pkg/ntlm/relay"

	"github.com/spf13/cobra"
)

// ADCSCommand effectue un relay NTLM vers un serveur AD CS.
var ADCSCommand = &cobra.Command{
	Use:   "adcs",
	Short: "Relay NTLM vers un serveur AD CS",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := configuration.LoadConfig("configs/config.yaml")
		if err != nil {
			return fmt.Errorf("configuration loading error : %v", err)
		}

		err = relay.ScanADCS(cfg.NTLM.ADCS)
		if err != nil {
			return fmt.Errorf("error during AD CS scan : %v", err)
		}

		return relay.ExploitADCS(cfg.NTLM.ADCS)
	},
}

// NTLMv1Cmd effectue une authentification NTLMv1.
var NTLMv1Cmd = &cobra.Command{
	Use:   "ntlmv1",
	Short: "NTLMv1 authentication",
	RunE: func(cmd *cobra.Command, args []string) error {
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		domain, _ := cmd.Flags().GetString("domain")

		auth := ntlmv1.NewNTLMv1Auth(username, password, domain)
		response, err := auth.GenerateResponse()
		if err != nil {
			return fmt.Errorf("failed to generate NTLMv1 response: %v", err)
		}

		fmt.Printf("NTLMv1 Response: %s\n", response)
		return nil
	},
}

// NTLMv2Cmd effectue une authentification NTLMv2.
var NTLMv2Cmd = &cobra.Command{
	Use:   "ntlmv2",
	Short: "NTLMv2 authentication",
	RunE: func(cmd *cobra.Command, args []string) error {
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		domain, _ := cmd.Flags().GetString("domain")

		auth := ntlmv2.NewNTLMv2Auth(username, password, domain)
		response, err := auth.GenerateResponse()
		if err != nil {
			return fmt.Errorf("failed to generate NTLMv2 response: %v", err)
		}

		fmt.Printf("NTLMv2 Response: %s\n", response)
		return nil
	},
}

// NTLMRelayCmd démarre un serveur de relay NTLM.
var NTLMRelayCmd = &cobra.Command{
	Use:   "ntlmrelay",
	Short: "Start an NTLM relay server",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, _ := cmd.Flags().GetString("addr")

		rs := relay.NewRelayServer(addr)
		fmt.Printf("Starting NTLM relay server on %s\n", addr)
		return rs.Start()
	},
}

func init() {
	NTLMv1Cmd.Flags().String("username", "", "Username for NTLMv1 authentication")
	NTLMv1Cmd.Flags().String("password", "", "Password for NTLMv1 authentication")
	NTLMv1Cmd.Flags().String("domain", "", "Domain for NTLMv1 authentication")

	NTLMv2Cmd.Flags().String("username", "", "Username for NTLMv2 authentication")
	NTLMv2Cmd.Flags().String("password", "", "Password for NTLMv2 authentication")
	NTLMv2Cmd.Flags().String("domain", "", "Domain for NTLMv2 authentication")

	NTLMRelayCmd.Flags().String("addr", ":8080", "Address to listen on")

	// Ajoute les flags pour ADCSCommand si nécessaire
	ADCSCommand.Flags().String("adcs-url", "", "AD CS server URL")
	ADCSCommand.Flags().String("template", "User", "Certificate template to request")

	// Intègre toutes les sous-commandes
	NTLMCmd.AddCommand(NTLMv1Cmd)
	NTLMCmd.AddCommand(NTLMv2Cmd)
	NTLMCmd.AddCommand(NTLMRelayCmd)
	NTLMCmd.AddCommand(ADCSCommand) // NOUVELLE commande
}

// NTLMCmd est la commande racine pour les opérations NTLM.
var NTLMCmd = &cobra.Command{
	Use:   "ntlm",
	Short: "NTLM operations",
}
