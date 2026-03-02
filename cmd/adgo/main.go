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

	// Flags globaux
	Username string
	Password string
	Domain   string
	NTLMHash string
	Quiet    bool
	NoBanner bool
)

var rootCmd = &cobra.Command{
	Use:   "adgo",
	Short: "ADgo - Active Directory tooling in Go",
}

func printBanner() {
	c1 := "\033[38;2;0;105;180m"  // Bleu foncé
	c2 := "\033[38;2;20;130;220m" // Bleu moyen
	c3 := "\033[38;2;40;150;240m" // Bleu clair
	r := "\033[0m"

	fmt.Println(c1 + "╔════════════════════════════════════════════╗" + r)
	fmt.Println(c2 + "║                                            ║" + r)
	fmt.Println(c3 + "║     █████╗ ██████╗  ██████╗  ██████╗       ║" + r)
	fmt.Println(c2 + "║    ██╔══██╗██╔══██╗██╔════╝ ██╔═══██╗      ║" + r)
	fmt.Println(c1 + "║    ███████║██║  ██║██║  ███╗██║   ██║      ║" + r)
	fmt.Println(c2 + "║    ██╔══██║██║  ██║██║   ██║██║   ██║      ║" + r)
	fmt.Println(c3 + "║    ██║  ██║██████╔╝╚██████╔╝╚██████╔╝      ║" + r)
	fmt.Println(c2 + "║    ╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚═════╝       ║" + r)
	fmt.Println(c1 + "║                                            ║" + r)
	fmt.Println(c3 + "║                  ADgo                      ║" + r)
	fmt.Println(c2 + "║         Active Directory tooling           ║" + r)
	fmt.Println(c1 + "╚════════════════════════════════════════════╝" + r)
}

func init() {
	// Flags globaux
	rootCmd.PersistentFlags().StringVarP(&Username, "username", "u", "", "Username (ex: administrator ou user@domain)")
	rootCmd.PersistentFlags().StringVarP(&Password, "password", "p", "", "Password")
	rootCmd.PersistentFlags().StringVarP(&Domain, "domain", "d", "", "Domain name (ex: lab.local)")

	rootCmd.PersistentFlags().StringVar(&NTLMHash, "hash", "", "NTLM NT hash (instead of password)")
	rootCmd.PersistentFlags().StringVar(&NTLMHash, "ntlm", "", "NTLM NT hash (alias for --hash)")

	rootCmd.PersistentFlags().BoolVar(&Quiet, "quiet", false, "Quiet mode - suppress success/info messages")
	rootCmd.PersistentFlags().BoolVar(&NoBanner, "no-banner", false, "Disable ASCII banner")

	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "Configuration file (e.g., configs/config.yaml)")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug mode")
	rootCmd.PersistentFlags().BoolVar(&jsonOut, "json", false, "Output in JSON format")
	rootCmd.PersistentFlags().BoolVar(&bloodhound, "bloodhound", false, "Output in BloodHound format")

	// Ajout des commandes (inchangé)
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
		commands.CoercionCmd,
	)
}

func main() {
	if !NoBanner {
		printBanner()
	}

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
