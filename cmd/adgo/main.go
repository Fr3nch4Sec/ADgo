// cmd/adgo/main.go
package main

import (
	"adgo/cmd/adgo/commands"
	"adgo/pkg/common"
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

// Flags locaux non partagés avec les commandes
var (
	configFile string
	debug      bool
	jsonOut    bool
	bloodhound bool
)

var rootCmd = &cobra.Command{
	Use:   "adgo",
	Short: "ADgo — Active Directory offensive toolkit in Go",
	Long: `ADgo — alternative to NetExec / CrackMapExec, written in pure Go.

Authentication (all commands):
  -u, --username  Username (e.g. administrator or user@domain)
  -p, --password  Password
  -d, --domain    Domain name (e.g. lab.local)
      --hash      NT hash for Pass-the-Hash (e.g. aad3b435b51404ee...)

Quick start:
  adgo scan 192.168.1.0/24 -u admin -p pass -d LAB
  adgo exec 192.168.1.10 -u admin -p pass -d LAB -c "whoami"
  adgo ldap users -u admin -p pass -d LAB --dc-ip 192.168.1.10
  adgo kerberos asreproast -u admin -p pass -d LAB --dc-ip 192.168.1.10`,
}

func printBanner() {
	c1 := "\033[38;2;0;105;180m"
	c2 := "\033[38;2;20;130;220m"
	c3 := "\033[38;2;40;150;240m"
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
	fmt.Println(c3 + "║  ADgo — Active Directory toolkit in Go     ║" + r)
	fmt.Println(c2 + "╚════════════════════════════════════════════╝" + r)
}

func init() {

	rootCmd.PersistentFlags().StringVarP(&common.Username, "username", "u", "", "Username (e.g. administrator or user@domain)")
	rootCmd.PersistentFlags().StringVarP(&common.Password, "password", "p", "", "Password")
	rootCmd.PersistentFlags().StringVarP(&common.Domain, "domain", "d", "", "Domain name (e.g. lab.local)")

	rootCmd.PersistentFlags().StringVar(&common.NTLMHash, "hash", "", "NT hash for Pass-the-Hash (32 hex chars)")
	rootCmd.PersistentFlags().StringVar(&common.NTLMHash, "ntlm", "", "NT hash for Pass-the-Hash (alias for --hash)")

	rootCmd.PersistentFlags().BoolVar(&common.Quiet, "quiet", false, "Quiet mode — suppress info messages")
	rootCmd.PersistentFlags().BoolVar(&common.NoBanner, "no-banner", false, "Disable ASCII banner")
	rootCmd.PersistentFlags().BoolVar(&common.Debug, "debug", false, "Enable debug output")

	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "Config file (default: configs/config.yaml)")
	rootCmd.PersistentFlags().BoolVar(&jsonOut, "json", false, "Output in JSON format")
	rootCmd.PersistentFlags().BoolVar(&bloodhound, "bloodhound", false, "Output in BloodHound CE format")

	rootCmd.AddCommand(
		// === Nouvelles commandes Priorité 1 ===
		commands.ScanCmd, // adgo scan 192.168.1.0/24 [creds]
		commands.ExecCmd, // adgo exec <target> -c "cmd"

		// === Commandes existantes ===
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
		commands.AttackCmd,
		commands.SprayCmd,
	)
}

func main() {
	if !common.NoBanner {
		printBanner()
	}

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
