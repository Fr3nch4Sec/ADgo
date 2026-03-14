// cmd/adgo/main.go
package main

import (
	"adgo/cmd/adgo/commands"
	"adgo/pkg/common"
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

var (
	configFile  string
	jsonOut     bool
	bloodhound  bool
	sessionFlag bool
	logFileFlag string
)

var rootCmd = &cobra.Command{
	Use:   "adgo",
	Short: "ADgo — Active Directory offensive toolkit in Go",
	Long: `ADgo — pure Go alternative to NetExec / CrackMapExec / impacket.

Authentication (all commands):
  -u, --username   Username
  -p, --password   Password
  -d, --domain     Domain (e.g. lab.local)
      --hash       NT hash for Pass-the-Hash

═══════════════════════════════════════════════════
 QUICK START
═══════════════════════════════════════════════════
  adgo autopwn 192.168.1.0/24 -u admin -p pass -d LAB
  adgo scan    192.168.1.0/24 -u admin -p pass -d LAB
  adgo exec    192.168.1.10   -u admin -p pass -d LAB -c cmd

═══════════════════════════════════════════════════
 BLOODHOUND & ADCS
═══════════════════════════════════════════════════
  adgo bloodhound --dc-ip 192.168.1.10 -u admin -p pass -d LAB
  adgo adcs       --dc-ip 192.168.1.10 -u admin -p pass -d LAB

═══════════════════════════════════════════════════
 ENUMERATION (LDAP)
═══════════════════════════════════════════════════
  adgo ldap users       --dc-ip 192.168.1.10 -u admin -p pass -d LAB
  adgo ldap acl         --dc-ip 192.168.1.10 -u admin -p pass -d LAB
  adgo ldap trusts      --dc-ip 192.168.1.10 -u admin -p pass -d LAB
  adgo ldap rbcd        --dc-ip 192.168.1.10 -u admin -p pass -d LAB --target DC01$
  adgo ldap shadowcred  --dc-ip 192.168.1.10 -u admin -p pass -d LAB --target john

═══════════════════════════════════════════════════
 CREDENTIAL ATTACKS
═══════════════════════════════════════════════════
  adgo laps              --dc-ip 192.168.1.10 -u admin -p pass -d LAB
  adgo gmsa              --dc-ip 192.168.1.10 -u admin -p pass -d LAB
  adgo gpp               --dc-ip 192.168.1.10 -u user  -p pass -d LAB
  adgo smb secretsdump   192.168.1.10 -u admin -p pass -d LAB
  adgo smb ntds          192.168.1.10 -u admin -p pass -d LAB

═══════════════════════════════════════════════════
 KERBEROS
═══════════════════════════════════════════════════
  adgo kerberos kerberoast  --dc-ip 192.168.1.10 -u admin -p pass -d LAB
  adgo kerberos kerberoast  --dc-ip 192.168.1.10 -u admin -p pass -d LAB --force-rc4
  adgo kerberos asreproast  --dc-ip 192.168.1.10 -u admin -p pass -d LAB
  adgo kerberos userenum    --dc-ip 192.168.1.10 --users users.txt -d LAB
  adgo kerberos kerspray    --dc-ip 192.168.1.10 --users users.txt -p pass -d LAB
  adgo kerberos s4u         --dc-ip 192.168.1.10 -u attacker$ -p pass -d LAB \
                              --impersonate administrator --spn cifs/dc01.lab.local

═══════════════════════════════════════════════════
 RELAY & PIVOTING
═══════════════════════════════════════════════════
  adgo relay --target 192.168.1.10 --type adcs   (ESC8)
  adgo relay --target 192.168.1.10 --type ldap
  adgo proxy --listen 127.0.0.1:1080

═══════════════════════════════════════════════════
 PLAYBOOKS
═══════════════════════════════════════════════════
  adgo playbook run full-recon.yaml --vars-file lab.env
  adgo playbook run lateral.yaml -v DC_IP=192.168.1.10 DOMAIN=lab.local
  adgo playbook list ./playbooks/
  adgo playbook new my-attack

═══════════════════════════════════════════════════
 SESSION & LOGGING
═══════════════════════════════════════════════════
  adgo autopwn 192.168.1.0/24 -u admin -p pass -d LAB \
      --session --log-file ./run.jsonl
  adgo scan 192.168.1.0/24 -u admin -p pass -d LAB --resume`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if sessionFlag && common.Domain != "" {
			common.InitSession(common.Domain, "")
		}
		if logFileFlag != "" {
			common.InitLogFile(logFileFlag)
		}
		common.CurrentCommand = cmd.CommandPath()
		return nil
	},
}

func printBanner() {
	colors := []string{
		"\033[38;2;255;140;0m",
		"\033[38;2;255;100;0m",
		"\033[38;2;230;60;10m",
		"\033[38;2;200;30;20m",
		"\033[38;2;170;10;30m",
		"\033[38;2;140;0;40m",
	}
	dim := "\033[38;2;80;80;80m"
	bold := "\033[1m"
	r := "\033[0m"

	lines := []string{
		` █████╗ ██████╗  ██████╗  ██████╗ `,
		`██╔══██╗██╔══██╗██╔════╝ ██╔═══██╗`,
		`███████║██║  ██║██║  ███╗██║   ██║`,
		`██╔══██║██║  ██║██║   ██║██║   ██║`,
		`██║  ██║██████╔╝╚██████╔╝╚██████╔╝`,
		`╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚═════╝ `,
	}

	width := 36
	fmt.Printf("%s┌%s┐%s\n", dim, repeatStr("─", width+2), r)
	for i, line := range lines {
		c := colors[i]
		if i == 0 {
			c = bold + colors[0]
		}
		fmt.Printf("%s│%s %s%s%s %s│%s\n", dim, r, c, line, r, dim, r)
	}
	fmt.Printf("%s├%s┤%s\n", dim, repeatStr("─", width+2), r)

	tagline := "Active Directory toolkit in Go"
	pad := (width - len(tagline)) / 2
	fmt.Printf("%s│%s%s%s%s%s%s│%s\n",
		dim, r,
		repeatStr(" ", pad+1),
		"\033[38;2;255;140;0m"+bold, tagline, r,
		repeatStr(" ", width-pad-len(tagline)+1),
		dim+r,
	)
	info := "github.com/Fr3nch4Sec/ADgo"
	infoPad := (width - len(info)) / 2
	fmt.Printf("%s│%s%s%s%s%s│%s\n",
		dim, r,
		repeatStr(" ", infoPad+1),
		dim, info,
		repeatStr(" ", width-infoPad-len(info)+1),
		dim+r,
	)
	fmt.Printf("%s└%s┘%s\n\n", dim, repeatStr("─", width+2), r)
}

func repeatStr(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}

func init() {
	// Auth flags — bindés sur common.* pour être visibles partout
	rootCmd.PersistentFlags().StringVarP(&common.Username, "username", "u", "", "Username")
	rootCmd.PersistentFlags().StringVarP(&common.Password, "password", "p", "", "Password")
	rootCmd.PersistentFlags().StringVarP(&common.Domain, "domain", "d", "", "Domain (e.g. lab.local)")
	rootCmd.PersistentFlags().StringVar(&common.NTLMHash, "hash", "", "NT hash for Pass-the-Hash (32 hex chars)")
	rootCmd.PersistentFlags().StringVar(&common.NTLMHash, "ntlm", "", "Alias for --hash")

	// Output flags
	rootCmd.PersistentFlags().BoolVar(&common.Quiet, "quiet", false, "Suppress info messages")
	rootCmd.PersistentFlags().BoolVar(&common.NoBanner, "no-banner", false, "Disable ASCII banner")
	rootCmd.PersistentFlags().BoolVar(&common.Debug, "debug", false, "Enable debug output")
	rootCmd.PersistentFlags().BoolVar(&jsonOut, "json", false, "JSON output")
	rootCmd.PersistentFlags().BoolVar(&bloodhound, "bloodhound", false, "BloodHound CE output")

	// Session & logging — disponibles sur TOUTES les commandes
	rootCmd.PersistentFlags().BoolVar(&sessionFlag, "session", false,
		"Save findings to ~/.adgo/session_<domain>_<date>.json")
	rootCmd.PersistentFlags().StringVar(&logFileFlag, "log-file", "",
		"Append all events to JSON log file (e.g. --log-file run.jsonl)")

	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "Config file")

	rootCmd.AddCommand(
		// All-in-one
		commands.AutoPwnCmd,
		commands.PlaybookCmd,

		// Discovery & exec & pivoting
		commands.ScanCmd,
		commands.ExecCmd,
		commands.ProxyCmd,
		commands.RelayCmd,

		// BloodHound & ADCS
		commands.BloodHoundCmd,
		commands.ADCSCmd,

		// Credential harvesting
		commands.LAPSCmd,
		commands.GMSACmd,
		commands.GPPCmd,

		// Protocol modules
		// LDAPCmd contient en sous-commandes (via init()) :
		//   users, groups, computers, spns, asreproast, password-policy
		//   acl, rbcd, trusts, shadowcred
		commands.LDAPCmd,

		// SMBCmd contient : secretsdump, ntds (via init())
		commands.SMBCmd,

		// KerberosCmd contient : kerberoast(updated), asreproast, getTGT,
		//   userenum, kerspray, s4u (via init())
		commands.KerberosCmd,

		// Modules existants
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

var _ *cobra.Command
