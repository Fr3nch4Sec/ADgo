// cmd/adgo/main.go
package main

import (
	"adgo/cmd/adgo/commands"
	"adgo/pkg/common"
	"adgo/pkg/configuration"
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

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
  # Save your lab settings once
  adgo config set dc-ip 192.168.1.10
  adgo config set domain lab.local
  adgo config set username admin

  # Then run without repeating flags
  adgo autopwn 192.168.1.0/24 -p pass
  adgo bloodhound -p pass

═══════════════════════════════════════════════════
 DISCOVERY & EXEC
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
  adgo kerberos kerberoast  --dc-ip 192.168.1.10 -u admin -p pass -d LAB --force-rc4
  adgo kerberos userenum    --dc-ip 192.168.1.10 --users users.txt -d LAB
  adgo kerberos kerspray    --dc-ip 192.168.1.10 --users users.txt -p pass -d LAB
  adgo kerberos s4u         --dc-ip 192.168.1.10 -u attacker$ -p pass -d LAB \
                              --impersonate administrator --spn cifs/dc01.lab.local

═══════════════════════════════════════════════════
 RELAY & PIVOTING
═══════════════════════════════════════════════════
  adgo relay --target 192.168.1.10 --type adcs
  adgo proxy --listen 127.0.0.1:1080

═══════════════════════════════════════════════════
 INTERACTIVE TUI
═══════════════════════════════════════════════════
  adgo tui                              ← menu interactif
  adgo tui scan 192.168.1.0/24 -u admin -p pass -d LAB
  adgo tui users --dc-ip 192.168.1.10 -u admin -p pass -d LAB

═══════════════════════════════════════════════════
 PLAYBOOKS
═══════════════════════════════════════════════════
  adgo playbook run  .\playbooks\full-recon.yml --vars-file lab.env
  adgo playbook list .\playbooks\
  adgo playbook new  my-attack

═══════════════════════════════════════════════════
 SESSION & LOGGING
═══════════════════════════════════════════════════
  adgo autopwn 192.168.1.0/24 -u admin -p pass -d LAB \
      --session --log-file ./run.jsonl`,

	// PersistentPreRunE : injecte la config persistante + init session/log
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Injecter la config utilisateur dans les flags non définis
		injectUserConfig(cmd)

		// Session persistante
		if sessionFlag && common.Domain != "" {
			common.InitSession(common.Domain, "")
		}

		// Log JSON
		if logFileFlag != "" {
			common.InitLogFile(logFileFlag)
		}

		common.CurrentCommand = cmd.CommandPath()
		return nil
	},
}

// injectUserConfig applique les valeurs de la config utilisateur
// uniquement sur les flags qui n'ont pas été définis explicitement en CLI.
func injectUserConfig(cmd *cobra.Command) {
	cfg := configuration.LoadUserConfig()

	// Helper : injecter seulement si le flag CLI n'a pas été fourni
	inject := func(flagName, value string) {
		if value == "" {
			return
		}
		// Chercher dans les flags persistants via le cmd reçu en paramètre
		if f := cmd.Root().PersistentFlags().Lookup(flagName); f != nil {
			if !f.Changed {
				f.Value.Set(value)
			}
		}
	}

	inject("domain", cfg.Domain)
	inject("username", cfg.Username)

	// dc-ip est un flag local à chaque commande — on l'injecte via une variable
	// commune accessible depuis les commandes
	if cfg.DCIP != "" && common.DefaultDCIP == "" {
		common.DefaultDCIP = cfg.DCIP
	}
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
	// Auth flags → common.* (visibles dans toutes les sous-commandes)
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

	// Session & logging
	rootCmd.PersistentFlags().BoolVar(&sessionFlag, "session", false,
		"Save findings to ~/.adgo/session_<domain>_<date>.json")
	rootCmd.PersistentFlags().StringVar(&logFileFlag, "log-file", "",
		"Append all events to JSON log file (e.g. --log-file run.jsonl)")

	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "Config file")

	rootCmd.AddCommand(
		// Config persistante
		commands.ConfigCmd,

		// TUI interactif
		commands.TUICmd,

		// Playbooks
		commands.PlaybookCmd,

		// All-in-one
		commands.AutoPwnCmd,

		// Discovery & pivoting
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

		// Protocol modules (sous-commandes enregistrées via init())
		commands.LDAPCmd,
		commands.SMBCmd,
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
	// ============================================================
	// Graceful shutdown — Ctrl+C propre
	// ============================================================
	// Crée un context annulable qui se déclenche sur SIGINT ou SIGTERM.
	// Toutes les commandes qui supportent le context s'arrêteront proprement :
	//   - Les goroutines de scan se terminent
	//   - Les shadow copies VSS sont supprimées (si --cleanup)
	//   - Les fichiers temporaires sont nettoyés
	//   - La session est sauvegardée avant de quitter
	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt,    // Ctrl+C
		syscall.SIGTERM, // kill / systemd stop
	)
	defer stop()

	// Propager le context dans cobra
	rootCmd.SetContext(ctx)

	if !common.NoBanner {
		printBanner()
	}

	// Afficher un message propre si l'utilisateur fait Ctrl+C
	go func() {
		<-ctx.Done()
		// Laisser cobra finir son exécution courante
		// Les commandes qui écoutent ctx.Done() se termineront d'elles-mêmes
		if ctx.Err() == context.Canceled {
			fmt.Fprintf(os.Stderr, "\n[!] Interrupted — cleaning up...\n")
			// Sauvegarder la session si active
			if common.GetSession() != nil {
				common.PrintSessionSummary()
			}
		}
	}()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		log.Fatal(err)
	}
}

var _ *cobra.Command
