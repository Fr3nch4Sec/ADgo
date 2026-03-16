// cmd/adgo/commands/tui_cmd.go
//
// Commande `adgo tui` — lance l'interface TUI bubbletea.
//
// Usage :
//   adgo tui                                   # menu principal
//   adgo tui scan 192.168.1.0/24               # dashboard scan direct
//   adgo tui spray --users u.txt --passwords p.txt
//   adgo tui kerberoast --users u.txt
//   adgo tui asreproast --users u.txt
//   adgo tui userenum --users u.txt
//   adgo tui playbook ./playbooks/full-recon.yml
//   adgo tui session                            # credentials/hôtes session
//   adgo tui config                             # réglages persistants
//
// Toutes les commandes héritent des flags globaux -u / -p / -d / --dc-ip
// via le PersistentPreRunE du rootCmd.

package commands

import (
	"fmt"

	"adgo/pkg/common"
	"adgo/pkg/configuration"
	"adgo/pkg/tui"

	"github.com/spf13/cobra"
)

// ============================================================
// Commande racine TUI
// ============================================================

var TUICmd = &cobra.Command{
	Use:   "tui",
	Short: "Interactive TUI — menu-driven interface for all ADgo operations",
	Long: `Launch the interactive TUI powered by bubbletea.

Without a sub-command, opens the main menu. With a sub-command,
jumps directly to that view.

Examples:
  adgo tui                                     # main menu
  adgo tui scan 192.168.1.0/24 -u admin -p pass -d LAB
  adgo tui spray --users u.txt --passwords p.txt
  adgo tui kerberoast --users u.txt --force-rc4
  adgo tui asreproast --users u.txt
  adgo tui userenum --users u.txt
  adgo tui playbook ./playbooks/full-recon.yml
  adgo tui session
  adgo tui config`,
	// PersistentPreRunE sur TUICmd :
	//   1. Supprime la bannière (le TUI a la sienne)
	//   2. Réappelle injectUserConfig car cobra n'enchaîne pas les PersistentPreRunE parent→child
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		common.NoBanner = true
		cfg := loadUserConfigSafe()
		if cfg != nil {
			if cfg.DCIP != "" && common.DefaultDCIP == "" {
				common.DefaultDCIP = cfg.DCIP
			}
			injectFlagIfEmpty(cmd, "domain", cfg.Domain)
			injectFlagIfEmpty(cmd, "username", cfg.Username)
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := buildAppContext(cmd)
		return tui.RunTUI(ctx)
	},
}

// ============================================================
// Helpers internes
// ============================================================

// buildAppContext construit le contexte de l'app depuis les flags globaux.
func buildAppContext(cmd *cobra.Command) tui.AppContext {
	dcIP := common.DefaultDCIP
	if f := cmd.Root().PersistentFlags().Lookup("dc-ip"); f != nil {
		if v := f.Value.String(); v != "" {
			dcIP = v
		}
	}
	return tui.AppContext{
		DCIP:     dcIP,
		Domain:   common.Domain,
		Username: common.Username,
		Password: common.Password,
		NTHash:   common.NTLMHash,
	}
}

// loadUserConfigSafe charge la config utilisateur (~/.adgo/config.yaml).
// Retourne nil si le fichier n'existe pas.
func loadUserConfigSafe() *configuration.UserConfig {
	return configuration.LoadUserConfig()
}

// injectFlagIfEmpty injecte value dans le flag flagName seulement s'il n'a pas été
// fourni explicitement en CLI. Cherche dans les flags persistants du rootCmd.
func injectFlagIfEmpty(cmd *cobra.Command, flagName, value string) {
	if value == "" {
		return
	}
	if f := cmd.Root().PersistentFlags().Lookup(flagName); f != nil && !f.Changed {
		f.Value.Set(value)
	}
}

// ============================================================
// Sub-commandes TUI
// ============================================================

// tuiScanCmd lance le dashboard de scan réseau directement.
var tuiScanCmd = &cobra.Command{
	Use:     "scan [target]",
	Short:   "Live network scan dashboard",
	Example: `adgo tui scan 192.168.1.0/24 -u admin -p pass -d LAB`,
	Args:    cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := ""
		if len(args) > 0 {
			target = args[0]
		}
		ctx := buildAppContext(cmd)
		return tui.RunTUICommand(tui.ViewDashboard, ctx, map[string]interface{}{
			"target": target,
			"total":  0,
		})
	},
}

// tuiSprayCmd lance la vue spray.
var tuiSprayCmd = &cobra.Command{
	Use:   "spray",
	Short: "Password spray with live results",
	RunE: func(cmd *cobra.Command, args []string) error {
		usersFile, _ := cmd.Flags().GetString("users")
		passwdsFile, _ := cmd.Flags().GetString("passwords")
		delay, _ := cmd.Flags().GetInt("delay")
		threads, _ := cmd.Flags().GetInt("threads")

		if usersFile == "" || passwdsFile == "" {
			return fmt.Errorf("--users and --passwords are required")
		}

		ctx := buildAppContext(cmd)
		return tui.RunTUICommand(tui.ViewSpray, ctx, map[string]interface{}{
			"users_file":     usersFile,
			"passwords_file": passwdsFile,
			"delay":          delay,
			"threads":        threads,
		})
	},
}

// tuiKerberoastCmd lance la vue kerberoast.
var tuiKerberoastCmd = &cobra.Command{
	Use:   "kerberoast",
	Short: "Kerberoast with live hash capture",
	RunE: func(cmd *cobra.Command, args []string) error {
		usersFile, _ := cmd.Flags().GetString("users")
		forceRC4, _ := cmd.Flags().GetBool("force-rc4")
		output, _ := cmd.Flags().GetString("output")

		ctx := buildAppContext(cmd)
		return tui.RunTUICommand(tui.ViewKerberos, ctx, map[string]interface{}{
			"mode":        "kerberoast",
			"users_file":  usersFile,
			"force_rc4":   forceRC4,
			"output_file": output,
		})
	},
}

// tuiASREPRoastCmd lance la vue AS-REP roast.
var tuiASREPRoastCmd = &cobra.Command{
	Use:   "asreproast",
	Short: "AS-REP Roast with live hash capture",
	RunE: func(cmd *cobra.Command, args []string) error {
		usersFile, _ := cmd.Flags().GetString("users")
		output, _ := cmd.Flags().GetString("output")

		ctx := buildAppContext(cmd)
		return tui.RunTUICommand(tui.ViewKerberos, ctx, map[string]interface{}{
			"mode":        "asreproast",
			"users_file":  usersFile,
			"output_file": output,
		})
	},
}

// tuiUserEnumCmd lance la vue user enumeration.
var tuiUserEnumCmd = &cobra.Command{
	Use:   "userenum",
	Short: "Kerberos user enumeration (no credentials needed)",
	RunE: func(cmd *cobra.Command, args []string) error {
		usersFile, _ := cmd.Flags().GetString("users")
		if usersFile == "" {
			return fmt.Errorf("--users is required")
		}
		ctx := buildAppContext(cmd)
		return tui.RunTUICommand(tui.ViewKerberos, ctx, map[string]interface{}{
			"mode":       "userenum",
			"users_file": usersFile,
		})
	},
}

// tuiKersprayCmd lance la vue kerberos spray.
var tuiKersprayCmd = &cobra.Command{
	Use:   "kerspray",
	Short: "Kerberos password spray (stealth — generates Event 4768 not 4625)",
	RunE: func(cmd *cobra.Command, args []string) error {
		usersFile, _ := cmd.Flags().GetString("users")
		ctx := buildAppContext(cmd)
		return tui.RunTUICommand(tui.ViewKerberos, ctx, map[string]interface{}{
			"mode":       "kerspray",
			"users_file": usersFile,
		})
	},
}

// tuiPlaybookCmd lance la vue playbook.
var tuiPlaybookCmd = &cobra.Command{
	Use:   "playbook [file]",
	Short: "Run a playbook with live step output",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := buildAppContext(cmd)
		return tui.RunTUICommand(tui.ViewPlaybook, ctx, map[string]interface{}{
			"path": args[0],
		})
	},
}

// tuiSessionCmd lance la vue session.
var tuiSessionCmd = &cobra.Command{
	Use:   "session",
	Short: "View discovered credentials and hosts from current session",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := buildAppContext(cmd)
		return tui.RunTUICommand(tui.ViewSession, ctx, nil)
	},
}

// tuiConfigCmd lance la vue configuration.
var tuiConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage persistent ADgo settings",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := buildAppContext(cmd)
		return tui.RunTUICommand(tui.ViewConfig, ctx, nil)
	},
}

// ============================================================
// init — enregistrement des sous-commandes et flags
// ============================================================

func init() {
	// tuiSprayCmd flags
	tuiSprayCmd.Flags().String("users", "", "Path to usernames file")
	tuiSprayCmd.Flags().String("passwords", "", "Path to passwords file")
	tuiSprayCmd.Flags().Int("delay", 30, "Delay between attempts (seconds)")
	tuiSprayCmd.Flags().Int("threads", 1, "Concurrent threads")

	// tuiKerberoastCmd flags
	tuiKerberoastCmd.Flags().String("users", "", "Path to usernames file")
	tuiKerberoastCmd.Flags().Bool("force-rc4", false, "Force RC4-HMAC downgrade")
	tuiKerberoastCmd.Flags().String("output", "", "Save hashes to file")

	// tuiASREPRoastCmd flags
	tuiASREPRoastCmd.Flags().String("users", "", "Path to usernames file")
	tuiASREPRoastCmd.Flags().String("output", "", "Save hashes to file")

	// tuiUserEnumCmd flags
	tuiUserEnumCmd.Flags().String("users", "", "Path to usernames file")

	// tuiKersprayCmd flags
	tuiKersprayCmd.Flags().String("users", "", "Path to usernames file")

	// Enregistrer toutes les sous-commandes
	TUICmd.AddCommand(
		tuiScanCmd,
		tuiSprayCmd,
		tuiKerberoastCmd,
		tuiASREPRoastCmd,
		tuiUserEnumCmd,
		tuiKersprayCmd,
		tuiPlaybookCmd,
		tuiSessionCmd,
		tuiConfigCmd,
	)
}
