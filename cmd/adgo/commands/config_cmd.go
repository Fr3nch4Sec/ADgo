// cmd/adgo/commands/config_cmd.go
//
// adgo config set <key> <value>  — sauvegarder un paramètre
// adgo config get <key>          — lire un paramètre
// adgo config show               — afficher toute la config
// adgo config clear              — supprimer la config

package commands

import (
	"fmt"
	"strings"

	"adgo/pkg/common"
	"adgo/pkg/configuration"

	"github.com/spf13/cobra"
)

var ConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage persistent configuration (~/.adgo/config.yaml)",
	Long: `Save frequently used parameters to avoid retyping them.

Priority: CLI flags > environment variables > user config > defaults

Examples:
  # Save your lab settings once
  adgo config set dc-ip 192.168.1.10
  adgo config set domain lab.local
  adgo config set username admin
  adgo config set workers 100

  # Then run commands without repeating flags
  adgo ldap users --dc-ip (uses saved value)
  adgo bloodhound         (uses saved dc-ip, domain, username)

  # Show current config
  adgo config show

  # Remove a specific key
  adgo config unset dc-ip

  # Remove all config
  adgo config clear`,
}

// adgo config set <key> <value>
var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Save a configuration value",
	Args:  cobra.ExactArgs(2),
	Example: `  adgo config set dc-ip 192.168.1.10
  adgo config set domain lab.local
  adgo config set username administrator
  adgo config set workers 100
  adgo config set timeout 3
  adgo config set playbooks-dir ./playbooks`,
	RunE: func(cmd *cobra.Command, args []string) error {
		key, value := args[0], args[1]

		if err := configuration.SetField(key, value); err != nil {
			return err
		}

		common.PrintSuccess(fmt.Sprintf("Saved: %s = %s", key, maskIfSensitive(key, value)))
		fmt.Printf("  Config file: %s\n", configuration.ConfigPath())
		return nil
	},
}

// adgo config get <key>
var configGetCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Read a configuration value",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := configuration.LoadUserConfig()
		key := strings.ToLower(args[0])

		rows := configuration.FormatUserConfig(cfg)
		for _, row := range rows {
			if strings.ToLower(row[0]) == key {
				fmt.Printf("%s = %s\n", row[0], maskIfSensitive(row[0], row[1]))
				return nil
			}
		}

		common.PrintWarning(fmt.Sprintf("Key %q not set (use: adgo config set %s <value>)", key, key))
		return nil
	},
}

// adgo config show
var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Display all saved configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := configuration.LoadUserConfig()
		rows := configuration.FormatUserConfig(cfg)

		fmt.Printf("Config file: %s\n\n", configuration.ConfigPath())

		if len(rows) == 0 {
			common.PrintWarning("No configuration saved yet.")
			fmt.Println()
			fmt.Println("Save your settings with:")
			fmt.Println("  adgo config set dc-ip 192.168.1.10")
			fmt.Println("  adgo config set domain lab.local")
			fmt.Println("  adgo config set username admin")
			return nil
		}

		common.PrintTable([]string{"KEY", "VALUE"}, rows)

		fmt.Println()
		fmt.Println("These values are used as defaults when CLI flags are not provided.")
		fmt.Println("CLI flags always take priority over saved config.")
		return nil
	},
}

// adgo config unset <key>
var configUnsetCmd = &cobra.Command{
	Use:   "unset <key>",
	Short: "Remove a configuration value",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		key := args[0]
		if err := configuration.UnsetField(key); err != nil {
			return err
		}
		common.PrintSuccess(fmt.Sprintf("Removed: %s", key))
		return nil
	},
}

// adgo config clear
var configClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Delete all saved configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := configuration.ClearUserConfig(); err != nil {
			return err
		}
		common.PrintSuccess("Configuration cleared.")
		return nil
	},
}

// maskIfSensitive masque les valeurs sensibles pour l'affichage
func maskIfSensitive(key, value string) string {
	k := strings.ToLower(key)
	if k == "password" || k == "hash" || k == "ntlm" {
		if len(value) > 4 {
			return value[:2] + strings.Repeat("*", len(value)-2)
		}
		return "****"
	}
	return value
}

func init() {
	ConfigCmd.AddCommand(configSetCmd)
	ConfigCmd.AddCommand(configGetCmd)
	ConfigCmd.AddCommand(configShowCmd)
	ConfigCmd.AddCommand(configUnsetCmd)
	ConfigCmd.AddCommand(configClearCmd)
}
