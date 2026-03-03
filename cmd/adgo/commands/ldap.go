// cmd/adgo/commands/ldap.go
package commands

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"adgo/pkg/common"
	"adgo/pkg/ldap"

	"github.com/spf13/cobra"
)

// toBloodHoundJSONUsers convertit les utilisateurs en format BloodHound (avec métadonnées).
func toBloodHoundJSONUsers(users []ldap.UserEntry) ([]map[string]interface{}, error) {
	var bloodHoundData []map[string]interface{}
	for _, user := range users {
		bloodHoundData = append(bloodHoundData, map[string]interface{}{
			"Properties": map[string]interface{}{
				"name":            user.Name,
				"samaccountname":  user.SAMAccountName,
				"lastlogon":       user.LastLogon,
				"enabled":         !strings.Contains(user.AccountControl, "DISABLED"),
				"passwordlastset": user.PwdLastSet,
				"spns":            user.SPNs,
			},
			"ObjectType": "User",
		})
	}
	return bloodHoundData, nil
}

// toBloodHoundJSONGroups convertit une liste de groupes en format BloodHound.
func toBloodHoundJSONGroups(groups []ldap.GroupEntry) ([]map[string]interface{}, error) {
	var bloodHoundData []map[string]interface{}
	for _, group := range groups {
		bloodHoundData = append(bloodHoundData, map[string]interface{}{
			"Properties": map[string]interface{}{
				"name": group.Name,
			},
			"ObjectType": "Group",
		})
	}
	return bloodHoundData, nil
}

// toBloodHoundJSONComputers convertit une liste d'ordinateurs en format BloodHound.
func toBloodHoundJSONComputers(computers []ldap.ComputerEntry) ([]map[string]interface{}, error) {
	var bloodHoundData []map[string]interface{}
	for _, computer := range computers {
		bloodHoundData = append(bloodHoundData, map[string]interface{}{
			"Properties": map[string]interface{}{
				"name": computer.Name,
			},
			"ObjectType": "Computer",
		})
	}
	return bloodHoundData, nil
}

// writeBloodHoundFile écrit les données BloodHound dans un fichier JSON.
func writeBloodHoundFile(data []map[string]interface{}, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create BloodHound file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to write BloodHound data: %v", err)
	}
	return nil
}

// LDAPUsersCmd énumère les utilisateurs via LDAP avec support pour :
// - Filtrage personnalisé (--filter)
// - Comptes désactivés (--disabled-only)
// - Export CSV enrichi (--csv)
// - Sortie JSON/BloodHound
var LDAPUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Enumerate domain users via LDAP",
	Example: `
  # List all users
  adgo ldap users

  # Filter users (ex: names containing "admin")
  adgo ldap users --filter "name=*admin*"

  # List deactivated accounts
  adgo ldap users --disabled-only --csv disabled_users.csv

  # Export to CSV with details
  adgo ldap users --csv users_details.csv

  # JSON output
  adgo ldap users --json

  # BloodHound output
  adgo ldap users --bloodhound`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		creds, err := common.LoadCredentials()
		if err != nil {
			return common.WrapError("failed to load credentials", err)
		}

		debug, _ := cmd.Flags().GetBool("debug")
		jsonOut, _ := cmd.Flags().GetBool("json")
		bloodhound, _ := cmd.Flags().GetBool("bloodhound")
		csvOutput, _ := cmd.Flags().GetString("csv")
		filter, _ := cmd.Flags().GetString("filter")
		disabledOnly, _ := cmd.Flags().GetBool("disabled-only")

		common.PrintDebug(fmt.Sprintf("Connecting to LDAP server: %s (Filter: %s, DisabledOnly: %v)",
			creds.LDAPServer, filter, disabledOnly), debug)

		client, err := ldap.NewClient(ctx, creds.LDAPServer, creds.BindDN, creds.Password, creds.UseSSL)
		if err != nil {
			return common.WrapError("failed to create LDAP client", err)
		}
		defer client.Close()

		// Appel à la fonction avec tous les paramètres
		users, err := client.EnumerateUsersWithFilter(creds.BaseDN, filter, disabledOnly)
		if err != nil {
			return common.WrapError("failed to enumerate users", err)
		}

		// Export CSV si demandé
		if csvOutput != "" {
			file, err := os.Create(csvOutput)
			if err != nil {
				return common.WrapError(fmt.Sprintf("failed to create CSV file: %s", csvOutput), err)
			}
			defer file.Close()

			w := csv.NewWriter(file)
			if err := w.Write([]string{
				"DN", "Name", "SAMAccountName", "LastLogon", "AccountControl", "PwdLastSet", "SPNs",
			}); err != nil {
				return common.WrapError("failed to write CSV header", err)
			}

			for _, user := range users {
				if err := w.Write([]string{
					user.DN,
					user.Name,
					user.SAMAccountName,
					user.LastLogon,
					user.AccountControl,
					user.PwdLastSet,
					strings.Join(user.SPNs, ";"),
				}); err != nil {
					return common.WrapError("failed to write CSV row", err)
				}
			}
			w.Flush()
			fmt.Printf("CSV output written to %s\n", csvOutput)
			return nil
		}

		// Sortie BloodHound
		if bloodhound {
			bloodHoundData, err := toBloodHoundJSONUsers(users)
			if err != nil {
				return common.WrapError("failed to convert to BloodHound format", err)
			}
			if err := writeBloodHoundFile(bloodHoundData, "bloodhound_users.json"); err != nil {
				return common.WrapError("failed to write BloodHound file", err)
			}
			fmt.Println("BloodHound output written to bloodhound_users.json")
			return nil
		}

		// Sortie JSON ou tableau standard
		common.PrintOutput(users, bloodhound, jsonOut, debug)
		return nil
	},
}

// LDAPGroupsCmd énumère les groupes via LDAP.
var LDAPGroupsCmd = &cobra.Command{
	Use:   "groups",
	Short: "Enumerate domain groups via LDAP",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		creds, err := common.LoadCredentials()
		if err != nil {
			return common.WrapError("failed to load credentials", err)
		}

		debug, _ := cmd.Flags().GetBool("debug")
		jsonOut, _ := cmd.Flags().GetBool("json")
		bloodhound, _ := cmd.Flags().GetBool("bloodhound")

		client, err := ldap.NewClient(ctx, creds.LDAPServer, creds.BindDN, creds.Password, creds.UseSSL)
		if err != nil {
			return common.WrapError("failed to create LDAP client", err)
		}
		defer client.Close()

		groups, err := client.EnumerateAllGroups(creds.BaseDN)
		if err != nil {
			return common.WrapError("failed to enumerate groups", err)
		}

		// Gestion du format BloodHound
		if bloodhound {
			var bloodHoundData []map[string]interface{}
			for _, group := range groups {
				bloodHoundData = append(bloodHoundData, map[string]interface{}{
					"Properties": map[string]interface{}{
						"name": group.Name,
					},
					"ObjectType": "Group",
				})
			}
			if err := writeBloodHoundFile(bloodHoundData, "bloodhound_groups.json"); err != nil {
				return common.WrapError("failed to write BloodHound file", err)
			}
			fmt.Println("BloodHound output written to bloodhound_groups.json")
			return nil
		}

		// Format standard
		common.PrintOutput(groups, bloodhound, jsonOut, debug)
		return nil
	},
}

// LDAPComputersCmd énumère les ordinateurs via LDAP.
var LDAPComputersCmd = &cobra.Command{
	Use:   "computers",
	Short: "Enumerate domain computers via LDAP",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		creds, err := common.LoadCredentials()
		if err != nil {
			return common.WrapError("failed to load credentials", err)
		}

		debug, _ := cmd.Flags().GetBool("debug")
		jsonOut, _ := cmd.Flags().GetBool("json")
		bloodhound, _ := cmd.Flags().GetBool("bloodhound")

		client, err := ldap.NewClient(ctx, creds.LDAPServer, creds.BindDN, creds.Password, creds.UseSSL)
		if err != nil {
			return common.WrapError("failed to create LDAP client", err)
		}
		defer client.Close()

		computers, err := client.EnumerateAllComputers(creds.BaseDN)
		if err != nil {
			return common.WrapError("failed to enumerate computers", err)
		}

		// Gestion du format BloodHound
		if bloodhound {
			var bloodHoundData []map[string]interface{}
			for _, computer := range computers {
				bloodHoundData = append(bloodHoundData, map[string]interface{}{
					"Properties": map[string]interface{}{
						"name": computer.Name,
					},
					"ObjectType": "Computer",
				})
			}
			if err := writeBloodHoundFile(bloodHoundData, "bloodhound_computers.json"); err != nil {
				return common.WrapError("failed to write BloodHound file", err)
			}
			fmt.Println("BloodHound output written to bloodhound_computers.json")
			return nil
		}

		// Format standard
		common.PrintOutput(computers, bloodhound, jsonOut, debug)
		return nil
	},
}

// LDAPSPNsCmd énumère les utilisateurs avec des SPNs via LDAP.
var LDAPSPNsCmd = &cobra.Command{
	Use:   "spns",
	Short: "Enumerate users with SPNs via LDAP",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		creds, err := common.LoadCredentials()
		if err != nil {
			return common.WrapError("failed to load credentials", err)
		}

		debug, _ := cmd.Flags().GetBool("debug")
		jsonOut, _ := cmd.Flags().GetBool("json")
		bloodhound, _ := cmd.Flags().GetBool("bloodhound")

		client, err := ldap.NewClient(ctx, creds.LDAPServer, creds.BindDN, creds.Password, creds.UseSSL)
		if err != nil {
			return common.WrapError("failed to create LDAP client", err)
		}
		defer client.Close()

		spns, err := client.EnumerateSPNs(creds.BaseDN)
		if err != nil {
			return common.WrapError("failed to enumerate SPNs", err)
		}

		// BloodHound n'est pas directement compatible avec les SPNs, donc on utilise le format standard
		common.PrintOutput(spns, bloodhound, jsonOut, debug)
		return nil
	},
}

// LDAPASREPRoastCmd énumère les utilisateurs vulnérables à AS-REP Roasting.
var LDAPASREPRoastCmd = &cobra.Command{
	Use:   "asreproast",
	Short: "Perform AS-REP Roasting attack",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		creds, err := common.LoadCredentials()
		if err != nil {
			return common.WrapError("failed to load credentials", err)
		}

		debug, _ := cmd.Flags().GetBool("debug")
		jsonOut, _ := cmd.Flags().GetBool("json")
		bloodhound, _ := cmd.Flags().GetBool("bloodhound")

		client, err := ldap.NewClient(ctx, creds.LDAPServer, creds.BindDN, creds.Password, creds.UseSSL)
		if err != nil {
			return common.WrapError("failed to create LDAP client", err)
		}
		defer client.Close()

		users, err := client.EnumerateASREPRoastableUsers(creds.BaseDN)
		if err != nil {
			return common.WrapError("failed to enumerate AS-REP Roastable users", err)
		}

		// BloodHound n'est pas directement compatible avec AS-REP Roast, donc on utilise le format standard
		common.PrintOutput(users, bloodhound, jsonOut, debug)
		return nil
	},
}

// LDAPPasswordPolicyCmd récupère les politiques de mot de passe via LDAP.
var LDAPPasswordPolicyCmd = &cobra.Command{
	Use:   "password-policy",
	Short: "Get domain password policy via LDAP",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		creds, err := common.LoadCredentials()
		if err != nil {
			return common.WrapError("failed to load credentials", err)
		}

		debug, _ := cmd.Flags().GetBool("debug")
		jsonOut, _ := cmd.Flags().GetBool("json")
		bloodhound, _ := cmd.Flags().GetBool("bloodhound")

		client, err := ldap.NewClient(ctx, creds.LDAPServer, creds.BindDN, creds.Password, creds.UseSSL)
		if err != nil {
			return common.WrapError("failed to create LDAP client", err)
		}
		defer client.Close()

		policy, err := client.GetPasswordPolicy(creds.BaseDN)
		if err != nil {
			return common.WrapError("failed to get password policy", err)
		}

		// BloodHound n'est pas compatible avec les politiques de mot de passe
		common.PrintOutput(policy, bloodhound, jsonOut, debug)
		return nil
	},
}

func init() {
	// Flags communs à toutes les commandes LDAP
	for _, cmd := range []*cobra.Command{
		LDAPUsersCmd,
		LDAPGroupsCmd,
		LDAPComputersCmd,
		LDAPSPNsCmd,
		LDAPASREPRoastCmd,
		LDAPPasswordPolicyCmd,
	} {
		cmd.Flags().Bool("debug", false, "Enable debug output")
		cmd.Flags().Bool("json", false, "Output in JSON format")
		cmd.Flags().Bool("bloodhound", false, "Output in BloodHound format")
	}

	// Flags spécifiques à LDAPUsersCmd
	LDAPUsersCmd.Flags().String("filter", "", "LDAP filter (e.g., 'name=*admin*')")
	LDAPUsersCmd.Flags().String("csv", "", "Output to CSV file (e.g., 'users.csv')")
	LDAPUsersCmd.Flags().Bool("disabled-only", false, "List only disabled user accounts")

	// Ajout des commandes au parent LDAPCmd
	LDAPCmd.AddCommand(
		LDAPUsersCmd,
		LDAPGroupsCmd,
		LDAPComputersCmd,
		LDAPSPNsCmd,
		LDAPASREPRoastCmd,
		LDAPPasswordPolicyCmd,
	)
}

// LDAPCmd est la commande racine pour les opérations LDAP.
var LDAPCmd = &cobra.Command{
	Use:   "ldap",
	Short: "LDAP operations",
}
