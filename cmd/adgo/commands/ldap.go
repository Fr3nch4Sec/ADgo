// cmd/adgo/commands/ldap.go
package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"adgo/pkg/common"
	"adgo/pkg/ldap"

	"github.com/spf13/cobra"
)

// toBloodHoundJSONUsers convertit une liste d'utilisateurs en format BloodHound.
func toBloodHoundJSONUsers(users []*ldap.UserEntry) ([]map[string]interface{}, error) {
	var bloodHoundData []map[string]interface{}
	for _, user := range users {
		bloodHoundData = append(bloodHoundData, map[string]interface{}{
			"Properties": map[string]interface{}{
				"name":           user.Name,
				"samaccountname": user.SAMAccountName,
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

// LDAPUsersCmd énumère les utilisateurs via LDAP.
var LDAPUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Enumerate domain users via LDAP",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		creds, err := common.LoadCredentials()
		if err != nil {
			return common.WrapError("failed to load credentials", err)
		}

		debug, _ := cmd.Flags().GetBool("debug")
		jsonOut, _ := cmd.Flags().GetBool("json")
		bloodhound, _ := cmd.Flags().GetBool("bloodhound")

		common.PrintDebug(fmt.Sprintf("Connecting to LDAP server: %s", creds.LDAPServer), debug)

		client, err := ldap.NewClient(ctx, creds.LDAPServer, creds.BindDN, creds.Password, creds.UseSSL)
		if err != nil {
			return common.WrapError("failed to create LDAP client", err)
		}
		defer client.Close()

		users, err := client.EnumerateAllUsers(creds.BaseDN)
		if err != nil {
			return common.WrapError("failed to enumerate users", err)
		}

		// Gestion du format BloodHound
		if bloodhound {
			var bloodHoundData []map[string]interface{}
			for _, user := range users {
				bloodHoundData = append(bloodHoundData, map[string]interface{}{
					"Properties": map[string]interface{}{
						"name":           user.Name,
						"samaccountname": user.SamAccount,
					},
					"ObjectType": "User",
				})
			}
			if err := writeBloodHoundFile(bloodHoundData, "bloodhound_users.json"); err != nil {
				return common.WrapError("failed to write BloodHound file", err)
			}
			fmt.Println("BloodHound output written to bloodhound_users.json")
			return nil
		}

		// Format standard (JSON/tableau)
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

	LDAPCmd.AddCommand(LDAPUsersCmd)
	LDAPCmd.AddCommand(LDAPGroupsCmd)
	LDAPCmd.AddCommand(LDAPComputersCmd)
	LDAPCmd.AddCommand(LDAPSPNsCmd)
	LDAPCmd.AddCommand(LDAPASREPRoastCmd)
	LDAPCmd.AddCommand(LDAPPasswordPolicyCmd)
}

// LDAPCmd est la commande racine pour les opérations LDAP.
var LDAPCmd = &cobra.Command{
	Use:   "ldap",
	Short: "LDAP operations",
}
