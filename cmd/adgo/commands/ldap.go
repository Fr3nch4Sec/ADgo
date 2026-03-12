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

// newLDAPClient crée un client LDAP en choisissant automatiquement
// la méthode d'authentification (simple bind, NTLM password, NTLM PtH).
// C'est le point d'entrée unique pour toutes les commandes LDAP.
func newLDAPClient(ctx context.Context, creds *common.Credentials) (*ldap.Client, error) {
	// NTLM (avec mot de passe ou Pass-the-Hash) si domain + username sont disponibles
	if creds.SMBDomain != "" && creds.SMBUsername != "" {
		return ldap.NewClientNTLM(
			ctx,
			creds.LDAPServer,
			creds.SMBDomain,
			creds.SMBUsername,
			creds.Password,
			creds.NTLMHash,
			creds.UseSSL,
		)
	}
	// Fallback : simple bind (BindDN + password)
	return ldap.NewClient(ctx, creds.LDAPServer, creds.BindDN, creds.Password, creds.UseSSL)
}

// toBloodHoundJSONUsers convertit les utilisateurs en format BloodHound
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

func writeBloodHoundFile(data []map[string]interface{}, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create BloodHound file: %v", err)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// LDAPUsersCmd énumère les utilisateurs via LDAP
var LDAPUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Enumerate domain users via LDAP (supports NTLM + Pass-the-Hash)",
	Example: `
  # Simple bind
  adgo ldap users --dc-ip 192.168.1.10 -u admin@lab.local -p Password123

  # NTLM authentication (domain + username)
  adgo ldap users --dc-ip 192.168.1.10 -u admin -p Password123 -d LAB

  # Pass-the-Hash
  adgo ldap users --dc-ip 192.168.1.10 -u admin --hash aad3b435... -d LAB

  # Export CSV
  adgo ldap users --dc-ip 192.168.1.10 -u admin -p pass -d LAB --csv users.csv

  # Comptes désactivés seulement
  adgo ldap users --dc-ip 192.168.1.10 -u admin -p pass -d LAB --disabled-only`,
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

		common.PrintInfo(fmt.Sprintf("Connecting to %s as %s\\%s",
			creds.LDAPServer, creds.SMBDomain, creds.SMBUsername))

		client, err := newLDAPClient(ctx, creds)
		if err != nil {
			return common.WrapError("LDAP connection failed", err)
		}
		defer client.Close()

		users, err := client.EnumerateUsersWithFilter(creds.BaseDN, filter, disabledOnly)
		if err != nil {
			return common.WrapError("failed to enumerate users", err)
		}

		common.PrintCount(len(users), "users")

		if csvOutput != "" {
			file, err := os.Create(csvOutput)
			if err != nil {
				return common.WrapError("failed to create CSV", err)
			}
			defer file.Close()
			w := csv.NewWriter(file)
			w.Write([]string{"DN", "Name", "SAMAccountName", "LastLogon", "AccountControl", "PwdLastSet", "SPNs"})
			for _, user := range users {
				w.Write([]string{
					user.DN, user.Name, user.SAMAccountName,
					user.LastLogon, user.AccountControl, user.PwdLastSet,
					strings.Join(user.SPNs, ";"),
				})
			}
			w.Flush()
			common.PrintSuccess(fmt.Sprintf("CSV saved: %s", csvOutput))
			return nil
		}

		if bloodhound {
			data, _ := toBloodHoundJSONUsers(users)
			writeBloodHoundFile(data, "bloodhound_users.json")
			common.PrintSuccess("BloodHound output: bloodhound_users.json")
			return nil
		}

		common.PrintOutput(users, bloodhound, jsonOut, debug)
		return nil
	},
}

// LDAPGroupsCmd énumère les groupes via LDAP
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

		client, err := newLDAPClient(ctx, creds)
		if err != nil {
			return common.WrapError("LDAP connection failed", err)
		}
		defer client.Close()

		groups, err := client.EnumerateAllGroups(creds.BaseDN)
		if err != nil {
			return common.WrapError("failed to enumerate groups", err)
		}
		common.PrintCount(len(groups), "groups")

		if bloodhound {
			data, _ := toBloodHoundJSONGroups(groups)
			writeBloodHoundFile(data, "bloodhound_groups.json")
			common.PrintSuccess("BloodHound output: bloodhound_groups.json")
			return nil
		}
		common.PrintOutput(groups, bloodhound, jsonOut, debug)
		return nil
	},
}

// LDAPComputersCmd énumère les ordinateurs via LDAP
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

		client, err := newLDAPClient(ctx, creds)
		if err != nil {
			return common.WrapError("LDAP connection failed", err)
		}
		defer client.Close()

		computers, err := client.EnumerateAllComputers(creds.BaseDN)
		if err != nil {
			return common.WrapError("failed to enumerate computers", err)
		}
		common.PrintCount(len(computers), "computers")

		if bloodhound {
			data, _ := toBloodHoundJSONComputers(computers)
			writeBloodHoundFile(data, "bloodhound_computers.json")
			common.PrintSuccess("BloodHound output: bloodhound_computers.json")
			return nil
		}
		common.PrintOutput(computers, bloodhound, jsonOut, debug)
		return nil
	},
}

// LDAPSPNsCmd énumère les SPNs via LDAP
var LDAPSPNsCmd = &cobra.Command{
	Use:   "spns",
	Short: "Enumerate users with SPNs (Kerberoastable accounts)",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		creds, err := common.LoadCredentials()
		if err != nil {
			return common.WrapError("failed to load credentials", err)
		}
		debug, _ := cmd.Flags().GetBool("debug")
		jsonOut, _ := cmd.Flags().GetBool("json")
		bloodhound, _ := cmd.Flags().GetBool("bloodhound")

		client, err := newLDAPClient(ctx, creds)
		if err != nil {
			return common.WrapError("LDAP connection failed", err)
		}
		defer client.Close()

		spns, err := client.EnumerateSPNs(creds.BaseDN)
		if err != nil {
			return common.WrapError("failed to enumerate SPNs", err)
		}
		common.PrintCount(len(spns), "SPN accounts (Kerberoastable)")
		common.PrintOutput(spns, bloodhound, jsonOut, debug)
		return nil
	},
}

// LDAPASREPRoastCmd énumère les comptes AS-REP Roastables
var LDAPASREPRoastCmd = &cobra.Command{
	Use:   "asreproast",
	Short: "Enumerate AS-REP Roastable accounts (no pre-auth required)",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		creds, err := common.LoadCredentials()
		if err != nil {
			return common.WrapError("failed to load credentials", err)
		}
		debug, _ := cmd.Flags().GetBool("debug")
		jsonOut, _ := cmd.Flags().GetBool("json")
		bloodhound, _ := cmd.Flags().GetBool("bloodhound")

		client, err := newLDAPClient(ctx, creds)
		if err != nil {
			return common.WrapError("LDAP connection failed", err)
		}
		defer client.Close()

		users, err := client.EnumerateASREPRoastableUsers(creds.BaseDN)
		if err != nil {
			return common.WrapError("failed to enumerate AS-REP roastable users", err)
		}
		common.PrintCount(len(users), "AS-REP Roastable accounts")
		common.PrintOutput(users, bloodhound, jsonOut, debug)
		return nil
	},
}

// LDAPPasswordPolicyCmd récupère la politique de mots de passe
var LDAPPasswordPolicyCmd = &cobra.Command{
	Use:   "password-policy",
	Short: "Get domain password policy (lockout threshold, complexity...)",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		creds, err := common.LoadCredentials()
		if err != nil {
			return common.WrapError("failed to load credentials", err)
		}
		debug, _ := cmd.Flags().GetBool("debug")
		jsonOut, _ := cmd.Flags().GetBool("json")
		bloodhound, _ := cmd.Flags().GetBool("bloodhound")

		client, err := newLDAPClient(ctx, creds)
		if err != nil {
			return common.WrapError("LDAP connection failed", err)
		}
		defer client.Close()

		policy, err := client.GetPasswordPolicy(creds.BaseDN)
		if err != nil {
			return common.WrapError("failed to get password policy", err)
		}
		common.PrintOutput(policy, bloodhound, jsonOut, debug)
		return nil
	},
}

func init() {
	// Flags communs à toutes les commandes LDAP
	for _, c := range []*cobra.Command{
		LDAPUsersCmd,
		LDAPGroupsCmd,
		LDAPComputersCmd,
		LDAPSPNsCmd,
		LDAPASREPRoastCmd,
		LDAPPasswordPolicyCmd,
	} {
		c.Flags().Bool("debug", false, "Enable debug output")
		c.Flags().Bool("json", false, "Output in JSON format")
		c.Flags().Bool("bloodhound", false, "Output in BloodHound CE format")
		c.Flags().String("dc-ip", "", "Domain Controller IP (overrides auto-discovery)")
	}

	// Flags spécifiques
	LDAPUsersCmd.Flags().String("filter", "", "Custom LDAP filter (e.g. 'name=*admin*')")
	LDAPUsersCmd.Flags().String("csv", "", "Export results to CSV file")
	LDAPUsersCmd.Flags().Bool("disabled-only", false, "Only list disabled accounts")

	LDAPCmd.AddCommand(
		LDAPUsersCmd,
		LDAPGroupsCmd,
		LDAPComputersCmd,
		LDAPSPNsCmd,
		LDAPASREPRoastCmd,
		LDAPPasswordPolicyCmd,
	)
}

// LDAPCmd est la commande racine pour les opérations LDAP
var LDAPCmd = &cobra.Command{
	Use:   "ldap",
	Short: "LDAP enumeration (users, groups, computers, SPNs, policy)",
	Long: `Enumerate Active Directory objects via LDAP.
Supports password authentication, NTLM, and Pass-the-Hash.

Examples:
  adgo ldap users -u admin -p pass -d LAB --dc-ip 192.168.1.10
  adgo ldap users -u admin --hash aad3b435... -d LAB --dc-ip 192.168.1.10
  adgo ldap groups --dc-ip 192.168.1.10 -u admin -p pass -d LAB
  adgo ldap spns --dc-ip 192.168.1.10 -u admin -p pass -d LAB`,
}
