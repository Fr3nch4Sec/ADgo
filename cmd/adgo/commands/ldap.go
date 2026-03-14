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

// buildLDAPURL construit l'URL LDAP depuis une IP ou hostname.
// Si l'IP est déjà une URL complète, on la retourne telle quelle.
func buildLDAPURL(dcIP string, useSSL bool) string {
	if strings.HasPrefix(dcIP, "ldap://") || strings.HasPrefix(dcIP, "ldaps://") {
		return dcIP
	}
	if useSSL {
		return fmt.Sprintf("ldaps://%s:636", dcIP)
	}
	return fmt.Sprintf("ldap://%s:389", dcIP)
}

// resolveLDAPServer retourne le serveur LDAP à utiliser :
//   - --dc-ip du flag si fourni
//   - sinon creds.LDAPServer (depuis config ou auto-découverte DNS)
func resolveLDAPServer(cmd *cobra.Command, creds *common.Credentials) string {
	if dcIP, _ := cmd.Flags().GetString("dc-ip"); dcIP != "" {
		return buildLDAPURL(dcIP, creds.UseSSL)
	}
	// S'assurer que LDAPServer a bien un scheme (ldap://)
	if creds.LDAPServer != "" && !strings.HasPrefix(creds.LDAPServer, "ldap") {
		return buildLDAPURL(creds.LDAPServer, creds.UseSSL)
	}
	return creds.LDAPServer
}

// newLDAPClient crée un client LDAP avec la bonne méthode d'auth.
// Si --dc-ip est fourni il override le serveur de creds.
func newLDAPClient(ctx context.Context, creds *common.Credentials, cmd *cobra.Command) (*ldap.Client, error) {
	server := resolveLDAPServer(cmd, creds)
	if server == "" {
		return nil, fmt.Errorf("no LDAP server: use --dc-ip 192.168.1.10 or -d domain.local for auto-discovery")
	}

	// NTLM (password ou PtH) si domain + username disponibles
	if creds.SMBDomain != "" && creds.SMBUsername != "" {
		return ldap.NewClientNTLM(
			ctx,
			server,
			creds.SMBDomain,
			creds.SMBUsername,
			creds.Password,
			creds.NTLMHash,
			creds.UseSSL,
		)
	}
	// Fallback : simple bind
	return ldap.NewClient(ctx, server, creds.BindDN, creds.Password, creds.UseSSL)
}

// domainToBaseDN convertit "lab.local" → "DC=lab,DC=local"
func domainToBaseDNfromCreds(creds *common.Credentials) string {
	if creds.BaseDN != "" {
		return creds.BaseDN
	}
	// Construire depuis le domain
	domain := creds.SMBDomain
	if domain == "" {
		return ""
	}
	parts := strings.Split(strings.ToLower(domain), ".")
	dcs := make([]string, len(parts))
	for i, p := range parts {
		dcs[i] = "DC=" + p
	}
	return strings.Join(dcs, ",")
}

// ============================================================
// Output helpers
// ============================================================

func toBloodHoundJSONUsers(users []ldap.UserEntry) ([]map[string]interface{}, error) {
	var data []map[string]interface{}
	for _, u := range users {
		data = append(data, map[string]interface{}{
			"Properties": map[string]interface{}{
				"name":            u.Name,
				"samaccountname":  u.SAMAccountName,
				"lastlogon":       u.LastLogon,
				"enabled":         !strings.Contains(u.AccountControl, "DISABLED"),
				"passwordlastset": u.PwdLastSet,
				"spns":            u.SPNs,
			},
			"ObjectType": "User",
		})
	}
	return data, nil
}

func toBloodHoundJSONGroups(groups []ldap.GroupEntry) ([]map[string]interface{}, error) {
	var data []map[string]interface{}
	for _, g := range groups {
		data = append(data, map[string]interface{}{
			"Properties": map[string]interface{}{"name": g.Name},
			"ObjectType": "Group",
		})
	}
	return data, nil
}

func toBloodHoundJSONComputers(computers []ldap.ComputerEntry) ([]map[string]interface{}, error) {
	var data []map[string]interface{}
	for _, c := range computers {
		data = append(data, map[string]interface{}{
			"Properties": map[string]interface{}{"name": c.Name},
			"ObjectType": "Computer",
		})
	}
	return data, nil
}

func writeBloodHoundFile(data []map[string]interface{}, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("cannot create %s: %v", filename, err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

// ============================================================
// Commandes LDAP
// ============================================================

var LDAPUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Enumerate domain users (NTLM + Pass-the-Hash supported)",
	Example: `
  adgo ldap users --dc-ip 192.168.1.10 -u admin -p Password123 -d LAB
  adgo ldap users --dc-ip 192.168.1.10 -u admin --hash aad3b435b51404ee... -d LAB
  adgo ldap users --dc-ip 192.168.1.10 -u admin -p pass -d LAB --csv users.csv
  adgo ldap users --dc-ip 192.168.1.10 -u admin -p pass -d LAB --disabled-only`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		creds, err := common.LoadCredentials()
		if err != nil {
			return fmt.Errorf("credentials error: %v\nUsage: adgo ldap users --dc-ip <IP> -u <USER> -p <PASS> -d <DOMAIN>", err)
		}

		debug, _ := cmd.Flags().GetBool("debug")
		jsonOut, _ := cmd.Flags().GetBool("json")
		bloodhound, _ := cmd.Flags().GetBool("bloodhound")
		csvOutput, _ := cmd.Flags().GetString("csv")
		filter, _ := cmd.Flags().GetString("filter")
		disabledOnly, _ := cmd.Flags().GetBool("disabled-only")

		server := resolveLDAPServer(cmd, creds)
		common.PrintInfo(fmt.Sprintf("LDAP → %s as %s\\%s", server, strings.ToUpper(creds.SMBDomain), creds.SMBUsername))

		client, err := newLDAPClient(ctx, creds, cmd)
		if err != nil {
			return fmt.Errorf("LDAP connection failed: %v", err)
		}
		defer client.Close()

		baseDN := domainToBaseDNfromCreds(creds)
		users, err := client.EnumerateUsersWithFilter(baseDN, filter, disabledOnly)
		if err != nil {
			return fmt.Errorf("enumeration failed: %v", err)
		}

		common.PrintCount(len(users), "users")

		if csvOutput != "" {
			f, err := os.Create(csvOutput)
			if err != nil {
				return fmt.Errorf("cannot create CSV: %v", err)
			}
			defer f.Close()
			w := csv.NewWriter(f)
			w.Write([]string{"DN", "Name", "SAMAccountName", "LastLogon", "AccountControl", "PwdLastSet", "SPNs"})
			for _, u := range users {
				w.Write([]string{u.DN, u.Name, u.SAMAccountName, u.LastLogon, u.AccountControl, u.PwdLastSet, strings.Join(u.SPNs, ";")})
			}
			w.Flush()
			common.PrintSuccess(fmt.Sprintf("Saved: %s", csvOutput))
			return nil
		}

		if bloodhound {
			data, _ := toBloodHoundJSONUsers(users)
			writeBloodHoundFile(data, "bloodhound_users.json")
			common.PrintSuccess("BloodHound: bloodhound_users.json")
			return nil
		}

		common.PrintOutput(users, bloodhound, jsonOut, debug)
		return nil
	},
}

var LDAPGroupsCmd = &cobra.Command{
	Use:   "groups",
	Short: "Enumerate domain groups",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		creds, err := common.LoadCredentials()
		if err != nil {
			return fmt.Errorf("credentials error: %v", err)
		}
		debug, _ := cmd.Flags().GetBool("debug")
		jsonOut, _ := cmd.Flags().GetBool("json")
		bloodhound, _ := cmd.Flags().GetBool("bloodhound")

		client, err := newLDAPClient(ctx, creds, cmd)
		if err != nil {
			return fmt.Errorf("LDAP connection failed: %v", err)
		}
		defer client.Close()

		baseDN := domainToBaseDNfromCreds(creds)
		groups, err := client.EnumerateAllGroups(baseDN)
		if err != nil {
			return fmt.Errorf("enumeration failed: %v", err)
		}
		common.PrintCount(len(groups), "groups")

		if bloodhound {
			data, _ := toBloodHoundJSONGroups(groups)
			writeBloodHoundFile(data, "bloodhound_groups.json")
			common.PrintSuccess("BloodHound: bloodhound_groups.json")
			return nil
		}
		common.PrintOutput(groups, bloodhound, jsonOut, debug)
		return nil
	},
}

var LDAPComputersCmd = &cobra.Command{
	Use:   "computers",
	Short: "Enumerate domain computers",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		creds, err := common.LoadCredentials()
		if err != nil {
			return fmt.Errorf("credentials error: %v", err)
		}
		debug, _ := cmd.Flags().GetBool("debug")
		jsonOut, _ := cmd.Flags().GetBool("json")
		bloodhound, _ := cmd.Flags().GetBool("bloodhound")

		client, err := newLDAPClient(ctx, creds, cmd)
		if err != nil {
			return fmt.Errorf("LDAP connection failed: %v", err)
		}
		defer client.Close()

		baseDN := domainToBaseDNfromCreds(creds)
		computers, err := client.EnumerateAllComputers(baseDN)
		if err != nil {
			return fmt.Errorf("enumeration failed: %v", err)
		}
		common.PrintCount(len(computers), "computers")

		if bloodhound {
			data, _ := toBloodHoundJSONComputers(computers)
			writeBloodHoundFile(data, "bloodhound_computers.json")
			common.PrintSuccess("BloodHound: bloodhound_computers.json")
			return nil
		}
		common.PrintOutput(computers, bloodhound, jsonOut, debug)
		return nil
	},
}

var LDAPSPNsCmd = &cobra.Command{
	Use:   "spns",
	Short: "Enumerate Kerberoastable accounts (with SPNs)",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		creds, err := common.LoadCredentials()
		if err != nil {
			return fmt.Errorf("credentials error: %v", err)
		}
		debug, _ := cmd.Flags().GetBool("debug")
		jsonOut, _ := cmd.Flags().GetBool("json")
		bloodhound, _ := cmd.Flags().GetBool("bloodhound")

		client, err := newLDAPClient(ctx, creds, cmd)
		if err != nil {
			return fmt.Errorf("LDAP connection failed: %v", err)
		}
		defer client.Close()

		baseDN := domainToBaseDNfromCreds(creds)
		spns, err := client.EnumerateSPNs(baseDN)
		if err != nil {
			return fmt.Errorf("enumeration failed: %v", err)
		}
		common.PrintCount(len(spns), "SPN accounts (Kerberoastable)")
		common.PrintOutput(spns, bloodhound, jsonOut, debug)
		return nil
	},
}

var LDAPASREPRoastCmd = &cobra.Command{
	Use:   "asreproast",
	Short: "Enumerate AS-REP Roastable accounts (no pre-auth)",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		creds, err := common.LoadCredentials()
		if err != nil {
			return fmt.Errorf("credentials error: %v", err)
		}
		debug, _ := cmd.Flags().GetBool("debug")
		jsonOut, _ := cmd.Flags().GetBool("json")
		bloodhound, _ := cmd.Flags().GetBool("bloodhound")

		client, err := newLDAPClient(ctx, creds, cmd)
		if err != nil {
			return fmt.Errorf("LDAP connection failed: %v", err)
		}
		defer client.Close()

		baseDN := domainToBaseDNfromCreds(creds)
		users, err := client.EnumerateASREPRoastableUsers(baseDN)
		if err != nil {
			return fmt.Errorf("enumeration failed: %v", err)
		}
		common.PrintCount(len(users), "AS-REP Roastable accounts")
		common.PrintOutput(users, bloodhound, jsonOut, debug)
		return nil
	},
}

var LDAPPasswordPolicyCmd = &cobra.Command{
	Use:   "password-policy",
	Short: "Get domain password policy (lockout threshold, complexity...)",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		creds, err := common.LoadCredentials()
		if err != nil {
			return fmt.Errorf("credentials error: %v", err)
		}
		debug, _ := cmd.Flags().GetBool("debug")
		jsonOut, _ := cmd.Flags().GetBool("json")
		bloodhound, _ := cmd.Flags().GetBool("bloodhound")

		client, err := newLDAPClient(ctx, creds, cmd)
		if err != nil {
			return fmt.Errorf("LDAP connection failed: %v", err)
		}
		defer client.Close()

		baseDN := domainToBaseDNfromCreds(creds)
		policy, err := client.GetPasswordPolicy(baseDN)
		if err != nil {
			return fmt.Errorf("failed to get password policy: %v", err)
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
		c.Flags().String("dc-ip", "", "Domain Controller IP (e.g. 192.168.1.10)")
	}

	LDAPUsersCmd.Flags().String("filter", "", "Custom LDAP filter (e.g. 'name=*admin*')")
	LDAPUsersCmd.Flags().String("csv", "", "Export to CSV file")
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

var LDAPCmd = &cobra.Command{
	Use:   "ldap",
	Short: "LDAP enumeration (users, groups, computers, SPNs, policy)",
	Long: `Enumerate Active Directory objects via LDAP.
Supports password, NTLM, and Pass-the-Hash authentication.

Examples:
  adgo ldap users     --dc-ip 192.168.1.10 -u admin -p pass -d LAB
  adgo ldap groups    --dc-ip 192.168.1.10 -u admin --hash aad3b435... -d LAB
  adgo ldap computers --dc-ip 192.168.1.10 -u admin -p pass -d LAB
  adgo ldap spns      --dc-ip 192.168.1.10 -u admin -p pass -d LAB
  adgo ldap password-policy --dc-ip 192.168.1.10 -u admin -p pass -d LAB`,
}
