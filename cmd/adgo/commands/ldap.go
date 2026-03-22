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

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/spf13/cobra"
)

// buildLDAPURL construit l'URL LDAP depuis une IP ou hostname.
func buildLDAPURL(dcIP string, useSSL bool) string {
	if strings.HasPrefix(dcIP, "ldap://") || strings.HasPrefix(dcIP, "ldaps://") {
		return dcIP
	}
	if useSSL {
		return fmt.Sprintf("ldaps://%s:636", dcIP)
	}
	return fmt.Sprintf("ldap://%s:389", dcIP)
}

// resolveLDAPServer retourne l'URL LDAP à utiliser.
// Priorité : --dc-ip flag local > DefaultDCIP (config) > creds.LDAPServer
func resolveLDAPServer(cmd *cobra.Command, useSSL bool) string {
	if dcIP, _ := cmd.Flags().GetString("dc-ip"); dcIP != "" {
		return buildLDAPURL(dcIP, useSSL)
	}
	if common.DefaultDCIP != "" {
		return buildLDAPURL(common.DefaultDCIP, useSSL)
	}
	return ""
}

// loadCredsForLDAP charge les credentials depuis les flags globaux uniquement.
// Ne tente PAS la découverte DNS — inutile et cassé en lab/CTF.
func loadCredsForLDAP() (*common.Credentials, error) {
	creds := &common.Credentials{
		SMBUsername: common.Username,
		SMBDomain:   common.Domain,
		Password:    common.Password,
		NTLMHash:    common.NTLMHash,
	}

	if creds.SMBUsername != "" && creds.SMBDomain != "" {
		creds.BindDN = creds.SMBUsername + "@" + creds.SMBDomain
	}

	return creds, nil
}

// newLDAPClientFromCmd crée un client LDAP en fonction des credentials disponibles.
// - Credentials complets → NTLM bind
// - Credentials vides   → anonymous bind (simple bind sans credentials)
func newLDAPClientFromCmd(ctx context.Context, cmd *cobra.Command) (*ldap.Client, *common.Credentials, error) {
	creds, _ := loadCredsForLDAP()

	server := resolveLDAPServer(cmd, false)
	if server == "" {
		return nil, nil, fmt.Errorf("--dc-ip required (e.g. --dc-ip 192.168.1.10)")
	}

	// Pas de credentials → anonymous bind
	if creds.SMBUsername == "" || creds.Password == "" && creds.NTLMHash == "" {
		common.PrintInfo(fmt.Sprintf("LDAP → %s (anonymous bind)", server))
		// Connexion sans bind NTLM — simple DialURL sans authentification
		conn, err := goldap.DialURL(server)
		if err != nil {
			return nil, creds, fmt.Errorf("LDAP connection failed: %v", err)
		}
		// Bind anonyme
		if err := conn.UnauthenticatedBind(""); err != nil {
			conn.Close()
			return nil, creds, fmt.Errorf("anonymous LDAP bind failed: %v", err)
		}
		// Wrapper dans ldap.Client via le constructeur existant
		// On utilise NewClient avec des credentials vides
		client, err := ldap.NewClient(ctx, server, "", "", false)
		if err != nil {
			return nil, creds, fmt.Errorf("anonymous LDAP client failed: %v", err)
		}
		return client, creds, nil
	}

	// Credentials présents → NTLM
	if creds.SMBDomain == "" {
		return nil, creds, fmt.Errorf("domain required: use -d DOMAIN")
	}

	common.PrintInfo(fmt.Sprintf("LDAP → %s as %s\\%s",
		server, strings.ToUpper(creds.SMBDomain), creds.SMBUsername))

	client, err := ldap.NewClientNTLM(ctx, server,
		creds.SMBDomain, creds.SMBUsername,
		creds.Password, creds.NTLMHash, false)
	if err != nil {
		return nil, creds, fmt.Errorf("LDAP connection failed: %v", err)
	}

	return client, creds, nil
}

func domainToBaseDNfromCreds(creds *common.Credentials) string {
	if creds != nil && creds.BaseDN != "" {
		return creds.BaseDN
	}
	domain := common.Domain
	if creds != nil && creds.SMBDomain != "" {
		domain = creds.SMBDomain
	}
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
  adgo ldap users --dc-ip 192.168.1.10 -d LAB                             (anonymous)
  adgo ldap users --dc-ip 192.168.1.10 -u admin -p pass -d LAB --csv users.csv`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		client, creds, err := newLDAPClientFromCmd(ctx, cmd)
		if err != nil {
			return err
		}
		defer client.Close()

		debug, _ := cmd.Flags().GetBool("debug")
		jsonOut, _ := cmd.Flags().GetBool("json")
		bloodhound, _ := cmd.Flags().GetBool("bloodhound")
		csvOutput, _ := cmd.Flags().GetString("csv")
		filter, _ := cmd.Flags().GetString("filter")
		disabledOnly, _ := cmd.Flags().GetBool("disabled-only")

		baseDN := domainToBaseDNfromCreds(creds)
		if baseDN == "" {
			return fmt.Errorf("cannot determine BaseDN — use -d DOMAIN (e.g. -d nanocorp.htb)")
		}

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
	Example: `
  adgo ldap groups --dc-ip 192.168.1.10 -u admin -p pass -d LAB
  adgo ldap groups --dc-ip 192.168.1.10 -d LAB                   (anonymous)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		client, creds, err := newLDAPClientFromCmd(ctx, cmd)
		if err != nil {
			return err
		}
		defer client.Close()

		debug, _ := cmd.Flags().GetBool("debug")
		jsonOut, _ := cmd.Flags().GetBool("json")
		bloodhound, _ := cmd.Flags().GetBool("bloodhound")

		baseDN := domainToBaseDNfromCreds(creds)
		if baseDN == "" {
			return fmt.Errorf("cannot determine BaseDN — use -d DOMAIN")
		}

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

		client, creds, err := newLDAPClientFromCmd(ctx, cmd)
		if err != nil {
			return err
		}
		defer client.Close()

		debug, _ := cmd.Flags().GetBool("debug")
		jsonOut, _ := cmd.Flags().GetBool("json")
		bloodhound, _ := cmd.Flags().GetBool("bloodhound")

		baseDN := domainToBaseDNfromCreds(creds)
		if baseDN == "" {
			return fmt.Errorf("cannot determine BaseDN — use -d DOMAIN")
		}

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

		client, creds, err := newLDAPClientFromCmd(ctx, cmd)
		if err != nil {
			return err
		}
		defer client.Close()

		debug, _ := cmd.Flags().GetBool("debug")
		jsonOut, _ := cmd.Flags().GetBool("json")
		bloodhound, _ := cmd.Flags().GetBool("bloodhound")

		baseDN := domainToBaseDNfromCreds(creds)
		if baseDN == "" {
			return fmt.Errorf("cannot determine BaseDN — use -d DOMAIN")
		}

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

		client, creds, err := newLDAPClientFromCmd(ctx, cmd)
		if err != nil {
			return err
		}
		defer client.Close()

		debug, _ := cmd.Flags().GetBool("debug")
		jsonOut, _ := cmd.Flags().GetBool("json")
		bloodhound, _ := cmd.Flags().GetBool("bloodhound")

		baseDN := domainToBaseDNfromCreds(creds)
		if baseDN == "" {
			return fmt.Errorf("cannot determine BaseDN — use -d DOMAIN")
		}

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

		client, creds, err := newLDAPClientFromCmd(ctx, cmd)
		if err != nil {
			return err
		}
		defer client.Close()

		debug, _ := cmd.Flags().GetBool("debug")
		jsonOut, _ := cmd.Flags().GetBool("json")
		bloodhound, _ := cmd.Flags().GetBool("bloodhound")

		baseDN := domainToBaseDNfromCreds(creds)
		if baseDN == "" {
			return fmt.Errorf("cannot determine BaseDN — use -d DOMAIN")
		}

		policy, err := client.GetPasswordPolicy(baseDN)
		if err != nil {
			return fmt.Errorf("failed to get password policy: %v", err)
		}
		common.PrintOutput(policy, bloodhound, jsonOut, debug)
		return nil
	},
}

func init() {
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
Supports password, NTLM, Pass-the-Hash, and anonymous authentication.

Examples:
  # Avec credentials
  adgo ldap users     --dc-ip 192.168.1.10 -u admin -p pass -d LAB
  adgo ldap groups    --dc-ip 192.168.1.10 -u admin --hash aad3b435... -d LAB

  # Anonymous (si le DC le permet)
  adgo ldap users     --dc-ip 192.168.1.10 -d nanocorp.htb
  adgo ldap groups    --dc-ip 192.168.1.10 -d nanocorp.htb`,
}
