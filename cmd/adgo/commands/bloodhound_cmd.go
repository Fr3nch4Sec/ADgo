// cmd/adgo/commands/bloodhound_cmd.go
//
// adgo bloodhound — Collecte complète BloodHound CE en une commande
//
// Collecte en parallèle :
//   ✓ Utilisateurs (avec SIDs, SPNs, flags AS-REP, admin count)
//   ✓ Groupes (avec membres résolus)
//   ✓ Ordinateurs (OS, unconstrained delegation)
//   ✓ ACLs dangereuses (GenericAll, DCSync, WriteDACL...)
//
// Equivaut à : SharpHound.exe -c All --zipfilename adgo_bh.zip
//
// Exemples :
//   adgo bloodhound --dc-ip 192.168.1.10 -u admin -p pass -d LAB
//   adgo bloodhound --dc-ip 192.168.1.10 -u admin --hash aad3b435... -d LAB
//   adgo bloodhound --dc-ip 192.168.1.10 -u admin -p pass -d LAB --no-acl
//   adgo bloodhound --dc-ip 192.168.1.10 -u admin -p pass -d LAB --output ./bh_data/

package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"adgo/pkg/adattack"
	"adgo/pkg/common"
	"adgo/pkg/ldap"

	"github.com/spf13/cobra"
)

var BloodHoundCmd = &cobra.Command{
	Use:   "bloodhound",
	Short: "Collect BloodHound CE data (users, groups, computers, ACLs)",
	Long: `Full BloodHound CE collection — equivalent to SharpHound -c All.

Collects in parallel:
  • Users       — SIDs, SPNs, AS-REP Roastable, admin count, last logon
  • Groups      — Members resolved to SIDs, admin count
  • Computers   — OS, unconstrained delegation flag
  • ACLs        — GenericAll, DCSync, WriteDACL, WriteOwner, ForceChangePassword...

Output: JSON files ready for bloodhound-cli upload or web UI import.

Examples:
  adgo bloodhound --dc-ip 192.168.1.10 -u admin -p pass -d LAB
  adgo bloodhound --dc-ip 192.168.1.10 -u admin --hash aad3b435... -d LAB
  adgo bloodhound --dc-ip 192.168.1.10 -u admin -p pass -d LAB --no-acl
  adgo bloodhound --dc-ip 192.168.1.10 -u admin -p pass -d LAB --output ./loot/

After collection:
  bloodhound-cli upload --path ./bloodhound/
  # or drag & drop the JSON files into the BloodHound CE web UI`,
	RunE: runBloodHound,
}

var (
	bhDCIP        string
	bhOutput      string
	bhNoACL       bool
	bhNoUsers     bool
	bhNoGroups    bool
	bhNoComputers bool
)

func init() {
	BloodHoundCmd.Flags().StringVar(&bhDCIP, "dc-ip", "", "Domain Controller IP (required)")
	BloodHoundCmd.Flags().StringVar(&bhOutput, "output", "./bloodhound", "Output directory for JSON files")
	BloodHoundCmd.Flags().BoolVar(&bhNoACL, "no-acl", false, "Skip ACL enumeration (faster but incomplete)")
	BloodHoundCmd.Flags().BoolVar(&bhNoUsers, "no-users", false, "Skip user enumeration")
	BloodHoundCmd.Flags().BoolVar(&bhNoGroups, "no-groups", false, "Skip group enumeration")
	BloodHoundCmd.Flags().BoolVar(&bhNoComputers, "no-computers", false, "Skip computer enumeration")
	BloodHoundCmd.MarkFlagRequired("dc-ip")
}

func runBloodHound(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	creds, err := requireCredsWithDCIP(bhDCIP)
	if err != nil {
		return err
	}

	server := buildLDAPServer(bhDCIP, creds)
	baseDN := buildBaseDN(creds)

	if baseDN == "" {
		return fmt.Errorf("cannot determine BaseDN — specify -d DOMAIN.LOCAL")
	}

	common.PrintInfo(fmt.Sprintf("BloodHound collection → %s as %s\\%s",
		server, strings.ToUpper(creds.SMBDomain), creds.SMBUsername))
	common.PrintInfo(fmt.Sprintf("BaseDN: %s", baseDN))
	common.PrintInfo(fmt.Sprintf("Output: %s", bhOutput))

	// Connexion LDAP
	ldapClient, err := ldap.NewClientNTLM(ctx, server, creds.SMBDomain, creds.SMBUsername,
		creds.Password, creds.NTLMHash, false)
	if err != nil {
		return fmt.Errorf("LDAP connection failed: %v", err)
	}
	defer ldapClient.Close()

	export := &common.FullBHExport{}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error

	spinner := common.NewSpinner("Collecting")
	spinner.Start()

	// Utilisateurs — EnumerateBHUsers retourne []models.BHUserEntry
	if !bhNoUsers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			users, err := ldapClient.EnumerateBHUsers(baseDN)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Errorf("users: %v", err))
				return
			}
			for _, u := range users {
				// Convertir models.BHUserEntry → common.BHUser
				export.Users = append(export.Users, common.BHUserEntryToNode(common.BHUserEntry{
					DN:             u.DN,
					SAMAccountName: u.SAMAccountName,
					SID:            u.SID,
					DomainSID:      u.DomainSID,
					Domain:         u.Domain,
					SPNs:           u.SPNs,
					Enabled:        u.Enabled,
					PwdNeverExp:    u.PwdNeverExp,
					DontReqPreAuth: u.DontReqPreAuth,
					AdminCount:     u.AdminCount,
					LastLogon:      u.LastLogon,
					Description:    u.Description,
				}))
			}
		}()
	}

	// Groupes
	if !bhNoGroups {
		wg.Add(1)
		go func() {
			defer wg.Done()
			groups, err := ldapClient.EnumerateBHGroups(baseDN)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Errorf("groups: %v", err))
				return
			}
			for _, g := range groups {
				members := make([]common.BHGroupMember, len(g.Members))
				for i, m := range g.Members {
					members[i] = common.BHGroupMember{
						ObjectIdentifier: m.ObjectIdentifier,
						ObjectType:       m.ObjectType,
					}
				}
				export.Groups = append(export.Groups, common.BHGroupEntryToNode(common.BHGroupEntry{
					DN:             g.DN,
					SAMAccountName: g.SAMAccountName,
					SID:            g.SID,
					DomainSID:      g.DomainSID,
					Domain:         g.Domain,
					Members:        members,
					AdminCount:     g.AdminCount,
					Description:    g.Description,
				}))
			}
		}()
	}

	// Ordinateurs
	if !bhNoComputers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			computers, err := ldapClient.EnumerateBHComputers(baseDN)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Errorf("computers: %v", err))
				return
			}
			for _, c := range computers {
				export.Computers = append(export.Computers, common.BHComputerEntryToNode(common.BHComputerEntry{
					DN:               c.DN,
					SAMAccountName:   c.SAMAccountName,
					SID:              c.SID,
					DomainSID:        c.DomainSID,
					Domain:           c.Domain,
					Enabled:          c.Enabled,
					OS:               c.OS,
					UnconsDelegation: c.UnconsDelegation,
					Description:      c.Description,
				}))
			}
		}()
	}

	// ACLs
	var aclRights []adattack.ACLRight
	if !bhNoACL {
		wg.Add(1)
		go func() {
			defer wg.Done()
			aclClient := adattack.NewACLClient(ldapClient.Conn(), baseDN)
			rights, err := aclClient.FindDangerousACLs()
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Errorf("ACLs: %v", err))
				return
			}
			aclRights = rights
		}()
	}

	wg.Wait()
	spinner.Stop()

	for _, e := range errs {
		common.PrintWarning(fmt.Sprintf("Collection warning: %v", e))
	}

	if len(aclRights) > 0 {
		export.ACLs = common.ACLRightsToBHAces(aclRights)
	}

	fmt.Println()
	common.NxSummaryHeader("Collection complete")
	common.NxSummaryLine("Users", len(export.Users))
	common.NxSummaryLine("Groups", len(export.Groups))
	common.NxSummaryLine("Computers", len(export.Computers))
	common.NxSummaryLine("ACL rights", len(aclRights))
	fmt.Println()

	if len(export.Users)+len(export.Groups)+len(export.Computers) == 0 {
		return fmt.Errorf("nothing collected — check credentials and domain")
	}

	stats, err := common.ExportFullBloodHound(export, bhOutput)
	if err != nil {
		return fmt.Errorf("export failed: %v", err)
	}

	fmt.Println()
	common.PrintSuccess(fmt.Sprintf("BloodHound CE collection done in %s", stats.Duration.Round(1e9)))

	return nil
}
