// pkg/common/bloodhound_export.go
//
// Export BloodHound CE complet en une seule passe :
//   - Utilisateurs (avec SIDs réels, SPNs, flags UAC)
//   - Groupes (avec membres résolus en SIDs)
//   - Ordinateurs (avec OS, delegation flags)
//   - ACLs dangereuses (GenericAll, DCSync, WriteDACL...)
//   - Domaine (infos de base)
//
// Format : JSON compatible BloodHound CE v5 (BH 4.x / 5.x)
// Importer : bloodhound-cli upload --path ./bloodhound_*.json
//            ou via l'interface web → Administration → Upload Data

package common

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"adgo/pkg/adattack"
)

// FullBHExport contient tous les objets pour un export complet
type FullBHExport struct {
	Users     []BHUser
	Groups    []BHGroup
	Computers []BHComputer
	Domain    *BHDomain
	ACLs      []BHAceNode
}

// BHDomain nœud domaine BloodHound
type BHDomain struct {
	Properties       BHDomainProperties `json:"Properties"`
	ObjectIdentifier string             `json:"ObjectIdentifier"` // SID du domaine
	Aces             []BHAce            `json:"Aces"`
	IsDeleted        bool               `json:"IsDeleted"`
	IsACLProtected   bool               `json:"IsACLProtected"`
	ChildObjects     []BHChildObject    `json:"ChildObjects"`
	GPOs             []interface{}      `json:"GPOs"`
	OUs              []interface{}      `json:"OUs"`
	Trusts           []interface{}      `json:"Trusts"`
}

// BHDomainProperties propriétés du domaine
type BHDomainProperties struct {
	Domain            string `json:"domain"`
	Name              string `json:"name"`
	DistinguishedName string `json:"distinguishedname"`
	DomainSID         string `json:"domainsid"`
	Functional        int    `json:"functionallevel"`
}

// BHChildObject enfant d'un objet BloodHound
type BHChildObject struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	ObjectType       string `json:"ObjectType"`
}

// BHAceNode nœud minimal pour exporter des ACEs (sans duplication des objets)
type BHAceNode struct {
	ObjectIdentifier string  `json:"ObjectIdentifier"`
	Aces             []BHAce `json:"Aces"`
}

// ExportStats statistiques de l'export
type ExportStats struct {
	Users     int
	Groups    int
	Computers int
	ACLRights int
	Duration  time.Duration
}

// ============================================================
// Export complet
// ============================================================

// ExportFullBloodHound génère tous les fichiers JSON pour un import BloodHound CE.
// outputDir : répertoire de sortie (créé si absent)
func ExportFullBloodHound(export *FullBHExport, outputDir string) (*ExportStats, error) {
	start := time.Now()

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("cannot create output dir %s: %v", outputDir, err)
	}

	ts := time.Now().Format("20060102_150405")

	stats := &ExportStats{}

	// Export utilisateurs
	if len(export.Users) > 0 {
		path := fmt.Sprintf("%s/bloodhound_%s_users.json", outputDir, ts)
		if err := writeBHFileTyped(export.Users, "users", path); err != nil {
			return nil, fmt.Errorf("users export failed: %v", err)
		}
		stats.Users = len(export.Users)
		PrintSuccess(fmt.Sprintf("Users   → %s (%d)", path, stats.Users))
	}

	// Export groupes
	if len(export.Groups) > 0 {
		path := fmt.Sprintf("%s/bloodhound_%s_groups.json", outputDir, ts)
		if err := writeBHFileTyped(export.Groups, "groups", path); err != nil {
			return nil, fmt.Errorf("groups export failed: %v", err)
		}
		stats.Groups = len(export.Groups)
		PrintSuccess(fmt.Sprintf("Groups  → %s (%d)", path, stats.Groups))
	}

	// Export ordinateurs
	if len(export.Computers) > 0 {
		path := fmt.Sprintf("%s/bloodhound_%s_computers.json", outputDir, ts)
		if err := writeBHFileTyped(export.Computers, "computers", path); err != nil {
			return nil, fmt.Errorf("computers export failed: %v", err)
		}
		stats.Computers = len(export.Computers)
		PrintSuccess(fmt.Sprintf("Computers → %s (%d)", path, stats.Computers))
	}

	// Export domaine
	if export.Domain != nil {
		path := fmt.Sprintf("%s/bloodhound_%s_domains.json", outputDir, ts)
		if err := writeBHFileTyped([]*BHDomain{export.Domain}, "domains", path); err != nil {
			return nil, fmt.Errorf("domain export failed: %v", err)
		}
		PrintSuccess(fmt.Sprintf("Domain  → %s", path))
	}

	// Export ACLs (injecte les ACEs dans des nœuds par SID cible)
	if len(export.ACLs) > 0 {
		path := fmt.Sprintf("%s/bloodhound_%s_aces.json", outputDir, ts)
		if err := writeBHFileTyped(export.ACLs, "aces", path); err != nil {
			return nil, fmt.Errorf("ACLs export failed: %v", err)
		}
		stats.ACLRights = len(export.ACLs)
		PrintSuccess(fmt.Sprintf("ACLs    → %s (%d nodes with ACEs)", path, stats.ACLRights))
	}

	stats.Duration = time.Since(start)

	// Instructions d'import
	fmt.Println()
	PrintInfo("Import into BloodHound CE:")
	fmt.Printf("  bloodhound-cli upload --path %s\n", outputDir)
	fmt.Println("  or via web UI → Administration → Upload Data")

	return stats, nil
}

// ============================================================
// Conversion ACLRight → BHAce
// ============================================================

// ACLRightsToBHAces convertit une liste d'ACLRight (pkg/adattack) en nœuds BH CE.
// Les ACEs sont groupées par SID cible pour minimiser le nombre de fichiers.
func ACLRightsToBHAces(rights []adattack.ACLRight) []BHAceNode {
	// Grouper les ACEs par TargetDN (on utilisera le DN comme identifiant temporaire)
	byTarget := make(map[string][]BHAce)
	for _, r := range rights {
		if r.ObjectName == "" || r.TargetDN == "" {
			continue
		}

		// Construire un identifiant pour le principal (SID ou DN)
		principalID := r.ObjectDN
		if principalID == "" {
			principalID = r.ObjectName
		}

		ace := BHAce{
			PrincipalSID:  principalID,
			PrincipalType: r.ObjectType,
			RightName:     mapACLRightToBH(r.Right),
			IsInherited:   r.Inherited,
		}

		targetKey := r.TargetDN
		byTarget[targetKey] = append(byTarget[targetKey], ace)
	}

	var nodes []BHAceNode
	for targetDN, aces := range byTarget {
		nodes = append(nodes, BHAceNode{
			ObjectIdentifier: targetDN,
			Aces:             aces,
		})
	}

	return nodes
}

// mapACLRightToBH mappe les noms de droits ADgo vers les edge names BloodHound
func mapACLRightToBH(right string) string {
	mapping := map[string]string{
		"GenericAll":                  "GenericAll",
		"WriteDACL":                   "WriteDacl",
		"WriteOwner":                  "WriteOwner",
		"GenericWrite":                "GenericWrite",
		"ForceChangePassword":         "ForceChangePassword",
		"DCSync":                      "DCSync",
		"AllExtendedRights":           "AllExtendedRights",
		"WriteProperty":               "WriteProperty",
		"Self-Membership (AddMember)": "AddMember",
	}
	if bh, ok := mapping[right]; ok {
		return bh
	}
	return right
}

// ============================================================
// Conversion BHUserEntry → BHUser (avec SID réel)
// ============================================================

// BHUserEntryToNode convertit un BHUserEntry (LDAP enrichi) en nœud BHUser
func BHUserEntryToNode(u BHUserEntry) BHUser {
	domain := strings.ToUpper(u.Domain)
	return BHUser{
		Properties: BHUserProperties{
			Domain:            domain,
			Name:              strings.ToUpper(u.SAMAccountName) + "@" + domain,
			DistinguishedName: strings.ToUpper(u.DN),
			DomainSID:         u.DomainSID,
			SAMAccountName:    u.SAMAccountName,
			Enabled:           u.Enabled,
			HasSPN:            len(u.SPNs) > 0,
			DontReqPreAuth:    u.DontReqPreAuth,
			PwdNeverExpires:   u.PwdNeverExp,
			LastLogon:         u.LastLogon,
			LastLogonTS:       u.LastLogon,
			Description:       u.Description,
			AdminCount:        u.AdminCount,
		},
		ObjectIdentifier: u.SID,
		Aces:             []BHAce{},
	}
}

// BHGroupEntryToNode convertit un BHGroupEntry en nœud BHGroup
func BHGroupEntryToNode(g BHGroupEntry) BHGroup {
	domain := strings.ToUpper(g.Domain)
	members := make([]BHGroupMember, 0, len(g.Members))
	for _, m := range g.Members {
		members = append(members, BHGroupMember{
			ObjectIdentifier: m.ObjectIdentifier,
			ObjectType:       m.ObjectType,
		})
	}
	return BHGroup{
		Properties: BHGroupProperties{
			Domain:            domain,
			Name:              strings.ToUpper(g.SAMAccountName) + "@" + domain,
			DistinguishedName: strings.ToUpper(g.DN),
			DomainSID:         g.DomainSID,
			SAMAccountName:    g.SAMAccountName,
			AdminCount:        g.AdminCount,
			Description:       g.Description,
		},
		ObjectIdentifier: g.SID,
		Members:          members,
		Aces:             []BHAce{},
	}
}

// BHComputerEntryToNode convertit un BHComputerEntry en nœud BHComputer
func BHComputerEntryToNode(c BHComputerEntry) BHComputer {
	domain := strings.ToUpper(c.Domain)
	return BHComputer{
		Properties: BHComputerProperties{
			Domain:            domain,
			Name:              strings.ToUpper(c.SAMAccountName) + "@" + domain,
			DistinguishedName: strings.ToUpper(c.DN),
			DomainSID:         c.DomainSID,
			SAMAccountName:    c.SAMAccountName,
			Enabled:           c.Enabled,
			OSVersion:         c.OS,
			Description:       c.Description,
			UnconsDelegation:  c.UnconsDelegation,
		},
		ObjectIdentifier: c.SID,
		Aces:             []BHAce{},
	}
}

// ============================================================
// Writer JSON générique
// ============================================================

func writeBHFileTyped(data interface{}, dataType, outputFile string) error {
	count := 0
	switch v := data.(type) {
	case []BHUser:
		count = len(v)
	case []BHGroup:
		count = len(v)
	case []BHComputer:
		count = len(v)
	case []*BHDomain:
		count = len(v)
	case []BHAceNode:
		count = len(v)
	}

	file := struct {
		Data interface{} `json:"data"`
		Meta struct {
			Methods int    `json:"methods"`
			Type    string `json:"type"`
			Count   int    `json:"count"`
			Version int    `json:"version"`
		} `json:"meta"`
	}{
		Data: data,
	}
	file.Meta.Methods = 0
	file.Meta.Type = dataType
	file.Meta.Count = count
	file.Meta.Version = 5

	f, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(file)
}
