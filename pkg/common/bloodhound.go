// pkg/common/bloodhound.go
package common

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// ============================================================
// Types BloodHound CE (format v5 — compatible BH 4.x / 5.x)
// ============================================================

// BHMeta section meta obligatoire dans chaque fichier BH
type BHMeta struct {
	Methods int    `json:"methods"`
	Type    string `json:"type"` // "users", "groups", "computers", "domains"
	Count   int    `json:"count"`
	Version int    `json:"version"` // 5
}

// BHFile structure racine d'un fichier BloodHound
type BHFile struct {
	Data interface{} `json:"data"`
	Meta BHMeta      `json:"meta"`
}

// BHAce représente une entrée ACL dans un objet BloodHound
type BHAce struct {
	PrincipalSID  string `json:"PrincipalSID"`
	PrincipalType string `json:"PrincipalType"` // "User", "Group", "Computer"
	RightName     string `json:"RightName"`
	IsInherited   bool   `json:"IsInherited"`
}

// ============================================================
// Objets BloodHound enrichis (SID requis pour BH CE)
// ============================================================

// BHUserProperties propriétés d'un utilisateur BloodHound
type BHUserProperties struct {
	Domain            string `json:"domain"`
	Name              string `json:"name"` // USER@DOMAIN.COM
	DistinguishedName string `json:"distinguishedname"`
	DomainSID         string `json:"domainsid"`
	SAMAccountName    string `json:"samaccountname"`
	Enabled           bool   `json:"enabled"`
	HasSPN            bool   `json:"hasspn"`
	DontReqPreAuth    bool   `json:"dontreqpreauth"`
	PwdNeverExpires   bool   `json:"pwdneverexpires"`
	LastLogon         int64  `json:"lastlogon"`
	LastLogonTS       int64  `json:"lastlogontimestamp"`
	Description       string `json:"description"`
	AdminCount        bool   `json:"admincount"`
}

// BHUser nœud utilisateur BloodHound
type BHUser struct {
	Properties       BHUserProperties `json:"Properties"`
	ObjectIdentifier string           `json:"ObjectIdentifier"` // SID réel
	Aces             []BHAce          `json:"Aces"`
	IsDeleted        bool             `json:"IsDeleted"`
	IsACLProtected   bool             `json:"IsACLProtected"`
}

// BHGroupProperties propriétés d'un groupe BloodHound
type BHGroupProperties struct {
	Domain            string `json:"domain"`
	Name              string `json:"name"`
	DistinguishedName string `json:"distinguishedname"`
	DomainSID         string `json:"domainsid"`
	SAMAccountName    string `json:"samaccountname"`
	AdminCount        bool   `json:"admincount"`
	Description       string `json:"description"`
}

// BHGroupMember membre d'un groupe BloodHound
type BHGroupMember struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	ObjectType       string `json:"ObjectType"` // "User", "Group", "Computer"
}

// BHGroup nœud groupe BloodHound
type BHGroup struct {
	Properties       BHGroupProperties `json:"Properties"`
	ObjectIdentifier string            `json:"ObjectIdentifier"`
	Members          []BHGroupMember   `json:"Members"`
	Aces             []BHAce           `json:"Aces"`
	IsDeleted        bool              `json:"IsDeleted"`
	IsACLProtected   bool              `json:"IsACLProtected"`
}

// BHComputerProperties propriétés d'un ordinateur BloodHound
type BHComputerProperties struct {
	Domain            string `json:"domain"`
	Name              string `json:"name"`
	DistinguishedName string `json:"distinguishedname"`
	DomainSID         string `json:"domainsid"`
	SAMAccountName    string `json:"samaccountname"`
	Enabled           bool   `json:"enabled"`
	OSVersion         string `json:"operatingsystem"`
	Description       string `json:"description"`
	UnconsDelegation  bool   `json:"unconstraineddelegation"`
}

// BHComputer nœud ordinateur BloodHound
type BHComputer struct {
	Properties       BHComputerProperties `json:"Properties"`
	ObjectIdentifier string               `json:"ObjectIdentifier"`
	Aces             []BHAce              `json:"Aces"`
	IsDeleted        bool                 `json:"IsDeleted"`
	IsACLProtected   bool                 `json:"IsACLProtected"`
}

// ============================================================
// Enriched LDAP types (avec SID — utilisés pour le BH export)
// ============================================================

// BHUserEntry entrée utilisateur enrichie (SID + attrs BloodHound)
type BHUserEntry struct {
	DN             string
	SAMAccountName string
	SID            string
	DomainSID      string
	Domain         string
	SPNs           []string
	Enabled        bool
	PwdNeverExp    bool
	DontReqPreAuth bool
	AdminCount     bool
	LastLogon      int64
	Description    string
}

// BHGroupEntry entrée groupe enrichie
type BHGroupEntry struct {
	DN             string
	SAMAccountName string
	SID            string
	DomainSID      string
	Domain         string
	Members        []BHGroupMember
	AdminCount     bool
	Description    string
}

// BHComputerEntry entrée ordinateur enrichie
type BHComputerEntry struct {
	DN               string
	SAMAccountName   string
	SID              string
	DomainSID        string
	Domain           string
	Enabled          bool
	OS               string
	UnconsDelegation bool
	Description      string
}

// BHACLRight droit ACL avec SIDs réels pour BloodHound
type BHACLRight struct {
	PrincipalSID  string
	PrincipalName string
	PrincipalType string // "User", "Group", "Computer"
	TargetSID     string
	TargetName    string
	TargetType    string
	Right         string
	Inherited     bool
}

// ============================================================
// Mapping ADgo rights → BloodHound edge names
// ============================================================

var adgoToBHRight = map[string]string{
	"GenericAll":          "GenericAll",
	"WriteDACL":           "WriteDacl",
	"WriteOwner":          "WriteOwner",
	"GenericWrite":        "GenericWrite",
	"ForceChangePassword": "ForceChangePassword",
	"DCSync":              "DCSync",
	"AddMember":           "AddMember",
	"AllExtendedRights":   "AllExtendedRights",
	"WriteProperty":       "WriteProperty",
	"Owns":                "Owns",
}

// toBHRightName convertit un nom de droit ADgo en nom d'edge BloodHound
func toBHRightName(adgoRight string) string {
	if bh, ok := adgoToBHRight[adgoRight]; ok {
		return bh
	}
	return adgoRight
}

// ============================================================
// Export BloodHound CE JSON
// ============================================================

// ExportBHUsers génère un fichier bloodhound_users.json compatible BH CE
func ExportBHUsers(users []BHUserEntry, outputFile string) error {
	if outputFile == "" {
		outputFile = fmt.Sprintf("bloodhound_users_%s.json", timestamp())
	}

	var nodes []BHUser
	for _, u := range users {
		domain := strings.ToUpper(u.Domain)
		node := BHUser{
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
		nodes = append(nodes, node)
	}

	return writeBHFile(nodes, "users", outputFile)
}

// ExportBHGroups génère un fichier bloodhound_groups.json compatible BH CE
func ExportBHGroups(groups []BHGroupEntry, outputFile string) error {
	if outputFile == "" {
		outputFile = fmt.Sprintf("bloodhound_groups_%s.json", timestamp())
	}

	var nodes []BHGroup
	for _, g := range groups {
		domain := strings.ToUpper(g.Domain)
		node := BHGroup{
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
			Members:          g.Members,
			Aces:             []BHAce{},
		}
		nodes = append(nodes, node)
	}

	return writeBHFile(nodes, "groups", outputFile)
}

// ExportBHComputers génère un fichier bloodhound_computers.json compatible BH CE
func ExportBHComputers(computers []BHComputerEntry, outputFile string) error {
	if outputFile == "" {
		outputFile = fmt.Sprintf("bloodhound_computers_%s.json", timestamp())
	}

	var nodes []BHComputer
	for _, c := range computers {
		domain := strings.ToUpper(c.Domain)
		node := BHComputer{
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
		nodes = append(nodes, node)
	}

	return writeBHFile(nodes, "computers", outputFile)
}

// ExportBHACLs injecte les ACEs dans les nœuds existants et
// génère un fichier bloodhound_acls.json compatible BH CE
func ExportBHACLs(rights []BHACLRight, outputFile string) error {
	if outputFile == "" {
		outputFile = fmt.Sprintf("bloodhound_acls_%s.json", timestamp())
	}

	// Grouper les ACEs par TargetSID
	bySID := make(map[string][]BHAce)
	targetType := make(map[string]string)

	for _, r := range rights {
		if r.PrincipalSID == "" || r.TargetSID == "" {
			continue
		}
		ace := BHAce{
			PrincipalSID:  r.PrincipalSID,
			PrincipalType: r.PrincipalType,
			RightName:     toBHRightName(r.Right),
			IsInherited:   r.Inherited,
		}
		bySID[r.TargetSID] = append(bySID[r.TargetSID], ace)
		targetType[r.TargetSID] = r.TargetType
	}

	// Créer des nœuds minimalistes pour les cibles
	type aclNode struct {
		ObjectIdentifier string  `json:"ObjectIdentifier"`
		Aces             []BHAce `json:"Aces"`
	}

	var nodes []aclNode
	for sid, aces := range bySID {
		nodes = append(nodes, aclNode{
			ObjectIdentifier: sid,
			Aces:             aces,
		})
	}

	return writeBHFile(nodes, "aces", outputFile)
}

// ============================================================
// Writer JSON
// ============================================================

func writeBHFile(data interface{}, dataType, outputFile string) error {
	count := 0
	switch v := data.(type) {
	case []BHUser:
		count = len(v)
	case []BHGroup:
		count = len(v)
	case []BHComputer:
		count = len(v)
	default:
		count = 0
	}

	file := BHFile{
		Data: data,
		Meta: BHMeta{
			Methods: 0,
			Type:    dataType,
			Count:   count,
			Version: 5,
		},
	}

	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("cannot create %s: %v", outputFile, err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(file); err != nil {
		return fmt.Errorf("JSON encode failed: %v", err)
	}

	fmt.Printf("[+] BloodHound CE export → %s (%d objects)\n", outputFile, count)
	fmt.Printf("[*] Import with: bloodhound-cli upload --path %s\n", outputFile)
	return nil
}

func timestamp() string {
	return time.Now().Format("20060102_150405")
}
