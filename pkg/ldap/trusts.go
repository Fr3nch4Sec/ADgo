// pkg/ldap/trusts.go
//
// Énumération des relations de confiance (trusts) inter-domaines.
//
// Les trusts sont stockés dans : CN=System,<BaseDN>
// Objet : objectClass=trustedDomain
//
// Types de trust (trustType) :
//   1 = Windows NT (downlevel)
//   2 = Active Directory (uplevel)
//   3 = MIT Kerberos
//
// Direction (trustDirection) :
//   0 = Disabled
//   1 = Inbound  (le domaine distant fait confiance à NOTRE domaine)
//   2 = Outbound (NOTRE domaine fait confiance au domaine distant)
//   3 = Bidirectional
//
// Attributs (trustAttributes) — flags :
//   0x001 = Non-transitive
//   0x002 = Uplevel-only
//   0x004 = Quarantined (SID filtering)
//   0x008 = Forest trust
//   0x010 = Cross-org (selective auth)
//   0x020 = Within forest
//   0x040 = Treat as external
//   0x800 = PAM trust

package ldap

import (
	"fmt"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
)

// TrustEntry représente une relation de confiance AD
type TrustEntry struct {
	Name         string   // nom du domaine distant
	DN           string   // DN de l'objet trustedDomain
	Type         string   // "AD", "NT", "MIT Kerberos"
	Direction    string   // "Inbound", "Outbound", "Bidirectional", "Disabled"
	Transitive   bool     // le trust est-il transitif ?
	ForestTrust  bool     // forest trust ?
	SIDFiltering bool     // SID filtering activé ? (protection contre SID history attacks)
	Flags        []string // liste des attributs notables
	RawType      int
	RawDirection int
	RawAttribs   int
}

// IsAttackable retourne true si ce trust présente un risque d'exploitation
// (outbound non filtré = on peut potentiellement se faire confiance depuis l'autre domaine)
func (t *TrustEntry) IsAttackable() bool {
	return (t.RawDirection == 2 || t.RawDirection == 3) && !t.SIDFiltering
}

// AttackPath retourne une description de l'exploitation possible
func (t *TrustEntry) AttackPath() string {
	if !t.IsAttackable() {
		return ""
	}
	if t.ForestTrust {
		return fmt.Sprintf("Forest trust → SID history attack possible from %s if SID filtering disabled", t.Name)
	}
	if t.RawDirection == 3 {
		return fmt.Sprintf("Bidirectional trust → compromise %s to pivot back to this domain", t.Name)
	}
	return fmt.Sprintf("Outbound trust to %s → users from %s can auth here", t.Name, t.Name)
}

// EnumerateTrusts énumère toutes les relations de confiance du domaine
func (c *Client) EnumerateTrusts(baseDN string) ([]TrustEntry, error) {
	// Les trusts sont sous CN=System,<baseDN>
	systemDN := "CN=System," + baseDN

	req := goldap.NewSearchRequest(
		systemDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=trustedDomain)",
		[]string{
			"cn",
			"distinguishedName",
			"trustType",
			"trustDirection",
			"trustAttributes",
			"flatName",       // nom NetBIOS du domaine distant
			"trustPartnerDN", // DN du domaine partenaire (si forêt)
		},
		nil,
	)

	sr, err := c.conn.Search(req)
	if err != nil {
		// Essayer depuis la racine si System n'est pas accessible directement
		req.BaseDN = baseDN
		sr, err = c.conn.Search(req)
		if err != nil {
			return nil, fmt.Errorf("trust enumeration failed: %v", err)
		}
	}

	var trusts []TrustEntry
	for _, entry := range sr.Entries {
		t := parseTrustEntry(entry)
		trusts = append(trusts, t)
	}

	return trusts, nil
}

func parseTrustEntry(entry *goldap.Entry) TrustEntry {
	t := TrustEntry{
		Name: entry.GetAttributeValue("cn"),
		DN:   entry.DN,
	}

	// trustType
	fmt.Sscanf(entry.GetAttributeValue("trustType"), "%d", &t.RawType)
	switch t.RawType {
	case 1:
		t.Type = "Windows NT (downlevel)"
	case 2:
		t.Type = "Active Directory"
	case 3:
		t.Type = "MIT Kerberos"
	default:
		t.Type = fmt.Sprintf("Unknown (%d)", t.RawType)
	}

	// trustDirection
	fmt.Sscanf(entry.GetAttributeValue("trustDirection"), "%d", &t.RawDirection)
	switch t.RawDirection {
	case 0:
		t.Direction = "Disabled"
	case 1:
		t.Direction = "Inbound"
	case 2:
		t.Direction = "Outbound"
	case 3:
		t.Direction = "Bidirectional"
	default:
		t.Direction = fmt.Sprintf("Unknown (%d)", t.RawDirection)
	}

	// trustAttributes (flags)
	fmt.Sscanf(entry.GetAttributeValue("trustAttributes"), "%d", &t.RawAttribs)
	a := t.RawAttribs

	t.Transitive = (a & 0x001) == 0 // bit 0 = non-transitive, so absent = transitive
	t.ForestTrust = (a & 0x008) != 0
	t.SIDFiltering = (a & 0x004) != 0 // quarantined = SID filtering

	// Construire les flags notables
	if t.ForestTrust {
		t.Flags = append(t.Flags, "FOREST_TRUST")
	}
	if t.SIDFiltering {
		t.Flags = append(t.Flags, "SID_FILTERING")
	}
	if (a & 0x010) != 0 {
		t.Flags = append(t.Flags, "CROSS_ORG")
	}
	if (a & 0x020) != 0 {
		t.Flags = append(t.Flags, "WITHIN_FOREST")
	}
	if (a & 0x040) != 0 {
		t.Flags = append(t.Flags, "TREAT_AS_EXTERNAL")
	}
	if (a & 0x800) != 0 {
		t.Flags = append(t.Flags, "PAM_TRUST")
	}
	if t.Transitive {
		t.Flags = append(t.Flags, "TRANSITIVE")
	}

	return t
}

// FormatTrustsTable formate les trusts pour PrintTable
func FormatTrustsTable(trusts []TrustEntry) [][]string {
	rows := make([][]string, 0, len(trusts))
	for _, t := range trusts {
		risk := "Low"
		if t.IsAttackable() {
			risk = "HIGH"
		}
		rows = append(rows, []string{
			t.Name,
			t.Type,
			t.Direction,
			boolToStr(t.ForestTrust, "Forest", "Domain"),
			boolToStr(t.SIDFiltering, "Filtered", "UNFILTERED"),
			boolToStr(t.Transitive, "Yes", "No"),
			risk,
		})
	}
	return rows
}

func boolToStr(b bool, ifTrue, ifFalse string) string {
	if b {
		return ifTrue
	}
	return ifFalse
}

// PrintTrustAnalysis affiche une analyse détaillée des trusts exploitables
func PrintTrustAnalysis(trusts []TrustEntry) {
	attackable := 0
	for _, t := range trusts {
		if t.IsAttackable() {
			attackable++
		}
	}

	if attackable == 0 {
		return
	}

	fmt.Printf("\n[!] %d potentially exploitable trust(s):\n", attackable)
	for _, t := range trusts {
		path := t.AttackPath()
		if path == "" {
			continue
		}
		fmt.Printf("\n  [TRUST] %s (%s)\n", t.Name, t.Direction)
		fmt.Printf("  [->]   %s\n", path)
		if !t.SIDFiltering && t.Transitive {
			fmt.Printf("  [->]   SID history attack: add SID of target group to compromised account\n")
			fmt.Printf("         mimikatz: misc::addsid /user:<user> /sids:<SID-target-group>\n")
		}
		if strings.Contains(t.Direction, "Bidirectional") {
			fmt.Printf("  [->]   Cross-domain Kerberoast: request TGS for SPNs in %s\n", t.Name)
		}
	}
}
