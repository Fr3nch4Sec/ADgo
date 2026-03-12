// pkg/ldap/ldap_bloodhound.go

package ldap

import (
	"encoding/binary"
	"fmt"
	"strings"

	"adgo/pkg/models"

	goldap "github.com/go-ldap/ldap/v3"
)

// ============================================================
// Enumération enrichie pour BloodHound CE (avec objectSid réel)
// ============================================================

// EnumerateBHUsers énumère les utilisateurs avec objectSid pour BloodHound CE
func (c *Client) EnumerateBHUsers(baseDN string) ([]models.BHUserEntry, error) {
	req := goldap.NewSearchRequest(
		baseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		0, 0, false,
		"(&(objectClass=user)(objectCategory=person))",
		[]string{
			"sAMAccountName",
			"objectSid",
			"userAccountControl",
			"servicePrincipalName",
			"description",
			"adminCount",
			"lastLogonTimestamp",
			"distinguishedName",
		},
		nil,
	)

	sr, err := c.conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %v", err)
	}

	domain := domainFromBaseDN(baseDN)
	domainSID := c.getDomainSID(baseDN)

	var users []models.BHUserEntry
	for _, entry := range sr.Entries {
		uac := parseIntAttr(entry.GetAttributeValue("userAccountControl"))

		sid := parseSIDBytes(entry.GetRawAttributeValue("objectSid"))
		if sid == "" {
			continue // pas de SID = objet inutilisable pour BH
		}

		users = append(users, models.BHUserEntry{
			DN:             entry.DN,
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			SID:            sid,
			DomainSID:      domainSID,
			Domain:         domain,
			SPNs:           entry.GetAttributeValues("servicePrincipalName"),
			Enabled:        uac&0x2 == 0,      // bit 1 = ACCOUNTDISABLE
			PwdNeverExp:    uac&0x10000 != 0,  // bit 16 = DONT_EXPIRE_PASSWORD
			DontReqPreAuth: uac&0x400000 != 0, // bit 22 = DONT_REQUIRE_PREAUTH
			AdminCount:     entry.GetAttributeValue("adminCount") == "1",
			LastLogon:      parseInt64Attr(entry.GetAttributeValue("lastLogonTimestamp")),
			Description:    entry.GetAttributeValue("description"),
		})
	}

	return users, nil
}

// EnumerateBHGroups énumère les groupes avec membres et objectSid
func (c *Client) EnumerateBHGroups(baseDN string) ([]models.BHGroupEntry, error) {
	req := goldap.NewSearchRequest(
		baseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=group)",
		[]string{
			"sAMAccountName",
			"objectSid",
			"member",
			"adminCount",
			"description",
			"distinguishedName",
		},
		nil,
	)

	sr, err := c.conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %v", err)
	}

	domain := domainFromBaseDN(baseDN)
	domainSID := c.getDomainSID(baseDN)

	var groups []models.BHGroupEntry
	for _, entry := range sr.Entries {
		sid := parseSIDBytes(entry.GetRawAttributeValue("objectSid"))
		if sid == "" {
			continue
		}

		// Résoudre les membres en SIDs
		var members []models.BHGroupMember
		for _, memberDN := range entry.GetAttributeValues("member") {
			memberSID := c.resolveDNtoSID(memberDN)
			memberType := guessTypeFromDN(memberDN)
			if memberSID != "" {
				members = append(members, models.BHGroupMember{
					ObjectIdentifier: memberSID,
					ObjectType:       memberType,
				})
			}
		}

		groups = append(groups, models.BHGroupEntry{
			DN:             entry.DN,
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			SID:            sid,
			DomainSID:      domainSID,
			Domain:         domain,
			Members:        members,
			AdminCount:     entry.GetAttributeValue("adminCount") == "1",
			Description:    entry.GetAttributeValue("description"),
		})
	}

	return groups, nil
}

// EnumerateBHComputers énumère les ordinateurs avec objectSid
func (c *Client) EnumerateBHComputers(baseDN string) ([]models.BHComputerEntry, error) {
	req := goldap.NewSearchRequest(
		baseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=computer)",
		[]string{
			"sAMAccountName",
			"objectSid",
			"userAccountControl",
			"operatingSystem",
			"description",
			"distinguishedName",
			"msDS-AllowedToDelegateTo",
		},
		nil,
	)

	sr, err := c.conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %v", err)
	}

	domain := domainFromBaseDN(baseDN)
	domainSID := c.getDomainSID(baseDN)

	var computers []models.BHComputerEntry
	for _, entry := range sr.Entries {
		sid := parseSIDBytes(entry.GetRawAttributeValue("objectSid"))
		if sid == "" {
			continue
		}

		uac := parseIntAttr(entry.GetAttributeValue("userAccountControl"))
		// bit 19 = TRUSTED_FOR_DELEGATION (unconstrained)
		unconsDelegation := uac&0x80000 != 0

		computers = append(computers, models.BHComputerEntry{
			DN:               entry.DN,
			SAMAccountName:   entry.GetAttributeValue("sAMAccountName"),
			SID:              sid,
			DomainSID:        domainSID,
			Domain:           domain,
			Enabled:          uac&0x2 == 0,
			OS:               entry.GetAttributeValue("operatingSystem"),
			Description:      entry.GetAttributeValue("description"),
			UnconsDelegation: unconsDelegation,
		})
	}

	return computers, nil
}

// ============================================================
// Helpers
// ============================================================

// parseSIDBytes convertit les bytes binaires d'un objectSid en string S-1-5-...
func parseSIDBytes(b []byte) string {
	if len(b) < 8 {
		return ""
	}

	// Revision (1 byte)
	revision := b[0]

	// SubAuthorityCount (1 byte)
	subCount := int(b[1])

	// IdentifierAuthority (6 bytes, big-endian)
	var authority uint64
	for i := 2; i < 8; i++ {
		authority = (authority << 8) | uint64(b[i])
	}

	if len(b) < 8+subCount*4 {
		return ""
	}

	// SubAuthorities (little-endian uint32 chacun)
	subs := make([]string, subCount)
	for i := 0; i < subCount; i++ {
		offset := 8 + i*4
		sub := binary.LittleEndian.Uint32(b[offset : offset+4])
		subs[i] = fmt.Sprintf("%d", sub)
	}

	return fmt.Sprintf("S-%d-%d-%s", revision, authority, strings.Join(subs, "-"))
}

// getDomainSID récupère le SID du domaine depuis rootDSE ou l'objet domaine
func (c *Client) getDomainSID(baseDN string) string {
	req := goldap.NewSearchRequest(
		baseDN,
		goldap.ScopeBaseObject,
		goldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=domain)",
		[]string{"objectSid"},
		nil,
	)

	sr, err := c.conn.Search(req)
	if err != nil || len(sr.Entries) == 0 {
		return ""
	}

	return parseSIDBytes(sr.Entries[0].GetRawAttributeValue("objectSid"))
}

// resolveDNtoSID résout un DN en SID via LDAP
func (c *Client) resolveDNtoSID(dn string) string {
	if dn == "" {
		return ""
	}

	req := goldap.NewSearchRequest(
		dn,
		goldap.ScopeBaseObject,
		goldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"objectSid"},
		nil,
	)

	sr, err := c.conn.Search(req)
	if err != nil || len(sr.Entries) == 0 {
		return ""
	}

	return parseSIDBytes(sr.Entries[0].GetRawAttributeValue("objectSid"))
}

// guessTypeFromDN devine le type d'objet depuis son DN (heuristique)
func guessTypeFromDN(dn string) string {
	dn = strings.ToLower(dn)
	switch {
	case strings.Contains(dn, "ou=computers") || strings.HasSuffix(dn, "$"):
		return "Computer"
	case strings.Contains(dn, "ou=groups") || strings.Contains(dn, "cn=users"):
		return "Group"
	default:
		return "User"
	}
}

// domainFromBaseDN extrait le FQDN depuis un BaseDN (ex: DC=lab,DC=local → lab.local)
func domainFromBaseDN(baseDN string) string {
	var parts []string
	for _, part := range strings.Split(baseDN, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "DC=") {
			parts = append(parts, strings.TrimPrefix(strings.TrimPrefix(part, "DC="), "dc="))
		}
	}
	return strings.Join(parts, ".")
}

func parseIntAttr(s string) uint32 {
	if s == "" {
		return 0
	}
	var v uint32
	fmt.Sscanf(s, "%d", &v)
	return v
}

func parseInt64Attr(s string) int64 {
	if s == "" {
		return -1
	}
	var v int64
	fmt.Sscanf(s, "%d", &v)
	return v
}
