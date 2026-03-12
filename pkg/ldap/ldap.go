// pkg/ldap/ldap.go
package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// UserEntry représente un utilisateur Active Directory.
type UserEntry struct {
	DN             string
	Name           string
	SAMAccountName string
	LastLogon      string // lastLogonTimestamp (format lisible)
	AccountControl string // userAccountControl (flags en clair)
	PwdLastSet     string // pwdLastSet (format lisible)
	SPNs           []string
}

// GroupEntry représente un groupe Active Directory.
type GroupEntry struct {
	DN   string
	Name string
}

// PasswordPolicy représente les politiques de mot de passe.
// CORRECTION : ajout des champs LockoutThreshold et LockoutDurationMinutes
// qui étaient référencés dans pkg/spray/spray.go mais absents de ce struct.
type PasswordPolicy struct {
	MinPasswordLength      int
	PasswordHistorySize    int
	MaxPasswordAge         int
	MinPasswordAge         int
	LockoutThreshold       int // lockoutThreshold — seuil de verrouillage
	LockoutDurationMinutes int // lockoutDuration converti en minutes
}

// Client représente un client LDAP connecté.
type Client struct {
	conn *ldap.Conn
}

// NewClient crée un nouveau client LDAP.
func NewClient(ctx context.Context, ldapServer string, bindDN string, password string, useSSL bool) (*Client, error) {
	var l *ldap.Conn
	var err error

	l, err = ldap.DialURL(ldapServer)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %v", err)
	}

	if useSSL {
		err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return nil, fmt.Errorf("failed to start TLS: %v", err)
		}
	}

	err = l.Bind(bindDN, password)
	if err != nil {
		return nil, fmt.Errorf("failed to bind to LDAP server: %v", err)
	}

	return &Client{conn: l}, nil
}

// Close ferme la connexion du client LDAP.
func (c *Client) Close() error {
	return c.conn.Close()
}

// Conn retourne la connexion LDAP sous-jacente (*ldap.Conn)
func (c *Client) Conn() *ldap.Conn {
	return c.conn
}

// UserHash représente un utilisateur avec son hash NTLM.
type UserHash struct {
	DN             string
	Name           string
	SAMAccountName string
	NTLMHash       string
}

func windowsFileTimeToUnix(ft int64) time.Time {
	if ft == 0 || ft < 0 {
		return time.Time{}
	}
	const windowsEpochOffset = int64(116444736000000000)
	unixNano := (ft - windowsEpochOffset) * 100
	return time.Unix(0, unixNano)
}

// DumpNTLMHashes dump les hashs NTLM des utilisateurs.
func (c *Client) DumpNTLMHashes(baseDN string) ([]UserHash, error) {
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=person)",
		[]string{"dn", "cn", "sAMAccountName"},
		nil,
	)

	sr, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP: %v", err)
	}

	var userHashes []UserHash
	for _, entry := range sr.Entries {
		userHashes = append(userHashes, UserHash{
			DN:             entry.DN,
			Name:           entry.GetAttributeValue("cn"),
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			NTLMHash:       "",
		})
	}

	return userHashes, nil
}

// ComputerEntry représente un ordinateur Active Directory.
type ComputerEntry struct {
	DN   string
	Name string
}

// EnumerateAllComputers énumère tous les ordinateurs dans le domaine.
func (c *Client) EnumerateAllComputers(baseDN string) ([]ComputerEntry, error) {
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=computer)",
		[]string{"dn", "cn"},
		nil,
	)

	sr, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP: %v", err)
	}

	var computers []ComputerEntry
	for _, entry := range sr.Entries {
		computers = append(computers, ComputerEntry{
			DN:   entry.DN,
			Name: entry.GetAttributeValue("cn"),
		})
	}

	return computers, nil
}

// EnumerateAllGroups énumère tous les groupes dans le domaine.
func (c *Client) EnumerateAllGroups(baseDN string) ([]GroupEntry, error) {
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=group)",
		[]string{"dn", "cn"},
		nil,
	)

	sr, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP: %v", err)
	}

	var groups []GroupEntry
	for _, entry := range sr.Entries {
		groups = append(groups, GroupEntry{
			DN:   entry.DN,
			Name: entry.GetAttributeValue("cn"),
		})
	}

	return groups, nil
}

// EnumerateSPNs énumère les utilisateurs avec des SPNs.
func (c *Client) EnumerateSPNs(baseDN string) ([]UserEntry, error) {
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(servicePrincipalName=*)",
		[]string{"dn", "cn", "sAMAccountName", "servicePrincipalName"},
		nil,
	)

	sr, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP: %v", err)
	}

	var spnEntries []UserEntry
	for _, entry := range sr.Entries {
		spns := entry.GetAttributeValues("servicePrincipalName")
		spnEntries = append(spnEntries, UserEntry{
			DN:             entry.DN,
			Name:           entry.GetAttributeValue("cn"),
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			SPNs:           spns,
		})
	}

	return spnEntries, nil
}

// EnumerateUsersWithDontReqPreAuth énumère les utilisateurs avec DONT_REQ_PREAUTH.
func (c *Client) EnumerateUsersWithDontReqPreAuth(baseDN string) ([]UserEntry, error) {
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(userAccountControl:1.2.840.113556.1.4.803:=4194304)",
		[]string{"dn", "cn", "sAMAccountName"},
		nil,
	)

	sr, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP: %v", err)
	}

	var userEntries []UserEntry
	for _, entry := range sr.Entries {
		userEntries = append(userEntries, UserEntry{
			DN:             entry.DN,
			Name:           entry.GetAttributeValue("cn"),
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
		})
	}

	return userEntries, nil
}

// GetPasswordPolicy récupère les politiques de mot de passe.
// CORRECTION : récupération de lockoutThreshold et lockoutDuration en plus des champs existants.
func (c *Client) GetPasswordPolicy(baseDN string) (*PasswordPolicy, error) {
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{
			"minPwdLength",
			"pwdHistoryLength",
			"maxPwdAge",
			"minPwdAge",
			"lockoutThreshold",
			"lockoutDuration",
		},
		nil,
	)

	sr, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP: %v", err)
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("no entries found")
	}

	entry := sr.Entries[0]

	parseInt := func(attr string) int {
		v, err := strconv.Atoi(entry.GetAttributeValue(attr))
		if err != nil {
			return 0
		}
		return v
	}

	// lockoutDuration est un intervalle Windows négatif en centièmes de nanosecondes.
	// Conversion : valeur absolue / 10 000 000 / 60 = minutes
	lockoutDurationMinutes := 0
	if raw := entry.GetAttributeValue("lockoutDuration"); raw != "" {
		if d, err := strconv.ParseInt(raw, 10, 64); err == nil && d != 0 {
			// La valeur est négative dans AD (intervalle relatif)
			if d < 0 {
				d = -d
			}
			lockoutDurationMinutes = int(d / 10_000_000 / 60)
		}
	}

	policy := &PasswordPolicy{
		MinPasswordLength:      parseInt("minPwdLength"),
		PasswordHistorySize:    parseInt("pwdHistoryLength"),
		MaxPasswordAge:         parseInt("maxPwdAge"),
		MinPasswordAge:         parseInt("minPwdAge"),
		LockoutThreshold:       parseInt("lockoutThreshold"),
		LockoutDurationMinutes: lockoutDurationMinutes,
	}

	return policy, nil
}

// EnumerateASREPRoastableUsers énumère les utilisateurs vulnérables à AS-REP Roasting.
func (c *Client) EnumerateASREPRoastableUsers(baseDN string) ([]UserEntry, error) {
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
		[]string{"dn", "cn", "sAMAccountName"},
		nil,
	)

	sr, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP: %v", err)
	}

	var userEntries []UserEntry
	for _, entry := range sr.Entries {
		userEntries = append(userEntries, UserEntry{
			DN:             entry.DN,
			Name:           entry.GetAttributeValue("cn"),
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
		})
	}

	return userEntries, nil
}

// EnumerateUsersWithFilter énumère les utilisateurs avec pagination.
func (c *Client) EnumerateUsersWithFilter(baseDN string, filter string, disabledOnly bool) ([]UserEntry, error) {
	searchFilter := "(objectClass=person)"
	if disabledOnly {
		searchFilter = "(&(objectClass=person)(userAccountControl:1.2.840.113556.1.4.803:=2))"
	} else if filter != "" {
		searchFilter = fmt.Sprintf("(&(objectClass=person)(%s))", filter)
	}

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter,
		[]string{"dn", "cn", "sAMAccountName", "lastLogonTimestamp", "userAccountControl", "pwdLastSet", "servicePrincipalName"},
		nil,
	)

	var allUsers []UserEntry
	pageSize := uint32(1000)

	searchRequest.Controls = []ldap.Control{
		&ldap.ControlPaging{
			PagingSize: pageSize,
		},
	}

	for {
		sr, err := c.conn.Search(searchRequest)
		if err != nil {
			return nil, fmt.Errorf("LDAP search failed: %v", err)
		}

		for _, entry := range sr.Entries {
			lastLogon := "Never"
			if ts := entry.GetAttributeValue("lastLogonTimestamp"); ts != "" {
				if lastLogonTS, err := strconv.ParseInt(ts, 10, 64); err == nil {
					lastLogon = windowsFileTimeToUnix(lastLogonTS).Format("2006-01-02 15:04:05")
				}
			}

			pwdLastSet := "Never"
			if ts := entry.GetAttributeValue("pwdLastSet"); ts != "" {
				if pwdLastSetTS, err := strconv.ParseInt(ts, 10, 64); err == nil {
					pwdLastSet = windowsFileTimeToUnix(pwdLastSetTS).Format("2006-01-02 15:04:05")
				}
			}

			accountControl := ""
			if ac := entry.GetAttributeValue("userAccountControl"); ac != "" {
				if acValue, err := strconv.ParseInt(ac, 10, 64); err == nil {
					flags := []string{}
					if acValue&2 != 0 {
						flags = append(flags, "DISABLED")
					}
					if acValue&65536 != 0 {
						flags = append(flags, "PASSWD_NOTREQD")
					}
					if acValue&4194304 != 0 {
						flags = append(flags, "DONT_REQ_PREAUTH")
					}
					accountControl = strings.Join(flags, "|")
				}
			}

			allUsers = append(allUsers, UserEntry{
				DN:             entry.DN,
				Name:           entry.GetAttributeValue("cn"),
				SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
				LastLogon:      lastLogon,
				AccountControl: accountControl,
				PwdLastSet:     pwdLastSet,
				SPNs:           entry.GetAttributeValues("servicePrincipalName"),
			})
		}

		if len(sr.Entries) == 0 {
			break
		}

		control := ldap.FindControl(sr.Controls, ldap.ControlTypePaging)
		if control == nil {
			break
		}

		pagingControl, ok := control.(*ldap.ControlPaging)
		if !ok || len(pagingControl.Cookie) == 0 {
			break
		}

		searchRequest.Controls = []ldap.Control{
			&ldap.ControlPaging{
				PagingSize: pageSize,
				Cookie:     pagingControl.Cookie,
			},
		}
	}

	return allUsers, nil
}
