// pkg/ldap/ldap.go
package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"strconv"

	"github.com/go-ldap/ldap/v3"
)

// UserEntry représente un utilisateur Active Directory.
type UserEntry struct {
	DN             string
	Name           string
	SAMAccountName string
	SPNs           []string
}

// GroupEntry représente un groupe Active Directory.
type GroupEntry struct {
	DN   string
	Name string
}

// PasswordPolicy représente les politiques de mot de passe.
type PasswordPolicy struct {
	MinPasswordLength   int
	PasswordHistorySize int
	MaxPasswordAge      int
	MinPasswordAge      int
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

// UserHash représente un utilisateur avec son hash NTLM.
type UserHash struct {
	DN             string
	Name           string
	SAMAccountName string
	NTLMHash       string
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
			NTLMHash:       "", // Placeholder pour le hash NTLM
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
func (c *Client) GetPasswordPolicy(baseDN string) (*PasswordPolicy, error) {
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"minPwdLength", "pwdHistoryLength", "maxPwdAge", "minPwdAge"},
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

	minPwdLength, err := strconv.Atoi(entry.GetAttributeValue("minPwdLength"))
	if err != nil {
		minPwdLength = 0
	}

	pwdHistoryLength, err := strconv.Atoi(entry.GetAttributeValue("pwdHistoryLength"))
	if err != nil {
		pwdHistoryLength = 0
	}

	maxPwdAge, err := strconv.Atoi(entry.GetAttributeValue("maxPwdAge"))
	if err != nil {
		maxPwdAge = 0
	}

	minPwdAge, err := strconv.Atoi(entry.GetAttributeValue("minPwdAge"))
	if err != nil {
		minPwdAge = 0
	}

	policy := &PasswordPolicy{
		MinPasswordLength:   minPwdLength,
		PasswordHistorySize: pwdHistoryLength,
		MaxPasswordAge:      maxPwdAge,
		MinPasswordAge:      minPwdAge,
	}

	return policy, nil
}

// EnumerateASREPRoastableUsers énumère les utilisateurs vulnérables à AS-REP Roasting.
func (c *Client) EnumerateASREPRoastableUsers(baseDN string) ([]UserEntry, error) {
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=user)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=4194304)))",
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
