// pkg/samr/spn.go
package samr

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// EnumerateSPNs énumère les utilisateurs avec des SPNs.
func EnumerateSPNs(ctx context.Context, client *Client, baseDN string) ([]UserEntry, error) {
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(servicePrincipalName=*)",
		[]string{"dn", "cn", "servicePrincipalName"},
		nil,
	)

	sr, err := client.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP: %v", err)
	}

	var spnEntries []UserEntry
	for _, entry := range sr.Entries {
		spns := entry.GetAttributeValues("servicePrincipalName")
		spnEntries = append(spnEntries, UserEntry{
			DN:   entry.DN,
			Name: entry.GetAttributeValue("cn"),
			SPNs: spns,
		})
	}

	return spnEntries, nil
}

// EnumerateUsersWithDontReqPreAuth énumère les utilisateurs avec DONT_REQ_PREAUTH.
func EnumerateUsersWithDontReqPreAuth(ctx context.Context, client *Client, baseDN string) ([]UserEntry, error) {
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(userAccountControl:1.2.840.113556.1.4.803:=4194304)",
		[]string{"dn", "cn"},
		nil,
	)

	sr, err := client.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP: %v", err)
	}

	var userEntries []UserEntry
	for _, entry := range sr.Entries {
		userEntries = append(userEntries, UserEntry{
			DN:   entry.DN,
			Name: entry.GetAttributeValue("cn"),
		})
	}

	return userEntries, nil
}
