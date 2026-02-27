// pkg/samr/enum.go
package samr

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// EnumerateAllUsers énumère tous les utilisateurs dans le domaine.
func EnumerateAllUsers(ctx context.Context, client *Client, baseDN string) ([]UserEntry, error) {
	users, err := client.EnumerateUsers(baseDN)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate users: %v", err)
	}
	return users, nil
}

// EnumerateAllGroups énumère tous les groupes dans le domaine.
func EnumerateAllGroups(ctx context.Context, client *Client, baseDN string) ([]GroupEntry, error) {
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=group)",
		[]string{"dn", "cn"},
		nil,
	)

	sr, err := client.conn.Search(searchRequest)
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
