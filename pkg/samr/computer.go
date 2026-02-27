// pkg/samr/computer.go
package samr

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// ComputerEntry représente un ordinateur Active Directory.
type ComputerEntry struct {
	DN   string
	Name string
}

// EnumerateAllComputers énumère tous les ordinateurs dans le domaine.
func EnumerateAllComputers(ctx context.Context, client *Client, baseDN string) ([]ComputerEntry, error) {
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=computer)",
		[]string{"dn", "cn"},
		nil,
	)

	sr, err := client.conn.Search(searchRequest)
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
