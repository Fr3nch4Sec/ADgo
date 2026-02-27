// pkg/samr/orga_unit.go
package samr

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// OUEntry représente une unité d'organisation Active Directory.
type OUEntry struct {
	DN   string
	Name string
}

// EnumerateAllOUs énumère toutes les unités d'organisation dans le domaine.
func EnumerateAllOUs(ctx context.Context, client *Client, baseDN string) ([]OUEntry, error) {
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=organizationalUnit)",
		[]string{"dn", "ou"},
		nil,
	)

	sr, err := client.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP: %v", err)
	}

	var ous []OUEntry
	for _, entry := range sr.Entries {
		ous = append(ous, OUEntry{
			DN:   entry.DN,
			Name: entry.GetAttributeValue("ou"),
		})
	}

	return ous, nil
}
