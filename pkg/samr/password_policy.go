// pkg/samr/password_policy.go
package samr

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// PasswordPolicy représente les politiques de mot de passe.
type PasswordPolicy struct {
	MinPasswordLength   int
	PasswordHistorySize int
	MaxPasswordAge      int
	MinPasswordAge      int
}

// GetPasswordPolicy récupère les politiques de mot de passe.
func GetPasswordPolicy(ctx context.Context, client *Client, baseDN string) (*PasswordPolicy, error) {
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		// il y avait une erreur ici, avec "ldap.ScopeBase", auquel j'ai ajouté "Object"
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"minPwdLength", "pwdHistoryLength", "maxPwdAge", "minPwdAge"},
		nil,
	)

	sr, err := client.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP: %v", err)
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("no entries found")
	}

	entry := sr.Entries[0]

	policy := &PasswordPolicy{}
	if len(entry.Attributes) > 0 {
		for _, attr := range entry.Attributes {
			switch attr.Name {
			case "minPwdLength":
				if len(attr.Values) > 0 {
					fmt.Sscanf(attr.Values[0], "%d", &policy.MinPasswordLength)
				}
			case "pwdHistoryLength":
				if len(attr.Values) > 0 {
					fmt.Sscanf(attr.Values[0], "%d", &policy.PasswordHistorySize)
				}
			case "maxPwdAge":
				if len(attr.Values) > 0 {
					fmt.Sscanf(attr.Values[0], "%d", &policy.MaxPasswordAge)
				}
			case "minPwdAge":
				if len(attr.Values) > 0 {
					fmt.Sscanf(attr.Values[0], "%d", &policy.MinPasswordAge)
				}
			}
		}
	}

	return policy, nil
}
