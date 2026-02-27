// pkg/ldap/user.go
package ldap

import (
	"adgo/pkg/models"
)

// User représente un utilisateur LDAP.
type User struct {
	DN         string
	Name       string
	SamAccount string
	SID        string
	Enabled    bool
}

// ToBloodHoundJSON convertit un utilisateur en format BloodHound.
func ToBloodHoundJSON(user *models.User) map[string]interface{} {
	return map[string]interface{}{
		"Properties": map[string]interface{}{
			"name":                  user.Name,
			"samaccountname":        user.SamAccount,
			"objectsid":             user.SID,
			"primarygroupid":        user.PrimaryGroup,
			"serviceprincipalnames": user.SPNs,
			"enabled":               user.Enabled,
		},
		"ObjectType": "User",
	}
}
