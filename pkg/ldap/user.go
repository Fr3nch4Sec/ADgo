// pkg/ldap/user.go

package ldap

import "adgo/pkg/models"

// ToBloodHoundJSON convertit un utilisateur en format BloodHound.
func ToBloodHoundJSON(user *models.User) map[string]interface{} {
	return map[string]interface{}{
		"Properties": map[string]interface{}{
			"name":                  user.Name,
			"samaccountname":        user.SAMAccountName, // CORRECTION : SamAccount → SAMAccountName
			"objectsid":             user.SID,
			"primarygroupid":        user.PrimaryGroupID, // CORRECTION : PrimaryGroup → PrimaryGroupID
			"serviceprincipalnames": user.SPNs,
			"enabled":               user.Enabled,
		},
		"ObjectType": "User",
	}
}
