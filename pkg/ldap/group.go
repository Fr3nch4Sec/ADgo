// pkg/ldap/group.go
package ldap

// Group représente un groupe LDAP.
type Group struct {
	DN          string   `json:"-"`
	Name        string   `json:"name"`
	SamAccount  string   `json:"samaccountname"`
	SID         string   `json:"objectsid"`
	Members     []string `json:"members,omitempty"`
	Description string   `json:"description,omitempty"`
}

// ToBloodHoundJSON convertit un groupe en format BloodHound.
func (g *Group) ToBloodHoundJSON() map[string]interface{} {
	return map[string]interface{}{
		"Properties": map[string]interface{}{
			"name":           g.Name,
			"samaccountname": g.SamAccount,
			"objectsid":      g.SID,
			"description":    g.Description,
		},
		"ObjectType": "Group",
	}
}
