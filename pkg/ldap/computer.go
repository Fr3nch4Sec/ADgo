// pkg/ldap/computer.go
package ldap

// Computer représente un ordinateur LDAP.
type Computer struct {
	DN              string `json:"-"`
	Name            string `json:"name"`
	SamAccount      string `json:"samaccountname"`
	SID             string `json:"objectsid"`
	OperatingSystem string `json:"operatingsystem,omitempty"`
}

// ToBloodHoundJSON convertit un ordinateur en format BloodHound.
func (c *Computer) ToBloodHoundJSON() map[string]interface{} {
	return map[string]interface{}{
		"Properties": map[string]interface{}{
			"name":            c.Name,
			"samaccountname":  c.SamAccount,
			"objectsid":       c.SID,
			"operatingsystem": c.OperatingSystem,
		},
		"ObjectType": "Computer",
	}
}
