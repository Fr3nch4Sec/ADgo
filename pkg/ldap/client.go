// pkg/ldap/client.go
package ldap

import "adgo/pkg/models"

func (c *Client) EnumerateAllUsers(baseDN string) ([]*models.User, error) {
	// Logique pour récupérer les utilisateurs
	users := []*models.User{
		{
			Name:       "Administrator",
			SamAccount: "administrator",
			SID:        "S-1-5-21-123456789-1234567890-123456789-500",
			Enabled:    true,
		},
	}
	return users, nil
}
