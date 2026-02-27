// pkg/models/user.go
package models

// User représente un utilisateur LDAP.
type User struct {
	DN           string
	Name         string
	SamAccount   string
	SID          string
	PrimaryGroup string
	SPNs         []string
	Groups       []string
	Enabled      bool
}
