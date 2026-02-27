// pkg/samr/types.go
package samr

// UserEntry représente un utilisateur Active Directory.
type UserEntry struct {
	DN   string
	Name string
	SPNs []string
}

// GroupEntry représente un groupe Active Directory.
type GroupEntry struct {
	DN   string
	Name string
}
