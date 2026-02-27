// pkg/kerberos/tickets.go
package kerberos

import (
	"fmt"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
)

// EnumerateTickets énumère les tickets Kerberos.
func EnumerateTickets(username, password, domain, kdc string) error {
	cfg, err := config.Load("/etc/krb5.conf")
	if err != nil {
		return fmt.Errorf("failed to load Kerberos config: %v", err)
	}

	cl := client.NewWithPassword(username, domain, password, cfg)
	err = cl.Login()
	if err != nil {
		return fmt.Errorf("failed to login: %v", err)
	}

	// Exemple de récupération de ticket
	fmt.Printf("Successfully authenticated with Kerberos for user: %s\n", username)

	return nil
}
