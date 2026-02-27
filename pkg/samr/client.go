// pkg/samr/client.go
package samr

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	"adgo/pkg/common"

	"github.com/go-ldap/ldap/v3"
)

// Client représente un client LDAP connecté.
type Client struct {
	conn *ldap.Conn
}

// NewClient crée un nouveau client LDAP.
func NewClient(ctx context.Context, creds common.Credentials) (*Client, error) {
	var l *ldap.Conn
	var err error

	switch creds.AuthMethod {
	case "ldap":
		l, err = ldap.DialURL(creds.LDAPServer)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to LDAP server: %v", err)
		}

		if creds.UseSSL {
			err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
			if err != nil {
				return nil, fmt.Errorf("failed to start TLS: %v", err)
			}
		}

		err = l.Bind(creds.BindDN, creds.Password)
		if err != nil {
			return nil, fmt.Errorf("failed to bind to LDAP server: %v", err)
		}
	case "certificate":
		cert, err := tls.LoadX509KeyPair(creds.CertFile, creds.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate: %v", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		l, err = ldap.DialTLS("tcp", strings.TrimPrefix(creds.LDAPServer, "ldap://"), tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to LDAP server: %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupported authentication method: %s", creds.AuthMethod)
	}

	return &Client{conn: l}, nil
}

// Close ferme la connexion du client LDAP.
func (c *Client) Close() error {
	return c.conn.Close()
}

// EnumerateUsers énumère les utilisateurs dans le domaine.
func (c *Client) EnumerateUsers(baseDN string) ([]UserEntry, error) {
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=person)",
		[]string{"dn", "cn"},
		nil,
	)

	sr, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP: %v", err)
	}

	var users []UserEntry
	for _, entry := range sr.Entries {
		users = append(users, UserEntry{
			DN:   entry.DN,
			Name: entry.GetAttributeValue("cn"),
		})
	}

	return users, nil
}
