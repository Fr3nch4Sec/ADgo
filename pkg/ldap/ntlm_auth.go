// pkg/ldap/ntlm_auth.go
package ldap

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
)

// NewClientNTLM crée un client LDAP avec authentification NTLM.
// Supporte le mot de passe ET le Pass-the-Hash (NT hash en hex).
//
// Exemples :
//
//	// Mot de passe classique
//	c, err := ldap.NewClientNTLM(ctx, "ldap://192.168.1.10:389", "LAB", "john", "Password123", "", false)
//
//	// Pass-the-Hash
//	c, err := ldap.NewClientNTLM(ctx, "ldap://192.168.1.10:389", "LAB", "john", "", "aad3b435b51404eeaad3b435b51404ee", false)
func NewClientNTLM(ctx context.Context, ldapServer, domain, username, password, ntHash string, useSSL bool) (*Client, error) {
	l, err := goldap.DialURL(ldapServer)
	if err != nil {
		return nil, fmt.Errorf("LDAP connection failed: %v", err)
	}

	if useSSL {
		if err := l.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
			l.Close()
			return nil, fmt.Errorf("LDAP StartTLS failed: %v", err)
		}
	}

	if ntHash != "" {
		// === Pass-the-Hash via NTLM SASL ===
		// Valider que le hash est bien 32 caractères hex (16 bytes)
		ntHash = strings.TrimSpace(ntHash)
		hashBytes, err := hex.DecodeString(ntHash)
		if err != nil || len(hashBytes) != 16 {
			l.Close()
			return nil, fmt.Errorf("invalid NT hash (must be 32 hex chars, got %d chars)", len(ntHash))
		}

		// go-ldap v3.4.12 : NTLMBindRequest.Hash est un string (hex encodé)
		req := &goldap.NTLMBindRequest{
			Domain:   domain,
			Username: username,
			Hash:     ntHash,
		}
		if _, err := l.NTLMChallengeBind(req); err != nil {
			l.Close()
			return nil, fmt.Errorf("LDAP NTLM PtH bind failed (%s\\%s): %v", domain, username, err)
		}
	} else {
		// === Authentification NTLM par mot de passe ===
		if err := l.NTLMBind(domain, username, password); err != nil {
			l.Close()
			return nil, fmt.Errorf("LDAP NTLM bind failed (%s\\%s): %v", domain, username, err)
		}
	}

	return &Client{conn: l}, nil
}

// NewClientAuto crée un client LDAP en choisissant automatiquement la méthode :
//   - NTLMHash fourni → NTLM Pass-the-Hash
//   - Password + Domain fournis → NTLM avec mot de passe
//   - Sinon → simple bind (BindDN + password)
func NewClientAuto(ctx context.Context, ldapServer, bindDN, password, domain, username, ntHash string, useSSL bool) (*Client, error) {
	if domain != "" && username != "" {
		return NewClientNTLM(ctx, ldapServer, domain, username, password, ntHash, useSSL)
	}
	return NewClient(ctx, ldapServer, bindDN, password, useSSL)
}
