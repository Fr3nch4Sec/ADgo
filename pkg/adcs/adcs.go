// pkg/adcs/adcs.go

package adcs

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// ============================================================
// Types
// ============================================================

// CertAuthority représente une Autorité de Certification AD
type CertAuthority struct {
	Name         string
	DNSHostname  string
	DN           string
	WebEnrollURL string // http://<host>/certsrv — pour ESC8
}

// CertTemplate représente un template de certificat ADCS
type CertTemplate struct {
	Name             string
	DisplayName      string
	DN               string
	OID              string
	EKUs             []string // Extended Key Usages (OIDs)
	EnrollmentRights []string // Qui peut s'inscrire (SIDs/noms)
	RequiresApproval bool     // CT_FLAG_PEND_ALL_REQUESTS
	SANEnabled       bool     // CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (0x1)
	AuthorizedSig    int      // Nombre de signatures autorisées requises
	ValidityPeriod   string
	Vulnerabilities  []string // ["ESC1", "ESC4"...]
}

// ADCSClient client pour l'énumération ADCS via LDAP
type ADCSClient struct {
	conn   *ldap.Conn
	baseDN string
}

// Flags msPKI-Certificate-Name-Flag
const (
	CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT      = 0x00000001
	CT_FLAG_ENROLLEE_SUPPLIES_ALT_SUBJECT  = 0x00010000
	CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x00400000
)

// Flags msPKI-Enrollment-Flag
const (
	CT_FLAG_PEND_ALL_REQUESTS     = 0x00000002
	CT_FLAG_NO_SECURITY_EXTENSION = 0x00080000
)

// OIDs EKU importants
const (
	EKU_CLIENT_AUTH         = "1.3.6.1.5.5.7.3.2"
	EKU_SMART_CARD_LOGON    = "1.3.6.1.4.1.311.20.2.2"
	EKU_ANY_PURPOSE         = "2.5.29.37.0"
	EKU_CERTIFICATE_REQUEST = "1.3.6.1.4.1.311.21.8" // ADCS spécifique
)

// ============================================================
// Client
// ============================================================

// NewADCSClient crée un client ADCS connecté via LDAP existant
func NewADCSClient(conn *ldap.Conn, baseDN string) *ADCSClient {
	return &ADCSClient{conn: conn, baseDN: baseDN}
}

// ============================================================
// Enumération des CAs
// ============================================================

// EnumerateCAs liste toutes les Certificate Authorities du domaine
func (c *ADCSClient) EnumerateCAs() ([]CertAuthority, error) {
	// Les CAs sont dans : CN=Certification Authorities,CN=Public Key Services,
	//                      CN=Services,CN=Configuration,DC=...
	configDN := "CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration," + c.baseDN

	req := ldap.NewSearchRequest(
		configDN,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=certificationAuthority)",
		[]string{"cn", "dNSHostName", "distinguishedName"},
		nil,
	)

	sr, err := c.conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("CAs enumeration failure: %v", err)
	}

	var cas []CertAuthority
	for _, entry := range sr.Entries {
		hostname := entry.GetAttributeValue("dNSHostName")
		ca := CertAuthority{
			Name:        entry.GetAttributeValue("cn"),
			DNSHostname: hostname,
			DN:          entry.DN,
			// Web Enrollment URL pour tester ESC8
			WebEnrollURL: fmt.Sprintf("http://%s/certsrv", hostname),
		}
		cas = append(cas, ca)
	}

	return cas, nil
}

// ============================================================
// Enumération des Templates
// ============================================================

// EnumerateTemplates liste tous les templates et détecte les vulnérabilités
func (c *ADCSClient) EnumerateTemplates() ([]CertTemplate, error) {
	templatesDN := "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration," + c.baseDN

	req := ldap.NewSearchRequest(
		templatesDN,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=pKICertificateTemplate)",
		[]string{
			"cn",
			"displayName",
			"distinguishedName",
			"msPKI-Certificate-Name-Flag",
			"msPKI-Enrollment-Flag",
			"msPKI-RA-Signature",
			"pKIExtendedKeyUsage",
			"nTSecurityDescriptor",
			"pKIDefaultKeySpec",
			"pKIMaxIssuingDepth",
		},
		nil,
	)

	sr, err := c.conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("template enumeration failed: %v", err)
	}

	var templates []CertTemplate
	for _, entry := range sr.Entries {
		t := CertTemplate{
			Name:        entry.GetAttributeValue("cn"),
			DisplayName: entry.GetAttributeValue("displayName"),
			DN:          entry.DN,
			EKUs:        entry.GetAttributeValues("pKIExtendedKeyUsage"),
		}

		// Parser msPKI-Certificate-Name-Flag
		if flagStr := entry.GetAttributeValue("msPKI-Certificate-Name-Flag"); flagStr != "" {
			if flag, err := strconv.ParseInt(flagStr, 10, 64); err == nil {
				t.SANEnabled = (flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) != 0
			}
		}

		// Parser msPKI-Enrollment-Flag
		if flagStr := entry.GetAttributeValue("msPKI-Enrollment-Flag"); flagStr != "" {
			if flag, err := strconv.ParseInt(flagStr, 10, 64); err == nil {
				t.RequiresApproval = (flag & CT_FLAG_PEND_ALL_REQUESTS) != 0
			}
		}

		// Parser msPKI-RA-Signature (authorized signatures required)
		if sigStr := entry.GetAttributeValue("msPKI-RA-Signature"); sigStr != "" {
			if sig, err := strconv.Atoi(sigStr); err == nil {
				t.AuthorizedSig = sig
			}
		}

		// Détecter les vulnérabilités
		t.Vulnerabilities = detectVulnerabilities(t)

		templates = append(templates, t)
	}

	return templates, nil
}

// ============================================================
// Détection des vulnérabilités
// ============================================================

// detectVulnerabilities analyse un template et retourne la liste des ESC applicables
func detectVulnerabilities(t CertTemplate) []string {
	var vulns []string

	// ── ESC1 ────────────────────────────────────────────────
	// Conditions : SAN activé + EKU Client Auth + pas d'approbation + 0 signatures
	if t.SANEnabled && !t.RequiresApproval && t.AuthorizedSig == 0 && hasClientAuthEKU(t.EKUs) {
		vulns = append(vulns, "ESC1")
	}

	// ── ESC2 ────────────────────────────────────────────────
	// Template "Any Purpose" ou EKU vide (can be used for anything)
	if hasAnyPurposeEKU(t.EKUs) || len(t.EKUs) == 0 {
		if !t.RequiresApproval && t.AuthorizedSig == 0 {
			vulns = append(vulns, "ESC2")
		}
	}

	// ── ESC3 ────────────────────────────────────────────────
	// Template avec EKU Certificate Request Agent
	if hasCertRequestAgentEKU(t.EKUs) && !t.RequiresApproval {
		vulns = append(vulns, "ESC3")
	}

	return vulns
}

// hasClientAuthEKU vérifie si le template a l'EKU Client Authentication
func hasClientAuthEKU(ekus []string) bool {
	for _, eku := range ekus {
		if eku == EKU_CLIENT_AUTH || eku == EKU_SMART_CARD_LOGON {
			return true
		}
	}
	return false
}

// hasAnyPurposeEKU vérifie si le template a l'EKU "Any Purpose"
func hasAnyPurposeEKU(ekus []string) bool {
	for _, eku := range ekus {
		if eku == EKU_ANY_PURPOSE {
			return true
		}
	}
	return false
}

// hasCertRequestAgentEKU vérifie la présence du Certificate Request Agent EKU
func hasCertRequestAgentEKU(ekus []string) bool {
	for _, eku := range ekus {
		if strings.HasPrefix(eku, "1.3.6.1.4.1.311.20.2.1") {
			return true
		}
	}
	return false
}

// ============================================================
// ESC6 : Flag EDITF_ATTRIBUTESUBJECTALTNAME2 sur la CA
// ============================================================

// CheckESC6 vérifie si la CA a le flag EDITF_ATTRIBUTESUBJECTALTNAME2 activé
// Ce flag permet de spécifier un SAN arbitraire même sur les templates normaux
func (c *ADCSClient) CheckESC6() ([]string, error) {
	// Ce flag est dans la policy de la CA, accessible via LDAP sur l'enrollment service
	enrollmentDN := "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration," + c.baseDN

	req := ldap.NewSearchRequest(
		enrollmentDN,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=pKIEnrollmentService)",
		[]string{"cn", "flags"},
		nil,
	)

	sr, err := c.conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("ESC6 check failed: %v", err)
	}

	var vulnerable []string
	for _, entry := range sr.Entries {
		flagStr := entry.GetAttributeValue("flags")
		if flagStr != "" {
			if flag, err := strconv.ParseInt(flagStr, 10, 64); err == nil {
				// EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000 = 262144
				if (flag & 0x00040000) != 0 {
					vulnerable = append(vulnerable, entry.GetAttributeValue("cn"))
				}
			}
		}
	}

	return vulnerable, nil
}

// ============================================================
// ESC8 : Vérification du Web Enrollment HTTP (NTLM relay possible)
// ============================================================

// CheckESC8 vérifie si le Web Enrollment accepte NTLM (vulnérable au relay)
func CheckESC8(caURL string) bool {
	// ESC8 : /certsrv/ accessible en HTTP + authentification NTLM
	// Si le header WWW-Authenticate contient "NTLM" → vulnérable au relay
	// Note : on ne fait pas de vraie requête ici pour éviter les logs côté CA
	// En vrai pentest : utiliser ntlmrelayx vers http://<CA>/certsrv/certfnsh.asp

	// Vérification simple : l'URL utilise HTTP (pas HTTPS) → potentiellement vulnérable
	return strings.HasPrefix(caURL, "http://")
}

// ============================================================
// Fonction principale d'audit
// ============================================================

// RunAudit effectue un audit complet ADCS et affiche les résultats
func RunAudit(ctx context.Context, ldapConn *ldap.Conn, baseDN string) error {
	client := NewADCSClient(ldapConn, baseDN)

	fmt.Println("\n[*] === ADCS Audit ===")

	// 1. Lister les CAs
	fmt.Println("\n[*] List of Certificate Authorities...")
	cas, err := client.EnumerateCAs()
	if err != nil {
		return fmt.Errorf("CAs enumeration failed: %v", err)
	}

	for _, ca := range cas {
		fmt.Printf("  [CA] %s (%s)\n", ca.Name, ca.DNSHostname)
		fmt.Printf("       Web Enrollment : %s\n", ca.WebEnrollURL)
		if CheckESC8(ca.WebEnrollURL) {
			fmt.Printf("       [!] Potential ESC8 : Active HTTP Web Enrollment → NTLM relay possible\n")
		}
	}

	// 2. Vérifier ESC6
	fmt.Println("\n[*] ESC6 Verification (EDITF_ATTRIBUTESUBJECTALTNAME2)...")
	esc6CAs, err := client.CheckESC6()
	if err != nil {
		fmt.Printf("  [-] ESC6 check failed: %v\n", err)
	} else if len(esc6CAs) > 0 {
		for _, ca := range esc6CAs {
			fmt.Printf("  [!] ESC6 : CA '%s' has the flag EDITF_ATTRIBUTESUBJECTALTNAME2 activated\n", ca)
		}
	} else {
		fmt.Println("  [+] No CA vulnerable to ESC6 detected")
	}

	// 3. Lister les templates vulnérables
	fmt.Println("\n[*] Certificate Template Analysis...")
	templates, err := client.EnumerateTemplates()
	if err != nil {
		return fmt.Errorf("template enumeration failed: %v", err)
	}

	vulnFound := false
	for _, t := range templates {
		if len(t.Vulnerabilities) > 0 {
			vulnFound = true
			fmt.Printf("\n  [!] Vulnerable template : %s\n", t.Name)
			fmt.Printf("      Vulnerabilities : %s\n", strings.Join(t.Vulnerabilities, ", "))
			fmt.Printf("      SAN enabled     : %v\n", t.SANEnabled)
			fmt.Printf("      Approbation    : %v\n", t.RequiresApproval)
			fmt.Printf("      EKUs           : %s\n", strings.Join(t.EKUs, ", "))
			if containsStr(t.Vulnerabilities, "ESC1") {
				fmt.Printf("      [>] Exploit ESC1 : adgo adcs exploit --template %s --upn administrator@%s\n",
					t.Name, baseDN)
			}
		}
	}

	if !vulnFound {
		fmt.Println("  [+] No vulnerable templates detected")
	}

	fmt.Printf("\n[*] Audit completed : %d CAs, %d templates analyzed\n", len(cas), len(templates))
	return nil
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
