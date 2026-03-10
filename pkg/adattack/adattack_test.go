// pkg/adattack/adattack_test.go
package adattack

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"strings"
	"testing"
)

// =============================================================================
// TESTS : parseSID / encodeSID
// =============================================================================

func TestParseSID_System(t *testing.T) {
	// S-1-5-18 = SYSTEM — structure documentée Microsoft
	raw := make([]byte, 12)
	raw[0] = 0x01 // Revision = 1
	raw[1] = 0x01 // SubAuthorityCount = 1
	// Authority = 5 (bytes 2-7, big-endian)
	raw[7] = 0x05
	// SubAuthority[0] = 18
	binary.LittleEndian.PutUint32(raw[8:], 18)

	result := parseSID(raw)
	if result != "S-1-5-18" {
		t.Errorf("attendu %q, obtenu %q", "S-1-5-18", result)
	}
}

func TestParseSID_DomainUser(t *testing.T) {
	// S-1-5-21-1000-2000-3000-500
	raw := make([]byte, 8+5*4)
	raw[0] = 0x01 // Revision
	raw[1] = 0x05 // SubAuthorityCount = 5
	raw[7] = 0x05 // Authority = 5
	binary.LittleEndian.PutUint32(raw[8:], 21)
	binary.LittleEndian.PutUint32(raw[12:], 1000)
	binary.LittleEndian.PutUint32(raw[16:], 2000)
	binary.LittleEndian.PutUint32(raw[20:], 3000)
	binary.LittleEndian.PutUint32(raw[24:], 500)

	result := parseSID(raw)
	expected := "S-1-5-21-1000-2000-3000-500"
	if result != expected {
		t.Errorf("attendu %q, obtenu %q", expected, result)
	}
}

func TestParseSID_TooShort(t *testing.T) {
	// Doit retourner "" sans paniquer
	result := parseSID([]byte{0x01, 0x02})
	if result != "" {
		t.Errorf("SID trop court : attendu \"\", obtenu %q", result)
	}
}

func TestEncodeSID_RoundTrip(t *testing.T) {
	// Encode puis redécode → doit retrouver le SID original
	original := "S-1-5-21-1000-2000-3000-500"

	encoded, err := encodeSID(original)
	if err != nil {
		t.Fatalf("encodeSID échoué : %v", err)
	}

	decoded := parseSID(encoded)
	if decoded != original {
		t.Errorf("round-trip échoué : attendu %q, obtenu %q", original, decoded)
	}
}

func TestEncodeSID_Invalid(t *testing.T) {
	_, err := encodeSID("pas-un-sid")
	if err == nil {
		t.Error("encodeSID invalide : attendu une erreur, obtenu nil")
	}
}

func TestEncodeSID_System(t *testing.T) {
	encoded, err := encodeSID("S-1-5-18")
	if err != nil {
		t.Fatalf("encodeSID S-1-5-18 échoué : %v", err)
	}
	if len(encoded) < 12 {
		t.Fatalf("encoded trop court : %d bytes", len(encoded))
	}
	if encoded[0] != 0x01 {
		t.Errorf("Revision : attendu 1, obtenu %d", encoded[0])
	}
	if encoded[1] != 0x01 {
		t.Errorf("SubAuthCount : attendu 1, obtenu %d", encoded[1])
	}
}

// =============================================================================
// TESTS : buildKeyCredentialBlob
// =============================================================================

func TestBuildKeyCredentialBlob_Version(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("génération clé RSA échouée : %v", err)
	}

	keyID, blob, err := buildKeyCredentialBlob(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("buildKeyCredentialBlob échoué : %v", err)
	}

	if keyID == "" {
		t.Error("KeyID vide")
	}
	if len(blob) < 4 {
		t.Fatalf("blob trop court : %d bytes", len(blob))
	}

	version := binary.LittleEndian.Uint32(blob[0:4])
	if version != 0x00000200 {
		t.Errorf("version : attendu 0x200, obtenu 0x%X", version)
	}
}

func TestBuildKeyCredentialBlob_BlobSize(t *testing.T) {
	// Une clé RSA 2048 encodée en DER fait ~270 bytes
	// Le blob doit être significativement plus grand que ça
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, blob, err := buildKeyCredentialBlob(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("buildKeyCredentialBlob échoué : %v", err)
	}
	if len(blob) < 300 {
		t.Errorf("blob trop petit pour une clé RSA 2048 : %d bytes", len(blob))
	}
}

func TestBuildKeyCredentialBlob_KeyIDBase64(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyID, _, _ := buildKeyCredentialBlob(&privKey.PublicKey)

	for _, c := range keyID {
		valid := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' || c == '='
		if !valid {
			t.Errorf("KeyID contient un caractère non-Base64 : %q", c)
			break
		}
	}
}

// =============================================================================
// TESTS : appendEntry
// =============================================================================

func TestAppendEntry_Format(t *testing.T) {
	value := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	entry := appendEntry(3, value)

	// Taille totale : 2 (type) + 4 (len) + len(value)
	if len(entry) != 6+len(value) {
		t.Errorf("longueur : attendu %d, obtenu %d", 6+len(value), len(entry))
	}

	entryType := binary.LittleEndian.Uint16(entry[0:2])
	if entryType != 3 {
		t.Errorf("type : attendu 3, obtenu %d", entryType)
	}

	entryLen := binary.LittleEndian.Uint32(entry[2:6])
	if entryLen != uint32(len(value)) {
		t.Errorf("len encodée : attendu %d, obtenu %d", len(value), entryLen)
	}

	if !bytes.Equal(entry[6:], value) {
		t.Error("valeur corrompue dans l'entry")
	}
}

// =============================================================================
// TESTS : buildRBCDSecurityDescriptor / parseSecurityDescriptor (round-trip)
// =============================================================================

func TestBuildRBCDSecurityDescriptor_Structure(t *testing.T) {
	sd, err := buildRBCDSecurityDescriptor("S-1-5-21-1000-2000-3000-1105")
	if err != nil {
		t.Fatalf("buildRBCDSecurityDescriptor échoué : %v", err)
	}

	if len(sd) < 20 {
		t.Fatalf("SD trop court : %d bytes", len(sd))
	}
	if sd[0] != 0x01 {
		t.Errorf("Revision : attendu 1, obtenu %d", sd[0])
	}

	control := binary.LittleEndian.Uint16(sd[2:4])
	if (control & 0x0004) == 0 {
		t.Errorf("SE_DACL_PRESENT absent : Control=0x%04X", control)
	}

	daclOffset := binary.LittleEndian.Uint32(sd[16:20])
	if int(daclOffset) >= len(sd) {
		t.Errorf("DACL offset hors limites : offset=%d, len=%d", daclOffset, len(sd))
	}
}

func TestBuildRBCDSecurityDescriptor_InvalidSID(t *testing.T) {
	_, err := buildRBCDSecurityDescriptor("SID-INVALIDE")
	if err == nil {
		t.Error("SID invalide : attendu une erreur, obtenu nil")
	}
}

func TestParseSecurityDescriptor_RoundTrip(t *testing.T) {
	// Construire un SD → le parser → retrouver le SID
	sid := "S-1-5-21-1000-2000-3000-1105"
	sd, err := buildRBCDSecurityDescriptor(sid)
	if err != nil {
		t.Fatalf("construction SD échouée : %v", err)
	}

	aces, err := parseSecurityDescriptor(sd)
	if err != nil {
		t.Fatalf("parsing SD échoué : %v", err)
	}
	if len(aces) == 0 {
		t.Fatal("aucune ACE parsée")
	}

	found := false
	for _, ace := range aces {
		if strings.Contains(ace.SID, "1105") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("SID avec sub-auth 1105 introuvable dans les ACEs : %+v", aces)
	}
}

func TestParseSecurityDescriptor_TooShort(t *testing.T) {
	_, err := parseSecurityDescriptor([]byte{0x01, 0x00})
	if err == nil {
		t.Error("SD trop court : attendu une erreur")
	}
}

func TestParseSecurityDescriptor_NoDACL(t *testing.T) {
	// SD valide mais sans DACL (tous les offsets à 0)
	sd := make([]byte, 20)
	sd[0] = 0x01 // Revision valide, daclOffset = 0

	aces, err := parseSecurityDescriptor(sd)
	if err != nil {
		t.Errorf("SD sans DACL ne doit pas erreur : %v", err)
	}
	if len(aces) != 0 {
		t.Errorf("SD sans DACL ne doit pas retourner d'ACEs : %d trouvées", len(aces))
	}
}

// =============================================================================
// TESTS : helpers
// =============================================================================

func TestSanitizeFilename(t *testing.T) {
	cases := []struct{ in, out string }{
		{"john", "john"},
		{"JOHN.DOE", "JOHN_DOE"},
		{"user@domain.local", "user_domain_local"},
		{"CN=John,DC=lab,DC=local", "CN_John_DC_lab_DC_local"},
		{"normal_user-01", "normal_user-01"},
	}
	for _, c := range cases {
		if got := sanitizeFilename(c.in); got != c.out {
			t.Errorf("sanitizeFilename(%q) : attendu %q, obtenu %q", c.in, c.out, got)
		}
	}
}

func TestContainsStr(t *testing.T) {
	if !containsStr("CN=john,DC=lab", "=") {
		t.Error("doit trouver '=' dans un DN")
	}
	if containsStr("john", "=") {
		t.Error("ne doit pas trouver '=' dans un sAMAccountName")
	}
	if !containsStr("abc", "abc") {
		t.Error("égalité exacte doit retourner true")
	}
	if containsStr("ab", "abc") {
		t.Error("substr plus longue que s doit retourner false")
	}
}

func TestContainsKeyID_Match(t *testing.T) {
	value := "B:100:deadbeef:CN=john,DC=lab,DC=local"
	keyID := sha256Hex(value)[:16]

	if !containsKeyID(value, keyID) {
		t.Error("doit matcher avec le bon KeyID")
	}
	if containsKeyID(value, "0000000000000000") {
		t.Error("ne doit pas matcher avec un mauvais KeyID")
	}
}

func TestContainsKeyID_EmptyInputs(t *testing.T) {
	if containsKeyID("", "abc") {
		t.Error("value vide doit retourner false")
	}
	if containsKeyID("abc", "") {
		t.Error("keyID vide doit retourner false")
	}
}
