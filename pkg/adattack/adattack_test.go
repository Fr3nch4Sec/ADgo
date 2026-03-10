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
	raw := make([]byte, 12)
	raw[0] = 0x01
	raw[1] = 0x01
	raw[7] = 0x05
	binary.LittleEndian.PutUint32(raw[8:], 18)

	result := parseSID(raw)
	if result != "S-1-5-18" {
		t.Errorf("expected %q, got %q", "S-1-5-18", result)
	}
}

func TestParseSID_DomainUser(t *testing.T) {
	raw := make([]byte, 8+5*4)
	raw[0] = 0x01
	raw[1] = 0x05
	raw[7] = 0x05
	binary.LittleEndian.PutUint32(raw[8:], 21)
	binary.LittleEndian.PutUint32(raw[12:], 1000)
	binary.LittleEndian.PutUint32(raw[16:], 2000)
	binary.LittleEndian.PutUint32(raw[20:], 3000)
	binary.LittleEndian.PutUint32(raw[24:], 500)

	result := parseSID(raw)
	expected := "S-1-5-21-1000-2000-3000-500"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestParseSID_TooShort(t *testing.T) {
	result := parseSID([]byte{0x01, 0x02})
	if result != "" {
		t.Errorf("short SID: expected \"\", got %q", result)
	}
}

func TestEncodeSID_RoundTrip(t *testing.T) {
	original := "S-1-5-21-1000-2000-3000-500"
	encoded, err := encodeSID(original)
	if err != nil {
		t.Fatalf("encodeSID failed: %v", err)
	}
	decoded := parseSID(encoded)
	if decoded != original {
		t.Errorf("round-trip failed: expected %q, got %q", original, decoded)
	}
}

func TestEncodeSID_Invalid(t *testing.T) {
	_, err := encodeSID("not-a-sid")
	if err == nil {
		t.Error("encodeSID on invalid input: expected error, got nil")
	}
}

func TestEncodeSID_System(t *testing.T) {
	encoded, err := encodeSID("S-1-5-18")
	if err != nil {
		t.Fatalf("encodeSID S-1-5-18 failed: %v", err)
	}
	if len(encoded) < 12 {
		t.Fatalf("encoded too short: %d bytes", len(encoded))
	}
	if encoded[0] != 0x01 {
		t.Errorf("Revision: expected 1, got %d", encoded[0])
	}
	if encoded[1] != 0x01 {
		t.Errorf("SubAuthorityCount: expected 1, got %d", encoded[1])
	}
}

// =============================================================================
// TESTS : buildKeyCredentialBlob
// =============================================================================

func TestBuildKeyCredentialBlob_Version(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("RSA key generation failed: %v", err)
	}

	keyID, blob, err := buildKeyCredentialBlob(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("buildKeyCredentialBlob failed: %v", err)
	}

	if keyID == "" {
		t.Error("KeyID is empty")
	}
	if len(blob) < 4 {
		t.Fatalf("blob too short: %d bytes", len(blob))
	}

	version := binary.LittleEndian.Uint32(blob[0:4])
	if version != 0x00000200 {
		t.Errorf("version: expected 0x200, got 0x%X", version)
	}
}

func TestBuildKeyCredentialBlob_BlobSize(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, blob, err := buildKeyCredentialBlob(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("buildKeyCredentialBlob failed: %v", err)
	}
	if len(blob) < 300 {
		t.Errorf("blob too small for 2048-bit RSA: %d bytes", len(blob))
	}
}

func TestBuildKeyCredentialBlob_KeyIDBase64(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyID, _, _ := buildKeyCredentialBlob(&privKey.PublicKey)

	for _, c := range keyID {
		valid := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' || c == '='
		if !valid {
			t.Errorf("KeyID contains invalid base64 character: %q", c)
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

	if len(entry) != 6+len(value) {
		t.Errorf("incorrect length: expected %d, got %d", 6+len(value), len(entry))
	}

	entryType := binary.LittleEndian.Uint16(entry[0:2])
	if entryType != 3 {
		t.Errorf("type: expected 3, got %d", entryType)
	}

	entryLen := binary.LittleEndian.Uint32(entry[2:6])
	if entryLen != uint32(len(value)) {
		t.Errorf("encoded length: expected %d, got %d", len(value), entryLen)
	}

	if !bytes.Equal(entry[6:], value) {
		t.Error("value corrupted in entry")
	}
}

// =============================================================================
// TESTS : buildRBCDSecurityDescriptor / parseSecurityDescriptor
// =============================================================================

func TestBuildRBCDSecurityDescriptor_Structure(t *testing.T) {
	sd, err := buildRBCDSecurityDescriptor("S-1-5-21-1000-2000-3000-1105")
	if err != nil {
		t.Fatalf("buildRBCDSecurityDescriptor failed: %v", err)
	}

	if len(sd) < 20 {
		t.Fatalf("security descriptor too short: %d bytes", len(sd))
	}
	if sd[0] != 0x01 {
		t.Errorf("Revision: expected 1, got %d", sd[0])
	}

	control := binary.LittleEndian.Uint16(sd[2:4])
	if (control & 0x0004) == 0 {
		t.Errorf("SE_DACL_PRESENT missing: Control=0x%04X", control)
	}

	daclOffset := binary.LittleEndian.Uint32(sd[16:20])
	if int(daclOffset) >= len(sd) {
		t.Errorf("DACL offset out of bounds: %d (size %d)", daclOffset, len(sd))
	}
}

func TestBuildRBCDSecurityDescriptor_InvalidSID(t *testing.T) {
	_, err := buildRBCDSecurityDescriptor("INVALID-SID")
	if err == nil {
		t.Error("invalid SID: expected error, got nil")
	}
}

func TestParseSecurityDescriptor_RoundTrip(t *testing.T) {
	sid := "S-1-5-21-1000-2000-3000-1105"
	sd, err := buildRBCDSecurityDescriptor(sid)
	if err != nil {
		t.Fatalf("failed to build SD: %v", err)
	}

	aces, err := parseSecurityDescriptor(sd)
	if err != nil {
		t.Fatalf("failed to parse SD: %v", err)
	}
	if len(aces) == 0 {
		t.Fatal("no ACEs parsed")
	}

	found := false
	for _, ace := range aces {
		if strings.Contains(ace.SID, "1105") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("SID ending with 1105 not found in ACEs: %+v", aces)
	}
}

func TestParseSecurityDescriptor_TooShort(t *testing.T) {
	_, err := parseSecurityDescriptor([]byte{0x01, 0x00})
	if err == nil {
		t.Error("short security descriptor: expected error")
	}
}

func TestParseSecurityDescriptor_NoDACL(t *testing.T) {
	sd := make([]byte, 20)
	sd[0] = 0x01

	aces, err := parseSecurityDescriptor(sd)
	if err != nil {
		t.Errorf("SD without DACL should not error: %v", err)
	}
	if len(aces) != 0 {
		t.Errorf("SD without DACL should return 0 ACEs, got %d", len(aces))
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
			t.Errorf("sanitizeFilename(%q): expected %q, got %q", c.in, c.out, got)
		}
	}
}

func TestContainsStr(t *testing.T) {
	if !containsStr("CN=john,DC=lab", "=") {
		t.Error("should find '=' in DN")
	}
	if containsStr("john", "=") {
		t.Error("should not find '=' in sAMAccountName")
	}
	if !containsStr("abc", "abc") {
		t.Error("exact match should return true")
	}
	if containsStr("ab", "abc") {
		t.Error("longer substring should return false")
	}
}

func TestContainsKeyID_Match(t *testing.T) {
	value := "B:100:deadbeef:CN=john,DC=lab,DC=local"
	keyID := sha256Hex(value)[:16]

	if !containsKeyID(value, keyID) {
		t.Error("should match correct KeyID")
	}
	if containsKeyID(value, "0000000000000000") {
		t.Error("should not match wrong KeyID")
	}
}

func TestContainsKeyID_EmptyInputs(t *testing.T) {
	if containsKeyID("", "abc") {
		t.Error("empty value should return false")
	}
	if containsKeyID("abc", "") {
		t.Error("empty keyID should return false")
	}
}
