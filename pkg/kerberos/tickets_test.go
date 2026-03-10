// pkg/kerberos/tickets_test.go
package kerberos

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// =============================================================================
// TESTS : buildCCacheHeader
// =============================================================================

func TestCCacheHeader_MagicBytes(t *testing.T) {
	// Le header MIT ccache v4 commence toujours par 0x0504
	header := buildCCacheHeader()

	if len(header) < 2 {
		t.Fatalf("header too short: %d bytes", len(header))
	}

	tag := binary.BigEndian.Uint16(header[0:2])
	if tag != 0x0504 {
		t.Errorf("magic bytes: expected 0x0504, got 0x%04X", tag)
	}
}

func TestCCacheHeader_HeaderLenField(t *testing.T) {
	// Bytes 2-3 : longueur des tags du header — doit être > 0
	header := buildCCacheHeader()

	if len(header) < 4 {
		t.Fatalf("header too short: %d bytes", len(header))
	}

	headerLen := binary.BigEndian.Uint16(header[2:4])
	if headerLen == 0 {
		t.Error("header_len field is 0 — time_offset tag missing")
	}
}

func TestCCacheHeader_TimeOffsetTag(t *testing.T) {
	// Le premier tag doit être 0x0001 (time offset)
	header := buildCCacheHeader()

	if len(header) < 6 {
		t.Fatalf("header too short for tag: %d bytes", len(header))
	}

	tagType := binary.BigEndian.Uint16(header[4:6])
	if tagType != 0x0001 {
		t.Errorf("first tag type: expected 0x0001, got 0x%04X", tagType)
	}
}

// =============================================================================
// TESTS : encodePrincipal
// =============================================================================

func TestEncodePrincipal_NameType(t *testing.T) {
	// Les 4 premiers bytes = nameType = 1 (NT_PRINCIPAL)
	p := encodePrincipal("john", "LAB.LOCAL")

	if len(p) < 8 {
		t.Fatalf("principal too short: %d bytes", len(p))
	}

	nameType := binary.BigEndian.Uint32(p[0:4])
	if nameType != 1 {
		t.Errorf("nameType: expected 1 (NT_PRINCIPAL), got %d", nameType)
	}
}

func TestEncodePrincipal_ComponentCount(t *testing.T) {
	// Bytes 4-7 = num_components = 1
	p := encodePrincipal("john", "LAB.LOCAL")

	count := binary.BigEndian.Uint32(p[4:8])
	if count != 1 {
		t.Errorf("num_components: expected 1, got %d", count)
	}
}

func TestEncodePrincipal_ContainsRealm(t *testing.T) {
	p := encodePrincipal("john", "LAB.LOCAL")
	if !containsBytes(p, []byte("LAB.LOCAL")) {
		t.Error("realm 'LAB.LOCAL' not found in encoded principal")
	}
}

func TestEncodePrincipal_ContainsUsername(t *testing.T) {
	p := encodePrincipal("administrator", "CORP.EXAMPLE.COM")
	if !containsBytes(p, []byte("administrator")) {
		t.Error("username 'administrator' not found in encoded principal")
	}
}

// =============================================================================
// TESTS : encodeTimestamp
// =============================================================================

func TestEncodeTimestamp_KnownValue(t *testing.T) {
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	encoded := encodeTimestamp(ts)

	if len(encoded) != 4 {
		t.Fatalf("timestamp must be 4 bytes, got %d", len(encoded))
	}

	decoded := binary.BigEndian.Uint32(encoded)
	if decoded != uint32(ts.Unix()) {
		t.Errorf("timestamp: expected %d, got %d", uint32(ts.Unix()), decoded)
	}
}

func TestEncodeTimestamp_Zero(t *testing.T) {
	encoded := encodeTimestamp(time.Time{})
	if !bytes.Equal(encoded, []byte{0, 0, 0, 0}) {
		t.Errorf("zero timestamp: expected 4 zero bytes, got %v", encoded)
	}
}

func TestEncodeTimestamp_FutureDate(t *testing.T) {
	// Un timestamp dans le futur doit être > 0
	future := time.Now().Add(10 * time.Hour)
	encoded := encodeTimestamp(future)
	val := binary.BigEndian.Uint32(encoded)
	if val == 0 {
		t.Error("future timestamp encoded as 0")
	}
}

// =============================================================================
// TESTS : buildKeyblock
// =============================================================================

func TestBuildKeyblock_EncType(t *testing.T) {
	key := make([]byte, 16)
	kb := buildKeyblock(17, key) // 17 = AES128

	if len(kb) < 2 {
		t.Fatalf("keyblock too short: %d bytes", len(kb))
	}

	encType := binary.BigEndian.Uint16(kb[0:2])
	if encType != 17 {
		t.Errorf("enctype: expected 17, got %d", encType)
	}
}

func TestBuildKeyblock_KeyLen(t *testing.T) {
	key := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03}
	kb := buildKeyblock(23, key) // 23 = RC4-HMAC

	if len(kb) < 4 {
		t.Fatalf("keyblock too short: %d bytes", len(kb))
	}

	keyLen := binary.BigEndian.Uint16(kb[2:4])
	if int(keyLen) != len(key) {
		t.Errorf("keylen: expected %d, got %d", len(key), keyLen)
	}
}

func TestBuildKeyblock_KeyBytes(t *testing.T) {
	key := []byte{0xCA, 0xFE, 0xBA, 0xBE}
	kb := buildKeyblock(23, key)

	if !bytes.Equal(kb[4:], key) {
		t.Error("key bytes corrupted in keyblock")
	}
}

func TestBuildKeyblock_NTHash(t *testing.T) {
	// RC4-HMAC (23) est utilisé pour Pass-the-Key avec NT hash
	ntHash := make([]byte, 16)
	for i := range ntHash {
		ntHash[i] = byte(i)
	}
	kb := buildKeyblock(23, ntHash)
	encType := binary.BigEndian.Uint16(kb[0:2])
	if encType != 23 {
		t.Errorf("RC4-HMAC enctype: expected 23, got %d", encType)
	}
}

// =============================================================================
// TESTS : countedOctetString
// =============================================================================

func TestCountedOctetString_Normal(t *testing.T) {
	s := "john"
	enc := countedOctetString(s)

	if len(enc) != 4+len(s) {
		t.Errorf("length: expected %d, got %d", 4+len(s), len(enc))
	}

	length := binary.BigEndian.Uint32(enc[0:4])
	if int(length) != len(s) {
		t.Errorf("count field: expected %d, got %d", len(s), length)
	}

	if string(enc[4:]) != s {
		t.Errorf("content: expected %q, got %q", s, string(enc[4:]))
	}
}

func TestCountedOctetString_Empty(t *testing.T) {
	enc := countedOctetString("")
	if len(enc) != 4 {
		t.Errorf("empty string: expected 4 bytes, got %d", len(enc))
	}
	if binary.BigEndian.Uint32(enc[0:4]) != 0 {
		t.Error("empty string count must be 0")
	}
}

// =============================================================================
// TESTS : buildCCacheFile (intégration)
// =============================================================================

func TestBuildCCacheFile_NonEmpty(t *testing.T) {
	ccache, err := buildCCacheFile("john", "LAB.LOCAL", []byte("fakeTGTbytes"), 23)
	if err != nil {
		t.Fatalf("buildCCacheFile failed: %v", err)
	}
	if len(ccache) < 50 {
		t.Errorf("ccache too small: %d bytes", len(ccache))
	}
}

func TestBuildCCacheFile_MagicBytes(t *testing.T) {
	ccache, err := buildCCacheFile("john", "LAB.LOCAL", []byte("fakeTGT"), 17)
	if err != nil {
		t.Fatalf("buildCCacheFile failed: %v", err)
	}

	tag := binary.BigEndian.Uint16(ccache[0:2])
	if tag != 0x0504 {
		t.Errorf("magic: expected 0x0504, got 0x%04X", tag)
	}
}

func TestBuildCCacheFile_ContainsPrincipal(t *testing.T) {
	ccache, err := buildCCacheFile("administrator", "CORP.LOCAL", []byte("fakeTGT"), 23)
	if err != nil {
		t.Fatalf("buildCCacheFile failed: %v", err)
	}

	if !containsBytes(ccache, []byte("administrator")) {
		t.Error("username 'administrator' not found in ccache")
	}
	if !containsBytes(ccache, []byte("CORP.LOCAL")) {
		t.Error("realm 'CORP.LOCAL' not found in ccache")
	}
}

func TestBuildCCacheFile_ContainsTicket(t *testing.T) {
	ticket := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}
	ccache, err := buildCCacheFile("john", "LAB.LOCAL", ticket, 23)
	if err != nil {
		t.Fatalf("buildCCacheFile failed: %v", err)
	}

	if !containsBytes(ccache, ticket) {
		t.Error("ticket bytes not found in ccache")
	}
}

// =============================================================================
// TESTS : helpers internes
// =============================================================================

func TestRealmToLower(t *testing.T) {
	cases := []struct{ in, out string }{
		{"LAB.LOCAL", "lab.local"},
		{"CORP.EXAMPLE.COM", "corp.example.com"},
		{"already.lower", "already.lower"},
	}
	for _, c := range cases {
		if got := realmToLower(c.in); got != c.out {
			t.Errorf("realmToLower(%q): expected %q, got %q", c.in, c.out, got)
		}
	}
}

// =============================================================================
// Helper de test
// =============================================================================

func containsBytes(data, sub []byte) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i <= len(data)-len(sub); i++ {
		if bytes.Equal(data[i:i+len(sub)], sub) {
			return true
		}
	}
	return false
}
