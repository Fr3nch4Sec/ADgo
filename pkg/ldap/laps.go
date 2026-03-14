// pkg/ldap/laps.go
//
// LAPS (Local Administrator Password Solution) et gMSA (Group Managed Service Accounts)
//
// LAPS classique : l'attribut ms-Mcs-AdmPwd contient le mot de passe admin local
//                  en clair (si l'appelant a les droits de lecture).
//
// LAPS v2        : l'attribut msLAPS-Password contient un JSON chiffré.
//                  msLAPS-EncryptedPassword nécessite un déchiffrement DPAPI.
//
// gMSA           : l'attribut msDS-ManagedPassword contient un blob MSDS-MANAGEDPASSWORD_BLOB
//                  dont on peut extraire le NT hash.

package ldap

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
)

// LAPSEntry résultat LAPS pour un ordinateur
type LAPSEntry struct {
	ComputerName string
	DN           string
	Password     string // clair (LAPS v1) ou JSON (LAPS v2)
	Expiration   time.Time
	LAPSVersion  int // 1 = ms-Mcs-AdmPwd, 2 = msLAPS-Password
}

// GMSAEntry résultat gMSA pour un compte de service
type GMSAEntry struct {
	AccountName string
	DN          string
	NTHash      string // NT hash calculé depuis le blob gMSA
	RawBlob     []byte
}

// ============================================================
// LAPS v1 — ms-Mcs-AdmPwd
// ============================================================

// GetLAPSPasswords récupère les mots de passe LAPS de tous les ordinateurs accessibles.
// Nécessite que le compte appelant ait les droits de lecture sur ms-Mcs-AdmPwd.
func (c *Client) GetLAPSPasswords(baseDN string) ([]LAPSEntry, error) {
	// Chercher tous les ordinateurs avec ms-Mcs-AdmPwd ou msLAPS-Password
	req := goldap.NewSearchRequest(
		baseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=computer)",
		[]string{
			"cn",
			"distinguishedName",
			"ms-Mcs-AdmPwd",               // LAPS v1 — mot de passe en clair
			"ms-Mcs-AdmPwdExpirationTime", // LAPS v1 — expiration
			"msLAPS-Password",             // LAPS v2 — JSON chiffré
			"msLAPS-EncryptedPassword",    // LAPS v2 — chiffré DPAPI (non déchiffrable ici)
			"msLAPS-PasswordExpirationTime",
		},
		nil,
	)

	sr, err := c.conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("LAPS search failed: %v", err)
	}

	var entries []LAPSEntry
	for _, entry := range sr.Entries {
		cn := entry.GetAttributeValue("cn")

		// LAPS v1
		if pwd := entry.GetAttributeValue("ms-Mcs-AdmPwd"); pwd != "" {
			exp := parseWindowsFileTime(entry.GetAttributeValue("ms-Mcs-AdmPwdExpirationTime"))
			entries = append(entries, LAPSEntry{
				ComputerName: cn,
				DN:           entry.DN,
				Password:     pwd,
				Expiration:   exp,
				LAPSVersion:  1,
			})
			continue
		}

		// LAPS v2 (JSON, pas encore déchiffré)
		if pwd := entry.GetAttributeValue("msLAPS-Password"); pwd != "" {
			exp := parseWindowsFileTime(entry.GetAttributeValue("msLAPS-PasswordExpirationTime"))
			entries = append(entries, LAPSEntry{
				ComputerName: cn,
				DN:           entry.DN,
				Password:     pwd, // JSON {"n":"Administrator","t":"...","p":"..."}
				Expiration:   exp,
				LAPSVersion:  2,
			})
		}
	}

	return entries, nil
}

// GetLAPSForComputer récupère le mot de passe LAPS d'un ordinateur spécifique.
func (c *Client) GetLAPSForComputer(baseDN, computerName string) (*LAPSEntry, error) {
	filter := fmt.Sprintf("(&(objectClass=computer)(cn=%s))",
		goldap.EscapeFilter(computerName))

	req := goldap.NewSearchRequest(
		baseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		0, 0, false,
		filter,
		[]string{"cn", "distinguishedName", "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime", "msLAPS-Password"},
		nil,
	)

	sr, err := c.conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("LAPS search failed: %v", err)
	}
	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("computer %q not found", computerName)
	}

	entry := sr.Entries[0]
	pwd := entry.GetAttributeValue("ms-Mcs-AdmPwd")
	if pwd == "" {
		pwd = entry.GetAttributeValue("msLAPS-Password")
	}
	if pwd == "" {
		return nil, fmt.Errorf("no LAPS password readable for %s (no rights or LAPS not deployed)", computerName)
	}

	ver := 1
	if entry.GetAttributeValue("msLAPS-Password") != "" {
		ver = 2
	}

	return &LAPSEntry{
		ComputerName: entry.GetAttributeValue("cn"),
		DN:           entry.DN,
		Password:     pwd,
		Expiration:   parseWindowsFileTime(entry.GetAttributeValue("ms-Mcs-AdmPwdExpirationTime")),
		LAPSVersion:  ver,
	}, nil
}

// ============================================================
// gMSA — msDS-ManagedPassword
// ============================================================

// GetGMSAPasswords récupère les blobs gMSA et calcule les NT hashes.
// Nécessite d'être membre d'un groupe autorisé à lire msDS-ManagedPassword.
func (c *Client) GetGMSAPasswords(baseDN string) ([]GMSAEntry, error) {
	req := goldap.NewSearchRequest(
		baseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		0, 0, false,
		// msDS-GroupMSAMembership indique que c'est un gMSA
		"(&(objectClass=msDS-GroupManagedServiceAccount))",
		[]string{"sAMAccountName", "distinguishedName", "msDS-ManagedPassword"},
		nil,
	)

	sr, err := c.conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("gMSA search failed: %v", err)
	}

	var entries []GMSAEntry
	for _, entry := range sr.Entries {
		blob := entry.GetRawAttributeValue("msDS-ManagedPassword")
		account := entry.GetAttributeValue("sAMAccountName")

		e := GMSAEntry{
			AccountName: account,
			DN:          entry.DN,
			RawBlob:     blob,
		}

		if len(blob) > 0 {
			ntHash, err := extractGMSANTHash(blob)
			if err == nil {
				e.NTHash = ntHash
			} else {
				e.NTHash = fmt.Sprintf("(parse error: %v)", err)
			}
		} else {
			e.NTHash = "(no rights or gMSA not readable)"
		}

		entries = append(entries, e)
	}

	return entries, nil
}

// extractGMSANTHash parse le blob MSDS-MANAGEDPASSWORD_BLOB et calcule le NT hash.
//
// Structure du blob (MS-ADTS 2.2.33) :
//
//	Version        : WORD  (offset 0)
//	Reserved       : WORD  (offset 2)
//	Length         : DWORD (offset 4)
//	CurrentPasswordOffset : WORD (offset 8)
//	PreviousPasswordOffset: WORD (offset 10)
//	QueryPasswordIntervalOffset: WORD (offset 12)
//	UnchangedPasswordIntervalOffset: WORD (offset 14)
//	CurrentPassword: bytes à CurrentPasswordOffset (256 bytes = clé AES-256)
func extractGMSANTHash(blob []byte) (string, error) {
	if len(blob) < 16 {
		return "", fmt.Errorf("blob too short (%d bytes)", len(blob))
	}

	version := binary.LittleEndian.Uint16(blob[0:2])
	if version != 1 {
		return "", fmt.Errorf("unsupported blob version: %d", version)
	}

	currentPwdOffset := int(binary.LittleEndian.Uint16(blob[8:10]))
	if currentPwdOffset == 0 || currentPwdOffset+256 > len(blob) {
		return "", fmt.Errorf("invalid password offset %d (blob len %d)", currentPwdOffset, len(blob))
	}

	// Le mot de passe gMSA est une clé aléatoire de 256 bytes
	// Le NT hash = MD4(password) avec le password en UTF-16LE
	// Mais ici le blob contient directement la clé — on calcule MD4 directement
	password := blob[currentPwdOffset : currentPwdOffset+256]

	// NT hash = MD4(password bytes)
	// Pour gMSA, le blob contient directement la clé — MD4 calculé sur les bytes bruts
	h := newMD4()
	h.write(password)
	ntHash := hex.EncodeToString(h.sum())

	return ntHash, nil
}

// ============================================================
// Helpers
// ============================================================

// parseWindowsFileTime convertit un Windows FILETIME (string décimale) en time.Time.
// Un FILETIME est le nombre d'intervalles de 100 ns depuis le 01/01/1601 UTC.
func parseWindowsFileTime(s string) time.Time {
	if s == "" || s == "0" {
		return time.Time{}
	}
	var ft int64
	fmt.Sscanf(s, "%d", &ft)
	if ft <= 0 {
		return time.Time{}
	}
	const epoch = int64(116444736000000000) // intervalles entre 1601 et 1970
	unixNano := (ft - epoch) * 100
	return time.Unix(0, unixNano)
}

// FormatLAPSTable retourne les entrées LAPS formatées pour PrintTable.
func FormatLAPSTable(entries []LAPSEntry) [][]string {
	rows := make([][]string, 0, len(entries))
	for _, e := range entries {
		exp := "Never"
		if !e.Expiration.IsZero() {
			exp = e.Expiration.Format("2006-01-02 15:04")
		}
		ver := "LAPSv1"
		if e.LAPSVersion == 2 {
			ver = "LAPSv2"
		}
		rows = append(rows, []string{e.ComputerName, e.Password, exp, ver})
	}
	return rows
}

// FormatGMSATable retourne les entrées gMSA formatées pour PrintTable.
func FormatGMSATable(entries []GMSAEntry) [][]string {
	rows := make([][]string, 0, len(entries))
	for _, e := range entries {
		account := e.AccountName
		if !strings.HasSuffix(account, "$") {
			account += "$"
		}
		rows = append(rows, []string{account, e.NTHash, e.DN})
	}
	return rows
}

// ============================================================
// MD4 — implémentation minimale (RFC 1320, sans dépendance externe)
// ============================================================

type md4State struct {
	s  [4]uint32
	x  [64]byte
	nx int
	ln uint64
}

func newMD4() *md4State {
	return &md4State{s: [4]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476}}
}

func (m *md4State) write(p []byte) {
	m.ln += uint64(len(p))
	if m.nx > 0 {
		n := copy(m.x[m.nx:], p)
		m.nx += n
		if m.nx == 64 {
			md4Block(m, m.x[:])
			m.nx = 0
		}
		p = p[n:]
	}
	for len(p) >= 64 {
		md4Block(m, p[:64])
		p = p[64:]
	}
	if len(p) > 0 {
		m.nx = copy(m.x[:], p)
	}
}

func (m *md4State) sum() []byte {
	tc := m.ln
	var tmp [64]byte
	tmp[0] = 0x80
	if tc%64 < 56 {
		m.write(tmp[0 : 56-tc%64])
	} else {
		m.write(tmp[0 : 64+56-tc%64])
	}
	tc <<= 3
	binary.LittleEndian.PutUint64(tmp[:], tc)
	m.write(tmp[0:8])

	var out [16]byte
	binary.LittleEndian.PutUint32(out[0:], m.s[0])
	binary.LittleEndian.PutUint32(out[4:], m.s[1])
	binary.LittleEndian.PutUint32(out[8:], m.s[2])
	binary.LittleEndian.PutUint32(out[12:], m.s[3])
	return out[:]
}

// md4Block processes a 64-byte block (RFC 1320 §3.3–3.4)
func md4Block(m *md4State, p []byte) {
	var X [16]uint32
	for i := range X {
		X[i] = binary.LittleEndian.Uint32(p[4*i:])
	}

	a, b, c, d := m.s[0], m.s[1], m.s[2], m.s[3]
	aa, bb, cc, dd := a, b, c, d

	rot := func(x, s uint32) uint32 { return x<<s | x>>(32-s) }

	// Auxiliary functions
	F := func(x, y, z uint32) uint32 { return x&y | ^x&z }
	G := func(x, y, z uint32) uint32 { return x&y | x&z | y&z }
	H := func(x, y, z uint32) uint32 { return x ^ y ^ z }

	// Round 1
	a = rot(a+F(b, c, d)+X[0], 3)
	d = rot(d+F(a, b, c)+X[1], 7)
	c = rot(c+F(d, a, b)+X[2], 11)
	b = rot(b+F(c, d, a)+X[3], 19)
	a = rot(a+F(b, c, d)+X[4], 3)
	d = rot(d+F(a, b, c)+X[5], 7)
	c = rot(c+F(d, a, b)+X[6], 11)
	b = rot(b+F(c, d, a)+X[7], 19)
	a = rot(a+F(b, c, d)+X[8], 3)
	d = rot(d+F(a, b, c)+X[9], 7)
	c = rot(c+F(d, a, b)+X[10], 11)
	b = rot(b+F(c, d, a)+X[11], 19)
	a = rot(a+F(b, c, d)+X[12], 3)
	d = rot(d+F(a, b, c)+X[13], 7)
	c = rot(c+F(d, a, b)+X[14], 11)
	b = rot(b+F(c, d, a)+X[15], 19)

	// Round 2 (constant 0x5a827999)
	a = rot(a+G(b, c, d)+X[0]+0x5a827999, 3)
	d = rot(d+G(a, b, c)+X[4]+0x5a827999, 5)
	c = rot(c+G(d, a, b)+X[8]+0x5a827999, 9)
	b = rot(b+G(c, d, a)+X[12]+0x5a827999, 13)
	a = rot(a+G(b, c, d)+X[1]+0x5a827999, 3)
	d = rot(d+G(a, b, c)+X[5]+0x5a827999, 5)
	c = rot(c+G(d, a, b)+X[9]+0x5a827999, 9)
	b = rot(b+G(c, d, a)+X[13]+0x5a827999, 13)
	a = rot(a+G(b, c, d)+X[2]+0x5a827999, 3)
	d = rot(d+G(a, b, c)+X[6]+0x5a827999, 5)
	c = rot(c+G(d, a, b)+X[10]+0x5a827999, 9)
	b = rot(b+G(c, d, a)+X[14]+0x5a827999, 13)
	a = rot(a+G(b, c, d)+X[3]+0x5a827999, 3)
	d = rot(d+G(a, b, c)+X[7]+0x5a827999, 5)
	c = rot(c+G(d, a, b)+X[11]+0x5a827999, 9)
	b = rot(b+G(c, d, a)+X[15]+0x5a827999, 13)

	// Round 3 (constant 0x6ed9eba1)
	a = rot(a+H(b, c, d)+X[0]+0x6ed9eba1, 3)
	d = rot(d+H(a, b, c)+X[8]+0x6ed9eba1, 9)
	c = rot(c+H(d, a, b)+X[4]+0x6ed9eba1, 11)
	b = rot(b+H(c, d, a)+X[12]+0x6ed9eba1, 15)
	a = rot(a+H(b, c, d)+X[2]+0x6ed9eba1, 3)
	d = rot(d+H(a, b, c)+X[10]+0x6ed9eba1, 9)
	c = rot(c+H(d, a, b)+X[6]+0x6ed9eba1, 11)
	b = rot(b+H(c, d, a)+X[14]+0x6ed9eba1, 15)
	a = rot(a+H(b, c, d)+X[1]+0x6ed9eba1, 3)
	d = rot(d+H(a, b, c)+X[9]+0x6ed9eba1, 9)
	c = rot(c+H(d, a, b)+X[5]+0x6ed9eba1, 11)
	b = rot(b+H(c, d, a)+X[13]+0x6ed9eba1, 15)
	a = rot(a+H(b, c, d)+X[3]+0x6ed9eba1, 3)
	d = rot(d+H(a, b, c)+X[11]+0x6ed9eba1, 9)
	c = rot(c+H(d, a, b)+X[7]+0x6ed9eba1, 11)
	b = rot(b+H(c, d, a)+X[15]+0x6ed9eba1, 15)

	m.s[0] += aa
	m.s[1] += bb
	m.s[2] += cc
	m.s[3] += dd
}
