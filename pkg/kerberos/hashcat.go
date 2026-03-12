// pkg/kerberos/hashcat.go

package kerberos

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"
)

// HashcatHash représente un hash prêt pour hashcat
type HashcatHash struct {
	Username string
	Domain   string
	SPN      string // vide pour ASREPRoast
	Hash     string // format hashcat complet
	Mode     int    // 13100 = Kerberoast, 18200 = ASREPRoast
	EncType  int    // 17=AES128, 18=AES256, 23=RC4-HMAC
}

// ============================================================
// Kerberoast → hashcat mode 13100
// Format : $krb5tgs$<etype>$*<user>$<REALM>$<spn>*$<checksum>$<data>
// ============================================================

// FormatKerberoastHash formate un cipher TGS en hash hashcat mode 13100.
// ticketBytes = EncPart.Cipher du ticket retourné par GetServiceTicket
func FormatKerberoastHash(username, domain, spn string, ticketBytes []byte, encType int) HashcatHash {
	hash := buildHashString("krb5tgs", encType, username, domain, spn, ticketBytes)
	return HashcatHash{
		Username: username,
		Domain:   strings.ToUpper(domain),
		SPN:      spn,
		Hash:     hash,
		Mode:     13100,
		EncType:  encType,
	}
}

// ============================================================
// ASREPRoast → hashcat mode 18200
// Format : $krb5asrep$<etype>$<user>@<REALM>:<checksum>$<data>
// ============================================================

// FormatASREPRoastHash formate un enc-part AS-REP en hash hashcat mode 18200.
// asRepBytes = EncPart.Cipher de la réponse AS-REP
func FormatASREPRoastHash(username, domain string, asRepBytes []byte, encType int) HashcatHash {
	hash := buildHashString("krb5asrep", encType, username, domain, "", asRepBytes)
	return HashcatHash{
		Username: username,
		Domain:   strings.ToUpper(domain),
		Hash:     hash,
		Mode:     18200,
		EncType:  encType,
	}
}

// ============================================================
// Builder interne
// ============================================================

func buildHashString(prefix string, encType int, username, domain, spn string, cipherBytes []byte) string {
	realm := strings.ToUpper(domain)

	// Taille du checksum selon l'enctype
	checksumLen := 16 // RC4-HMAC (23) — par défaut
	if encType == 17 || encType == 18 {
		checksumLen = 12 // AES128/AES256
	}

	if len(cipherBytes) <= checksumLen {
		return ""
	}

	checksum := hex.EncodeToString(cipherBytes[:checksumLen])
	data := hex.EncodeToString(cipherBytes[checksumLen:])

	switch prefix {
	case "krb5tgs":
		// $krb5tgs$23$*user$REALM$spn*$checksum$data
		return fmt.Sprintf("$%s$%d$*%s$%s$%s*$%s$%s",
			prefix, encType, username, realm, spn, checksum, data)
	default:
		// $krb5asrep$23$user@REALM:checksum$data
		return fmt.Sprintf("$%s$%d$%s@%s:%s$%s",
			prefix, encType, username, realm, checksum, data)
	}
}

// ============================================================
// Sauvegarde fichier
// ============================================================

// SaveHashcatFile sauvegarde les hashes dans un fichier texte (un par ligne).
// outputFile vide = nom automatique avec timestamp
func SaveHashcatFile(hashes []HashcatHash, outputFile string) error {
	if len(hashes) == 0 {
		return fmt.Errorf("no hashes to save")
	}

	if outputFile == "" {
		ts := time.Now().Format("20060102_150405")
		switch hashes[0].Mode {
		case 13100:
			outputFile = fmt.Sprintf("kerberoast_%s.txt", ts)
		case 18200:
			outputFile = fmt.Sprintf("asreproast_%s.txt", ts)
		default:
			outputFile = fmt.Sprintf("hashes_%d_%s.txt", hashes[0].Mode, ts)
		}
	}

	var lines []string
	for _, h := range hashes {
		if h.Hash != "" {
			lines = append(lines, h.Hash)
		}
	}

	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(outputFile, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write hashcat file: %v", err)
	}

	fmt.Printf("[+] %d hash(es) saved → %s\n", len(lines), outputFile)
	fmt.Printf("[*] Crack: hashcat -m %d %s /path/to/wordlist.txt\n",
		hashes[0].Mode, outputFile)
	return nil
}

// PrintHashcatHashes affiche les hashes dans le terminal
func PrintHashcatHashes(hashes []HashcatHash) {
	if len(hashes) == 0 {
		fmt.Println("[-] No hashes found")
		return
	}
	fmt.Printf("\n[+] %d hash(es) (hashcat mode %d)\n\n", len(hashes), hashes[0].Mode)
	for _, h := range hashes {
		if h.SPN != "" {
			fmt.Printf("  %-20s  SPN: %-40s  enctype: %d\n", h.Username, h.SPN, h.EncType)
		} else {
			fmt.Printf("  %s@%s  enctype: %d\n", h.Username, h.Domain, h.EncType)
		}
		fmt.Printf("  %s\n\n", h.Hash)
	}
}
