// pkg/proxy/socks5.go
//
// Serveur SOCKS5 local qui tunnelise les connexions à travers une session SMB.
//
// Utilisation en pentest :
//   1. adgo proxy --listen 127.0.0.1:1080 -u admin -p pass -d LAB --pivot 192.168.1.10
//   2. proxychains adgo ldap users --dc-ip 172.16.0.1 ...
//   3. proxychains impacket-secretsdump ...
//
// Le trafic SOCKS5 → connexion TCP via le pivot SMB → réseau interne
//
// RFC 1928 (SOCKS5) + RFC 1929 (auth user/pass)
// Méthode : CONNECT uniquement (pas BIND ni UDP pour l'instant)

package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// SOCKS5 constants
const (
	socks5Version = 0x05

	// Auth methods
	authNone     = 0x00
	authUserPass = 0x02
	authNoAccept = 0xFF

	// Commands
	cmdConnect = 0x01

	// Address types
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	// Reply codes
	repSuccess          = 0x00
	repGeneralFailure   = 0x01
	repConnRefused      = 0x05
	repHostUnreachable  = 0x04
	repCmdNotSupported  = 0x07
	repAddrNotSupported = 0x08
)

// DialFunc est la fonction utilisée pour établir les connexions sortantes.
// Par défaut : net.DialTimeout.
// Pour le tunneling SMB : remplacée par une fonction qui route via le pivot.
type DialFunc func(network, address string, timeout time.Duration) (net.Conn, error)

// Server est un serveur SOCKS5
type Server struct {
	listenAddr string
	username   string // optionnel — auth user/pass si défini
	password   string
	dial       DialFunc
	timeout    time.Duration
	verbose    bool
	mu         sync.Mutex
	conns      int
}

// ServerConfig configuration du serveur SOCKS5
type ServerConfig struct {
	ListenAddr string
	Username   string // laisser vide pour pas d'auth
	Password   string
	Dial       DialFunc      // nil = net.DialTimeout standard
	Timeout    time.Duration // timeout de connexion (défaut 10s)
	Verbose    bool
}

// NewServer crée un serveur SOCKS5
func NewServer(cfg *ServerConfig) *Server {
	dial := cfg.Dial
	if dial == nil {
		dial = func(network, addr string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout(network, addr, timeout)
		}
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &Server{
		listenAddr: cfg.ListenAddr,
		username:   cfg.Username,
		password:   cfg.Password,
		dial:       dial,
		timeout:    timeout,
		verbose:    cfg.Verbose,
	}
}

// ListenAndServe démarre le serveur SOCKS5 (bloquant)
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("SOCKS5 listen failed on %s: %v", s.listenAddr, err)
	}
	defer ln.Close()

	fmt.Printf("[+] SOCKS5 proxy listening on %s\n", s.listenAddr)
	if s.username != "" {
		fmt.Printf("[*] Auth required: %s:***\n", s.username)
	} else {
		fmt.Println("[*] No authentication required")
	}
	fmt.Println("[*] Use with: proxychains / SOCKS5 proxy settings")
	fmt.Printf("[*] Example: export ALL_PROXY=socks5://%s\n", s.listenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		s.mu.Lock()
		s.conns++
		s.mu.Unlock()
		go s.handleConn(conn)
	}
}

// handleConn gère une connexion SOCKS5 cliente
func (s *Server) handleConn(client net.Conn) {
	defer func() {
		client.Close()
		s.mu.Lock()
		s.conns--
		s.mu.Unlock()
	}()

	client.SetDeadline(time.Now().Add(30 * time.Second))

	// 1. Négociation de méthode d'auth
	if err := s.negotiateAuth(client); err != nil {
		if s.verbose {
			fmt.Printf("[-] Auth negotiation failed from %s: %v\n", client.RemoteAddr(), err)
		}
		return
	}

	// 2. Lire la requête CONNECT
	target, err := s.readRequest(client)
	if err != nil {
		if s.verbose {
			fmt.Printf("[-] Request read failed from %s: %v\n", client.RemoteAddr(), err)
		}
		return
	}

	if s.verbose {
		fmt.Printf("[*] SOCKS5 CONNECT → %s (from %s)\n", target, client.RemoteAddr())
	}

	// 3. Connecter à la cible
	remote, err := s.dial("tcp", target, s.timeout)
	if err != nil {
		sendReply(client, repHostUnreachable)
		if s.verbose {
			fmt.Printf("[-] Cannot reach %s: %v\n", target, err)
		}
		return
	}
	defer remote.Close()

	// 4. Envoyer la réponse SUCCESS
	sendReply(client, repSuccess)

	// 5. Bidirectional pipe
	client.SetDeadline(time.Time{}) // pas de deadline pendant le tunnel
	remote.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(remote, client)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(client, remote)
		done <- struct{}{}
	}()
	<-done
}

// negotiateAuth gère la négociation de méthode d'authentification SOCKS5
func (s *Server) negotiateAuth(conn net.Conn) error {
	// Lire le header : VER + NMETHODS
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != socks5Version {
		return fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	// Choisir la méthode
	if s.username == "" {
		// Pas d'auth — accepter si le client propose NO_AUTH
		for _, m := range methods {
			if m == authNone {
				conn.Write([]byte{socks5Version, authNone})
				return nil
			}
		}
	} else {
		// Auth user/pass (RFC 1929) — accepter si proposée
		for _, m := range methods {
			if m == authUserPass {
				conn.Write([]byte{socks5Version, authUserPass})
				return s.handleUserPassAuth(conn)
			}
		}
	}

	conn.Write([]byte{socks5Version, authNoAccept})
	return fmt.Errorf("no acceptable auth method")
}

// handleUserPassAuth gère l'authentification user/pass RFC 1929
func (s *Server) handleUserPassAuth(conn net.Conn) error {
	// VER(1) + ULEN(1) + UNAME(ULEN) + PLEN(1) + PASSWD(PLEN)
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	// header[0] = sous-version (0x01)
	ulen := int(header[1])
	uname := make([]byte, ulen)
	if _, err := io.ReadFull(conn, uname); err != nil {
		return err
	}

	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, plenBuf); err != nil {
		return err
	}
	passwd := make([]byte, int(plenBuf[0]))
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return err
	}

	if string(uname) == s.username && string(passwd) == s.password {
		conn.Write([]byte{0x01, 0x00}) // success
		return nil
	}

	conn.Write([]byte{0x01, 0x01}) // failure
	return fmt.Errorf("invalid credentials")
}

// readRequest lit la requête SOCKS5 CONNECT et retourne "host:port"
func (s *Server) readRequest(conn net.Conn) (string, error) {
	// VER + CMD + RSV + ATYP
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}
	if header[0] != socks5Version {
		return "", fmt.Errorf("bad version in request")
	}
	if header[1] != cmdConnect {
		sendReply(conn, repCmdNotSupported)
		return "", fmt.Errorf("unsupported command: %d", header[1])
	}

	var host string
	switch header[3] { // ATYP
	case atypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()

	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", err
		}
		domain := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}
		host = string(domain)

	case atypIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = "[" + net.IP(addr).String() + "]"

	default:
		sendReply(conn, repAddrNotSupported)
		return "", fmt.Errorf("unsupported address type: %d", header[3])
	}

	// Port (2 bytes big-endian)
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf)

	return fmt.Sprintf("%s:%d", host, port), nil
}

// sendReply envoie une réponse SOCKS5
func sendReply(conn net.Conn, code byte) {
	// VER + REP + RSV + ATYP(IPv4) + BND.ADDR(4) + BND.PORT(2)
	reply := []byte{socks5Version, code, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}
	conn.Write(reply)
}

// Stats retourne les stats du serveur
func (s *Server) Stats() (conns int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns
}
