// pkg/ntlm/relay/relay.go
package relay

import (
	"fmt"
	"net/http"
)

// RelayServer représente un serveur de relai NTLM.
type RelayServer struct {
	server *http.Server
}

// NewRelayServer crée un nouveau serveur de relai NTLM.
func NewRelayServer(addr string) *RelayServer {
	mux := http.NewServeMux()
	server := &http.Server{Addr: addr, Handler: mux}

	rs := &RelayServer{server: server}

	mux.HandleFunc("/ntlm", rs.handleNTLM)

	return rs
}

// handleNTLM gère les requêtes NTLM.
func (rs *RelayServer) handleNTLM(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.Header().Set("WWW-Authenticate", `NTLM`)
		http.Error(w, "Authorization required", http.StatusUnauthorized)
		return
	}

	// Analyser l'en-tête d'autorisation NTLM
	fmt.Printf("Received NTLM Message: %s\n", authHeader)

	// Logique pour relayer l'authentification NTLM
	// Utilise des bibliothèques comme github.com/Azure/go-ntlmssp pour gérer NTLM

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "NTLM Relay Successful")
}

// Start démarre le serveur de relai NTLM.
func (rs *RelayServer) Start() error {
	return rs.server.ListenAndServe()
}
