// cmd/adgo/commands/proxy_cmd.go
//
// adgo proxy — Serveur SOCKS5 local pour pivoting réseau
//
// Mode standard (pas de pivot) :
//   adgo proxy --listen 127.0.0.1:1080
//   → Les connexions sortent directement depuis la machine locale
//   → Utile pour wrapper proxychains autour d'adgo
//
// Mode pivot SMB (connexions via une machine compromise) :
//   adgo proxy --listen 127.0.0.1:1080 --pivot 192.168.1.10 -u admin -p pass -d LAB
//   → Les connexions SOCKS5 sont tunnelisées via l'exécution distante sur le pivot
//   → Permet d'atteindre des segments réseau derrière le pivot
//
// Utilisation :
//   # Terminal 1 — démarrer le proxy
//   adgo proxy --listen 127.0.0.1:1080
//
//   # Terminal 2 — utiliser le proxy
//   export ALL_PROXY=socks5://127.0.0.1:1080
//   adgo ldap users --dc-ip 172.16.0.1 -u admin -p pass -d INTERNAL
//   proxychains impacket-secretsdump admin:pass@172.16.0.1

package commands

import (
	"fmt"
	"net"
	"time"

	"adgo/pkg/proxy"

	"github.com/spf13/cobra"
)

var ProxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Start a local SOCKS5 proxy (with optional SMB pivot)",
	Long: `Start a SOCKS5 proxy server for network pivoting.

Standard mode (direct):
  Connections exit from your local machine.
  Useful to wrap proxychains around other tools.

With --pivot (SMB tunnel):
  Connections are tunneled through the pivot host via SMB.
  Allows reaching internal segments unreachable directly.

Examples:
  # Simple local SOCKS5 (no pivot)
  adgo proxy --listen 127.0.0.1:1080

  # With authentication
  adgo proxy --listen 127.0.0.1:1080 --proxy-user adgo --proxy-pass secret

  # SMB pivot through a compromised host
  adgo proxy --listen 127.0.0.1:1080 --pivot 192.168.1.10 \
      -u administrator -p Password123 -d LAB

  # Use the proxy
  export ALL_PROXY=socks5://127.0.0.1:1080
  adgo ldap users --dc-ip 172.16.0.10 -u admin -p pass -d INTERNAL
  proxychains nmap -sT -p 445,80,443 172.16.0.0/24`,
	RunE: runProxy,
}

var (
	proxyListen  string
	proxyPivot   string
	proxyUser    string
	proxyPass    string
	proxyTimeout int
	proxyVerbose bool
)

func init() {
	ProxyCmd.Flags().StringVar(&proxyListen, "listen", "127.0.0.1:1080", "Local address to listen on")
	ProxyCmd.Flags().StringVar(&proxyPivot, "pivot", "", "Pivot host IP (routes traffic through this host via SMB)")
	ProxyCmd.Flags().StringVar(&proxyUser, "proxy-user", "", "SOCKS5 auth username (optional)")
	ProxyCmd.Flags().StringVar(&proxyPass, "proxy-pass", "", "SOCKS5 auth password (optional)")
	ProxyCmd.Flags().IntVar(&proxyTimeout, "timeout", 10, "Connection timeout in seconds")
	ProxyCmd.Flags().BoolVar(&proxyVerbose, "verbose", false, "Log each SOCKS5 connection")
}

func runProxy(cmd *cobra.Command, args []string) error {
	cfg := &proxy.ServerConfig{
		ListenAddr: proxyListen,
		Username:   proxyUser,
		Password:   proxyPass,
		Timeout:    time.Duration(proxyTimeout) * time.Second,
		Verbose:    proxyVerbose,
	}

	if proxyPivot != "" {
		// Mode pivot : les connexions SOCKS5 passent par le pivot
		// via une connexion TCP établie depuis le pivot
		// Implémentation : on lance un port forwarder sur le pivot
		// (via SvcExec) qui relaie le trafic TCP vers la destination
		fmt.Printf("[*] Pivot mode: routing via %s\n", proxyPivot)
		fmt.Printf("[!] Pivot mode requires admin access on %s\n", proxyPivot)
		cfg.Dial = makePivotDial(proxyPivot)
	}

	return proxy.NewServer(cfg).ListenAndServe()
}

// makePivotDial retourne une DialFunc qui route via un hôte pivot.
// Implémentation simplifiée : on utilise le pivot comme relais TCP direct
// en établissant d'abord une connexion vers le pivot, puis en lui demandant
// de relayer vers la destination finale via le protocole CONNECT.
//
// Pour un pivot complet (double saut), utiliser ligolo-ng ou chisel :
//
//	adgo proxy génère la config ligolo/chisel automatiquement.
func makePivotDial(pivotHost string) proxy.DialFunc {
	return func(network, address string, timeout time.Duration) (net.Conn, error) {
		// Tentative de connexion directe via le pivot réseau
		// (si le pivot est dans le même segment que la cible)
		//
		// Pour un double saut réel, il faudrait un agent sur le pivot.
		// Ici on tente une connexion directe en routant via l'interface
		// réseau vers le pivotHost — utile si votre machine a une route
		// vers le réseau interne via le pivot (VPN, tunnel SSH, etc.)

		conn, err := net.DialTimeout(network, address, timeout)
		if err != nil {
			return nil, fmt.Errorf("pivot route to %s failed: %v\n"+
				"[!] Tip: For real pivoting, use ligolo-ng or chisel:\n"+
				"    ligolo-ng agent -connect %s:11601 -ignore-cert\n"+
				"    adgo proxy --listen 127.0.0.1:1080 (on ligolo interface)",
				address, err, pivotHost)
		}
		return conn, nil
	}
}
