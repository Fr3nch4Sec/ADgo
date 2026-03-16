// cmd/adgo/commands/targets_cmd.go
//
// Commande : adgo scan <target> [options]
//
// Exemples :
//   adgo scan 192.168.1.0/24                             # découverte SMB
//   adgo scan 192.168.1.0/24 -u admin -p pass -d LAB    # test creds + infos
//   adgo scan targets.txt -u admin --hash aad3b4... -d LAB
//   adgo scan 192.168.1.10-50 --port 445,5985

package commands

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"adgo/pkg/common"
	"adgo/pkg/scanner"

	"github.com/hirochachacha/go-smb2"
	"github.com/spf13/cobra"
)

// ScanCmd commande de scan multi-hosts
var ScanCmd = &cobra.Command{
	Use:   "scan <target>",
	Short: "Scan and authenticate against one or multiple hosts",
	Long: `Scan a target or range for open ports, attempt authentication,
and display results in NetExec-style format.

Target formats:
  Single IP   : 192.168.1.10
  CIDR        : 192.168.1.0/24
  IP range    : 192.168.1.10-20
  Hosts file  : targets.txt (one target per line)

Examples:
  # Discovery only (no creds)
  adgo scan 192.168.1.0/24

  # Test credentials on all SMB hosts
  adgo scan 192.168.1.0/24 -u administrator -p Password123 -d LAB

  # Pass-the-Hash
  adgo scan 192.168.1.0/24 -u administrator --hash aad3b435b51404ee... -d LAB

  # Specific port
  adgo scan 192.168.1.0/24 --port 5985

  # Only show successful auths
  adgo scan 192.168.1.0/24 -u admin -p pass -d LAB --success-only`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

var (
	scanPorts       string
	scanWorkers     int
	scanTimeout     int
	scanSuccessOnly bool
	scanProto       string
)

func init() {
	ScanCmd.Flags().StringVar(&scanPorts, "port", "445", "Port(s) to scan, comma-separated (e.g. 445,5985)")
	ScanCmd.Flags().IntVar(&scanWorkers, "workers", 50, "Parallel workers")
	ScanCmd.Flags().IntVar(&scanTimeout, "timeout", 2, "Connection timeout in seconds")
	ScanCmd.Flags().BoolVar(&scanSuccessOnly, "success-only", false, "Only show successful authentications")
	ScanCmd.Flags().StringVar(&scanProto, "protocol", "smb", "Protocol to use: smb, winrm")
}

func runScan(cmd *cobra.Command, args []string) error {
	targetStr := args[0]

	user := common.Username
	pass := common.Password
	domain := common.Domain
	ntHash := common.NTLMHash

	withCreds := user != "" && (pass != "" || ntHash != "")

	// Parser les ports
	ports, err := parsePorts(scanPorts)
	if err != nil {
		return fmt.Errorf("invalid ports %q: %v", scanPorts, err)
	}

	// Parser les cibles
	targets, err := scanner.ParseTargets(targetStr)
	if err != nil {
		return fmt.Errorf("invalid target: %v", err)
	}

	common.PrintInfo(fmt.Sprintf("Scanning %d host(s) on port(s) %s", len(targets), scanPorts))
	if withCreds {
		common.PrintInfo(fmt.Sprintf("Testing credentials: %s\\%s", strings.ToUpper(domain), user))
	}
	fmt.Println()

	// Décoder hash si fourni
	var hashBytes []byte
	if ntHash != "" {
		hashBytes, err = hex.DecodeString(ntHash)
		if err != nil {
			return fmt.Errorf("invalid NT hash: %v", err)
		}
	}

	var mu sync.Mutex
	var successCount, failCount, openCount int

	cfg := &scanner.ScanConfig{
		Workers: scanWorkers,
		Timeout: time.Duration(scanTimeout) * time.Second,
		Ports:   ports,
	}

	scanner.RunWorkerPool(targets, cfg, func(t scanner.Target) scanner.ScanResult {
		for _, port := range ports {
			result := probeAndAuth(t, port, user, pass, domain, hashBytes, withCreds)
			if result.Open {
				mu.Lock()
				openCount++
				mu.Unlock()
			}
			if withCreds {
				if result.Error == nil && result.Open {
					mu.Lock()
					successCount++
					mu.Unlock()
				} else if result.Error != nil {
					mu.Lock()
					failCount++
					mu.Unlock()
				}
			}
			_ = result
		}
		return scanner.ScanResult{Target: t}
	})

	// Résumé
	fmt.Println()
	common.NxSummaryHeader("Scan complete")
	common.NxSummaryLine("Hosts scanned", len(targets))
	common.NxSummaryLine("Ports open", openCount)
	if withCreds {
		common.NxSummaryLine("Auth success", successCount)
		common.NxSummaryLine("Auth failure", failCount)
	}

	return nil
}

// probeAndAuth sonde le port ET tente l'auth si des creds sont fournis
func probeAndAuth(t scanner.Target, port int, user, pass, domain string, hashBytes []byte, withCreds bool) scanner.ScanResult {
	timeout := time.Duration(scanTimeout) * time.Second

	line := common.NxLine{
		Protocol: portToProto(port),
		Host:     t.IP,
		Port:     port,
		Hostname: t.Host,
	}

	// --- Probe TCP ---
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", t.IP, port), timeout)
	if err != nil {
		return scanner.ScanResult{Target: t, Port: port, Open: false}
	}
	conn.Close()

	// Port ouvert : afficher info de base
	switch port {
	case 445:
		info, hostname := probeSMBInfo(t.IP, timeout)
		if hostname != "" {
			line.Hostname = hostname
		}
		if !scanSuccessOnly {
			common.NxInfo(line, info)
		}
	case 5985, 5986:
		if !scanSuccessOnly {
			common.NxInfo(line, fmt.Sprintf("WinRM accessible (port %d)", port))
		}
	default:
		if !scanSuccessOnly {
			common.NxInfo(line, fmt.Sprintf("port %d open", port))
		}
	}

	if !withCreds {
		return scanner.ScanResult{Target: t, Port: port, Open: true}
	}

	// --- Tentative d'authentification ---
	switch port {
	case 445:
		authed, isAdmin := trySMBAuth(t.IP, user, domain, pass, hashBytes, timeout)
		if authed {
			cred := common.NxCredString(domain, user, pass, func() string {
				if len(hashBytes) > 0 {
					return fmt.Sprintf("%x", hashBytes)
				}
				return ""
			}())
			if isAdmin {
				common.NxPwned(line, cred)
			} else {
				common.NxSuccess(line, cred)
			}
			return scanner.ScanResult{Target: t, Port: port, Open: true}
		}
		if !scanSuccessOnly {
			common.NxFailure(line, fmt.Sprintf("%s\\%s - STATUS_LOGON_FAILURE", strings.ToUpper(domain), user))
		}

	case 5985, 5986:
		if !scanSuccessOnly {
			common.NxInfo(line, fmt.Sprintf("WinRM auth test not implemented yet (use 'adgo exec')"))
		}
	}

	return scanner.ScanResult{Target: t, Port: port, Open: true, Error: fmt.Errorf("auth failed")}
}

// probeSMBInfo tente une connexion SMB anonyme pour récupérer infos de base
func probeSMBInfo(ip string, timeout time.Duration) (info, hostname string) {
	conn, err := net.DialTimeout("tcp", ip+":445", timeout)
	if err != nil {
		return "SMB open", ""
	}
	defer conn.Close()

	// Tentative de négociation anonyme
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{User: "", Password: ""},
	}
	session, err := d.Dial(conn)
	if err != nil {
		// Impossible d'obtenir les infos mais le port est ouvert
		return "SMB open (anonymous session rejected)", ""
	}
	defer session.Logoff()

	// On a une session — on peut lister les shares pour vérifier l'accès
	shares, err := session.ListSharenames()
	if err == nil && len(shares) > 0 {
		return fmt.Sprintf("SMB open (anonymous: %d shares visible)", len(shares)), ""
	}

	return "SMB open", ""
}

// trySMBAuth tente une authentification SMB et vérifie l'accès admin via ADMIN$
func trySMBAuth(ip, user, domain, pass string, hashBytes []byte, timeout time.Duration) (authed, isAdmin bool) {
	conn, err := net.DialTimeout("tcp", ip+":445", timeout)
	if err != nil {
		return false, false
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     user,
			Password: pass,
			Domain:   domain,
			Hash:     hashBytes,
		},
	}

	session, err := d.Dial(conn)
	if err != nil {
		return false, false
	}
	defer session.Logoff()

	// Auth réussie — tester l'accès admin via ADMIN$
	fs, err := session.Mount("ADMIN$")
	if err == nil {
		fs.Umount()
		return true, true
	}

	// Auth réussie mais pas admin (on peut peut-être accéder à d'autres shares)
	return true, false
}

// ============================================================
// Helpers
// ============================================================

func parsePorts(portsStr string) ([]int, error) {
	var ports []int
	for _, p := range strings.Split(portsStr, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port: %s", p)
		}
		ports = append(ports, n)
	}
	if len(ports) == 0 {
		return []int{445}, nil
	}
	return ports, nil
}

func portToProto(port int) string {
	switch port {
	case 445:
		return "SMB"
	case 5985, 5986:
		return "WINRM"
	case 389, 636:
		return "LDAP"
	case 88:
		return "KERBEROS"
	default:
		return fmt.Sprintf("TCP/%d", port)
	}
}
