// cmd/adgo/commands/exec_cmd.go
//
// Commande : adgo exec <cible> -u USER [-p PASS | --hash NTLM] -c "COMMANDE"
//
// Détection automatique du protocole :
//   1. WinRM (5985) → exec avec capture de sortie
//   2. SMB (445)    → exec via SVCCTL (capture via C$)
//
// Exemples :
//   adgo exec 192.168.1.10 -u administrator -p Password123 -d LAB -c "whoami"
//   adgo exec 192.168.1.10 -u administrator --hash aad3b4...04ee -d LAB -c "net user"
//   adgo exec 192.168.1.0/24 -u administrator -p Password123 -d LAB -c "whoami"

package commands

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"adgo/pkg/common"
	"adgo/pkg/scanner"
	"adgo/pkg/smb"
	"adgo/pkg/winrm"

	"github.com/spf13/cobra"
)

// ExecCmd commande d'exécution distante unifiée
var ExecCmd = &cobra.Command{
	Use:   "exec <target>",
	Short: "Execute a command on remote host(s) via SMB or WinRM",
	Long: `Execute a command on one or multiple targets, auto-detecting the best protocol.

Protocol priority:
  1. WinRM (port 5985/5986) — output fully captured
  2. SMB  (port 445)        — exec via SVCCTL, output via C$

Target formats:
  Single IP   : 192.168.1.10
  CIDR        : 192.168.1.0/24
  IP range    : 192.168.1.10-20
  Hosts file  : targets.txt

Examples:
  adgo exec 192.168.1.10 -u administrator -p Password123 -d LAB -c "whoami"
  adgo exec 192.168.1.10 -u administrator --hash aad3b435b51404ee... -d LAB -c "whoami /all"
  adgo exec 192.168.1.0/24 -u admin -p pass -d LAB -c "hostname" --workers 20`,
	Args: cobra.ExactArgs(1),
	RunE: runExec,
}

var (
	execCommand  string
	execProtocol string
	execWorkers  int
	execTimeout  int
	execNoClean  bool
)

func init() {
	ExecCmd.Flags().StringVarP(&execCommand, "command", "c", "", "Command to execute (required)")
	ExecCmd.Flags().StringVarP(&execProtocol, "protocol", "P", "auto", "Protocol: auto, smb, winrm")
	ExecCmd.Flags().IntVar(&execWorkers, "workers", 10, "Parallel workers for multi-host scans")
	ExecCmd.Flags().IntVar(&execTimeout, "timeout", 15, "Execution timeout in seconds")
	ExecCmd.Flags().BoolVar(&execNoClean, "no-cleanup", false, "Do not delete output temp file (SMB mode)")

	ExecCmd.MarkFlagRequired("command")
}

func runExec(cmd *cobra.Command, args []string) error {
	targetStr := args[0]

	// Credentials depuis les flags globaux (common.*)
	user := common.Username
	pass := common.Password
	domain := common.Domain
	ntHash := common.NTLMHash

	if user == "" {
		return fmt.Errorf("username required: use -u USER")
	}
	if pass == "" && ntHash == "" {
		return fmt.Errorf("password or NT hash required: use -p PASS or --hash NTHASH")
	}
	if domain == "" {
		return fmt.Errorf("domain required: use -d DOMAIN")
	}

	// Parser les cibles
	targets, err := scanner.ParseTargets(targetStr)
	if err != nil {
		return fmt.Errorf("invalid target %q: %v", targetStr, err)
	}

	common.PrintInfo(fmt.Sprintf("Executing %q on %d target(s) as %s\\%s",
		execCommand, len(targets), strings.ToUpper(domain), user))

	// Décoder le hash si fourni
	var hashBytes []byte
	if ntHash != "" {
		hashBytes, err = hex.DecodeString(ntHash)
		if err != nil {
			return fmt.Errorf("invalid NT hash: %v", err)
		}
	}

	// Worker pool
	cfg := &scanner.ScanConfig{
		Workers: execWorkers,
		Timeout: time.Duration(execTimeout) * time.Second,
	}

	scanner.RunWorkerPool(targets, cfg, func(t scanner.Target) scanner.ScanResult {
		execOnTarget(t, user, pass, domain, hashBytes, execCommand)
		return scanner.ScanResult{Target: t}
	})

	return nil
}

// execOnTarget exécute la commande sur une cible unique avec auto-détection de protocole
func execOnTarget(t scanner.Target, user, pass, domain string, hashBytes []byte, command string) {
	proto := strings.ToLower(execProtocol)
	line := common.NxLine{Protocol: "???", Host: t.IP, Port: 0, Hostname: t.Host}

	// Auto-détection du protocole
	if proto == "auto" || proto == "winrm" {
		if portOpen(t.IP, 5985, 1*time.Second) {
			proto = "winrm"
		} else if portOpen(t.IP, 5986, 1*time.Second) {
			proto = "winrm-https"
		}
	}
	if proto == "auto" {
		if portOpen(t.IP, 445, 1*time.Second) {
			proto = "smb"
		}
	}

	switch proto {
	case "winrm":
		line.Protocol = "WINRM"
		line.Port = 5985
		out, err := winrm.RunCommand(t.IP, user, pass, command)
		if err != nil {
			common.NxFailure(line, err.Error())
			return
		}
		common.NxExecOutput(line, out)

	case "winrm-https":
		line.Protocol = "WINRM"
		line.Port = 5986
		out, err := winrm.RunCommandHTTPS(t.IP, user, pass, command)
		if err != nil {
			common.NxFailure(line, err.Error())
			return
		}
		common.NxExecOutput(line, out)

	case "smb":
		line.Protocol = "SMB"
		line.Port = 445
		cfg := smb.DefaultExecConfig()
		cfg.Timeout = time.Duration(execTimeout) * time.Second
		cfg.NoCleanup = execNoClean

		result, err := smb.SvcExec(t.IP, user, domain, pass, hashBytes, command, cfg)
		if err != nil {
			common.NxFailure(line, fmt.Sprintf("SMB exec failed: %v", err))
			return
		}
		if result.Output == "" {
			common.NxWarning(line, "Command executed (no output captured)")
		} else {
			common.NxExecOutput(line, result.Output)
		}

	default:
		common.NxFailure(line, fmt.Sprintf("no reachable protocol on %s (445/5985/5986 closed)", t.IP))
	}
}

func portOpen(host string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
