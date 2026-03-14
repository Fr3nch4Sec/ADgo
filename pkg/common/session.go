// pkg/common/session.go
//
// Session persistante et logging JSON structuré.
//
// La session stocke :
//   - Les credentials valides découverts (scan, spray, laps, gmsa...)
//   - Les hôtes avec leur état (ouvert, authentifié, admin)
//   - Un log JSON de toutes les découvertes (importable dans d'autres outils)
//
// Fichier de session : ~/.adgo/session_<domaine>_<date>.json
// Activé avec : --session (crée/charge la session)
// Log JSON    : --log-file ./adgo_run.json

package common

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ============================================================
// Types
// ============================================================

// SessionCred credential découvert pendant la session
type SessionCred struct {
	Domain   string    `json:"domain"`
	Username string    `json:"username"`
	Password string    `json:"password,omitempty"`
	NTHash   string    `json:"nt_hash,omitempty"`
	IsAdmin  bool      `json:"is_admin"`
	Source   string    `json:"source"` // "spray", "laps", "gmsa", "gpp", "dcsync"
	FoundAt  time.Time `json:"found_at"`
}

// SessionHost hôte découvert et son état
type SessionHost struct {
	IP       string    `json:"ip"`
	Hostname string    `json:"hostname,omitempty"`
	OS       string    `json:"os,omitempty"`
	Ports    []int     `json:"ports_open"`
	IsAdmin  bool      `json:"is_admin"`
	LastSeen time.Time `json:"last_seen"`
}

// LogEntry entrée de log JSON structuré
type LogEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level"` // "info", "success", "warning", "error"
	Command   string                 `json:"command"`
	Host      string                 `json:"host,omitempty"`
	Message   string                 `json:"message"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// Session état complet d'une session ADgo
type Session struct {
	ID        string        `json:"id"`
	Domain    string        `json:"domain"`
	StartTime time.Time     `json:"start_time"`
	Creds     []SessionCred `json:"credentials"`
	Hosts     []SessionHost `json:"hosts"`
	Log       []LogEntry    `json:"log"`

	path string
	mu   sync.Mutex
}

// ============================================================
// Session globale
// ============================================================

var globalSession *Session
var globalLogFile *os.File
var globalLogMu sync.Mutex
var CurrentCommand string // mis à jour par chaque commande

// InitSession charge ou crée une session pour le domaine donné.
// sessionPath : chemin du fichier de session (vide = auto)
func InitSession(domain, sessionPath string) (*Session, error) {
	if sessionPath == "" {
		dir := filepath.Join(homeDir(), ".adgo")
		os.MkdirAll(dir, 0700)
		ts := time.Now().Format("20060102")
		sessionPath = filepath.Join(dir, fmt.Sprintf("session_%s_%s.json",
			strings.ToLower(domain), ts))
	}

	s := &Session{
		Domain:    domain,
		StartTime: time.Now(),
		path:      sessionPath,
	}

	// Charger une session existante si le fichier existe
	if data, err := os.ReadFile(sessionPath); err == nil {
		if err := json.Unmarshal(data, s); err == nil {
			fmt.Printf("[*] Loaded session: %s (%d creds, %d hosts)\n",
				sessionPath, len(s.Creds), len(s.Hosts))
			s.path = sessionPath
			globalSession = s
			return s, nil
		}
	}

	s.ID = fmt.Sprintf("%s-%s", domain, time.Now().Format("150405"))
	globalSession = s
	fmt.Printf("[*] New session: %s\n", sessionPath)
	return s, nil
}

// InitLogFile ouvre le fichier de log JSON (append si existant)
func InitLogFile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("cannot open log file %s: %v", path, err)
	}
	globalLogFile = f
	return nil
}

// GetSession retourne la session active (nil si pas de session)
func GetSession() *Session {
	return globalSession
}

// ============================================================
// Logging structuré
// ============================================================

// LogSuccess enregistre un succès dans le log JSON + terminal
func LogSuccess(host, message string, data map[string]interface{}) {
	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     "success",
		Command:   CurrentCommand,
		Host:      host,
		Message:   message,
		Data:      data,
	}
	writeLogEntry(entry)
	if globalSession != nil {
		globalSession.mu.Lock()
		globalSession.Log = append(globalSession.Log, entry)
		globalSession.mu.Unlock()
		globalSession.save()
	}
}

// LogInfo enregistre une info dans le log JSON
func LogInfo(host, message string, data map[string]interface{}) {
	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Command:   CurrentCommand,
		Host:      host,
		Message:   message,
		Data:      data,
	}
	writeLogEntry(entry)
}

// LogError enregistre une erreur dans le log JSON
func LogError(host, message string) {
	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     "error",
		Command:   CurrentCommand,
		Host:      host,
		Message:   message,
	}
	writeLogEntry(entry)
}

func writeLogEntry(entry LogEntry) {
	if globalLogFile == nil {
		return
	}
	globalLogMu.Lock()
	defer globalLogMu.Unlock()
	data, _ := json.Marshal(entry)
	globalLogFile.Write(data)
	globalLogFile.WriteString("\n")
}

// ============================================================
// Gestion des credentials dans la session
// ============================================================

// SaveCred enregistre un credential découvert dans la session
func SaveCred(domain, username, password, ntHash, source string, isAdmin bool) {
	cred := SessionCred{
		Domain:   strings.ToUpper(domain),
		Username: username,
		Password: password,
		NTHash:   ntHash,
		IsAdmin:  isAdmin,
		Source:   source,
		FoundAt:  time.Now(),
	}

	// Affichage visible
	PrintCredential(domain, username, func() string {
		if ntHash != "" {
			return "aad3b435b51404eeaad3b435b51404ee:" + ntHash
		}
		return password
	}())

	// Log JSON
	LogSuccess("", fmt.Sprintf("Credential found: %s\\%s", domain, username), map[string]interface{}{
		"domain":   domain,
		"username": username,
		"source":   source,
		"is_admin": isAdmin,
	})

	if globalSession == nil {
		return
	}

	globalSession.mu.Lock()
	// Dédupliquer
	for _, c := range globalSession.Creds {
		if strings.EqualFold(c.Username, username) && strings.EqualFold(c.Domain, domain) {
			globalSession.mu.Unlock()
			return
		}
	}
	globalSession.Creds = append(globalSession.Creds, cred)
	globalSession.mu.Unlock()
	globalSession.save()
}

// SaveHost enregistre un hôte découvert dans la session
func SaveHost(ip, hostname, os string, ports []int, isAdmin bool) {
	if globalSession == nil {
		return
	}

	host := SessionHost{
		IP:       ip,
		Hostname: hostname,
		OS:       os,
		Ports:    ports,
		IsAdmin:  isAdmin,
		LastSeen: time.Now(),
	}

	globalSession.mu.Lock()
	for i, h := range globalSession.Hosts {
		if h.IP == ip {
			globalSession.Hosts[i] = host
			globalSession.mu.Unlock()
			globalSession.save()
			return
		}
	}
	globalSession.Hosts = append(globalSession.Hosts, host)
	globalSession.mu.Unlock()
	globalSession.save()
}

// GetAdminCreds retourne les premiers credentials admin de la session
func GetAdminCreds() *SessionCred {
	if globalSession == nil {
		return nil
	}
	globalSession.mu.Lock()
	defer globalSession.mu.Unlock()
	for _, c := range globalSession.Creds {
		if c.IsAdmin {
			return &c
		}
	}
	if len(globalSession.Creds) > 0 {
		return &globalSession.Creds[0]
	}
	return nil
}

// GetAllCreds retourne tous les credentials de la session
func GetAllCreds() []SessionCred {
	if globalSession == nil {
		return nil
	}
	globalSession.mu.Lock()
	defer globalSession.mu.Unlock()
	cp := make([]SessionCred, len(globalSession.Creds))
	copy(cp, globalSession.Creds)
	return cp
}

// PrintSessionSummary affiche un résumé de la session
func PrintSessionSummary() {
	if globalSession == nil {
		return
	}
	globalSession.mu.Lock()
	defer globalSession.mu.Unlock()

	fmt.Println()
	NxSummaryHeader("Session summary")
	NxSummaryLine("Domain", globalSession.Domain)
	NxSummaryLine("Duration", time.Since(globalSession.StartTime).Round(time.Second))
	NxSummaryLine("Hosts discovered", len(globalSession.Hosts))
	NxSummaryLine("Credentials found", len(globalSession.Creds))

	adminCount := 0
	for _, c := range globalSession.Creds {
		if c.IsAdmin {
			adminCount++
		}
	}
	NxSummaryLine("Admin credentials", adminCount)

	if len(globalSession.Creds) > 0 {
		fmt.Println()
		PrintSuccess("Credentials found:")
		for _, c := range globalSession.Creds {
			marker := "  "
			if c.IsAdmin {
				marker = "  [ADMIN] "
			}
			secret := c.Password
			if c.NTHash != "" {
				secret = c.NTHash[:8] + "..."
			}
			fmt.Printf("%s%s\\%s : %s  (via %s)\n", marker, c.Domain, c.Username, secret, c.Source)
		}
	}
}

// ============================================================
// Persistence
// ============================================================

func (s *Session) save() {
	if s.path == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(s.path, data, 0600)
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	if h := os.Getenv("USERPROFILE"); h != "" {
		return h
	}
	return "."
}

// ============================================================
// Resume state — sauvegarde la progression d'un scan
// ============================================================

// ScanState état de progression d'un scan (pour --resume)
type ScanState struct {
	Command   string    `json:"command"`
	Targets   []string  `json:"targets"`
	Completed []string  `json:"completed"`
	StartedAt time.Time `json:"started_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

var scanStateFile string
var scanState *ScanState
var scanStateMu sync.Mutex

// InitScanState initialise l'état de resume pour un scan
func InitScanState(command string, targets []string, stateFile string) *ScanState {
	scanStateFile = stateFile

	// Essayer de charger un état existant
	if stateFile != "" {
		if data, err := os.ReadFile(stateFile); err == nil {
			var state ScanState
			if json.Unmarshal(data, &state) == nil && state.Command == command {
				PrintInfo(fmt.Sprintf("Resuming scan: %d/%d targets completed",
					len(state.Completed), len(state.Targets)))
				scanState = &state
				return scanState
			}
		}
	}

	scanState = &ScanState{
		Command:   command,
		Targets:   targets,
		StartedAt: time.Now(),
	}
	return scanState
}

// MarkCompleted marque une cible comme traitée
func MarkCompleted(target string) {
	if scanState == nil {
		return
	}
	scanStateMu.Lock()
	scanState.Completed = append(scanState.Completed, target)
	scanState.UpdatedAt = time.Now()
	scanStateMu.Unlock()

	if scanStateFile != "" {
		data, _ := json.MarshalIndent(scanState, "", "  ")
		os.WriteFile(scanStateFile, data, 0600)
	}
}

// GetPendingTargets retourne les cibles non encore traitées
func GetPendingTargets(allTargets []string) []string {
	if scanState == nil || len(scanState.Completed) == 0 {
		return allTargets
	}

	completed := make(map[string]bool)
	for _, t := range scanState.Completed {
		completed[t] = true
	}

	var pending []string
	for _, t := range allTargets {
		if !completed[t] {
			pending = append(pending, t)
		}
	}

	return pending
}
