// pkg/tui/kerberos_view.go
//
// Vue Kerberos — kerberoast, AS-REP roast, user enum et kerspray.
//
// Modes :
//   "kerberoast"  → TGS-REQ sur chaque SPN, affiche hashes live
//   "asreproast"  → AS-REQ sans pré-auth, affiche hashes live
//   "userenum"    → teste chaque compte, affiche valides/invalides
//   "kerspray"    → spray Kerberos, affiche credentials valides

package tui

import (
	"fmt"
	"strings"
	"time"

	"adgo/pkg/kerberos"

	tea "github.com/charmbracelet/bubbletea"
)

// ============================================================
// Config
// ============================================================

// KerberosViewConfig paramètres de la vue kerberos.
type KerberosViewConfig struct {
	Mode       string // "kerberoast", "asreproast", "userenum", "kerspray"
	Domain     string
	DCIP       string
	Username   string
	Password   string
	NTHash     string
	UsersFile  string
	ForceRC4   bool
	OutputFile string
}

// ============================================================
// Messages spécifiques
// ============================================================

type kerberosHashMsg struct{ h kerberos.HashcatHash }
type kerberosUserMsg struct{ r kerberos.KerbResult }
type kerberosDoneMsg struct {
	mode    string
	total   int
	success int
}

// ============================================================
// Model
// ============================================================

// KerberosModel est la vue bubbletea des opérations Kerberos.
type KerberosModel struct {
	cfg *KerberosViewConfig

	phase string // "init", "running", "done", "error"
	err   string

	// Résultats live
	hashes       []kerberos.HashcatHash
	validUsers   []string
	invalidUsers int
	lockedUsers  []string

	// Compteurs
	total     int
	processed int

	// Channels
	hashCh chan kerberos.HashcatHash
	userCh chan kerberos.KerbResult
	doneCh chan kerberosDoneMsg

	width  int
	height int
}

// NewKerberosModel crée la vue Kerberos.
func NewKerberosModel(cfg *KerberosViewConfig) KerberosModel {
	return KerberosModel{
		cfg:    cfg,
		phase:  "init",
		hashCh: make(chan kerberos.HashcatHash, 128),
		userCh: make(chan kerberos.KerbResult, 128),
		doneCh: make(chan kerberosDoneMsg, 1),
	}
}

// ============================================================
// Init
// ============================================================

func (m KerberosModel) Init() tea.Cmd {
	return tea.Batch(
		m.startOperation(),
		m.waitMsg(),
	)
}

func (m KerberosModel) startOperation() tea.Cmd {
	return func() tea.Msg {
		go m.runOperation()
		return nil
	}
}

// runOperation exécute l'opération kerberos en goroutine.
func (m *KerberosModel) runOperation() {
	switch m.cfg.Mode {
	case "kerberoast":
		m.runKerberoast()
	case "asreproast":
		m.runASREPRoast()
	case "userenum":
		m.runUserEnum()
	case "kerspray":
		m.runKerspray()
	}
}

func (m *KerberosModel) runKerberoast() {
	// Lancer KerberoastTargetsRC4 et streamer les résultats
	bruteConfig := &kerberos.BruteConfig{
		Domain:    m.cfg.Domain,
		DCIP:      m.cfg.DCIP,
		UsersFile: m.cfg.UsersFile,
	}
	users, _ := kerberos.EnumerateUsers(bruteConfig)
	_ = users
	// Dans une implémentation complète, on appellerait KerberoastTargetsRC4
	// et on enverrait chaque résultat dans m.hashCh au fil de l'eau.
	// Pour l'instant on signale done.
	m.doneCh <- kerberosDoneMsg{mode: "kerberoast", total: 0, success: 0}
}

func (m *KerberosModel) runASREPRoast() {
	results, err := kerberos.ASREPRoastNoCreds(
		m.cfg.UsersFile, m.cfg.Domain, m.cfg.DCIP, m.cfg.OutputFile,
	)
	if err != nil {
		m.doneCh <- kerberosDoneMsg{mode: "asreproast"}
		return
	}
	success := 0
	for _, r := range results {
		if r.Vulnerable {
			success++
			m.hashCh <- r.Hash
		}
	}
	m.doneCh <- kerberosDoneMsg{mode: "asreproast", total: len(results), success: success}
}

func (m *KerberosModel) runUserEnum() {
	cfg := &kerberos.BruteConfig{
		Domain:    m.cfg.Domain,
		DCIP:      m.cfg.DCIP,
		UsersFile: m.cfg.UsersFile,
		Threads:   5,
	}
	result, err := kerberos.EnumerateUsers(cfg)
	if err != nil {
		m.doneCh <- kerberosDoneMsg{mode: "userenum"}
		return
	}
	for _, u := range result.ValidCreds {
		m.userCh <- u
	}
	m.doneCh <- kerberosDoneMsg{
		mode:    "userenum",
		total:   result.Attempts,
		success: len(result.ValidUsers),
	}
}

func (m *KerberosModel) runKerspray() {
	cfg := &kerberos.BruteConfig{
		Domain:    m.cfg.Domain,
		DCIP:      m.cfg.DCIP,
		UsersFile: m.cfg.UsersFile,
		Password:  m.cfg.Password,
		Threads:   3,
	}
	result, err := kerberos.KerberosSpray(cfg)
	if err != nil {
		m.doneCh <- kerberosDoneMsg{mode: "kerspray"}
		return
	}
	for _, c := range result.ValidCreds {
		m.userCh <- c
	}
	m.doneCh <- kerberosDoneMsg{
		mode:    "kerspray",
		total:   result.Attempts,
		success: len(result.ValidCreds),
	}
}

func (m KerberosModel) waitMsg() tea.Cmd {
	return func() tea.Msg {
		select {
		case h, ok := <-m.hashCh:
			if !ok {
				return nil
			}
			return kerberosHashMsg{h}
		case u, ok := <-m.userCh:
			if !ok {
				return nil
			}
			return kerberosUserMsg{u}
		case d, ok := <-m.doneCh:
			if !ok {
				return nil
			}
			return d
		}
	}
}

// ============================================================
// Update
// ============================================================

func (m KerberosModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc":
			return m, Back()
		case "s":
			// Sauvegarder les hashes dans un fichier
			if len(m.hashes) > 0 {
				kerberos.SaveHashcatFile(m.hashes, m.cfg.OutputFile)
			}
		}

	case kerberosHashMsg:
		m.phase = "running"
		m.hashes = append(m.hashes, msg.h)
		m.processed++
		return m, m.waitMsg()

	case kerberosUserMsg:
		m.phase = "running"
		r := msg.r
		if r.Valid && r.Success {
			m.validUsers = append(m.validUsers, r.Username)
		} else if r.Locked {
			m.lockedUsers = append(m.lockedUsers, r.Username)
		} else if !r.Valid {
			m.invalidUsers++
		} else {
			m.validUsers = append(m.validUsers, r.Username)
		}
		m.processed++
		return m, m.waitMsg()

	case kerberosDoneMsg:
		m.phase = "done"
		m.total = msg.total
	}

	return m, nil
}

// ============================================================
// View
// ============================================================

func (m KerberosModel) View() string {
	if m.width == 0 {
		m.width = 100
		m.height = 30
	}

	var sb strings.Builder

	// En-tête
	title := modeTitle(m.cfg.Mode)
	phaseStr := ""
	switch m.phase {
	case "init":
		phaseStr = StyleInfo.Render(" ⟳ starting...")
	case "running":
		phaseStr = StyleInfo.Render(" ⟳ running")
	case "done":
		phaseStr = StyleSuccess.Render(" ✓ done")
	case "error":
		phaseStr = StyleError.Render(" ✗ error")
	}

	sb.WriteString("  " + StyleTitle.Render(title) + phaseStr + "\n")
	sb.WriteString("  " + StyleDim.Render(fmt.Sprintf(
		"%s → %s  |  domain: %s",
		m.cfg.DCIP, m.cfg.Domain, m.cfg.Domain,
	)) + "\n\n")

	// Contenu selon le mode
	switch m.cfg.Mode {
	case "kerberoast", "asreproast":
		sb.WriteString(m.renderHashTable())
	case "userenum", "kerspray":
		sb.WriteString(m.renderUserTable())
	}

	// Raccourcis
	sb.WriteString("\n  ")
	keys := []string{
		RenderKeyHelp("q", "back"),
	}
	if len(m.hashes) > 0 {
		keys = append(keys, RenderKeyHelp("s", "save hashes"))
	}
	sb.WriteString(strings.Join(keys, "  "))

	return sb.String()
}

func (m KerberosModel) renderHashTable() string {
	if len(m.hashes) == 0 {
		if m.phase == "done" {
			return "  " + StyleDim.Render("No hashes captured.\n")
		}
		return "  " + StyleInfo.Render("Waiting for TGS responses...\n")
	}

	var sb strings.Builder
	sb.WriteString(StyleSuccess.Render(fmt.Sprintf(
		"  [+] %d hash(es) captured\n\n", len(m.hashes),
	)))
	sb.WriteString(StyleTableHeader.Render(
		fmt.Sprintf("  %-22s %-40s %-8s %-8s",
			"USERNAME", "SPN / TYPE", "ENCTYPE", "MODE"),
	) + "\n")

	shown := m.hashes
	maxRows := 12
	if m.height > 20 {
		maxRows = m.height - 14
	}
	if len(shown) > maxRows {
		shown = shown[len(shown)-maxRows:] // afficher les plus récents
	}

	for _, h := range shown {
		label := h.SPN
		if label == "" {
			label = h.Domain
		}
		encStr := enctypeShort(h.EncType)
		modeStr := fmt.Sprintf("%d", h.Mode)
		sb.WriteString(fmt.Sprintf("  %-22s %-40s %-8s %-8s\n",
			StyleSuccess.Render(h.Username),
			StyleDim.Render(truncateStr(label, 38)),
			encStr,
			StyleDim.Render(modeStr),
		))
		// Afficher le hash tronqué
		hashPreview := h.Hash
		if len(hashPreview) > 70 {
			hashPreview = hashPreview[:67] + "..."
		}
		sb.WriteString("    " + StyleDim.Render(hashPreview) + "\n\n")
	}

	return sb.String()
}

func (m KerberosModel) renderUserTable() string {
	var sb strings.Builder

	// Compteurs
	sb.WriteString(fmt.Sprintf(
		"  %s  %s  %s  %s\n\n",
		StyleSuccess.Render(fmt.Sprintf("Valid: %d", len(m.validUsers))),
		StyleDim.Render(fmt.Sprintf("Invalid: %d", m.invalidUsers)),
		StyleWarning.Render(fmt.Sprintf("Locked: %d", len(m.lockedUsers))),
		StyleDim.Render(fmt.Sprintf("Processed: %d", m.processed)),
	))

	if len(m.validUsers) > 0 {
		sb.WriteString(StyleSuccess.Render("  Valid accounts:\n"))
		shown := m.validUsers
		if len(shown) > 20 {
			shown = shown[len(shown)-20:]
		}
		for _, u := range shown {
			sb.WriteString("    " + StyleSuccess.Render("✓") + " " + u + "\n")
		}
	} else if m.phase != "done" {
		sb.WriteString("  " + StyleInfo.Render("Testing accounts...\n"))
	}

	return sb.String()
}

// ============================================================
// Helpers
// ============================================================

func modeTitle(mode string) string {
	switch mode {
	case "kerberoast":
		return "Kerberoast"
	case "asreproast":
		return "AS-REP Roast"
	case "userenum":
		return "Kerberos User Enumeration"
	case "kerspray":
		return "Kerberos Password Spray"
	}
	return "Kerberos"
}

func enctypeShort(t int) string {
	switch t {
	case 23:
		return StyleSuccess.Render("RC4")
	case 18:
		return StyleWarning.Render("AES256")
	case 17:
		return StyleWarning.Render("AES128")
	}
	return StyleDim.Render(fmt.Sprintf("enc%d", t))
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// Imports pour time (utilisé dans spray_view.go mais déclaré ici pour éviter confusion)
var _ = time.Second
