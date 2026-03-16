// pkg/tui/spray_view.go
//
// Vue password spray — affichage en temps réel du spray avec :
//   - Barre de progression globale
//   - Compteurs tentatives / succès / lockouts
//   - Tableau live des credentials trouvés
//   - Avertissements de lockout
//   - Délai entre passes affiché avec countdown

package tui

import (
	"fmt"
	"strings"
	"time"

	"adgo/pkg/spray"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ============================================================
// Config & messages
// ============================================================

// SprayViewConfig paramètres transmis à la vue spray.
type SprayViewConfig struct {
	UsersFile     string
	PasswordsFile string
	Domain        string
	DCIP          string
	Username      string // compte utilisé pour lire la policy (optionnel)
	Password      string
	Delay         int // secondes
	Threads       int
}

// sprayResultMsg wraps un spray.SprayResult pour le channel bubbletea.
type sprayResultMsg struct{ r spray.SprayResult }

// sprayDoneMsg signale la fin du spray.
type sprayDoneMsg struct{ summary *spray.SpraySummary }

// sprayPauseMsg compte à rebours entre deux passes.
type sprayPauseMsg struct {
	remaining time.Duration
	password  string
}

// sprayPolicyMsg reporte la politique de lockout récupérée.
type sprayPolicyMsg struct {
	threshold int
	window    string
	duration  string
}

// ============================================================
// Model
// ============================================================

// SprayModel est la vue bubbletea du password spray.
type SprayModel struct {
	cfg *SprayViewConfig

	// État
	phase       string // "policy", "spraying", "paused", "done", "error"
	currentPass string
	passNum     int
	totalPasses int

	// Compteurs
	attempts  int
	successes int
	locked    int
	failed    int

	// Policy récupérée
	policy sprayPolicyMsg

	// Credentials trouvés
	creds []spray.SprayResult

	// Comptes lockés
	lockedAccounts []string

	// Pause countdown
	pauseRemaining time.Duration
	pauseTotal     time.Duration

	// Error
	err string

	// Summary final
	summary *spray.SpraySummary

	// UI
	width  int
	height int

	// Channels de communication avec la goroutine de spray
	resultCh chan spray.SprayResult
	doneCh   chan *spray.SpraySummary
	pauseCh  chan sprayPauseMsg
}

// NewSprayModel crée la vue spray et lance la goroutine en arrière-plan.
func NewSprayModel(cfg *SprayViewConfig) SprayModel {
	m := SprayModel{
		cfg:      cfg,
		phase:    "policy",
		resultCh: make(chan spray.SprayResult, 256),
		doneCh:   make(chan *spray.SpraySummary, 1),
		pauseCh:  make(chan sprayPauseMsg, 16),
	}
	return m
}

// ============================================================
// Init
// ============================================================

func (m SprayModel) Init() tea.Cmd {
	return tea.Batch(
		m.waitResult(),
		m.startSpray(),
	)
}

// startSpray lance le spray en goroutine et retourne les msgs via channels.
func (m SprayModel) startSpray() tea.Cmd {
	return func() tea.Msg {
		go func() {
			cfg := &spray.SprayConfig{
				UsersFile:     m.cfg.UsersFile,
				PasswordsFile: m.cfg.PasswordsFile,
				Domain:        m.cfg.Domain,
				DCIP:          m.cfg.DCIP,
				Delay:         m.cfg.Delay,
				Threads:       m.cfg.Threads,
				Verbose:       false,
				LockoutCheck:  true,
			}
			summary, _ := spray.PasswordSpray(cfg)
			m.doneCh <- summary
		}()
		return nil
	}
}

// waitResult écoute le channel de résultats.
func (m SprayModel) waitResult() tea.Cmd {
	return func() tea.Msg {
		select {
		case r, ok := <-m.resultCh:
			if !ok {
				return nil
			}
			return sprayResultMsg{r}
		case summary, ok := <-m.doneCh:
			if !ok {
				return nil
			}
			return sprayDoneMsg{summary}
		case p, ok := <-m.pauseCh:
			if !ok {
				return nil
			}
			return p
		}
	}
}

// tickCmd déclenche un tick pour le countdown.
func sprayTickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return MsgTick(t)
	})
}

// ============================================================
// Update
// ============================================================

func (m SprayModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc":
			return m, Back()
		}

	case sprayResultMsg:
		r := msg.r
		m.attempts++
		if r.Success {
			m.successes++
			m.creds = append(m.creds, r)
			m.phase = "spraying"
		} else if r.Error == "account locked or disabled" {
			m.locked++
			m.lockedAccounts = append(m.lockedAccounts, r.Username)
		} else {
			m.failed++
		}
		return m, m.waitResult()

	case sprayDoneMsg:
		m.phase = "done"
		m.summary = msg.summary
		if msg.summary != nil {
			m.successes = len(msg.summary.SuccessfulCreds)
		}

	case sprayPauseMsg:
		m.phase = "paused"
		m.pauseRemaining = msg.remaining
		m.pauseTotal = msg.remaining
		m.currentPass = msg.password
		return m, tea.Batch(m.waitResult(), sprayTickCmd())

	case MsgTick:
		if m.phase == "paused" && m.pauseRemaining > 0 {
			m.pauseRemaining -= time.Second
			if m.pauseRemaining <= 0 {
				m.phase = "spraying"
			}
			return m, tea.Batch(m.waitResult(), sprayTickCmd())
		}
		return m, m.waitResult()

	case sprayPolicyMsg:
		m.policy = msg
		m.phase = "spraying"
		return m, m.waitResult()
	}

	return m, nil
}

// ============================================================
// View
// ============================================================

func (m SprayModel) View() string {
	if m.width == 0 {
		m.width = 100
		m.height = 30
	}

	var sb strings.Builder

	// En-tête
	sb.WriteString(m.renderHeader())
	sb.WriteString("\n\n")

	// Selon la phase
	switch m.phase {
	case "policy":
		sb.WriteString("  " + StyleInfo.Render("⟳") + " Reading lockout policy...\n")

	case "spraying", "paused", "done":
		sb.WriteString(m.renderCounters())
		sb.WriteString("\n\n")

		if m.phase == "paused" {
			sb.WriteString(m.renderPauseBar())
			sb.WriteString("\n\n")
		}

		if len(m.creds) > 0 {
			sb.WriteString(m.renderCredsTable())
			sb.WriteString("\n\n")
		}

		if len(m.lockedAccounts) > 0 {
			sb.WriteString(m.renderLockedWarning())
			sb.WriteString("\n\n")
		}

		if m.phase == "done" {
			sb.WriteString(m.renderDone())
			sb.WriteString("\n\n")
		}

	case "error":
		sb.WriteString(StyleError.Render("  [!] "+m.err) + "\n\n")
	}

	// Barre de statut
	sb.WriteString(RenderStatusBar(AppContext{
		Domain: m.cfg.Domain, DCIP: m.cfg.DCIP,
	}, m.width))

	return sb.String()
}

func (m SprayModel) renderHeader() string {
	title := StyleTitle.Render("Password Spray")
	phase := ""
	switch m.phase {
	case "spraying":
		phase = StyleInfo.Render(" ⟳ running")
	case "paused":
		phase = StyleWarning.Render(" ⏸ paused")
	case "done":
		phase = StyleSuccess.Render(" ✓ done")
	}
	target := StyleDim.Render(fmt.Sprintf(
		"  %s → %s  |  users: %s  |  passwords: %s",
		m.cfg.Domain, m.cfg.DCIP,
		m.cfg.UsersFile, m.cfg.PasswordsFile,
	))
	return "  " + title + phase + "\n  " + target
}

func (m SprayModel) renderCounters() string {
	boxes := []struct {
		label string
		value string
		style lipgloss.Style
	}{
		{"Attempts", fmt.Sprintf("%d", m.attempts), StyleDim},
		{"Valid", fmt.Sprintf("%d", m.successes), StyleSuccess},
		{"Failed", fmt.Sprintf("%d", m.failed), StyleDim},
		{"Locked", fmt.Sprintf("%d", m.locked), StyleWarning},
	}

	var parts []string
	for _, b := range boxes {
		parts = append(parts, fmt.Sprintf(
			"%s %s",
			b.style.Render(b.label+":"),
			StyleTitle.Render(b.value),
		))
	}

	if m.currentPass != "" {
		parts = append(parts, StyleDim.Render("pass: ")+StyleInfo.Render(maskPass(m.currentPass)))
	}

	return "  " + strings.Join(parts, "   │   ")
}

func (m SprayModel) renderPauseBar() string {
	if m.pauseTotal == 0 {
		return ""
	}
	pct := 0
	if m.pauseTotal > 0 {
		remaining := m.pauseRemaining
		if remaining < 0 {
			remaining = 0
		}
		done := m.pauseTotal - remaining
		pct = int(float64(done) / float64(m.pauseTotal) * 100)
	}

	bar := RenderProgressBar(pct, 100, 30)
	return fmt.Sprintf("  %s  Pause before next password: %v remaining",
		bar, m.pauseRemaining.Round(time.Second))
}

func (m SprayModel) renderCredsTable() string {
	var sb strings.Builder
	sb.WriteString(StyleSuccess.Render("  [+] Valid credentials found:\n"))
	sb.WriteString(StyleTableHeader.Render(
		fmt.Sprintf("  %-25s %-25s %-10s", "USERNAME", "PASSWORD", "SOURCE"),
	))
	sb.WriteString("\n")
	for _, c := range m.creds {
		sb.WriteString(fmt.Sprintf("  %-25s %-25s %-10s\n",
			StyleSuccess.Render(c.Username),
			c.Password,
			"spray",
		))
	}
	return sb.String()
}

func (m SprayModel) renderLockedWarning() string {
	var sb strings.Builder
	sb.WriteString(StyleWarning.Render(
		fmt.Sprintf("  [!] %d potentially locked account(s):\n", len(m.lockedAccounts)),
	))
	shown := m.lockedAccounts
	if len(shown) > 5 {
		shown = shown[:5]
	}
	for _, u := range shown {
		sb.WriteString("      " + StyleWarning.Render(u) + "\n")
	}
	if len(m.lockedAccounts) > 5 {
		sb.WriteString(StyleDim.Render(fmt.Sprintf(
			"      ... and %d more\n", len(m.lockedAccounts)-5,
		)))
	}
	return sb.String()
}

func (m SprayModel) renderDone() string {
	var sb strings.Builder
	sb.WriteString(StyleSuccess.Render("  [+] Spray complete\n"))
	if m.summary != nil {
		sb.WriteString(StyleDim.Render(fmt.Sprintf(
			"      %d attempts | %d valid | %v elapsed\n",
			m.summary.TotalAttempts,
			len(m.summary.SuccessfulCreds),
			m.summary.Duration.Round(time.Second),
		)))
	}
	sb.WriteString("\n  " + RenderKeyHelp("q", "back to menu"))
	return sb.String()
}

// maskPass masque partiellement un mot de passe pour l'affichage.
func maskPass(p string) string {
	if len(p) <= 2 {
		return "**"
	}
	return p[:1] + strings.Repeat("*", len(p)-1)
}
