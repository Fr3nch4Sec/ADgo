// pkg/tui/dashboard.go
//
// Dashboard de scan en temps réel — bubbletea
//
// Affiche :
//   - Barre de progression du scan
//   - Tableau des hôtes découverts (scrollable)
//   - Compteurs en temps réel (open / pwned / failed)
//   - Raccourcis clavier (pause, export, quit)

package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ============================================================
// Messages (événements bubbletea)
// ============================================================

// HostResult résultat d'un hôte scanné
type HostResult struct {
	IP       string
	Hostname string
	Port     int
	Protocol string // "SMB", "WINRM"
	Status   string // "pwned", "authed", "failed", "open", "closed"
	User     string // credential utilisé
	Error    string
}

// MsgHostResult nouveau résultat d'hôte
type MsgHostResult struct {
	Result HostResult
}

// MsgScanDone scan terminé
type MsgScanDone struct {
	Duration time.Duration
}

// MsgTick tick pour l'animation
type MsgTick time.Time

// ============================================================
// Model
// ============================================================

// DashboardModel état du dashboard de scan
type DashboardModel struct {
	// Config du scan
	Target   string
	Total    int
	Protocol string
	Username string

	// État
	Results  []HostResult
	Scanned  int
	Paused   bool
	Done     bool
	Duration time.Duration
	Started  time.Time

	// Compteurs
	OpenCount   int
	PwnedCount  int
	AuthedCount int
	FailedCount int

	// UI
	ScrollOffset int
	TermWidth    int
	TermHeight   int

	// Channel pour recevoir les résultats depuis les goroutines de scan
	ResultCh <-chan HostResult
	DoneCh   <-chan time.Duration
}

// NewDashboard crée un nouveau dashboard
func NewDashboard(target string, total int, protocol, username string,
	resultCh <-chan HostResult, doneCh <-chan time.Duration) DashboardModel {
	return DashboardModel{
		Target:   target,
		Total:    total,
		Protocol: protocol,
		Username: username,
		ResultCh: resultCh,
		DoneCh:   doneCh,
		Started:  time.Now(),
	}
}

// ============================================================
// Init
// ============================================================

func (m DashboardModel) Init() tea.Cmd {
	return tea.Batch(
		tickCmd(),
		waitForResult(m.ResultCh, m.DoneCh),
	)
}

// tickCmd déclenche un tick toutes les 100ms pour l'animation
func tickCmd() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return MsgTick(t)
	})
}

// waitForResult attend un résultat depuis le channel de scan
func waitForResult(resultCh <-chan HostResult, doneCh <-chan time.Duration) tea.Cmd {
	return func() tea.Msg {
		select {
		case r, ok := <-resultCh:
			if !ok {
				return nil
			}
			return MsgHostResult{Result: r}
		case d, ok := <-doneCh:
			if !ok {
				return nil
			}
			return MsgScanDone{Duration: d}
		}
	}
}

// ============================================================
// Update
// ============================================================

func (m DashboardModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.TermWidth = msg.Width
		m.TermHeight = msg.Height
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit

		case "p":
			m.Paused = !m.Paused
			return m, nil

		case "up", "k":
			if m.ScrollOffset > 0 {
				m.ScrollOffset--
			}
			return m, nil

		case "down", "j":
			maxScroll := len(m.Results) - m.visibleRows()
			if maxScroll < 0 {
				maxScroll = 0
			}
			if m.ScrollOffset < maxScroll {
				m.ScrollOffset++
			}
			return m, nil

		case "e":
			// TODO: export résultats
			return m, nil
		}

	case MsgTick:
		return m, tea.Batch(tickCmd())

	case MsgHostResult:
		r := msg.Result
		m.Results = append(m.Results, r)
		m.Scanned++

		switch r.Status {
		case "pwned":
			m.PwnedCount++
			m.OpenCount++
		case "authed":
			m.AuthedCount++
			m.OpenCount++
		case "open":
			m.OpenCount++
		case "failed":
			m.FailedCount++
		}

		// Auto-scroll vers le bas si on était déjà en bas
		maxScroll := len(m.Results) - m.visibleRows()
		if maxScroll > 0 && m.ScrollOffset >= maxScroll-1 {
			m.ScrollOffset = maxScroll
		}

		// Continuer à écouter le channel
		return m, waitForResult(m.ResultCh, m.DoneCh)

	case MsgScanDone:
		m.Done = true
		m.Duration = msg.Duration
		return m, nil
	}

	return m, nil
}

// ============================================================
// View
// ============================================================

func (m DashboardModel) View() string {
	if m.TermWidth == 0 {
		m.TermWidth = 100
		m.TermHeight = 30
	}

	var sb strings.Builder

	// En-tête
	sb.WriteString(m.renderHeader())
	sb.WriteString("\n")

	// Barre de progression
	sb.WriteString(m.renderProgress())
	sb.WriteString("\n\n")

	// Tableau des résultats
	sb.WriteString(m.renderTable())
	sb.WriteString("\n")

	// Pied de page
	sb.WriteString(m.renderFooter())

	return sb.String()
}

func (m DashboardModel) renderHeader() string {
	width := m.TermWidth - 4

	// Titre
	title := StyleTitle.Render("ADgo") + StyleDim.Render(" — ") +
		StyleInfo.Render(m.Protocol+" scan")

	// Infos à droite
	elapsed := time.Since(m.Started).Round(time.Second)
	if m.Done {
		elapsed = m.Duration.Round(time.Second)
	}
	info := StyleDim.Render(fmt.Sprintf("target: %s  │  user: %s  │  %v",
		m.Target, m.Username, elapsed))

	// Statut pause/done
	status := ""
	if m.Paused {
		status = StyleWarning.Render(" ⏸ PAUSED")
	} else if m.Done {
		status = StyleSuccess.Render(" ✓ DONE")
	}

	header := lipgloss.JoinHorizontal(lipgloss.Top,
		title+status,
		lipgloss.NewStyle().Width(width-lipgloss.Width(title+status)-lipgloss.Width(info)).Render(""),
		info,
	)

	return StyleBox.Width(width).Render(header)
}

func (m DashboardModel) renderProgress() string {
	width := m.TermWidth - 8
	barWidth := width - 20

	pct := 0
	if m.Total > 0 {
		pct = m.Scanned * 100 / m.Total
	}

	bar := RenderProgressBar(m.Scanned, m.Total, barWidth)
	label := StyleDim.Render(fmt.Sprintf("  %d/%d  %d%%", m.Scanned, m.Total, pct))

	// Compteurs
	counters := strings.Join([]string{
		StyleSuccess.Render(fmt.Sprintf("✓ %d pwned", m.PwnedCount)),
		StyleInfo.Render(fmt.Sprintf("● %d open", m.OpenCount)),
		StyleDim.Render(fmt.Sprintf("✗ %d failed", m.FailedCount)),
	}, "  "+StyleDim.Render("│")+"  ")

	return "  " + bar + label + "\n  " + counters
}

func (m DashboardModel) renderTable() string {
	width := m.TermWidth - 4

	// En-têtes des colonnes
	colIP := 16
	colPort := 7
	colHost := 16
	colStatus := 16
	colUser := width - colIP - colPort - colHost - colStatus - 8

	header := StyleTableHeader.Render(
		fmt.Sprintf("  %-*s %-*s %-*s %-*s %-*s",
			colIP, "HOST",
			colPort, "PORT",
			colHost, "HOSTNAME",
			colStatus, "STATUS",
			colUser, "USER",
		),
	)

	// Lignes visibles
	visibleRows := m.visibleRows()
	start := m.ScrollOffset
	end := start + visibleRows
	if end > len(m.Results) {
		end = len(m.Results)
	}

	var rows []string
	for i := start; i < end; i++ {
		rows = append(rows, m.renderRow(m.Results[i], colIP, colPort, colHost, colStatus, colUser))
	}

	// Padding si pas assez de résultats
	for len(rows) < visibleRows {
		rows = append(rows, "")
	}

	content := header + "\n" + strings.Join(rows, "\n")

	// Indicateur de scroll
	scrollInfo := ""
	if len(m.Results) > visibleRows {
		scrollInfo = StyleDim.Render(fmt.Sprintf(
			"  %d-%d of %d  [↑↓] scroll",
			start+1, end, len(m.Results),
		))
	}

	return StyleBoxDim.Width(width).Render(content) + "\n" + scrollInfo
}

func (m DashboardModel) renderRow(r HostResult, colIP, colPort, colHost, colStatus, colUser int) string {
	statusStr := RenderBadge(r.Status)
	userStr := ""
	if r.User != "" {
		userStr = StyleDim.Render(r.User)
	}
	if r.Error != "" && r.Status == "failed" {
		userStr = StyleError.Render(truncate(r.Error, colUser))
	}

	portStr := fmt.Sprintf("%d", r.Port)
	if r.Protocol != "" {
		portStr = r.Protocol + "/" + portStr
	}

	row := fmt.Sprintf("  %-*s %-*s %-*s",
		colIP, r.IP,
		colPort, portStr,
		colHost, truncate(r.Hostname, colHost),
	)

	// Colorier la ligne selon le statut
	switch r.Status {
	case "pwned":
		row = StyleSuccess.Render(row)
	case "failed":
		row = StyleDim.Render(row)
	default:
		row = StyleInfo.Render(row)
	}

	return row + " " + padRight(statusStr, colStatus) + " " + userStr
}

func (m DashboardModel) renderFooter() string {
	keys := strings.Join([]string{
		RenderKeyHelp("q", "quit"),
		RenderKeyHelp("p", "pause"),
		RenderKeyHelp("↑↓", "scroll"),
		RenderKeyHelp("e", "export"),
	}, "  ")

	return "  " + keys
}

func (m DashboardModel) visibleRows() int {
	// En-tête (5) + progress (3) + box padding (4) + footer (2)
	reserved := 14
	rows := m.TermHeight - reserved
	if rows < 3 {
		rows = 3
	}
	return rows
}

// ============================================================
// Helpers
// ============================================================

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

func padRight(s string, width int) string {
	visible := lipgloss.Width(s)
	if visible >= width {
		return s
	}
	return s + strings.Repeat(" ", width-visible)
}
