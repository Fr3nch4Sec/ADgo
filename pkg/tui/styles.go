// pkg/tui/styles.go
package tui

import "github.com/charmbracelet/lipgloss"

var (
	// Couleurs principales — orange/rouge comme la bannière ADgo
	colorOrange   = lipgloss.Color("214") // orange vif
	colorRed      = lipgloss.Color("196") // rouge
	colorGreen    = lipgloss.Color("82")  // vert succès
	colorYellow   = lipgloss.Color("226") // jaune warning
	colorCyan     = lipgloss.Color("51")  // cyan info
	colorGray     = lipgloss.Color("240") // gris dim
	colorDarkGray = lipgloss.Color("236") // fond sombre
	colorWhite    = lipgloss.Color("255") // blanc

	// Styles de texte
	StyleTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorOrange)

	StyleSubtitle = lipgloss.NewStyle().
			Foreground(colorGray)

	StyleSuccess = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorGreen)

	StyleError = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorRed)

	StyleWarning = lipgloss.NewStyle().
			Foreground(colorYellow)

	StyleInfo = lipgloss.NewStyle().
			Foreground(colorCyan)

	StyleDim = lipgloss.NewStyle().
			Foreground(colorGray)

	StyleHighlight = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorOrange).
			Background(colorDarkGray)

	// Bordures
	StyleBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorOrange).
			Padding(0, 1)

	StyleBoxDim = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorGray).
			Padding(0, 1)

	StyleHeader = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorWhite).
			Background(lipgloss.Color("235")).
			Padding(0, 1)

	// Status badges
	StyleBadgePwned = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorGreen).
			Background(lipgloss.Color("22")).
			Padding(0, 1)

	StyleBadgeFailed = lipgloss.NewStyle().
				Foreground(colorGray).
				Padding(0, 1)

	StyleBadgeScanning = lipgloss.NewStyle().
				Foreground(colorYellow).
				Padding(0, 1)

	// Table header
	StyleTableHeader = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorOrange).
				BorderBottom(true).
				BorderStyle(lipgloss.NormalBorder()).
				BorderForeground(colorGray)

	// Barre de progression
	StyleProgressFilled = lipgloss.NewStyle().
				Foreground(colorOrange)

	StyleProgressEmpty = lipgloss.NewStyle().
				Foreground(colorDarkGray)

	// Raccourcis clavier
	StyleKey = lipgloss.NewStyle().
			Foreground(colorOrange).
			Bold(true)

	StyleKeyDesc = lipgloss.NewStyle().
			Foreground(colorGray)
)

// RenderKeyHelp affiche un raccourci clavier formaté : [q] quitter
func RenderKeyHelp(key, desc string) string {
	return StyleKey.Render("["+key+"]") + " " + StyleKeyDesc.Render(desc)
}

// RenderBadge affiche un badge de statut
func RenderBadge(status string) string {
	switch status {
	case "pwned", "admin":
		return StyleBadgePwned.Render("✓ PWNED")
	case "authed":
		return StyleSuccess.Render("✓ authed")
	case "open":
		return StyleInfo.Render("● open")
	case "scanning":
		return StyleBadgeScanning.Render("⟳ scanning")
	case "failed":
		return StyleBadgeFailed.Render("✗ failed")
	case "closed":
		return StyleDim.Render("· closed")
	default:
		return StyleDim.Render(status)
	}
}

// RenderProgressBar affiche une barre de progression ASCII
func RenderProgressBar(current, total, width int) string {
	if total == 0 {
		return ""
	}
	pct := float64(current) / float64(total)
	filled := int(float64(width) * pct)
	if filled > width {
		filled = width
	}

	bar := ""
	for i := 0; i < width; i++ {
		if i < filled {
			bar += StyleProgressFilled.Render("█")
		} else {
			bar += StyleProgressEmpty.Render("░")
		}
	}
	return bar
}
