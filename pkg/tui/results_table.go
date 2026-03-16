// pkg/tui/results_table.go
//
// Tableau de résultats navigable — pour ldap users, ldap groups, etc.
// Supporte le filtrage en temps réel et les actions sur la sélection.

package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// TableColumn définit une colonne du tableau
type TableColumn struct {
	Title string
	Width int
}

// TableRow ligne du tableau
type TableRow struct {
	Values  []string
	Tags    []string // "admin", "disabled", "kerberoastable", "asreproast"
	RawData interface{}
}

// TableAction action disponible sur la sélection
type TableAction struct {
	Key     string
	Label   string
	Command string // commande adgo à lancer sur la sélection
}

// TableModel modèle du tableau navigable
type TableModel struct {
	Title   string
	Cols    []TableColumn
	Rows    []TableRow
	Cursor  int
	Offset  int
	Filter  string
	Editing bool // mode saisie du filtre

	Actions []TableAction
	Width   int
	Height  int

	// Résultats filtrés (calculés)
	filtered []int // indices des lignes visibles
}

// NewUsersTable crée un tableau d'utilisateurs AD
func NewUsersTable(title string) TableModel {
	return TableModel{
		Title: title,
		Cols: []TableColumn{
			{Title: "USERNAME", Width: 22},
			{Title: "ENABLED", Width: 9},
			{Title: "ADMIN", Width: 7},
			{Title: "SPN", Width: 5},
			{Title: "PREAUTH", Width: 9},
			{Title: "LAST LOGON", Width: 20},
		},
		Actions: []TableAction{
			{Key: "k", Label: "kerberoast", Command: "kerberos kerberoast"},
			{Key: "s", Label: "shadowcred", Command: "ldap shadowcred --target"},
			{Key: "e", Label: "export CSV", Command: ""},
		},
	}
}

// NewHostsTable crée un tableau d'hôtes scannés
func NewHostsTable(title string) TableModel {
	return TableModel{
		Title: title,
		Cols: []TableColumn{
			{Title: "IP", Width: 16},
			{Title: "HOSTNAME", Width: 20},
			{Title: "PORT", Width: 7},
			{Title: "STATUS", Width: 14},
			{Title: "OS", Width: 20},
		},
		Actions: []TableAction{
			{Key: "x", Label: "exec cmd", Command: "exec"},
			{Key: "d", Label: "secretsdump", Command: "smb secretsdump"},
			{Key: "n", Label: "ntds dump", Command: "smb ntds"},
		},
	}
}

// AddRow ajoute une ligne au tableau et recalcule le filtre
func (m *TableModel) AddRow(row TableRow) {
	m.Rows = append(m.Rows, row)
	m.recalcFilter()
}

// SetRows définit toutes les lignes
func (m *TableModel) SetRows(rows []TableRow) {
	m.Rows = rows
	m.recalcFilter()
}

// ============================================================
// Init
// ============================================================

func (m TableModel) Init() tea.Cmd {
	return nil
}

// ============================================================
// Update
// ============================================================

func (m TableModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height

	case tea.KeyMsg:
		if m.Editing {
			return m.updateFilter(msg)
		}

		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit

		case "up", "k":
			if m.Cursor > 0 {
				m.Cursor--
				if m.Cursor < m.Offset {
					m.Offset--
				}
			}

		case "down", "j":
			max := len(m.filtered) - 1
			if m.Cursor < max {
				m.Cursor++
				if m.Cursor >= m.Offset+m.visibleRows() {
					m.Offset++
				}
			}

		case "/":
			// Activer le mode filtre
			m.Editing = true
			m.Filter = ""

		case "esc":
			m.Filter = ""
			m.Editing = false
			m.recalcFilter()

		case "enter":
			// Action par défaut sur la sélection
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m TableModel) updateFilter(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter", "esc":
		m.Editing = false
	case "backspace":
		if len(m.Filter) > 0 {
			m.Filter = m.Filter[:len(m.Filter)-1]
		}
	default:
		if len(msg.String()) == 1 {
			m.Filter += msg.String()
		}
	}
	m.recalcFilter()
	m.Cursor = 0
	m.Offset = 0
	return m, nil
}

// ============================================================
// View
// ============================================================

func (m TableModel) View() string {
	if m.Width == 0 {
		m.Width = 100
		m.Height = 30
	}

	var sb strings.Builder

	// Titre + compteur
	count := fmt.Sprintf("%d", len(m.filtered))
	if m.Filter != "" {
		count += fmt.Sprintf(" (filter: %s)", m.Filter)
	}
	title := StyleTitle.Render(m.Title) + "  " + StyleDim.Render(count+" results")
	sb.WriteString("  " + title + "\n\n")

	// Barre de filtre
	sb.WriteString(m.renderFilterBar())
	sb.WriteString("\n")

	// En-têtes
	sb.WriteString(m.renderHeader())
	sb.WriteString("\n")

	// Lignes
	sb.WriteString(m.renderRows())
	sb.WriteString("\n")

	// Actions
	sb.WriteString(m.renderActions())
	sb.WriteString("\n")

	return sb.String()
}

func (m TableModel) renderFilterBar() string {
	if m.Editing {
		return "  " + StyleInfo.Render("Filter: ") +
			StyleHighlight.Render(m.Filter+"_")
	}
	if m.Filter != "" {
		return "  " + StyleInfo.Render("Filter: ") +
			StyleWarning.Render(m.Filter) +
			StyleDim.Render("  [esc] clear")
	}
	return "  " + StyleDim.Render("[/] filter")
}

func (m TableModel) renderHeader() string {
	var parts []string
	for _, col := range m.Cols {
		parts = append(parts, StyleTableHeader.Width(col.Width).Render(col.Title))
	}
	return "  " + strings.Join(parts, " ")
}

func (m TableModel) renderRows() string {
	visible := m.visibleRows()
	end := m.Offset + visible
	if end > len(m.filtered) {
		end = len(m.filtered)
	}

	var rows []string
	for i := m.Offset; i < end; i++ {
		rowIdx := m.filtered[i]
		row := m.Rows[rowIdx]
		rows = append(rows, m.renderRow(row, i == m.Cursor))
	}

	// Padding
	for len(rows) < visible {
		rows = append(rows, "")
	}

	return strings.Join(rows, "\n")
}

func (m TableModel) renderRow(row TableRow, selected bool) string {
	var parts []string
	for i, col := range m.Cols {
		val := ""
		if i < len(row.Values) {
			val = row.Values[i]
		}

		cell := lipgloss.NewStyle().Width(col.Width).Render(truncate(val, col.Width-1))
		parts = append(parts, cell)
	}

	line := "  " + strings.Join(parts, " ")

	if selected {
		return StyleHighlight.Render(line)
	}

	// Colorier selon les tags
	for _, tag := range row.Tags {
		switch tag {
		case "admin":
			return StyleSuccess.Render(line)
		case "disabled":
			return StyleDim.Render(line)
		case "kerberoastable", "asreproast":
			return StyleWarning.Render(line)
		}
	}

	return line
}

func (m TableModel) renderActions() string {
	if len(m.Actions) == 0 {
		return "  " + RenderKeyHelp("q", "quit")
	}

	keys := []string{RenderKeyHelp("↑↓", "navigate")}
	for _, a := range m.Actions {
		keys = append(keys, RenderKeyHelp(a.Key, a.Label))
	}
	keys = append(keys, RenderKeyHelp("q", "quit"))

	return "  " + strings.Join(keys, "  ")
}

// recalcFilter recalcule les lignes visibles selon le filtre
func (m *TableModel) recalcFilter() {
	m.filtered = nil
	filter := strings.ToLower(m.Filter)

	for i, row := range m.Rows {
		if filter == "" {
			m.filtered = append(m.filtered, i)
			continue
		}
		// Chercher dans toutes les colonnes
		for _, val := range row.Values {
			if strings.Contains(strings.ToLower(val), filter) {
				m.filtered = append(m.filtered, i)
				break
			}
		}
	}
}

func (m TableModel) visibleRows() int {
	reserved := 10
	rows := m.Height - reserved
	if rows < 3 {
		rows = 3
	}
	return rows
}

// SelectedRow retourne la ligne actuellement sélectionnée
func (m TableModel) SelectedRow() *TableRow {
	if len(m.filtered) == 0 || m.Cursor >= len(m.filtered) {
		return nil
	}
	row := m.Rows[m.filtered[m.Cursor]]
	return &row
}
