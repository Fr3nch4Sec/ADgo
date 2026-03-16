// pkg/tui/menu.go
//
// Menu principal interactif — sélection de commande avec bubbletea

package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// MenuItem élément du menu
type MenuItem struct {
	Label    string
	Desc     string
	Command  string // commande adgo à lancer
	Children []MenuItem
	Disabled bool
}

// MenuModel état du menu principal
type MenuModel struct {
	Items    []MenuItem
	Cursor   int
	Selected *MenuItem
	Width    int
	Height   int
	Header   string // contexte : "lab.local | admin | 192.168.1.10"
}

// NewMainMenu crée le menu principal ADgo
func NewMainMenu(dcIP, domain, username string) MenuModel {
	header := ""
	if domain != "" {
		header = fmt.Sprintf("%s | %s | %s", domain, username, dcIP)
	}

	return MenuModel{
		Header: header,
		Items: []MenuItem{
			{
				Label: "Scan & Enumerate",
				Desc:  "Discover hosts, enumerate AD objects",
				Children: []MenuItem{
					{Label: "Network scan", Desc: "Scan subnet for SMB/WinRM hosts", Command: "scan"},
					{Label: "LDAP users", Desc: "Enumerate domain users", Command: "ldap users"},
					{Label: "LDAP groups", Desc: "Enumerate domain groups", Command: "ldap groups"},
					{Label: "LDAP ACLs", Desc: "Find dangerous permissions", Command: "ldap acl"},
					{Label: "Domain trusts", Desc: "Enumerate trust relationships", Command: "ldap trusts"},
				},
			},
			{
				Label: "Credential Attacks",
				Desc:  "LAPS, gMSA, GPP, spray, dump",
				Children: []MenuItem{
					{Label: "LAPS passwords", Desc: "Read local admin passwords", Command: "laps"},
					{Label: "gMSA hashes", Desc: "Read service account NT hashes", Command: "gmsa"},
					{Label: "GPP passwords", Desc: "Scan SYSVOL for cpassword", Command: "gpp"},
					{Label: "Secretsdump", Desc: "Dump local hashes via registry", Command: "smb secretsdump"},
					{Label: "NTDS dump (VSS)", Desc: "Dump NTDS.dit via shadow copy", Command: "smb ntds"},
					{Label: "Password spray", Desc: "Spray with anti-lockout", Command: "spray"},
				},
			},
			{
				Label: "Kerberos",
				Desc:  "Kerberoast, AS-REP, S4U, tickets",
				Children: []MenuItem{
					{Label: "Kerberoast", Desc: "Request TGS for SPN accounts", Command: "kerberos kerberoast"},
					{Label: "Kerberoast RC4", Desc: "Force RC4 — faster to crack", Command: "kerberos kerberoast --force-rc4"},
					{Label: "AS-REP Roast", Desc: "No pre-auth accounts", Command: "kerberos asreproast"},
					{Label: "User enum", Desc: "Find valid accounts (no creds)", Command: "kerberos userenum"},
					{Label: "Kerberos spray", Desc: "Stealth spray via AS-REQ", Command: "kerberos kerspray"},
					{Label: "S4U2Proxy", Desc: "RBCD delegation abuse", Command: "kerberos s4u"},
				},
			},
			{
				Label: "BloodHound & ADCS",
				Desc:  "Collect data, audit certificates",
				Children: []MenuItem{
					{Label: "BloodHound collection", Desc: "Full SharpHound equivalent", Command: "bloodhound"},
					{Label: "ADCS audit", Desc: "Find ESC1-ESC8", Command: "adcs"},
				},
			},
			{
				Label: "Lateral Movement",
				Desc:  "Execute, relay, pivot",
				Children: []MenuItem{
					{Label: "AutoPwn", Desc: "Scan → auth → exec all hosts", Command: "autopwn"},
					{Label: "Exec command", Desc: "Run command on remote host", Command: "exec"},
					{Label: "NTLM relay", Desc: "Relay to ADCS/LDAP/SMB", Command: "relay"},
					{Label: "SOCKS5 proxy", Desc: "Local proxy for pivoting", Command: "proxy"},
				},
			},
			{
				Label:   "Playbooks",
				Desc:    "Run saved attack sequences",
				Command: "playbook list ./playbooks",
			},
			{
				Label:   "Config",
				Desc:    "Manage saved settings",
				Command: "config show",
			},
		},
	}
}

// ============================================================
// Init
// ============================================================

func (m MenuModel) Init() tea.Cmd {
	return nil
}

// ============================================================
// Update
// ============================================================

func (m MenuModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit

		case "up", "k":
			if m.Cursor > 0 {
				m.Cursor--
			}

		case "down", "j":
			if m.Cursor < len(m.Items)-1 {
				m.Cursor++
			}

		case "enter", " ":
			selected := m.Items[m.Cursor]
			if !selected.Disabled {
				m.Selected = &selected
				return m, tea.Quit
			}
		}
	}

	return m, nil
}

// ============================================================
// View
// ============================================================

func (m MenuModel) View() string {
	if m.Width == 0 {
		m.Width = 80
	}

	var sb strings.Builder

	// Bannière compacte
	sb.WriteString(m.renderBanner())
	sb.WriteString("\n")

	// Contexte
	if m.Header != "" {
		sb.WriteString("  " + StyleInfo.Render("Connected: ") +
			StyleDim.Render(m.Header) + "\n\n")
	}

	// Menu
	sb.WriteString(m.renderMenu())
	sb.WriteString("\n")

	// Aide
	sb.WriteString("  " + strings.Join([]string{
		RenderKeyHelp("↑↓", "navigate"),
		RenderKeyHelp("enter", "select"),
		RenderKeyHelp("q", "quit"),
	}, "  "))
	sb.WriteString("\n")

	return sb.String()
}

func (m MenuModel) renderBanner() string {
	lines := []string{
		" █████╗ ██████╗  ██████╗  ██████╗ ",
		"██╔══██╗██╔══██╗██╔════╝ ██╔═══██╗",
		"███████║██║  ██║██║  ███╗██║   ██║",
		"██╔══██║██║  ██║██║   ██║██║   ██║",
		"██║  ██║██████╔╝╚██████╔╝╚██████╔╝",
		"╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚═════╝ ",
	}

	colors := []lipgloss.Color{"214", "208", "202", "196", "160", "124"}
	var rendered []string
	for i, line := range lines {
		rendered = append(rendered,
			lipgloss.NewStyle().Foreground(colors[i]).Bold(i == 0).Render(line))
	}

	return lipgloss.JoinVertical(lipgloss.Left, rendered...)
}

func (m MenuModel) renderMenu() string {
	var items []string
	for i, item := range m.Items {
		cursor := "  "
		labelStyle := StyleDim
		descStyle := StyleDim

		if i == m.Cursor {
			cursor = StyleOrange.Render("▶ ")
			labelStyle = StyleTitle
			descStyle = StyleInfo
		} else if item.Disabled {
			labelStyle = StyleDim
			descStyle = StyleDim
		} else {
			labelStyle = lipgloss.NewStyle().Foreground(colorWhite)
		}

		label := cursor + labelStyle.Render(item.Label)
		desc := ""
		if item.Desc != "" {
			desc = "  " + descStyle.Render(item.Desc)
		}

		items = append(items, label+desc)
	}

	return strings.Join(items, "\n")
}

var StyleOrange = lipgloss.NewStyle().Foreground(colorOrange).Bold(true)
