// pkg/tui/session_view.go
//
// Vue session — affiche les credentials et hôtes accumulés pendant la session.

package tui

import (
	"fmt"
	"strings"

	"adgo/pkg/common"

	tea "github.com/charmbracelet/bubbletea"
)

// ============================================================
// Session View
// ============================================================

// SessionModel affiche les credentials et hôtes de la session courante.
type SessionModel struct {
	ctx    AppContext
	creds  []common.SessionCred
	hosts  []common.SessionHost
	tab    int // 0=creds, 1=hosts
	cursor int
	width  int
	height int
}

func NewSessionModel(ctx AppContext) SessionModel {
	return SessionModel{
		ctx:   ctx,
		creds: common.GetAllCreds(),
	}
}

func (m SessionModel) Init() tea.Cmd { return nil }

func (m SessionModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc":
			return m, Back()
		case "tab":
			m.tab = (m.tab + 1) % 2
			m.cursor = 0
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			max := len(m.creds) - 1
			if m.tab == 1 {
				max = len(m.hosts) - 1
			}
			if m.cursor < max {
				m.cursor++
			}
		case "r":
			// Rafraîchir depuis la session
			m.creds = common.GetAllCreds()
		}
	}
	return m, nil
}

func (m SessionModel) View() string {
	if m.width == 0 {
		m.width = 100
	}
	var sb strings.Builder

	sb.WriteString("  " + StyleTitle.Render("Session") + "  ")
	tabs := []string{"Credentials", "Hosts"}
	for i, t := range tabs {
		if i == m.tab {
			sb.WriteString(StyleTitle.Render("["+t+"]") + "  ")
		} else {
			sb.WriteString(StyleDim.Render("["+t+"]") + "  ")
		}
	}
	sb.WriteString("\n\n")

	if m.tab == 0 {
		sb.WriteString(m.renderCreds())
	} else {
		sb.WriteString(m.renderHosts())
	}

	sb.WriteString("\n  ")
	sb.WriteString(strings.Join([]string{
		RenderKeyHelp("tab", "switch tab"),
		RenderKeyHelp("↑↓", "scroll"),
		RenderKeyHelp("r", "refresh"),
		RenderKeyHelp("q", "back"),
	}, "  "))

	return sb.String()
}

func (m SessionModel) renderCreds() string {
	if len(m.creds) == 0 {
		return "  " + StyleDim.Render("No credentials in session yet.\n")
	}
	var sb strings.Builder
	sb.WriteString(StyleTableHeader.Render(
		fmt.Sprintf("  %-20s %-30s %-10s %-8s",
			"DOMAIN\\USER", "SECRET", "SOURCE", "ADMIN"),
	) + "\n")
	for i, c := range m.creds {
		secret := c.Password
		if c.NTHash != "" {
			secret = c.NTHash[:8] + "..."
		}
		isAdmin := ""
		if c.IsAdmin {
			isAdmin = StyleSuccess.Render("YES")
		} else {
			isAdmin = StyleDim.Render("no")
		}
		line := fmt.Sprintf("  %-20s %-30s %-10s %-8s",
			c.Domain+"\\"+c.Username, secret, c.Source, isAdmin)
		if i == m.cursor {
			sb.WriteString(StyleHighlight.Render(line) + "\n")
		} else {
			sb.WriteString(line + "\n")
		}
	}
	return sb.String()
}

func (m SessionModel) renderHosts() string {
	if len(m.hosts) == 0 {
		return "  " + StyleDim.Render("No hosts discovered yet.\n")
	}
	var sb strings.Builder
	sb.WriteString(StyleTableHeader.Render(
		fmt.Sprintf("  %-16s %-20s %-30s %-8s",
			"IP", "HOSTNAME", "OS", "ADMIN"),
	) + "\n")
	for i, h := range m.hosts {
		isAdmin := StyleDim.Render("no")
		if h.IsAdmin {
			isAdmin = StyleSuccess.Render("YES")
		}
		line := fmt.Sprintf("  %-16s %-20s %-30s %-8s",
			h.IP, h.Hostname, truncateStr(h.OS, 28), isAdmin)
		if i == m.cursor {
			sb.WriteString(StyleHighlight.Render(line) + "\n")
		} else {
			sb.WriteString(line + "\n")
		}
	}
	return sb.String()
}

// ============================================================
// ACL View
// ============================================================

// ACLModel affiche les droits ACL dangereux trouvés.
type ACLModel struct {
	ctx    AppContext
	rights []ACLRightMsg
	cursor int
	filter string
	width  int
	height int
}

func NewACLModel(ctx AppContext) ACLModel {
	return ACLModel{ctx: ctx}
}

func (m ACLModel) Init() tea.Cmd { return nil }

func (m ACLModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc":
			return m, Back()
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.rights)-1 {
				m.cursor++
			}
		}
	case ACLRightMsg:
		m.rights = append(m.rights, msg)
		return m, nil
	}
	return m, nil
}

func (m ACLModel) View() string {
	if m.width == 0 {
		m.width = 100
	}
	var sb strings.Builder
	sb.WriteString("  " + StyleTitle.Render("Dangerous ACLs") + "\n\n")

	if len(m.rights) == 0 {
		sb.WriteString("  " + StyleDim.Render("No dangerous ACLs found yet.") + "\n")
		sb.WriteString("  " + StyleDim.Render("Run: adgo ldap acl --dc-ip ... to populate.") + "\n")
	} else {
		sb.WriteString(StyleTableHeader.Render(
			fmt.Sprintf("  %-20s %-20s %-22s %-30s",
				"FROM", "→ TARGET", "RIGHT", "ABUSE"),
		) + "\n")
		for i, r := range m.rights {
			rightStr := StyleWarning.Render(r.Right)
			if r.Right == "GenericAll" || r.Right == "DCSync" {
				rightStr = StyleError.Render(r.Right)
			}
			line := fmt.Sprintf("  %-20s %-20s %-22s %-30s",
				r.ObjectName, r.TargetName, rightStr,
				StyleDim.Render(truncateStr(r.AbuseInfo, 28)),
			)
			if i == m.cursor {
				sb.WriteString(StyleHighlight.Render(line) + "\n")
				// Afficher l'abuse info complète en bas
				sb.WriteString("    " + StyleInfo.Render("↳ "+r.AbuseInfo) + "\n")
			} else {
				sb.WriteString(line + "\n")
			}
		}
	}

	sb.WriteString("\n  " + RenderKeyHelp("↑↓", "navigate") + "  " + RenderKeyHelp("q", "back"))
	return sb.String()
}

// ============================================================
// BloodHound Collection View
// ============================================================

// BloodHoundModel affiche la progression de la collecte BloodHound.
type BloodHoundModel struct {
	ctx   AppContext
	phase string
	steps []struct {
		name  string
		done  bool
		count int
	}
	total  int
	errors []string
	width  int
	height int
}

func NewBloodHoundModel(ctx AppContext) BloodHoundModel {
	return BloodHoundModel{
		ctx:   ctx,
		phase: "collecting",
		steps: []struct {
			name  string
			done  bool
			count int
		}{
			{"Users", false, 0},
			{"Groups", false, 0},
			{"Computers", false, 0},
			{"ACLs", false, 0},
			{"Trusts", false, 0},
		},
	}
}

func (m BloodHoundModel) Init() tea.Cmd { return nil }

func (m BloodHoundModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc":
			return m, Back()
		}
	case ProgressMsg:
		for i, s := range m.steps {
			if s.name == msg.Label {
				m.steps[i].count = msg.Current
				if msg.Current >= msg.Total && msg.Total > 0 {
					m.steps[i].done = true
				}
			}
		}
	case DoneMsg:
		m.phase = "done"
		m.total = msg.Count
	}
	return m, nil
}

func (m BloodHoundModel) View() string {
	if m.width == 0 {
		m.width = 100
	}
	var sb strings.Builder

	phaseStr := StyleInfo.Render(" ⟳ collecting")
	if m.phase == "done" {
		phaseStr = StyleSuccess.Render(" ✓ done")
	}
	sb.WriteString("  " + StyleTitle.Render("BloodHound CE Collection") + phaseStr + "\n\n")

	for _, s := range m.steps {
		icon := StyleDim.Render("·")
		if s.done {
			icon = StyleSuccess.Render("✓")
		} else if m.phase == "collecting" && s.count > 0 {
			icon = StyleInfo.Render("⟳")
		}
		countStr := ""
		if s.count > 0 {
			countStr = StyleDim.Render(fmt.Sprintf(" (%d)", s.count))
		}
		sb.WriteString(fmt.Sprintf("  %s %s%s\n", icon, s.name, countStr))
	}

	if m.phase == "done" {
		sb.WriteString("\n  " + StyleSuccess.Render(fmt.Sprintf(
			"[+] Collection complete — %d objects", m.total,
		)) + "\n")
		sb.WriteString("  " + StyleDim.Render("Import: bloodhound-cli upload --path ./bloodhound/") + "\n")
	}

	sb.WriteString("\n  " + RenderKeyHelp("q", "back"))
	return sb.String()
}

// ============================================================
// ADCS View
// ============================================================

// ADCSModel affiche les résultats d'audit ADCS (ESC1-8).
type ADCSModel struct {
	ctx    AppContext
	vulns  []ESCFoundMsg
	cas    []string
	phase  string
	cursor int
	width  int
	height int
}

func NewADCSModel(ctx AppContext) ADCSModel {
	return ADCSModel{ctx: ctx, phase: "scanning"}
}

func (m ADCSModel) Init() tea.Cmd { return nil }

func (m ADCSModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc":
			return m, Back()
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.vulns)-1 {
				m.cursor++
			}
		}
	case ESCFoundMsg:
		m.vulns = append(m.vulns, msg)
	case DoneMsg:
		m.phase = "done"
	}
	return m, nil
}

func (m ADCSModel) View() string {
	if m.width == 0 {
		m.width = 100
	}
	var sb strings.Builder

	phaseStr := StyleInfo.Render(" ⟳ auditing")
	if m.phase == "done" {
		phaseStr = StyleSuccess.Render(" ✓ done")
	}
	sb.WriteString("  " + StyleTitle.Render("ADCS Audit (ESC1-8)") + phaseStr + "\n\n")

	if len(m.vulns) == 0 {
		if m.phase == "done" {
			sb.WriteString("  " + StyleSuccess.Render("[+] No vulnerable templates detected.") + "\n")
		} else {
			sb.WriteString("  " + StyleInfo.Render("Scanning certificate templates...") + "\n")
		}
	} else {
		sb.WriteString(StyleError.Render(fmt.Sprintf(
			"  [!] %d vulnerable template(s) found\n\n", len(m.vulns),
		)))
		sb.WriteString(StyleTableHeader.Render(
			fmt.Sprintf("  %-30s %-20s %-10s", "TEMPLATE", "VULNERABILITIES", "SAN"),
		) + "\n")
		for i, v := range m.vulns {
			escList := strings.Join(v.ESCNumbers, ", ")
			sanStr := StyleDim.Render("no")
			if v.SANEnabled {
				sanStr = StyleError.Render("YES")
			}
			line := fmt.Sprintf("  %-30s %-20s %-10s",
				StyleError.Render(v.Template),
				escList,
				sanStr,
			)
			if i == m.cursor {
				sb.WriteString(StyleHighlight.Render(line) + "\n")
				sb.WriteString("    " + StyleInfo.Render("↳ "+v.Abuse) + "\n")
			} else {
				sb.WriteString(line + "\n")
			}
		}
	}

	sb.WriteString("\n  " + RenderKeyHelp("↑↓", "navigate") + "  " + RenderKeyHelp("q", "back"))
	return sb.String()
}

// ============================================================
// Config View
// ============================================================

// ConfigModel affiche et édite la configuration persistante (~/.adgo/config.yaml).
type ConfigModel struct {
	ctx     AppContext
	fields  []configField
	cursor  int
	editing bool
	width   int
	height  int
}

type configField struct {
	key   string
	value string
	hint  string
}

func NewConfigModel(ctx AppContext) ConfigModel {
	return ConfigModel{
		ctx: ctx,
		fields: []configField{
			{"dc-ip", ctx.DCIP, "Domain Controller IP"},
			{"domain", ctx.Domain, "Domain FQDN (e.g. lab.local)"},
			{"username", ctx.Username, "Default username"},
			{"workers", "50", "Concurrent threads"},
			{"timeout", "3", "Connection timeout (seconds)"},
		},
	}
}

func (m ConfigModel) Init() tea.Cmd { return nil }

func (m ConfigModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc":
			if m.editing {
				m.editing = false
			} else {
				return m, Back()
			}
		case "up", "k":
			if !m.editing && m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if !m.editing && m.cursor < len(m.fields)-1 {
				m.cursor++
			}
		case "enter":
			m.editing = !m.editing
		case "s":
			if !m.editing {
				// Sauvegarder via configuration.SetField
				// (appel réel à implémenter)
			}
		}
	}
	return m, nil
}

func (m ConfigModel) View() string {
	if m.width == 0 {
		m.width = 100
	}
	var sb strings.Builder

	sb.WriteString("  " + StyleTitle.Render("Configuration") + "  " +
		StyleDim.Render("~/.adgo/config.yaml") + "\n\n")

	for i, f := range m.fields {
		selected := i == m.cursor
		keyStr := StyleDim.Render(fmt.Sprintf("%-12s", f.key))
		valStr := f.value
		if valStr == "" {
			valStr = StyleDim.Render("(not set)")
		}
		hintStr := StyleDim.Render("  " + f.hint)

		line := fmt.Sprintf("  %s  %s%s", keyStr, valStr, hintStr)
		if selected {
			if m.editing {
				// 3 verbes %s → 3 args : clé, valeur+curseur, hint
				line = fmt.Sprintf("  %s  %s_%s",
					StyleTitle.Render(fmt.Sprintf("%-12s", f.key)),
					valStr,
					hintStr,
				)
			}
			sb.WriteString(StyleHighlight.Render(line) + "\n")
		} else {
			sb.WriteString(line + "\n")
		}
	}

	sb.WriteString("\n  ")
	sb.WriteString(strings.Join([]string{
		RenderKeyHelp("↑↓", "navigate"),
		RenderKeyHelp("enter", "edit"),
		RenderKeyHelp("s", "save"),
		RenderKeyHelp("q", "back"),
	}, "  "))

	return sb.String()
}
