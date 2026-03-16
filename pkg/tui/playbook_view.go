// pkg/tui/playbook_view.go
//
// Vue Playbook — exécution live d'un playbook avec :
//   - Liste des étapes avec statut (pending / running / ok / fail / skip)
//   - Output de l'étape courante affiché en direct
//   - Variables résolues affichées
//   - Option dry-run

package tui

import (
	"fmt"
	"strings"
	"time"

	"adgo/pkg/playbook"

	tea "github.com/charmbracelet/bubbletea"
)

// ============================================================
// Messages
// ============================================================

type playbookStepStartMsg struct{ stepID string }
type playbookStepOutMsg struct {
	stepID string
	line   string
}
type playbookStepEndMsg struct {
	result playbook.StepResult
}
type playbookAllDoneMsg struct {
	result *playbook.RunResult
}

// StepStatus état d'affichage d'une étape.
type StepStatus int

const (
	StepPending StepStatus = iota
	StepRunning
	StepOK
	StepFailed
	StepSkipped
)

// stepState stocke l'état d'affichage d'une étape.
type stepState struct {
	id      string
	name    string
	status  StepStatus
	output  []string
	errMsg  string
	elapsed time.Duration
}

// ============================================================
// Model
// ============================================================

// PlaybookModel est la vue bubbletea d'un playbook.
type PlaybookModel struct {
	ctx  AppContext
	path string

	// Playbook chargé
	pb    *playbook.Playbook
	steps []stepState

	// État
	phase      string // "loading", "running", "done", "error"
	activeStep int    // index de l'étape en cours
	err        string

	// Output de l'étape courante (ring buffer pour éviter OOM)
	liveOutput []string
	maxOutput  int

	// Résultat final
	result *playbook.RunResult

	// Channels
	stepStartCh chan string
	stepOutCh   chan playbookStepOutMsg
	stepEndCh   chan playbook.StepResult
	doneCh      chan *playbook.RunResult

	// Scroll
	scrollOffset int
	width        int
	height       int
}

// NewPlaybookModel crée la vue playbook.
func NewPlaybookModel(path string, ctx AppContext) PlaybookModel {
	return PlaybookModel{
		ctx:         ctx,
		path:        path,
		phase:       "loading",
		maxOutput:   100,
		stepStartCh: make(chan string, 16),
		stepOutCh:   make(chan playbookStepOutMsg, 256),
		stepEndCh:   make(chan playbook.StepResult, 16),
		doneCh:      make(chan *playbook.RunResult, 1),
	}
}

// ============================================================
// Init
// ============================================================

func (m PlaybookModel) Init() tea.Cmd {
	return tea.Batch(
		m.loadAndRun(),
		m.waitMsg(),
		playTickCmd(),
	)
}

func (m PlaybookModel) loadAndRun() tea.Cmd {
	return func() tea.Msg {
		pb, err := playbook.Load(m.path)
		if err != nil {
			return ErrMsg{Err: fmt.Errorf("cannot load playbook: %v", err)}
		}

		// Initialiser les états des étapes
		steps := make([]stepState, len(pb.Steps))
		for i, s := range pb.Steps {
			steps[i] = stepState{
				id:     s.ID,
				name:   s.Name,
				status: StepPending,
			}
		}

		// Lancer l'exécution en goroutine (version instrumentée)
		go func() {
			vars := map[string]string{
				"domain":   pb.Env["domain"],
				"dc_ip":    pb.Env["dc_ip"],
				"username": pb.Env["username"],
				"password": pb.Env["password"],
			}
			runner := playbook.NewRunner("", vars, true, false)
			result, _ := runner.Run(pb)
			m.doneCh <- result
		}()

		return struct {
			pb    *playbook.Playbook
			steps []stepState
		}{pb, steps}
	}
}

func (m PlaybookModel) waitMsg() tea.Cmd {
	return func() tea.Msg {
		select {
		case id, ok := <-m.stepStartCh:
			if !ok {
				return nil
			}
			return playbookStepStartMsg{id}
		case o, ok := <-m.stepOutCh:
			if !ok {
				return nil
			}
			return o
		case r, ok := <-m.stepEndCh:
			if !ok {
				return nil
			}
			return playbookStepEndMsg{r}
		case d, ok := <-m.doneCh:
			if !ok {
				return nil
			}
			return playbookAllDoneMsg{d}
		}
	}
}

func playTickCmd() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return MsgTick(t)
	})
}

// ============================================================
// Update
// ============================================================

func (m PlaybookModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc":
			return m, Back()
		case "up", "k":
			if m.scrollOffset > 0 {
				m.scrollOffset--
			}
		case "down", "j":
			m.scrollOffset++
		}

	case ErrMsg:
		m.phase = "error"
		m.err = msg.Error()

	// Le loadAndRun retourne un struct anonyme — on le traite via interface{}
	case interface{}:
		// playbook chargé
		type loadResult struct {
			pb    *playbook.Playbook
			steps []stepState
		}
		if lr, ok := msg.(loadResult); ok {
			m.pb = lr.pb
			m.steps = lr.steps
			m.phase = "running"
		}

	case playbookStepStartMsg:
		for i, s := range m.steps {
			if s.id == msg.stepID {
				m.steps[i].status = StepRunning
				m.activeStep = i
				m.liveOutput = nil
				break
			}
		}
		return m, m.waitMsg()

	case playbookStepOutMsg:
		// Ajouter la ligne à l'output live (ring buffer)
		m.liveOutput = append(m.liveOutput, msg.line)
		if len(m.liveOutput) > m.maxOutput {
			m.liveOutput = m.liveOutput[1:]
		}
		return m, m.waitMsg()

	case playbookStepEndMsg:
		r := msg.result
		for i, s := range m.steps {
			if s.id == r.StepID {
				if r.Skipped {
					m.steps[i].status = StepSkipped
				} else if r.Success {
					m.steps[i].status = StepOK
				} else {
					m.steps[i].status = StepFailed
					m.steps[i].errMsg = r.Error
				}
				m.steps[i].elapsed = r.Duration
				break
			}
		}
		return m, m.waitMsg()

	case playbookAllDoneMsg:
		m.phase = "done"
		m.result = msg.result

	case MsgTick:
		if m.phase == "running" {
			return m, tea.Batch(m.waitMsg(), playTickCmd())
		}
	}

	return m, nil
}

// ============================================================
// View
// ============================================================

func (m PlaybookModel) View() string {
	if m.width == 0 {
		m.width = 100
		m.height = 30
	}

	var sb strings.Builder

	// En-tête
	name := m.path
	if m.pb != nil {
		name = m.pb.Name
	}
	phaseStr := ""
	switch m.phase {
	case "loading":
		phaseStr = StyleInfo.Render(" ⟳ loading")
	case "running":
		phaseStr = StyleInfo.Render(" ⟳ running")
	case "done":
		phaseStr = StyleSuccess.Render(" ✓ done")
	case "error":
		phaseStr = StyleError.Render(" ✗ error")
	}

	sb.WriteString("  " + StyleTitle.Render("Playbook") + StyleDim.Render(" — "+name) + phaseStr + "\n\n")

	if m.phase == "error" {
		sb.WriteString(StyleError.Render("  [!] "+m.err) + "\n\n")
		sb.WriteString("  " + RenderKeyHelp("q", "back"))
		return sb.String()
	}

	// Liste des étapes (moitié gauche)
	sb.WriteString(m.renderStepList())
	sb.WriteString("\n")

	// Output de l'étape active (moitié droite / bas)
	if len(m.liveOutput) > 0 {
		sb.WriteString(m.renderLiveOutput())
		sb.WriteString("\n")
	}

	// Résumé si terminé
	if m.phase == "done" && m.result != nil {
		sb.WriteString(m.renderSummary())
		sb.WriteString("\n")
	}

	// Statut bar
	sb.WriteString("  " + RenderKeyHelp("↑↓", "scroll") + "  " + RenderKeyHelp("q", "back"))

	return sb.String()
}

func (m PlaybookModel) renderStepList() string {
	var sb strings.Builder

	for i, s := range m.steps {
		icon := ""
		style := StyleDim
		switch s.status {
		case StepPending:
			icon = "·"
		case StepRunning:
			icon = "⟳"
			style = StyleInfo
		case StepOK:
			icon = "✓"
			style = StyleSuccess
		case StepFailed:
			icon = "✗"
			style = StyleError
		case StepSkipped:
			icon = "⊘"
			style = StyleDim
		}

		num := fmt.Sprintf("%2d.", i+1)
		elapsed := ""
		if s.elapsed > 0 {
			elapsed = StyleDim.Render(fmt.Sprintf("  %v", s.elapsed.Round(time.Millisecond)))
		}
		errStr := ""
		if s.errMsg != "" {
			errStr = "\n       " + StyleError.Render(truncateStr(s.errMsg, 60))
		}

		sb.WriteString(fmt.Sprintf("  %s %s %s%s%s\n",
			StyleDim.Render(num),
			style.Render(icon),
			style.Render(s.name),
			elapsed,
			errStr,
		))
	}

	return sb.String()
}

func (m PlaybookModel) renderLiveOutput() string {
	maxLines := 8
	if m.height > 30 {
		maxLines = 12
	}

	lines := m.liveOutput
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}

	var sb strings.Builder
	sb.WriteString("  " + StyleDim.Render("── output ──") + "\n")
	for _, l := range lines {
		sb.WriteString("  " + StyleDim.Render(truncateStr(l, m.width-4)) + "\n")
	}
	return sb.String()
}

func (m PlaybookModel) renderSummary() string {
	r := m.result
	ok, fail, skip := 0, 0, 0
	for _, s := range r.Steps {
		if s.Skipped {
			skip++
		} else if s.Success {
			ok++
		} else {
			fail++
		}
	}

	return fmt.Sprintf("  %s  %s  %s  %s\n",
		StyleSuccess.Render(fmt.Sprintf("✓ %d ok", ok)),
		StyleError.Render(fmt.Sprintf("✗ %d failed", fail)),
		StyleDim.Render(fmt.Sprintf("⊘ %d skipped", skip)),
		StyleDim.Render(fmt.Sprintf("in %v", r.Duration.Round(time.Second))),
	)
}
