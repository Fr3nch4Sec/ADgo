// pkg/tui/app.go
//
// Routeur central des vues TUI.
//
// Toutes les vues bubbletea partagent une interface commune (View) et
// transitent via AppModel qui gère le cycle de vie, les keybindings globaux
// et la pile de navigation (stack-based : Esc/q revient à la vue précédente).
//
// Hiérarchie :
//   AppModel
//   ├── MenuModel           (écran d'accueil)
//   ├── DashboardModel      (scan réseau live)
//   ├── TableModel          (résultats LDAP, etc.)
//   ├── SprayModel          (password spray live)      ← nouveau
//   ├── KerberosModel       (kerberoast/asrep live)    ← nouveau
//   ├── PlaybookModel       (exécution playbook)       ← nouveau
//   ├── SessionModel        (credentials/hôtes)        ← nouveau
//   ├── ACLModel            (chemins d'attaque)        ← nouveau
//   ├── BloodHoundModel     (collecte progress)        ← nouveau
//   ├── ADCSModel           (résultats ESC1-8)         ← nouveau
//   └── ConfigModel         (réglages persistants)     ← nouveau

package tui

import (
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// ============================================================
// ViewID — identifiant de vue
// ============================================================

type ViewID int

const (
	ViewMenu ViewID = iota
	ViewDashboard
	ViewTable
	ViewSpray
	ViewKerberos
	ViewPlaybook
	ViewSession
	ViewACL
	ViewBloodHound
	ViewADCS
	ViewConfig
)

// ============================================================
// NavigateMsg — message de navigation inter-vues
// ============================================================

// NavigateMsg demande au routeur de changer de vue.
// Args contient les paramètres spécifiques à la vue cible.
type NavigateMsg struct {
	To   ViewID
	Args map[string]interface{}
}

// Navigate construit un NavigateMsg (helper)
func Navigate(to ViewID, args ...map[string]interface{}) tea.Cmd {
	a := map[string]interface{}{}
	if len(args) > 0 {
		a = args[0]
	}
	return func() tea.Msg { return NavigateMsg{To: to, Args: a} }
}

// BackMsg revient à la vue précédente
type BackMsg struct{}

func Back() tea.Cmd { return func() tea.Msg { return BackMsg{} } }

// ============================================================
// AppModel — routeur principal
// ============================================================

// AppModel maintient la pile de vues et délègue les messages.
type AppModel struct {
	// Pile de navigation (dernier = vue courante)
	stack []tea.Model

	// Raccourcis globaux actifs
	globalKeys GlobalKeyBindings

	// Dimensions du terminal (propagées à toutes les vues)
	width  int
	height int

	// Contexte de connexion (disponible pour toutes les vues)
	Ctx AppContext

	quitting bool
}

// AppContext regroupe les paramètres de connexion partagés entre toutes les vues.
type AppContext struct {
	DCIP     string
	Domain   string
	Username string
	Password string
	NTHash   string
}

// NewApp crée l'application TUI avec le menu comme vue initiale.
func NewApp(ctx AppContext) AppModel {
	menu := NewMainMenu(ctx.DCIP, ctx.Domain, ctx.Username)
	return AppModel{
		stack:      []tea.Model{menu},
		globalKeys: DefaultGlobalKeys(),
		Ctx:        ctx,
	}
}

// current retourne la vue active
func (a *AppModel) current() tea.Model {
	if len(a.stack) == 0 {
		return nil
	}
	return a.stack[len(a.stack)-1]
}

// push empile une nouvelle vue
func (a *AppModel) push(m tea.Model) {
	a.stack = append(a.stack, m)
}

// pop revient à la vue précédente (minimum 1 vue dans la pile)
func (a *AppModel) pop() {
	if len(a.stack) > 1 {
		a.stack = a.stack[:len(a.stack)-1]
	}
}

// ============================================================
// Init / Update / View
// ============================================================

func (a AppModel) Init() tea.Cmd {
	if cur := a.current(); cur != nil {
		return cur.Init()
	}
	return nil
}

func (a AppModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	// Dimensions du terminal
	case tea.WindowSizeMsg:
		a.width = msg.Width
		a.height = msg.Height
		if cur := a.current(); cur != nil {
			updated, cmd := cur.Update(msg)
			a.stack[len(a.stack)-1] = updated
			return a, cmd
		}
		return a, nil

	// Raccourcis globaux (vérifiés AVANT la vue courante)
	case tea.KeyMsg:
		if cmd := a.globalKeys.Handle(msg, &a); cmd != nil {
			return a, cmd
		}

	// Navigation vers une nouvelle vue
	case NavigateMsg:
		newView := a.buildView(msg.To, msg.Args)
		if newView != nil {
			a.push(newView)
			return a, newView.Init()
		}
		return a, nil

	// Retour arrière
	case BackMsg:
		if len(a.stack) <= 1 {
			// Plus rien derrière → quitter
			return a, tea.Quit
		}
		a.pop()
		return a, nil

	// Quitter
	case tea.QuitMsg:
		a.quitting = true
		return a, tea.Quit
	}

	// Déléguer à la vue courante
	if cur := a.current(); cur != nil {
		updated, cmd := cur.Update(msg)
		a.stack[len(a.stack)-1] = updated
		return a, cmd
	}

	return a, nil
}

func (a AppModel) View() string {
	if a.quitting {
		return "\n"
	}
	if cur := a.current(); cur != nil {
		return cur.View()
	}
	return ""
}

// ============================================================
// buildView — fabrique de vues
// ============================================================

// buildView instancie la vue demandée avec ses arguments.
// Les vues qui nécessitent des channels ou des goroutines les lancent ici.
func (a *AppModel) buildView(id ViewID, args map[string]interface{}) tea.Model {
	str := func(key string) string {
		if v, ok := args[key]; ok {
			return fmt.Sprintf("%v", v)
		}
		return ""
	}

	switch id {
	case ViewMenu:
		return NewMainMenu(a.Ctx.DCIP, a.Ctx.Domain, a.Ctx.Username)

	case ViewDashboard:
		target := str("target")
		totalAny := args["total"]
		total := 0
		if totalAny != nil {
			total = int(totalAny.(int))
		}
		resultCh := make(chan HostResult, 256)
		doneCh := make(chan time.Duration, 1)
		return NewDashboard(target, total, "SMB", a.Ctx.Username, resultCh, doneCh)

	case ViewSpray:
		cfg := &SprayViewConfig{
			UsersFile:     str("users_file"),
			PasswordsFile: str("passwords_file"),
			Domain:        a.Ctx.Domain,
			DCIP:          a.Ctx.DCIP,
			Username:      a.Ctx.Username,
			Password:      a.Ctx.Password,
		}
		return NewSprayModel(cfg)

	case ViewKerberos:
		cfg := &KerberosViewConfig{
			Mode:     str("mode"),
			Domain:   a.Ctx.Domain,
			DCIP:     a.Ctx.DCIP,
			Username: a.Ctx.Username,
			Password: a.Ctx.Password,
		}
		return NewKerberosModel(cfg)

	case ViewPlaybook:
		return NewPlaybookModel(str("path"), a.Ctx)

	case ViewSession:
		return NewSessionModel(a.Ctx)

	case ViewACL:
		return NewACLModel(a.Ctx)

	case ViewBloodHound:
		return NewBloodHoundModel(a.Ctx)

	case ViewADCS:
		return NewADCSModel(a.Ctx)

	case ViewConfig:
		return NewConfigModel(a.Ctx)
	}

	return nil
}

// ============================================================
// Run — point d'entrée
// ============================================================

// RunTUI lance l'application TUI complète (menu principal).
// WithAltScreen : le TUI prend tout le terminal, propre à la fermeture.
// La bannière ASCII est supprimée par PersistentPreRunE de TUICmd avant ce call.
func RunTUI(ctx AppContext) error {
	app := NewApp(ctx)
	p := tea.NewProgram(
		app,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)
	_, err := p.Run()
	return err
}

// RunTUICommand lance le TUI directement sur une vue spécifique.
func RunTUICommand(viewID ViewID, ctx AppContext, args map[string]interface{}) error {
	app := NewApp(ctx)

	view := app.buildView(viewID, args)
	if view == nil {
		return fmt.Errorf("unknown view: %d", viewID)
	}
	app.stack = []tea.Model{view}

	p := tea.NewProgram(
		app,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)
	_, err := p.Run()
	return err
}

// ============================================================
// StatusBar — barre de statut commune (bas de chaque vue)
// ============================================================

// RenderStatusBar génère la barre de statut commune à toutes les vues.
// Elle affiche le contexte de connexion + les raccourcis globaux.
func RenderStatusBar(ctx AppContext, width int, extraKeys ...string) string {
	conn := ""
	if ctx.Domain != "" {
		conn = StyleDim.Render(ctx.Domain+"/"+ctx.Username) + "  " +
			StyleDim.Render("→ "+ctx.DCIP)
	}

	keys := []string{RenderKeyHelp("q", "back"), RenderKeyHelp("?", "help")}
	keys = append(keys, extraKeys...)

	right := strings.Join(keys, "  ")
	pad := width - len(conn) - len(right) - 4
	if pad < 0 {
		pad = 0
	}

	return "  " + conn + strings.Repeat(" ", pad) + right
}

// Évite les imports inutilisés (time est utilisé dans buildView)
var _ = os.Stderr
