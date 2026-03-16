// pkg/tui/keybindings.go
//
// Raccourcis clavier globaux interceptés AVANT chaque vue.
// Les vues peuvent définir leurs propres keybindings supplémentaires.

package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

// GlobalKeyBindings définit les touches interceptées au niveau application.
type GlobalKeyBindings struct {
	Quit []string // touches qui quittent l'app
	Back []string // touches qui reviennent en arrière
	Help []string // touches qui affichent l'aide
}

// DefaultGlobalKeys retourne les raccourcis par défaut.
func DefaultGlobalKeys() GlobalKeyBindings {
	return GlobalKeyBindings{
		Quit: []string{"ctrl+c"},
		Back: []string{"esc"},
		Help: []string{"?"},
	}
}

// Handle teste si msg correspond à un raccourci global et retourne la commande
// correspondante. Retourne nil si la touche n'est pas un raccourci global.
func (g GlobalKeyBindings) Handle(msg tea.KeyMsg, app *AppModel) tea.Cmd {
	key := msg.String()

	for _, k := range g.Quit {
		if key == k {
			return tea.Quit
		}
	}

	for _, k := range g.Back {
		if key == k {
			// Si on est à la vue racine (menu), quitter
			if len(app.stack) <= 1 {
				return tea.Quit
			}
			return Back()
		}
	}

	return nil
}

// ============================================================
// msgs.go inlined — messages async communs à toutes les vues
// ============================================================

// ErrMsg encapsule une erreur arrivée en async depuis une goroutine.
type ErrMsg struct{ Err error }

func (e ErrMsg) Error() string { return e.Err.Error() }

// DoneMsg signale la fin d'une opération longue.
type DoneMsg struct {
	Label string
	Count int
}

// ProgressMsg met à jour la progression d'une tâche.
type ProgressMsg struct {
	Label   string
	Current int
	Total   int
}

// CredFoundMsg signale qu'un credential valide a été trouvé.
type CredFoundMsg struct {
	Username string
	Password string
	NTHash   string
	Source   string // "spray", "kerberoast", "laps"...
	IsAdmin  bool
}

// HashFoundMsg signale qu'un hash kerberos a été capturé.
type HashFoundMsg struct {
	Username string
	SPN      string
	Hash     string
	Mode     int // 13100 ou 18200
	EncType  int
}

// PlaybookStepMsg signale l'avancement d'une étape de playbook.
type PlaybookStepMsg struct {
	StepID  string
	Name    string
	Success bool
	Output  string
	Error   string
}

// ACLRightMsg signale un droit ACL dangereux trouvé.
type ACLRightMsg struct {
	ObjectName string
	TargetName string
	Right      string
	AbuseInfo  string
}

// ESCFoundMsg signale une vulnérabilité ADCS trouvée.
type ESCFoundMsg struct {
	Template   string
	ESCNumbers []string // ["ESC1", "ESC4"]
	SANEnabled bool
	Abuse      string
}
