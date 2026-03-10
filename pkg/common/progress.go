// pkg/common/progress.go
package common

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
)

// ============================================================
// Progress bar — sans dépendance externe (juste fatih/color)
// ============================================================

// ProgressBar représente une barre de progression terminal
type ProgressBar struct {
	total     int
	current   int
	width     int    // largeur en caractères de la barre
	label     string // label affiché à gauche
	startTime time.Time
	done      bool
}

// NewProgressBar crée une nouvelle barre de progression
// label : texte affiché avant la barre (ex: "ACL enum")
// total : nombre total d'éléments à traiter
func NewProgressBar(label string, total int) *ProgressBar {
	return &ProgressBar{
		total:     total,
		current:   0,
		width:     40,
		label:     label,
		startTime: time.Now(),
	}
}

// Increment avance la barre d'un pas et la redessine
func (p *ProgressBar) Increment() {
	p.current++
	p.render()
}

// IncrementWith avance la barre et affiche un message contextuel
func (p *ProgressBar) IncrementWith(msg string) {
	p.current++
	p.renderWith(msg)
}

// Done marque la barre comme terminée et passe à la ligne suivante
func (p *ProgressBar) Done() {
	if p.done {
		return
	}
	p.done = true
	p.current = p.total
	p.render()
	fmt.Fprintln(os.Stdout) // nouvelle ligne après la barre
}

// DoneWith marque la barre terminée avec un message de résumé
func (p *ProgressBar) DoneWith(summary string) {
	p.Done()
	elapsed := time.Since(p.startTime).Round(time.Second)
	colorSuccess.Fprintf(os.Stdout, "[+] %s — %s in %s\n", p.label, summary, elapsed)
}

// ============================================================
// Rendu interne
// ============================================================

func (p *ProgressBar) render() {
	p.renderWith("")
}

func (p *ProgressBar) renderWith(msg string) {
	if p.total == 0 {
		return
	}

	pct := float64(p.current) / float64(p.total)
	filled := int(pct * float64(p.width))
	if filled > p.width {
		filled = p.width
	}

	bar := strings.Repeat("█", filled) + strings.Repeat("░", p.width-filled)
	elapsed := time.Since(p.startTime)

	// ETA calculé seulement si on a avancé
	eta := ""
	if p.current > 0 && p.current < p.total {
		perItem := elapsed / time.Duration(p.current)
		remaining := perItem * time.Duration(p.total-p.current)
		eta = fmt.Sprintf(" ETA %s", remaining.Round(time.Second))
	}

	// Tronquer le message contextuel si trop long
	suffix := ""
	if msg != "" {
		if len(msg) > 30 {
			msg = msg[:27] + "..."
		}
		suffix = " " + msg
	}

	// \r pour réécrire la même ligne
	line := fmt.Sprintf("\r  %s [%s] %d/%d (%.0f%%)%s%s",
		p.label, bar, p.current, p.total, pct*100, eta, suffix)

	// Colorer la barre selon l'avancement
	switch {
	case pct >= 1.0:
		color.New(color.FgGreen).Fprint(os.Stdout, line)
	case pct >= 0.5:
		color.New(color.FgCyan).Fprint(os.Stdout, line)
	default:
		color.New(color.FgWhite).Fprint(os.Stdout, line)
	}
}

// ============================================================
// Spinner — pour les opérations de durée inconnue
// ============================================================

// Spinner affiche une animation pendant une opération bloquante
type Spinner struct {
	label  string
	frames []string
	stop   chan struct{}
	done   chan struct{}
}

// NewSpinner crée un spinner pour une opération de durée inconnue
// Exemple : NewSpinner("Connecting to DC")
func NewSpinner(label string) *Spinner {
	return &Spinner{
		label:  label,
		frames: []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
}

// Start lance le spinner en arrière-plan (non bloquant)
func (s *Spinner) Start() {
	go func() {
		defer close(s.done)
		i := 0
		for {
			select {
			case <-s.stop:
				fmt.Fprintf(os.Stdout, "\r%-60s\r", "")
				return
			default:
				colorInfo.Fprintf(os.Stdout, "\r  %s %s ", s.frames[i%len(s.frames)], s.label)
				time.Sleep(80 * time.Millisecond)
				i++
			}
		}
	}()
}

// Stop arrête le spinner
func (s *Spinner) Stop() {
	close(s.stop)
	<-s.done
}

// StopWith arrête le spinner et affiche un message de résultat
func (s *Spinner) StopWith(success bool, msg string) {
	s.Stop()
	if success {
		PrintSuccess(msg)
	} else {
		PrintErrorMsg(msg)
	}
}
