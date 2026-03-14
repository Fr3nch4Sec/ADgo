// pkg/common/output.go
//
// Fonctions d'affichage communes à toutes les commandes ADgo.
//
// PrintInfo / PrintSuccess / PrintWarning / PrintFound  — messages formatés
// PrintTable                                             — tableau ASCII
// PrintCredential                                        — credential en évidence
// PrintCount                                             — compteur de résultats
// PrintOutput                                            — affichage générique JSON/texte
// NewSpinner / Spinner                                   — indicateur de progression
// NxSummaryLine                                          — ligne de résumé NxStyle

package common

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
)

// ============================================================
// Couleurs
// ============================================================

var (
	colorInfo    = color.New(color.FgCyan)
	colorSuccess = color.New(color.FgGreen, color.Bold)
	colorWarning = color.New(color.FgYellow)
	colorError   = color.New(color.FgRed)
	colorPwned   = color.New(color.FgHiGreen, color.Bold)
	colorCred    = color.New(color.FgHiYellow, color.Bold)
	colorDim     = color.New(color.Faint)
)

// ============================================================
// Messages simples
// ============================================================

// PrintInfo affiche un message d'information [*]
func PrintInfo(msg string) {
	if Quiet {
		return
	}
	colorInfo.Printf("[*] %s\n", msg)
}

// PrintSuccess affiche un message de succès [+]
func PrintSuccess(msg string) {
	colorSuccess.Printf("[+] %s\n", msg)
}

// PrintWarning affiche un avertissement [!]
func PrintWarning(msg string) {
	colorWarning.Printf("[!] %s\n", msg)
}

// PrintError affiche une erreur [-]
func PrintError(msg interface{}) {
	colorError.Printf("[-] %v\n", msg)
}

// PrintFound affiche un champ trouvé (label: valeur)
func PrintFound(label string, value interface{}) {
	colorDim.Printf("    %-16s ", label+":")
	fmt.Printf("%v\n", value)
}

// PrintCredential affiche un credential trouvé de façon très visible
func PrintCredential(domain, username, secret string) {
	colorPwned.Printf("[CRED] ")
	colorCred.Printf("%s\\%s", strings.ToUpper(domain), username)
	colorDim.Printf(" : ")
	colorCred.Printf("%s\n", secret)
}

// PrintCount affiche un compteur de résultats
func PrintCount(n int, what string) {
	if n == 0 {
		colorWarning.Printf("[!] No %s found\n", what)
		return
	}
	colorSuccess.Printf("[+] Found %d %s\n", n, what)
}

// ============================================================
// Tableau ASCII
// ============================================================

// PrintTable affiche un tableau formaté avec en-têtes et lignes
func PrintTable(headers []string, rows [][]string) {
	if len(rows) == 0 {
		return
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader(headers)
	table.SetBorder(false)
	table.SetColumnSeparator("  ")
	table.SetHeaderLine(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("─")
	table.SetTablePadding("  ")
	table.SetNoWhiteSpace(false)
	table.SetAutoWrapText(false)

	// Colorer certaines colonnes selon leur contenu
	for _, row := range rows {
		colored := make([]string, len(row))
		for i, cell := range row {
			colored[i] = colorizeCell(cell)
		}
		table.Append(colored)
	}

	table.Render()
}

// colorizeCell applique des couleurs selon le contenu de la cellule
func colorizeCell(cell string) string {
	switch strings.ToUpper(cell) {
	case "HIGH", "PWNED", "ADMIN", "YES", "ENABLED", "TRUE":
		return color.GreenString(cell)
	case "UNFILTERED", "VULNERABLE", "EXPOSED":
		return color.HiRedString(cell)
	case "MEDIUM", "WARNING":
		return color.YellowString(cell)
	case "LOW", "NO", "DISABLED", "FALSE", "FILTERED":
		return color.New(color.Faint).Sprint(cell)
	case "FOREST":
		return color.CyanString(cell)
	}
	// Hashes NT — mettre en évidence
	if len(cell) == 32 && isHexString(cell) {
		return color.HiYellowString(cell)
	}
	// Mots de passe trouvés (entre parenthèses ou format clair)
	if strings.Contains(cell, "aad3b435") {
		return color.New(color.Faint).Sprint(cell)
	}
	return cell
}

func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// ============================================================
// PrintOutput — affichage générique (JSON ou tableau)
// ============================================================

// PrintOutput affiche des données dans le format demandé.
// Supporte JSON, BloodHound JSON, ou affichage texte générique.
func PrintOutput(data interface{}, bloodhound, jsonOutput, debug bool) {
	if jsonOutput || bloodhound {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(data)
		return
	}

	// Affichage texte selon le type
	switch v := data.(type) {
	case []string:
		for _, s := range v {
			fmt.Println(" ", s)
		}
	case string:
		fmt.Println(v)
	default:
		// Fallback JSON si on ne sait pas quoi faire du type
		b, _ := json.MarshalIndent(data, "  ", "  ")
		fmt.Println(string(b))
	}
}

// ============================================================
// Spinner — indicateur de progression
// ============================================================

// Spinner indicateur de progression en ligne de commande
type Spinner struct {
	label   string
	frames  []string
	stop    chan struct{}
	stopped bool
	mu      sync.Mutex
}

// NewSpinner crée un nouveau spinner avec le label donné
func NewSpinner(label string) *Spinner {
	return &Spinner{
		label:  label,
		frames: []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		stop:   make(chan struct{}),
	}
}

// Start démarre le spinner (non-bloquant)
func (s *Spinner) Start() {
	if Quiet {
		return
	}
	go func() {
		i := 0
		for {
			select {
			case <-s.stop:
				fmt.Printf("\r%-60s\r", "") // effacer la ligne
				return
			default:
				frame := s.frames[i%len(s.frames)]
				colorInfo.Printf("\r%s %s... ", frame, s.label)
				i++
				time.Sleep(80 * time.Millisecond)
			}
		}
	}()
}

// Stop arrête le spinner et efface la ligne
func (s *Spinner) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return
	}
	s.stopped = true
	close(s.stop)
	time.Sleep(90 * time.Millisecond) // laisser la goroutine effacer
}

// ============================================================
// Résumé NxStyle
// ============================================================

// NxSummaryHeader affiche l'en-tête d'un résumé
func NxSummaryHeader(title string) {
	line := strings.Repeat("─", 52)
	fmt.Printf(" %s\n %-40s\n %s\n", line, title, line)
}

// NxSummaryLine affiche une ligne de résumé (label + valeur alignés)
func NxSummaryLine(label string, value interface{}) {
	colorDim.Printf("  %-28s", label+":")
	fmt.Printf(" %v\n", value)
}
