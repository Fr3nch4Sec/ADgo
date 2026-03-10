// pkg/common/print.go
package common

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/fatih/color"
)

// ============================================================
// Couleurs — définies une seule fois, utilisées partout
// ============================================================

var (
	colorSuccess = color.New(color.FgGreen, color.Bold)
	colorError   = color.New(color.FgRed, color.Bold)
	colorWarning = color.New(color.FgYellow, color.Bold)
	colorInfo    = color.New(color.FgCyan)
	colorDim     = color.New(color.Faint)
	colorBold    = color.New(color.Bold)
)

// ============================================================
// Fonctions Print principales
// ============================================================

// PrintSuccess affiche un message de succès [+] en vert
func PrintSuccess(msg string) {
	colorSuccess.Fprintf(os.Stdout, "[+] %s\n", msg)
}

// PrintError affiche une erreur [-] en rouge sur stderr
func PrintError(err error) {
	if err == nil {
		return
	}
	colorError.Fprintf(os.Stderr, "[-] %s\n", err.Error())
}

// PrintErrorMsg affiche un message d'erreur string en rouge
func PrintErrorMsg(msg string) {
	colorError.Fprintf(os.Stderr, "[-] %s\n", msg)
}

// PrintInfo affiche une information [*] en cyan
func PrintInfo(msg string) {
	colorInfo.Fprintf(os.Stdout, "[*] %s\n", msg)
}

// PrintWarning affiche un avertissement [!] en jaune
func PrintWarning(msg string) {
	colorWarning.Fprintf(os.Stdout, "[!] %s\n", msg)
}

// PrintDim affiche un texte discret (résultats négatifs, détails secondaires)
func PrintDim(msg string) {
	colorDim.Fprintf(os.Stdout, "    %s\n", msg)
}

// PrintSeparator affiche une ligne de séparation
func PrintSeparator() {
	colorDim.Fprintln(os.Stdout, "──────────────────────────────────────────────────")
}

// ============================================================
// PrintOutput — affichage générique (JSON, BloodHound, texte)
// Signature conservée pour compatibilité avec tous les appels existants
// ============================================================

func PrintOutput(data interface{}, quiet, jsonOut, bloodhound bool) {
	if bloodhound {
		printBloodHound(data)
		return
	}

	if jsonOut {
		b, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			PrintError(fmt.Errorf("JSON marshal failed: %v", err))
			return
		}
		fmt.Println(string(b))
		return
	}

	if quiet {
		return
	}

	fmt.Printf("%+v\n", data)
}

// ============================================================
// Helpers colorisés pour les opérations courantes
// ============================================================

// PrintFound affiche un élément trouvé dans une énumération
func PrintFound(label, value string) {
	colorSuccess.Fprintf(os.Stdout, "  %-25s", label+":")
	fmt.Fprintf(os.Stdout, " %s\n", value)
}

// PrintField affiche un champ de résultat standard
func PrintField(label, value string) {
	colorInfo.Fprintf(os.Stdout, "  %-25s", label+":")
	fmt.Fprintf(os.Stdout, " %s\n", value)
}

// PrintCount affiche un résumé de comptage ("Found 42 users")
func PrintCount(count int, label string) {
	if count == 0 {
		colorWarning.Fprintf(os.Stdout, "[!] No %s found\n", label)
	} else {
		colorSuccess.Fprintf(os.Stdout, "[+] Found %d %s\n", count, label)
	}
}

// PrintCredential affiche un credential découvert de façon très visible
func PrintCredential(domain, username, secret string) {
	colorSuccess.Fprintf(os.Stdout, "\n  *** CREDENTIAL FOUND *** ")
	colorBold.Fprintf(os.Stdout, "%s\\%s", domain, username)
	fmt.Fprintf(os.Stdout, " : %s\n\n", secret)
}
