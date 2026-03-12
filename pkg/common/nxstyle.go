// pkg/common/nxstyle.go
//
// Output formaté à la NetExec/CrackMapExec :
//
//	SMB   192.168.1.10   445   DC01   [*] Windows Server 2019 (domain:LAB) (signing:True)
//	SMB   192.168.1.10   445   DC01   [+] LAB\administrator (Pwn3d!)
//	SMB   192.168.1.11   445   WEB01  [-] STATUS_LOGON_FAILURE

package common

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
)

// ============================================================
// Couleurs NxStyle
// ============================================================

var (
	nxGreen  = color.New(color.FgGreen, color.Bold)
	nxRed    = color.New(color.FgRed, color.Bold)
	nxYellow = color.New(color.FgYellow)
	nxCyan   = color.New(color.FgCyan)
	nxWhite  = color.New(color.FgWhite, color.Faint)
	nxPwned  = color.New(color.FgGreen, color.Bold, color.BgBlack)
	nxBold   = color.New(color.Bold)
)

// NxLine représente une ligne d'output structurée
type NxLine struct {
	Protocol string // "SMB", "LDAP", "WINRM", "KERBEROS"...
	Host     string // IP ou hostname
	Port     int    // port (0 = ne pas afficher)
	Hostname string // NetBIOS / FQDN de la cible (si connu)
}

// formatPrefix retourne le préfixe commun :  "SMB   192.168.1.10   445   DC01  "
func (l NxLine) formatPrefix() string {
	proto := fmt.Sprintf("%-8s", l.Protocol)
	host := fmt.Sprintf("%-15s", l.Host)

	var port string
	if l.Port > 0 {
		port = fmt.Sprintf("%-6d", l.Port)
	} else {
		port = "      "
	}

	var name string
	if l.Hostname != "" {
		name = fmt.Sprintf("%-12s", l.Hostname)
	} else {
		name = fmt.Sprintf("%-12s", "-")
	}

	return proto + host + " " + port + " " + name + " "
}

// NxInfo affiche une ligne d'information [*] (gris/cyan)
// Exemple : détection d'OS, infos de connexion
func NxInfo(l NxLine, msg string) {
	prefix := l.formatPrefix()
	nxCyan.Fprint(os.Stdout, prefix)
	nxWhite.Fprintf(os.Stdout, "[*] %s\n", msg)
}

// NxSuccess affiche une ligne de succès [+] (vert)
func NxSuccess(l NxLine, msg string) {
	prefix := l.formatPrefix()
	nxCyan.Fprint(os.Stdout, prefix)
	nxGreen.Fprintf(os.Stdout, "[+] %s\n", msg)
}

// NxFailure affiche une ligne d'échec [-] (rouge)
func NxFailure(l NxLine, msg string) {
	prefix := l.formatPrefix()
	nxCyan.Fprint(os.Stdout, prefix)
	nxRed.Fprintf(os.Stdout, "[-] %s\n", msg)
}

// NxWarning affiche un avertissement [!] (jaune)
func NxWarning(l NxLine, msg string) {
	prefix := l.formatPrefix()
	nxCyan.Fprint(os.Stdout, prefix)
	nxYellow.Fprintf(os.Stdout, "[!] %s\n", msg)
}

// NxPwned affiche un accès admin confirmé avec (Pwn3d!) bien visible
func NxPwned(l NxLine, cred string) {
	prefix := l.formatPrefix()
	nxCyan.Fprint(os.Stdout, prefix)
	nxGreen.Fprintf(os.Stdout, "[+] %s ", cred)
	nxPwned.Fprintln(os.Stdout, "(Pwn3d!)")
}

// NxExecOutput affiche la sortie d'une commande exécutée
func NxExecOutput(l NxLine, output string) {
	prefix := l.formatPrefix()
	lines := strings.Split(strings.TrimRight(output, "\r\n"), "\n")
	for i, line := range lines {
		line = strings.TrimRight(line, "\r")
		if i == 0 {
			nxCyan.Fprint(os.Stdout, prefix)
			nxGreen.Fprintf(os.Stdout, "[+] ")
		} else {
			// Continuer les lignes suivantes alignées sous le premier résultat
			fmt.Fprintf(os.Stdout, "%s    ", strings.Repeat(" ", len(prefix)))
		}
		fmt.Fprintf(os.Stdout, "%s\n", line)
	}
}

// NxHostInfo construit le message d'information d'un hôte SMB
// Exemple : "Windows Server 2019 Build 17763 x64 (domain:LAB) (signing:True) (SMBv1:False)"
func NxHostInfo(osName, domain string, signing, smbv1 bool) string {
	parts := []string{}
	if osName != "" {
		parts = append(parts, osName)
	}
	if domain != "" {
		parts = append(parts, fmt.Sprintf("(domain:%s)", domain))
	}
	parts = append(parts, fmt.Sprintf("(signing:%v)", signing))
	parts = append(parts, fmt.Sprintf("(SMBv1:%v)", smbv1))
	return strings.Join(parts, " ")
}

// NxCredString formate des credentials pour l'affichage
// Exemple : "LAB\administrator:Password123" ou "LAB\administrator (hash)"
func NxCredString(domain, username, password, ntHash string) string {
	user := username
	if domain != "" {
		user = domain + `\` + username
	}
	if ntHash != "" {
		return fmt.Sprintf("%s (hash:%s...)", user, ntHash[:8])
	}
	return fmt.Sprintf("%s:%s", user, password)
}

// ============================================================
// Helpers pour le résumé final (style spray/scan)
// ============================================================

// NxSummaryHeader affiche un en-tête de résumé
func NxSummaryHeader(title string) {
	sep := strings.Repeat("─", 60)
	nxBold.Fprintf(os.Stdout, "\n%s\n %s\n%s\n", sep, title, sep)
}

// NxSummaryLine affiche une ligne de résumé
func NxSummaryLine(label string, value interface{}) {
	nxCyan.Fprintf(os.Stdout, "  %-25s", label+":")
	fmt.Fprintf(os.Stdout, " %v\n", value)
}

// PrintScanHeader affiche les colonnes d'en-tête du scan
func PrintScanHeader() {
	nxBold.Fprintf(os.Stdout, "%-8s %-15s %-6s %-12s %s\n",
		"PROTO", "HOST", "PORT", "NAME", "MESSAGE")
	fmt.Fprintln(os.Stdout, strings.Repeat("─", 70))
}
