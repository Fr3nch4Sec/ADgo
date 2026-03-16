// pkg/common/output.go
//
// Optimisations appliquées :
//   1. sync.Pool pour réutiliser les bytes.Buffer de tablewriter
//   2. Écriture bufférisée vers stdout (évite un syscall par ligne)
//   3. Spinner avec atomic bool (pas de mutex)
//   4. colorizeCell : map lookup au lieu de switch (O(1) vs O(n))

package common

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
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
// Writer bufférisé global — réduit les syscalls stdout
// ============================================================

var stdoutWriter = bufio.NewWriterSize(os.Stdout, 4096)

// flushStdout vide le buffer stdout (appeler avant os.Exit ou en fin de commande)
func flushStdout() {
	stdoutWriter.Flush()
}

// ============================================================
// Messages simples
// ============================================================

func PrintInfo(msg string) {
	if Quiet {
		return
	}
	colorInfo.Printf("[*] %s\n", msg)
}

func PrintSuccess(msg string) {
	colorSuccess.Printf("[+] %s\n", msg)
}

func PrintWarning(msg string) {
	colorWarning.Printf("[!] %s\n", msg)
}

func PrintError(msg interface{}) {
	colorError.Printf("[-] %v\n", msg)
}

func PrintFound(label string, value interface{}) {
	colorDim.Printf("    %-16s ", label+":")
	fmt.Printf("%v\n", value)
}

func PrintCredential(domain, username, secret string) {
	colorPwned.Printf("[CRED] ")
	colorCred.Printf("%s\\%s", strings.ToUpper(domain), username)
	colorDim.Printf(" : ")
	colorCred.Printf("%s\n", secret)
}

func PrintCount(n int, what string) {
	if n == 0 {
		colorWarning.Printf("[!] No %s found\n", what)
		return
	}
	colorSuccess.Printf("[+] Found %d %s\n", n, what)
}

// ============================================================
// Table — optimisée avec sync.Pool
// ============================================================

// tableBufferPool réutilise les bytes.Buffer pour éviter les allocations
var tableBufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// colorMap table de lookup O(1) pour colorizeCell
// Wrappers nécessaires car color.HiRedString a la signature func(string, ...interface{}) string
var colorMap = map[string]func(string) string{
	"HIGH":       func(s string) string { return color.HiRedString("%s", s) },
	"UNFILTERED": func(s string) string { return color.HiRedString("%s", s) },
	"VULNERABLE": func(s string) string { return color.HiRedString("%s", s) },
	"EXPOSED":    func(s string) string { return color.HiRedString("%s", s) },
	"ADMIN":      func(s string) string { return color.GreenString("%s", s) },
	"YES":        func(s string) string { return color.GreenString("%s", s) },
	"ENABLED":    func(s string) string { return color.GreenString("%s", s) },
	"TRUE":       func(s string) string { return color.GreenString("%s", s) },
	"PWNED":      func(s string) string { return color.HiGreenString("%s", s) },
	"MEDIUM":     func(s string) string { return color.YellowString("%s", s) },
	"WARNING":    func(s string) string { return color.YellowString("%s", s) },
	"FOREST":     func(s string) string { return color.CyanString("%s", s) },
	"LOW":        func(s string) string { return color.New(color.Faint).Sprint(s) },
	"NO":         func(s string) string { return color.New(color.Faint).Sprint(s) },
	"DISABLED":   func(s string) string { return color.New(color.Faint).Sprint(s) },
	"FALSE":      func(s string) string { return color.New(color.Faint).Sprint(s) },
	"FILTERED":   func(s string) string { return color.New(color.Faint).Sprint(s) },
}

// PrintTable affiche un tableau formaté
func PrintTable(headers []string, rows [][]string) {
	if len(rows) == 0 {
		return
	}

	// Récupérer un buffer du pool
	buf := tableBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer tableBufferPool.Put(buf)

	table := tablewriter.NewWriter(buf)
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

	for _, row := range rows {
		colored := make([]string, len(row))
		for i, cell := range row {
			colored[i] = colorizeCell(cell)
		}
		table.Append(colored)
	}

	table.Render()

	// Écrire le buffer vers stdout en une seule opération
	os.Stdout.Write(buf.Bytes())
}

// colorizeCell applique une couleur selon le contenu
func colorizeCell(cell string) string {
	upper := strings.ToUpper(cell)

	// Lookup O(1) dans la map
	if fn, ok := colorMap[upper]; ok {
		return fn(cell)
	}

	// Hashes NT (32 chars hex)
	if len(cell) == 32 && isHexString(cell) {
		return color.HiYellowString(cell)
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
// PrintOutput
// ============================================================

func PrintOutput(data interface{}, bloodhound, jsonOutput, debug bool) {
	if jsonOutput || bloodhound {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(data)
		return
	}
	switch v := data.(type) {
	case []string:
		for _, s := range v {
			fmt.Println(" ", s)
		}
	case string:
		fmt.Println(v)
	default:
		b, _ := json.MarshalIndent(data, "  ", "  ")
		fmt.Println(string(b))
	}
}

// ============================================================
// Spinner — optimisé avec atomic bool
// ============================================================

// Spinner indicateur de progression
type Spinner struct {
	label   string
	frames  []string
	stopped uint32 // atomic : 0=running, 1=stopped
	stop    chan struct{}
}

func NewSpinner(label string) *Spinner {
	return &Spinner{
		label:  label,
		frames: []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		stop:   make(chan struct{}),
	}
}

func (s *Spinner) Start() {
	if Quiet {
		return
	}
	go func() {
		i := 0
		for {
			select {
			case <-s.stop:
				fmt.Printf("\r%-60s\r", "")
				return
			default:
				colorInfo.Printf("\r%s %s... ", s.frames[i%len(s.frames)], s.label)
				i++
				time.Sleep(80 * time.Millisecond)
			}
		}
	}()
}

func (s *Spinner) Stop() {
	// atomic.CompareAndSwap garantit que Stop() ne peut être appelé qu'une fois
	if atomic.CompareAndSwapUint32(&s.stopped, 0, 1) {
		close(s.stop)
		time.Sleep(90 * time.Millisecond)
	}
}

// ============================================================
// Résumé NxStyle
// ============================================================

func NxSummaryHeader(title string) {
	line := strings.Repeat("─", 52)
	fmt.Printf(" %s\n %-40s\n %s\n", line, title, line)
}

func NxSummaryLine(label string, value interface{}) {
	colorDim.Printf("  %-28s", label+":")
	fmt.Printf(" %v\n", value)
}
