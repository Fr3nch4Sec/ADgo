// pkg/playbook/playbook.go
//
// Système de playbooks ADgo — templates YAML réutilisables
//
// Un playbook décrit :
//   - L'environnement cible (DC, domaine, credentials)
//   - Une séquence d'étapes (commandes adgo, scripts externes, conditions)
//   - Des variables interpolées à l'exécution
//
// Format YAML inspiré de Nuclei :
//
//   id: full-domain-recon
//   name: Full Domain Reconnaissance
//   description: Enumerate users, groups, ACLs, LAPS and run BloodHound
//   tags: [recon, ldap, bloodhound]
//   author: yourname
//
//   env:
//     dc_ip: "{{DC_IP}}"
//     domain: "{{DOMAIN}}"
//     username: "{{USERNAME}}"
//     password: "{{PASSWORD}}"
//
//   steps:
//     - id: users
//       name: Enumerate users
//       type: adgo
//       command: ldap users
//       args:
//         dc-ip: "{{dc_ip}}"
//         username: "{{username}}"
//         password: "{{password}}"
//         domain: "{{domain}}"
//       on_success: continue
//       on_failure: continue
//
//     - id: bloodhound
//       name: BloodHound collection
//       type: adgo
//       command: bloodhound
//       args:
//         dc-ip: "{{dc_ip}}"
//         username: "{{username}}"
//         password: "{{password}}"
//         domain: "{{domain}}"
//         output: "./bh_{{domain}}"
//
//     - id: external_script
//       name: Run custom Python script
//       type: shell
//       command: python3 ./scripts/my_script.py --dc {{dc_ip}} --domain {{domain}}
//       timeout: 60
//       on_failure: stop

package playbook

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ============================================================
// Types
// ============================================================

// Playbook définit une séquence d'actions sur un environnement AD
type Playbook struct {
	ID          string            `yaml:"id"`
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Author      string            `yaml:"author"`
	Tags        []string          `yaml:"tags"`
	Version     string            `yaml:"version"`
	Env         map[string]string `yaml:"env"`  // variables de l'environnement cible
	Vars        map[string]string `yaml:"vars"` // variables calculées / constantes
	Steps       []Step            `yaml:"steps"`
	path        string            // chemin du fichier playbook
}

// Step une étape du playbook
type Step struct {
	ID          string            `yaml:"id"`
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Type        string            `yaml:"type"`        // "adgo", "shell", "python", "condition"
	Command     string            `yaml:"command"`     // sous-commande adgo ou commande shell
	Args        map[string]string `yaml:"args"`        // flags adgo (clé sans --)
	Env         map[string]string `yaml:"env"`         // variables d'env pour cette étape
	Timeout     int               `yaml:"timeout"`     // secondes (défaut 120)
	OnSuccess   string            `yaml:"on_success"`  // "continue" (défaut), "stop", "next:<id>"
	OnFailure   string            `yaml:"on_failure"`  // "continue", "stop" (défaut), "next:<id>"
	Condition   string            `yaml:"condition"`   // expression à évaluer (type: condition)
	SaveOutput  string            `yaml:"save_output"` // nom de variable pour stocker la sortie
	Disabled    bool              `yaml:"disabled"`
}

// StepResult résultat d'une étape
type StepResult struct {
	StepID   string
	Name     string
	Success  bool
	Output   string
	Error    string
	Duration time.Duration
	Skipped  bool
}

// RunResult résultat complet d'un playbook
type RunResult struct {
	PlaybookID string
	StartedAt  time.Time
	Duration   time.Duration
	Steps      []StepResult
	Vars       map[string]string // variables accumulées pendant l'exécution
	Success    bool
}

// ============================================================
// Loader
// ============================================================

// Load charge un playbook depuis un fichier YAML
func Load(path string) (*Playbook, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read playbook %s: %v", path, err)
	}

	var pb Playbook
	if err := yaml.Unmarshal(data, &pb); err != nil {
		return nil, fmt.Errorf("invalid YAML in %s: %v", path, err)
	}

	if pb.ID == "" {
		pb.ID = strings.TrimSuffix(filepath.Base(path), ".yaml")
	}
	pb.path = path

	if pb.Env == nil {
		pb.Env = make(map[string]string)
	}
	if pb.Vars == nil {
		pb.Vars = make(map[string]string)
	}

	return &pb, nil
}

// LoadDir charge tous les playbooks d'un répertoire
func LoadDir(dir string) ([]*Playbook, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("cannot read playbook dir %s: %v", dir, err)
	}

	var playbooks []*Playbook
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		pb, err := Load(filepath.Join(dir, e.Name()))
		if err != nil {
			fmt.Printf("[!] Skipping %s: %v\n", e.Name(), err)
			continue
		}
		playbooks = append(playbooks, pb)
	}
	return playbooks, nil
}

// ============================================================
// Runner
// ============================================================

// Runner exécute un playbook
type Runner struct {
	adgoBin string            // chemin vers l'exécutable adgo (défaut: os.Args[0])
	vars    map[string]string // variables d'exécution (CLI overrides + env)
	verbose bool
	dryRun  bool
}

// NewRunner crée un runner de playbook
func NewRunner(adgoBin string, vars map[string]string, verbose, dryRun bool) *Runner {
	if adgoBin == "" {
		adgoBin = os.Args[0] // s'appeler soi-même
	}
	if vars == nil {
		vars = make(map[string]string)
	}
	return &Runner{adgoBin: adgoBin, vars: vars, verbose: verbose, dryRun: dryRun}
}

// Run exécute un playbook complet
func (r *Runner) Run(pb *Playbook) (*RunResult, error) {
	result := &RunResult{
		PlaybookID: pb.ID,
		StartedAt:  time.Now(),
		Vars:       make(map[string]string),
	}

	// Fusionner les variables : playbook.Env → playbook.Vars → CLI vars
	merged := make(map[string]string)
	for k, v := range pb.Env {
		merged[k] = v
	}
	for k, v := range pb.Vars {
		merged[k] = v
	}
	for k, v := range r.vars {
		merged[k] = v
	}

	// Résoudre les variables d'environnement OS ({{DC_IP}} → $DC_IP)
	for k, v := range merged {
		merged[k] = resolveEnvVars(v)
	}

	fmt.Printf("\n[playbook] %s\n", pb.Name)
	if pb.Description != "" {
		fmt.Printf("           %s\n", pb.Description)
	}
	fmt.Printf("[playbook] %d step(s) | vars: %s\n\n",
		len(pb.Steps), formatVarsPreview(merged))

	// Exécuter les étapes
	stepIdx := 0
	for stepIdx < len(pb.Steps) {
		step := pb.Steps[stepIdx]

		if step.Disabled {
			stepIdx++
			continue
		}

		// Interpoler les variables dans cette étape
		step = interpolateStep(step, merged)

		fmt.Printf("[%d/%d] %s", stepIdx+1, len(pb.Steps), step.Name)
		if step.Description != "" {
			fmt.Printf(" — %s", step.Description)
		}
		fmt.Println()

		sr := r.runStep(step, merged)
		result.Steps = append(result.Steps, sr)

		// Sauvegarder la sortie comme variable si demandé
		if step.SaveOutput != "" && sr.Output != "" {
			merged[step.SaveOutput] = strings.TrimSpace(sr.Output)
			result.Vars[step.SaveOutput] = merged[step.SaveOutput]
		}

		// Décider de la suite
		next := decideNext(sr.Success, step, pb.Steps)
		switch next.action {
		case "stop":
			if !sr.Success {
				fmt.Printf("[playbook] Stopping on failure of step %q\n", step.ID)
			}
			goto done
		case "jump":
			// Trouver l'index de la prochaine étape par ID
			jumpIdx := findStepIndex(pb.Steps, next.target)
			if jumpIdx < 0 {
				fmt.Printf("[!] Step %q not found for jump\n", next.target)
				stepIdx++
			} else {
				stepIdx = jumpIdx
			}
		default: // continue
			stepIdx++
		}
	}

done:
	result.Duration = time.Since(result.StartedAt)

	// Calculer le succès global
	result.Success = true
	for _, sr := range result.Steps {
		if !sr.Success && !sr.Skipped {
			result.Success = false
			break
		}
	}

	printRunSummary(result)
	return result, nil
}

// runStep exécute une étape individuelle
func (r *Runner) runStep(step Step, vars map[string]string) StepResult {
	start := time.Now()
	sr := StepResult{StepID: step.ID, Name: step.Name}

	timeout := step.Timeout
	if timeout <= 0 {
		timeout = 120
	}

	if r.dryRun {
		cmd := buildCommand(r.adgoBin, step, vars)
		fmt.Printf("  [dry-run] %s\n", strings.Join(cmd, " "))
		sr.Success = true
		sr.Output = "[dry-run]"
		sr.Duration = time.Since(start)
		return sr
	}

	var output string
	var err error

	switch step.Type {
	case "adgo", "":
		output, err = r.runAdgo(step, vars, timeout)
	case "shell", "bash", "cmd":
		output, err = r.runShell(step, vars, timeout)
	case "python":
		output, err = r.runPython(step, vars, timeout)
	case "condition":
		matched := evaluateCondition(step.Condition, vars)
		if r.verbose {
			fmt.Printf("  [condition] %q → %v\n", step.Condition, matched)
		}
		sr.Success = matched
		sr.Duration = time.Since(start)
		return sr
	default:
		err = fmt.Errorf("unknown step type %q", step.Type)
	}

	sr.Duration = time.Since(start)
	sr.Output = output
	sr.Success = err == nil

	if err != nil {
		sr.Error = err.Error()
		fmt.Printf("  [-] FAILED in %v: %v\n", sr.Duration.Round(time.Millisecond), err)
	} else {
		fmt.Printf("  [+] OK in %v\n", sr.Duration.Round(time.Millisecond))
	}

	if r.verbose && output != "" {
		for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
			fmt.Printf("      %s\n", line)
		}
	}

	return sr
}

// runAdgo exécute une sous-commande adgo
func (r *Runner) runAdgo(step Step, vars map[string]string, timeoutSec int) (string, error) {
	args := buildAdgoArgs(step, vars)

	if r.verbose {
		fmt.Printf("  [exec] %s %s\n", r.adgoBin, strings.Join(args, " "))
	}

	cmd := exec.Command(r.adgoBin, args...)
	cmd.Env = buildEnv(step.Env, vars)

	var sb strings.Builder
	cmd.Stdout = &sb
	cmd.Stderr = &sb

	if err := runWithTimeout(cmd, time.Duration(timeoutSec)*time.Second); err != nil {
		return sb.String(), err
	}
	return sb.String(), nil
}

// runShell exécute une commande shell
func (r *Runner) runShell(step Step, vars map[string]string, timeoutSec int) (string, error) {
	cmdStr := interpolate(step.Command, vars)

	if r.verbose {
		fmt.Printf("  [shell] %s\n", cmdStr)
	}

	var cmd *exec.Cmd
	if isWindows() {
		cmd = exec.Command("cmd", "/c", cmdStr)
	} else {
		cmd = exec.Command("sh", "-c", cmdStr)
	}
	cmd.Env = buildEnv(step.Env, vars)

	var sb strings.Builder
	cmd.Stdout = &sb
	cmd.Stderr = &sb

	if err := runWithTimeout(cmd, time.Duration(timeoutSec)*time.Second); err != nil {
		return sb.String(), err
	}
	return sb.String(), nil
}

// runPython exécute un script Python
func (r *Runner) runPython(step Step, vars map[string]string, timeoutSec int) (string, error) {
	cmdStr := interpolate(step.Command, vars)
	parts := splitArgs(cmdStr)

	python := "python3"
	if isWindows() {
		python = "python"
	}

	args := append([]string{python}, parts...)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = buildEnv(step.Env, vars)

	if r.verbose {
		fmt.Printf("  [python] %s\n", cmdStr)
	}

	var sb strings.Builder
	cmd.Stdout = &sb
	cmd.Stderr = &sb

	if err := runWithTimeout(cmd, time.Duration(timeoutSec)*time.Second); err != nil {
		return sb.String(), err
	}
	return sb.String(), nil
}

// ============================================================
// Helpers
// ============================================================

type nextAction struct {
	action string // "continue", "stop", "jump"
	target string // pour "jump"
}

func decideNext(success bool, step Step, allSteps []Step) nextAction {
	directive := step.OnSuccess
	if !success {
		directive = step.OnFailure
		if directive == "" {
			directive = "stop" // défaut en cas d'échec
		}
	}
	if directive == "" {
		directive = "continue"
	}

	switch {
	case directive == "stop":
		return nextAction{action: "stop"}
	case strings.HasPrefix(directive, "next:"):
		return nextAction{action: "jump", target: strings.TrimPrefix(directive, "next:")}
	default:
		return nextAction{action: "continue"}
	}
}

func findStepIndex(steps []Step, id string) int {
	for i, s := range steps {
		if s.ID == id {
			return i
		}
	}
	return -1
}

// interpolate remplace {{var}} par sa valeur dans vars
func interpolate(s string, vars map[string]string) string {
	re := regexp.MustCompile(`\{\{(\w+)\}\}`)
	return re.ReplaceAllStringFunc(s, func(match string) string {
		key := re.FindStringSubmatch(match)[1]
		if val, ok := vars[key]; ok {
			return val
		}
		// Essayer la variable d'environnement OS
		if val := os.Getenv(strings.ToUpper(key)); val != "" {
			return val
		}
		return match // laisser tel quel si non résolu
	})
}

// interpolateStep interpole toutes les chaînes d'une étape
func interpolateStep(step Step, vars map[string]string) Step {
	step.Command = interpolate(step.Command, vars)
	step.Condition = interpolate(step.Condition, vars)
	newArgs := make(map[string]string)
	for k, v := range step.Args {
		newArgs[k] = interpolate(v, vars)
	}
	step.Args = newArgs
	return step
}

// buildAdgoArgs construit les arguments CLI pour une sous-commande adgo
func buildAdgoArgs(step Step, vars map[string]string) []string {
	// Le command peut être "ldap users" → ["ldap", "users"]
	parts := strings.Fields(step.Command)
	args := append([]string{}, parts...)

	// Ajouter --no-banner pour les appels non-interactifs
	args = append(args, "--no-banner")

	for k, v := range step.Args {
		if v == "true" {
			args = append(args, "--"+k)
		} else if v != "" && v != "false" {
			args = append(args, "--"+k, v)
		}
	}
	return args
}

// buildCommand retourne la commande complète pour l'affichage dry-run
func buildCommand(bin string, step Step, vars map[string]string) []string {
	return append([]string{bin}, buildAdgoArgs(step, vars)...)
}

// buildEnv construit les variables d'environnement pour exec.Cmd
func buildEnv(stepEnv, vars map[string]string) []string {
	env := os.Environ()
	for k, v := range stepEnv {
		env = append(env, k+"="+interpolate(v, vars))
	}
	return env
}

// resolveEnvVars remplace {{VAR}} par la valeur de la variable d'environnement OS
func resolveEnvVars(s string) string {
	re := regexp.MustCompile(`\{\{([A-Z_][A-Z0-9_]*)\}\}`)
	return re.ReplaceAllStringFunc(s, func(match string) string {
		key := re.FindStringSubmatch(match)[1]
		if val := os.Getenv(key); val != "" {
			return val
		}
		return match
	})
}

// evaluateCondition évalue une condition simple
// Supporte : "var == value", "var != value", "var contains value"
func evaluateCondition(condition string, vars map[string]string) bool {
	condition = strings.TrimSpace(condition)
	condition = interpolate(condition, vars)

	if strings.Contains(condition, " contains ") {
		parts := strings.SplitN(condition, " contains ", 2)
		if len(parts) == 2 {
			return strings.Contains(strings.ToLower(parts[0]), strings.ToLower(strings.TrimSpace(parts[1])))
		}
	}
	if strings.Contains(condition, " == ") {
		parts := strings.SplitN(condition, " == ", 2)
		if len(parts) == 2 {
			return strings.TrimSpace(parts[0]) == strings.TrimSpace(parts[1])
		}
	}
	if strings.Contains(condition, " != ") {
		parts := strings.SplitN(condition, " != ", 2)
		if len(parts) == 2 {
			return strings.TrimSpace(parts[0]) != strings.TrimSpace(parts[1])
		}
	}
	// Condition simple : non-vide
	return condition != "" && condition != "false" && condition != "0"
}

func runWithTimeout(cmd *exec.Cmd, timeout time.Duration) error {
	if err := cmd.Start(); err != nil {
		return err
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		cmd.Process.Kill()
		return fmt.Errorf("timeout after %v", timeout)
	}
}

func splitArgs(s string) []string {
	// Split simple respectant les guillemets
	var args []string
	sc := bufio.NewScanner(strings.NewReader(s))
	sc.Split(bufio.ScanWords)
	for sc.Scan() {
		args = append(args, sc.Text())
	}
	return args
}

func isWindows() bool {
	return os.PathSeparator == '\\'
}

func formatVarsPreview(vars map[string]string) string {
	var parts []string
	for k, v := range vars {
		if len(v) > 20 {
			v = v[:20] + "..."
		}
		parts = append(parts, k+"="+v)
	}
	if len(parts) > 4 {
		return strings.Join(parts[:4], ", ") + fmt.Sprintf(" (+%d)", len(parts)-4)
	}
	return strings.Join(parts, ", ")
}

func printRunSummary(result *RunResult) {
	ok, fail, skip := 0, 0, 0
	for _, sr := range result.Steps {
		if sr.Skipped {
			skip++
		} else if sr.Success {
			ok++
		} else {
			fail++
		}
	}

	fmt.Printf("\n[playbook] %s — done in %v\n",
		result.PlaybookID, result.Duration.Round(time.Second))
	fmt.Printf("           ✓ %d  ✗ %d  ⊘ %d\n", ok, fail, skip)

	if fail > 0 {
		fmt.Println("           Failed steps:")
		for _, sr := range result.Steps {
			if !sr.Success && !sr.Skipped {
				fmt.Printf("           - %s: %s\n", sr.Name, sr.Error)
			}
		}
	}
}
