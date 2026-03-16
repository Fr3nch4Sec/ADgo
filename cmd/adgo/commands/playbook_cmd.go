// cmd/adgo/commands/playbook_cmd.go
//
// adgo playbook run <file>   — exécuter un playbook
// adgo playbook list [dir]   — lister les playbooks disponibles
// adgo playbook validate <f> — valider la syntaxe d'un playbook
// adgo playbook new <name>   — générer un template vide

package commands

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"regexp"

	"adgo/pkg/common"
	"adgo/pkg/playbook"

	"github.com/spf13/cobra"
)

var PlaybookCmd = &cobra.Command{
	Use:   "playbook",
	Short: "Run YAML playbooks — reusable AD attack/recon sequences",
	Long: `Execute YAML playbooks — Nuclei-style templates for AD operations.

A playbook defines a sequence of adgo commands, shell scripts, or Python
scripts to run against a specific AD environment. Variables are interpolated
at runtime, making playbooks reusable across different labs and engagements.

Examples:
  # Run a playbook with inline variables
  adgo playbook run full-recon.yaml -v DC_IP=192.168.1.10 DOMAIN=lab.local USERNAME=admin PASSWORD=pass

  # Run with a variables file
  adgo playbook run full-recon.yaml --vars-file lab.env

  # Dry-run (print commands without executing)
  adgo playbook run full-recon.yaml --vars-file lab.env --dry-run

  # List available playbooks
  adgo playbook list ./playbooks/

  # Generate a new playbook template
  adgo playbook new my-attack`,
}

// ============================================================
// adgo playbook run
// ============================================================

var playbookRunCmd = &cobra.Command{
	Use:   "run <playbook.yaml>",
	Short: "Execute a playbook",
	Args:  cobra.ExactArgs(1),
	Example: `  adgo playbook run full-recon.yaml -v DC_IP=192.168.1.10 DOMAIN=lab.local USERNAME=admin PASSWORD=pass
  adgo playbook run lateral.yaml --vars-file lab.env --dry-run
  adgo playbook run kerberoast.yaml --vars-file lab.env --verbose`,
	RunE: func(cmd *cobra.Command, args []string) error {
		pbPath := args[0]
		varsFlag, _ := cmd.Flags().GetStringArray("var")
		varsFile, _ := cmd.Flags().GetString("vars-file")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		verbose, _ := cmd.Flags().GetBool("verbose")

		// Charger le playbook
		pb, err := playbook.Load(pbPath)
		if err != nil {
			return fmt.Errorf("cannot load playbook: %v", err)
		}

		// Construire la map de variables
		vars := make(map[string]string)

		// 1. Variables depuis le fichier --vars-file
		if varsFile != "" {
			fileVars, err := loadVarsFile(varsFile)
			if err != nil {
				return fmt.Errorf("cannot load vars file %s: %v", varsFile, err)
			}
			for k, v := range fileVars {
				vars[k] = v
			}
		}

		// 2. Variables depuis -v KEY=VALUE (override le fichier)
		for _, v := range varsFlag {
			parts := strings.SplitN(v, "=", 2)
			if len(parts) == 2 {
				vars[parts[0]] = parts[1]
			} else {
				return fmt.Errorf("invalid variable format %q (expected KEY=VALUE)", v)
			}
		}

		// 3. Variables globales adgo (--username, --password, --domain)
		if common.Username != "" {
			vars["USERNAME"] = common.Username
			vars["username"] = common.Username
		}
		if common.Password != "" {
			vars["PASSWORD"] = common.Password
			vars["password"] = common.Password
		}
		if common.Domain != "" {
			vars["DOMAIN"] = common.Domain
			vars["domain"] = common.Domain
		}
		if common.NTLMHash != "" {
			vars["HASH"] = common.NTLMHash
			vars["hash"] = common.NTLMHash
		}

		// Créer le répertoire de sortie si spécifié dans les vars
		if outDir, ok := vars["output_dir"]; ok && outDir != "" && !dryRun {
			os.MkdirAll(outDir, 0755)
		}

		// Exécuter
		runner := playbook.NewRunner("", vars, verbose, dryRun)
		result, err := runner.Run(pb)
		if err != nil {
			return fmt.Errorf("playbook execution failed: %v", err)
		}

		if !result.Success {
			return fmt.Errorf("playbook %q finished with failures", pb.ID)
		}

		return nil
	},
}

// ============================================================
// adgo playbook list
// ============================================================

var playbookListCmd = &cobra.Command{
	Use:   "list [directory]",
	Short: "List available playbooks",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dir := "./playbooks"
		if len(args) > 0 {
			dir = args[0]
		}

		if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
			common.PrintWarning(fmt.Sprintf("Playbook directory %q not found.", dir))
			fmt.Println()
			fmt.Println("Create it and add your YAML playbooks:")
			fmt.Printf("  mkdir %s\n", dir)
			fmt.Printf("  copy full-recon.yml %s\\\n", dir)
			fmt.Println()
			fmt.Println("Or generate a new one:")
			fmt.Printf("  adgo playbook new my-attack\n")
			return nil
		}

		// Debug: lister les fichiers trouvés dans le dossier
		if entries, dirErr := os.ReadDir(dir); dirErr == nil {
			if len(entries) == 0 {
				common.PrintWarning(fmt.Sprintf("Directory %q exists but is empty.", dir))
				fmt.Println("  → Copy your .yml or .yaml files into this directory.")
				return nil
			}
			if common.Debug {
				fmt.Printf("[debug] Files in %s:\n", dir)
				for _, e := range entries {
					fmt.Printf("  %s (dir=%v)\n", e.Name(), e.IsDir())
				}
			}
		}

		playbooks, err := playbook.LoadDir(dir)
		if err != nil {
			return fmt.Errorf("cannot list playbooks in %s: %v", dir, err)
		}

		if len(playbooks) == 0 {
			common.PrintWarning(fmt.Sprintf("No playbooks found in %s", dir))
			fmt.Println()
			fmt.Println("Create a playbook or use the built-in templates:")
			fmt.Println("  adgo playbook new my-playbook")
			return nil
		}

		common.PrintSuccess(fmt.Sprintf("Found %d playbook(s) in %s", len(playbooks), dir))
		fmt.Println()

		rows := make([][]string, 0, len(playbooks))
		for _, pb := range playbooks {
			tags := strings.Join(pb.Tags, ", ")
			steps := fmt.Sprintf("%d", len(pb.Steps))
			rows = append(rows, []string{pb.ID, pb.Name, steps, tags, pb.Author})
		}
		common.PrintTable([]string{"ID", "NAME", "STEPS", "TAGS", "AUTHOR"}, rows)

		fmt.Println()
		fmt.Println("Run a playbook:")
		fmt.Printf("  adgo playbook run %s/<id>.yml --vars-file lab.env\n", dir)
		return nil
	},
}

// ============================================================
// adgo playbook validate
// ============================================================

var playbookValidateCmd = &cobra.Command{
	Use:   "validate <playbook.yaml>",
	Short: "Validate a playbook YAML file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		pb, err := playbook.Load(args[0])
		if err != nil {
			common.PrintError(fmt.Errorf("INVALID: %v", err))
			return err
		}

		common.PrintSuccess(fmt.Sprintf("Valid playbook: %s", pb.Name))
		common.PrintFound("ID", pb.ID)
		common.PrintFound("Steps", len(pb.Steps))
		common.PrintFound("Tags", strings.Join(pb.Tags, ", "))

		// Vérifications supplémentaires
		warnings := validatePlaybook(pb)
		if len(warnings) > 0 {
			fmt.Println()
			for _, w := range warnings {
				common.PrintWarning(w)
			}
		}

		// Lister les variables requises
		vars := extractRequiredVars(pb)
		if len(vars) > 0 {
			fmt.Println()
			fmt.Println("Required variables:")
			for _, v := range vars {
				fmt.Printf("  {{%s}}\n", v)
			}
		}

		return nil
	},
}

// ============================================================
// adgo playbook new
// ============================================================

var playbookNewCmd = &cobra.Command{
	Use:   "new <name>",
	Short: "Generate a new playbook template",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		filename := strings.ToLower(strings.ReplaceAll(name, " ", "-")) + ".yaml"

		if _, err := os.Stat(filename); err == nil {
			return fmt.Errorf("file %s already exists", filename)
		}

		template := generatePlaybookTemplate(name)
		if err := os.WriteFile(filename, []byte(template), 0644); err != nil {
			return fmt.Errorf("cannot write %s: %v", filename, err)
		}

		common.PrintSuccess(fmt.Sprintf("Playbook template created: %s", filename))
		fmt.Println()
		fmt.Println("Edit the file to add your steps, then run:")
		fmt.Printf("  adgo playbook validate %s\n", filename)
		fmt.Printf("  adgo playbook run %s -v DC_IP=... DOMAIN=... USERNAME=... PASSWORD=...\n", filename)
		return nil
	},
}

// ============================================================
// Helpers
// ============================================================

// loadVarsFile charge un fichier de variables KEY=VALUE (format .env)
func loadVarsFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	vars := make(map[string]string)
	sc := bufio.NewScanner(f)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("line %d: invalid format %q (expected KEY=VALUE)", lineNum, line)
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		// Supprimer les guillemets optionnels
		val = strings.Trim(val, `"'`)
		if val != "" {
			vars[key] = val
			// Ajouter aussi en lowercase pour la compatibilité
			vars[strings.ToLower(key)] = val
		}
	}
	return vars, sc.Err()
}

// validatePlaybook vérifie la cohérence d'un playbook
func validatePlaybook(pb *playbook.Playbook) []string {
	var warnings []string

	if pb.Name == "" {
		warnings = append(warnings, "playbook has no 'name'")
	}
	if len(pb.Steps) == 0 {
		warnings = append(warnings, "playbook has no steps")
	}

	stepIDs := make(map[string]bool)
	for _, s := range pb.Steps {
		if s.ID == "" {
			warnings = append(warnings, fmt.Sprintf("step %q has no 'id'", s.Name))
		} else if stepIDs[s.ID] {
			warnings = append(warnings, fmt.Sprintf("duplicate step id: %q", s.ID))
		}
		stepIDs[s.ID] = true

		if s.Command == "" && s.Type != "condition" {
			warnings = append(warnings, fmt.Sprintf("step %q has no 'command'", s.ID))
		}
	}

	return warnings
}

// extractRequiredVars liste les variables {{VAR}} utilisées dans le playbook
func extractRequiredVars(pb *playbook.Playbook) []string {
	seen := make(map[string]bool)
	var vars []string

	addVars := func(s string) {
		// Trouver tous les {{VAR}} en majuscules (= variables requises, pas les vars internes)
		reVar := regexp.MustCompile(`\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}`)
		for _, match := range reVar.FindAllStringSubmatch(s, -1) {
			if len(match) >= 2 {
				v := match[1]
				// Les vars en MAJUSCULES sont des variables requises par l'utilisateur
				if strings.ToUpper(v) == v && !seen[v] {
					seen[v] = true
					vars = append(vars, v)
				}
			}
		}
	}

	for _, s := range pb.Steps {
		addVars(s.Command)
		for _, v := range s.Args {
			addVars(v)
		}
		addVars(s.Condition)
	}
	for _, v := range pb.Env {
		addVars(v)
	}
	return vars
}

// generatePlaybookTemplate génère un template YAML vide
func generatePlaybookTemplate(name string) string {
	id := strings.ToLower(strings.ReplaceAll(name, " ", "-"))
	return fmt.Sprintf(`# ADgo Playbook — %s
# Generated by: adgo playbook new

id: %s
name: %s
description: ""
author: ""
tags: []
version: "1.0"

# Variables d'environnement (utiliser {{VAR}} pour les valeurs dynamiques)
env:
  dc_ip: "{{DC_IP}}"
  domain: "{{DOMAIN}}"
  username: "{{USERNAME}}"
  password: "{{PASSWORD}}"

# Étapes du playbook
steps:
  - id: step1
    name: First step
    description: ""
    type: adgo           # adgo | shell | python | condition
    command: ldap users  # sous-commande adgo (ex: ldap users, scan, bloodhound)
    args:
      dc-ip: "{{dc_ip}}"
      username: "{{username}}"
      password: "{{password}}"
      domain: "{{domain}}"
    on_success: continue # continue (défaut) | stop | next:<step_id>
    on_failure: continue # stop (défaut) | continue | next:<step_id>

  - id: step2
    name: Shell command
    type: shell
    command: echo "Done for domain {{domain}}"
    on_failure: continue

  - id: step3
    name: Python script
    type: python
    command: ./scripts/my_script.py --dc {{dc_ip}}
    timeout: 60
    disabled: true  # Mettre false pour activer
    on_failure: continue
`, name, id, name)
}

func init() {
	// Flags pour playbook run
	playbookRunCmd.Flags().StringArrayP("var", "v", nil, "Variable KEY=VALUE (can be repeated)")
	playbookRunCmd.Flags().String("vars-file", "", "Load variables from a .env file")
	playbookRunCmd.Flags().Bool("dry-run", false, "Print commands without executing")
	playbookRunCmd.Flags().Bool("verbose", false, "Show step output")

	PlaybookCmd.AddCommand(playbookRunCmd)
	PlaybookCmd.AddCommand(playbookListCmd)
	PlaybookCmd.AddCommand(playbookValidateCmd)
	PlaybookCmd.AddCommand(playbookNewCmd)
}
