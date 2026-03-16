// pkg/configuration/userconfig.go
//
// Configuration persistante utilisateur — ~/.adgo/config.yaml
//
// Permet de sauvegarder les paramètres fréquents pour éviter de les
// retaper à chaque commande :
//
//   adgo config set dc-ip 192.168.1.10
//   adgo config set domain lab.local
//   adgo config set username admin
//   adgo config set workers 100
//
//   adgo config show
//   adgo config clear
//
// Priorité des valeurs (du plus fort au plus faible) :
//   1. Flag CLI    (--dc-ip 192.168.1.10)
//   2. Var d'env   (ADGO_DC_IP=192.168.1.10)
//   3. Config user (~/.adgo/config.yaml)
//   4. Valeur par défaut

package configuration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// UserConfig configuration persistante de l'utilisateur
type UserConfig struct {
	// Connexion par défaut
	DCIP     string `yaml:"dc_ip,omitempty"`
	Domain   string `yaml:"domain,omitempty"`
	Username string `yaml:"username,omitempty"`

	// Options par défaut
	Workers int    `yaml:"workers,omitempty"`
	Timeout int    `yaml:"timeout,omitempty"`
	LogFile string `yaml:"log_file,omitempty"`
	Output  string `yaml:"output_dir,omitempty"`

	// Playbooks
	PlaybooksDir string `yaml:"playbooks_dir,omitempty"`
	VarsFile     string `yaml:"vars_file,omitempty"`
}

// userConfigPath retourne le chemin du fichier de config utilisateur
func userConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".adgo", "config.yaml")
}

// LoadUserConfig charge la config utilisateur.
// Retourne une config vide si le fichier n'existe pas — pas d'erreur.
func LoadUserConfig() *UserConfig {
	cfg := &UserConfig{
		Workers: 50,
		Timeout: 3,
	}

	data, err := os.ReadFile(userConfigPath())
	if err != nil {
		return cfg // fichier absent → config par défaut
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return cfg // YAML invalide → config par défaut silencieuse
	}

	return cfg
}

// SaveUserConfig sauvegarde la config utilisateur
func SaveUserConfig(cfg *UserConfig) error {
	path := userConfigPath()

	// Créer le répertoire ~/.adgo/ si absent
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("cannot create config dir: %v", err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("cannot serialize config: %v", err)
	}

	// Fichier lisible uniquement par l'utilisateur (contient potentiellement des creds)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("cannot write config: %v", err)
	}

	return nil
}

// SetField définit une clé dans la config utilisateur
func SetField(key, value string) error {
	cfg := LoadUserConfig()

	switch strings.ToLower(key) {
	case "dc-ip", "dc_ip", "dcip":
		cfg.DCIP = value
	case "domain", "d":
		cfg.Domain = value
	case "username", "user", "u":
		cfg.Username = value
	case "workers":
		var n int
		fmt.Sscanf(value, "%d", &n)
		if n <= 0 {
			return fmt.Errorf("workers must be a positive integer")
		}
		cfg.Workers = n
	case "timeout":
		var n int
		fmt.Sscanf(value, "%d", &n)
		if n <= 0 {
			return fmt.Errorf("timeout must be a positive integer")
		}
		cfg.Timeout = n
	case "log-file", "log_file":
		cfg.LogFile = value
	case "output", "output-dir", "output_dir":
		cfg.Output = value
	case "playbooks-dir", "playbooks_dir":
		cfg.PlaybooksDir = value
	case "vars-file", "vars_file":
		cfg.VarsFile = value
	default:
		return fmt.Errorf("unknown config key %q\n\nValid keys: dc-ip, domain, username, workers, timeout, log-file, output, playbooks-dir, vars-file", key)
	}

	return SaveUserConfig(cfg)
}

// UnsetField supprime une clé de la config utilisateur
func UnsetField(key string) error {
	return SetField(key, "")
}

// ClearUserConfig supprime toute la config utilisateur
func ClearUserConfig() error {
	path := userConfigPath()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cannot delete config: %v", err)
	}
	return nil
}

// ConfigPath retourne le chemin affiché à l'utilisateur
func ConfigPath() string {
	return userConfigPath()
}

// FormatUserConfig retourne la config sous forme de lignes KEY=VALUE
func FormatUserConfig(cfg *UserConfig) [][]string {
	rows := [][]string{}

	add := func(k, v string) {
		if v != "" {
			rows = append(rows, []string{k, v})
		}
	}
	addInt := func(k string, v int) {
		if v > 0 {
			rows = append(rows, []string{k, fmt.Sprintf("%d", v)})
		}
	}

	add("dc-ip", cfg.DCIP)
	add("domain", cfg.Domain)
	add("username", cfg.Username)
	addInt("workers", cfg.Workers)
	addInt("timeout", cfg.Timeout)
	add("log-file", cfg.LogFile)
	add("output", cfg.Output)
	add("playbooks-dir", cfg.PlaybooksDir)
	add("vars-file", cfg.VarsFile)

	return rows
}
