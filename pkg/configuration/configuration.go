// pkg/configuration/configuration.go
package configuration

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config représente la configuration de connexion.
type Config struct {
	LDAPServer  string `yaml:"ldap_server"`
	BindDN      string `yaml:"bind_dn"`
	Password    string `yaml:"password"`
	BaseDN      string `yaml:"base_dn"`
	AuthMethod  string `yaml:"auth_method"`
	UseSSL      bool   `yaml:"use_ssl"`
	CertFile    string `yaml:"cert_file"`
	KeyFile     string `yaml:"key_file"`
	SMBServer   string `yaml:"smb_server"`
	SMBUsername string `yaml:"smb_username"`
	SMBPassword string `yaml:"smb_password"`
	SMBDomain   string `yaml:"smb_domain"`
}

// LoadConfig charge la configuration depuis un fichier YAML.
func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

// LoadConfigWithEnv charge la configuration depuis un fichier YAML et surcharge avec les variables d'environnement.
func LoadConfigWithEnv(filename string) (*Config, error) {
	config, err := LoadConfig(filename)
	if err != nil {
		return nil, err
	}

	// Surcharge avec les variables d'environnement
	if val := os.Getenv("ADGO_LDAP_SERVER"); val != "" {
		config.LDAPServer = val
	}
	if val := os.Getenv("ADGO_PASSWORD"); val != "" {
		config.Password = val
	}
	// ... (fais de même pour les autres champs)

	return config, nil
}
