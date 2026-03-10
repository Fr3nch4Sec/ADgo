// pkg/configuration/configuration.go

package configuration

import (
	"os"
	"strconv"

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
	NTLM        struct {
		Relay struct {
			ListenIP   string `yaml:"listen_ip"`
			ListenPort int    `yaml:"listen_port"`
		} `yaml:"relay"`
		ADCS struct {
			ADCSURL  string `yaml:"adcs_url"`
			Template string `yaml:"template"`
		} `yaml:"adcs"`
	} `yaml:"ntlm"`
}

// LoadConfig charge la configuration depuis un fichier YAML.
func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

// Load charge depuis le fichier par défaut.
func Load() (*Config, error) {
	return LoadConfig("configs/config.yaml")
}

// LoadConfigWithEnv charge le YAML et surcharge avec les variables d'environnement.
func LoadConfigWithEnv(filename string) (*Config, error) {
	config, err := LoadConfig(filename)
	if err != nil {
		// Si le fichier n'existe pas, partir d'une config vide
		config = &Config{}
	}

	type envMapping struct {
		envVar string
		field  *string
	}

	stringMappings := []envMapping{
		{"ADGO_LDAP_SERVER", &config.LDAPServer},
		{"ADGO_BIND_DN", &config.BindDN},
		{"ADGO_PASSWORD", &config.Password},
		{"ADGO_BASE_DN", &config.BaseDN},
		{"ADGO_AUTH_METHOD", &config.AuthMethod},
		{"ADGO_CERT_FILE", &config.CertFile},
		{"ADGO_KEY_FILE", &config.KeyFile},
		{"ADGO_SMB_SERVER", &config.SMBServer},
		{"ADGO_SMB_USERNAME", &config.SMBUsername},
		{"ADGO_SMB_PASSWORD", &config.SMBPassword},
		{"ADGO_SMB_DOMAIN", &config.SMBDomain},
		{"ADGO_NTLM_ADCS_URL", &config.NTLM.ADCS.ADCSURL},
		{"ADGO_NTLM_ADCS_TEMPLATE", &config.NTLM.ADCS.Template},
		{"ADGO_NTLM_RELAY_IP", &config.NTLM.Relay.ListenIP},
	}

	for _, m := range stringMappings {
		if val := os.Getenv(m.envVar); val != "" {
			*m.field = val
		}
	}

	if val := os.Getenv("ADGO_USE_SSL"); val == "true" || val == "1" {
		config.UseSSL = true
	}

	if val := os.Getenv("ADGO_NTLM_RELAY_PORT"); val != "" {
		if port, err := strconv.Atoi(val); err == nil {
			config.NTLM.Relay.ListenPort = port
		}
	}

	return config, nil
}
