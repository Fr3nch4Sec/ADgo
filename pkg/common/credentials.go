package common

import (
	"fmt"
	"strings"

	"adgo/pkg/configuration"
)

// Flags globaux
var (
	Username   string
	Password   string
	Domain     string
	ConfigFile string
	NTLMHash   string
	Quiet      bool
	NoBanner   bool
	Debug      bool
)

// Credentials représente les informations d'identification
type Credentials struct {
	LDAPServer  string
	BindDN      string
	Password    string
	NTLMHash    string
	BaseDN      string
	AuthMethod  string // "password" ou "ntlm"
	UseSSL      bool
	CertFile    string
	KeyFile     string
	SMBServer   string
	SMBUsername string
	SMBPassword string
	SMBDomain   string
}

// FromConfig convertit une configuration en Credentials
func FromConfig(config *configuration.Config) *Credentials {
	return &Credentials{
		LDAPServer:  config.LDAPServer,
		BindDN:      config.BindDN,
		Password:    config.Password,
		BaseDN:      config.BaseDN,
		AuthMethod:  config.AuthMethod,
		UseSSL:      config.UseSSL,
		CertFile:    config.CertFile,
		KeyFile:     config.KeyFile,
		SMBServer:   config.SMBServer,
		SMBUsername: config.SMBUsername,
		SMBPassword: config.SMBPassword,
		SMBDomain:   config.SMBDomain,
	}
}

// LoadCredentials : priorité flags > config + auto-découverte DC
func LoadCredentials() (*Credentials, error) {
	creds := &Credentials{}

	// 1. Flags globaux (priorité maximale)
	if Username != "" {
		creds.BindDN = Username
		if Domain != "" && !strings.Contains(Username, "@") && !strings.Contains(Username, "\\") {
			creds.BindDN = Username + "@" + Domain
		}
		creds.SMBDomain = Domain
		creds.SMBUsername = Username

		if NTLMHash != "" {
			creds.NTLMHash = NTLMHash
			creds.Password = ""
			creds.AuthMethod = "ntlm"
			creds.SMBPassword = NTLMHash
		} else {
			creds.Password = Password
			creds.SMBPassword = Password
			creds.AuthMethod = "password"
		}

		// Auto-découverte du DC si Domain fourni et pas de LDAPServer manuel
		if Domain != "" && creds.LDAPServer == "" {
			dcIP, err := DiscoverDC(Domain)
			if err != nil {
				return nil, fmt.Errorf("failed to auto-discover DC for domain %s: %w", Domain, err)
			}
			creds.LDAPServer = dcIP + ":389" // change en ":636" si UseSSL par défaut
			PrintDebug(fmt.Sprintf("Auto-discovered DC: %s", creds.LDAPServer), Debug)
		}
	}

	// 2. Fallback sur config si flags insuffisants
	if creds.BindDN == "" || (creds.Password == "" && creds.NTLMHash == "") {
		filename := "configs/config.yaml"
		if ConfigFile != "" {
			filename = ConfigFile
		}

		cfg, err := configuration.LoadConfigWithEnv(filename)
		if err != nil {
			return nil, fmt.Errorf("no credentials provided: use -u USER -p PASS [--hash NTLMHASH] [-d DOMAIN] or --config")
		}
		creds = FromConfig(cfg)

		// Auto-découverte depuis config si domaine présent mais pas LDAPServer
		if creds.LDAPServer == "" && creds.SMBDomain != "" {
			dcIP, err := DiscoverDC(creds.SMBDomain)
			if err == nil {
				creds.LDAPServer = dcIP + ":389"
				PrintDebug(fmt.Sprintf("Auto-discovered DC from config domain: %s", creds.LDAPServer), Debug)
			}
		}
	}

	// 3. Vérification finale
	if creds.BindDN == "" || (creds.Password == "" && creds.NTLMHash == "") {
		return nil, fmt.Errorf("missing credentials: use -u USER -p PASS [--hash NTLMHASH] [-d DOMAIN] or --config")
	}

	if creds.LDAPServer == "" {
		return nil, fmt.Errorf("no LDAP server found. Provide --dc-ip or use -d with auto-discovery")
	}

	return creds, nil
}
