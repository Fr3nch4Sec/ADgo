// pkg/common/credentials.go
package common

import (
	"adgo/pkg/configuration"
)

// Credentials représente les informations d'identification.
type Credentials struct {
	LDAPServer  string
	BindDN      string
	Password    string
	BaseDN      string
	AuthMethod  string
	UseSSL      bool
	CertFile    string
	KeyFile     string
	SMBServer   string
	SMBUsername string
	SMBPassword string
	SMBDomain   string
}

// FromConfig convertit une configuration en Credentials.
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

// LoadFromConfigFile charge les credentials depuis un fichier de configuration.
func LoadFromConfigFile(filename string) (*Credentials, error) {
	config, err := configuration.LoadConfigWithEnv(filename)
	if err != nil {
		return nil, WrapError("failed to load config file", err)
	}
	return FromConfig(config), nil
}
