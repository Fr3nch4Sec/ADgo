// pkg/ntlm/relay/types.go
package relay

type ADCSConfig struct {
	ADCSURL  string `yaml:"adcs_url"`
	Template string `yaml:"template"`
}
