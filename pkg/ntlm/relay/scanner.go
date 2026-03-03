// pkg/ntlm/relay/types.go
package relay

import (
	"fmt"
	"net/http"
)

// ScanADCS vérifie si le serveur AD CS est accessible
func ScanADCS(cfg ADCSConfig) error {
	resp, err := http.Get(cfg.ADCSURL)
	if err != nil {
		return fmt.Errorf("impossible de joindre %s : %v", cfg.ADCSURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("le serveur AD CS a retourné un code %d", resp.StatusCode)
	}

	fmt.Println("[+] Serveur AD CS détecté et accessible")
	return nil
}
