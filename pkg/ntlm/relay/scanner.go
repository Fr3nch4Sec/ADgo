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
		return fmt.Errorf("Unable to reach %s : %v", cfg.ADCSURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("The AD CS server returned a %d code", resp.StatusCode)
	}

	fmt.Println("[+] AD CS server detected and accessible")
	return nil
}
