// pkg/winrm/winrm.go
package winrm

import (
	"bytes"
	"fmt"
	"os/exec"
)

// RunCommand exécute une commande via WinRM en utilisant une approche locale.
func RunCommand(host, username, password, command string) (string, error) {
	// Utiliser une commande locale pour simuler WinRM
	cmd := exec.Command("powershell", "-Command", fmt.Sprintf(
		"$session = New-PSSession -ComputerName %s -Credential (New-Object System.Management.Automation.PSCredential('%s', (ConvertTo-SecureString '%s' -AsPlainText -Force))); Invoke-Command -Session $session -ScriptBlock { %s }",
		host, username, password, command))

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("failed to run command: %v, stderr: %s", err, stderr.String())
	}

	return out.String(), nil
}
