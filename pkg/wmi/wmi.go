// pkg/wmi/wmi.go
package wmi

import (
	"bytes"
	"fmt"
	"os/exec"
)

// QueryWMI interroge des informations WMI en utilisant PowerShell.
func QueryWMI(host, username, password, query string) (string, error) {
	// Utiliser une commande locale pour simuler WMI
	cmd := exec.Command("powershell", "-Command", fmt.Sprintf(
		"$session = New-PSSession -ComputerName %s -Credential (New-Object System.Management.Automation.PSCredential('%s', (ConvertTo-SecureString '%s' -AsPlainText -Force))); Invoke-Command -Session $session -ScriptBlock { Get-WmiObject -Query '%s' | ConvertTo-Json }",
		host, username, password, query))

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("failed to run WMI query: %v, stderr: %s", err, stderr.String())
	}

	return out.String(), nil
}
