// pkg/wmi/wmi.go
package wmi

import (
	"bytes"
	"fmt"

	"github.com/masterzen/winrm"
)

// QueryWMI exécute une requête WQL via WinRM (pas de PowerShell local)
func QueryWMI(host, username, password, query string) (string, error) {
	endpoint := winrm.NewEndpoint(host, 5985, false, false, nil, nil, nil, 0)
	client, err := winrm.NewClient(endpoint, username, password)
	if err != nil {
		return "", fmt.Errorf("WinRM client failed: %v", err)
	}

	// Encapsuler la query WQL dans une commande PowerShell distante
	// (exécutée sur la CIBLE, pas en local — c'est l'approche correcte)
	psCmd := fmt.Sprintf(
		"Get-WmiObject -Query '%s' | Select-Object * | ConvertTo-Json -Depth 3",
		query,
	)

	var stdout, stderr bytes.Buffer
	exitCode, err := client.Run(psCmd, &stdout, &stderr)
	if err != nil || exitCode != 0 {
		return "", fmt.Errorf("WMI query failed (exit %d): %v\nstderr: %s",
			exitCode, err, stderr.String())
	}

	return stdout.String(), nil
}
