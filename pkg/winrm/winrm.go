// pkg/winrm/winrm.go

package winrm

import (
	"bytes"
	"fmt"

	"github.com/masterzen/winrm"
)

// RunCommand exécute une commande via WinRM (pur Go, pas de PowerShell local)
// CORRECTION : remplace l'appel exec.Command("powershell", ...)
func RunCommand(host, username, password, command string) (string, error) {
	endpoint := winrm.NewEndpoint(
		host,
		5985,  // port WinRM HTTP (5986 pour HTTPS)
		false, // HTTPS
		false, // insecure
		nil, nil, nil,
		0, // timeout (0 = défaut)
	)

	client, err := winrm.NewClient(endpoint, username, password)
	if err != nil {
		return "", fmt.Errorf("failed to create WinRM client: %v", err)
	}

	var stdout, stderr bytes.Buffer
	exitCode, err := client.Run(command, &stdout, &stderr)
	if err != nil {
		return "", fmt.Errorf("WinRM command failed (exit %d): %v\nstderr: %s",
			exitCode, err, stderr.String())
	}

	if exitCode != 0 {
		return "", fmt.Errorf("command exited with code %d: %s", exitCode, stderr.String())
	}

	return stdout.String(), nil
}

// RunCommandHTTPS exécute une commande via WinRM sur HTTPS (port 5986)
func RunCommandHTTPS(host, username, password, command string) (string, error) {
	endpoint := winrm.NewEndpoint(host, 5986, true, true, nil, nil, nil, 0)
	client, err := winrm.NewClient(endpoint, username, password)
	if err != nil {
		return "", fmt.Errorf("WinRM HTTPS client failed: %v", err)
	}

	var stdout, stderr bytes.Buffer
	exitCode, err := client.Run(command, &stdout, &stderr)
	if err != nil || exitCode != 0 {
		return "", fmt.Errorf("WinRM HTTPS command failed (exit %d): %v", exitCode, err)
	}
	return stdout.String(), nil
}
