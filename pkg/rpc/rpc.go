// pkg/rpc/rpc.go
package rpc

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"net"
	"os/exec"
)

//go:embed scripts/*.ps1
var scriptFS embed.FS

// RPCInfo représente les informations RPC.
type RPCInfo struct {
	Service string
	Port    int
}

// RPCClient représente un client RPC.
type RPCClient struct {
	Host string
}

// NewRPCClient crée un nouveau client RPC.
func NewRPCClient(host string) *RPCClient {
	return &RPCClient{Host: host}
}

// ExecuteScript exécute un script embarqué.
func (r *RPCClient) ExecuteScript(scriptName string) (string, error) {
	scriptContent, err := fs.ReadFile(scriptFS, "scripts/"+scriptName)
	if err != nil {
		return "", fmt.Errorf("failed to read script: %v", err)
	}

	cmd := exec.Command("powershell", "-Command", "-")
	cmd.Stdin = bytes.NewReader(scriptContent)

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		return "", fmt.Errorf("failed to execute script: %v, stderr: %s", err, stderr.String())
	}

	return out.String(), nil
}

// EnumerateRPC énumère les services RPC.
func (r *RPCClient) EnumerateRPC() ([]RPCInfo, error) {
	conn, err := net.Dial("tcp", r.Host+":135")
	if err != nil {
		return nil, fmt.Errorf("failed to connect to RPC endpoint: %v", err)
	}
	defer conn.Close()

	services := []RPCInfo{
		{Service: "Endpoint Mapper", Port: 135},
	}

	return services, nil
}

// EnumerateRPC est une fonction utilitaire pour énumérer les services RPC.
func EnumerateRPC(host string) ([]RPCInfo, error) {
	client := NewRPCClient(host)
	return client.EnumerateRPC()
}
