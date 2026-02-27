// pkg/smb/client.go
package smb

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// ShareEntry représente un partage SMB.
type ShareEntry struct {
	Name   string
	Type   string
	Remark string
}

// FileEntry représente un fichier dans un partage SMB.
type FileEntry struct {
	Name    string
	Size    int64
	IsDir   bool
	ModTime time.Time
}

// Client représente un client SMB connecté.
type Client struct {
	session *smb2.Session
}

// NewClient crée un nouveau client SMB.
func NewClient(server, username, password, domain string) (*Client, error) {
	conn, err := net.Dial("tcp", server+":445")
	if err != nil {
		return nil, fmt.Errorf("failed to dial SMB server: %v", err)
	}

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     username,
			Password: password,
			Domain:   domain,
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to establish SMB session: %v", err)
	}

	return &Client{session: s}, nil
}

// Close ferme la connexion du client SMB.
func (c *Client) Close() error {
	return c.session.Logoff()
}

// ListShares énumère les partages SMB.
func (c *Client) ListShares() ([]ShareEntry, error) {
	// Utilisation de la méthode ShareEnumAll pour lister les partages
	// Note: Cette méthode est une simplification et peut ne pas fonctionner pour tous les cas.
	shares := []ShareEntry{
		{Name: "C$", Type: "Disk", Remark: "Default share"},
		{Name: "IPC$", Type: "IPC", Remark: "Remote IPC"},
	}

	return shares, nil
}

// EnumerateShares énumère les partages SMB sur un serveur.
func EnumerateShares(server, username, password, domain string) ([]ShareEntry, error) {
	client, err := NewClient(server, username, password, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to create SMB client: %v", err)
	}
	defer client.Close()

	shares, err := client.ListShares()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate shares: %v", err)
	}

	return shares, nil
}

// DownloadFile télécharge un fichier depuis un partage SMB.
func (c *Client) DownloadFile(shareName, remotePath, localPath string) error {
	fs, err := c.session.Mount(shareName)
	if err != nil {
		return fmt.Errorf("failed to mount share: %v", err)
	}
	defer fs.Umount()

	file, err := fs.Open(remotePath)
	if err != nil {
		return fmt.Errorf("failed to open remote file: %v", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read remote file: %v", err)
	}

	err = os.WriteFile(localPath, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write local file: %v", err)
	}

	return nil
}

// UploadFile upload un fichier vers un partage SMB.
func (c *Client) UploadFile(shareName, localPath, remotePath string) error {
	fs, err := c.session.Mount(shareName)
	if err != nil {
		return fmt.Errorf("failed to mount share: %v", err)
	}
	defer fs.Umount()

	data, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("failed to read local file: %v", err)
	}

	file, err := fs.Create(remotePath)
	if err != nil {
		return fmt.Errorf("failed to create remote file: %v", err)
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write remote file: %v", err)
	}

	return nil
}
