// cmd/adgo/commands/smb.go
package commands

import (
	"fmt"

	"adgo/pkg/common"
	"adgo/pkg/smb"

	"github.com/spf13/cobra"
)

// SMBSharesCmd énumère les partages SMB.
var SMBSharesCmd = &cobra.Command{
	Use:   "shares",
	Short: "Enumerate SMB shares",
	RunE: func(cmd *cobra.Command, args []string) error {
		server, _ := cmd.Flags().GetString("server")
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		domain, _ := cmd.Flags().GetString("domain")

		shares, err := smb.EnumerateShares(server, username, password, domain)
		if err != nil {
			common.PrintError(fmt.Errorf("failed to enumerate shares: %v", err))
			return err
		}

		common.PrintOutput(shares, false, false, false)
		common.PrintSuccess("SMB shares enumerated successfully")
		return nil
	},
}

// SMBDownloadCmd télécharge un fichier depuis un partage SMB.
var SMBDownloadCmd = &cobra.Command{
	Use:   "download",
	Short: "Download a file from an SMB share",
	RunE: func(cmd *cobra.Command, args []string) error {
		server, _ := cmd.Flags().GetString("server")
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		domain, _ := cmd.Flags().GetString("domain")
		share, _ := cmd.Flags().GetString("share")
		remotePath, _ := cmd.Flags().GetString("remote-path")
		localPath, _ := cmd.Flags().GetString("local-path")

		client, err := smb.NewClient(server, username, password, domain)
		if err != nil {
			common.PrintError(fmt.Errorf("failed to create SMB client: %v", err))
			return err
		}
		defer client.Close()

		err = client.DownloadFile(share, remotePath, localPath)
		if err != nil {
			common.PrintError(fmt.Errorf("failed to download file: %v", err))
			return err
		}

		common.PrintSuccess(fmt.Sprintf("File downloaded successfully from %s to %s", remotePath, localPath))
		return nil
	},
}

// SMBUploadCmd uploade un fichier vers un partage SMB.
var SMBUploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Upload a file to an SMB share",
	RunE: func(cmd *cobra.Command, args []string) error {
		server, _ := cmd.Flags().GetString("server")
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		domain, _ := cmd.Flags().GetString("domain")
		share, _ := cmd.Flags().GetString("share")
		localPath, _ := cmd.Flags().GetString("local-path")
		remotePath, _ := cmd.Flags().GetString("remote-path")

		client, err := smb.NewClient(server, username, password, domain)
		if err != nil {
			common.PrintError(fmt.Errorf("failed to create SMB client: %v", err))
			return err
		}
		defer client.Close()

		err = client.UploadFile(share, localPath, remotePath)
		if err != nil {
			common.PrintError(fmt.Errorf("failed to upload file: %v", err))
			return err
		}

		common.PrintSuccess(fmt.Sprintf("File uploaded successfully from %s to %s", localPath, remotePath))
		return nil
	},
}

func init() {
	SMBSharesCmd.Flags().String("server", "", "SMB server address (e.g., 192.168.1.10)")
	SMBSharesCmd.Flags().String("username", "", "Username for SMB server")
	SMBSharesCmd.Flags().String("password", "", "Password for SMB server")
	SMBSharesCmd.Flags().String("domain", "", "Domain for SMB server")

	SMBDownloadCmd.Flags().String("server", "", "SMB server address (e.g., 192.168.1.10)")
	SMBDownloadCmd.Flags().String("username", "", "Username for SMB server")
	SMBDownloadCmd.Flags().String("password", "", "Password for SMB server")
	SMBDownloadCmd.Flags().String("domain", "", "Domain for SMB server")
	SMBDownloadCmd.Flags().String("share", "", "SMB share name")
	SMBDownloadCmd.Flags().String("remote-path", "", "Remote file path")
	SMBDownloadCmd.Flags().String("local-path", "", "Local file path")

	SMBUploadCmd.Flags().String("server", "", "SMB server address (e.g., 192.168.1.10)")
	SMBUploadCmd.Flags().String("username", "", "Username for SMB server")
	SMBUploadCmd.Flags().String("password", "", "Password for SMB server")
	SMBUploadCmd.Flags().String("domain", "", "Domain for SMB server")
	SMBUploadCmd.Flags().String("share", "", "SMB share name")
	SMBUploadCmd.Flags().String("local-path", "", "Local file path")
	SMBUploadCmd.Flags().String("remote-path", "", "Remote file path")

	SMBCmd.AddCommand(SMBSharesCmd)
	SMBCmd.AddCommand(SMBDownloadCmd)
	SMBCmd.AddCommand(SMBUploadCmd)
}

// SMBCmd est la commande racine pour les opérations SMB.
var SMBCmd = &cobra.Command{
	Use:   "smb",
	Short: "SMB operations",
}
