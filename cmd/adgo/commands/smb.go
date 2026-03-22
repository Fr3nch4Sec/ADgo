// cmd/adgo/commands/smb.go
package commands

import (
	"fmt"
	"strings"

	"adgo/pkg/common"
	"adgo/pkg/smb"

	"github.com/spf13/cobra"
)

// SMBSharesCmd énumère les partages SMB.
// Supporte : credentials, anonymous (-A), guest
var SMBSharesCmd = &cobra.Command{
	Use:   "shares <target>",
	Short: "Enumerate SMB shares (supports anonymous/null session)",
	Long: `Enumerate SMB shares on a target host.

Examples:
  # Avec credentials
  adgo smb shares 192.168.1.10 -u administrator -p Password123 -d LAB

  # Session anonyme (null session)
  adgo smb shares 192.168.1.10 -A

  # Compte guest
  adgo smb shares 192.168.1.10 -u guest -p '' -d WORKGROUP

  # Pass-the-Hash
  adgo smb shares 192.168.1.10 -u admin --hash aad3b435b51404ee... -d LAB`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		server := args[0]

		anonymous, _ := cmd.Flags().GetBool("anonymous")

		var username, password, domain string

		if anonymous {
			username = ""
			password = ""
			domain = ""
			common.PrintInfo(fmt.Sprintf("SMB → %s (null/anonymous session)", server))
		} else {
			username = common.Username
			password = common.Password
			domain = common.Domain

			if username == "" {
				username, _ = cmd.Flags().GetString("username")
			}
			if password == "" {
				password, _ = cmd.Flags().GetString("password")
			}
			if domain == "" {
				domain, _ = cmd.Flags().GetString("domain")
			}

			if username == "" && password == "" {
				common.PrintInfo(fmt.Sprintf("SMB → %s (no credentials, trying null session)", server))
			} else {
				common.PrintInfo(fmt.Sprintf("SMB → %s as %s\\%s", server, strings.ToUpper(domain), username))
			}
		}

		shares, err := smb.EnumerateShares(server, username, password, domain)
		if err != nil {
			common.PrintError(fmt.Errorf("failed to enumerate shares: %v", err))
			if username != "" && !anonymous {
				common.PrintInfo("Tip: try anonymous with -A  |  try guest with -u guest -p ''")
			}
			return err
		}

		if len(shares) == 0 {
			common.PrintWarning("No shares found (or access denied)")
			return nil
		}

		common.PrintSuccess(fmt.Sprintf("Found %d share(s) on %s", len(shares), server))
		rows := make([][]string, 0, len(shares))
		for _, s := range shares {
			rows = append(rows, []string{s.Name, s.Type, s.Remark})
		}
		common.PrintTable([]string{"SHARE", "TYPE", "REMARK"}, rows)
		return nil
	},
}

// SMBDownloadCmd télécharge un fichier depuis un partage SMB.
var SMBDownloadCmd = &cobra.Command{
	Use:   "download <target>",
	Short: "Download a file from an SMB share",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		server := args[0]

		username := common.Username
		password := common.Password
		domain := common.Domain
		if username == "" {
			username, _ = cmd.Flags().GetString("username")
		}
		if password == "" {
			password, _ = cmd.Flags().GetString("password")
		}
		if domain == "" {
			domain, _ = cmd.Flags().GetString("domain")
		}
		share, _ := cmd.Flags().GetString("share")
		remotePath, _ := cmd.Flags().GetString("remote-path")
		localPath, _ := cmd.Flags().GetString("local-path")

		client, err := smb.NewClient(server, username, password, domain)
		if err != nil {
			common.PrintError(fmt.Errorf("failed to create SMB client: %v", err))
			return err
		}
		defer client.Close()

		if err := client.DownloadFile(share, remotePath, localPath); err != nil {
			common.PrintError(fmt.Errorf("failed to download file: %v", err))
			return err
		}

		common.PrintSuccess(fmt.Sprintf("Downloaded %s → %s", remotePath, localPath))
		return nil
	},
}

// SMBUploadCmd uploade un fichier vers un partage SMB.
var SMBUploadCmd = &cobra.Command{
	Use:   "upload <target>",
	Short: "Upload a file to an SMB share",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		server := args[0]

		username := common.Username
		password := common.Password
		domain := common.Domain
		if username == "" {
			username, _ = cmd.Flags().GetString("username")
		}
		if password == "" {
			password, _ = cmd.Flags().GetString("password")
		}
		if domain == "" {
			domain, _ = cmd.Flags().GetString("domain")
		}
		share, _ := cmd.Flags().GetString("share")
		localPath, _ := cmd.Flags().GetString("local-path")
		remotePath, _ := cmd.Flags().GetString("remote-path")

		client, err := smb.NewClient(server, username, password, domain)
		if err != nil {
			common.PrintError(fmt.Errorf("failed to create SMB client: %v", err))
			return err
		}
		defer client.Close()

		if err := client.UploadFile(share, localPath, remotePath); err != nil {
			common.PrintError(fmt.Errorf("failed to upload file: %v", err))
			return err
		}

		common.PrintSuccess(fmt.Sprintf("Uploaded %s → %s", localPath, remotePath))
		return nil
	},
}

func init() {
	SMBSharesCmd.Flags().BoolP("anonymous", "A", false, "Use null/anonymous session (no credentials)")
	SMBSharesCmd.Flags().String("username", "", "Username (overridden by global -u)")
	SMBSharesCmd.Flags().String("password", "", "Password (overridden by global -p)")
	SMBSharesCmd.Flags().String("domain", "", "Domain (overridden by global -d)")

	SMBDownloadCmd.Flags().String("username", "", "Username")
	SMBDownloadCmd.Flags().String("password", "", "Password")
	SMBDownloadCmd.Flags().String("domain", "", "Domain")
	SMBDownloadCmd.Flags().String("share", "", "SMB share name")
	SMBDownloadCmd.Flags().String("remote-path", "", "Remote file path")
	SMBDownloadCmd.Flags().String("local-path", "", "Local file path")

	SMBUploadCmd.Flags().String("username", "", "Username")
	SMBUploadCmd.Flags().String("password", "", "Password")
	SMBUploadCmd.Flags().String("domain", "", "Domain")
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
