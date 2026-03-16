// cmd/adgo/commands/adcs_cmd.go
//
// adgo adcs — Audit complet AD CS (ESC1 à ESC8)

package commands

import (
	"context"
	"fmt"
	"strings"

	"adgo/pkg/adcs"
	"adgo/pkg/common"
	"adgo/pkg/ldap"

	"github.com/spf13/cobra"
)

var ADCSCmd = &cobra.Command{
	Use:   "adcs",
	Short: "Audit AD CS for certificate template vulnerabilities (ESC1-ESC8)",
	Long: `Full Active Directory Certificate Services audit.

Detects:
  ESC1 — SAN enabled + Client Auth EKU + no manager approval
  ESC2 — Any Purpose EKU (usable for anything)
  ESC3 — Certificate Request Agent EKU
  ESC4 — Non-admin has WriteProperty/GenericWrite on template
  ESC6 — CA flag EDITF_ATTRIBUTESUBJECTALTNAME2 (arbitrary SAN on any template)
  ESC7 — Non-admin has ManageCA or ManageCertificates on CA
  ESC8 — Web Enrollment over HTTP with NTLM (relay target)

Examples:
  adgo adcs --dc-ip 192.168.1.10 -u admin -p pass -d LAB
  adgo adcs --dc-ip 192.168.1.10 -u admin --hash aad3b435... -d LAB
  adgo adcs --dc-ip 192.168.1.10 -u admin -p pass -d LAB --template "User"

After finding ESC1:
  certipy req -ca '<CA Name>' -template <TEMPLATE> -upn administrator@<domain>
  certipy auth -pfx administrator.pfx -dc-ip <DC_IP>`,
	RunE: runADCSAudit,
}

var (
	adcsDCIP     string
	adcsTemplate string
)

func init() {
	ADCSCmd.Flags().StringVar(&adcsDCIP, "dc-ip", "", "Domain Controller IP (required)")
	ADCSCmd.Flags().StringVar(&adcsTemplate, "template", "", "Audit a specific template only")
	ADCSCmd.MarkFlagRequired("dc-ip")
}

func runADCSAudit(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	creds, err := requireCredsWithDCIP(adcsDCIP)
	if err != nil {
		return err
	}

	server := buildLDAPServer(adcsDCIP, creds)
	common.PrintInfo(fmt.Sprintf("ADCS audit → %s as %s\\%s",
		server, strings.ToUpper(creds.SMBDomain), creds.SMBUsername))

	ldapClient, err := ldap.NewClientNTLM(ctx, server, creds.SMBDomain, creds.SMBUsername,
		creds.Password, creds.NTLMHash, false)
	if err != nil {
		return fmt.Errorf("LDAP connection failed: %v", err)
	}
	defer ldapClient.Close()

	baseDN := buildBaseDN(creds)

	spinner := common.NewSpinner("Auditing ADCS")
	spinner.Start()

	// Utiliser le conn LDAP sous-jacent pour passer à pkg/adcs
	result, err := adcs.RunFullAudit(ldapClient.Conn(), baseDN)

	spinner.Stop()

	if err != nil {
		return fmt.Errorf("ADCS audit failed: %v", err)
	}

	adcs.PrintFullAudit(result)

	// Résumé
	fmt.Println()
	if len(result.VulnCount) > 0 {
		common.NxSummaryHeader("ADCS vulnerabilities")
		for esc, count := range result.VulnCount {
			common.NxSummaryLine(esc, count)
		}
		fmt.Println()
		common.PrintWarning("Use certipy or adgo kerberos getTGT --pfx <cert> to exploit")
	}

	return nil
}
