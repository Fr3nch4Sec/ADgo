// cmd/adgo/commands/samr.go
package commands

import (
	"context"
	"fmt"

	"adgo/pkg/common"
	"adgo/pkg/samr"

	"github.com/spf13/cobra"
)

var SAMREnumUsersCmd = &cobra.Command{
	Use:   "samr enum-users",
	Short: "Enumerate domain users via SAMR",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		creds, err := common.LoadCredentials()
		if err != nil {
			common.PrintError(err)
			return err
		}

		client, err := samr.NewClient(ctx, *creds)
		if err != nil {
			common.PrintError(fmt.Errorf("failed to create SAMR client: %v", err))
			return err
		}
		defer client.Close()

		users, err := client.EnumerateUsers(creds.BaseDN)
		if err != nil {
			common.PrintError(fmt.Errorf("failed to enumerate users: %v", err))
			return err
		}

		common.PrintOutput(users, false, false, false)
		common.PrintSuccess("Users enumerated successfully via SAMR")

		return nil
	},
}
