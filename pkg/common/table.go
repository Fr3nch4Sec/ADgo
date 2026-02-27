// pkg/common/table.go
package common

import (
	"os"

	"github.com/olekukonko/tablewriter"
)

// PrintTable affiche un tableau aligné dans le terminal
func PrintTable(headers []string, data [][]string) {
	table := tablewriter.NewWriter(os.Stdout)

	table.SetHeader(headers)
	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("|")
	table.SetColumnSeparator("|")
	table.SetRowSeparator("-")
	table.SetHeaderLine(true)
	table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})

	table.AppendBulk(data)
	table.Render()
}
