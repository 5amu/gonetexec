package cli

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const help string = `Usage
  {{.UseLine}}

`

func generateCli(cmd *cobra.Command, flagsets ...*pflag.FlagSet) *cobra.Command {
	var builder strings.Builder
	builder.WriteString(help)
	for _, set := range flagsets {
		cmd.Flags().AddFlagSet(set)
		builder.WriteString(set.Name())
		builder.WriteString(":\n")
		builder.WriteString(set.FlagUsages())
		builder.WriteString("\n")
	}
	cmd.SetUsageTemplate(builder.String())
	return cmd
}
