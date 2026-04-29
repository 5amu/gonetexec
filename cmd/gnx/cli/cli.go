package cli

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/text/encoding/unicode"
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

func generatePassword(n int) string {
	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!?_")
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteRune(chars[rand.Intn(len(chars))])
	}
	return b.String()
}

func stringToUTF16String(s string) string {
	pwd := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	out, _ := pwd.NewEncoder().String(s)
	return out
}

func writeLines(lines []string, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}
