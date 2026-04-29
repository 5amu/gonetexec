package main

import (
	"fmt"
	"os"

	"github.com/5amu/gonetexec/cmd/gnx/cli"
	"github.com/spf13/cobra"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "gnx",
		Short: "GoNetExec - A modular network tool",
	}

	rootCmd.AddCommand(cli.NewFTPCmd())
	rootCmd.AddCommand(cli.NewKrb5Cmd())
	rootCmd.AddCommand(cli.NewLDAPCmd())
	rootCmd.AddCommand(cli.NewSMBCmd())
	rootCmd.AddCommand(cli.NewSSHCmd())
	rootCmd.AddCommand(cli.NewVNCCmd())
	rootCmd.AddCommand(cli.NewWinRMCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
