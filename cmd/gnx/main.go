package main

import (
	"fmt"
	"os"

	"github.com/5amu/gonetexec/cmd/gnx/cli"
	"github.com/5amu/gonetexec/cmd/gnx/cli/optldap"
	"github.com/5amu/gonetexec/cmd/gnx/cli/optssh"
	"github.com/5amu/gonetexec/cmd/gnx/cli/optvnc"
	"github.com/spf13/cobra"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "gnx",
		Short: "GoNetExec - A modular network tool",
	}

	rootCmd.AddCommand(cli.NewFTPCmd())
	rootCmd.AddCommand(cli.NewKrb5Cmd())
	rootCmd.AddCommand(optldap.NewLDAPCmd())
	rootCmd.AddCommand(cli.NewSMBCmd())
	rootCmd.AddCommand(optssh.NewSSHCmd())
	rootCmd.AddCommand(optvnc.NewVNCCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
