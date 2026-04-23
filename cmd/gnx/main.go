package main

import (
	"fmt"
	"os"

	"github.com/5amu/go-flags"
	"github.com/5amu/gonetexec/cmd/gnx/cli"
	"github.com/5amu/gonetexec/cmd/gnx/cli/optldap"
	"github.com/5amu/gonetexec/cmd/gnx/cli/optsmb"
	"github.com/5amu/gonetexec/cmd/gnx/cli/optssh"
	"github.com/5amu/gonetexec/cmd/gnx/cli/optvnc"
)

type MainOptions struct {
	FTP  cli.FTPOptions  `command:"ftp" description:"Own stuff using FTP"`
	LDAP optldap.Options `command:"ldap" description:"Own stuff using LDAP"`
	KRB5 cli.Krb5Options `command:"krb5" description:"Own stuff using KERBEROS"`
	//MSSQL optmssql.Options `command:"mssql" description:"Own stuff using MSSQL"`
	//RDP   optrdp.Options   `command:"rdp" description:"Own stuff using RDP"`
	SMB optsmb.Options `command:"smb" description:"Own stuff using SMB"`
	SSH optssh.Options `command:"ssh" description:"Own stuff using SSH"`
	VNC optvnc.Options `command:"vnc" description:"Own stuff using VNC"`
	//WINRM optwinrm.Options `command:"winrm" description:"Own stuff using WINRM"`
	//WMI   optwmi.Options   `command:"wmi" description:"Own stuff using WMI"`
}

func main() {
	p := flags.NewNamedParser("GoAD", flags.Default)

	var opts MainOptions
	_, err := p.AddGroup("Application Options", "", &opts)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if _, err := p.Parse(); err != nil {
		os.Exit(1)
	}

	fmt.Println()
	defer fmt.Println()

	for _, c := range p.Commands() {
		if p.Find(c.Name) == p.Active {
			switch c.Name {
			case "ftp":
				opts.FTP.Run()
			//case "mssql":
			//	opts.MSSQL.Run()
			//case "rdp":
			//  opts.RDP.Run()
			//case "wmi":
			//  opts.WMI.Run()
			//case "winrm":
			//	opts.WINRM.Run()
			case "ldap":
				opts.LDAP.Run()
			case "krb5":
				opts.KRB5.Run()
			case "smb":
				opts.SMB.Run()
			case "ssh":
				opts.SSH.Run()
			case "vnc":
				opts.VNC.Run()
			}
		}
	}
}
