package optldap

import (
	"fmt"
	"strings"

	"github.com/5amu/goad/internal/printer"
	"github.com/5amu/goad/internal/utils"
	"github.com/5amu/goad/pkg/mstypes"
	"github.com/go-ldap/ldap/v3"
)

func (o *Options) read(target string) {
	prt := printer.NewPrinter("LDAP", target, o.target2SMBInfo[target].NetBIOSComputerName, o.Connection.Port)
	defer prt.PrintStored(&o.printMutex)

	prt.StoreInfo("LDAP Query Filter")
	prt.StoreInfo(o.filter)

	lclient, _, err := o.authenticate(target)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}
	defer lclient.Close()

	if o.filter == "" {
		return
	}

	var domain string = o.Connection.Domain
	if domain == "" {
		domain = o.target2SMBInfo[target].DNSDomainName
	}

	err = FindObjectsWithCallback(lclient, domain, o.filter, func(m map[string]interface{}) error {
		var data []string
		for _, a := range o.attributes {
			switch a {
			case LastLogon, PasswordLastSet, WhenCreated:
				data = append(data, DecodeADTimestamp(UnpackToString(m[a])))
			case ObjectSid:
				data = append(data, DecodeSID(UnpackToString(m[a])))
			case ManagedPassword:
				var blob mstypes.MSDSManagedPasswordBlob
				_ = mstypes.UnmarshalBinary(&blob, []byte(UnpackToString(m[ManagedPassword])))
				data = append(data, HashDataNTLM(blob.CurrentPassword))
			default:
				data = append(data, UnpackToString(m[a]))
			}
		}
		prt.Store(data...)
		return nil
	}, o.attributes...)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}
}

func (o *Options) create(target string) {
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

	var req *ldap.AddRequest

	switch o.createUAC {
	case WORKSTATION_TRUST_ACCOUNT:
		o.createName = strings.TrimSuffix(o.createName, "$")
		req = ldap.NewAddRequest(fmt.Sprintf("CN=%s,CN=Computers,%s", o.createName, toDN(domain)), []ldap.Control{})
		req.Attribute(ObjectClass, []string{"top", "organizationalPerson", "user", "computer"})
	case NORMAL_ACCOUNT:
		req = ldap.NewAddRequest(fmt.Sprintf("CN=Users,%s", toDN(domain)), []ldap.Control{})
		req.Attribute(ObjectClass, []string{"top", "organizationalPerson", "user", "person"})
	default:
		return
	}

	req.Attribute(UACAttr, []string{fmt.Sprint(o.createUAC)})
	req.Attribute(InstanceType, []string{fmt.Sprintf("%d", IT_Writable)})

	var password string = utils.GeneratePassword(12)

	switch o.createUAC {
	case WORKSTATION_TRUST_ACCOUNT:
		req.Attribute(SAMAccountName, []string{o.createName + "$"})
		req.Attribute(DnsHostname, []string{fmt.Sprintf("%s.%s", o.createName, domain)})
		req.Attribute(ServicePrincipalName, []string{
			fmt.Sprintf("HOST/%s", o.createName),
			fmt.Sprintf("HOST/%s.%s", o.createName, domain),
			fmt.Sprintf("RestrictedKrbHost/%s", o.createName),
			fmt.Sprintf("RestrictedKrbHost/%s.%s", o.createName, domain),
		})
		req.Attribute(UnicodePassword, []string{utils.StringToUTF16(password)})
	default:
		return
	}

	if err := lclient.Add(req); err != nil {
		prt.StoreFailure(err.Error())
	} else {
		prt.Store(o.createName, password)
	}
}

type DeletionType int

const (
	DelComputer DeletionType = iota
	DelUser
)

func (o *Options) delete(target string) {
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

	var req *ldap.DelRequest
	switch o.deletionType {
	case DelComputer:
		o.deletionName = strings.TrimSuffix(o.deletionName, "$")
		req = ldap.NewDelRequest(fmt.Sprintf("CN=%s,CN=Computers,%s", o.deletionName, toDN(domain)), []ldap.Control{})
	default:
		return
	}

	if err := lclient.Del(req); err != nil {
		prt.StoreFailure(err.Error())
	} else {
		prt.Store(o.deletionName, "successfullty deleted")
	}
}
