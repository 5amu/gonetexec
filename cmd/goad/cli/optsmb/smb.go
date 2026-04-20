package optsmb

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/5amu/goad/internal/printer"
	"github.com/5amu/goad/internal/utils"
	"github.com/5amu/goad/pkg/proxyconn"
	"github.com/5amu/goad/pkg/smb"
	"github.com/fatih/color"
)

type Options struct {
	Targets struct {
		TARGETS []string `description:"Provide target IP/FQDN/FILE"`
	} `positional-args:"yes"`

	Connection struct {
		Username string `short:"u" description:"Provide username (or FILE)"`
		Password string `short:"p" description:"Provide password (or FILE)"`
		NTLM     string `short:"H" long:"hashes" description:"authenticate with NTLM hash"`
		Domain   string `short:"d" long:"domain" description:"provide domain"`
		Port     int    `long:"port" default:"445" description:"Provide SMB port"`
	} `group:"Connection Options" description:"Connection Options"`

	Shares bool   `long:"shares" description:"list open shares"`
	Exec   string `short:"x" long:"exec" description:"execute a command by creating a service via RPC"`
	Client bool   `long:"client" description:"Open a client to the remote machine"`

	credentials    []utils.Credential
	target2SMBInfo map[string]*smb.SMBFingerprint
	printMutex     sync.Mutex
	targets        []string
}

func (o *Options) getFunction() func(string) {
	if o.Shares {
		return o.enumShares
	}
	if o.Exec != "" {
		return o.exec
	}
	if o.Client {
		return o.smbclient
	}
	return func(s string) {
		_, _, _ = o.authenticate(s, DefaultPort, false)
	}
}

func (o *Options) Run() {
	o.targets = utils.ExtractTargets(o.Targets.TARGETS)
	o.target2SMBInfo = GatherSMBInfoToMap(o.targets, o.Connection.Port)
	var f func(string) = o.getFunction()

	if !slices.Contains(os.Args, "-u") {
		return
	}

	o.credentials = utils.NewCredentialsDispacher(
		o.Connection.Username,
		o.Connection.Password,
		o.Connection.NTLM,
		utils.Clusterbomb,
	)

	var wg sync.WaitGroup
	for t := range o.target2SMBInfo {
		wg.Add(1)
		go func(g string) {
			f(g)
			wg.Done()
		}(t)
	}
	wg.Wait()
}

func (o *Options) authenticate(host string, port int, stopAtFirstMatch bool) (*smb.Session, utils.Credential, error) {
	prt := printer.NewPrinter("SMB", host, o.target2SMBInfo[host].NetBIOSComputerName, DefaultPort)
	defer prt.PrintStored(&o.printMutex)

	var domain string = o.Connection.Domain
	if o.Connection.Domain == "" {
		domain = o.target2SMBInfo[host].DNSDomainName
	}

	var valid bool = false
	for _, creds := range o.credentials {
		conn, err := proxyconn.GetConnection(host, port)
		if err != nil {
			return nil, utils.Credential{}, err
		}

		initiator := smb.NTLMInitiator{
			User:      creds.Username,
			Domain:    domain,
			TargetSPN: "cifs/" + o.target2SMBInfo[host].NetBIOSComputerName,
		}
		if creds.Hash != "" {
			initiator.Hash = []byte(creds.Hash)
		} else {
			initiator.Password = creds.Password
		}

		s, err := (&smb.Dialer{Initiator: &initiator}).DialContext(context.TODO(), conn)
		if err == nil {
			if stopAtFirstMatch {
				if sid := s.GetSessionID(); sid != nil {
					prt.StoreInfo("SMB2 Session ID : " + color.HiMagentaString("%x", sid))
				}
				pstr := s.GetNtProofStr()
				skey := s.GetSessionKey()
				if len(pstr)+len(skey) > 16 {
					hash := creds.Hash
					if creds.Hash == "" {
						hash = hex.EncodeToString(ntlmhash(creds.Password))
					}
					secretKey := CalculateSMB3EncryptionKey(creds.Username, domain, hash, skey, pstr)
					if len(secretKey) != 0 {
						prt.StoreInfo("SMB3 Session Key: " + color.HiMagentaString("%x", secretKey))
					}
				}
				return s, creds, nil
			}
			if IsAdminShareWritable(s) {
				prt.StoreSuccess(creds.StringWithDomain(domain) + color.YellowString(" (Pwn3d!)"))
			} else {
				prt.StoreSuccess(creds.StringWithDomain(domain))
			}
			valid = true
		}
	}
	if valid {
		return nil, utils.Credential{}, nil
	}
	return nil, utils.Credential{}, fmt.Errorf("no valid authentication")
}

func (o *Options) enumShares(target string) {
	prt := printer.NewPrinter("SMB", target, o.target2SMBInfo[target].NetBIOSComputerName, 445)
	defer prt.PrintStored(&o.printMutex)

	s, _, err := o.authenticate(target, DefaultPort, true)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}

	sh, err := s.ListSharenames()
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}

	var res [][]string
	for _, sname := range sh {
		var toAppend []string
		var readable bool = false
		var writable bool = false

		if strings.EqualFold(sname, "IPC$") {
			readable = true
			writable = false
		} else {
			fs, err := s.Mount(sname)
			if err == nil {
				readable = true
				err = fs.WriteFile("goadtest.txt", []byte("test"), 0444)
				writable = !os.IsPermission(err)
				if writable {
					// cleanup
					_ = fs.Remove("goadtest.txt")
				}
				go func() {
					_ = fs.Umount()
				}()
			}
		}
		toAppend = []string{sname}
		if readable {
			w := "READ"
			if writable {
				w = w + ",WRITE"
			}
			toAppend = append(toAppend, w)
		}
		res = append(res, toAppend)
	}

	prt.StoreSuccess("Listing shares: ")
	for _, shareInfo := range res {
		prt.Store(shareInfo...)
	}
}

func (o *Options) exec(target string) {
	prt := printer.NewPrinter("SMB", target, o.target2SMBInfo[target].NetBIOSComputerName, 445)
	defer prt.PrintStored(&o.printMutex)

	s, _, err := o.authenticate(target, DefaultPort, true)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}

	if out, err := s.SmbExec(o.Exec, "C$"); err != nil {
		prt.StoreFailure(err.Error())
		return
	} else {
		prt.StoreWithoutStripping(out)
	}
}
