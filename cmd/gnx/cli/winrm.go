package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	altsmb "github.com/5amu/gonetexec/pkg/smb"

	"github.com/5amu/gonetexec/internal/logger"
	"github.com/5amu/gonetexec/internal/runner"
	putils "github.com/5amu/gonetexec/pkg/proxyconn"
	"github.com/mandiant/gopacket/pkg/session"
	"github.com/masterzen/winrm"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const winrmDefaultPort = 5985

func NewWinRMCmd() *cobra.Command {
	var username, password string
	var port int
	var useSSL bool
	var execCmd string
	var shell bool

	cmd := &cobra.Command{
		Use:   "winrm [TARGETS...]",
		Short: "Own stuff using WinRM",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			targets := runner.ExtractTargets(args)
			if len(targets) == 0 {
				return
			}

			credentials := runner.NewCredentialsDispacher(
				username,
				password,
				"",
				runner.Clusterbomb,
			)

			var runners []runner.Runner
			for _, target := range targets {
				target.Port = port
				for _, creds := range credentials {
					runners = append(runners, &WinRMRunner{
						target:    target,
						port:      port,
						creds:     creds,
						useSSL:    useSSL,
						execCmd:   execCmd,
						shell:     shell,
					})
				}
			}

			if err := runner.ParallelRun(context.Background(), runners, nil); err != nil {
				l := logger.New("WINRM", targets[0].Host, targets[0].Host, port)
				l.Error(fmt.Sprintln(err))
			}
		},
	}

	connFlags := pflag.NewFlagSet("Connection Flags", pflag.ContinueOnError)
	connFlags.StringVarP(&username, "username", "u", "", "Provide username (or FILE)")
	connFlags.StringVarP(&password, "password", "p", "", "Provide password (or FILE)")
	connFlags.IntVar(&port, "port", winrmDefaultPort, "Port to contact")
	connFlags.BoolVar(&useSSL, "ssl", false, "Encrypt WinRM connection")

	actionFlags := pflag.NewFlagSet("Action Flags", pflag.ContinueOnError)
	actionFlags.StringVarP(&execCmd, "exec", "x", "", "Execute command on target host")
	actionFlags.BoolVar(&shell, "shell", false, "Spawn a powershell shell")

	return generateCli(cmd, connFlags, actionFlags)
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

type WinRMRunner struct {
	target    session.Target
	port      int
	creds     session.Credentials
	useSSL    bool
	execCmd   string
	shell     bool
	cancelCtx context.CancelFunc
}

func (r *WinRMRunner) Start(ctx context.Context) error {
	childCtx, cancel := context.WithCancel(ctx)
	r.cancelCtx = cancel
	defer r.Stop()

	info, err := altsmb.Fingerprint(r.target.Host, 445)
	if err != nil {
		l := logger.New("WINRM", r.target.Host, r.target.Host, r.port)
		l.Error(fmt.Sprintln(err))
		return err
	}

	if r.shell {
		return r.openShell(childCtx, info)
	}
	if r.execCmd != "" {
		return r.exec(childCtx, info)
	}
	return r.authenticate(childCtx, info)
}

func (r *WinRMRunner) Stop() {
	if r.cancelCtx != nil {
		r.cancelCtx()
	}
}

// ---------------------------------------------------------------------------
// WinRM helpers
// ---------------------------------------------------------------------------

func (r *WinRMRunner) winrmClient(creds session.Credentials) (*winrm.Client, error) {
	params := winrm.DefaultParameters
	params.TransportDecorator = func() winrm.Transporter {
		return winrm.NewClientNTLMWithDial(putils.GetDialFunc())
	}
	return winrm.NewClientWithParameters(
		winrm.NewEndpoint(r.target.Host, r.port, r.useSSL, true, nil, nil, nil, 0),
		creds.Username,
		creds.Password,
		params,
	)
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

func (r *WinRMRunner) authenticate(ctx context.Context, info *altsmb.SMBFingerprint) error {
	l := logger.New("WINRM", r.target.Host, info.NetBIOSComputerName, r.port)

	client, err := r.winrmClient(r.creds)
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}

	// Run a no-op command to verify auth works.
	_, err = client.RunWithContext(ctx, "hostname", os.Stdout, os.Stderr)
	if err != nil {
		l.Log(ctx, logger.LevelSuccess.Level(), fmt.Sprintf("[-] %s", r.creds.Username))
		return err
	}

	l.Log(ctx, logger.LevelSuccess.Level(), fmt.Sprintf("[*] %s", r.creds.Username))
	return nil
}

func (r *WinRMRunner) exec(ctx context.Context, info *altsmb.SMBFingerprint) error {
	l := logger.New("WINRM", r.target.Host, info.NetBIOSComputerName, r.port)

	var client *winrm.Client
	var found bool
	for _, cred := range []session.Credentials{r.creds} {
		c, err := r.winrmClient(cred)
		if err != nil {
			l.Log(ctx, logger.LevelSuccess.Level(), fmt.Sprintf("[-] %s", cred.Username))
			continue
		}
		client = c
		found = true
		l.Log(ctx, logger.LevelSuccess.Level(), fmt.Sprintf("[*] %s", cred.Username))
		break
	}
	if !found {
		return fmt.Errorf("no valid credentials")
	}

	var stdoutBuff, stderrBuff bytes.Buffer
	_, err := client.RunWithContext(ctx, r.execCmd, &stdoutBuff, &stderrBuff)
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}

	out := stdoutBuff.String() + stderrBuff.String()
	lines := strings.Split(out, "\n")
	for _, s := range lines[:len(lines)-1] {
		l.Info(s)
	}
	return nil
}

func (r *WinRMRunner) openShell(ctx context.Context, info *altsmb.SMBFingerprint) error {
	l := logger.New("WINRM", r.target.Host, info.NetBIOSComputerName, r.port)

	client, err := r.winrmClient(r.creds)
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}

	_, err = client.RunWithContextWithInput(ctx, "powershell.exe", os.Stdout, os.Stderr, os.Stdin)
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	return nil
}
