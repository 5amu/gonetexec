package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/5amu/gonetexec/internal/fingerprint"
	"github.com/5amu/gonetexec/internal/logger"
	"github.com/5amu/gonetexec/internal/runner"
	"github.com/mandiant/gopacket/pkg/session"
	"github.com/mandiant/gopacket/pkg/transport"
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
						target:  target,
						port:    port,
						creds:   creds,
						useSSL:  useSSL,
						execCmd: execCmd,
						shell:   shell,
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

	// The SMB fingerprint only labels the host in log lines. It is
	// best-effort: WinRM must still work when 445 is closed or filtered.
	name := r.target.Host
	if info, err := fingerprint.SMB(session.Target{Host: r.target.Host, IP: r.target.IP, Port: 445}); err == nil && info.NetBIOSComputerName != "" {
		name = info.NetBIOSComputerName
	}

	if r.shell {
		return r.openShell(childCtx, name)
	}
	if r.execCmd != "" {
		return r.exec(childCtx, name)
	}
	return r.authenticate(childCtx, name)
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
		return winrm.NewClientNTLMWithDial(transport.Dial)
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

func (r *WinRMRunner) authenticate(ctx context.Context, name string) error {
	l := logger.New("WINRM", r.target.Host, name, r.port)

	client, err := r.winrmClient(r.creds)
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}

	// Verify auth with a no-op command, discarding its output.
	var out, errBuf bytes.Buffer
	if _, err := client.RunWithContext(ctx, "hostname", &out, &errBuf); err != nil {
		l.Error(fmt.Sprintf("%s %s", credentialStringWinRM(r.creds), err))
		return err
	}

	l.Log(ctx, logger.LevelSuccess.Level(), credentialStringWinRM(r.creds))
	return nil
}

func (r *WinRMRunner) exec(ctx context.Context, name string) error {
	l := logger.New("WINRM", r.target.Host, name, r.port)

	client, err := r.winrmClient(r.creds)
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}

	var stdoutBuff, stderrBuff bytes.Buffer
	if _, err := client.RunWithContext(ctx, r.execCmd, &stdoutBuff, &stderrBuff); err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}

	l.Log(ctx, logger.LevelSuccess.Level(), credentialStringWinRM(r.creds))
	out := strings.TrimRight(stdoutBuff.String()+stderrBuff.String(), "\r\n")
	if out != "" {
		for _, s := range strings.Split(out, "\n") {
			l.Info(strings.TrimRight(s, "\r"))
		}
	}
	return nil
}

func (r *WinRMRunner) openShell(ctx context.Context, name string) error {
	l := logger.New("WINRM", r.target.Host, name, r.port)

	client, err := r.winrmClient(r.creds)
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}

	if _, err := client.RunWithContextWithInput(ctx, "powershell.exe", os.Stdout, os.Stderr, os.Stdin); err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	return nil
}

func credentialStringWinRM(c session.Credentials) string {
	if c.Password == "" {
		return c.Username
	}
	return fmt.Sprintf("%s:%s", c.Username, c.Password)
}
