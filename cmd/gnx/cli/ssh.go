package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/5amu/gonetexec/internal/logger"
	"github.com/5amu/gonetexec/internal/runner"
	"github.com/mandiant/gopacket/pkg/session"
	"github.com/mandiant/gopacket/pkg/transport"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"
)

const sshDefaultPort = 22

func NewSSHCmd() *cobra.Command {
	var username, password, privKey string
	var port int
	var execCmd string
	var shell bool

	cmd := &cobra.Command{
		Use:   "ssh [TARGETS...]",
		Short: "Own stuff using SSH",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			targets := runner.ExtractTargets(args)
			if len(targets) == 0 {
				return
			}

			credentials := runner.NewCredentialsClusterBomb(
				runner.ExtractLinesFromFileOrString(username),
				runner.ExtractLinesFromFileOrString(password),
			)

			// Gather banners up-front (parallel, like original).
			banners := gatherBanners(targets, port)

			doNothing := !cmd.Flags().Changed("username")

			var runners []runner.Runner
			for _, target := range targets {
				target.Port = port
				banner := banners[target.Host]
				for _, creds := range credentials {
					runners = append(runners, &SSHRunner{
						target:    target,
						port:      port,
						banner:    banner,
						creds:     creds,
						privKey:   privKey,
						execCmd:   execCmd,
						shell:     shell,
						doNothing: doNothing,
					})
				}
			}

			if err := runner.ParallelRun(context.Background(), runners, nil); err != nil {
				l := logger.New("SSH", targets[0].Host, targets[0].Host, port)
				l.Error(fmt.Sprintln(err))
			}
		},
	}

	connFlags := pflag.NewFlagSet("Connection Flags", pflag.ContinueOnError)
	connFlags.StringVarP(&username, "username", "u", "", "Provide username (or FILE)")
	connFlags.StringVarP(&password, "password", "p", "", "Provide password (or FILE)")
	connFlags.StringVarP(&privKey, "private-key", "k", "", "Provide a path to a ssh private key without password")
	connFlags.IntVar(&port, "port", sshDefaultPort, "Port to contact")

	actionFlags := pflag.NewFlagSet("Action Flags", pflag.ContinueOnError)
	actionFlags.StringVar(&execCmd, "exec", "", "Execute command on target host")
	actionFlags.BoolVar(&shell, "shell", false, "Spawn a shell")

	return generateCli(cmd, connFlags, actionFlags)
}

// ---------------------------------------------------------------------------
// Banner gathering
// ---------------------------------------------------------------------------

func gatherBanners(targets []session.Target, port int) map[string]string {
	res := make(map[string]string)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, t := range targets {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			banner, err := grabBanner(host, port)
			if err != nil {
				return
			}
			parsed := parseBanner(banner)

			l := logger.New("SSH", host, parsed, port)
			l.Info(banner)

			mu.Lock()
			res[host] = parsed
			mu.Unlock()
		}(t.Host)
	}
	wg.Wait()
	return res
}

func grabBanner(host string, port int) (string, error) {
	conn, err := transport.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(string(buf[:n]), "\r\n", ""), nil
}

func parseBanner(s string) string {
	totrim := []string{"SSH-2.0-OpenSSH_for_", "SSH-2.0-"}
	spl := strings.Split(s, " ")
	var r string
	if len(spl) == 1 {
		r = spl[0]
	} else {
		r = spl[1]
	}
	for _, prefix := range totrim {
		r = strings.TrimPrefix(r, prefix)
	}
	return r
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

type SSHRunner struct {
	target    session.Target
	port      int
	banner    string
	creds     session.Credentials
	privKey   string
	execCmd   string
	shell     bool
	doNothing bool
	cancelCtx context.CancelFunc
}

func (r *SSHRunner) Start(ctx context.Context) error {
	childCtx, cancel := context.WithCancel(ctx)
	r.cancelCtx = cancel
	defer r.Stop()

	l := logger.New("SSH", r.target.Host, r.banner, r.port)

	if r.doNothing {
		return nil
	}

	if r.shell {
		return r.spawnShell(childCtx, l)
	}
	if r.execCmd != "" {
		return r.runExec(childCtx, l)
	}
	return r.authenticate(childCtx, l)
}

func (r *SSHRunner) Stop() {
	if r.cancelCtx != nil {
		r.cancelCtx()
	}
}

// ---------------------------------------------------------------------------
// Connect helpers
// ---------------------------------------------------------------------------

func (r *SSHRunner) connect() (*ssh.Client, error) {
	if r.privKey != "" {
		return connectWithKey(r.creds.Username, r.privKey, r.target.Host, r.port)
	}
	return connectWithPassword(r.creds.Username, r.creds.Password, r.target.Host, r.port)
}

func connectWithPassword(user, pass, host string, port int) (*ssh.Client, error) {
	return sshConnect(user, ssh.Password(pass), host, port)
}

func connectWithKey(user, keyPath, host string, port int) (*ssh.Client, error) {
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}
	return sshConnect(user, ssh.PublicKeys(signer), host, port)
}

func sshConnect(user string, signer ssh.AuthMethod, host string, port int) (*ssh.Client, error) {
	conn, err := transport.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}
	c, ch, req, err := ssh.NewClientConn(conn, fmt.Sprintf("%s:%d", host, port), &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{signer},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(c, ch, req), nil
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

func (r *SSHRunner) authenticate(ctx context.Context, l *slog.Logger) error {
	client, err := r.connect()
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	defer client.Close()

	credStr := credentialStringSSH(r.creds)
	l.Log(ctx, logger.LevelSuccess.Level(), credStr)
	return nil
}

func (r *SSHRunner) runExec(ctx context.Context, l *slog.Logger) error {
	client, err := r.connect()
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	defer client.Close()

	var stdoutBuff, stderrBuff bytes.Buffer
	if err := sshRun(client, r.execCmd, &stdoutBuff, &stderrBuff); err != nil {
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

func (r *SSHRunner) spawnShell(ctx context.Context, l *slog.Logger) error {
	client, err := r.connect()
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	defer client.Close()

	if err := sshShell(client); err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// SSH session helpers
// ---------------------------------------------------------------------------

func sshRun(c *ssh.Client, cmd string, stdout, stderr io.Writer) error {
	session, err := c.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	session.Stdout = stdout
	session.Stderr = stderr
	if err := session.Run(cmd); err != nil {
		switch err.(type) {
		case *ssh.ExitMissingError:
			return fmt.Errorf("command didn't execute: %v", err)
		case *ssh.ExitError:
			// non-zero exit code is fine for our purposes
		default:
			return err
		}
	}
	return nil
}

func sshShell(c *ssh.Client) error {
	session, err := c.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm-256color", 80, 40, modes); err != nil {
		return err
	}

	session.Stdout = os.Stdout
	session.Stdin = os.Stdin
	session.Stderr = os.Stderr

	if err := session.Shell(); err != nil {
		return err
	}
	return session.Wait()
}

func credentialStringSSH(creds session.Credentials) string {
	if creds.Password != "" {
		return fmt.Sprintf("%s:%s", creds.Username, creds.Password)
	}
	return creds.Username
}
