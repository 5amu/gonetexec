package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/5amu/gonetexec/internal/logger"
	"github.com/5amu/gonetexec/internal/runner"
	"github.com/5amu/gonetexec/pkg/proxyconn"
	"github.com/mandiant/gopacket/pkg/session"
	"github.com/mitchellh/go-vnc"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const vncDefaultPort = 5900

func NewVNCCmd() *cobra.Command {
	var password string
	var port int

	cmd := &cobra.Command{
		Use:   "vnc [TARGETS...]",
		Short: "Own stuff using VNC",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			targets := runner.ExtractTargets(args)
			if len(targets) == 0 {
				return
			}

			credentials := runner.NewCredentialsClusterBomb(
				[]string{""},
				runner.ExtractLinesFromFileOrString(password),
			)

			// Gather VNC banners up-front.
			banners := gatherVNCBanners(targets, port)

			doNothing := !slices.Contains(os.Args, "-p")

			var runners []runner.Runner
			for _, target := range targets {
				target.Port = port
				banner := banners[target.Host]
				for _, creds := range credentials {
					runners = append(runners, &VNCRunner{
						target:    target,
						port:      port,
						banner:    banner,
						creds:     creds,
						doNothing: doNothing,
					})
				}
			}

			if err := runner.ParallelRun(context.Background(), runners, nil); err != nil {
				l := logger.New("VNC", targets[0].Host, targets[0].Host, port)
				l.Error(fmt.Sprintln(err))
			}
		},
	}

	connFlags := pflag.NewFlagSet("Connection Flags", pflag.ContinueOnError)
	connFlags.StringVarP(&password, "password", "p", "", "Provide password (or FILE)")
	connFlags.IntVar(&port, "port", vncDefaultPort, "Port to contact")

	return generateCli(cmd, connFlags)
}

// ---------------------------------------------------------------------------
// Banner gathering
// ---------------------------------------------------------------------------

func gatherVNCBanners(targets []session.Target, port int) map[string]string {
	res := make(map[string]string)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, t := range targets {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			if verifyVNC(host, port) {
				l := logger.New("VNC", host, host, port)
				l.Info(fmt.Sprintf("VNC Server of %s", host))

				mu.Lock()
				res[host] = host
				mu.Unlock()
			}
		}(t.Host)
	}
	wg.Wait()
	return res
}

func verifyVNC(host string, port int) bool {
	conn, err := proxyconn.GetConnection(host, port)
	if err != nil {
		return false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	var protocolVersion [12]byte
	if _, err := io.ReadFull(conn, protocolVersion[:]); err != nil {
		return false
	}

	var major, minor uint
	l, err := fmt.Sscanf(string(protocolVersion[:]), "RFB %d.%d\n", &major, &minor)
	if l != 2 || err != nil {
		return false
	}
	return major == 3 && (minor == 3 || minor == 7 || minor == 8)
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

type VNCRunner struct {
	target    session.Target
	port      int
	banner    string
	creds     session.Credentials
	doNothing bool
	cancelCtx context.CancelFunc
}

func (r *VNCRunner) Start(ctx context.Context) error {
	childCtx, cancel := context.WithCancel(ctx)
	r.cancelCtx = cancel
	defer r.Stop()

	l := logger.New("VNC", r.target.Host, r.banner, r.port)

	if r.doNothing {
		return nil
	}

	return r.authenticate(childCtx, l)
}

func (r *VNCRunner) Stop() {
	if r.cancelCtx != nil {
		r.cancelCtx()
	}
}

func (r *VNCRunner) authenticate(ctx context.Context, l *slog.Logger) error {
	conn, err := proxyconn.GetConnection(r.target.Host, r.port)
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}

	c, err := vnc.Client(conn, &vnc.ClientConfig{
		Auth: []vnc.ClientAuth{
			&vnc.PasswordAuth{Password: r.creds.Password},
		},
	})
	if err != nil {
		l.Log(ctx, logger.LevelSuccess.Level(), fmt.Sprintf("[-] %s", r.creds.Password))
		return err
	}

	desktopName := c.DesktopName
	go func() { _ = c.Close() }()

	l.Log(ctx, logger.LevelSuccess.Level(), fmt.Sprintf("[*] %s", r.creds.Password))
	l.Info(fmt.Sprintf("VNC Desktop Name: %s", desktopName))
	return nil
}
