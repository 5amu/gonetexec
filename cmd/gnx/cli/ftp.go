package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/5amu/gonetexec/internal/logger"
	"github.com/5amu/gonetexec/internal/runner"
	"github.com/jlaffaye/ftp"
	"github.com/mandiant/gopacket/pkg/session"
	"github.com/mandiant/gopacket/pkg/transport"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// ftpTimeoutSec bounds control- and data-connection establishment.
const ftpTimeoutSec = 5

func NewFTPCmd() *cobra.Command {
	var username, password string
	var port int

	var getFile, readFile, srcFile, putFile, dstFile string
	var list, recursiveList bool

	cmd := &cobra.Command{
		Use:   "ftp [TARGETS...]",
		Short: "Own stuff using FTP",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			targets := runner.ExtractTargets(args)
			credentials := runner.NewCredentialsClusterBomb(
				runner.ExtractLinesFromFileOrString(username),
				runner.ExtractLinesFromFileOrString(password),
			)

			var (
				f          func(*ftp.ServerConn, session.Target, string, string) error
				bannerGrab bool
			)
			if !cmd.Flags().Changed("username") {
				// If no username is provided, just try to check if an ftp server is running and grab the banner if possible.
				f = nil
				bannerGrab = true

			} else if list {
				// List mode will list files in the root directory of the FTP server.
				f = ftpList
			} else if recursiveList {
				// Recursive list mode will list all files in the FTP server, starting from the root directory.
				f = ftpRecursiveList
			} else if putFile != "" {
				// Put mode will upload a local file to the FTP server. If the destination file is not specified,
				// it will be saved with the same name as the source file in the current working directory.
				srcFile = putFile
				f = ftpPutFile
			} else if readFile != "" {
				// Read mode will read the content of a file stored in the FTP server and print it to the console.
				srcFile = readFile
				f = ftpReadFile
			} else if getFile != "" {
				// Get mode will download a file from the FTP server and save it locally. If the destination file is not specified,
				// it will be saved with the same name as the source file in the current working directory.
				srcFile = getFile
				f = ftpGetFile
			} else {
				return
			}

			var runners []runner.Runner
			for _, target := range targets {
				target.Port = port
				for _, creds := range credentials {
					runners = append(runners, &FTPRunner{
						target:      target,
						credentials: creds,
						srcFile:     srcFile,
						dstFile:     dstFile,
						run:         f,
						bannerGrab:  bannerGrab,
					})
				}
			}

			if err := runner.ParallelRun(context.Background(), runners, nil); err != nil {
				fmt.Println("Error running FTP operations:", err)
			}
		},
	}

	connection := pflag.NewFlagSet("Connection Flags", pflag.ContinueOnError)
	connection.StringVarP(&username, "username", "u", "", "Provide username (or FILE)")
	connection.StringVarP(&password, "password", "p", "", "Provide password (or FILE)")
	connection.IntVar(&port, "port", 21, "Port to contact")

	operations := pflag.NewFlagSet("Operation Flags", pflag.ContinueOnError)
	operations.StringVar(&getFile, "get", "", "Get specified file")
	operations.StringVar(&putFile, "put", "", "Put specified file")
	operations.StringVar(&dstFile, "dst", "", "Destination file (get/put)")
	operations.StringVar(&readFile, "read", "", "Read a file stored in the server")
	operations.BoolVar(&list, "list", false, "List files in / directory")
	operations.BoolVar(&recursiveList, "recursive-list", false, "List all files in FTP server (might take long)")

	return generateCli(cmd, connection, operations)
}

type FTPRunner struct {
	target      session.Target
	credentials session.Credentials
	srcFile     string
	dstFile     string

	run        func(*ftp.ServerConn, session.Target, string, string) error
	cancelCtx  context.CancelFunc
	bannerGrab bool
}

func (r *FTPRunner) Start(ctx context.Context) error {
	_, cancel := context.WithCancel(ctx)
	r.cancelCtx = cancel
	defer r.Stop()

	addr := r.target.Addr()

	if r.bannerGrab {
		l := logger.New("FTP", r.target.Host, r.target.Host, r.target.Port)
		conn, err := transport.DialTimeout("tcp", addr, ftpTimeoutSec)
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close() }()

		_ = conn.SetReadDeadline(time.Now().Add(ftpTimeoutSec * time.Second))
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			l.Error(fmt.Sprintln(err))
			return err
		}
		l.Info(fmt.Sprintf("Banner: %s", strings.TrimSpace(string(buf[:n]))))
		return nil
	}

	// Route both the control connection and every PASV data connection through
	// the transport dialer so the proxy configuration is honoured and each
	// connection is freshly established.
	srv, err := ftp.Dial(addr, ftp.DialWithDialFunc(func(network, address string) (net.Conn, error) {
		return transport.DialTimeout(network, address, ftpTimeoutSec)
	}))
	if err != nil {
		return err
	}
	defer func() { _ = srv.Quit() }()

	if err := srv.Login(r.credentials.Username, r.credentials.Password); err != nil {
		return err
	}

	if r.run == nil {
		return nil
	}
	return r.run(srv, r.target, r.srcFile, r.dstFile)
}

func (r *FTPRunner) Stop() {
	if r.cancelCtx != nil {
		r.cancelCtx()
	}
}

func ftpList(c *ftp.ServerConn, t session.Target, src, dst string) error {
	l := logger.New("FTP", t.Host, t.Host, t.Port)

	e, err := c.List("/")
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}

	for _, entry := range e {
		l.Info(entry.Name)
	}
	return nil
}

func ftpRecursiveList(c *ftp.ServerConn, t session.Target, src, dst string) error {
	l := logger.New("FTP", t.Host, t.Host, t.Port)

	for fs := c.Walk("/"); fs.Next(); {
		l.Info(fs.Path())
	}
	return nil
}

func ftpPutFile(c *ftp.ServerConn, t session.Target, src, dst string) error {
	l := logger.New("FTP", t.Host, t.Host, t.Port)

	if dst == "" {
		dst = src
	}

	data, err := os.ReadFile(src)
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}

	reader := bytes.NewBuffer(data)

	err = c.Stor(dst, reader)
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}

	l.Log(context.Background(), logger.LevelSuccess.Level(), fmt.Sprintf("Successfully uploaded %s to %s", src, dst))
	return nil
}

func ftpReadFile(c *ftp.ServerConn, t session.Target, src, dst string) error {
	l := logger.New("FTP", t.Host, t.Host, t.Port)

	r, err := c.Retr(src)
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	defer func() { _ = r.Close() }()

	buf, err := io.ReadAll(r)
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}

	l.Info(fmt.Sprintf("Content of %s\n", src))
	l.Info(string(buf))
	return nil
}

func ftpGetFile(c *ftp.ServerConn, t session.Target, src, dst string) error {
	l := logger.New("FTP", t.Host, t.Host, t.Port)

	if dst == "" {
		dst = path.Base(src)
	}
	outfile, err := os.Create(dst)
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	defer func() { _ = outfile.Close() }()

	r, err := c.Retr(src)
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	defer func() { _ = r.Close() }()

	buf, err := io.ReadAll(r)
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}

	_, err = outfile.Write(buf)
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}

	l.Info(fmt.Sprintf("Output of file %s written to %s", src, dst))
	return nil
}
