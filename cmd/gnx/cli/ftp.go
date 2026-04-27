package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"slices"
	"time"

	"github.com/5amu/gonetexec/internal/logger"
	"github.com/5amu/gonetexec/internal/runner"
	"github.com/jlaffaye/ftp"
	"github.com/mandiant/gopacket/pkg/session"
	"github.com/mandiant/gopacket/pkg/transport"
	"github.com/spf13/cobra"
)

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
			if !slices.Contains(os.Args, "-u") {
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

	cmd.Flags().StringVarP(&username, "username", "u", "", "Provide username (or FILE)")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Provide password (or FILE)")
	cmd.Flags().IntVar(&port, "port", 21, "Port to contact")

	cmd.Flags().StringVar(&getFile, "get", "", "Get specified file")
	cmd.Flags().StringVar(&putFile, "put", "", "Put specified file")
	cmd.Flags().StringVar(&dstFile, "dst", "", "Destination file (get/put)")
	cmd.Flags().StringVar(&readFile, "read", "", "Read a file stored in the server")
	cmd.Flags().BoolVar(&list, "list", false, "List files in / directory")
	cmd.Flags().BoolVar(&recursiveList, "recursive-list", false, "List all files in FTP server (might take long)")

	return cmd
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
	childCtx, cancel := context.WithCancel(ctx)
	r.cancelCtx = cancel
	defer r.Stop()

	conn, err := transport.DialTimeout("TCP", fmt.Sprintf("%s:%d", r.target.Host, r.target.Port), 2)
	if err != nil {
		return err
	}
	defer conn.Close()

	if r.bannerGrab {
		l := logger.New("FTP", r.target.Host, r.target.Host, r.target.Port)
		buf := make([]byte, 1024)

		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			l.Error(fmt.Sprintln(err))
			return err
		}
		banner := string(buf[:n])
		l.Info(fmt.Sprintf("Banner: %s", banner))
		return nil
	}

	srvC := make(chan *ftp.ServerConn)
	errC := make(chan error)
	go func(h string, p int) {
		if c, err := ftp.Dial(
			fmt.Sprintf("%s:%d", h, p),
			ftp.DialWithDialFunc(func(network, address string) (net.Conn, error) {
				return conn, nil
			}),
		); err != nil {
			errC <- err
		} else {
			srvC <- c
		}
	}(r.target.Host, r.target.Port)

	var srv *ftp.ServerConn
	select {
	case err := <-errC:
		return err
	case srv = <-srvC:
	case <-time.After(2 * time.Second):
		return fmt.Errorf("connect timed out")
	case <-childCtx.Done():
		return fmt.Errorf("context expired")
	}

	go func() {
		if err := srv.Login(r.credentials.Username, r.credentials.Password); err != nil {
			errC <- err
		}
	}()

	select {
	case <-childCtx.Done():
		return fmt.Errorf("context expired")
	case err = <-errC:
		if err != nil {
			return err
		}
	}
	defer srv.Quit()

	go func() {
		if err := r.run(srv, r.target, r.srcFile, r.dstFile); err != nil {
			errC <- err
		}
	}()

	select {
	case <-childCtx.Done():
		return fmt.Errorf("context expired")
	case err = <-errC:
		return err
	}
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
	defer r.Close()

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

	var outfile *os.File
	if dst == "" {
		basePath := path.Base(src)

		dstF, err := os.Create(basePath)
		if err != nil {
			l.Error(fmt.Sprintln(err))
			return err
		}
		outfile = dstF
		dst = dstF.Name()
	} else {
		dstF, err := os.Open(dst)
		if err != nil {
			l.Error(fmt.Sprintln(err))
			return err
		}
		outfile = dstF
		dst = dstF.Name()
	}
	defer outfile.Close()

	r, err := c.Retr(src)
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	defer r.Close()

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
