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

	"github.com/5amu/goad/internal/logger"
	"github.com/5amu/goad/internal/runner"
	"github.com/jlaffaye/ftp"
	"github.com/mandiant/gopacket/pkg/session"
	"github.com/mandiant/gopacket/pkg/transport"
)

type FTPOptions struct {
	Targets struct {
		TARGETS []string `description:"Provide target IP/FQDN/FILE"`
	} `positional-args:"yes"`

	Connection struct {
		Username string `short:"u" description:"Provide username (or FILE)"`
		Password string `short:"p" description:"Provide password (or FILE)"`
		Port     int    `long:"port" default:"21" description:"Port to contact"`
	} `group:"Connection Options" description:"Connection Options"`

	Mode struct {
		GetFile       string `long:"get" description:"Get specified file"`
		PutFile       string `long:"put" description:"Put specified file"`
		DstFile       string `long:"dst" description:"Destination file (get/put)"`
		ReadFile      string `long:"read" description:"Read a file stored in the server"`
		List          bool   `long:"list" description:"List files in / directory"`
		RecursiveList bool   `long:"recursive-list" description:"List all files in FTP server (might take long)"`
	} `group:"Possible Operations"`
}

func (o *FTPOptions) Run() {
	targets := runner.ExtractTargets(o.Targets.TARGETS)
	credentials := runner.NewCredentialsClusterBomb(
		runner.ExtractLinesFromFileOrString(o.Connection.Username),
		runner.ExtractLinesFromFileOrString(o.Connection.Password),
	)

	var (
		f          func(*ftp.ServerConn, session.Target, string, string) error
		dstFile    string
		srcFile    string
		bannerGrab bool
	)
	if !slices.Contains(os.Args, "-u") {
		// If no username is provided, just try to check if an ftp server is running and grab the banner if possible.
		f = nil
		bannerGrab = true

	} else if o.Mode.List {
		// List mode will list files in the root directory of the FTP server.
		f = func(sc *ftp.ServerConn, t session.Target, s1, s2 string) error {
			l := logger.New("FTP", t.Host, t.Host, t.Port)

			e, err := sc.List("/")
			if err != nil {
				l.Error(fmt.Sprintln(err))
				return err
			}

			for _, entry := range e {
				l.Info(entry.Name)
			}
			return nil
		}
	} else if o.Mode.RecursiveList {
		// Recursive list mode will list all files in the FTP server, starting from the root directory.
		f = func(sc *ftp.ServerConn, t session.Target, s1, s2 string) error {
			l := logger.New("FTP", t.Host, t.Host, t.Port)

			for fs := sc.Walk("/"); fs.Next(); {
				l.Info(fs.Path())
			}
			return nil
		}
	} else if o.Mode.PutFile != "" {
		// Put mode will upload a local file to the FTP server. If the destination file is not specified,
		// it will be saved with the same name as the source file in the current working directory.
		srcFile = o.Mode.PutFile
		dstFile = o.Mode.DstFile
		f = func(sc *ftp.ServerConn, t session.Target, src, dst string) error {
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

			err = sc.Stor(dst, reader)
			if err != nil {
				l.Error(fmt.Sprintln(err))
				return err
			}

			l.Info(fmt.Sprintf("Successfully uploaded %s to %s", src, dst))
			return nil
		}
	} else if o.Mode.ReadFile != "" {
		// Read mode will read the content of a file stored in the FTP server and print it to the console.
		srcFile = o.Mode.ReadFile
		f = func(sc *ftp.ServerConn, t session.Target, s1, s2 string) error {
			l := logger.New("FTP", t.Host, t.Host, t.Port)

			r, err := sc.Retr(s1)
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

			l.Info(fmt.Sprintf("Content of %s\n", s1))
			l.Info(string(buf))
			return nil
		}
	} else if o.Mode.GetFile != "" {
		// Get mode will download a file from the FTP server and save it locally. If the destination file is not specified,
		// it will be saved with the same name as the source file in the current working directory.
		srcFile = o.Mode.GetFile
		dstFile = o.Mode.DstFile
		f = func(sc *ftp.ServerConn, t session.Target, src, dst string) error {
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

			r, err := sc.Retr(src)
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
	} else {
		return
	}

	var runners []runner.Runner
	for _, target := range targets {
		target.Port = o.Connection.Port
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

	if err := runner.ParallelRun(context.Background(), runners, false, DefaultThreads); err != nil {
		fmt.Println("Error running FTP operations:", err)
	}
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
