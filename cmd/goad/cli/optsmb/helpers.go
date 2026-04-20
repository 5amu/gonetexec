package optsmb

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/5amu/goad/internal/printer"
	"github.com/5amu/goad/pkg/proxyconn"
	"github.com/5amu/goad/pkg/smb"
	"github.com/fatih/color"
)

const DefaultPort = 445

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
		// cleanup
		_ = fs.Remove("goadtest.txt")
	}
	return !os.IsPermission(err)
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

func GetSMBInfo(host string, port int) (f *smb.SMBFingerprint) {
	fchan := make(chan *smb.SMBFingerprint)
	go func() {
		fingerprint, err := smb.FingerprintWithDialer(host, port, proxyconn.GetDialFunc())
		if err != nil {
			fchan <- nil
		}
		fchan <- fingerprint
	}()

	select {
	case f = <-fchan:
	case <-time.After(2 * time.Second):
	}
	return
}

func GatherSMBInfoToMap(targets []string, port int) map[string]*smb.SMBFingerprint {
	ret := make(map[string]*smb.SMBFingerprint)
	var wg sync.WaitGroup

	var mapMutex sync.Mutex
	guard := make(chan struct{}, 128)
	for _, t := range targets {
		wg.Add(1)
		guard <- struct{}{}
		go func(s string) {
			v := GetSMBInfo(s, port)
			<-guard
			if v != nil {
				prt := printer.NewPrinter("SMB", s, v.NetBIOSComputerName, port)
				mapMutex.Lock()
				ret[s] = v
				mapMutex.Unlock()
				prt.PrintInfo(FormatFingerprintData(v))
			}
			wg.Done()
		}(t)
	}
	wg.Wait()
	return ret
}
