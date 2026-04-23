package smb

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/5amu/gonetexec/pkg/smb/internal/utf16le"
)

type SMBFingerprint struct {
	// V1Support if supports SMBv1
	V1Support bool

	// Security Mode of the connection
	SigningRequired bool

	// Reported Vesion of OS
	OSVersion string

	// NETBIOS
	NetBIOSComputerName string
	NetBIOSDomainName   string

	// DNS
	DNSComputerName string
	DNSDomainName   string
	ForestName      string
}

func Fingerprint(host string, port int) (*SMBFingerprint, error) {
	var d net.Dialer
	return FingerprintWithDialer(host, port, d.Dial)
}

func FingerprintWithDialer(host string, port int, dialer func(network string, addr string) (net.Conn, error)) (*SMBFingerprint, error) {
	conn1, err := dialer("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}

	var info SMBFingerprint
	info.V1Support = NewV1Client().WithConn(conn1).IsSMBv1()
	go conn1.Close()

	conn3, err := dialer("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}

	d := &Dialer{
		Initiator: &NTLMSSPInitiator{},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	s, _ := d.DialContext(ctx, conn3)
	initiator := d.Initiator.(*NTLMSSPInitiator)

	if s != nil {
		if s.s != nil {
			info.SigningRequired = s.s.requireSigning
		}
	}

	sd := initiator.ntlm.SessionDetails()
	info.OSVersion = fmt.Sprintf("%d.%d.%d", sd.Version.ProductMajorVersion, sd.Version.ProductMinorVersion, sd.Version.ProductBuild)

	infomap := initiator.GetInfoMap()
	info.NetBIOSComputerName = utf16le.DecodeToString([]byte(infomap.NbComputerName))
	info.NetBIOSDomainName = utf16le.DecodeToString([]byte(infomap.NbDomainName))
	info.DNSComputerName = utf16le.DecodeToString([]byte(infomap.DnsComputerName))
	info.DNSDomainName = utf16le.DecodeToString([]byte(infomap.DnsDomainName))
	info.ForestName = utf16le.DecodeToString([]byte(infomap.DnsTreeName))
	return &info, nil
}
