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
	conn, err := net.Dial("tcp", fmt.Sprintf("%v:%d", string(net.ParseIP(host)), port))
	if err != nil {
		return nil, err
	}
	return FingerprintWithConn(conn)
}

func FingerprintWithConn(conn net.Conn) (*SMBFingerprint, error) {
	var info SMBFingerprint

	d := &Dialer{
		Initiator: &NTLMSSPInitiator{},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	s, _ := d.DialContext(ctx, conn)
	initiator := d.Initiator.(*NTLMSSPInitiator)

	if s != nil {
		if s.S != nil {
			info.SigningRequired = s.S.RequireSigning
		}
	}

	if initiator.Ntlm == nil {
		return &info, nil
	}

	sd := initiator.Ntlm.SessionDetails()
	info.OSVersion = fmt.Sprintf("%d.%d.%d", sd.Version.ProductMajorVersion, sd.Version.ProductMinorVersion, sd.Version.ProductBuild)

	infomap := initiator.GetInfoMap()
	info.NetBIOSComputerName = utf16le.DecodeToString([]byte(infomap.NbComputerName))
	info.NetBIOSDomainName = utf16le.DecodeToString([]byte(infomap.NbDomainName))
	info.DNSComputerName = utf16le.DecodeToString([]byte(infomap.DnsComputerName))
	info.DNSDomainName = utf16le.DecodeToString([]byte(infomap.DnsDomainName))
	info.ForestName = utf16le.DecodeToString([]byte(infomap.DnsTreeName))
	return &info, nil
}
