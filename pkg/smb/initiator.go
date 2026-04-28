package smb

import (
	"encoding/asn1"

	"github.com/5amu/gonetexec/pkg/smb/internal/ntlm"
	"github.com/5amu/gonetexec/pkg/smb/internal/ntlmssp"
	"github.com/5amu/gonetexec/pkg/smb/internal/spnego"
)

type Initiator interface {
	oid() asn1.ObjectIdentifier
	initSecContext() ([]byte, error)            // GSS_Init_sec_context
	acceptSecContext(sc []byte) ([]byte, error) // GSS_Accept_sec_context
	sum(bs []byte) []byte                       // GSS_getMIC
	sessionKey() []byte                         // QueryContextAttributes(ctx, SECPKG_ATTR_SESSION_KEY, &out)
}

// NTLMInitiator implements session-setup through NTLMv2.
// It doesn't support NTLMv1. You can use Hash instead of Password.
type NTLMInitiator struct {
	User        string
	Password    string
	Hash        []byte
	Domain      string
	Workstation string
	TargetSPN   string

	Ntlm   *ntlm.Client
	seqNum uint32
}

func (i *NTLMInitiator) oid() asn1.ObjectIdentifier {
	return spnego.NlmpOid
}

func (i *NTLMInitiator) initSecContext() ([]byte, error) {
	i.Ntlm = &ntlm.Client{
		User:        i.User,
		Password:    i.Password,
		Hash:        i.Hash,
		Domain:      i.Domain,
		Workstation: i.Workstation,
		TargetSPN:   i.TargetSPN,
	}
	nmsg, err := i.Ntlm.Negotiate()
	if err != nil {
		return nil, err
	}
	return nmsg, nil
}

func (i *NTLMInitiator) acceptSecContext(sc []byte) ([]byte, error) {
	amsg, err := i.Ntlm.Authenticate(sc)
	if err != nil {
		return nil, err
	}
	return amsg, nil
}

func (i *NTLMInitiator) sum(bs []byte) []byte {
	mic, _ := i.Ntlm.Session().Sum(bs, i.seqNum)
	return mic
}

func (i *NTLMInitiator) sessionKey() []byte {
	return i.Ntlm.Session().SessionKey()
}

func (i *NTLMInitiator) InfoMap() *ntlm.InfoMap {
	return i.Ntlm.Session().InfoMap()
}

type NTLMSSPInitiator struct {
	User        string
	Password    string
	Hash        []byte
	Domain      string
	Workstation string
	TargetSPN   string

	Ntlm        *ntlmssp.Client
	ntlmInfoMap *NTLMSSPInfoMap
	//seqNum      uint32
}

type NTLMSSPInfoMap struct {
	NbComputerName  string
	NbDomainName    string
	DnsComputerName string
	DnsDomainName   string
	DnsTreeName     string
	// Flags           uint32
	// Timestamp       time.Time
	// SingleHost
	// TargetName string
	// ChannelBindings
}

func (i *NTLMSSPInitiator) oid() asn1.ObjectIdentifier {
	return spnego.NlmpOid
}

func (i *NTLMSSPInitiator) GetInfoMap() *NTLMSSPInfoMap {
	return i.infoMap()
}

func (i *NTLMSSPInitiator) initSecContext() (_ []byte, err error) {
	i.Ntlm, err = ntlmssp.NewClient(
		ntlmssp.SetCompatibilityLevel(1),
		ntlmssp.SetUserInfo(i.User, i.Password),
		ntlmssp.SetDomain(""),
	)
	if err != nil {
		return nil, err
	}
	nmsg, err := i.Ntlm.Authenticate(nil, nil)
	if err != nil {
		return nil, err
	}
	return nmsg, nil
}

func (i *NTLMSSPInitiator) acceptSecContext(sc []byte) ([]byte, error) {
	amsg, err := i.Ntlm.Authenticate(sc, nil)
	if err != nil {
		return nil, err
	}

	i.ntlmInfoMap = &NTLMSSPInfoMap{
		NbComputerName:  "",
		NbDomainName:    "",
		DnsComputerName: "",
		DnsDomainName:   "",
		DnsTreeName:     "",
	}
	if NbComputerName, found := i.Ntlm.SessionDetails().TargetInfo.Get(ntlmssp.MsvAvNbComputerName); found {
		i.ntlmInfoMap.NbComputerName = string(NbComputerName)
	}
	if NbDomainName, found := i.Ntlm.SessionDetails().TargetInfo.Get(ntlmssp.MsvAvNbDomainName); found {
		i.ntlmInfoMap.NbDomainName = string(NbDomainName)
	}
	if DnsComputerName, found := i.Ntlm.SessionDetails().TargetInfo.Get(ntlmssp.MsvAvDNSComputerName); found {
		i.ntlmInfoMap.DnsComputerName = string(DnsComputerName)
	}
	if DnsDomainName, found := i.Ntlm.SessionDetails().TargetInfo.Get(ntlmssp.MsvAvDNSDomainName); found {
		i.ntlmInfoMap.DnsDomainName = string(DnsDomainName)
	}
	if DnsTreeName, found := i.Ntlm.SessionDetails().TargetInfo.Get(ntlmssp.MsvAvDNSTreeName); found {
		i.ntlmInfoMap.DnsTreeName = string(DnsTreeName)
	}
	return amsg, nil
}

func (i *NTLMSSPInitiator) sum(bs []byte) []byte {
	return nil
}

func (i *NTLMSSPInitiator) sessionKey() []byte {
	return i.Ntlm.SessionDetails().ExportedSessionKey
}

func (i *NTLMSSPInitiator) infoMap() *NTLMSSPInfoMap {
	return i.ntlmInfoMap
}
