// Package fingerprint performs an unauthenticated SMB fingerprint of a remote
// host: SMB dialect, message-signing policy, SMBv1 availability and the NTLM
// target information (OS version, NetBIOS/DNS computer and domain names).
//
// The wire format below is the unavoidable SMB1/SMB2 negotiate + session-setup
// framing; everything that can be delegated to mandiant/gopacket is: NTLM
// AV-pair parsing (pkg/ntlm), UTF-16LE decoding (pkg/utf16le) and the
// proxy-aware dialer (pkg/transport).
package fingerprint

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/mandiant/gopacket/pkg/ntlm"
	"github.com/mandiant/gopacket/pkg/session"
	"github.com/mandiant/gopacket/pkg/transport"
	"github.com/mandiant/gopacket/pkg/utf16le"
)

const (
	smb1Magic = "\xffSMB"
	smb2Magic = "\xfeSMB"

	smb2Negotiate    = 0x0000
	smb2SessionSetup = 0x0001

	dialect202 = 0x0202
	dialect210 = 0x0210
	dialect300 = 0x0300
	dialect302 = 0x0302
	dialect311 = 0x0311

	signingEnabled  = 0x0001
	signingRequired = 0x0002

	statusMoreProcessingRequired = 0xC0000016

	defaultSMBPort = 445
)

// SMBInfo is the result of an unauthenticated SMB fingerprint.
type SMBInfo struct {
	// V1Support reports whether the server still answers SMBv1 negotiation.
	V1Support bool

	// Dialect is the SMB2+ dialect the server preferred (0 if unknown).
	Dialect uint16

	// SigningEnabled / SigningRequired reflect the server security mode.
	SigningEnabled  bool
	SigningRequired bool

	// OSVersion is the NTLM-reported version string ("major.minor.build").
	OSVersion string

	// NetBIOS names.
	NetBIOSComputerName string
	NetBIOSDomainName   string

	// DNS names.
	DNSComputerName string
	DNSDomainName   string
	ForestName      string
}

// DialectString renders Dialect as a human-readable SMB version.
func (i *SMBInfo) DialectString() string {
	switch i.Dialect {
	case dialect202:
		return "SMB 2.0.2"
	case dialect210:
		return "SMB 2.1"
	case dialect300:
		return "SMB 3.0"
	case dialect302:
		return "SMB 3.0.2"
	case dialect311:
		return "SMB 3.1.1"
	case 0:
		return "unknown"
	default:
		return fmt.Sprintf("0x%04x", i.Dialect)
	}
}

// SMB fingerprints target over SMB, dialing through the configured transport
// (proxy-aware). The SMB2 negotiate is mandatory and its failure is returned as
// an error; the SMBv1 probe and the NTLM session-setup probe are best-effort
// and only enrich the result.
func SMB(target session.Target) (*SMBInfo, error) {
	return SMBTimeout(target, 5*time.Second)
}

// SMBTimeout is SMB with an explicit per-connection timeout.
func SMBTimeout(target session.Target, timeout time.Duration) (*SMBInfo, error) {
	port := target.Port
	if port == 0 {
		port = defaultSMBPort
	}
	host := target.Host
	if target.IP != "" {
		host = target.IP
	}
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	network := target.Network()

	var info SMBInfo

	// Mandatory: SMB2 negotiate (signing policy + dialect + security blob).
	conn, err := dial(network, address, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := writeNetBIOS(conn, buildSMB2Negotiate()); err != nil {
		return nil, err
	}
	resp, err := readNetBIOS(conn)
	if err != nil {
		return nil, err
	}
	secMode, dialect, err := parseSMB2Negotiate(resp)
	if err != nil {
		return nil, err
	}
	info.Dialect = dialect
	info.SigningEnabled = secMode&signingEnabled != 0
	info.SigningRequired = secMode&signingRequired != 0

	// Best-effort: NTLM challenge via session setup on the same connection.
	if challenge, err := ntlmChallenge(conn); err == nil {
		enrichFromChallenge(&info, challenge)
	}

	// Best-effort: SMBv1 availability on a fresh connection.
	info.V1Support = smb1Enabled(network, address, timeout)

	return &info, nil
}

func dial(network, address string, timeout time.Duration) (net.Conn, error) {
	return transport.DialTimeout(network, address, int(timeout.Seconds()))
}

// ntlmChallenge drives an anonymous SMB2 SESSION_SETUP (NTLM type 1) and
// returns the raw NTLM CHALLENGE (type 2) message from the response.
func ntlmChallenge(conn net.Conn) ([]byte, error) {
	if err := writeNetBIOS(conn, buildSessionSetupType1()); err != nil {
		return nil, err
	}
	resp, err := readNetBIOS(conn)
	if err != nil {
		return nil, err
	}
	if len(resp) >= 12 {
		status := binary.LittleEndian.Uint32(resp[8:12])
		if status != statusMoreProcessingRequired && status != 0 {
			return nil, fmt.Errorf("session setup status 0x%08x", status)
		}
	}
	idx := bytes.Index(resp, []byte("NTLMSSP\x00"))
	if idx < 0 {
		return nil, fmt.Errorf("NTLMSSP challenge not found")
	}
	msg := resp[idx:]
	if len(msg) < 48 {
		return nil, fmt.Errorf("NTLM challenge too short")
	}
	if binary.LittleEndian.Uint32(msg[8:12]) != 2 {
		return nil, fmt.Errorf("not an NTLM challenge message")
	}
	return msg, nil
}

// enrichFromChallenge fills OS version and target-info names from an NTLM
// CHALLENGE message, delegating AV-pair parsing to pkg/ntlm.
func enrichFromChallenge(info *SMBInfo, msg []byte) {
	if len(msg) >= 56 {
		major := msg[48]
		minor := msg[49]
		build := binary.LittleEndian.Uint16(msg[50:52])
		info.OSVersion = fmt.Sprintf("%d.%d.%d", major, minor, build)
	}

	tiLen := binary.LittleEndian.Uint16(msg[40:42])
	tiOff := binary.LittleEndian.Uint32(msg[44:48])
	if tiLen == 0 || int(tiOff)+int(tiLen) > len(msg) {
		return
	}
	pairs, ok := ntlm.ParseAvPairs(msg[tiOff : tiOff+uint32(tiLen)])
	if !ok {
		return
	}
	if v, ok := pairs[ntlm.MsvAvNbComputerName]; ok {
		info.NetBIOSComputerName = utf16le.DecodeToString(v)
	}
	if v, ok := pairs[ntlm.MsvAvNbDomainName]; ok {
		info.NetBIOSDomainName = utf16le.DecodeToString(v)
	}
	if v, ok := pairs[ntlm.MsvAvDnsComputerName]; ok {
		info.DNSComputerName = utf16le.DecodeToString(v)
	}
	if v, ok := pairs[ntlm.MsvAvDnsDomainName]; ok {
		info.DNSDomainName = utf16le.DecodeToString(v)
	}
	if v, ok := pairs[ntlm.MsvAvDnsTreeName]; ok {
		info.ForestName = utf16le.DecodeToString(v)
	}
}

// smb1Enabled reports whether the server answers an SMBv1-only negotiate.
func smb1Enabled(network, address string, timeout time.Duration) bool {
	conn, err := dial(network, address, timeout)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := writeNetBIOS(conn, buildSMB1Negotiate()); err != nil {
		return false
	}
	resp, err := readNetBIOS(conn)
	if err != nil {
		return false
	}
	return len(resp) >= 4 && string(resp[0:4]) == smb1Magic
}

// ---------------------------------------------------------------------------
// Packet builders
// ---------------------------------------------------------------------------

func buildSMB1Negotiate() []byte {
	dialects := []byte("\x02NT LM 0.12\x00")

	header := make([]byte, 32)
	copy(header[0:4], smb1Magic)
	header[4] = 0x72 // SMB_COM_NEGOTIATE
	header[13] = 0x18
	binary.LittleEndian.PutUint16(header[14:16], 0xc803)

	cmd := []byte{0x00}
	cmd = append(cmd, byte(len(dialects)), byte(len(dialects)>>8))
	cmd = append(cmd, dialects...)
	return append(header, cmd...)
}

func buildSMB2Negotiate() []byte {
	dialects := []uint16{dialect202, dialect210, dialect300, dialect302, dialect311}

	header := make([]byte, 64)
	copy(header[0:4], smb2Magic)
	binary.LittleEndian.PutUint16(header[4:6], 64) // StructureSize
	binary.LittleEndian.PutUint16(header[12:14], smb2Negotiate)
	binary.LittleEndian.PutUint16(header[14:16], 1) // CreditRequest

	nego := make([]byte, 36+len(dialects)*2)
	binary.LittleEndian.PutUint16(nego[0:2], 36)
	binary.LittleEndian.PutUint16(nego[2:4], uint16(len(dialects)))
	binary.LittleEndian.PutUint16(nego[4:6], signingEnabled)
	binary.LittleEndian.PutUint32(nego[8:12], 0x00000040) // GLOBAL_CAP_ENCRYPTION
	for i := 12; i < 28; i++ {
		nego[i] = byte(i) // pseudo client GUID
	}
	for i, d := range dialects {
		binary.LittleEndian.PutUint16(nego[36+i*2:38+i*2], d)
	}
	return append(header, nego...)
}

func buildSessionSetupType1() []byte {
	spnego := wrapSPNEGO(buildNTLMType1())

	header := make([]byte, 64)
	copy(header[0:4], smb2Magic)
	binary.LittleEndian.PutUint16(header[4:6], 64)
	binary.LittleEndian.PutUint16(header[12:14], smb2SessionSetup)
	binary.LittleEndian.PutUint16(header[14:16], 1)  // CreditCharge
	binary.LittleEndian.PutUint16(header[18:20], 31) // CreditRequest
	binary.LittleEndian.PutUint64(header[24:32], 1)  // MessageId

	setup := make([]byte, 24)
	binary.LittleEndian.PutUint16(setup[0:2], 25) // StructureSize (24 + 1 buffer)
	setup[3] = signingEnabled
	binary.LittleEndian.PutUint16(setup[12:14], 64+24) // SecurityBufferOffset
	binary.LittleEndian.PutUint16(setup[14:16], uint16(len(spnego)))

	packet := append(header, setup...)
	return append(packet, spnego...)
}

func buildNTLMType1() []byte {
	msg := []byte("NTLMSSP\x00")
	msg = append(msg, 0x01, 0x00, 0x00, 0x00) // Type 1
	flags := make([]byte, 4)
	// UNICODE | OEM | REQUEST_TARGET | NTLM | ALWAYS_SIGN | EXT_SESSION_SECURITY | VERSION
	binary.LittleEndian.PutUint32(flags, 0xe2088297)
	msg = append(msg, flags...)
	msg = append(msg, 0, 0, 0, 0, 0, 0, 0, 0) // Domain fields
	msg = append(msg, 0, 0, 0, 0, 0, 0, 0, 0) // Workstation fields
	msg = append(msg, 0x06, 0x01, 0x00, 0x00) // Version 6.1
	msg = append(msg, 0x00, 0x00, 0x00, 0x0f) // Build + NTLM revision
	return msg
}

func wrapSPNEGO(ntlmMsg []byte) []byte {
	ntlmOID := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
	mechType := append([]byte{0x06, byte(len(ntlmOID))}, ntlmOID...)
	mechTypeList := asn1Wrap(0x30, mechType)
	mechTypes := asn1Wrap(0xa0, mechTypeList)
	mechToken := asn1Wrap(0xa2, asn1Wrap(0x04, ntlmMsg))
	negTokenInit := asn1Wrap(0x30, append(mechTypes, mechToken...))
	spnegoOID := []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	app := append(spnegoOID, asn1Wrap(0xa0, negTokenInit)...)
	return asn1Wrap(0x60, app)
}

func asn1Wrap(tag byte, data []byte) []byte {
	n := len(data)
	switch {
	case n < 128:
		return append([]byte{tag, byte(n)}, data...)
	case n < 256:
		return append([]byte{tag, 0x81, byte(n)}, data...)
	default:
		return append([]byte{tag, 0x82, byte(n >> 8), byte(n)}, data...)
	}
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

func parseSMB2Negotiate(data []byte) (secMode, dialect uint16, err error) {
	if len(data) < 4 || string(data[0:4]) != smb2Magic {
		return 0, 0, fmt.Errorf("not an SMB2 response")
	}
	if len(data) < 64+64 {
		return 0, 0, fmt.Errorf("SMB2 negotiate response too short")
	}
	body := data[64:]
	secMode = binary.LittleEndian.Uint16(body[2:4])
	dialect = binary.LittleEndian.Uint16(body[4:6])
	return secMode, dialect, nil
}

// ---------------------------------------------------------------------------
// NetBIOS session framing
// ---------------------------------------------------------------------------

func writeNetBIOS(conn net.Conn, payload []byte) error {
	header := []byte{0x00, byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload))}
	_, err := conn.Write(append(header, payload...))
	return err
}

func readNetBIOS(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	length := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	if length == 0 {
		return nil, fmt.Errorf("empty NetBIOS response")
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}
	return data, nil
}
