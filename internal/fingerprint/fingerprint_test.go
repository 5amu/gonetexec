package fingerprint

import (
	"encoding/binary"
	"testing"

	"github.com/mandiant/gopacket/pkg/ntlm"
)

func TestDialectString(t *testing.T) {
	cases := map[uint16]string{
		dialect202: "SMB 2.0.2",
		dialect210: "SMB 2.1",
		dialect300: "SMB 3.0",
		dialect302: "SMB 3.0.2",
		dialect311: "SMB 3.1.1",
		0:          "unknown",
		0x1234:     "0x1234",
	}
	for d, want := range cases {
		info := &SMBInfo{Dialect: d}
		if got := info.DialectString(); got != want {
			t.Errorf("Dialect 0x%04x: got %q want %q", d, got, want)
		}
	}
}

func TestParseSMB2Negotiate(t *testing.T) {
	// Minimal SMB2 negotiate response: 64-byte header + >=64-byte body.
	resp := make([]byte, 128)
	copy(resp[0:4], smb2Magic)
	body := resp[64:]
	binary.LittleEndian.PutUint16(body[2:4], signingEnabled|signingRequired)
	binary.LittleEndian.PutUint16(body[4:6], dialect311)

	secMode, dialect, err := parseSMB2Negotiate(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dialect != dialect311 {
		t.Errorf("dialect: got 0x%04x want 0x%04x", dialect, dialect311)
	}
	if secMode&signingRequired == 0 || secMode&signingEnabled == 0 {
		t.Errorf("secMode: got 0x%04x, expected signing enabled+required", secMode)
	}
}

func TestParseSMB2NegotiateRejectsNonSMB2(t *testing.T) {
	if _, _, err := parseSMB2Negotiate([]byte("\xffSMBxxxx")); err == nil {
		t.Error("expected error for non-SMB2 response")
	}
	if _, _, err := parseSMB2Negotiate(nil); err == nil {
		t.Error("expected error for empty response")
	}
}

func toUTF16LE(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

func avPair(id uint16, val []byte) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint16(b[0:2], id)
	binary.LittleEndian.PutUint16(b[2:4], uint16(len(val)))
	return append(b, val...)
}

func TestEnrichFromChallenge(t *testing.T) {
	var ti []byte
	ti = append(ti, avPair(ntlm.MsvAvNbComputerName, toUTF16LE("WS01"))...)
	ti = append(ti, avPair(ntlm.MsvAvNbDomainName, toUTF16LE("CORP"))...)
	ti = append(ti, avPair(ntlm.MsvAvDnsComputerName, toUTF16LE("ws01.corp.local"))...)
	ti = append(ti, avPair(ntlm.MsvAvDnsDomainName, toUTF16LE("corp.local"))...)
	ti = append(ti, avPair(ntlm.MsvAvDnsTreeName, toUTF16LE("corp.local"))...)
	ti = append(ti, avPair(ntlm.MsvAvEOL, nil)...)

	msg := make([]byte, 56)
	copy(msg[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(msg[8:12], 2)
	// Version 10.0.19041
	msg[48] = 10
	msg[49] = 0
	binary.LittleEndian.PutUint16(msg[50:52], 19041)
	// Target info fields: len at [40:42], offset at [44:48].
	binary.LittleEndian.PutUint16(msg[40:42], uint16(len(ti)))
	binary.LittleEndian.PutUint32(msg[44:48], 56)
	msg = append(msg, ti...)

	var info SMBInfo
	enrichFromChallenge(&info, msg)

	if info.OSVersion != "10.0.19041" {
		t.Errorf("OSVersion: got %q want %q", info.OSVersion, "10.0.19041")
	}
	if info.NetBIOSComputerName != "WS01" {
		t.Errorf("NetBIOSComputerName: got %q", info.NetBIOSComputerName)
	}
	if info.NetBIOSDomainName != "CORP" {
		t.Errorf("NetBIOSDomainName: got %q", info.NetBIOSDomainName)
	}
	if info.DNSComputerName != "ws01.corp.local" {
		t.Errorf("DNSComputerName: got %q", info.DNSComputerName)
	}
	if info.DNSDomainName != "corp.local" {
		t.Errorf("DNSDomainName: got %q", info.DNSDomainName)
	}
	if info.ForestName != "corp.local" {
		t.Errorf("ForestName: got %q", info.ForestName)
	}
}

func TestNegotiatePacketsAreWellFormed(t *testing.T) {
	if got := buildSMB2Negotiate(); string(got[0:4]) != smb2Magic {
		t.Error("SMB2 negotiate missing SMB2 magic")
	}
	if got := buildSMB1Negotiate(); string(got[0:4]) != smb1Magic {
		t.Error("SMB1 negotiate missing SMB1 magic")
	}
	// The session setup must carry an NTLM type-1 token inside the SPNEGO blob.
	setup := buildSessionSetupType1()
	if string(setup[0:4]) != smb2Magic {
		t.Error("session setup missing SMB2 magic")
	}
}
