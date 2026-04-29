package responder

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"github.com/lkarlslund/binstruct"
)

type NTLMSource string

const (
	SMB NTLMSource = "SMB"
)

type NTLMResult struct {
	User, WorkStation, Target string
	Challenge                 []byte
	Hash                      []byte
	MoreHash                  []byte
	GatheredFrom              NTLMSource
}

func (nr NTLMResult) String() string {
	if len(nr.MoreHash) == 0 {
		return fmt.Sprintf("%s::%s:%X:%X\n",
			nr.User,
			nr.WorkStation,
			nr.Challenge,
			nr.Hash)
	}
	return fmt.Sprintf("%s::%s:%X:%X:%X\n",
		nr.User,
		nr.Target,
		nr.Challenge,
		nr.Hash,
		nr.MoreHash,
	)
}

type NTLMMessageHeader struct {
	Header      []byte `bin:"len:8"`
	MessageType uint32
}

type OffsetData struct {
	Length uint16
	Space  uint16
	Offset uint32
	Data   []byte `bin:"len:Length,offsetStart:Offset,offsetRestore:true"`
}

type NTLMMessage2 struct {
	NTLMMessageHeader
	Target    OffsetData
	Flags     uint32
	Challenge []byte `bin:"len:8"`
	// Context []byte `bin:"len:8"`
	// TargetInformation []byte `bin:"len:8"`
	// OSVersion []byte `bin:"len:8"`
}

type NTLMMessage3 struct {
	NTLMMessageHeader
	LMHash          OffsetData
	NTLMHash        OffsetData
	TargetName      OffsetData
	UserName        OffsetData
	WorkStationName OffsetData
	SessionKey      OffsetData
	Flags           uint32
	OSVersion       []byte `bin:"len:8"`
}

type MessageType uint32

const (
	NtLmNegotiate MessageType = iota + 1
	NtLmChallenge
	NtLmAuthenticate
	MessageUndefined
)

func IsNTLM(pd []byte) bool {
	// Signature (8 bytes): An 8-byte character array that MUST contain the
	// ASCII string ('N', 'T', 'L', 'M', 'S', 'S', 'P', '\0').
	return bytes.Contains(pd, []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00})
}

func GetMessageType(pd []byte) MessageType {
	offset := bytes.Index(pd, []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00})
	if offset == -1 {
		// Does not have NTLM message header
		return MessageUndefined
	}
	// This is the start of the raw NTLM message
	var header NTLMMessageHeader
	err := binstruct.UnmarshalLE(pd[offset:], &header)
	if err != nil {
		return MessageUndefined
	}

	switch MessageType(header.MessageType) {
	case NtLmNegotiate:
		return NtLmNegotiate
	case NtLmChallenge:
		return NtLmChallenge
	case NtLmAuthenticate:
		return NtLmAuthenticate
	}
	return MessageUndefined
}

func GetChallenge(pd []byte) []byte {
	offset := bytes.Index(pd, []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00})
	if offset == -1 {
		// Does not have NTLM message header
		return nil
	}

	var message NTLMMessage2
	if err := binstruct.UnmarshalLE(pd[offset:], &message); err != nil {
		return nil
	}
	return message.Challenge
}

func utf16String(b []byte) string {
	if len(b)%2 != 0 {
		b = append(b, 0)
	}
	data := make([]uint16, len(b)/2)
	for i := 0; i < len(data); i++ {
		data[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(data))
}

func NewNTLMResult(pd []byte, challenge []byte) (*NTLMResult, error) {
	offset := bytes.Index(pd, []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00})
	if offset == -1 {
		// Does not have NTLM message header
		return nil, fmt.Errorf("not an NTLM message")
	}

	var msg3 NTLMMessage3
	if err := binstruct.UnmarshalLE(pd[offset:], &msg3); err != nil {
		return nil, err
	}

	if msg3.NTLMHash.Length == 24 {
		return &NTLMResult{
		User:        utf16String(msg3.UserName.Data),
		WorkStation: utf16String(msg3.WorkStationName.Data),
		Challenge:   challenge,
		Hash:        msg3.NTLMHash.Data,
		}, nil
	} else if msg3.NTLMHash.Length > 24 {
		return &NTLMResult{
			User:        utf16String(msg3.UserName.Data),
			WorkStation: utf16String(msg3.WorkStationName.Data),
			Target:      utf16String(msg3.TargetName.Data),
			Challenge:   challenge,
			Hash:        msg3.NTLMHash.Data[:16],
			MoreHash:    msg3.NTLMHash.Data[16:],
		}, nil
	}
	return nil, fmt.Errorf(
		"received short NTLM hash: %s:%s:%s:%X:%X:%X",
		utf16String(msg3.UserName.Data),
		utf16String(msg3.WorkStationName.Data),
		utf16String(msg3.TargetName.Data),
		challenge,
		msg3.NTLMHash.Data,
		msg3.LMHash.Data,
	)
}
