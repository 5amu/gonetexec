package dcerpc

import (
	"encoding/binary"
	"fmt"
	"math/rand"

	"github.com/5amu/gonetexec/pkg/encoder"
)

// PDU PacketType
// https://pubs.opengroup.org/onlinepubs/9629399/chap12.htm
const (
	PDURequest = iota
	PDUPing
	PDUResponse
	PDUFault
	PDUWorking
	PDUNoCall
	PDUReject
	PDUAck
	PDUClCancel
	PDUFack
	PDUCancelAck
	PDUBind
	PDUBindAck
	PDUBindNak
	PDUAlterContext
	PDUAlterContextResp
	PDUShutdown
	PDUCoCancel
	PDUOrphaned
)

// PDU PacketFlags
// https://pubs.opengroup.org/onlinepubs/9629399/chap12.htm
const (
	FirstFrag         = 0x01
	LastFrag          = 0x02
	PDUFlagPending    = 0x03
	CancelPending     = 0x04
	PDUFlagNoFack     = 0x08
	PDUFlagMayBe      = 0x10
	PDUFlagIdemPotent = 0x20
	PDUFlagBroadcast  = 0x40
	PDUFlagReserved80 = 0x80
)

// Supported version is 5.0
const (
	PDUVersion      = 5
	PDUVersionMinor = 0
)

type HeaderStruct struct {
	RpcVersion         uint8
	RpcVersionMinor    uint8
	PacketType         uint8
	PacketFlags        byte
	DataRepresentation []byte `smb:"fixed:4"`
	FragLength         uint16
	AuthLength         uint16
	CallId             uint32
}

func NewHeader() *HeaderStruct {
	return &HeaderStruct{
		RpcVersion:         PDUVersion,
		RpcVersionMinor:    PDUVersionMinor,
		PacketType:         PDURequest,
		PacketFlags:        FirstFrag | LastFrag,
		DataRepresentation: []byte{0x10, 0, 0, 0}, // Little-Endian, float = IEEE, char = ASCII
		FragLength:         0,                     // must be updated before sending
		AuthLength:         0,
		CallId:             rand.Uint32(),
	}
}

type RequestStruct struct {
	HeaderStruct
	AllocHint uint32
	ContextID uint16
	OpNum     uint16
	Payload   interface{}
}

func (req *RequestStruct) Bytes() []byte {
	b, _ := encoder.Marshal(req)
	sz := len(b)

	// Set FragLength to the size of the RPC request
	binary.LittleEndian.PutUint16(b[8:10], uint16(sz))

	// Set AllocHint to the size of the RPC body (the header is 24 bytes)
	binary.LittleEndian.PutUint32(b[24:28], uint32(sz)-24)
	return b
}

type ResponseStruct struct {
	HeaderStruct
	AllocHint   uint32 // len of stub
	ContextID   uint16
	CancelCount uint8
	Reserved    uint8
	Stub        []byte
	ReturnCode  uint32
}

func ParseResponse(b []byte) (rs ResponseStruct, err error) {
	if len(b) < 24 {
		return rs, fmt.Errorf("response is too short (<24 bytes)")
	}

	var header HeaderStruct
	if err = encoder.Unmarshal(b[0:24], &header); err != nil {
		return rs, err
	}

	rs.HeaderStruct = header
	binary.LittleEndian.PutUint32(b[24:28], rs.AllocHint)

	l := 32 + int(rs.AllocHint) + 4
	if len(b) != l {
		return rs, fmt.Errorf("response is too short (<%d bytes)", l)
	}

	binary.LittleEndian.PutUint16(b[28:30], rs.ContextID)
	rs.CancelCount = b[30]
	rs.Stub = b[32 : 32+rs.AllocHint]
	binary.LittleEndian.PutUint32(b[32+rs.AllocHint:], rs.ReturnCode)
	return rs, nil
}
