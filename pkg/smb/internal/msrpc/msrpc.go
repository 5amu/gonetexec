package msrpc

import (
	"encoding/binary"

	"github.com/5amu/gonetexec/pkg/encoder"
)

var le = binary.LittleEndian

func roundup(x, align int) int {
	return (x + (align - 1)) &^ (align - 1)
}

// PDU PacketType
// https://pubs.opengroup.org/onlinepubs/9629399/chap12.htm
const (
	PDURequest            = 0
	PDUPing               = 1
	PDUResponse           = 2
	PDUFault              = 3
	PDUWorking            = 4
	PDUNoCall             = 5
	PDUReject             = 6
	PDUAck                = 7
	PDUCl_Cancel          = 8
	PDUFack               = 9
	PDUCancel_Ack         = 10
	PDUBind               = 11
	PDUBind_Ack           = 12
	PDUBind_Nak           = 13
	PDUAlter_Context      = 14
	PDUAlter_Context_Resp = 15
	PDUShutdown           = 17
	PDUCo_Cancel          = 18
	PDUOrphaned           = 19
)

// PDU PacketFlags
// https://pubs.opengroup.org/onlinepubs/9629399/chap12.htm
const (
	//PDUFlagReserved_01 = 0x01
	FirstFrag = 0x01
	LastFrag  = 0x02
	//PDUFlagLastFrag    = 0x02
	PDUFlagPending = 0x03
	CancelPending  = 0x04
	//PDUFlagFrag        = 0x04
	PDUFlagNoFack      = 0x08
	PDUFlagMayBe       = 0x10
	PDUFlagIdemPotent  = 0x20
	PDUFlagBroadcast   = 0x40
	PDUFlagReserved_80 = 0x80
)

const (
	RPC_VERSION       = 5
	RPC_VERSION_MINOR = 0

	RPC_TYPE_REQUEST  = 0
	RPC_TYPE_RESPONSE = 2
	RPC_TYPE_BIND     = 11
	RPC_TYPE_BIND_ACK = 12

	RPC_PACKET_FLAG_FIRST = 0x01
	RPC_PACKET_FLAG_LAST  = 0x02

	NDR_VERSION   = 2
	NDR64_VERSION = 1
)

var (
	// NDR v1: 8a885d04-1ceb-11c9-9fe8-08002b104860
	NDR_UUID = []byte("045d888aeb1cc9119fe808002b104860")

	// NDR64 v1: 71710533-beba-4937-8319-b5dbef9ccc36
	NDR64_UUID = []byte("33057171babe37498319b5dbef9ccc36")
)

type RpcHeaderStruct struct {
	RpcVersion         uint8
	RpcVersionMinor    uint8
	PacketType         uint8
	PacketFlags        byte
	DataRepresentation []byte `smb:"fixed:4"`
	FragLength         uint16
	AuthLength         uint16
	CallId             uint32
}

type RpcRequestStruct struct {
	RpcHeaderStruct
	AllocHint uint32
	ContextID uint16
	OpNum     uint16
	Payload   interface{}
}

func (req *RpcRequestStruct) Bytes() []byte {
	// surely there is something more efficient
	b, _ := encoder.Marshal(req)
	sz := len(b)
	req.FragLength = uint16(sz)
	req.AllocHint = uint32(sz) - 24
	b, _ = encoder.Marshal(req)
	return b
}
