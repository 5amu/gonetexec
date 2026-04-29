package msrpc

import (
	"encoding/hex"

	"github.com/5amu/gonetexec/pkg/encoder"
)

type RpcBindRequestContextEntry struct {
	ContextID             uint16
	TransItemCount        uint16
	InterfaceUUID         []byte `fixed:"16"`
	InterfaceVersion      uint16
	InterfaceVersionMinor uint16
	TransferSyntaxUUID    []byte `fixed:"16"`
	TransferSyntaxVersion uint32
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/a6b7b03c-4ac5-4c25-8c52-f2bec872ac97
type RpcBindRequest struct {
	RpcHeaderStruct
	MaxSendFrag  uint16
	MaxRecvFrag  uint16
	AssocGroup   uint32
	ContextCount uint32
	RpcBindRequestContextEntry
}

func (rbh *RpcBindRequest) Bytes() []byte {
	b, _ := encoder.Marshal(rbh)
	return b
}

type OpenedPipe int

const (
	SRVSVC OpenedPipe = iota
	NTSVCS
)

func NewRpcBindRequestHeader(callid uint32, op OpenedPipe) *RpcBindRequest {
	var rbr RpcBindRequest
	rbr.RpcHeaderStruct.CallId = callid
	rbr.InterfaceUUID = make([]byte, 16)
	switch op {
	case SRVSVC:
		_, _ = hex.Decode(rbr.InterfaceUUID, SRVSVC_UUID)
		rbr.InterfaceVersion = SRVSVC_VERSION
		rbr.InterfaceVersionMinor = SRVSVC_VERSION_MINOR
	case NTSVCS:
		_, _ = hex.Decode(rbr.InterfaceUUID, SVCCTL_UUID)
		rbr.InterfaceVersion = SVCCTL_VERSION
		rbr.InterfaceVersionMinor = SVCCTL_VERSION_MINOR
	}
	return &rbr
}

func (r *RpcBindRequest) Size() int {
	return 72
}

func (rbr *RpcBindRequest) Encode(b []byte) {
	rbr.RpcVersion = RPC_VERSION
	rbr.RpcVersionMinor = RPC_VERSION_MINOR
	rbr.PacketType = RPC_TYPE_BIND
	rbr.PacketFlags = RPC_PACKET_FLAG_FIRST | RPC_PACKET_FLAG_LAST

	// order = Little-Endian, float = IEEE, char = ASCII
	rbr.DataRepresentation = make([]byte, 4)
	rbr.DataRepresentation[0] = 0x10
	rbr.DataRepresentation[1] = 0
	rbr.DataRepresentation[2] = 0
	rbr.DataRepresentation[3] = 0

	rbr.FragLength = uint16(72) // frag length
	rbr.AuthLength = 0          // auth length
	//rbr.CallId = rbr.CallId     // call id

	rbr.MaxSendFrag = 4280 // max xmit frag
	rbr.MaxRecvFrag = 4280 // max recv frag
	rbr.AssocGroup = 0     // assoc group
	rbr.ContextCount = 1   // num ctx items
	rbr.ContextID = 0      // ctx item[1] .context id
	rbr.TransItemCount = 1 // ctx item[1] .num trans items

	rbr.TransferSyntaxUUID = make([]byte, 16)
	_, _ = hex.Decode(rbr.TransferSyntaxUUID, NDR_UUID)
	rbr.TransferSyntaxVersion = NDR_VERSION

	copy(b, rbr.Bytes())
}

type BindAckDecoder []byte

func (c BindAckDecoder) IsInvalid() bool {
	if len(c) < 24 {
		return true
	}
	if c.Version() != RPC_VERSION {
		return true
	}
	if c.VersionMinor() != RPC_VERSION_MINOR {
		return true
	}
	if c.PacketType() != RPC_TYPE_BIND_ACK {
		return true
	}
	return false
}

func (c BindAckDecoder) Version() uint8 {
	return c[0]
}

func (c BindAckDecoder) VersionMinor() uint8 {
	return c[1]
}

func (c BindAckDecoder) PacketType() uint8 {
	return c[2]
}

func (c BindAckDecoder) CallId() uint32 {
	return le.Uint32(c[12:16])
}
