package dcerpc

import (
	"encoding/binary"
	"fmt"

	"github.com/5amu/gonetexec/pkg/encoder"
)

// NDR
// x32: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/b6090c2b-f44a-47a1-a13b-b82ade0137b2
var MSRPC_NDR32 MsrpcUUID = MsrpcUUID{
	UUID:    "8a885d04-1ceb-11c9-9fe8-08002b104860",
	Version: 2,
}

// NDR
// x64: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/dca648a5-42d3-432c-9927-2f22e50fa266
var MSRPC_NDR64 MsrpcUUID = MsrpcUUID{
	UUID:    "71710533-beba-4937-8319-b5dbef9ccc36",
	Version: 1,
}

type BindContextEntry struct {
	ContextID             uint16
	TransItemCount        uint16
	InterfaceUUID         []byte `smb:"fixed:16"`
	InterfaceVersion      uint16
	InterfaceVersionMinor uint16
	TransferSyntaxUUID    []byte `smb:"fixed:16"`
	TransferSyntaxVersion uint32
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/a6b7b03c-4ac5-4c25-8c52-f2bec872ac97
type BindStruct struct {
	HeaderStruct
	MaxSendFrag  uint16
	MaxRecvFrag  uint16
	AssocGroup   uint32
	ContextCount uint32
	CtxEntries   []byte
}

func NewBindStruct(syntax string, syntaxVer int, iface string, ifaceVer int, ifaceVerMinor int) *BindStruct {
	header := NewHeader()
	header.PacketType = PDUBind
	b, _ := encoder.Marshal(BindContextEntry{
		ContextID:             0,
		TransItemCount:        1,
		InterfaceUUID:         encoder.UUIDFromString(iface),
		InterfaceVersion:      uint16(ifaceVer),
		InterfaceVersionMinor: uint16(ifaceVerMinor),
		TransferSyntaxUUID:    encoder.UUIDFromString(syntax),
		TransferSyntaxVersion: uint32(syntaxVer),
	})
	return &BindStruct{
		HeaderStruct: *header,
		MaxSendFrag:  4280,
		MaxRecvFrag:  4280,
		AssocGroup:   0,
		ContextCount: 1,
		CtxEntries:   b,
	}
}

func (req *BindStruct) Bytes() []byte {
	b, _ := encoder.Marshal(req)
	sz := len(b)

	// Set FragLength to the size of the RPC request
	binary.LittleEndian.PutUint16(b[8:10], uint16(sz))
	return b
}

type AckResult struct {
	Result         uint16
	TransferSyntax []byte `smb:"fixed:16"`
	SyntaxVersion  uint32
}

type AckResponse struct {
	MaxXmitFrag      uint16
	MaxRecvFrag      uint16
	AssocGroup       uint32
	SecondaryAddrLen uint16
	SecondaryAddr    []byte
	NumResults       uint8
	CtxItems         []AckResult
}

type VersionT struct {
	Major uint8
	Minor uint8
}

type PrtVersionsSupportedT struct {
	NProtocols uint8
	PProtocols []VersionT
}

type NackResponse struct {
	ProviderRejectReason uint16
	Versions             PrtVersionsSupportedT
	Signature            []byte `smb:"fixed:16"` // optional
	ExtendedErrorInfo    []byte
}

// Nack reasons
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/6f81bffe-8fce-498a-addf-94654a57b329
const (
	REASON_NOT_SPECIFIED               = 0x00
	TEMPORARY_CONGESTION               = 0x01 // not used
	LOCAL_LIMIT_EXCEEDED               = 0x02
	PROTOCOL_VERSION_NOT_SPECIFIED     = 0x04
	AUTHENTICATION_TYPE_NOT_RECOGNIZED = 0x08
	INVALID_CHECKSUM                   = 0x09
)

type BindResponse struct {
	HeaderStruct
	Body interface{}
}

func ParseBindResponse(res []byte) (br BindResponse, err error) {
	if len(res) < 24 {
		return br, fmt.Errorf("bind response length is less than header size")
	}

	var header HeaderStruct
	err = encoder.Unmarshal(res[0:24], &header)
	if err != nil {
		return br, err
	}

	br.HeaderStruct = header
	b := res[24:]

	switch br.PacketType {
	case PDUBindAck:
		if len(b) < 10 {
			return br, fmt.Errorf("ack response too small (<10 bytes)")
		}

		var secAddrLen uint16 = binary.LittleEndian.Uint16(b[8:10])
		var nRes uint8 = uint8(b[10+int(secAddrLen)+1])

		l := 10 + int(secAddrLen) + 1 + int(nRes*22)
		if len(b) < l {
			return br, fmt.Errorf("ack response too small (<%d bytes)", l)
		}

		var ack AckResponse
		ack.MaxRecvFrag = binary.LittleEndian.Uint16(b[0:2])
		ack.MaxRecvFrag = binary.LittleEndian.Uint16(b[2:4])
		ack.AssocGroup = binary.LittleEndian.Uint32(b[4:8])
		ack.SecondaryAddrLen = secAddrLen
		ack.SecondaryAddr = b[10 : 10+secAddrLen]
		ack.NumResults = nRes

		off := 10 + secAddrLen + 1
		for i := 0; i < int(nRes); i++ {
			var ackRes AckResult
			ackRes.Result = binary.LittleEndian.Uint16(b[off : off+2])
			ackRes.TransferSyntax = b[off+2 : off+18]
			ackRes.SyntaxVersion = binary.LittleEndian.Uint32(b[off+18 : off+22])
			off += 22
			ack.CtxItems = append(ack.CtxItems, ackRes)
		}
		br.Body = ack
		return br, nil
	case PDUBindNak:
		// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/92ba4942-0b1f-41aa-8924-69dd6e49b546
		//
		// typedef struct {
		//	u_int8 n_protocols; /* count */
		// 	p_rt_version_t [size_is(n_protocols)] p_protocols[];
		// } p_rt_versions_supported_t;
		//
		// typedef version_t p_rt_version_t;
		//
		// typedef struct {
		//	u_int8 major;
		//	u_int8 minor;
		// } version_t;
		if len(b) < 3 {
			return br, fmt.Errorf("nack response too small (<3 bytes)")
		}

		var nack NackResponse
		nack.ProviderRejectReason = binary.LittleEndian.Uint16(b[0:2])
		nack.Versions.NProtocols = b[2]

		l := 3 + int(nack.Versions.NProtocols)*2
		if len(b) < l {
			return br, fmt.Errorf("nack response too small (<%d bytes)", l)
		}

		off := 3
		for i := 0; i < int(nack.Versions.NProtocols); i++ {
			var vers VersionT
			vers.Major = b[off]
			vers.Minor = b[off+1]
			off += 2
			nack.Versions.PProtocols = append(nack.Versions.PProtocols, vers)
		}

		// if frag_length > header + protocol versions => signature
		if int(br.FragLength) > off {
			nack.Signature = b[off : off+16]
		}

		// there might be an extended blob present
		if int(br.FragLength) > off+16 {
			nack.ExtendedErrorInfo = b[off+16:]
		}
		return br, NackReason(br)
	}
	return br, fmt.Errorf("unexpected bind response")
}

func NackReason(br BindResponse) error {
	nack, ok := br.Body.(NackResponse)
	if !ok {
		return fmt.Errorf("not a NackResponse")
	}

	switch nack.ProviderRejectReason {
	case REASON_NOT_SPECIFIED:
		return fmt.Errorf("error code %d: REASON_NOT_SPECIFIED", nack.ProviderRejectReason)
	case TEMPORARY_CONGESTION:
		return fmt.Errorf("error code %d: TEMPORARY_CONGESTION", nack.ProviderRejectReason)
	case LOCAL_LIMIT_EXCEEDED:
		return fmt.Errorf("error code %d: LOCAL_LIMIT_EXCEEDED", nack.ProviderRejectReason)
	case PROTOCOL_VERSION_NOT_SPECIFIED:
		return fmt.Errorf("error code %d: PROTOCOL_VERSION_NOT_SPECIFIED", nack.ProviderRejectReason)
	case AUTHENTICATION_TYPE_NOT_RECOGNIZED:
		return fmt.Errorf("error code %d: AUTHENTICATION_TYPE_NOT_RECOGNIZED", nack.ProviderRejectReason)
	case INVALID_CHECKSUM:
		return fmt.Errorf("error code %d: INVALID_CHECKSUM", nack.ProviderRejectReason)
	default:
		return fmt.Errorf("unknown code %d", nack.ProviderRejectReason)
	}
}
