package msrpc

import (
	"slices"

	"github.com/5amu/gonetexec/pkg/smb/internal/utf16le"
)

var SRVSVC_UUID = []byte("c84f324b7016d30112785a47bf6ee188")

const (
	SRVSVC_VERSION       = 3
	SRVSVC_VERSION_MINOR = 0

	OP_NET_SHARE_ENUM = 15
)

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/c4a98e7b-d416-439c-97bd-4d9f52f8ba52
type NetrShareEnumRequest struct {
	ServerName struct {
		ReferentID uint32
		MaxCount   uint32
		Offset     uint32
		Count      uint32
		Name       []byte
	}
	Level        uint32
	Ctr          uint32
	ReferentID   uint32
	CountCtr1    uint32
	PointerCtr1  uint32
	MaxBuffer    uint32
	ResumeHandle uint32
}

type NetShareEnumAllRequest struct {
	CallId     uint32
	ServerName string
	Level      uint32
}

func NewNetShareEnumAllRequest(callid uint32, srvname string) *NetShareEnumAllRequest {
	var nsenum NetShareEnumAllRequest
	nsenum.CallId = callid
	nsenum.ServerName = srvname
	nsenum.Level = 1 // level 1 seems to be portable
	return &nsenum
}

func (r *NetShareEnumAllRequest) Size() int {
	off := 40 + utf16le.EncodedStringLen(r.ServerName) + 2
	off = roundup(off, 4)
	off += 24 // header
	off += 4  // resume handle
	return off
}

func (r *NetShareEnumAllRequest) Encode(b []byte) {
	var srvname []byte = make([]byte, utf16le.EncodedStringLen(r.ServerName))
	utf16le.EncodeString(srvname, r.ServerName)
	srvname = append(srvname, []byte{0, 0}...)

	var count int = utf16le.EncodedStringLen(r.ServerName)/2 + 1

	req := RpcRequestStruct{
		RpcHeaderStruct: RpcHeaderStruct{
			RpcVersion:         RPC_VERSION,
			RpcVersionMinor:    RPC_VERSION_MINOR,
			PacketType:         RPC_TYPE_REQUEST,
			PacketFlags:        RPC_PACKET_FLAG_FIRST | RPC_PACKET_FLAG_LAST,
			DataRepresentation: []byte{0x10, 0, 0, 0},
			AuthLength:         0,
			CallId:             r.CallId,
		},
		ContextID: 0,
		OpNum:     OP_NET_SHARE_ENUM,
		Payload: NetrShareEnumRequest{
			ServerName: struct {
				ReferentID uint32
				MaxCount   uint32
				Offset     uint32
				Count      uint32
				Name       []byte
			}{
				ReferentID: 0x20000,
				MaxCount:   uint32(count),
				Offset:     0,
				Count:      uint32(count),
				Name:       srvname,
			},
			Level:        r.Level,
			Ctr:          1,
			ReferentID:   0x20004,
			CountCtr1:    0,
			PointerCtr1:  0,
			MaxBuffer:    0xffffffff,
			ResumeHandle: 0,
		},
	}
	copy(b, req.Bytes())
}

type NetShareEnumAllResponseDecoder []byte

func (c NetShareEnumAllResponseDecoder) IsInvalid() bool {
	return len(c) < 24 || slices.Compare(c[0:3], []byte{RPC_VERSION, RPC_VERSION_MINOR, RPC_TYPE_RESPONSE}) != 0
}

func (c NetShareEnumAllResponseDecoder) CallId() uint32 {
	return le.Uint32(c[12:16])
}

func (c NetShareEnumAllResponseDecoder) IsIncomplete() bool {
	if len(c) < 48 {
		return true
	}

	level := le.Uint32(c[24:28])

	count := int(le.Uint32(c[36:40]))

	switch level {
	case 0:
		offset := 48 + count*4 // name pointer
		if len(c) < offset {
			return true
		}

		for i := 0; i < count; i++ {
			if len(c) < offset+12 {
				return true
			}

			noff := int(le.Uint32(c[offset+4 : offset+8]))    // offset
			nlen := int(le.Uint32(c[offset+8:offset+12])) * 2 // actual count
			offset = roundup(offset+12+noff+nlen, 4)

			if len(c) < offset {
				return true
			}
		}
	case 1:
		offset := 48 + count*12
		if len(c) < offset {
			return true
		}

		for i := 0; i < count; i++ {
			{ // name
				if len(c) < offset+12 {
					return true
				}

				noff := int(le.Uint32(c[offset+4 : offset+8]))    // offset
				nlen := int(le.Uint32(c[offset+8:offset+12])) * 2 // actual count
				offset = roundup(offset+12+noff+nlen, 4)

				if len(c) < offset {
					return true
				}
			}

			{ // comment
				if len(c) < offset+12 {
					return true
				}

				coff := int(le.Uint32(c[offset+4 : offset+8]))    // offset
				clen := int(le.Uint32(c[offset+8:offset+12])) * 2 // actual count
				offset = roundup(offset+12+coff+clen, 4)

				if len(c) < offset {
					return true
				}
			}
		}
	default:
		// TODO not supported yet
		return true
	}

	return false
}

func (c NetShareEnumAllResponseDecoder) Buffer() []byte {
	return c[24:]
}

func (c NetShareEnumAllResponseDecoder) ShareNameList() []string {
	level := le.Uint32(c[24:28])

	count := int(le.Uint32(c[36:40]))

	ss := make([]string, count)

	switch level {
	case 0:
		offset := 48 + count*4 // name pointer
		for i := 0; i < count; i++ {
			noff := int(le.Uint32(c[offset+4 : offset+8]))    // offset
			nlen := int(le.Uint32(c[offset+8:offset+12])) * 2 // actual count

			ss[i] = utf16le.DecodeToString(c[offset+12+noff : offset+12+noff+nlen])

			offset = roundup(offset+12+noff+nlen, 4)
		}
	case 1:
		offset := 48 + count*12
		for i := 0; i < count; i++ {
			{ // name
				noff := int(le.Uint32(c[offset+4 : offset+8]))    // offset
				nlen := int(le.Uint32(c[offset+8:offset+12])) * 2 // actual count

				ss[i] = utf16le.DecodeToString(c[offset+12+noff : offset+12+noff+nlen])

				offset = roundup(offset+12+noff+nlen, 4)
			}

			{ // comment
				coff := int(le.Uint32(c[offset+4 : offset+8]))    // offset
				clen := int(le.Uint32(c[offset+8:offset+12])) * 2 // actual count
				offset = roundup(offset+12+coff+clen, 4)
			}
		}
	default:
		// TODO not supported yet
		return nil
	}

	return ss
}
