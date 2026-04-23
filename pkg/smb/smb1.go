package smb

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/5amu/gonetexec/pkg/encoder"
)

// SMBv1 is supported as far as DETECTION goes. In 2024 I'm not willing to
// fully support it... I guess that help would be appreciated wut not actively
// wanted. Thank you for your understanding.
const ProtocolSmb = "\xFFSMB"
const (
	DialectSmb_1_0   = "\x02NT LM 0.12\x00"
	DialectSmb_2_0_2 = "\x02SMB 2.002\x00"
	DialectSmb_2_Wld = "\x02SMB 2.???\x00"
)

type HeaderV1 struct {
	ProtocolID       []byte `smb:"fixed:4"`
	Command          uint8
	Status           uint32
	Flags            uint8
	Flags2           uint16
	PIDHigh          uint16
	SecurityFeatures []byte `smb:"fixed:8"`
	Reserved         uint16
	TID              uint16
	PIDLow           uint16
	UID              uint16
	MID              uint16
}

type NegotiateReqV1 struct {
	HeaderV1
	WordCount uint8
	ByteCount uint16  // hardcoded to 12
	Dialects  []uint8 `smb:"fixed:12"`
}

type V1Client struct {
	Host      string
	Port      int
	Conn      net.Conn
	messageId int
}

func NewV1Client() *V1Client {
	return &V1Client{}
}

func (c *V1Client) WithHostPort(host string, port int) *V1Client {
	c.Host = host
	c.Port = port
	return c
}

func (c *V1Client) WithConn(conn net.Conn) *V1Client {
	c.Conn = conn
	return c
}

func (c *V1Client) IsSMBv1() bool {
	if c.Conn == nil {
		var err error
		c.Conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", c.Host, c.Port))
		if err != nil {
			return false
		}
	}

	c.messageId = 0
	req := NegotiateReqV1{
		HeaderV1: HeaderV1{
			ProtocolID:       []byte(ProtocolSmb),
			Command:          0x72, //SMB1 Negotiate
			Status:           0,
			Flags:            0x18,
			Flags2:           0xc801,
			PIDHigh:          0,
			SecurityFeatures: []byte{0, 0, 0, 0, 0, 0, 0, 0},
			Reserved:         0,
			TID:              0xffff,
			PIDLow:           0xfeff,
			UID:              0,
			MID:              0,
		},
		WordCount: 0,
		ByteCount: 12,
		Dialects:  []uint8(DialectSmb_1_0),
	}

	pkt, err := encoder.Marshal(req)
	if err != nil {
		return false
	}

	buf, err := send(c.Conn, pkt)
	if err != nil {
		return false
	}
	return string(buf[0:4]) == ProtocolSmb
}

func send(conn net.Conn, buf []byte) (res []byte, err error) {
	b := new(bytes.Buffer)
	if err = binary.Write(b, binary.BigEndian, uint32(len(buf))); err != nil {
		return nil, err
	}

	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	if _, err = rw.Write(append(b.Bytes(), buf...)); err != nil {
		return nil, err
	}
	rw.Flush()

	var size uint32
	if err = binary.Read(rw, binary.BigEndian, &size); err != nil {
		return
	}
	if size > 0x00FFFFFF || size < 4 {
		return nil, fmt.Errorf("invalid NetBIOS session message")
	}

	data := make([]byte, size)
	l, err := io.ReadFull(rw, data)
	if err != nil {
		return nil, err
	}
	if uint32(l) != size {
		return nil, fmt.Errorf("message size invalid")
	}
	return data, nil
}
