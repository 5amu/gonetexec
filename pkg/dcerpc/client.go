package dcerpc

import (
	"net"

	"github.com/5amu/gonetexec/pkg/auth"
)

type Client struct {
	// expose functions like the Conn interface https://pkg.go.dev/net#Conn
	// could also be using a named pipe or NETBIOS, as long as the methods
	// are exposed correctly
	Transport          net.Conn
	Authenticator      *auth.SpnegoClient
	SupportsEncryption bool
	Encrypt            bool
	X64Syntax          bool
}

func (c *Client) Send(pkt []byte) ([]byte, error) {
	if c.Authenticator != nil {
		// add authentication
	}
	if c.SupportsEncryption && c.Encrypt {
		// encrypt pkt
	}
	return nil, nil
}

func (c *Client) Authenticate() error {
	if c.Authenticator == nil {
		return nil
	}
	return nil
}

func (c *Client) SignPkt(pkt []byte) ([]byte, error) {
	return nil, nil
}
