package optldap

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/5amu/goad/pkg/proxyconn"
	"github.com/go-ldap/ldap/v3"
)

func connect(host string, port int, useSsl bool) (*ldap.Conn, error) {
	ch := make(chan *ldap.Conn)
	er := make(chan error)
	go func() {
		conn, err := proxyconn.GetConnection(host, port)
		if err != nil {
			er <- err
			return
		}
		if useSsl {
			conn = tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
			client := ldap.NewConn(conn, true)
			client.Start()
			ch <- client
			return
		}
		client := ldap.NewConn(conn, false)
		client.Start()
		if err := client.StartTLS(&tls.Config{InsecureSkipVerify: true}); err == nil {
			ch <- client
			return
		}
		client.Close()

		conn, err = proxyconn.GetConnection(host, port)
		if err != nil {
			er <- err
		}
		client = ldap.NewConn(conn, false)
		client.Start()
		ch <- client
	}()

	var ret *ldap.Conn
	select {
	case ret = <-ch:
	case err := <-er:
		return nil, fmt.Errorf("%v", err)
	case <-time.After(2 * time.Second):
		return nil, fmt.Errorf("timeout reached when contacting LDAP server")
	}
	return ret, nil
}

func authenticate(c *ldap.Conn, realm, username, password string) error {
	if c == nil {
		return fmt.Errorf("not connected")
	}

	if err := c.NTLMBind(realm, username, password); err == nil {
		return nil
	}

	switch password {
	case "":
		if err := c.UnauthenticatedBind(username); err != nil {
			return err
		}
	default:
		if err := c.Bind(username, password); err != nil {
			return err
		}
	}
	return nil
}
