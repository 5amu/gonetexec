package optkrb5

import (
	"fmt"
	"strings"

	"github.com/5amu/goad/pkg/kclient"
	kconfig "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
)

// Client is a kerberos client
type KerberosClient struct {
	Realm  string
	KDCs   map[int]string
	config *kconfig.Config
	client *kclient.Client
}

func buildTemplate(realm, domainController string) string {
	if domainController == "" {
		krbTemplate := "[libdefaults]\ndns_lookup_kdc = true\ndefault_realm = {{Realm}}"
		return strings.ReplaceAll(krbTemplate, "{{Realm}}", realm)
	} else {
		krbTemplate := "[libdefaults]\ndefault_realm = {{Realm}}\n[realms]\n{{Realm}} = {\n\tkdc = {{DomainController}}\n\tadmin_server = {{DomainController}}\n}"
		return strings.ReplaceAll(strings.ReplaceAll(krbTemplate, "{{Realm}}", realm), "{{DomainController}}", domainController)
	}
}

func NewKerberosClient(domain, controller string) (*KerberosClient, error) {
	realm := strings.ToUpper(domain)
	cfg, err := kconfig.NewFromString(
		buildTemplate(realm, controller),
	)
	if err != nil {
		return nil, err
	}
	_, kdcs, err := cfg.GetKDCs(realm, false)
	if err != nil {
		return nil, fmt.Errorf("couldn't find any KDCs for realm %s. Please specify a Domain Controller", realm)
	}
	return &KerberosClient{Realm: realm, config: cfg, KDCs: kdcs}, nil
}

func (kc *KerberosClient) AuthenticateWithPassword(username, password string) {
	if kc.client != nil {
		kc.client.Destroy()
		kc.client = nil
	}
	kc.client = kclient.NewWithPassword(username, kc.Realm, password, kc.config, kclient.DisablePAFXFAST(true))
}

func (kc *KerberosClient) AuthenticateWithKeytab(username, keytabPath string) error {
	if kc.client != nil {
		return nil
	}
	keytabData, err := keytab.Load(keytabPath)
	if err != nil {
		return err
	}
	kc.client = kclient.NewWithKeytab(username, kc.Realm, keytabData, kc.config, kclient.DisablePAFXFAST(true))
	return nil
}

type TGS struct {
	Ticket               messages.Ticket
	TargetUser           string
	ServicePrincipalName string
	Hash                 string
}

func (c *KerberosClient) GetServiceTicket(target, spn string) (*TGS, error) {
	ticket, _, err := c.client.GetServiceTicket(spn)
	if err != nil {
		return nil, err
	}
	return &TGS{
		Ticket: ticket,
		Hash:   TGSToHashcat(ticket, target),
	}, nil
}

type AsRepTGT struct {
	Ticket *messages.ASRep
	User   string
	Hash   string
}

type ErrorRequiresPreauth struct {
	msg string
}

func (e *ErrorRequiresPreauth) Error() string {
	return e.msg
}

func (c *KerberosClient) GetAsReqTgt(username string) (*AsRepTGT, error) {
	c.AuthenticateWithPassword(username, "lolz")
	defer c.client.Destroy()

	req, err := messages.NewASReqForTGT(c.Realm, c.config, c.client.Credentials.CName())
	if err != nil {
		return nil, err
	}

	b, err := req.Marshal()
	if err != nil {
		return nil, err
	}

	rb, err := c.client.SendToKDC(b, c.Realm)
	if err != nil {
		e, ok := err.(messages.KRBError)
		if !ok {
			return nil, err
		}
		switch e.ErrorCode {
		case errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN:
			return nil, fmt.Errorf("user %s does not exist", username)
		case errorcode.KDC_ERR_PREAUTH_REQUIRED:
			return nil, &ErrorRequiresPreauth{
				msg: fmt.Sprintf("user %s exists, requires preauth", username),
			}
		default:
			return nil, err
		}
	}

	var t messages.ASRep
	if err := t.Unmarshal(rb); err != nil {
		return nil, err
	}

	return &AsRepTGT{
		Ticket: &t,
		User:   username,
		Hash:   ASREPToHashcat(t),
	}, nil
}

func (c *KerberosClient) TestLogin(username, password string) (bool, error) {
	client := kclient.NewWithPassword(username, c.Realm, password,
		c.config, kclient.DisablePAFXFAST(true), kclient.AssumePreAuthentication(true),
	)
	defer client.Destroy()

	if ok, err := client.IsConfigured(); !ok {
		return false, err
	}

	if err := client.Login(); err != nil {
		return false, err
	}
	return true, nil
}

func (c *KerberosClient) Close() {
	c.client.Destroy()
}
