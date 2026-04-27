package optldap

import (
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"

	"github.com/5amu/gonetexec/cmd/gnx/cli/optsmb"
	"github.com/5amu/gonetexec/internal/printer"
	"github.com/5amu/gonetexec/internal/utils"
	"github.com/5amu/gonetexec/pkg/smb"
	"github.com/go-ldap/ldap/v3"
	"github.com/spf13/cobra"
)

type Options struct {
	Targets struct {
		TARGETS []string `description:"Provide target IP/FQDN/FILE"`
	} `positional-args:"yes"`

	Connection struct {
		Username    string `short:"u" description:"Provide username (or FILE)"`
		Password    string `short:"p" description:"Provide password (or FILE)"`
		NullSession bool   `long:"null-session" description:"Authenticate with null credentials"`
		NTLM        string `short:"H" long:"hashes" description:"Authenticate with NTLM hash"`
		Domain      string `short:"d" long:"domain" description:"Provide domain"`
		Port        int    `long:"port" default:"389" description:"Ldap port to contact"`
		SSL         bool   `short:"s" long:"ssl" description:"Use ssl to interact with ldap"`
	} `group:"Connection Options" description:"Connection Options"`

	Hashes struct {
		AsrepRoast string `long:"asreproast" description:"Grab AS_REP ticket(s) parsed to be cracked with hashcat"`
		Kerberoast string `long:"kerberoast" description:"Grab TGS ticket(s) parsed to be cracked with hashcat"`
	} `group:"Hash Retrieval Options" description:"Hash Retrieval Options"`

	// CRUD
	// Create / Read / Update / Delete

	// Create
	Create struct {
		AddComputer string `long:"add-computer" description:"Create a computer object"`
	} `group:"Create Options" description:"Create Options"`

	// Read
	Read struct {
		CustomFilter     string `short:"f" long:"filter" description:"Bring your own filter"`
		CustomAttributes string `short:"a" long:"attributes" description:"Ask your attributes (comma separated)"`

		Script                     bool `long:"script" description:"Filter for objects with flag SCRIPT"`
		Disabled                   bool `long:"disabled" description:"Filter for objects with flag ACCOUNTDISABLE"`
		HomedirRequired            bool `long:"homedir-required" description:"Filter for objects with flag HOMEDIR_REQUIRED"`
		Lockout                    bool `long:"lockout" description:"Filter for objects with flag LOCKOUT"`
		PasswordNotRequired        bool `long:"password-not-required" description:"Filter for objects with flag PASSWD_NOTREQD"`
		PasswordCantChange         bool `long:"password-cant-change" description:"Filter for objects with flag PASSWD_CANT_CHANGE"`
		EncryptedTextPwdAllowed    bool `long:"encrypted-text-pwd-allowed" description:"Filter for objects with flag ENCRYPTED_TEXT_PWD_ALLOWED"`
		TempDuplicateAccount       bool `long:"temp-duplicate-account" description:"Filter for objects with flag TEMP_DUPLICATE_ACCOUNT"`
		NormalAccount              bool `long:"normal-account" description:"Filter for objects with flag NORMAL_ACCOUNT"`
		InterdomainTrustAccount    bool `long:"interdomain-trust-account" description:"Filter for objects with flag INTERDOMAIN_TRUST_ACCOUNT"`
		WorkstationTrustAccount    bool `long:"workstation-trust-account" description:"Filter for objects with flag WORKSTATION_TRUST_ACCOUNT"`
		ServerTrustAccount         bool `long:"server-trust-account" description:"Filter for objects with flag SERVER_TRUST_ACCOUNT"`
		DontExpirePassword         bool `long:"password-never-expires" description:"Filter for objects with flag DONT_EXPIRE_PASSWD"`
		MNSLogonAccount            bool `long:"mns-logon-account" description:"Filter for objects with flag MNS_LOGON_ACCOUNT"`
		SmartcardRequired          bool `long:"smartcard-required" description:"Filter for objects with flag SMARTCARD_REQUIRED"`
		TrustedForDelegation       bool `long:"trusted-for-delegation" description:"Filter for objects with flag TRUSTED_FOR_DELEGATION"`
		NotDelegated               bool `long:"not-delegated" description:"Filter for objects with flag NOT_DELEGATED"`
		UseDESKeyOnly              bool `long:"use-des-key-only" description:"Filter for objects with flag USE_DES_KEY_ONLY"`
		DontRequirePreauth         bool `long:"dont-require-preauth" description:"Filter for objects with flag DONT_REQ_PREAUTH"`
		PasswordExpired            bool `long:"password-expired" description:"Filter for objects with flag PASSWORD_EXPIRED"`
		TrustedToAuthForDelegation bool `long:"trusted-to-auth-for-delegation" description:"Filter for objects with flag TRUSTED_TO_AUTH_FOR_DELEGATION"`
		PartialSecretsAccount      bool `long:"partial-secrets-account" description:"Filter for objects with flag PARTIAL_SECRETS_ACCOUNT"`

		AdminCount  bool   `long:"admin-count" description:"Enumerate objects that have an adminCount"`
		Computers   bool   `long:"computers" description:"Enumerate objects that are computers"`
		Groups      bool   `long:"groups" description:"Enumerate objects that are domain groups"`
		Users       bool   `long:"users" description:"Enumerate objects that are enabled domain users"`
		ActiveUsers bool   `long:"active-users" description:"Enumerate objects that are active enabled domain users"`
		User        string `long:"user" description:"Get data about a single user"`
		GetSID      bool   `long:"sid" description:"Get domain SID"`
		GMSA        bool   `long:"gmsa" description:"Get GMSA passwords"`
		Not         bool   `long:"not" description:"Negate next filter"`
	} `group:"Read Options" description:"Read Options"`

	// Update
	Update struct {
	} `group:"Update Options" description:"Update Options"`

	// Delete
	Delete struct {
		DeleteComputer string `long:"del-computer" description:"Delete a computer object"`
	} `group:"Delete Options" description:"Delete Options"`

	/*
		BH struct {
			Bloodhound           string   `long:"bloodhound" description:"Run bloodhound collector (v4.2) and save in output file (zip)"`
			BloodhoundNameserver string   `short:"n" long:"nameserver" description:"Provide a nameserver for bloodhound collector"`
			Collection           []string `short:"c" long:"collection" default:"Default" description:"Which information to collect. Supported: Group, LocalAdmin, Session, Trusts, Default, DCOnly, DCOM, RDP, PSRemote, LoggedOn, Container, ObjectProps, ACL, All"`
		} `group:"Run Bloodhound Collector v4.2" description:"Run Bloodhound Collector v4.2"`
	*/

	// Common utils
	target2SMBInfo map[string]*smb.SMBFingerprint
	printMutex     sync.Mutex
	credentials    []utils.Credential

	// Utils for Create
	createName string
	createUAC  UserAccountControl

	// Utils for Read
	filters    []string
	filter     string
	attributes []string

	// Utils for Update

	// Utils for Delete
	deletionType DeletionType
	deletionName string
}

func NewLDAPCmd() *cobra.Command {
	opts := &Options{}

	cmd := &cobra.Command{
		Use:   "ldap [TARGETS...]",
		Short: "Own stuff using LDAP",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			opts.Targets.TARGETS = args
			opts.Run()
		},
	}

	cmd.Flags().StringVarP(&opts.Connection.Username, "username", "u", "", "Provide username (or FILE)")
	cmd.Flags().StringVarP(&opts.Connection.Password, "password", "p", "", "Provide password (or FILE)")
	cmd.Flags().BoolVar(&opts.Connection.NullSession, "null-session", false, "Authenticate with null credentials")
	cmd.Flags().StringVarP(&opts.Connection.NTLM, "hashes", "H", "", "Authenticate with NTLM hash")
	cmd.Flags().StringVarP(&opts.Connection.Domain, "domain", "d", "", "Provide domain")
	cmd.Flags().IntVar(&opts.Connection.Port, "port", 389, "Ldap port to contact")
	cmd.Flags().BoolVarP(&opts.Connection.SSL, "ssl", "s", false, "Use ssl to interact with ldap")
	cmd.Flags().StringVar(&opts.Hashes.AsrepRoast, "asreproast", "", "Grab AS_REP ticket(s) parsed to be cracked with hashcat")
	cmd.Flags().StringVar(&opts.Hashes.Kerberoast, "kerberoast", "", "Grab TGS ticket(s) parsed to be cracked with hashcat")
	cmd.Flags().StringVar(&opts.Create.AddComputer, "add-computer", "", "Create a computer object")
	cmd.Flags().StringVarP(&opts.Read.CustomFilter, "filter", "f", "", "Bring your own filter")
	cmd.Flags().StringVarP(&opts.Read.CustomAttributes, "attributes", "a", "", "Ask your attributes (comma separated)")
	cmd.Flags().BoolVar(&opts.Read.Script, "script", false, "Filter for objects with flag SCRIPT")
	cmd.Flags().BoolVar(&opts.Read.Disabled, "disabled", false, "Filter for objects with flag ACCOUNTDISABLE")
	cmd.Flags().BoolVar(&opts.Read.HomedirRequired, "homedir-required", false, "Filter for objects with flag HOMEDIR_REQUIRED")
	cmd.Flags().BoolVar(&opts.Read.Lockout, "lockout", false, "Filter for objects with flag LOCKOUT")
	cmd.Flags().BoolVar(&opts.Read.PasswordNotRequired, "password-not-required", false, "Filter for objects with flag PASSWD_NOTREQD")
	cmd.Flags().BoolVar(&opts.Read.PasswordCantChange, "password-cant-change", false, "Filter for objects with flag PASSWD_CANT_CHANGE")
	cmd.Flags().BoolVar(&opts.Read.EncryptedTextPwdAllowed, "encrypted-text-pwd-allowed", false, "Filter for objects with flag ENCRYPTED_TEXT_PWD_ALLOWED")
	cmd.Flags().BoolVar(&opts.Read.TempDuplicateAccount, "temp-duplicate-account", false, "Filter for objects with flag TEMP_DUPLICATE_ACCOUNT")
	cmd.Flags().BoolVar(&opts.Read.NormalAccount, "normal-account", false, "Filter for objects with flag NORMAL_ACCOUNT")
	cmd.Flags().BoolVar(&opts.Read.InterdomainTrustAccount, "interdomain-trust-account", false, "Filter for objects with flag INTERDOMAIN_TRUST_ACCOUNT")
	cmd.Flags().BoolVar(&opts.Read.WorkstationTrustAccount, "workstation-trust-account", false, "Filter for objects with flag WORKSTATION_TRUST_ACCOUNT")
	cmd.Flags().BoolVar(&opts.Read.ServerTrustAccount, "server-trust-account", false, "Filter for objects with flag SERVER_TRUST_ACCOUNT")
	cmd.Flags().BoolVar(&opts.Read.DontExpirePassword, "password-never-expires", false, "Filter for objects with flag DONT_EXPIRE_PASSWD")
	cmd.Flags().BoolVar(&opts.Read.MNSLogonAccount, "mns-logon-account", false, "Filter for objects with flag MNS_LOGON_ACCOUNT")
	cmd.Flags().BoolVar(&opts.Read.SmartcardRequired, "smartcard-required", false, "Filter for objects with flag SMARTCARD_REQUIRED")
	cmd.Flags().BoolVar(&opts.Read.TrustedForDelegation, "trusted-for-delegation", false, "Filter for objects with flag TRUSTED_FOR_DELEGATION")
	cmd.Flags().BoolVar(&opts.Read.NotDelegated, "not-delegated", false, "Filter for objects with flag NOT_DELEGATED")
	cmd.Flags().BoolVar(&opts.Read.UseDESKeyOnly, "use-des-key-only", false, "Filter for objects with flag USE_DES_KEY_ONLY")
	cmd.Flags().BoolVar(&opts.Read.DontRequirePreauth, "dont-require-preauth", false, "Filter for objects with flag DONT_REQ_PREAUTH")
	cmd.Flags().BoolVar(&opts.Read.PasswordExpired, "password-expired", false, "Filter for objects with flag PASSWORD_EXPIRED")
	cmd.Flags().BoolVar(&opts.Read.TrustedToAuthForDelegation, "trusted-to-auth-for-delegation", false, "Filter for objects with flag TRUSTED_TO_AUTH_FOR_DELEGATION")
	cmd.Flags().BoolVar(&opts.Read.PartialSecretsAccount, "partial-secrets-account", false, "Filter for objects with flag PARTIAL_SECRETS_ACCOUNT")
	cmd.Flags().BoolVar(&opts.Read.AdminCount, "admin-count", false, "Enumerate objects that have an adminCount")
	cmd.Flags().BoolVar(&opts.Read.Computers, "computers", false, "Enumerate objects that are computers")
	cmd.Flags().BoolVar(&opts.Read.Groups, "groups", false, "Enumerate objects that are domain groups")
	cmd.Flags().BoolVar(&opts.Read.Users, "users", false, "Enumerate objects that are enabled domain users")
	cmd.Flags().BoolVar(&opts.Read.ActiveUsers, "active-users", false, "Enumerate objects that are active enabled domain users")
	cmd.Flags().StringVar(&opts.Read.User, "user", "", "Get data about a single user")
	cmd.Flags().BoolVar(&opts.Read.GetSID, "sid", false, "Get domain SID")
	cmd.Flags().BoolVar(&opts.Read.GMSA, "gmsa", false, "Get GMSA passwords")
	cmd.Flags().BoolVar(&opts.Read.Not, "not", false, "Negate next filter")
	cmd.Flags().StringVar(&opts.Delete.DeleteComputer, "del-computer", "", "Delete a computer object")

	return cmd
}


type ExecutionFunction int

const (
	Undefined ExecutionFunction = iota
	Create
	Read
	Update
	Delete
	Kerberoast
	Asreproast
)

func (o *Options) parallelExecution(runner func(string)) {
	if len(o.filters) == 1 {
		o.filter = o.filters[0]
	} else {
		o.filter = JoinFilters(o.filters...)
	}
	var wg sync.WaitGroup
	for target := range o.target2SMBInfo {
		wg.Add(1)
		go func(t string) {
			runner(t)
			wg.Done()
		}(target)
	}
	wg.Wait()
}

func (o *Options) Run() {
	o.target2SMBInfo = optsmb.GatherSMBInfoToMap(
		utils.ExtractTargets(o.Targets.TARGETS),
		optsmb.DefaultPort,
	)

	if !o.Connection.NullSession {
		o.credentials = utils.NewCredentialsDispacher(
			o.Connection.Username,
			o.Connection.Password,
			o.Connection.NTLM,
			utils.Clusterbomb,
		)
	}

	switch o.parseH() {
	case Asreproast:
		o.parallelExecution(o.asreproast)
		return
	case Kerberoast:
		o.parallelExecution(o.kerberoast)
		return
	}

	if o.parseC() == Create {
		o.parallelExecution(o.create)
		return
	}

	if o.parseR(os.Args[2:]) == Read {
		o.parallelExecution(o.read)
		return
	}

	if o.parseU() == Update {
		return
	}

	if o.parseD() == Delete {
		o.parallelExecution(o.delete)
		return
	}

	o.parallelExecution(func(s string) {
		_, _, _ = o.authenticate(s)
	})
}

func (o *Options) authenticate(target string) (*ldap.Conn, utils.Credential, error) {
	if !o.Connection.NullSession && len(o.credentials) == 0 {
		return nil, utils.Credential{}, fmt.Errorf("no credentials provided")
	}

	lconn, err := connect(target, o.Connection.Port, o.Connection.SSL)
	if err != nil {
		return nil, utils.Credential{}, err
	}

	prt := printer.NewPrinter("LDAP", target, o.target2SMBInfo[target].NetBIOSComputerName, o.Connection.Port)
	defer prt.PrintStored(&o.printMutex)

	var domain string = o.Connection.Domain
	if domain == "" {
		domain = o.target2SMBInfo[target].DNSDomainName
	}

	if o.Connection.NullSession {
		if err := lconn.UnauthenticatedBind(""); err != nil {
			prt.StoreFailure("null session not allowed")
			return nil, utils.Credential{}, fmt.Errorf("no valid authentication")
		}
		c := utils.Credential{Username: o.Connection.Username, Password: o.Connection.Password}
		prt.StoreSuccess(c.StringWithDomain(domain))
		return lconn, c, nil
	}

	for _, creds := range o.credentials {
		if creds.Hash != "" {
			if err := lconn.NTLMBindWithHash(domain, creds.Username, creds.Hash); err != nil {
				prt.StoreFailure(creds.StringWithDomain(domain))
			} else {
				prt.StoreSuccess(creds.StringWithDomain(domain))
				return lconn, creds, nil
			}
		} else {
			if err := authenticate(lconn, domain, creds.Username, creds.Password); err != nil {
				prt.StoreFailure(creds.StringWithDomain(domain))
			} else {
				prt.StoreSuccess(creds.StringWithDomain(domain))
				return lconn, creds, nil
			}
		}
	}
	return nil, utils.Credential{}, fmt.Errorf("no valid authentication")
}

func (o *Options) parseC() ExecutionFunction {
	if o.Create.AddComputer != "" {
		o.createName = o.Create.AddComputer
		o.createUAC = WORKSTATION_TRUST_ACCOUNT
		return Create
	}

	return Undefined
}

func (o *Options) parseR(args []string) ExecutionFunction {
	if o.Read.GetSID {
		o.filters = []string{UACFilter(SERVER_TRUST_ACCOUNT)}
		o.attributes = []string{ObjectSid}
		return Read
	}

	if o.Read.GMSA {
		o.filters = []string{FilterGMSA}
		o.attributes = []string{SAMAccountName, ManagedPassword}
		return Read
	}

	tmp := strings.Split(o.Read.CustomAttributes, ",")
	for _, a := range tmp {
		switch strings.ToLower(a) {
		case strings.ToLower(SAMAccountName), "name":
			o.attributes = append(o.attributes, SAMAccountName)
		case strings.ToLower(ServicePrincipalName), "spn":
			o.attributes = append(o.attributes, ServicePrincipalName)
		case strings.ToLower(ObjectSid):
			o.attributes = append(o.attributes, ObjectSid)
		case strings.ToLower(AdminCount):
			o.attributes = append(o.attributes, AdminCount)
		case strings.ToLower(DistinguishedName), "dn":
			o.attributes = append(o.attributes, DistinguishedName)
		case strings.ToLower(OperatingSystem):
			o.attributes = append(o.attributes, OperatingSystem)
		case strings.ToLower(OperatingSystemServicePack):
			o.attributes = append(o.attributes, OperatingSystemServicePack)
		case strings.ToLower(OperatingSystemVersion):
			o.attributes = append(o.attributes, OperatingSystemVersion)
		case strings.ToLower(PasswordLastSet):
			o.attributes = append(o.attributes, PasswordLastSet)
		case strings.ToLower(LastLogon):
			o.attributes = append(o.attributes, LastLogon)
		case strings.ToLower(MemberOf):
			o.attributes = append(o.attributes, MemberOf)
		case strings.ToLower(Description):
			o.attributes = append(o.attributes, Description)
		case strings.ToLower(ManagedPassword):
			o.attributes = append(o.attributes, ManagedPassword)
		case strings.ToLower(WhenCreated):
			o.attributes = append(o.attributes, WhenCreated)
		case "":
			o.attributes = []string{SAMAccountName, Description}
		default:
			o.attributes = append(o.attributes, a)
		}
	}

	var nextNegated bool = false

	for _, a := range args {
		attr, _ := strings.CutPrefix(a, "--")
		attr, _ = strings.CutPrefix(attr, "-")

		if attr == "" {
			continue
		}

		for _, f := range reflect.VisibleFields(reflect.TypeOf(o.Read)) {
			var filters []string
			switch attr {
			case f.Tag.Get("long"), f.Tag.Get("short"):
				switch f.Name {
				case "CustomFilter":
					filters = []string{o.Read.CustomFilter}

				case "Script":
					filters = []string{UACFilter(SCRIPT)}
				case "Disabled":
					filters = []string{UACFilter(ACCOUNTDISABLE)}
				case "HomedirRequired":
					filters = []string{UACFilter(HOMEDIR_REQUIRED)}
				case "Lockout":
					filters = []string{UACFilter(LOCKOUT)}
				case "PasswordNotRequired":
					filters = []string{UACFilter(PASSWD_NOTREQD)}
				case "PasswordCantChange":
					filters = []string{UACFilter(PASSWD_CANT_CHANGE)}
				case "EncryptedTextPwdAllowed":
					filters = []string{UACFilter(ENCRYPTED_TEXT_PWD_ALLOWED)}
				case "TempDuplicateAccount":
					filters = []string{UACFilter(TEMP_DUPLICATE_ACCOUNT)}
				case "NormalAccount":
					filters = []string{UACFilter(NORMAL_ACCOUNT)}
				case "InterdomainTrustAccount":
					filters = []string{UACFilter(INTERDOMAIN_TRUST_ACCOUNT)}
				case "WorkstationTrustAccount":
					filters = []string{UACFilter(WORKSTATION_TRUST_ACCOUNT)}
				case "ServerTrustAccount":
					filters = []string{UACFilter(SERVER_TRUST_ACCOUNT)}
				case "DontExpirePassword":
					filters = []string{UACFilter(DONT_EXPIRE_PASSWORD)}
				case "MNSLogonAccount":
					filters = []string{UACFilter(MNS_LOGON_ACCOUNT)}
				case "SmartcardRequired":
					filters = []string{UACFilter(SMARTCARD_REQUIRED)}
				case "TrustedForDelegation":
					filters = []string{UACFilter(TRUSTED_FOR_DELEGATION)}
				case "NotDelegated":
					filters = []string{UACFilter(NOT_DELEGATED)}
				case "UseDESKeyOnly":
					filters = []string{UACFilter(USE_DES_KEY_ONLY)}
				case "DontRequirePreauth":
					filters = []string{UACFilter(DONT_REQ_PREAUTH)}
				case "PasswordExpired":
					filters = []string{UACFilter(PASSWORD_EXPIRED)}
				case "TrustedToAuthForDelegation":
					filters = []string{UACFilter(TRUSTED_TO_AUTH_FOR_DELEGATION)}
				case "PartialSecretsAccount":
					filters = []string{UACFilter(PARTIAL_SECRETS_ACCOUNT)}

				case "AdminCount":
					filters = []string{FilterIsAdmin}
				case "Computers":
					filters = []string{FilterIsComputer}
				case "Groups":
					filters = []string{FilterIsGroup}
				case "Users":
					filters = []string{FilterIsUser}
				case "ActiveUsers":
					filters = []string{FilterIsUser, NegativeFilter(UACFilter(ACCOUNTDISABLE))}
				case "User":
					filters = []string{FilterIsUser, NewFilter(SAMAccountName, o.Read.User)}

				case "Not":
					nextNegated = true
				default:
					continue
				}
			}
			if len(filters) != 0 {
				if nextNegated {
					if len(filters) == 1 {
						o.filters = append(o.filters, NegativeFilter(filters[0]))
					} else {
						o.filters = append(o.filters, NegativeFilter(JoinFilters(filters...)))
					}
					nextNegated = false
				} else {
					o.filters = append(o.filters, filters...)
				}
			}
		}
	}
	if len(o.filters) > 0 {
		slices.Sort(o.filters)
		o.filters = slices.Compact[[]string, string](o.filters)
		return Read
	}
	return Undefined
}

func (o *Options) parseU() ExecutionFunction {
	return Undefined
}

func (o *Options) parseD() ExecutionFunction {
	if o.Delete.DeleteComputer != "" {
		o.deletionName = o.Delete.DeleteComputer
		o.deletionType = DelComputer
		return Delete
	}
	return Undefined
}

func (o *Options) parseH() ExecutionFunction {
	if o.Hashes.AsrepRoast != "" {
		o.filters = []string{
			FilterIsUser,
			UACFilter(DONT_REQ_PREAUTH),
		}
		return Asreproast
	}
	if o.Hashes.Kerberoast != "" {
		o.filters = []string{
			FilterIsUser,
			NegativeFilter(UACFilter(ACCOUNTDISABLE)),
		}
		return Kerberoast
	}
	return Undefined
}
