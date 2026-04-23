package optldap

import (
	"fmt"
	"strconv"
	"strings"
)

/*
   LDAP makes you search using an OID
   http://oid-info.com/get/1.2.840.113556.1.4.803
   The one for the userAccountControl in MS Active Directory is
   1.2.840.113556.1.4.803 (LDAP_MATCHING_RULE_BIT_AND)
   And we can look at the enabled flags using a query like (!(userAccountControl:1.2.840.113556.1.4.803:=2))
   https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
*/

type UserAccountControl int

var (
	SCRIPT                         UserAccountControl = 1
	ACCOUNTDISABLE                 UserAccountControl = 2
	HOMEDIR_REQUIRED               UserAccountControl = 8
	LOCKOUT                        UserAccountControl = 16
	PASSWD_NOTREQD                 UserAccountControl = 32
	PASSWD_CANT_CHANGE             UserAccountControl = 64
	ENCRYPTED_TEXT_PWD_ALLOWED     UserAccountControl = 128
	TEMP_DUPLICATE_ACCOUNT         UserAccountControl = 256
	NORMAL_ACCOUNT                 UserAccountControl = 512
	INTERDOMAIN_TRUST_ACCOUNT      UserAccountControl = 2048
	WORKSTATION_TRUST_ACCOUNT      UserAccountControl = 4096
	SERVER_TRUST_ACCOUNT           UserAccountControl = 8192
	DONT_EXPIRE_PASSWORD           UserAccountControl = 65536
	MNS_LOGON_ACCOUNT              UserAccountControl = 131072
	SMARTCARD_REQUIRED             UserAccountControl = 262144
	TRUSTED_FOR_DELEGATION         UserAccountControl = 524288
	NOT_DELEGATED                  UserAccountControl = 1048576
	USE_DES_KEY_ONLY               UserAccountControl = 2097152
	DONT_REQ_PREAUTH               UserAccountControl = 4194304
	PASSWORD_EXPIRED               UserAccountControl = 8388608
	TRUSTED_TO_AUTH_FOR_DELEGATION UserAccountControl = 16777216
	PARTIAL_SECRETS_ACCOUNT        UserAccountControl = 67108864
)

// https://learn.microsoft.com/en-us/windows/win32/adschema/a-instancetype
const (
	IT_NamingContextHead      uint32 = 1  // The head of naming context
	IT_ReplicaNotInstanciated uint32 = 2  // This replica is not instantiated
	IT_Writable               uint32 = 4  // The object is writable on this directory
	IT_Above                  uint32 = 8  // The naming context above this one on this directory is held
	IT_Constructed            uint32 = 10 // The naming context is in the process of being constructed for the first time by using replication
	IT_Removed                uint32 = 20 // The naming context is in the process of being removed from the local DSA
)

const (
	FilterIsUser     = "(objectCategory=person)"
	FilterIsGroup    = "(objectCategory=group)"
	FilterIsComputer = "(objectCategory=computer)"
	FilterIsAdmin    = "(adminCount=1)"
	FilterGMSA       = "(objectClass=msDS-GroupManagedServiceAccount)"
)

const (
	SAMAccountName             = "sAMAccountName"
	ServicePrincipalName       = "servicePrincipalName"
	ObjectSid                  = "objectSid"
	ObjectClass                = "objectClass"
	InstanceType               = "instanceType"
	AdminCount                 = "adminCount"
	UAC                        = "userAccountControl:1.2.840.113556.1.4.803:"
	UACAttr                    = "userAccountControl"
	DistinguishedName          = "distinguishedName"
	OperatingSystem            = "operatingSystem"
	OperatingSystemServicePack = "operatingSystemServicePack"
	OperatingSystemVersion     = "operatingSystemVersion"
	PasswordLastSet            = "pwdLastSet"
	LastLogon                  = "lastLogon"
	MemberOf                   = "memberOf"
	Description                = "description"
	ManagedPassword            = "msDS-ManagedPassword"
	UnicodePassword            = "unicodePwd"
	DnsHostname                = "dnsHostName"
	WhenCreated                = "whenCreated"
)

func JoinFilters(filters ...string) string {
	var builder strings.Builder
	builder.WriteString("(&")
	for _, s := range filters {
		builder.WriteString(s)
	}
	builder.WriteString(")")
	return builder.String()
}

func NegativeFilter(filter string) string {
	return fmt.Sprintf("(!%s)", filter)
}

func NewFilter(attribute string, equalsTo string) string {
	return fmt.Sprintf("(%s=%s)", attribute, equalsTo)
}

func UACFilter(prop UserAccountControl) string {
	return NewFilter(UAC, strconv.Itoa(int(prop)))
}

type UCD struct {
	DnsHostName    string
	UAC            UserAccountControl
	SPNs           []string
	SAMAccountName string
	UnicodePwd     string
}
