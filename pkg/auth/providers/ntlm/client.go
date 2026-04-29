package ntlm

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"errors"
	"hash"
	"strings"
	"time"

	"github.com/5amu/gonetexec/pkg/encoder"
	"github.com/5amu/gonetexec/pkg/utils"
	"golang.org/x/crypto/md4"
)

type Addr struct {
	Typ uint32
	Val []byte
}

// channelBindings represents gss_channel_bindings_struct
type ChannelBindings struct {
	InitiatorAddress Addr
	AcceptorAddress  Addr
	AppData          []byte
}

type Client struct {
	User        string
	Password    string
	Hash        []byte
	Domain      string
	Workstation string
	TargetSPN   string

	ChannelBinding *ChannelBindings // reserved for future implementation

	// Session Tracking
	NegotiateFlags     uint32
	ExportedSessionKey []byte
	ClientSigningKey   []byte
	ServerSigningKey   []byte
	ClientHandle       *rc4.Cipher
	ServerHandle       *rc4.Cipher

	// Don't use unless you know what you're doing
	NegMsg                NegotiateMessage
	TargetInfo            TargetInformation
	NegotiateMessageBytes []byte
}

func (c *Client) Negotiate() ([]byte, error) {
	//        NegotiateMessage
	//   0-8: Signature
	//  8-12: MessageType
	// 12-16: NegotiateFlags
	// 16-24: DomainNameFields
	// 24-32: WorkstationFields
	// 32-40: Version
	//   40-: Payload
	c.NegMsg = NegotiateMessage{
		MessageHeader: MessageHeader{
			Signature:   DefaultSignature,
			MessageType: NtLmNegotiate,
		},
		Version: DefaultVersion,
	}

	expectedLen := 40

	flags := DefaultFlags
	if c.Domain != "" {
		flags |= NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED
		uniS := encoder.StringToUnicode(strings.ToUpper(c.Domain))
		lenS := len(uniS)
		c.NegMsg.DomainNameFields = utils.NewVarField(&expectedLen, lenS)
		c.NegMsg.Payload = append(c.NegMsg.Payload, uniS...)
	}

	if c.Workstation != "" {
		flags |= NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED
		uniS := encoder.StringToUnicode(strings.ToUpper(c.Workstation))
		lenS := len(uniS)
		c.NegMsg.WorkstationFields = utils.NewVarField(&expectedLen, lenS)
		c.NegMsg.Payload = append(c.NegMsg.Payload, uniS...)
	}
	c.NegMsg.NegotiateFlags = flags
	msg, err := encoder.Marshal(c.NegMsg)
	if err != nil {
		return nil, err
	}
	c.NegotiateMessageBytes = msg
	return msg, nil
}

func (c *Client) GetNTLMHashFunc(targetName []byte) hash.Hash {
	unicodeDomain := encoder.StringToUnicode(c.Domain)
	if unicodeDomain == nil {
		unicodeDomain = targetName
	}

	if c.User != "" {
		upperUnicodeUser := encoder.StringToUnicode(strings.ToUpper(c.User))
		if c.Hash == nil {
			// this accepts an empty password
			unicodePassword := encoder.StringToUnicode(c.Password)
			m4 := md4.New()
			_, _ = m4.Write(unicodePassword)
			c.Hash = m4.Sum(nil)
		}
		hm := hmac.New(md5.New, c.Hash)
		_, _ = hm.Write(upperUnicodeUser)
		_, _ = hm.Write(unicodeDomain)

		return hmac.New(md5.New, hm.Sum(nil))
	}
	// TODO: implement anonymous login
	return nil
}

func (c *Client) Authenticate(cmsg []byte) (amsg []byte, err error) {
	var challenge ChallengeMessage
	if challenge, err = ParseChallengeMessage(cmsg); err != nil {
		return nil, err
	}

	// Check flag validity
	flags := c.NegMsg.NegotiateFlags & challenge.NegotiateFlags
	if flags&NTLMSSP_REQUEST_TARGET == 0 || flags&NTLMSSP_NEGOTIATE_TARGET_INFO == 0 {
		return nil, errors.New("invalid negotiate flags")
	}

	// 56 is static - dynamic fields are stored after 56 bytes
	start := 56 - challenge.TargetName.BufferOffset
	targetName := challenge.Payload[start : start+uint32(challenge.TargetName.Len)]

	// 56 is static - dynamic fields are stored after 56 bytes
	start = 56 - challenge.TargetInformation.BufferOffset
	info, err := ParseAvPairs(challenge.Payload[start : start+uint32(challenge.TargetInformation.Len)])
	if err != nil {
		return nil, err
	}

	//        AuthenticateMessage
	//   0-8: Signature
	//  8-12: MessageType
	// 12-20: LmChallengeResponseFields
	// 20-28: NtChallengeResponseFields
	// 28-36: DomainNameFields
	// 36-44: UserNameFields
	// 44-52: WorkstationFields
	// 52-60: EncryptedRandomSessionKeyFields
	// 60-64: NegotiateFlags
	// 64-72: Version
	// 72-88: MIC
	//   88-: Payload

	//        LMv2Response
	//  0-16: Response
	// 16-24: ChallengeFromClient
	// Empty LMv2ChallengeResponse => not supported
	lmChallengeResponse := [24]byte{}

	//        NTLMv2Response
	//  0-16: Response
	//   16-: NTLMv2ClientChallenge

	// Generate Random Client Challenge
	var clientChallenge [8]byte
	if _, err := rand.Read(clientChallenge[:]); err != nil {
		return nil, err
	}

	var response [16]byte
	var hash hash.Hash = c.GetNTLMHashFunc(targetName)
	_, _ = hash.Write(challenge.ServerChallenge[:])
	_, _ = hash.Write(clientChallenge[:])
	_ = hash.Sum(response[:])

	// if no timestamp provided in AvPairs, provide our own
	if c.TargetInfo.Timestamp == 0 {
		c.TargetInfo.Timestamp = uint64((time.Now().UnixNano() / 100) + 116444736000000000)
	}

	ntres := NTLMv2Response{
		Response: response,
		NTLMv2ClientChallenge: NTLMv2ClientChallenge{
			RespType:            1,
			HiRespType:          1,
			Timestamp:           c.TargetInfo.Timestamp,
			ChallengeFromClient: clientChallenge,
			AvPairs:             info.Raw(encoder.StringToUnicode(c.TargetSPN)),
		},
	}

	ntChallengeResponse, err := encoder.Marshal(ntres)
	if err != nil {
		return nil, err
	}

	hash.Reset()
	hash.Write(response[:])
	sessionBaseKey := hash.Sum(nil)
	keyExchangeKey := sessionBaseKey // if ntlm version == 2

	c.ExportedSessionKey = make([]byte, 16)
	var encryptedRandomSessionKey []byte
	if flags&NTLMSSP_NEGOTIATE_KEY_EXCH != 0 {
		if _, err := rand.Read(c.ExportedSessionKey); err != nil {
			return nil, err
		}

		cipher, err := rc4.NewCipher(keyExchangeKey)
		if err != nil {
			return nil, err
		}

		encryptedRandomSessionKey = make([]byte, 16)
		cipher.XORKeyStream(encryptedRandomSessionKey, c.ExportedSessionKey)
	} else {
		c.ExportedSessionKey = keyExchangeKey
	}

	unicodeDomain := encoder.StringToUnicode(strings.ToUpper(c.Domain))
	unicodeUser := encoder.StringToUnicode(strings.ToUpper(c.User))
	unicodeWorkstation := encoder.StringToUnicode(strings.ToUpper(c.Workstation))

	// Preparing payload
	var payload bytes.Buffer
	_, _ = payload.Write(lmChallengeResponse[:])
	_, _ = payload.Write(ntChallengeResponse)
	_, _ = payload.Write(unicodeDomain)
	_, _ = payload.Write(unicodeUser)
	_, _ = payload.Write(unicodeWorkstation)
	_, _ = payload.Write(encryptedRandomSessionKey)

	off := 88
	authenticate := AuthenicateMessage{
		MessageHeader: MessageHeader{
			Signature:   DefaultSignature,
			MessageType: NtLmAuthenticate,
		},
		LmChallengeResponseFields:      utils.NewVarField(&off, len(lmChallengeResponse)), // LmChallengeResponseLen = 24
		NtChallengeResponseFields:      utils.NewVarField(&off, len(ntChallengeResponse)), // NtChallengeResponseLen = [len(Response) = 16] + [len(NTLMv2ClientChallenge) = (minlen=28)(targetinfosize) + (padding=4)]
		DomainNameFields:               utils.NewVarField(&off, len(unicodeDomain)),
		UsernameFields:                 utils.NewVarField(&off, len(unicodeUser)),
		WorkstationFields:              utils.NewVarField(&off, len(unicodeWorkstation)),
		EncryptedRandomSessionKeyField: utils.NewVarField(&off, len(encryptedRandomSessionKey)), // len(EncryptedRandomSessionKey) = 0 or 16
		NegotiateFlags:                 flags,
		MIC:                            [16]byte{},      // hash.Sum()
		Payload:                        payload.Bytes(), // LM+NT+DOMAIN+USER+WORKSTATION+SESSKEY
	}

	amsg, err = encoder.Marshal(authenticate)
	if err != nil {
		return nil, err
	}

	hash = hmac.New(md5.New, c.ExportedSessionKey)
	hash.Write(c.NegotiateMessageBytes)
	hash.Write(cmsg)
	hash.Write(amsg)
	hash.Sum(authenticate.MIC[:])

	c.ClientSigningKey = signKey(flags, c.ExportedSessionKey, true)
	c.ServerSigningKey = signKey(flags, c.ExportedSessionKey, false)

	if c.ClientHandle, err = rc4.NewCipher(sealKey(flags, c.ExportedSessionKey, true)); err != nil {
		return nil, err
	}
	if c.ServerHandle, err = rc4.NewCipher(sealKey(flags, c.ExportedSessionKey, false)); err != nil {
		return nil, err
	}
	return encoder.Marshal(authenticate)
}
