package ntlm

import (
	"bytes"
	"errors"

	"github.com/5amu/gonetexec/pkg/encoder"
	"github.com/5amu/gonetexec/pkg/utils"
)

type MessageHeader struct {
	Signature   [8]byte
	MessageType uint32
}

type NegotiateMessage struct {
	MessageHeader
	NegotiateFlags    uint32
	DomainNameFields  utils.VarField
	WorkstationFields utils.VarField
	Version           [8]byte
	Payload           []byte
}

type AuthenicateMessage struct {
	MessageHeader
	LmChallengeResponseFields      utils.VarField
	NtChallengeResponseFields      utils.VarField
	DomainNameFields               utils.VarField
	UsernameFields                 utils.VarField
	WorkstationFields              utils.VarField
	EncryptedRandomSessionKeyField utils.VarField
	NegotiateFlags                 uint32
	MIC                            [16]byte
	Payload                        []byte
}

type ChallengeMessage struct {
	MessageHeader
	TargetName        utils.VarField
	NegotiateFlags    uint32
	ServerChallenge   [8]byte
	_                 [8]byte
	TargetInformation utils.VarField
	Version           [8]byte
	Payload           []byte
}

func ParseChallengeMessage(cmsg []byte) (ChallengeMessage, error) {
	//        ChallengeMessage
	//   0-8: Signature
	//  8-12: MessageType
	// 12-20: TargetNameFields
	// 20-24: NegotiateFlags
	// 24-32: ServerChallenge
	// 32-40: _
	// 40-48: TargetInfoFields
	// 48-56: Version
	//   56-: Payload
	var challenge ChallengeMessage
	if err := encoder.Unmarshal(cmsg, &challenge); err != nil {
		return challenge, err
	}

	// Check message signature
	if !bytes.Equal(challenge.Signature[:], DefaultSignature[:]) {
		return challenge, errors.New("invalid signature")
	}

	// Check message type
	if challenge.MessageType != NtLmChallenge {
		return challenge, errors.New("invalid message type")
	}

	// Check target name length
	if challenge.TargetName.MaxLen < challenge.TargetName.Len || len(challenge.Payload) < int(challenge.TargetName.Len) {
		return challenge, errors.New("invalid target name format")
	}

	// Check target info length
	if challenge.TargetInformation.MaxLen < challenge.TargetInformation.Len || len(challenge.Payload) < int(challenge.TargetInformation.Len) {
		return challenge, errors.New("invalid target info format")
	}
	return challenge, nil
}

type SingleHostData struct {
	Size       uint32
	Z4         uint32
	CustomData uint8
	MachineID  [32]byte
}

//	      NTLMv2ClientChallenge
//	 0-1: RespType
//	 1-2: HiRespType
//	 2-4: _
//	 4-8: _
//	8-16: TimeStamp
//
// 16-24: ChallengeFromClient
// 24-28: _
//
//	28-: AvPairs
type NTLMv2ClientChallenge struct {
	RespType            byte
	HiRespType          byte
	_                   uint16
	_                   uint32
	Timestamp           uint64
	ChallengeFromClient [8]byte
	_                   uint32
	AvPairs             []byte
}

//	NTLMv2Response
//
// 0-16: Response
//
//	16-: NTLMv2ClientChallenge
type NTLMv2Response struct {
	Response [16]byte
	NTLMv2ClientChallenge
}
