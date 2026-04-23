package smb

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"

	"github.com/5amu/gonetexec/pkg/smb/internal/crypto/ccm"
	"github.com/5amu/gonetexec/pkg/smb/internal/crypto/cmac"
	"github.com/5amu/gonetexec/pkg/smb/internal/smb2"
	spnegol "github.com/5amu/gonetexec/pkg/smb/internal/spnego"

	"github.com/5amu/gonetexec/pkg/smb/internal/erref"
)

func sessionSetup(conn *conn, i Initiator, ctx context.Context) (*session, error) {
	spnego := newSpnegoClient([]Initiator{i})

	outputToken, err := spnego.initSecContext()
	if err != nil {
		return nil, &InvalidResponseError{err.Error()}
	}

	req := &smb2.SessionSetupRequest{
		Flags:             0,
		Capabilities:      conn.capabilities & (smb2.SMB2_GLOBAL_CAP_DFS),
		Channel:           0,
		SecurityBuffer:    outputToken,
		PreviousSessionId: 0,
	}

	if conn.requireSigning {
		req.SecurityMode = smb2.SMB2_NEGOTIATE_SIGNING_REQUIRED
	} else {
		req.SecurityMode = smb2.SMB2_NEGOTIATE_SIGNING_ENABLED
	}

	req.CreditCharge = 1
	req.CreditRequestResponse = conn.account.initRequest()

	rr, err := conn.send(req, ctx)
	if err != nil {
		return nil, err
	}

	pkt, err := conn.recv(rr)
	if err != nil {
		return nil, err
	}

	p := smb2.PacketCodec(pkt)

	if erref.NtStatus(p.Status()) != erref.STATUS_MORE_PROCESSING_REQUIRED {
		return nil, &InvalidResponseError{fmt.Sprintf("expected status: %v, got %v", erref.STATUS_MORE_PROCESSING_REQUIRED, erref.NtStatus(p.Status()))}
	}

	res, err := accept(smb2.SMB2_SESSION_SETUP, pkt)
	if err != nil {
		return nil, err
	}

	r := smb2.SessionSetupResponseDecoder(res)
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken session setup response format"}
	}

	sessionFlags := r.SessionFlags()
	if conn.requireSigning {
		if sessionFlags&smb2.SMB2_SESSION_FLAG_IS_GUEST != 0 {
			return nil, &InvalidResponseError{"guest account doesn't support signing"}
		}
		if sessionFlags&smb2.SMB2_SESSION_FLAG_IS_NULL != 0 {
			return nil, &InvalidResponseError{"anonymous account doesn't support signing"}
		}
	}

	s := &session{
		conn:           conn,
		treeConnTables: make(map[uint32]*treeConn),
		sessionFlags:   sessionFlags,
		sessionId:      p.SessionId(),
	}

	switch conn.dialect {
	case smb2.SMB311:
		s.preauthIntegrityHashValue = conn.preauthIntegrityHashValue

		switch conn.preauthIntegrityHashId {
		case smb2.SHA512:
			h := sha512.New()
			h.Write(s.preauthIntegrityHashValue[:])
			h.Write(rr.pkt)
			h.Sum(s.preauthIntegrityHashValue[:0])

			h.Reset()
			h.Write(s.preauthIntegrityHashValue[:])
			h.Write(pkt)
			h.Sum(s.preauthIntegrityHashValue[:0])
		}

	}

	outputToken, err = spnego.acceptSecContext(r.SecurityBuffer())
	if err != nil {
		return nil, &InvalidResponseError{err.Error()}
	}

	req.SecurityBuffer = outputToken

	req.CreditRequestResponse = 0

	if t, e := spnegol.DecodeNegTokenResp(outputToken); e == nil {
		off := 8 + 4 + 8 + 4
		offset := binary.LittleEndian.Uint32(t.ResponseToken[off : off+4])
		s.nproofstr = t.ResponseToken[offset : offset+16]
		s.sessionk = t.ResponseToken[len(t.ResponseToken)-16 : len(t.ResponseToken)]
	}

	// We set session before sending packet just for setting hdr.SessionId.
	// But, we should not permit access from receiver until the session information is completed.
	conn.session = s

	rr, err = s.send(req, ctx)
	if err != nil {
		return nil, err
	}

	if s.sessionFlags&(smb2.SMB2_SESSION_FLAG_IS_GUEST|smb2.SMB2_SESSION_FLAG_IS_NULL) == 0 {
		sessionKey := spnego.sessionKey()

		switch conn.dialect {
		case smb2.SMB202, smb2.SMB210:
			s.signer = hmac.New(sha256.New, sessionKey)
			s.verifier = hmac.New(sha256.New, sessionKey)
		case smb2.SMB300, smb2.SMB302:
			signingKey := kdf(sessionKey, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"))
			ciph, err := aes.NewCipher(signingKey)
			if err != nil {
				return nil, &InternalError{err.Error()}
			}
			s.signer = cmac.New(ciph)
			s.verifier = cmac.New(ciph)

			// s.applicationKey = kdf(sessionKey, []byte("SMB2APP\x00"), []byte("SmbRpc\x00"))

			encryptionKey := kdf(sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerIn \x00"))
			decryptionKey := kdf(sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerOut\x00"))

			ciph, err = aes.NewCipher(encryptionKey)
			if err != nil {
				return nil, &InternalError{err.Error()}
			}
			s.encrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
			if err != nil {
				return nil, &InternalError{err.Error()}
			}

			ciph, err = aes.NewCipher(decryptionKey)
			if err != nil {
				return nil, &InternalError{err.Error()}
			}
			s.decrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
			if err != nil {
				return nil, &InternalError{err.Error()}
			}
		case smb2.SMB311:
			switch conn.preauthIntegrityHashId {
			case smb2.SHA512:
				h := sha512.New()
				h.Write(s.preauthIntegrityHashValue[:])
				h.Write(rr.pkt)
				h.Sum(s.preauthIntegrityHashValue[:0])
			}

			signingKey := kdf(sessionKey, []byte("SMBSigningKey\x00"), s.preauthIntegrityHashValue[:])
			ciph, err := aes.NewCipher(signingKey)
			if err != nil {
				return nil, &InternalError{err.Error()}
			}
			s.signer = cmac.New(ciph)
			s.verifier = cmac.New(ciph)

			// s.applicationKey = kdf(sessionKey, []byte("SMBAppKey\x00"), preauthIntegrityHashValue)

			encryptionKey := kdf(sessionKey, []byte("SMBC2SCipherKey\x00"), s.preauthIntegrityHashValue[:])
			decryptionKey := kdf(sessionKey, []byte("SMBS2CCipherKey\x00"), s.preauthIntegrityHashValue[:])

			switch s.cipherId {
			case smb2.AES128CCM:
				ciph, err := aes.NewCipher(encryptionKey)
				if err != nil {
					return nil, &InternalError{err.Error()}
				}
				s.encrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
				if err != nil {
					return nil, &InternalError{err.Error()}
				}

				ciph, err = aes.NewCipher(decryptionKey)
				if err != nil {
					return nil, &InternalError{err.Error()}
				}
				s.decrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
				if err != nil {
					return nil, &InternalError{err.Error()}
				}
			case smb2.AES128GCM:
				ciph, err := aes.NewCipher(encryptionKey)
				if err != nil {
					return nil, &InternalError{err.Error()}
				}
				s.encrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
				if err != nil {
					return nil, &InternalError{err.Error()}
				}

				ciph, err = aes.NewCipher(decryptionKey)
				if err != nil {
					return nil, &InternalError{err.Error()}
				}
				s.decrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
				if err != nil {
					return nil, &InternalError{err.Error()}
				}
			}
		}
	}

	pkt, err = s.recv(rr)
	if err != nil {
		return nil, err
	}

	res, err = accept(smb2.SMB2_SESSION_SETUP, pkt)
	if err != nil {
		return nil, err
	}

	r = smb2.SessionSetupResponseDecoder(res)
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken session setup response format"}
	}

	if erref.NtStatus(smb2.PacketCodec(pkt).Status()) != erref.STATUS_SUCCESS {
		return nil, &InvalidResponseError{"broken session setup response format"}
	}

	s.sessionFlags = r.SessionFlags()

	// now, allow access from receiver
	s.enableSession()

	return s, nil
}

type session struct {
	*conn
	treeConnTables            map[uint32]*treeConn
	sessionFlags              uint16
	sessionId                 uint64
	preauthIntegrityHashValue [64]byte

	signer    hash.Hash
	verifier  hash.Hash
	encrypter cipher.AEAD
	decrypter cipher.AEAD

	nproofstr []byte
	sessionk  []byte
}

func (s *session) logoff(ctx context.Context) error {
	req := new(smb2.LogoffRequest)

	req.CreditCharge = 1

	_, err := s.sendRecv(smb2.SMB2_LOGOFF, req, ctx)
	if err != nil {
		return err
	}

	s.conn.rdone <- struct{}{}
	s.conn.t.Close()

	return nil
}

func (s *session) sendRecv(cmd uint16, req smb2.Packet, ctx context.Context) (res []byte, err error) {
	rr, err := s.send(req, ctx)
	if err != nil {
		return nil, err
	}

	pkt, err := s.recv(rr)
	if err != nil {
		return nil, err
	}

	return accept(cmd, pkt)
}

func (s *session) recv(rr *requestResponse) (pkt []byte, err error) {
	pkt, err = s.conn.recv(rr)
	if err != nil {
		return nil, err
	}
	if sessionId := smb2.PacketCodec(pkt).SessionId(); sessionId != s.sessionId {
		return nil, &InvalidResponseError{fmt.Sprintf("expected session id: %v, got %v", s.sessionId, sessionId)}
	}
	return pkt, err
}

func (s *session) sign(pkt []byte) []byte {
	p := smb2.PacketCodec(pkt)

	p.SetFlags(p.Flags() | smb2.SMB2_FLAGS_SIGNED)

	h := s.signer

	h.Reset()

	h.Write(pkt)

	p.SetSignature(h.Sum(nil))

	return pkt
}

func (s *session) verify(pkt []byte) (ok bool) {
	p := smb2.PacketCodec(pkt)

	signature := append([]byte{}, p.Signature()...)

	p.SetSignature(zero[:])

	h := s.verifier

	h.Reset()

	h.Write(pkt)

	p.SetSignature(h.Sum(nil))

	return bytes.Equal(signature, p.Signature())
}

func (s *session) encrypt(pkt []byte) ([]byte, error) {
	nonce := make([]byte, s.encrypter.NonceSize())

	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	c := make([]byte, 52+len(pkt)+16)

	t := smb2.TransformCodec(c)

	t.SetProtocolId()
	t.SetNonce(nonce)
	t.SetOriginalMessageSize(uint32(len(pkt)))
	t.SetFlags(smb2.Encrypted)
	t.SetSessionId(s.sessionId)

	s.encrypter.Seal(c[:52], nonce, pkt, t.AssociatedData())

	t.SetSignature(c[len(c)-16:])

	c = c[:len(c)-16]

	return c, nil
}

func (s *session) decrypt(pkt []byte) ([]byte, error) {
	t := smb2.TransformCodec(pkt)

	c := append(t.EncryptedData(), t.Signature()...)

	return s.decrypter.Open(
		c[:0],
		t.Nonce()[:s.decrypter.NonceSize()],
		c,
		t.AssociatedData(),
	)
}
