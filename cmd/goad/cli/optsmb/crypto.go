package optsmb

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"unicode/utf16"

	"github.com/5amu/goad/pkg/encoder"
	"golang.org/x/crypto/md4" //nolint:staticcheck
)

func hmacmd5(k []byte, data []byte) []byte {
	h := hmac.New(md5.New, k)
	_, _ = h.Write(data)
	return h.Sum(nil)
}

func ntlmhash(pass string) []byte {
	uints := utf16.Encode([]rune(pass))
	b := bytes.Buffer{}
	_ = binary.Write(&b, binary.LittleEndian, &uints)
	mdfour := md4.New()
	_, _ = mdfour.Write(b.Bytes())
	return mdfour.Sum(nil)
}

func CalculateSMB3EncryptionKey(user, domain, hash string, sessionKey, ntProofStr []byte) []byte {

	usrdom := encoder.StringToUnicode(strings.ToUpper(user) + strings.ToUpper(domain))
	ntlmhs, _ := hex.DecodeString(hash)

	// ResponseNTKey
	rNTKey := hmacmd5(ntlmhs, usrdom)

	// KeyExchangeKey
	kExKey := hmacmd5(rNTKey, ntProofStr)

	// Session Key
	secretKey := make([]byte, len(sessionKey))
	ciph, _ := rc4.NewCipher(kExKey)
	ciph.XORKeyStream(secretKey, sessionKey)
	return secretKey
}
