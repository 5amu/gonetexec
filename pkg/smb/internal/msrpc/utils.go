package msrpc

import "github.com/5amu/gonetexec/pkg/smb/internal/utf16le"

func utf16lePlusCount(s string) ([]byte, int) {
	var b []byte = make([]byte, utf16le.EncodedStringLen(s+"\x00"))
	utf16le.EncodeString(b, s+"\x00")
	return b, utf16le.EncodedStringLen(s)/2 + 1
}
