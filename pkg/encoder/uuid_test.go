package encoder_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/5amu/gonetexec/pkg/encoder"
)

func TestUUIDFromString(t *testing.T) {
	ustr := "8a885d04-1ceb-11c9-9fe8-08002b104860"
	bsli := []byte{4, 93, 136, 138, 235, 28, 201, 17, 159, 232, 8, 0, 43, 16, 72, 96}

	b := encoder.UUIDFromString(ustr)
	if slices.Compare(b, bsli) != 0 {
		t.Fail()
	}
}

func TestStringFromUUID(t *testing.T) {
	ustr := "8a885d04-1ceb-11c9-9fe8-08002b104860"
	bsli := []byte{4, 93, 136, 138, 235, 28, 201, 17, 159, 232, 8, 0, 43, 16, 72, 96}

	d := encoder.StringFromUUID(bsli)
	if strings.Compare(d, ustr) != 0 {
		t.Fail()
	}
}
