package encoder_test

import (
	"slices"
	"testing"

	"github.com/5amu/gonetexec/pkg/encoder"
)

func TestStringToUnicode(t *testing.T) {
	str := "Test"
	exp := []byte{'T', '\x00', 'e', '\x00', 's', '\x00', 't', '\x00'}
	res := encoder.StringToUnicode(str)
	if slices.Compare(res, exp) != 0 {
		t.Errorf("%v, expected: %v", res, exp)
	}

	str2 := ""
	res2 := encoder.StringToUnicode(str2)
	if res2 != nil {
		t.Errorf("%v, expected: %v", res2, nil)
	}
	i := len(res2)
	if i != 0 {
		t.Errorf("should be 0")
	}
}
