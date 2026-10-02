package cli

import "testing"

func TestToDN(t *testing.T) {
	cases := map[string]string{
		"corp.local":    "dc=corp,dc=local",
		"a.b.c.example": "dc=a,dc=b,dc=c,dc=example",
		"single":        "dc=single",
	}
	for in, want := range cases {
		if got := toDN(in); got != want {
			t.Errorf("toDN(%q) = %q want %q", in, got, want)
		}
	}
}

func TestDecodeSID(t *testing.T) {
	// S-1-5-21-1-2-3 : revision 1, authority 5, sub-authorities 21,1,2,3.
	raw := []byte{
		0x01,                               // revision
		0x04,                               // sub-authority count
		0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // authority = 5 (big-endian)
		0x15, 0x00, 0x00, 0x00, // 21
		0x01, 0x00, 0x00, 0x00, // 1
		0x02, 0x00, 0x00, 0x00, // 2
		0x03, 0x00, 0x00, 0x00, // 3
	}
	want := "S-1-5-21-1-2-3"
	if got := decodeSID(string(raw)); got != want {
		t.Errorf("decodeSID = %q want %q", got, want)
	}
}

func TestDecodeADTimestamp(t *testing.T) {
	if got := decodeADTimestamp("0"); got != "Not Set" {
		t.Errorf("zero timestamp: got %q want Not Set", got)
	}
	if got := decodeADTimestamp("9223372036854775807"); got != "Not Set" {
		t.Errorf("never-expires timestamp: got %q want Not Set", got)
	}
}

func TestUACFilter(t *testing.T) {
	// DONT_REQ_PREAUTH used by asreproast.
	if got := uacFilter(uacDontRequirePreauth); got != "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" {
		t.Errorf("uacFilter = %q", got)
	}
}

func TestParseLDAPActionDelegation(t *testing.T) {
	action, _, _ := parseLDAPAction(
		nil, "", "", "", "", "", "",
		false, false, false, false,
		false, false, false, false,
		false, false, false, false,
		false, false, false, false,
		false, false, false, false,
		false, false,
		false, false, false, false, false,
		"", false, false, true, false,
	)
	if action != ldapDelegation {
		t.Errorf("find-delegation: got action %d want %d", action, ldapDelegation)
	}
}
