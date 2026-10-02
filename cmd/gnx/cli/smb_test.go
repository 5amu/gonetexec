package cli

import (
	"reflect"
	"testing"
)

func TestSplitArgs(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"ls", []string{"ls"}},
		{"get file.txt", []string{"get", "file.txt"}},
		{"  cd   Users  ", []string{"cd", "Users"}},
		{`get "Program Files\app.exe" out.exe`, []string{"get", `Program Files\app.exe`, "out.exe"}},
		{`cat "a b c"`, []string{"cat", "a b c"}},
		{"rename\told\tnew", []string{"rename", "old", "new"}},
	}
	for _, c := range cases {
		got := splitArgs(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("splitArgs(%q) = %#v want %#v", c.in, got, c.want)
		}
	}
}
