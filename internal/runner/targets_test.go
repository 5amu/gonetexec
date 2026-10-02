package runner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractTargetsSingleHost(t *testing.T) {
	got := ExtractTargets([]string{"dc01.corp.local"})
	if len(got) != 1 || got[0].Host != "dc01.corp.local" {
		t.Fatalf("got %+v", got)
	}
}

func TestExtractTargetsCIDR(t *testing.T) {
	cases := []struct {
		cidr string
		want int // number of usable hosts
	}{
		{"10.0.0.0/30", 2}, // 4 addrs minus network+broadcast
		{"10.0.0.0/31", 2}, // point-to-point: both usable
		{"10.0.0.5/32", 1}, // single host
		{"192.168.1.0/29", 6},
	}
	for _, c := range cases {
		got := ExtractTargets([]string{c.cidr})
		if len(got) != c.want {
			t.Errorf("%s: got %d hosts want %d", c.cidr, len(got), c.want)
		}
		for _, tgt := range got {
			if tgt.Host == "" || tgt.IP == "" {
				t.Errorf("%s: produced empty target %+v", c.cidr, tgt)
			}
		}
	}
}

func TestExtractTargetsFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(path, []byte("host-a\nhost-b\n10.0.0.0/31\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := ExtractTargets([]string{path})
	// host-a, host-b, plus two /31 hosts.
	if len(got) != 4 {
		t.Fatalf("got %d targets want 4: %+v", len(got), got)
	}
}
