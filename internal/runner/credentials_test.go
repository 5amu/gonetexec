package runner

import "testing"

func TestNewCredentialsClusterBomb(t *testing.T) {
	got := NewCredentialsClusterBomb([]string{"alice", "bob"}, []string{"pw1", "pw2"})
	if len(got) != 4 {
		t.Fatalf("got %d credentials want 4", len(got))
	}
	// Empty password list yields one attempt per user with a blank password.
	blank := NewCredentialsClusterBomb([]string{"alice"}, nil)
	if len(blank) != 1 || blank[0].Password != "" {
		t.Fatalf("expected one blank-password credential, got %+v", blank)
	}
}

func TestNewCredentialsPitchFork(t *testing.T) {
	got := NewCredentialsPitchFork([]string{"alice", "bob", "carol"}, []string{"pw1", "pw2"})
	if len(got) != 2 {
		t.Fatalf("got %d credentials want 2 (min of the two lists)", len(got))
	}
	if got[0].Username != "alice" || got[0].Password != "pw1" {
		t.Errorf("pair 0 = %+v", got[0])
	}
	if got[1].Username != "bob" || got[1].Password != "pw2" {
		t.Errorf("pair 1 = %+v", got[1])
	}
}

func TestNewCredentialsNTLM(t *testing.T) {
	got := NewCredentialsNTLM([]string{"alice", "bob"}, "aad3b4:deadbeef")
	if len(got) != 2 {
		t.Fatalf("got %d credentials want 2", len(got))
	}
	for _, c := range got {
		if c.Hash != "aad3b4:deadbeef" {
			t.Errorf("credential %q missing hash: %+v", c.Username, c)
		}
	}
}
