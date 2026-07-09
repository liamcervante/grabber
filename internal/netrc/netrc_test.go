package netrc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLookupFile(t *testing.T) {
	const content = `
machine github.com login gh-user password gh-pass
machine gitlab.com
  login gl-user
  password gl-pass

macdef greeting
echo hi machine trap.com login trap password trap

default login def-user password def-pass
`

	dir := t.TempDir()
	path := filepath.Join(dir, ".netrc")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		host      string
		wantLogin string
		wantPass  string
	}{
		{"github.com", "gh-user", "gh-pass"},
		{"gitlab.com", "gl-user", "gl-pass"},    // login/password on following lines
		{"unknown.com", "def-user", "def-pass"}, // falls through to default
		{"trap.com", "def-user", "def-pass"},    // macdef body must not be parsed as an entry
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			m, err := LookupFile(path, tt.host)
			if err != nil {
				t.Fatalf("LookupFile error: %v", err)
			}
			if m == nil {
				t.Fatalf("no machine found for %q", tt.host)
			}
			if m.Login != tt.wantLogin || m.Password != tt.wantPass {
				t.Errorf("got login=%q password=%q, want login=%q password=%q", m.Login, m.Password, tt.wantLogin, tt.wantPass)
			}
		})
	}
}

func TestLookupFile_NoDefaultNoMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".netrc")
	if err := os.WriteFile(path, []byte("machine github.com login u password p\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	m, err := LookupFile(path, "elsewhere.com")
	if err != nil {
		t.Fatalf("LookupFile error: %v", err)
	}
	if m != nil {
		t.Errorf("expected nil for unmatched host with no default, got %+v", m)
	}
}

func TestLookupFile_MissingFileIsNotError(t *testing.T) {
	m, err := LookupFile(filepath.Join(t.TempDir(), "does-not-exist"), "github.com")
	if err != nil {
		t.Fatalf("expected no error for missing file, got %v", err)
	}
	if m != nil {
		t.Errorf("expected nil machine for missing file, got %+v", m)
	}
}

func TestDefaultPath_NETRCEnv(t *testing.T) {
	t.Setenv("NETRC", "/custom/netrc/path")
	if got := DefaultPath(); got != "/custom/netrc/path" {
		t.Errorf("DefaultPath() = %q, want /custom/netrc/path", got)
	}
}

func TestDefaultPath_HomeFallback(t *testing.T) {
	t.Setenv("NETRC", "")
	got := DefaultPath()
	if got == "" {
		t.Skip("home directory not resolvable in this environment")
	}
	if !strings.HasSuffix(got, "netrc") {
		t.Errorf("DefaultPath() = %q, want a path ending in netrc", got)
	}
}
