// Package netrc provides minimal parsing of the netrc credential file. It
// supports the subset used for HTTP authentication — machine/default entries
// with login and password — and skips macdef bodies. It gives the HTTP protocol
// the same ~/.netrc support that tools like curl and git provide.
package netrc

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Machine holds the credentials for a single netrc entry.
type Machine struct {
	Name     string
	Login    string
	Password string
}

// Lookup returns the credentials for host from the user's netrc file, or nil if
// the file does not exist or contains no matching entry. The location is taken
// from $NETRC, falling back to ~/.netrc (~/_netrc on Windows). A `default` entry
// matches any host with no explicit `machine` entry.
func Lookup(host string) (*Machine, error) {
	path := DefaultPath()
	if path == "" {
		return nil, nil
	}
	return LookupFile(path, host)
}

// LookupFile is like Lookup but reads from an explicit path. A missing file or a
// directory is not an error: it returns nil, nil.
func LookupFile(path, host string) (*Machine, error) {
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if fi.IsDir() {
		return nil, nil
	}

	f, err := os.Open(path) // #nosec G304 -- the caller's own netrc file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	return parse(f, host)
}

// DefaultPath returns the netrc file path from $NETRC, or the per-user default
// (~/.netrc, or ~/_netrc on Windows). It returns "" if $NETRC is unset and the
// home directory cannot be determined.
func DefaultPath() string {
	if p := os.Getenv("NETRC"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	name := ".netrc"
	if runtime.GOOS == "windows" {
		name = "_netrc"
	}
	return filepath.Join(home, name)
}

func parse(r io.Reader, host string) (*Machine, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	// Collect tokens, skipping macdef bodies (which run until a blank line and
	// may contain arbitrary text, including netrc keywords).
	var tokens []string
	inMacdef := false
	for _, line := range strings.Split(string(data), "\n") {
		if inMacdef {
			if strings.TrimSpace(line) == "" {
				inMacdef = false
			}
			continue
		}
		for _, field := range strings.Fields(line) {
			if field == "macdef" {
				// The macdef name is the rest of this line; its body follows on
				// subsequent lines until a blank line.
				inMacdef = true
				break
			}
			tokens = append(tokens, field)
		}
	}

	var current, fallback, match *Machine
	for i := 0; i < len(tokens); i++ {
		switch tokens[i] {
		case "machine":
			i++
			if i >= len(tokens) {
				break
			}
			current = &Machine{Name: tokens[i]}
			if match == nil && tokens[i] == host {
				match = current
			}
		case "default":
			current = &Machine{}
			if fallback == nil {
				fallback = current
			}
		case "login":
			i++
			if i < len(tokens) && current != nil {
				current.Login = tokens[i]
			}
		case "password":
			i++
			if i < len(tokens) && current != nil {
				current.Password = tokens[i]
			}
		case "account":
			i++ // value ignored
		}
	}

	if match != nil {
		return match, nil
	}
	return fallback, nil
}
