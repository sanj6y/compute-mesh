// Package identity manages the node's stable identifier. The node_id is
// generated once, persisted under the data dir, and later bound into the
// node's certificate SAN by the pki package, so it must never change for the
// lifetime of an install.
package identity

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const nodeIDFile = "node_id"

// validNodeID is the subset of DNS-SD-instance-safe, URL-safe characters.
// It is also what the pki package will accept in the cert SAN URI.
var validNodeID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

var ErrInvalidNodeID = errors.New("identity: node_id must match " + validNodeID.String())

// Validate reports whether id is a well-formed node_id.
func Validate(id string) error {
	if !validNodeID.MatchString(id) {
		return fmt.Errorf("%w: %q", ErrInvalidNodeID, id)
	}
	return nil
}

// LoadOrCreate returns the node_id stored in dir, creating dir (0700) and the
// id (0600) on first run. The generated id is "<hostname>-<6 hex>" so logs
// stay readable across a small mesh while still being unique.
func LoadOrCreate(dir string) (string, error) {
	path := filepath.Join(dir, nodeIDFile)
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		id := strings.TrimSpace(string(b))
		if err := Validate(id); err != nil {
			return "", fmt.Errorf("%s: %w", path, err)
		}
		return id, nil
	case !errors.Is(err, os.ErrNotExist):
		return "", fmt.Errorf("identity: read %s: %w", path, err)
	}

	id, err := Generate()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("identity: create %s: %w", dir, err)
	}
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("identity: write %s: %w", path, err)
	}
	return id, nil
}

// Set writes an operator-chosen node_id, refusing to change an existing one
// unless overwrite is set: certs are bound to it.
func Set(dir, id string, overwrite bool) error {
	if err := Validate(id); err != nil {
		return err
	}
	path := filepath.Join(dir, nodeIDFile)
	if _, err := os.Stat(path); err == nil && !overwrite {
		existing, _ := LoadOrCreate(dir)
		if existing == id {
			return nil
		}
		return fmt.Errorf("identity: %s already holds node_id %q; certs are bound to it", path, existing)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("identity: create %s: %w", dir, err)
	}
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		return fmt.Errorf("identity: write %s: %w", path, err)
	}
	return nil
}

// Generate returns a fresh "<hostname>-<6 hex>" id without persisting it.
func Generate() (string, error) {
	var buf [3]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("identity: random: %w", err)
	}
	host, _ := os.Hostname()
	return sanitizeHost(host) + "-" + hex.EncodeToString(buf[:]), nil
}

// sanitizeHost lowercases and strips anything outside [a-z0-9-], truncating
// so the final id fits in 63 characters. Falls back to "node".
func sanitizeHost(h string) string {
	h = strings.ToLower(h)
	if i := strings.IndexByte(h, '.'); i >= 0 {
		h = h[:i] // "macbook-pro.local" -> "macbook-pro"
	}
	var sb strings.Builder
	for _, r := range h {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			sb.WriteRune(r)
		}
	}
	out := strings.Trim(sb.String(), "-")
	const maxHost = 63 - len("-abcdef")
	if len(out) > maxHost {
		out = strings.TrimRight(out[:maxHost], "-")
	}
	if out == "" {
		out = "node"
	}
	return out
}
