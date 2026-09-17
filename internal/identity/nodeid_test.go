package identity

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		id      string
		wantErr bool
	}{
		{"a", false},
		{"macbook-pro-1a2b3c", false},
		{"node-000000", false},
		{strings.Repeat("a", 63), false},
		{"", true},
		{"-leading", true},
		{"Upper", true},
		{"has.dot", true},
		{"has space", true},
		{"under_score", true},
		{strings.Repeat("a", 64), true},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			err := Validate(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate(%q) err = %v, wantErr %v", tt.id, err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrInvalidNodeID) {
				t.Errorf("error should wrap ErrInvalidNodeID, got %v", err)
			}
		})
	}
}

func TestSanitizeHost(t *testing.T) {
	tests := []struct{ in, want string }{
		{"MacBook-Pro.local", "macbook-pro"},
		{"Sanjay's MBP", "sanjaysmbp"},
		{"gpu_box_01", "gpubox01"},
		{"", "node"},
		{"---", "node"},
		{".local", "node"},
		{strings.Repeat("x", 100), strings.Repeat("x", 56)},
		{strings.Repeat("x", 55) + "-yyyy", strings.Repeat("x", 55)},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := sanitizeHost(tt.in)
			if got != tt.want {
				t.Errorf("sanitizeHost(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if err := Validate(got + "-abcdef"); err != nil {
				t.Errorf("sanitized host does not produce a valid id: %v", err)
			}
		})
	}
}

func TestGenerateIsValidAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		id, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		if err := Validate(id); err != nil {
			t.Fatalf("Generate() produced invalid id: %v", err)
		}
		if seen[id] {
			t.Fatalf("Generate() repeated %q", id)
		}
		seen[id] = true
	}
}

func TestLoadOrCreate(t *testing.T) {
	t.Run("creates then reuses", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "lcm") // does not exist yet
		id1, err := LoadOrCreate(dir)
		if err != nil {
			t.Fatal(err)
		}
		id2, err := LoadOrCreate(dir)
		if err != nil {
			t.Fatal(err)
		}
		if id1 != id2 {
			t.Errorf("second load %q != first %q", id2, id1)
		}
		info, err := os.Stat(filepath.Join(dir, nodeIDFile))
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("node_id perm = %o, want 0600", perm)
		}
		dinfo, _ := os.Stat(dir)
		if perm := dinfo.Mode().Perm(); perm != 0o700 {
			t.Errorf("dir perm = %o, want 0700", perm)
		}
	})

	t.Run("reads existing with whitespace", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, nodeIDFile), []byte("  custom-id \n"), 0o600)
		id, err := LoadOrCreate(dir)
		if err != nil {
			t.Fatal(err)
		}
		if id != "custom-id" {
			t.Errorf("got %q, want custom-id", id)
		}
	})

	t.Run("rejects corrupt file", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, nodeIDFile), []byte("Not Valid!"), 0o600)
		if _, err := LoadOrCreate(dir); !errors.Is(err, ErrInvalidNodeID) {
			t.Errorf("err = %v, want ErrInvalidNodeID", err)
		}
	})
}
