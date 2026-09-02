package securefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadProjectedAllowsKubernetesLayoutAndRejectsEscape(t *testing.T) {
	root := t.TempDir()
	version := filepath.Join(root, "..2026_09_02")
	if err := os.Mkdir(version, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(version, "private-key.pem")
	if err := os.WriteFile(target, []byte("secret"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(version), filepath.Join(root, "..data")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "private-key.pem")
	if err := os.Symlink(filepath.Join("..data", "private-key.pem"), path); err != nil {
		t.Fatal(err)
	}
	raw, err := ReadProjected(path, 64, 0o400)
	if err != nil || string(raw) != "secret" {
		t.Fatalf("projected secret = %q, %v", raw, err)
	}

	outside := filepath.Join(t.TempDir(), "outside.pem")
	if err := os.WriteFile(outside, []byte("escape"), 0o400); err != nil {
		t.Fatal(err)
	}
	escape := filepath.Join(root, "escape.pem")
	if err := os.Symlink(outside, escape); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProjected(escape, 64, 0o400); err == nil {
		t.Fatal("projected secret escape was accepted")
	}
}

func TestReadProjectedRejectsUnsafeMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProjected(path, 64, 0o400, 0o440, 0o600); err == nil {
		t.Fatal("unsafe secret mode was accepted")
	}
}
