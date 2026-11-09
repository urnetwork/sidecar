//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/urnetwork/sidecar"
)

// §5.9's headless key file: 0600 files in a 0700 directory, written whole; a file or directory opened to other users
// is refused as Failed, never read and never taken for absence.
func TestKeyFileRefusesLooseMode(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "keystore")
	store := &keyFileStore{files: &osKeyStoreDirectory{directory: directory}}
	if _, status := store.GetSecret("synthetic-item"); status != sidecar.SidecarKeyStoreAbsent {
		t.Fatalf("before: %d", status)
	}
	if status := store.PutSecret("synthetic-item", []byte("synthetic")); status != sidecar.SidecarKeyStoreOk {
		t.Fatalf("put: %d", status)
	}
	path := filepath.Join(directory, osKeyStoreItemFile("synthetic-item"))
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the file's mode: %v %v", info.Mode(), err)
	}
	if value, status := store.GetSecret("synthetic-item"); status != sidecar.SidecarKeyStorePresent || string(value) != "synthetic" {
		t.Fatalf("get: %d", status)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if value, status := store.GetSecret("synthetic-item"); status != sidecar.SidecarKeyStoreFailed || value != nil {
		t.Fatalf("a 0644 file: %d", status)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, status := store.GetSecret("synthetic-item"); status != sidecar.SidecarKeyStoreFailed {
		t.Fatalf("a 0755 directory: %d", status)
	}
	if status := store.PutSecret("synthetic-item", []byte("other")); status != sidecar.SidecarKeyStoreFailed {
		t.Fatalf("a write into a 0755 directory: %d", status)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if status := store.DeleteSecret("synthetic-item"); status != sidecar.SidecarKeyStoreOk {
		t.Fatalf("delete: %d", status)
	}
	if _, status := store.GetSecret("synthetic-item"); status != sidecar.SidecarKeyStoreAbsent {
		t.Fatalf("after: %d", status)
	}
	if status := store.DeleteSecret("synthetic-item"); status != sidecar.SidecarKeyStoreOk {
		t.Fatalf("deleting nothing: %d", status)
	}
}
