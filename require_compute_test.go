//go:build !js

// Holds the enclave SSH server off x/crypto/ssh below v0.59.0 while the module's raise waits. x/crypto/ssh's
// advisories cluster in its authentication callbacks, VerifiedPublicKeyCallback's source-address handling among them
// (CVE-2026-46595), so DESIGN-COMPUTE §12.5 and D-SSH-1 take keys through that callback only on v0.59.0 or later.
// v0.59.0 brings golang.org/x/text v0.44.0, normalizer 1's pin (DESIGN §4.7, §11.14), so CARCH-M11-02 left x/crypto
// at v0.58.0 and raised the question compute-modules-x-crypto-raise. Until go.mod names v0.59.0 or later, no Go file
// of this repository may set the callback, so the server cannot land on the vulnerable module.

package sidecar

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// x/crypto's require line in a go.mod, inside a require block or on its own.
var requireComputeXCryptoPattern = regexp.MustCompile(`(?m)^\s*(?:require\s+)?golang\.org/x/crypto v([0-9]+)\.([0-9]+)\.([0-9]+)\b`)

// The directories the scan leaves: vendored source, data, documents and version control.
var requireComputeSkippedDirectoryNames = map[string]bool{
	".git":           true,
	"design":         true,
	"research_notes": true,
	"testdata":       true,
	"third_party":    true,
}

// True when the go.mod text requires x/crypto v0.59.0 or later.
func requireComputeXCryptoFixed(goMod string) (bool, string) {
	match := requireComputeXCryptoPattern.FindStringSubmatch(goMod)
	if match == nil {
		return false, "no golang.org/x/crypto require"
	}
	major, _ := strconv.Atoi(match[1])
	minor, _ := strconv.Atoi(match[2])
	version := "v" + match[1] + "." + match[2] + "." + match[3]
	return 0 < major || 59 <= minor, version
}

// The Go files under top, tests aside, that set ssh's VerifiedPublicKeyCallback.
func requireComputeVerifiedKeyCallbackFiles(t *testing.T, top string) []string {
	t.Helper()
	files := []string{}
	err := filepath.WalkDir(top, func(walkPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if walkPath != top && requireComputeSkippedDirectoryNames[entry.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		data, err := os.ReadFile(walkPath)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), "VerifiedPublicKeyCallback") {
			files = append(files, walkPath)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestSshVerifiedKeyCallbackWaitsForTheFixedXCrypto(t *testing.T) {
	goMod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	fixed, version := requireComputeXCryptoFixed(string(goMod))
	if fixed {
		return
	}
	for _, file := range requireComputeVerifiedKeyCallbackFiles(t, ".") {
		t.Errorf("%s sets ssh's VerifiedPublicKeyCallback, and go.mod requires golang.org/x/crypto %s, below v0.59.0 (CVE-2026-46595; compute-modules-x-crypto-raise)", file, version)
	}
}

// The version reading, on both sides of v0.59.0 and past a major version.
func TestSshVerifiedKeyCallbackReadsTheXCryptoVersion(t *testing.T) {
	for goMod, want := range map[string]bool{
		"require (\n\tgolang.org/x/crypto v0.58.0\n)\n":             false,
		"require (\n\tgolang.org/x/crypto v0.59.0\n)\n":             true,
		"require (\n\tgolang.org/x/crypto v0.60.1 // indirect\n)\n": true,
		"require golang.org/x/crypto v1.0.0\n":                      true,
		"require golang.org/x/net v0.62.0\n":                        false,
	} {
		if got, version := requireComputeXCryptoFixed(goMod); got != want {
			t.Errorf("%q reads as %v (%s), want %v", goMod, got, version, want)
		}
	}
}

// A planted file that sets the callback fails the scan, and a test file does not count.
func TestSshVerifiedKeyCallbackScanFindsAPlantedServer(t *testing.T) {
	top := t.TempDir()
	plant := func(name string, text string) {
		path := filepath.Join(top, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	server := "package sidecar\n\nvar _ = ssh.ServerConfig{VerifiedPublicKeyCallback: nil}\n"
	plant("ssh_server.go", server)
	plant("ssh_server_test.go", server)
	plant("third_party/vendored/server.go", server)
	files := requireComputeVerifiedKeyCallbackFiles(t, top)
	if len(files) != 1 || filepath.Base(files[0]) != "ssh_server.go" {
		t.Fatalf("found %v, want ssh_server.go alone", files)
	}
}
