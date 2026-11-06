// Loads the mlswg's test vectors (testdata/mls/mlswg/) and the X-Wing KAT files. §10.4 runs every
// mlswg file covering a v0 feature under suite 0x0001, the only classical suite here, so each
// vector test skips the other suites' entries by value and fails when it finds no 0x0001 entry.

package sidecar

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The mlswg's JSON form of binary data. null decodes to nil.
type mlsHexBytes []byte

func (self *mlsHexBytes) UnmarshalJSON(encoded []byte) error {
	var text *string
	if err := json.Unmarshal(encoded, &text); err != nil {
		return err
	}
	if text == nil {
		*self = nil
		return nil
	}
	decoded, err := hex.DecodeString(*text)
	if err != nil {
		return err
	}
	*self = decoded
	return nil
}

// Reads one vector file into target.
func mlsLoadVectorFile(t testing.TB, path string, target any) {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, target); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

// Reads the mlswg vector file with this name.
func mlsLoadVectors(t testing.TB, name string, target any) {
	t.Helper()
	mlsLoadVectorFile(t, filepath.Join("testdata", "mls", "mlswg", name+".json"), target)
}

// Every vector file stays byte for byte what upstream published.
func TestMlsVectorFilesMatchUpstream(t *testing.T) {
	directory := filepath.Join("testdata", "mls", "mlswg")
	sums, err := os.Open(filepath.Join(directory, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	defer sums.Close()

	listedNames := map[string]bool{}
	scanner := bufio.NewScanner(sums)
	for scanner.Scan() {
		sum, name, found := strings.Cut(scanner.Text(), "  ")
		if !found {
			t.Fatalf("bad line %q", scanner.Text())
		}
		listedNames[name] = true
		encoded, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(encoded)); got != sum {
			t.Errorf("%s: sha256 %s, want %s", name, got, sum)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	// the sixteen files §10.3 names
	if len(listedNames) != 16 {
		t.Errorf("%d files listed, want 16", len(listedNames))
	}
	jsonPaths, err := filepath.Glob(filepath.Join(directory, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, jsonPath := range jsonPaths {
		if !listedNames[filepath.Base(jsonPath)] {
			t.Errorf("%s is not in SHA256SUMS", jsonPath)
		}
	}
}
