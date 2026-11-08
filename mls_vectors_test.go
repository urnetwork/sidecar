// Loads the mlswg's test vectors (testdata/mls/mlswg/) and the X-Wing KAT files. §10.4 runs every
// mlswg file covering a v0 feature under suite 0x0001, the only classical suite here, so each
// vector test skips the other suites' entries by value and fails when it finds no 0x0001 entry.
//
// The files are built into the test binary. §18.10 keeps mls_ on the sidecar_http leg, whose Worker
// has no file system, and a known answer proves most on the runtime the code ships on.

package sidecar

import (
	"bufio"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"testing"
)

// Everything under testdata/mls/, the mlswg's files and the X-Wing KATs alike.
//
//go:embed testdata/mls
var mlsVectorFiles embed.FS

// The mlswg's JSON form of binary data. null decodes to nil.
type mlsHexBytes []byte

// Hex text or null.
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

// Hex text, or null for nil, as the mlswg writes an absent value.
func (self mlsHexBytes) MarshalJSON() ([]byte, error) {
	if self == nil {
		return []byte("null"), nil
	}
	return json.Marshal(hex.EncodeToString(self))
}

// Reads one file under testdata/mls/ into target.
func mlsLoadVectorFile(t testing.TB, directory string, name string, target any) {
	t.Helper()
	filePath := path.Join("testdata", "mls", directory, name+".json")
	encoded, err := mlsVectorFiles.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, target); err != nil {
		t.Fatalf("%s: %v", filePath, err)
	}
}

// Reads the mlswg vector file with this name.
func mlsLoadVectors(t testing.TB, name string, target any) {
	t.Helper()
	mlsLoadVectorFile(t, "mlswg", name, target)
}

// Every vector file stays byte for byte what upstream published.
func TestMlsVectorFilesMatchUpstream(t *testing.T) {
	directory := path.Join("testdata", "mls", "mlswg")
	sums, err := mlsVectorFiles.Open(path.Join(directory, "SHA256SUMS"))
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
		encoded, err := mlsVectorFiles.ReadFile(path.Join(directory, name))
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
	jsonPaths, err := fs.Glob(mlsVectorFiles, path.Join(directory, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, jsonPath := range jsonPaths {
		if !listedNames[path.Base(jsonPath)] {
			t.Errorf("%s is not in SHA256SUMS", jsonPath)
		}
	}
}
