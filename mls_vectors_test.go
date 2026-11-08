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

// One mlswg file's place in §10.4's conformance plan: the tests that run it under 0x0001, named by value so a rename
// fails to build here rather than leaving this record stale, and what of it they skip and why.
type mlsVectorFileOutcome struct {
	tests []func(*testing.T)
	// whether its entries carry a cipher_suite, of which the tests run 0x0001's; the rest hold no suite's values
	suiteBound bool
	skipped    string
}

// Every one of the mlswg's 16 files (§10.3) under §10.4's plan. Each named test fails on any entry it runs and does
// not reproduce, and on finding no 0x0001 entry where the file is suite-bound; what one skips, it counts, and the
// reason here is the one it checks.
var mlsVectorFileOutcomes = map[string]mlsVectorFileOutcome{
	"crypto-basics.json":   {tests: []func(*testing.T){TestMlsCryptoBasicsVectors}, suiteBound: true},
	"deserialization.json": {tests: []func(*testing.T){TestMlsVectorHeaderVectors}},
	"key-schedule.json":    {tests: []func(*testing.T){TestMlsKeyScheduleVectors}, suiteBound: true},
	"message-protection.json": {tests: []func(*testing.T){TestMlsMessageProtectionVectors}, suiteBound: true,
		skipped: "each message opens and verifies through a test reader; the production parse refuses the standalone proposals, a member's PublicMessage commit and the application message (§10.4), and the PrivateMessage commit once it decrypts to a PSK proposal"},
	"messages.json": {tests: []func(*testing.T){TestMlsMessagesVectors, TestMlsMessagesFramingVectors, TestMlsMessagesKeyPackageVectors, TestMlsMessagesWelcomeVectors},
		skipped: "syntax alone: what the subset takes re-encodes byte for byte; Update, PSK and ReInit proposals, every framed message but a PrivateMessage commit, and group secrets naming a PSK are refused when parsed (§10.4)"},
	"passive-client-handling-commit.json": {tests: []func(*testing.T){TestMlsPassiveClientVectors}, suiteBound: true,
		skipped: "every 0x0001 entry's Welcome names a PSK, refused when parsed; mlsinterop's mls-go differential follows member commits instead (testdata/mls/0x0001/)"},
	"passive-client-random.json": {tests: []func(*testing.T){TestMlsPassiveClientVectors}, suiteBound: true,
		skipped: "the Welcome joins; its first commit is a member's PublicMessage, refused when parsed (D-KEYS-3), and the rest of the entry with it"},
	"passive-client-welcome.json": {tests: []func(*testing.T){TestMlsPassiveClientVectors}, suiteBound: true,
		skipped: "entries whose Welcome names a PSK, refused when parsed"},
	"psk_secret.json": {suiteBound: true,
		skipped: "the whole file: PSKs are refused when parsed (§10.4), so it covers no v0 feature"},
	"secret-tree.json":       {tests: []func(*testing.T){TestMlsSecretTreeVectors}, suiteBound: true},
	"transcript-hashes.json": {tests: []func(*testing.T){TestMlsTranscriptHashVectors}, suiteBound: true},
	"tree-math.json":         {tests: []func(*testing.T){TestMlsTreeMathVectors}},
	"tree-operations.json": {tests: []func(*testing.T){TestMlsTreeOperationsVectors}, suiteBound: true,
		skipped: "entries whose proposal is an Update, refused when parsed (§10.4)"},
	"tree-validation.json": {tests: []func(*testing.T){TestMlsTreeValidationVectors}, suiteBound: true},
	"treekem.json":         {tests: []func(*testing.T){TestMlsTreeKemVectors}, suiteBound: true},
	"welcome.json":         {tests: []func(*testing.T){TestMlsWelcomeVectors}, suiteBound: true},
}

// §22.10's per-file vectors evidence: every file SHA256SUMS lists has its outcome, every suite-bound file one 0x0001
// entry or more, and the run logs each file's counts with what its tests skip. tree-operations' Update entries are
// counted from the bytes, the first two of a Proposal being its type.
func TestMlsVectorFilesEachHaveAnOutcome(t *testing.T) {
	paths, err := fs.Glob(mlsVectorFiles, path.Join("testdata", "mls", "mlswg", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 16 || len(mlsVectorFileOutcomes) != 16 {
		t.Fatalf("%d files and %d outcomes, want 16 of each", len(paths), len(mlsVectorFileOutcomes))
	}
	for _, filePath := range paths {
		name := path.Base(filePath)
		outcome, ok := mlsVectorFileOutcomes[name]
		if !ok {
			t.Errorf("%s has no outcome", name)
			continue
		}
		var entries []map[string]any
		mlsLoadVectors(t, strings.TrimSuffix(name, ".json"), &entries)
		ours := 0
		for _, entry := range entries {
			if suite, ok := entry["cipher_suite"].(float64); ok && uint16(suite) == 0x0001 {
				ours += 1
			}
		}
		if outcome.suiteBound && ours == 0 {
			t.Errorf("%s holds no 0x0001 entry", name)
		}
		if len(outcome.tests) == 0 && outcome.skipped == "" {
			t.Errorf("%s: no test runs it and no reason says why", name)
		}
		line := fmt.Sprintf("%s: %d entries", name, len(entries))
		if outcome.suiteBound {
			line += fmt.Sprintf(", %d under 0x0001", ours)
		}
		if name == "tree-operations.json" {
			updates := 0
			for _, entry := range entries {
				proposal, _ := hex.DecodeString(fmt.Sprint(entry["proposal"]))
				if suite, _ := entry["cipher_suite"].(float64); uint16(suite) == 0x0001 && 2 <= len(proposal) && proposal[0] == 0 && proposal[1] == 2 {
					updates += 1
				}
			}
			line += fmt.Sprintf(", %d of them Updates", updates)
		}
		line += fmt.Sprintf("; run by %d tests", len(outcome.tests))
		if outcome.skipped != "" {
			line += "; skipped: " + outcome.skipped
		}
		t.Log(line)
	}
}
