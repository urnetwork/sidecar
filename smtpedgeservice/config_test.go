// smtpedge.yml as the edge block reads it (SMTP-M9-20): HELO names under helo_domain, the block's mark for a
// sending address that names none, and the engine's own refusals kept.

package smtpedgeservice_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/smtpedgeservice"
)

const testSmtpEdgeConfig = `
root: root.example
report_host: rpt.report.example
helo_domain: out.report.example
sending_addresses:
  - {address: 192.0.2.10, helo: o1.out.report.example}
  - {address: 192.0.2.11, helo: o2.out.report.example, fwmark: 7}
router_interfaces: [203.0.113.25]
router_lan: 10.0.0.25:2525
loop_allowlist: [loop.example]
`

func TestSmtpEdgeConfigLoadsTheBlocksFile(t *testing.T) {
	config, err := smtpedgeservice.LoadSmtpEdgeConfig([]byte(testSmtpEdgeConfig), 3)
	if err != nil {
		t.Fatal(err)
	}
	addresses := config.Settings.SendingAddresses
	if len(addresses) != 2 || addresses[0].Fwmark != 3 || addresses[1].Fwmark != 7 {
		t.Fatalf("addresses %+v", addresses)
	}
	if len(config.Settings.RouterInterfaces) != 1 || config.Settings.RouterLanAddress.Port() != 2525 || config.Settings.LoopAllowlist[0] != "loop.example" {
		t.Fatalf("settings %+v", config.Settings)
	}
}

// A HELO name outside helo_domain is refused, as is a file with none, and the engine's refusals still hold.
func TestSmtpEdgeConfigRefusesAHeloOutsideItsDomain(t *testing.T) {
	for _, data := range []string{
		"root: root.example\nreport_host: rpt.report.example\nhelo_domain: out.report.example\nsending_addresses: [{address: 192.0.2.10, helo: o1.out.other.example}]\n",
		"root: root.example\nreport_host: rpt.report.example\nhelo_domain: out.report.example\nsending_addresses: [{address: 192.0.2.10, helo: out.report.example}]\n",
		"root: root.example\nreport_host: rpt.report.example\nsending_addresses: [{address: 192.0.2.10, helo: o1.out.report.example}]\n",
		"root: root.example\nreport_host: rpt.report.example\nhelo_domain: out.report.example\nrouter_lan: 10.0.0.25:0\n",
		"root: root.example\nreport_host: rpt.report.example\nhelo_domain: out.report.example\nsending_addresses: [{address: 2001:db8::1, helo: o1.out.report.example}]\n",
	} {
		if _, err := smtpedgeservice.LoadSmtpEdgeConfig([]byte(data), 0); !errors.Is(err, smtpedgeservice.ErrSmtpEdgeSettingsRefused) {
			t.Errorf("%q: %v", data, err)
		}
	}
}

// A throwaway key set's keyset.json for a test: whatever octets, since the edge's config checks only that
// they hash to the id the file lists. No ceremony made it and it holds no key.
func writeTestProofKeySet(t *testing.T, directory string, content string) string {
	t.Helper()
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "keyset.json"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// proof_key_sets parses into the config (OPS-M9-02; DESIGN-DETAILS 3.2.7): each id decoded, each directory
// kept as written, not_after as a time or never, in the file's order; a file with none lists none, and the
// intake, which reads the same file, takes the key too.
func TestSmtpEdgeConfigParsesItsProofKeySets(t *testing.T) {
	home := t.TempDir()
	first := writeTestProofKeySet(t, filepath.Join(home, "smtpproof-keys", "first"), `{"version": 2, "set": "first"}`)
	second := writeTestProofKeySet(t, filepath.Join(home, "elsewhere", "second"), `{"version": 2, "set": "second"}`)
	third := writeTestProofKeySet(t, filepath.Join(home, "smtpproof-keys", "third"), `{"version": 2, "set": "third"}`)
	data := testSmtpEdgeConfig + "proof_key_sets:\n" +
		"  - {id: " + first + ", directory: smtpproof-keys/first}\n" +
		"  - {id: " + second + ", directory: " + filepath.Join(home, "elsewhere", "second") + ", not_after: 2026-12-01T00:00:00Z}\n" +
		"  - id: " + third + "\n    directory: ./smtpproof-keys/third/\n    not_after: \"2027-01-01T06:30:00+01:00\"\n"
	config, err := smtpedgeservice.LoadSmtpEdgeConfig([]byte(data), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.ProofKeySets) != 3 {
		t.Fatalf("%d proof key sets", len(config.ProofKeySets))
	}
	wantNotAfter := []time.Time{{}, time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 1, 5, 30, 0, 0, time.UTC)}
	wantDirectory := []string{filepath.Join("smtpproof-keys", "first"), filepath.Join(home, "elsewhere", "second"), filepath.Join("smtpproof-keys", "third")}
	for i, id := range []string{first, second, third} {
		proofKeySet := config.ProofKeySets[i]
		if hex.EncodeToString(proofKeySet.Id) != id || len(proofKeySet.Id) != sha256.Size || proofKeySet.Directory != wantDirectory[i] || !proofKeySet.NotAfter.Equal(wantNotAfter[i]) {
			t.Errorf("proof key set %d = %x %q %v", i, proofKeySet.Id, proofKeySet.Directory, proofKeySet.NotAfter)
		}
		// each directory holds its id's keyset.json, relative ones under the config home
		directory, err := config.ProofKeySetDirectory(proofKeySet, home)
		if err != nil {
			t.Fatalf("proof key set %d: %v", i, err)
		}
		if want := filepath.Join(home, wantDirectory[i]); filepath.IsAbs(wantDirectory[i]) && directory != wantDirectory[i] || !filepath.IsAbs(wantDirectory[i]) && directory != want {
			t.Errorf("proof key set %d opens %q", i, directory)
		}
	}

	// a set at or past its not_after is dropped, the others kept in order
	live := func(now time.Time) []string {
		ids := []string{}
		for _, proofKeySet := range config.ProofKeySetsAt(now) {
			ids = append(ids, hex.EncodeToString(proofKeySet.Id))
		}
		return ids
	}
	if got := live(time.Date(2026, 11, 30, 23, 59, 59, 0, time.UTC)); !slices.Equal(got, []string{first, second, third}) {
		t.Errorf("before any not_after: %v", got)
	}
	if got := live(time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)); !slices.Equal(got, []string{first, third}) {
		t.Errorf("at the second's not_after: %v", got)
	}
	if got := live(time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)); !slices.Equal(got, []string{first}) {
		t.Errorf("past both: %v", got)
	}

	// none listed: none held, and the engine's own loader, which the intake uses, reads the same file
	config, err = smtpedgeservice.LoadSmtpEdgeConfig([]byte(testSmtpEdgeConfig), 0)
	if err != nil || len(config.ProofKeySets) != 0 || len(config.ProofKeySetsAt(time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC))) != 0 {
		t.Fatalf("a file with no proof_key_sets lists %v: %v", config.ProofKeySets, err)
	}
	if settings, err := smtpedgeservice.LoadSmtpEdgeSettings([]byte(data)); err != nil || len(settings.ProofKeySets) != 3 {
		t.Fatalf("the engine's loader refuses proof_key_sets: %v", err)
	}
}

// A proof_key_sets entry that is not an id and a directory of the config home is refused by its form, before
// any file is read, and no refusal repeats the id or the directory it was given.
func TestSmtpEdgeConfigRefusesProofKeySetsByForm(t *testing.T) {
	id := strings.Repeat("ab", 32)
	other := strings.Repeat("cd", 32)
	for name, entries := range map[string]string{
		"a short id":                        "  - {id: " + id[:62] + ", directory: keys/one}\n",
		"an id that is not hex":             "  - {id: " + strings.Repeat("zz", 32) + ", directory: keys/one}\n",
		"an uppercase id":                   "  - {id: " + strings.ToUpper(id) + ", directory: keys/one}\n",
		"no id":                             "  - {directory: keys/one}\n",
		"no directory":                      "  - {id: " + id + "}\n",
		"a directory that climbs out":       "  - {id: " + id + ", directory: ../keys/one}\n",
		"a directory that climbs out later": "  - {id: " + id + ", directory: keys/../../one}\n",
		"an id twice":                       "  - {id: " + id + ", directory: keys/one}\n  - {id: " + id + ", directory: keys/two}\n",
		"a directory twice":                 "  - {id: " + id + ", directory: keys/one}\n  - {id: " + other + ", directory: keys/./one/}\n",
		"a not_after that is no time":       "  - {id: " + id + ", directory: keys/one, not_after: soon}\n",
		"an unknown key":                    "  - {id: " + id + ", directory: keys/one, pin: true}\n",
		"more sets than a verifier holds": "  - {id: " + strings.Repeat("01", 32) + ", directory: keys/1}\n  - {id: " + strings.Repeat("02", 32) + ", directory: keys/2}\n" +
			"  - {id: " + strings.Repeat("03", 32) + ", directory: keys/3}\n  - {id: " + strings.Repeat("04", 32) + ", directory: keys/4}\n  - {id: " + strings.Repeat("05", 32) + ", directory: keys/5}\n",
	} {
		_, err := smtpedgeservice.LoadSmtpEdgeConfig([]byte(testSmtpEdgeConfig+"proof_key_sets:\n"+entries), 0)
		if !errors.Is(err, smtpedgeservice.ErrSmtpEdgeSettingsRefused) {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if strings.Contains(err.Error(), id[:62]) || strings.Contains(err.Error(), "keys/") {
			t.Errorf("%s: the refusal repeats a value: %v", name, err)
		}
	}
	// four sets are a verifier's most, and are taken
	four := ""
	for _, octet := range []string{"01", "02", "03", "04"} {
		four += "  - {id: " + strings.Repeat(octet, 32) + ", directory: keys/" + octet + "}\n"
	}
	if config, err := smtpedgeservice.LoadSmtpEdgeConfig([]byte(testSmtpEdgeConfig+"proof_key_sets:\n"+four), 0); err != nil || len(config.ProofKeySets) != 4 {
		t.Errorf("four sets: %v", err)
	}
}

// A directory whose keyset.json is not its id's is refused: another set's file, an edited one, none at all, a
// directory in its place, one past the bound, and a relative directory with no config home. The refusal names
// the entry by its place and no path.
func TestSmtpEdgeConfigRefusesADirectoryThatIsNotItsIds(t *testing.T) {
	home := t.TempDir()
	first := writeTestProofKeySet(t, filepath.Join(home, "keys", "first"), `{"version": 2, "set": "first"}`)
	second := writeTestProofKeySet(t, filepath.Join(home, "keys", "second"), `{"version": 2, "set": "second"}`)
	if err := os.MkdirAll(filepath.Join(home, "keys", "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "keys", "directory", "keyset.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	long := writeTestProofKeySet(t, filepath.Join(home, "keys", "long"), strings.Repeat("x", 256*1024+1))
	atBound := writeTestProofKeySet(t, filepath.Join(home, "keys", "bound"), strings.Repeat("x", 256*1024))
	load := func(entries string) *smtpedgeservice.SmtpEdgeConfig {
		t.Helper()
		config, err := smtpedgeservice.LoadSmtpEdgeConfig([]byte(testSmtpEdgeConfig+"proof_key_sets:\n"+entries), 0)
		if err != nil {
			t.Fatal(err)
		}
		return config
	}
	for name, directory := range map[string]string{
		"another set's keyset.json":  "keys/second",
		"no keyset.json":             "keys/empty",
		"no directory":               "keys/absent",
		"a directory as keyset.json": "keys/directory",
	} {
		config := load("  - {id: " + first + ", directory: keys/first}\n  - {id: " + first[:62] + "00, directory: " + directory + "}\n")
		if _, err := config.ProofKeySetDirectory(config.ProofKeySets[0], home); err != nil {
			t.Fatalf("%s: the first set: %v", name, err)
		}
		_, err := config.ProofKeySetDirectory(config.ProofKeySets[1], home)
		if !errors.Is(err, smtpedgeservice.ErrSmtpEdgeSettingsRefused) {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !strings.Contains(err.Error(), "proof key set 1") || strings.Contains(err.Error(), home) || strings.Contains(err.Error(), "keys/") {
			t.Errorf("%s: the refusal is %v", name, err)
		}
	}
	// the second set's own id opens its directory, and the first's does not
	config := load("  - {id: " + second + ", directory: keys/second}\n  - {id: " + first + ", directory: " + filepath.Join(home, "keys", "second") + "}\n")
	if _, err := config.ProofKeySetDirectory(config.ProofKeySets[0], home); err != nil {
		t.Error(err)
	}
	if _, err := config.ProofKeySetDirectory(config.ProofKeySets[1], home); !errors.Is(err, smtpedgeservice.ErrSmtpEdgeSettingsRefused) {
		t.Errorf("an absolute directory holding another set: %v", err)
	}
	// an edit to keyset.json after the file listed its id
	if err := os.WriteFile(filepath.Join(home, "keys", "second", "keyset.json"), []byte(`{"version": 2, "set": "second" }`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := config.ProofKeySetDirectory(config.ProofKeySets[0], home); !errors.Is(err, smtpedgeservice.ErrSmtpEdgeSettingsRefused) {
		t.Errorf("an edited keyset.json: %v", err)
	}
	// the bound: a keyset.json at it is read, one past it is not, whatever its hash
	config = load("  - {id: " + atBound + ", directory: keys/bound}\n  - {id: " + long + ", directory: keys/long}\n")
	if _, err := config.ProofKeySetDirectory(config.ProofKeySets[0], home); err != nil {
		t.Errorf("a keyset.json at the bound: %v", err)
	}
	if _, err := config.ProofKeySetDirectory(config.ProofKeySets[1], home); !errors.Is(err, smtpedgeservice.ErrSmtpEdgeSettingsRefused) || !strings.Contains(err.Error(), "past its bound") {
		t.Errorf("a keyset.json past the bound: %v", err)
	}
	// a relative directory needs a config home, and a set the file does not list is no set
	if _, err := config.ProofKeySetDirectory(config.ProofKeySets[0], ""); !errors.Is(err, smtpedgeservice.ErrSmtpEdgeSettingsRefused) {
		t.Errorf("no config home: %v", err)
	}
	stray := &smtpedgeservice.SmtpEdgeProofKeySet{Id: config.ProofKeySets[0].Id, Directory: "keys/bound"}
	if _, err := config.ProofKeySetDirectory(stray, home); !errors.Is(err, smtpedgeservice.ErrSmtpEdgeSettingsRefused) {
		t.Errorf("a set the file does not list: %v", err)
	}
}
