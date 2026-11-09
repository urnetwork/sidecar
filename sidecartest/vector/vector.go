// The vector contract (TEST-M1-07; D-TEST-1, D-TEST-15): a vector file in testdata/<area>/ fixes the bytes
// the code must produce, and Check holds the code to them byte for byte and by hash, under GOMAXPROCS 1
// and 16, over repeated runs (Go randomizes map order on each), and under changed time zones and
// locales, as §22.9's index determinism row asks; legs.Run puts the same test on every leg, so "byte-equal
// on every leg" is each leg passing Check. A mismatch names the leg it happened on, from SIDECAR_LEG,
// which legs.Run sets.
//
// This package is a leaf: it imports nothing of this repository, so any package's external tests may
// use it, and a vector's bytes reach it already read, from the file system or from an embed, since the
// sidecar_http leg's Worker has none. Variants change process-wide state (GOMAXPROCS, time.Local, the
// locale's environment), so Check must not run beside a parallel test.

package vector

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"time"
)

// One case's expected bytes: its name, and its output, or the output's SHA-256 alone where the file
// holds only that.
type Expected struct {
	Name   string
	Output []byte
	Sha256 string
}

// One case as the code under test produced it.
type Case struct {
	Name   string
	Output []byte
}

// Produces every case of a vector file.
type Producer func() ([]Case, error)

// What Check varies between runs.
type Settings struct {
	// each value runs as GOMAXPROCS
	Maxprocs []int
	// runs at each GOMAXPROCS value; more than one shows a map order leaking into the bytes
	Repeats int
	// time zones the runs take as time.Local, each loaded by name, or fixed at its offset where the leg
	// has no zone database
	Zones []string
	// values for LANG and LC_ALL during the runs
	Locales []string
}

// §22.9's GOMAXPROCS 1 and 16, three runs each, zones on both sides of UTC with odd offsets, and a
// locale whose case rules differ from the default.
func DefaultSettings() *Settings {
	return &Settings{
		Maxprocs: []int{1, 16},
		Repeats:  3,
		Zones:    []string{"UTC", "Asia/Kathmandu", "America/St_Johns"},
		Locales:  []string{"C", "tr_TR.UTF-8"},
	}
}

// The leg this binary runs on: SIDECAR_LEG, which legs.Run sets, else the platform.
func Leg() string {
	if leg := os.Getenv("SIDECAR_LEG"); leg != "" {
		return leg
	}
	return runtime.GOOS + "/" + runtime.GOARCH
}

// What Check needs of a test.
type Reporter interface {
	Helper()
	Errorf(format string, arguments ...any)
}

// Fixed offsets for the default zones, where a leg has no zone database (js/wasm).
var zoneOffsets = map[string]int{"UTC": 0, "Asia/Kathmandu": 5*3600 + 45*60, "America/St_Johns": -(3*3600 + 30*60)}

func loadZone(name string) *time.Location {
	if location, err := time.LoadLocation(name); err == nil {
		return location
	}
	return time.FixedZone(name, zoneOffsets[name])
}

// Runs produce under every variant and compares each case with expected and with the first run's,
// reporting each difference with its case, variant and leg. A case missing from either side fails.
func Check(reporter Reporter, settings *Settings, expected []Expected, produce Producer) {
	reporter.Helper()
	leg := Leg()
	expectedByName := map[string]*Expected{}
	for index := range expected {
		expectedByName[expected[index].Name] = &expected[index]
	}

	savedProcs := runtime.GOMAXPROCS(0)
	savedLocal := time.Local
	savedLang, hadLang := os.LookupEnv("LANG")
	savedAll, hadAll := os.LookupEnv("LC_ALL")
	defer func() {
		runtime.GOMAXPROCS(savedProcs)
		time.Local = savedLocal
		restore := func(name string, value string, had bool) {
			if had {
				os.Setenv(name, value)
			} else {
				os.Unsetenv(name)
			}
		}
		restore("LANG", savedLang, hadLang)
		restore("LC_ALL", savedAll, hadAll)
	}()

	var first map[string][]byte
	firstVariant := ""
	for _, procs := range settings.Maxprocs {
		for _, zone := range settings.Zones {
			for _, locale := range settings.Locales {
				for repeat := range max(1, settings.Repeats) {
					runtime.GOMAXPROCS(procs)
					time.Local = loadZone(zone)
					os.Setenv("LANG", locale)
					os.Setenv("LC_ALL", locale)
					variant := fmt.Sprintf("GOMAXPROCS %d, TZ %s, locale %s, run %d", procs, zone, locale, repeat+1)
					cases, err := produce()
					if err != nil {
						reporter.Errorf("on leg %s under %s: the producer failed: %v", leg, variant, err)
						return
					}
					outputs := map[string][]byte{}
					for _, produced := range cases {
						if _, seen := outputs[produced.Name]; seen {
							reporter.Errorf("on leg %s under %s: case %s produced twice", leg, variant, produced.Name)
						}
						outputs[produced.Name] = produced.Output
					}
					if first == nil {
						first = outputs
						firstVariant = variant
						compareExpected(reporter, leg, variant, expected, expectedByName, outputs)
						continue
					}
					for _, name := range sortedNames(first, outputs) {
						if !bytes.Equal(first[name], outputs[name]) {
							reporter.Errorf("on leg %s, case %s differs under %s from %s: the bytes depend on the run (map order, GOMAXPROCS, the zone or the locale)",
								leg, name, variant, firstVariant)
						}
					}
				}
			}
		}
	}
}

func sortedNames(a map[string][]byte, b map[string][]byte) []string {
	names := []string{}
	for name := range a {
		names = append(names, name)
	}
	for name := range b {
		if _, found := a[name]; !found {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// One run's outputs against the file.
func compareExpected(reporter Reporter, leg string, variant string, expected []Expected, expectedByName map[string]*Expected, outputs map[string][]byte) {
	reporter.Helper()
	for _, want := range expected {
		output, produced := outputs[want.Name]
		if !produced {
			reporter.Errorf("on leg %s under %s: case %s is in the vector file and was not produced", leg, variant, want.Name)
			continue
		}
		hash := sha256.Sum256(output)
		got := hex.EncodeToString(hash[:])
		if want.Output != nil && !bytes.Equal(want.Output, output) {
			reporter.Errorf("on leg %s under %s: case %s's bytes differ from the vector file's (sha256 %s)", leg, variant, want.Name, got)
		}
		if want.Sha256 != "" && want.Sha256 != got {
			reporter.Errorf("on leg %s under %s: case %s hashes to %s, and the vector file holds %s", leg, variant, want.Name, got, want.Sha256)
		}
		if want.Output == nil && want.Sha256 == "" {
			reporter.Errorf("case %s holds neither bytes nor a hash", want.Name)
		}
	}
	for name := range outputs {
		if _, inFile := expectedByName[name]; !inFile {
			reporter.Errorf("on leg %s under %s: case %s was produced and is not in the vector file", leg, variant, name)
		}
	}
}

// A vector file in the common form, {"vectors": [{"name", "output_hex", "output_sha256"}]}: either or
// both of the bytes and the hash, and nothing else, so a typo cannot drop a check.
func Load(data []byte) ([]Expected, error) {
	file := struct {
		Vectors []struct {
			Name         string `json:"name"`
			OutputHex    string `json:"output_hex"`
			OutputSha256 string `json:"output_sha256"`
		} `json:"vectors"`
	}{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return nil, err
	}
	expected := []Expected{}
	names := map[string]bool{}
	for _, vector := range file.Vectors {
		if vector.Name == "" || names[vector.Name] {
			return nil, fmt.Errorf("a vector's name %q is empty or held twice", vector.Name)
		}
		names[vector.Name] = true
		if vector.OutputHex == "" && vector.OutputSha256 == "" {
			return nil, fmt.Errorf("vector %s holds neither bytes nor a hash", vector.Name)
		}
		var output []byte
		if vector.OutputHex != "" {
			decoded, err := hex.DecodeString(vector.OutputHex)
			if err != nil {
				return nil, fmt.Errorf("vector %s: %w", vector.Name, err)
			}
			output = decoded
		}
		expected = append(expected, Expected{Name: vector.Name, Output: output, Sha256: vector.OutputSha256})
	}
	if len(expected) == 0 {
		return nil, errors.New("the file holds no vector")
	}
	return expected, nil
}
