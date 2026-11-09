package vector

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

// A Reporter that keeps what Check reports, so a test can hold a failure Check must find.
type recorder struct {
	errors []string
}

func (self *recorder) Helper() {}

func (self *recorder) Errorf(format string, arguments ...any) {
	self.errors = append(self.errors, fmt.Sprintf(format, arguments...))
}

func (self *recorder) contains(text string) bool {
	for _, line := range self.errors {
		if strings.Contains(line, text) {
			return true
		}
	}
	return false
}

func fixed(name string, output string) Producer {
	return func() ([]Case, error) {
		return []Case{{Name: name, Output: []byte(output)}}, nil
	}
}

// Stable bytes pass, held by bytes and by hash, under every default variant.
func TestCheckPassesAStableProducer(t *testing.T) {
	expected, err := Load([]byte(`{"vectors": [
		{"name": "plain", "output_hex": "68656c6c6f"},
		{"name": "hashed", "output_sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	reporter := &recorder{}
	Check(reporter, DefaultSettings(), expected, func() ([]Case, error) {
		return []Case{{Name: "plain", Output: []byte("hello")}, {Name: "hashed", Output: []byte("hello")}}, nil
	})
	if 0 < len(reporter.errors) {
		t.Errorf("a stable producer failed: %v", reporter.errors)
	}
}

// A mismatch names its case and the leg it happened on.
func TestPlantedMismatchFailsNamingTheLeg(t *testing.T) {
	t.Setenv("SIDECAR_LEG", "tests js/wasm")
	reporter := &recorder{}
	Check(reporter, DefaultSettings(), []Expected{{Name: "planted", Output: []byte("expected")}}, fixed("planted", "produced"))
	if !reporter.contains("on leg tests js/wasm") || !reporter.contains("case planted's bytes differ") {
		t.Errorf("the mismatch is not named with its leg: %v", reporter.errors)
	}
}

// A producer whose bytes follow map order fails under repeated runs: Go randomizes each iteration's
// start, and over 64 keys and 20 runs the chance of every run agreeing is negligible.
func TestMapOrderDependenceFailsUnderRepeatedRuns(t *testing.T) {
	keys := map[int]bool{}
	for key := range 64 {
		keys[key] = true
	}
	produce := func() ([]Case, error) {
		builder := strings.Builder{}
		for key := range keys {
			fmt.Fprintf(&builder, "%d,", key)
		}
		return []Case{{Name: "ordered", Output: []byte(builder.String())}}, nil
	}
	first, _ := produce()
	reporter := &recorder{}
	settings := &Settings{Maxprocs: []int{1}, Repeats: 20, Zones: []string{"UTC"}, Locales: []string{"C"}}
	Check(reporter, settings, []Expected{{Name: "ordered", Output: first[0].Output}}, produce)
	if !reporter.contains("differs under") {
		t.Errorf("a map order in the bytes passed %d runs", settings.Repeats)
	}
}

// Bytes that follow the time zone or GOMAXPROCS fail across the variants.
func TestCheckSeesTheZoneAndGomaxprocs(t *testing.T) {
	zoned := func() ([]Case, error) {
		return []Case{{Name: "zoned", Output: []byte(time.Unix(0, 0).In(time.Local).Format(time.RFC3339))}}, nil
	}
	reporter := &recorder{}
	Check(reporter, DefaultSettings(), []Expected{{Name: "zoned", Output: []byte("1970-01-01T00:00:00Z")}}, zoned)
	if !reporter.contains("TZ Asia/Kathmandu") {
		t.Errorf("a zone in the bytes passed: %v", reporter.errors)
	}
	if runtime.GOARCH == "wasm" {
		// wasm runs one thread whatever GOMAXPROCS says, so the bytes cannot follow it there
		t.Log("GOMAXPROCS is fixed on wasm: its variants are not shown on this leg")
		return
	}
	procs := func() ([]Case, error) {
		return []Case{{Name: "procs", Output: []byte(fmt.Sprint(runtime.GOMAXPROCS(0)))}}, nil
	}
	reporter = &recorder{}
	Check(reporter, DefaultSettings(), []Expected{{Name: "procs", Output: []byte("1")}}, procs)
	if !reporter.contains("GOMAXPROCS 16") {
		t.Errorf("GOMAXPROCS in the bytes passed: %v", reporter.errors)
	}
	if runtime.GOMAXPROCS(0) == 16 && time.Local.String() == "Asia/Kathmandu" {
		t.Error("Check left its variant behind")
	}
}

// A case missing from either side fails, as does a producer's error.
func TestCheckFailsOnMissingOrExtraCases(t *testing.T) {
	reporter := &recorder{}
	Check(reporter, DefaultSettings(), []Expected{{Name: "wanted", Output: []byte("x")}}, fixed("other", "x"))
	if !reporter.contains("case wanted is in the vector file and was not produced") || !reporter.contains("case other was produced and is not in the vector file") {
		t.Errorf("%v", reporter.errors)
	}
	reporter = &recorder{}
	Check(reporter, DefaultSettings(), nil, func() ([]Case, error) { return nil, fmt.Errorf("planted") })
	if !reporter.contains("the producer failed: planted") {
		t.Errorf("%v", reporter.errors)
	}
}

// The common file form is read strictly.
func TestLoadRefusesMalformedFiles(t *testing.T) {
	for _, data := range []string{
		`{"vectors": []}`,
		`{"vectors": [{"name": "a"}]}`,
		`{"vectors": [{"name": "a", "output_hex": "zz"}]}`,
		`{"vectors": [{"name": "a", "output_hex": "00"}, {"name": "a", "output_hex": "00"}]}`,
		`{"vectors": [{"name": "a", "output_hexx": "00"}]}`,
	} {
		if _, err := Load([]byte(data)); err == nil {
			t.Errorf("%s loaded", data)
		}
	}
}
