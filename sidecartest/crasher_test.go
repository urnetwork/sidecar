//go:build !js

// CrasherSeed's round trip, its refusals, and the proof that what it writes runs: go test, with no -fuzz, runs a
// moved crasher as a seed and fails on it. Off js, whose tests run in Node with no corpus directory to read.

package sidecartest

import (
	"bytes"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// Writes data as a crasher a fuzzing run left somewhere outside the package, and returns its path.
func writeFoundCrasher(t *testing.T, data []byte) string {
	t.Helper()
	crasherPath := filepath.Join(t.TempDir(), "found-crasher")
	if err := os.WriteFile(crasherPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return crasherPath
}

// Every value a fuzz function takes, in go test's encoding and back, then moved in and read out again.
func TestCrasherSeedRoundTrips(t *testing.T) {
	oddNan := math.Float64frombits(0x7ff8000000000001)
	values := []any{
		[]byte{0x00, 0xff, 'x', '"'}, "a\"b\x00é", true, false,
		int(-3), int8(-128), int16(300), int64(-1 << 40),
		uint(7), uint16(65535), uint32(1 << 31), uint64(1 << 63),
		byte(0xff), byte('z'), rune('é'), rune(-1),
		float32(1.5), float64(-0.25), math.Inf(1), oddNan,
	}
	encoded, err := EncodeCrasher(values...)
	if err != nil {
		t.Fatal(err)
	}
	crasherPath := writeFoundCrasher(t, encoded)
	packageDirectory := t.TempDir()
	entryPath, err := CrasherSeed(packageDirectory, "FuzzPlanted", crasherPath, "TestPlantedCrashRegression")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(packageDirectory, "testdata", "fuzz", "FuzzPlanted", crasherEntryName(encoded)); entryPath != want {
		t.Fatalf("entry at %s, want %s", entryPath, want)
	}
	if moved, err := os.ReadFile(entryPath); err != nil || !bytes.Equal(moved, encoded) {
		t.Fatalf("the entry holds %q (%v), want the crasher's bytes", moved, err)
	}
	if _, err := os.Stat(crasherPath); !os.IsNotExist(err) {
		t.Fatalf("the crasher is still where it was found: %v", err)
	}
	crashers, err := Crashers(packageDirectory, "FuzzPlanted")
	if err != nil {
		t.Fatal(err)
	}
	if len(crashers) != 1 || crashers[0].Entry != crasherEntryName(encoded) || crashers[0].RegressionTest != "TestPlantedCrashRegression" || crashers[0].Path != entryPath {
		t.Fatalf("crashers %+v", crashers)
	}
	decoded, err := crashers[0].Values()
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != len(values) {
		t.Fatalf("%d values, want %d", len(decoded), len(values))
	}
	for index, value := range values {
		if reflect.TypeOf(decoded[index]) != reflect.TypeOf(value) {
			t.Errorf("value %d is a %T, want %T", index, decoded[index], value)
			continue
		}
		if number, ok := value.(float64); ok && math.IsNaN(number) {
			if math.Float64bits(decoded[index].(float64)) != math.Float64bits(number) {
				t.Errorf("value %d's NaN has bits %x", index, math.Float64bits(decoded[index].(float64)))
			}
			continue
		}
		if !reflect.DeepEqual(decoded[index], value) {
			t.Errorf("value %d is %#v, want %#v", index, decoded[index], value)
		}
	}
	list, err := os.ReadFile(filepath.Join(packageDirectory, "testdata", "fuzz", "FuzzPlanted.crashers"))
	if err != nil || string(list) != crasherEntryName(encoded)+" TestPlantedCrashRegression\n" {
		t.Fatalf("the list holds %q (%v)", list, err)
	}
}

// A crasher already in its corpus, as go test -fuzz leaves one, stays there and is listed; moving the same bytes
// in again lists them once.
func TestCrasherSeedListsACrasherInPlaceOnce(t *testing.T) {
	encoded, err := EncodeCrasher([]byte("in place"))
	if err != nil {
		t.Fatal(err)
	}
	packageDirectory := t.TempDir()
	corpusDirectory := filepath.Join(packageDirectory, "testdata", "fuzz", "FuzzPlanted")
	if err := os.MkdirAll(corpusDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	inPlace := filepath.Join(corpusDirectory, crasherEntryName(encoded))
	if err := os.WriteFile(inPlace, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	if entryPath, err := CrasherSeed(packageDirectory, "FuzzPlanted", inPlace, "TestPlantedInPlaceRegression"); err != nil || entryPath != inPlace {
		t.Fatalf("seeding in place: %s, %v", entryPath, err)
	}
	if _, err := os.Stat(inPlace); err != nil {
		t.Fatalf("the crasher in place was removed: %v", err)
	}
	if _, err := CrasherSeed(packageDirectory, "FuzzPlanted", writeFoundCrasher(t, encoded), "TestPlantedInPlaceRegression"); err != nil {
		t.Fatal(err)
	}
	crashers, err := Crashers(packageDirectory, "FuzzPlanted")
	if err != nil || len(crashers) != 1 {
		t.Fatalf("crashers %v, %v", crashers, err)
	}
}

// What is no crasher, no target or no test is refused, as are an entry whose name holds other bytes and an entry
// listed under another test; a refusal moves nothing.
func TestCrasherSeedRefusesWhatItCannotList(t *testing.T) {
	encoded, err := EncodeCrasher([]byte("crash"))
	if err != nil {
		t.Fatal(err)
	}
	packageDirectory := t.TempDir()
	for _, refused := range []struct {
		target   string
		data     []byte
		test     string
		contains string
	}{
		{target: "FuzzPlanted", data: []byte("raw bytes, no header"), test: "TestPlantedRegression", contains: "no corpus file"},
		{target: "FuzzPlanted", data: []byte("go test fuzz v1\n"), test: "TestPlantedRegression", contains: "no value"},
		{target: "FuzzPlanted", data: []byte("go test fuzz v1\ncomplex128(1)\n"), test: "TestPlantedRegression", contains: "no type"},
		{target: "Fuzzplanted", data: encoded, test: "TestPlantedRegression", contains: "no fuzz target"},
		{target: "FuzzPlanted", data: encoded, test: "planted", contains: "no test"},
	} {
		crasherPath := writeFoundCrasher(t, refused.data)
		if _, err := CrasherSeed(packageDirectory, refused.target, crasherPath, refused.test); err == nil || !strings.Contains(err.Error(), refused.contains) {
			t.Errorf("%s %q %s: %v, want %q", refused.target, refused.data, refused.test, err, refused.contains)
		}
		if _, err := os.Stat(crasherPath); err != nil {
			t.Errorf("a refused crasher was moved: %v", err)
		}
	}

	if _, err := CrasherSeed(packageDirectory, "FuzzPlanted", writeFoundCrasher(t, encoded), "TestPlantedRegression"); err != nil {
		t.Fatal(err)
	}
	if _, err := CrasherSeed(packageDirectory, "FuzzPlanted", writeFoundCrasher(t, encoded), "TestPlantedOtherRegression"); err == nil || !strings.Contains(err.Error(), "listed already") {
		t.Errorf("an entry listed under another test: %v", err)
	}
	other, err := EncodeCrasher([]byte("other"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packageDirectory, "testdata", "fuzz", "FuzzPlanted", crasherEntryName(other)), []byte("go test fuzz v1\n[]byte(\"tampered\")\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := CrasherSeed(packageDirectory, "FuzzPlanted", writeFoundCrasher(t, other), "TestPlantedRegression"); err == nil || !strings.Contains(err.Error(), "other bytes") {
		t.Errorf("an entry holding other bytes: %v", err)
	}
}

// Every corpus go test reads in this repository decodes here, so a regression test can run any seed on its own.
func TestDecodeCrasherReadsThisRepositorysCorpora(t *testing.T) {
	directories, err := filepath.Glob(filepath.Join("..", "testdata", "fuzz", "Fuzz*"))
	if err != nil {
		t.Fatal(err)
	}
	read := 0
	for _, directory := range directories {
		if info, err := os.Stat(directory); err != nil || !info.IsDir() {
			continue
		}
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if !entry.Type().IsRegular() {
				continue
			}
			data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeCrasher(data); err != nil {
				t.Errorf("%s/%s: %v", filepath.Base(directory), entry.Name(), err)
			}
			read += 1
		}
	}
	if read < 100 {
		t.Fatalf("read %d corpus files, and this repository holds hundreds", read)
	}
}

// What CrasherSeed writes is what go test runs: a target with no seeds passes, and once a crasher is moved in, go
// test, with no -fuzz, runs it as a seed named for its entry and fails on it.
func TestCrasherSeedRunsAsAnOrdinaryTest(t *testing.T) {
	goCommand, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("not run: this leg cannot run the go command: %v", err)
	}
	moduleDirectory := t.TempDir()
	files := map[string]string{
		"go.mod": "module crasher.example/planted\n\ngo 1.27\n",
		"planted_test.go": "package planted\n\nimport \"testing\"\n\n" +
			"func FuzzPlanted(f *testing.F) {\n\tf.Fuzz(func(t *testing.T, input []byte, count uint16) {\n" +
			"\t\tif string(input) == \"crash\" && count == 7 {\n\t\t\tt.Fatal(\"the moved crasher ran\")\n\t\t}\n\t})\n}\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(moduleDirectory, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	goTest := func() (string, error) {
		command := exec.Command(goCommand, "test", "-count=1", "-v", "-run", "^FuzzPlanted$", ".")
		command.Dir = moduleDirectory
		command.Env = append(slices.DeleteFunc(os.Environ(), func(variable string) bool {
			return strings.HasPrefix(variable, "GOFLAGS=") || strings.HasPrefix(variable, "GOOS=") || strings.HasPrefix(variable, "GOARCH=")
		}), "GOFLAGS=", "GOWORK=off", "GOTOOLCHAIN=local", "GOPROXY=off")
		output, err := command.CombinedOutput()
		return string(output), err
	}
	if output, err := goTest(); err != nil {
		t.Fatalf("the target with no seeds failed: %v\n%s", err, output)
	}
	encoded, err := EncodeCrasher([]byte("crash"), uint16(7))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CrasherSeed(moduleDirectory, "FuzzPlanted", writeFoundCrasher(t, encoded), "TestPlantedCrashRegression"); err != nil {
		t.Fatal(err)
	}
	output, err := goTest()
	if err == nil {
		t.Fatalf("go test passed with the crasher in the corpus:\n%s", output)
	}
	if !strings.Contains(output, "--- FAIL: FuzzPlanted/"+crasherEntryName(encoded)) || !strings.Contains(output, "the moved crasher ran") {
		t.Fatalf("the crasher did not run as a seed:\n%s", output)
	}
}
