//go:build !ios_extension

// The index vectors' runner (§22.9's Index determinism row, §4.7; D-TEST-15, FI-22; SEARCH-M10-41): every file under
// testdata/index/ is reproduced byte for byte, plaintext and hashes, by the tests this file names, and those tests run
// again under GOMAXPROCS 1 and 16, twice each, and under other time zones and locales, so nothing a build's runtime
// chooses reaches an index object's bytes. sidecartest/legs/legs_search_test.go runs the same tests on each leg this
// host has. The header a writer records is held to the linked build and to normalizer 1, so a toolchain or x/text bump
// fails here until a new normalizer is assigned (§11.14's tables row).

package sidecar

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// One vector file and the tests that reproduce it.
type testIndexVectorFile struct {
	path  string
	tests []string
	// The tests do not compile on the sidecar_http leg: remote search's sizes, which the Worker never sends.
	remote bool
	// Tests a second path reproduces the file by, too slow for every runtime's child: they run once each leg.
	slowTests []string
}

// testdata/index/README.md's table, which TestIndexVectorFilesAreAllReproduced holds to the directory both ways.
var testIndexVectorFiles = []testIndexVectorFile{
	{path: "testdata/index/conformance/charsets.json", tests: []string{"TestIndexCharsetLabels"}},
	{path: "testdata/index/conformance/entities.json", tests: []string{"TestIndexReferenceTableIsCurrent", "TestIndexReferenceTableIsEntitiesJson"}},
	{path: "testdata/index/conformance/file.json", tests: []string{"TestIndexConformanceFile"}, slowTests: []string{"TestIndexStreamConformanceFile"}},
	{path: "testdata/index/conformance/mail.json", tests: []string{"TestIndexConformanceMail"}, slowTests: []string{"TestIndexStreamConformanceMail"}},
	{path: "testdata/index/conformance/sizes.json", tests: []string{"TestSearchSizeVectors"}, remote: true},
	{path: "testdata/index/conformance/skip.json", tests: []string{"TestIndexSkipVectors"}},
	{path: "testdata/index/entry/vectors.json", tests: []string{"TestEntryVectors"}},
	{path: "testdata/index/extract/doc_keys.json", tests: []string{"TestDocKeyVectors"}},
	{path: "testdata/index/extract/vectors.json", tests: []string{"TestExtractVectors"}},
	{path: "testdata/index/head/vectors.json", tests: []string{"TestIndexHeadVectors"}},
	{path: "testdata/index/merge/vectors.json", tests: []string{"TestIndexMergeVectors"}},
	{path: "testdata/index/normalize/vectors.json", tests: []string{"TestNormalizationVectors", "TestLinkedTablesAreNormalizerOne"}},
	{path: "testdata/index/rollup/vectors.json", tests: []string{"TestIndexRollupVectors"}},
	{path: "testdata/index/shard/vectors.json", tests: []string{"TestShardVectors"}},
	{path: "testdata/index/slot/vectors.json", tests: []string{"TestSlotVectors"}},
}

// The directory's own description, which is no vector.
const testIndexVectorReadme = "testdata/index/README.md"

// Run in a child of the runner, which then runs only the vector tests: it starts no child of its own.
const testIndexVectorChildEnvironment = "SIDECAR_INDEX_VECTOR_CHILD"

// The runtimes a child runs the vector tests under, each twice: the scheduler's two extremes, and time zones and
// locales whose rules differ (a half-hour and a 45-minute offset; Turkish case rules, Japanese text, and none).
var testIndexVectorRuntimes = []struct {
	name        string
	environment []string
}{
	{name: "GOMAXPROCS=1", environment: []string{"GOMAXPROCS=1"}},
	{name: "GOMAXPROCS=16", environment: []string{"GOMAXPROCS=16"}},
	{name: "Chatham, Turkish", environment: []string{"TZ=Pacific/Chatham", "LANG=tr_TR.UTF-8", "LC_ALL=tr_TR.UTF-8"}},
	{name: "Kathmandu, Japanese", environment: []string{"TZ=Asia/Kathmandu", "LANG=ja_JP.UTF-8", "LC_ALL=ja_JP.UTF-8"}},
	{name: "St Johns, C", environment: []string{"TZ=America/St_Johns", "LANG=C", "LC_ALL=C"}},
}

// Every test the table names, in the table's order, once: remote ones only where withRemote, and the slow ones only
// where withSlow.
func testIndexVectorTestNames(withRemote bool, withSlow bool) []string {
	names := []string{}
	for _, file := range testIndexVectorFiles {
		if file.remote && !withRemote {
			continue
		}
		tests := file.tests
		if withSlow {
			tests = slices.Concat(tests, file.slowTests)
		}
		for _, name := range tests {
			if !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	return names
}

// The top-level tests this package's test files declare, from their source: a name in the table must be one.
func testDeclaredTestNames(t *testing.T) map[string]bool {
	t.Helper()
	paths, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	fileSet := token.NewFileSet()
	for _, path := range paths {
		file, err := parser.ParseFile(fileSet, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			function, ok := decl.(*ast.FuncDecl)
			if ok && function.Recv == nil && strings.HasPrefix(function.Name.Name, "Test") {
				declared[function.Name.Name] = true
			}
		}
	}
	return declared
}

// Every file under testdata/index/ but the README is a row of the table, every row's file exists, the README names each
// row's file and tests, and every test a row names is declared here: a vector nothing reproduces cannot sit there.
func TestIndexVectorFilesAreAllReproduced(t *testing.T) {
	present := []string{}
	err := fs.WalkDir(testIndexFiles, "testdata/index", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && path != testIndexVectorReadme {
			present = append(present, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	listed := []string{}
	for _, file := range testIndexVectorFiles {
		listed = append(listed, file.path)
	}
	for _, path := range present {
		if !slices.Contains(listed, path) {
			t.Errorf("%s is a vector no test in testIndexVectorFiles reproduces", path)
		}
	}
	for _, path := range listed {
		if !slices.Contains(present, path) {
			t.Errorf("%s is in testIndexVectorFiles and not under testdata/index", path)
		}
	}
	readme, err := testIndexFiles.ReadFile(testIndexVectorReadme)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range testIndexVectorFiles {
		row := ""
		for _, line := range strings.Split(string(readme), "\n") {
			if strings.HasPrefix(line, "| `"+strings.TrimPrefix(file.path, "testdata/index/")+"` |") {
				row = line
			}
		}
		if row == "" {
			t.Errorf("the README's table has no row for %s", file.path)
			continue
		}
		for _, name := range slices.Concat(file.tests, file.slowTests) {
			if !strings.Contains(row, "`"+name+"`") {
				t.Errorf("the README's row for %s does not name %s", file.path, name)
			}
		}
	}
	declared := testDeclaredTestNames(t)
	if len(declared) == 0 {
		// a page Worker has no file system: the source tree is read where it is, on every other leg
		t.Log("no test file is readable here, so the table's test names are checked on the legs that read the source")
		return
	}
	for _, name := range testIndexVectorTestNames(true, true) {
		if !declared[name] {
			t.Errorf("the table names %s, which no test file here declares", name)
		}
	}
}

// What one child run printed of the vector tests: how many times each passed.
func testIndexVectorPasses(output string, names []string) map[string]int {
	passes := map[string]int{}
	for _, line := range strings.Split(output, "\n") {
		for _, name := range names {
			if strings.HasPrefix(strings.TrimSpace(line), "--- PASS: "+name+" ") {
				passes[name] += 1
			}
		}
	}
	return passes
}

// The vector tests in a child of this binary under each of testIndexVectorRuntimes, twice each, the children at once:
// every one passes both times under every runtime. The slow second paths run once a leg, by the legs' runner. A leg that
// cannot start a process (js/wasm) reads not run here; its runner runs the tests themselves there.
func TestIndexVectorsUnderEveryRuntime(t *testing.T) {
	if os.Getenv(testIndexVectorChildEnvironment) != "" {
		t.Skip("a child of the runner runs the vector tests alone")
	}
	if os.Getenv(testWriteVectorsEnvironment) != "" {
		t.Skip("rewriting the vectors, not reproducing them")
	}
	if runtime.GOOS == "js" || runtime.GOOS == "wasip1" {
		t.Skip("not run: this leg starts no process; the every-leg runner runs the vector tests here directly")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Skipf("not run: this binary cannot find itself: %v", err)
	}
	names := testIndexVectorTestNames(true, false)
	pattern := "^(" + strings.Join(names, "|") + ")$"
	base := []string{}
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		switch name {
		case "GOMAXPROCS", "TZ", "LANG", "LC_ALL", testIndexVectorChildEnvironment:
			continue
		}
		base = append(base, entry)
	}
	outputs := make([][]byte, len(testIndexVectorRuntimes))
	errs := make([]error, len(testIndexVectorRuntimes))
	waitGroup := sync.WaitGroup{}
	for index, runtimeCase := range testIndexVectorRuntimes {
		waitGroup.Go(func() {
			command := exec.Command(binary, "-test.run", pattern, "-test.count=2", "-test.v", "-test.timeout=10m")
			command.Env = append(append(slices.Clone(base), runtimeCase.environment...), testIndexVectorChildEnvironment+"=1")
			outputs[index], errs[index] = command.CombinedOutput()
		})
	}
	waitGroup.Wait()
	for index, runtimeCase := range testIndexVectorRuntimes {
		if errs[index] != nil {
			t.Errorf("under %s the vector tests failed: %v\n%s", runtimeCase.name, errs[index], outputs[index])
			continue
		}
		passes := testIndexVectorPasses(string(outputs[index]), names)
		for _, name := range names {
			if passes[name] != 2 {
				t.Errorf("under %s %s passed %d times of 2", runtimeCase.name, name, passes[name])
			}
		}
	}
}

// A vector file of whole index files: each named file's bytes, in hex.
type testIndexFileVector struct {
	Name string `json:"name"`
	Hex  string `json:"hex"`
}

// The header a writer of this build records, against normalizer 1's versions, and each header the slot and shard vectors
// carry against it: field 5 norm.Version and field 14 x/text's module version. A finding each difference.
func testIndexHeaderFindings(tables indexTables, vectorHeaders map[string]*protocol.IndexFileHeader) []string {
	findings := []string{}
	written := indexNewFileHeader(indexFileAllShard, tables)
	if written.UnicodeVersion != indexNormalizerUnicodeVersion {
		findings = append(findings, fmt.Sprintf("a writer records unicode_version %q, and normalizer 1's is %s", written.UnicodeVersion, indexNormalizerUnicodeVersion))
	}
	if written.TextModuleVersion != indexNormalizerTextModuleVersion {
		findings = append(findings, fmt.Sprintf("a writer records text_module_version %q, and normalizer 1's is %s", written.TextModuleVersion, indexNormalizerTextModuleVersion))
	}
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for name := range vectorHeaders {
			if !yield(name) {
				return
			}
		}
	}) {
		header := vectorHeaders[name]
		if header.UnicodeVersion != written.UnicodeVersion || header.TextModuleVersion != written.TextModuleVersion {
			findings = append(findings, fmt.Sprintf("%s was written under %s and %s, and this build writes %s and %s",
				name, header.UnicodeVersion, header.TextModuleVersion, written.UnicodeVersion, written.TextModuleVersion))
		}
	}
	return findings
}

// The headers of every whole file the slot and shard vectors hold, by vector file and name; a table's part is no file.
func testIndexVectorHeaders(t *testing.T) map[string]*protocol.IndexFileHeader {
	t.Helper()
	headers := map[string]*protocol.IndexFileHeader{}
	for _, path := range []string{testSlotVectorPath, testShardVectorPath} {
		encoded, err := testIndexFiles.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		vectors := []testIndexFileVector{}
		if err := json.Unmarshal(encoded, &vectors); err != nil {
			t.Fatal(err)
		}
		for _, vector := range vectors {
			file, err := hex.DecodeString(vector.Hex)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(string(file), indexFileMagic) {
				continue
			}
			decoder := &indexDecoder{src: file}
			header := decoder.fileHeader()
			if decoder.err != nil {
				t.Fatalf("%s's %s: %v", path, vector.Name, decoder.err)
			}
			headers[path+"'s "+vector.Name] = header
		}
	}
	if len(headers) == 0 {
		t.Fatal("no header read: the check would pass on nothing")
	}
	return headers
}

// This build links normalizer 1's tables, and a writer records them as the vectors carry them; a build linking another
// x/text, planted here, fails on every header, so a bump cannot pass unseen.
func TestIndexHeadersRecordTheLinkedBuild(t *testing.T) {
	headers := testIndexVectorHeaders(t)
	tables := indexLinkedTables()
	if !tables.isNormalizerOne() {
		t.Errorf("this build links %+v, not normalizer 1's tables", tables)
	}
	if findings := testIndexHeaderFindings(tables, headers); len(findings) != 0 {
		t.Errorf("the linked build and the vectors differ: %v", findings)
	}
	bumped := tables
	bumped.textModuleVersion = "v0.45.0"
	if findings := testIndexHeaderFindings(bumped, headers); len(findings) != 1+len(headers) {
		t.Errorf("a build linking x/text v0.45.0 gave %d findings, want %d: %v", len(findings), 1+len(headers), findings)
	}
	otherUnicode := tables
	otherUnicode.normVersion = "18.0.0"
	if findings := testIndexHeaderFindings(otherUnicode, headers); len(findings) != 1+len(headers) {
		t.Errorf("a build on Unicode 18.0.0's norm tables gave %d findings, want %d: %v", len(findings), 1+len(headers), findings)
	}
}
