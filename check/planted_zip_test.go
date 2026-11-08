//go:build sidecar_check

// The module zip rule on planted paths, and the rule held to the go command itself: each planted
// path goes into a real module zip that a file:// proxy serves, and go mod download must refuse
// exactly the zips the rule refuses.

package check

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The NUL seed §22.4's release fixture found, in the place it was found.
const plantedNulSeedPath = "testdata/fuzz/FuzzParseSocketAddress/nul"

func TestHygieneFailsOnAReservedWindowsName(t *testing.T) {
	fixture := newFixture(t)
	fixture.write(plantedNulSeedPath, "go test fuzz v1\nstring(\"db\\x00x\")\n")
	fixture.write("docs/Com1.md", "a document\n")
	wantFindings(t, fixture.open().moduleZipFindings(t),
		"docs/Com1.md: a module zip may not hold this path: its element \"Com1.md\" is COM1, which Windows reserves",
		plantedNulSeedPath+": a module zip may not hold this path: its element \"nul\" is NUL, which Windows reserves")
}

func TestHygieneFailsOnACharacterAModuleZipRefuses(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("notes/what?.md", "a document\n")
	fixture.write("notes/a<b.md", "a document\n")
	wantFindings(t, fixture.open().moduleZipFindings(t),
		"notes/a<b.md: a module zip may not hold this path: its element \"a<b.md\" holds '<'",
		"notes/what?.md: a module zip may not hold this path: its element \"what?.md\" holds '?'")
}

func TestHygieneFailsOnATrailingDot(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("notes/readme.", "a document\n")
	wantFindings(t, fixture.open().moduleZipFindings(t),
		"notes/readme.: a module zip may not hold this path: its element \"readme.\" ends in a dot")
}

// smtpproof's zip is its own, and so is a module under testdata, which the go command leaves out of
// the root's: each path is read from its own module's root and named from the top.
func TestHygieneFailsOnAPathInANestedModule(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("smtpproof/testdata/aux.txt", "a vector\n")
	fixture.write("testdata/consumer/go.mod", "module consumer.example/m\n\ngo 1.27.3\n")
	fixture.write("testdata/consumer/lpt1", "a vector\n")
	wantFindings(t, fixture.open().moduleZipFindings(t),
		"smtpproof/testdata/aux.txt: a module zip may not hold this path: its element \"aux.txt\" is AUX",
		"testdata/consumer/lpt1: a module zip may not hold this path: its element \"lpt1\" is LPT1")
}

// A case-insensitive file system, such as this host's, holds one of two such paths, and git's index
// holds both, so the rule reads git where the top is a work tree's. The two are planted in the index
// alone, and each name finds the one file on disk whatever the file system's case rule.
func TestHygieneFailsOnTwoPathsThatDifferOnlyInCase(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("testdata/seed", "a seed\n")
	fixture.write("testdata/Seed", "a seed\n")
	top := filepath.Join(fixture.directory, "sidecar")
	runGit := func(arguments ...string) string {
		command := exec.Command("git", arguments...)
		command.Dir = top
		output, err := command.Output()
		if err != nil {
			t.Fatalf("git %s: %v", strings.Join(arguments, " "), err)
		}
		return strings.TrimSpace(string(output))
	}
	runGit("init", "-q")
	blob := runGit("hash-object", "-w", "testdata/seed")
	for _, name := range []string{"testdata/Seed", "testdata/seed"} {
		runGit("update-index", "--add", "--cacheinfo", "100644,"+blob+","+name)
	}
	repository := fixture.open()
	if !repository.isGitTop() {
		t.Fatal("the fixture is not read through git, so this plants nothing")
	}
	wantFindings(t, repository.moduleZipFindings(t),
		"testdata/seed: a module zip may not hold this path: \"testdata/seed\" differs from \"testdata/Seed\" only in case")
}

// Two directories that differ only in case collide too, however many files each holds.
func TestModuleZipFindingsReportADirectoryCollisionOnce(t *testing.T) {
	display := func(relativePath string) string {
		return relativePath
	}
	findings := moduleZipPathFindings([]string{"Vectors/a", "vectors/b", "vectors/c", "other/a"}, display)
	wantFindings(t, findings, "vectors/b: a module zip may not hold this path: \"vectors\" differs from \"Vectors\" only in case")
}

// What the go command takes stays clean: a space, a letter outside ASCII, a short-name tilde, a dot
// in front, and a reserved name with more after it.
func TestHygieneAllowsThePathsAModuleZipTakes(t *testing.T) {
	fixture := newFixture(t)
	for _, name := range []string{
		"testdata/fuzz/FuzzParseSocketAddress/nul_byte", "notes/a b.md", "notes/über.md", "notes/x~1.md",
		".github/workflows/check.yml", "docs/console.md", "docs/com10.md", "docs/auxiliary.md",
	} {
		fixture.write(name, "a document\n")
	}
	failFindings(t, "hygiene", fixture.open().moduleZipFindings(t))
}

// One module zip a file:// proxy serves: zip.example/check at version, holding a go.mod and names.
func writePlantedModuleZip(t *testing.T, proxyDirectory string, version string, names []string) {
	t.Helper()
	const modulePath = "zip.example/check"
	goMod := "module " + modulePath + "\n\ngo 1.27.3\n"
	versions := filepath.Join(proxyDirectory, filepath.FromSlash(modulePath), "@v")
	if err := os.MkdirAll(versions, 0o700); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for _, name := range append([]string{"go.mod"}, names...) {
		entry, err := writer.Create(modulePath + "@" + version + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		content := "planted\n"
		if name == "go.mod" {
			content = goMod
		}
		if _, err := entry.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	info := fmt.Sprintf(`{"Version":%q,"Time":"2026-01-01T00:00:00Z"}`+"\n", version)
	for name, content := range map[string][]byte{version + ".mod": []byte(goMod), version + ".zip": archive.Bytes(), version + ".info": []byte(info)} {
		if err := os.WriteFile(filepath.Join(versions, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// Each planted zip through go mod download from an offline file:// proxy into an empty module cache.
// The go command checks every path of a zip before it extracts any, so a refusal here is the one a
// consumer of the tag would meet.
func TestModuleZipRuleAgreesWithTheGoCommand(t *testing.T) {
	cases := [][]string{
		{plantedNulSeedPath},
		{"testdata/fuzz/FuzzParseSocketAddress/nul_byte"},
		{"aux.go"},
		{"docs/Com1.txt"},
		{"lpt9"},
		{"con.d/x"},
		{"docs/console.go"},
		{"docs/com10.md"},
		{"notes/readme."},
		{"notes/..."},
		{"notes/what?.md"},
		{"notes/a:b.md"},
		{"notes/tab\there.md"},
		{"notes/a b.md"},
		{"notes/über.md"},
		{"notes/x\u00b4.md"},
		{"notes/x~1.md"},
		{".github/workflows/check.yml"},
		{"testdata/Seed", "testdata/seed"},
		{"Vectors/a", "vectors/b"},
		{"GO.MOD"},
	}
	proxyDirectory := t.TempDir()
	environment := goEnvironment(
		"GOPROXY=file://"+filepath.ToSlash(proxyDirectory), "GOSUMDB=off", "GONOSUMDB=", "GOPRIVATE=", "GONOPROXY=",
		"GOMODCACHE="+t.TempDir(), "GOFLAGS=-modcacherw",
	)
	outside := t.TempDir()
	refusals := 0
	for index, names := range cases {
		version := fmt.Sprintf("v0.0.%d", index+1)
		writePlantedModuleZip(t, proxyDirectory, version, names)
		display := func(relativePath string) string {
			return relativePath
		}
		ruleRefuses := len(moduleZipPathFindings(names, display)) != 0
		command := exec.Command("go", "mod", "download", "-json", "zip.example/check@"+version)
		command.Dir = outside
		command.Env = environment
		output, err := command.CombinedOutput()
		goRefuses := err != nil
		if goRefuses != ruleRefuses {
			t.Errorf("%q: the go command refuses it %v, the rule %v:\n%s", names, goRefuses, ruleRefuses, output)
			continue
		}
		if goRefuses {
			refusals += 1
			// a refusal must be the zip's own, or a broken proxy would agree with every refused case
			if !slices.ContainsFunc([]string{"malformed file path", "case-insensitive file name collision", "go.mod file not in module root directory", "go.mod files must"}, func(reason string) bool {
				return bytes.Contains(output, []byte(reason))
			}) {
				t.Errorf("%q: the go command refused it for another reason:\n%s", names, output)
			}
		}
	}
	if refusals == 0 || refusals == len(cases) {
		t.Errorf("%d of %d cases refused, so the cases do not test both ways", refusals, len(cases))
	}
}
