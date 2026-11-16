//go:build sidecar_check

// The Apple network extensions' config head reader (QD-839; DESIGN-DETAILS 4.2.3, 4.2.5's Compile, step 3): the
// replaying reader's push record reads are on the ios_extension legs, the git export machinery is not, and the reader's
// own files compile on each extension leg once their tag is off. The reader stays tagged off the leg while question
// ios-leg-head-reader-size-over-budget is open, since with it the forwarding leg passes its size budget; until it is
// answered this holds the half that landed, so the change that remains is the tags, a rename and the list. Once the
// tags are off, the same rule reads the files as the leg compiles them.

package check

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// The reads a replaying reader takes a push's record through, which every extension leg compiles.
var iosExtensionPushRecordFiles = []string{"evs_push_record.go", "evs_reseed_record.go"}

// The git export machinery, which no extension leg compiles: export and its file-mode commits, the export notes, and
// the tree builder and object sink.
var iosExtensionGitExportFiles = []string{"evs_export.go", "evs_export_file.go", "evs_export_notes.go", "evs_git_build.go"}

// The reader's files, each by the names it has had: the forwarding role's reader is a bridge_forward file once it is
// on the leg, since the leg's closure seeds from that prefix.
var iosExtensionHeadReaderFiles = [][]string{
	{"evs_config_head.go"},
	{"bridge_forward_heads.go", "bridge_heads_forward.go"},
}

// The build line that leaves a root file off the extension legs.
const iosExtensionOffTagLine = "//go:build !ios_extension\n"

// What is wrong with the reader's place on one extension leg: a push record file the leg does not compile, a git
// export file it does, a reader file that is missing, and a compile of the root that fails with the reader's files
// read without their tag.
func (self *repository) iosExtensionHeadReaderFindings(t testing.TB, leg *buildLeg) []string {
	t.Helper()
	directory, err := self.legDirectory(leg)
	if err != nil {
		t.Fatal(err)
	}
	tags := "-tags=" + strings.Join(leg.tags, ",")
	output, err := runGo(directory, leg.environment(), "list", tags, "-json=Dir,GoFiles,CgoFiles", ".")
	if err != nil {
		t.Fatal(err)
	}
	listed := &listedPackage{}
	if err := json.Unmarshal(output, listed); err != nil {
		t.Fatal(err)
	}
	compiled := slices.Concat(listed.GoFiles, listed.CgoFiles)
	findings := []string{}
	for _, name := range iosExtensionPushRecordFiles {
		if !slices.Contains(compiled, name) {
			findings = append(findings, findingf("%s does not compile %s, which the replaying head reader reads a push's record through (QD-839)", leg.name, name))
		}
	}
	for _, name := range iosExtensionGitExportFiles {
		if slices.Contains(compiled, name) {
			findings = append(findings, findingf("%s compiles %s, the git export machinery the leg leaves out (DESIGN-DETAILS 4.2.3)", leg.name, name))
		}
	}
	// each reader file as the leg would compile it with its tag off
	replace := map[string]string{}
	scratch := t.TempDir()
	for _, names := range iosExtensionHeadReaderFiles {
		found := ""
		for _, name := range names {
			if _, err := os.Stat(filepath.Join(listed.Dir, name)); err == nil {
				found = name
				break
			}
		}
		if found == "" {
			findings = append(findings, findingf("the head reader's file %s is not in the root", strings.Join(names, " or ")))
			continue
		}
		if slices.Contains(compiled, found) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(listed.Dir, found))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(data, []byte(iosExtensionOffTagLine)) {
			findings = append(findings, findingf("%s does not compile %s, and its first line is not the plain %q this rule reads", leg.name, found, strings.TrimSpace(iosExtensionOffTagLine)))
			continue
		}
		untaggedPath := filepath.Join(scratch, found)
		if err := os.WriteFile(untaggedPath, data[len(iosExtensionOffTagLine):], 0o600); err != nil {
			t.Fatal(err)
		}
		replace[filepath.Join(listed.Dir, found)] = untaggedPath
	}
	if len(findings) != 0 {
		return findings
	}
	arguments := []string{"build", tags}
	if len(replace) != 0 {
		data, err := json.Marshal(map[string]map[string]string{"Replace": replace})
		if err != nil {
			t.Fatal(err)
		}
		overlayPath := filepath.Join(scratch, "overlay.json")
		if err := os.WriteFile(overlayPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		arguments = append(arguments, "-overlay="+overlayPath)
	}
	environment := leg.environment()
	switch {
	case !leg.compilesOn(runtime.GOOS, runtime.GOARCH):
		environment = append(environment, "CGO_ENABLED=0")
	case leg.cgoEnabled && leg.goos == "ios":
		environment, err = self.iosBuildEnvironment(leg)
		if err != nil {
			t.Fatalf("%s compiles only with Xcode: %v", leg.name, err)
		}
	}
	if _, err := runGo(directory, environment, append(arguments, ".")...); err != nil {
		findings = append(findings, findingf("%s does not compile the root with the config head reader's files on it: %v", leg.name, err))
	}
	return findings
}

// Both extension legs compile the push record reads and none of the git export, and compile the root with the head
// reader on it.
func TestIosExtensionLegsCompileTheConfigHeadReader(t *testing.T) {
	repository := openThisCheckout(t)
	legCount := 0
	for _, leg := range repository.legs {
		if !leg.hasTag(iosExtensionTag) {
			continue
		}
		legCount += 1
		failFindings(t, "legs", repository.iosExtensionHeadReaderFindings(t, leg))
	}
	if legCount == 0 {
		t.Fatal("no ios_extension leg was read, so nothing was compiled")
	}
}

// Its twin on a fixture: a reader file that names what only a file off the leg declares fails the leg's compile, and
// a push record file tagged off the leg, or a git export file on it, is found.
func TestIosExtensionHeadReaderRuleFindsWhatBreaksIt(t *testing.T) {
	plant := func(t *testing.T, change func(fixture *fixture)) []string {
		t.Helper()
		fixture := newFixture(t)
		fixture.keepLegs(macExtensionLegName)
		fixture.write("evs_push_record.go", "package sidecar\n\nfunc pushRecord() int {\n\treturn 1\n}\n")
		fixture.write("evs_reseed_record.go", "package sidecar\n\nfunc reseedRecord() int {\n\treturn 2\n}\n")
		fixture.write("evs_config_head.go", "//go:build !ios_extension\n\npackage sidecar\n\nfunc configHead() int {\n\treturn pushRecord() + reseedRecord()\n}\n")
		fixture.write("bridge_heads_forward.go", "//go:build !ios_extension\n\npackage sidecar\n\nfunc ForwardingHeads() int {\n\treturn configHead()\n}\n")
		fixture.write("evs_export.go", "//go:build !ios_extension\n\npackage sidecar\n\nfunc exportOnly() int {\n\treturn 3\n}\n")
		if change != nil {
			change(fixture)
		}
		repository := fixture.open()
		return repository.iosExtensionHeadReaderFindings(t, repository.leg(t, macExtensionLegName))
	}
	wantFindings(t, plant(t, nil))
	wantFindings(t, plant(t, func(fixture *fixture) {
		fixture.write("evs_config_head.go", "//go:build !ios_extension\n\npackage sidecar\n\nfunc configHead() int {\n\treturn pushRecord() + exportOnly()\n}\n")
	}), "does not compile the root with the config head reader's files on it")
	wantFindings(t, plant(t, func(fixture *fixture) {
		fixture.write("evs_push_record.go", "//go:build !ios_extension\n\npackage sidecar\n\nfunc pushRecord() int {\n\treturn 1\n}\n")
	}), "does not compile evs_push_record.go")
	wantFindings(t, plant(t, func(fixture *fixture) {
		fixture.write("evs_export.go", "package sidecar\n\nfunc exportOnly() int {\n\treturn 3\n}\n")
	}), "compiles evs_export.go, the git export machinery")
	// the reader on the leg, renamed into the Forwarder's prefix: read as the leg compiles it
	wantFindings(t, plant(t, func(fixture *fixture) {
		fixture.write("evs_config_head.go", "package sidecar\n\nfunc configHead() int {\n\treturn pushRecord() + reseedRecord()\n}\n")
		fixture.remove("bridge_heads_forward.go")
		fixture.write("bridge_forward_heads.go", "package sidecar\n\nfunc ForwardingHeads() int {\n\treturn configHead()\n}\n")
	}))
}
