//go:build sidecar_check

// The Apple network extensions' config head reader (QD-839, QD-973; owner decision 491; §18.10, DESIGN-DETAILS 4.2.3,
// 4.2.5's Compile, step 3): the replaying reader is on both ios_extension legs, as on every other leg a VPN component
// builds. Each extension leg compiles the reader's two files and the push record reads it replays through, compiles
// none of the git export machinery, and compiles the root so. The forwarding role's reader is a bridge_forward file,
// since the leg's closure seeds from that prefix and make size keeps its exported surface (isForwardingEntryFile);
// what the leg adds with it is make size's to hold.

package check

import (
	"encoding/json"
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

// The reader's files, which every extension leg compiles: the replaying reader, and the forwarding role's reader over
// it, the VPN component's entry point.
var iosExtensionHeadReaderFiles = []string{"evs_config_head.go", "bridge_forward_heads.go"}

// What is wrong with the reader's place on one extension leg: a push record file or a reader file the leg does not
// compile, a git export file it does, and a compile of the root that fails.
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
	for _, name := range iosExtensionHeadReaderFiles {
		if !slices.Contains(compiled, name) {
			findings = append(findings, findingf("%s does not compile %s, the config head reader every VPN component builds (QD-839, QD-973)", leg.name, name))
		}
	}
	if len(findings) != 0 {
		return findings
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
	if _, err := runGo(directory, environment, "build", tags, "."); err != nil {
		findings = append(findings, findingf("%s does not compile the root with the config head reader's files on it: %v", leg.name, err))
	}
	return findings
}

// Every extension leg compiles the push record reads and none of the git export, and compiles the root with the head
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

// Its twin on a fixture: a reader file tagged off the leg is found, under its own name or the forwarding reader's old
// one, as is a reader file that names what only a file off the leg declares, which fails the leg's compile, a push
// record file tagged off the leg, and a git export file on it.
func TestIosExtensionHeadReaderRuleFindsWhatBreaksIt(t *testing.T) {
	plant := func(t *testing.T, change func(fixture *fixture)) []string {
		t.Helper()
		fixture := newFixture(t)
		fixture.keepLegs(macExtensionLegName)
		fixture.write("evs_push_record.go", "package sidecar\n\nfunc pushRecord() int {\n\treturn 1\n}\n")
		fixture.write("evs_reseed_record.go", "package sidecar\n\nfunc reseedRecord() int {\n\treturn 2\n}\n")
		fixture.write("evs_config_head.go", "package sidecar\n\nfunc configHead() int {\n\treturn pushRecord() + reseedRecord()\n}\n")
		fixture.write("bridge_forward_heads.go", "package sidecar\n\nfunc ForwardingHeads() int {\n\treturn configHead()\n}\n")
		fixture.write("evs_export.go", "//go:build !ios_extension\n\npackage sidecar\n\nfunc exportOnly() int {\n\treturn 3\n}\n")
		if change != nil {
			change(fixture)
		}
		repository := fixture.open()
		return repository.iosExtensionHeadReaderFindings(t, repository.leg(t, macExtensionLegName))
	}
	wantFindings(t, plant(t, nil))
	// the reader as it stood while the budget question was open: both files tagged off the leg
	wantFindings(t, plant(t, func(fixture *fixture) {
		fixture.write("evs_config_head.go", "//go:build !ios_extension\n\npackage sidecar\n\nfunc configHead() int {\n\treturn pushRecord() + reseedRecord()\n}\n")
		fixture.write("bridge_forward_heads.go", "//go:build !ios_extension\n\npackage sidecar\n\nfunc ForwardingHeads() int {\n\treturn configHead()\n}\n")
	}), "does not compile evs_config_head.go, the config head reader", "does not compile bridge_forward_heads.go, the config head reader")
	wantFindings(t, plant(t, func(fixture *fixture) {
		fixture.write("bridge_forward_heads.go", "//go:build !ios_extension\n\npackage sidecar\n\nfunc ForwardingHeads() int {\n\treturn configHead()\n}\n")
	}), "does not compile bridge_forward_heads.go, the config head reader")
	// under its old name the leg's closure would not seed from it
	wantFindings(t, plant(t, func(fixture *fixture) {
		fixture.remove("bridge_forward_heads.go")
		fixture.write("bridge_heads_forward.go", "package sidecar\n\nfunc ForwardingHeads() int {\n\treturn configHead()\n}\n")
	}), "does not compile bridge_forward_heads.go, the config head reader")
	wantFindings(t, plant(t, func(fixture *fixture) {
		fixture.write("evs_config_head.go", "package sidecar\n\nfunc configHead() int {\n\treturn pushRecord() + exportOnly()\n}\n")
	}), "does not compile the root with the config head reader's files on it")
	wantFindings(t, plant(t, func(fixture *fixture) {
		fixture.write("evs_push_record.go", "//go:build !ios_extension\n\npackage sidecar\n\nfunc pushRecord() int {\n\treturn 1\n}\n")
	}), "does not compile evs_push_record.go")
	wantFindings(t, plant(t, func(fixture *fixture) {
		fixture.write("evs_export.go", "package sidecar\n\nfunc exportOnly() int {\n\treturn 3\n}\n")
	}), "compiles evs_export.go, the git export machinery")
}

// The forwarding role's reader is a file the leg's closure seeds from and make size keeps, which under its old name it
// was not; the replaying reader under it is on the leg because the forwarding reader reaches it.
func TestIosExtensionHeadReaderIsAForwardingEntryFile(t *testing.T) {
	if !slices.ContainsFunc(iosExtensionHeadReaderFiles, isForwardingEntryFile) || !isForwardingEntryFile("bridge_forward_heads.go") {
		t.Error("no head reader file is a forwarding entry file, so the leg's closure seeds from none and make size keeps no reader's surface")
	}
	if isForwardingEntryFile("bridge_heads_forward.go") || isForwardingEntryFile("evs_config_head.go") {
		t.Error("the reader's old name or the replaying reader's file reads as a forwarding entry file")
	}
}
