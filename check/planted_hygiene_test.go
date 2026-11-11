//go:build sidecar_check

// The hygiene row's planted violations, but for the hook rule's, which have their own file. Protobuf
// tests generate with the real protoc and the real go.mod tool, as the rules they prove do.

package check

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestHygieneFailsOnAnExtraReplace(t *testing.T) {
	fixture := newFixture(t)
	fixture.edit("go.mod", "replace @glog@ => ../glog", "replace @glog@ => ../glog\n\nreplace golang.org/x/net => ../net")
	wantFindings(t, fixture.open().replaceFindings(t), ".: replace golang.org/x/net => ../net is not one of §4.7's")
}

func TestHygieneFailsOnAMovedReplace(t *testing.T) {
	fixture := newFixture(t)
	fixture.edit("go.mod", "replace gvisor.dev/gvisor => ../gvisor", "replace gvisor.dev/gvisor => ../gvisor-fork")
	wantFindings(t, fixture.open().replaceFindings(t), ".: replace gvisor.dev/gvisor => ../gvisor-fork, and §4.7's is ../gvisor")
}

func TestHygieneFailsOnAMissingReplace(t *testing.T) {
	fixture := newFixture(t)
	fixture.edit("go.mod", "replace @glog@ => ../glog\n", "")
	wantFindings(t, fixture.open().replaceFindings(t), ".: no replace for @glog@, which §4.7 has it repeat")
}

// C-23 lets sidecarctl, and no other module, replace warp with its sibling checkout.
func TestHygieneLetsSidecarctlAloneReplaceWarp(t *testing.T) {
	fixture := newFixture(t)
	fixture.edit("sidecarctl/go.mod", "replace gvisor.dev/gvisor => ../../gvisor\n", "replace gvisor.dev/gvisor => ../../gvisor\n\nreplace "+warpBasePath+" => ../../warp\n")
	wantFindings(t, fixture.open().replaceFindings(t))

	fixture.edit("sidecarctl/go.mod", "replace "+warpBasePath+" => ../../warp\n", "replace "+warpBasePath+" => ../../warp-fork\n")
	wantFindings(t, fixture.open().replaceFindings(t), "sidecarctl: replace "+warpBasePath+" => ../../warp-fork, and C-23's is ../../warp")

	fixture.edit("cli/go.mod", "replace gvisor.dev/gvisor => ../../gvisor\n", "replace gvisor.dev/gvisor => ../../gvisor\n\nreplace "+warpBasePath+" => ../../warp\n")
	wantFindings(t, fixture.open().replaceFindings(t),
		"cli: replace "+warpBasePath+" => ../../warp is not one of §4.7's",
		"sidecarctl: replace "+warpBasePath+" => ../../warp-fork, and C-23's is ../../warp")
}

// Go does not inherit a replace, so each nested module is read on its own.
func TestHygieneFailsOnANestedModuleNotRepeatingAReplace(t *testing.T) {
	fixture := newFixture(t)
	fixture.edit("smtpproof/go.mod", "replace @connect@ => ../../connect\n", "")
	wantFindings(t, fixture.open().replaceFindings(t), "smtpproof: no replace for @connect@, which §4.7 has it repeat")
}

func TestHygieneFailsOnAVersionedReplace(t *testing.T) {
	fixture := newFixture(t)
	fixture.edit("go.mod", "replace gvisor.dev/gvisor => ../gvisor", "replace gvisor.dev/gvisor => example.com/gvisor v1.0.0")
	wantFindings(t, fixture.open().replaceFindings(t),
		".: replace gvisor.dev/gvisor => example.com/gvisor, and §4.7's is ../gvisor",
		".: replace gvisor.dev/gvisor pins a version")
}

// QD-193's forks: the root's at ./third_party, a nested module's one level up, each before the first
// link as mox's is now.
func TestHygieneAllowsTheForkReplaces(t *testing.T) {
	fixture := newFixture(t)
	fixture.edit("go.mod", "replace @glog@ => ../glog\n", "replace @glog@ => ../glog\n\nreplace github.com/emersion/go-smtp => ./third_party/go-smtp\n\nreplace github.com/mjl-/mox => ./third_party/mox\n")
	fixture.edit("cli/go.mod", "replace @glog@ => ../../glog\n", "replace @glog@ => ../../glog\n\nreplace github.com/emersion/go-smtp => ../third_party/go-smtp\n\nreplace github.com/mjl-/mox => ../third_party/mox\n")
	wantFindings(t, fixture.open().replaceFindings(t))
}

func TestHygieneFailsOnAMovedForkReplace(t *testing.T) {
	fixture := newFixture(t)
	fixture.edit("go.mod", "replace @glog@ => ../glog\n", "replace @glog@ => ../glog\n\nreplace github.com/emersion/go-smtp => ./third_party/go-smtp-v0.25.0\n")
	fixture.edit("smtpproof/go.mod", "replace @glog@ => ../../glog\n", "replace @glog@ => ../../glog\n\nreplace github.com/mjl-/mox => ./third_party/mox\n")
	wantFindings(t, fixture.open().replaceFindings(t),
		".: replace github.com/emersion/go-smtp => ./third_party/go-smtp-v0.25.0, and QD-193's is ./third_party/go-smtp",
		"smtpproof: replace github.com/mjl-/mox => ./third_party/mox, and QD-193's is ../third_party/mox")
}

// A module whose graph holds go-smtp and does not replace it links upstream's, where every session
// refuses: Go reads no replace from the root on its behalf.
func TestHygieneFailsOnAModuleLinkingAForkWithoutItsReplace(t *testing.T) {
	fixture := newFixture(t)
	fixture.edit("go.mod", "replace @glog@ => ../glog\n", "replace @glog@ => ../glog\n\nreplace github.com/emersion/go-smtp => ./third_party/go-smtp\n")
	fixture.edit("mlsinterop/go.mod", "go 1.27.4\n", "go 1.27.4\n\nrequire github.com/emersion/go-smtp v0.25.1 // indirect\n")
	wantFindings(t, fixture.open().replaceFindings(t),
		"mlsinterop: requires github.com/emersion/go-smtp and does not replace it with QD-193's fork at ../third_party/go-smtp")
}

// The release step moves the root into v2026/ and rebases a nested module's replaces, so a fork's
// path may climb further or stay below the root, but it stays local and ends at the fork.
func TestHygieneAllowsTheForkReplacesOnARelease(t *testing.T) {
	module := &repositoryModule{relativeName: "smtpproof", file: &moduleFile{}}
	addReplace := func(old string, newPath string, version string) {
		replace := struct {
			Old struct {
				Path    string
				Version string
			}
			New struct {
				Path    string
				Version string
			}
		}{}
		replace.Old.Path = old
		replace.New.Path = newPath
		replace.New.Version = version
		module.file.Replace = append(module.file.Replace, replace)
	}
	addReplace("github.com/emersion/go-smtp", "../../third_party/go-smtp", "")
	addReplace("github.com/mjl-/mox", "./third_party/mox", "")
	wantFindings(t, replaceFindingsRelease(module))

	addReplace("github.com/emersion/go-smtp", "../../go-smtp", "")
	addReplace("github.com/mjl-/mox", "github.com/mjl-/mox", "v0.0.17")
	wantFindings(t, replaceFindingsRelease(module),
		"smtpproof: replace github.com/emersion/go-smtp => ../../go-smtp does not end at third_party/go-smtp",
		"smtpproof: replace github.com/mjl-/mox => github.com/mjl-/mox v0.0.17 is not a local path")
}

func TestHygieneFailsOnAnotherGoLine(t *testing.T) {
	fixture := newFixture(t)
	fixture.edit("mlsinterop/go.mod", "go 1.27.4", "go 1.27.2")
	wantFindings(t, fixture.open().moduleLineFindings(t), "mlsinterop: go 1.27.2, and §4.7's is 1.27.4")
}

// A tool line adds its requirements to every consumer's graph, which is why govulncheck is not one.
func TestHygieneFailsOnAnExtraToolLine(t *testing.T) {
	fixture := newFixture(t)
	fixture.edit("go.mod", "tool google.golang.org/protobuf/cmd/protoc-gen-go", "tool google.golang.org/protobuf/cmd/protoc-gen-go\n\ntool golang.org/x/vuln/cmd/govulncheck")
	wantFindings(t, fixture.open().moduleLineFindings(t), "tool lines")
}

func TestHygieneFailsOnAGoWorkFile(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("go.work", "go 1.27.4\n\nuse .\n")
	wantFindings(t, fixture.open().workFileFindings(t), "go.work changes what builds resolve")
}

// cli keeps its unversioned path at release, and the release's sed turns an import of
// .../sidecar/cli/daemon into one under .../sidecar/v2026, which the root's tag does not hold.
func TestHygieneFailsOnASubpackageOfCli(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("cli/daemon/daemon.go", "package daemon\n")
	wantFindings(t, fixture.open().untaggedSubpackageFindings(t), "cli/daemon: a package beside cli's own")
}

// sidecarctl keeps its unversioned path too, and every command stays a file of its one package.
func TestHygieneFailsOnASubpackageOfSidecarctl(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("sidecarctl/certs/swap.go", "package certs\n")
	wantFindings(t, fixture.open().untaggedSubpackageFindings(t), "sidecarctl/certs: a package beside sidecarctl's own")
}

// One finding a package, its tests included, and testdata is no package.
func TestHygieneFailsOnASubpackageOfMlsinterop(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("mlsinterop/peer/peer.go", "package peer\n")
	fixture.write("mlsinterop/peer/peer_test.go", "package peer\n")
	fixture.write("mlsinterop/testdata/vectors/vector.go", "package vectors\n")
	wantFindings(t, fixture.open().untaggedSubpackageFindings(t), "mlsinterop/peer: a package beside mlsinterop's own")
}

// An external test of mlsinterop imports mlsinterop's own path, which the release's rewrite turns
// into one under .../sidecar/v2026: the development tree lists, and the release tree does not.
func TestHygieneFailsOnAnExternalTestImportingMlsinterop(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("tests mlsinterop linux/amd64")
	fixture.write("mlsinterop/doc_test.go", "package mlsinterop_test\n\nimport _ \"@module@/mlsinterop\"\n")
	repository := fixture.open()
	wantFindings(t, repository.untaggedSubpackageFindings(t),
		"mlsinterop/doc_test.go:3: the release's rewrite makes this \"@module@/v2026/mlsinterop\", which nothing provides: mlsinterop keeps its unversioned path")
	if _, err := repository.listLeg(repository.legs[0]); err != nil {
		t.Fatalf("the development tree does not list: %v", err)
	}

	fixture.toRelease()
	release := fixture.openRelease()
	if _, err := release.listLeg(release.legs[0]); err == nil {
		t.Errorf("the release tree lists, so this is no break")
	}
	wantFindings(t, release.untaggedSubpackageFindings(t),
		"mlsinterop/doc_test.go:3: the release's rewrite makes this \"@module@/v2026/mlsinterop\"")
}

// The rewrite reads every quoted string, not just imports, and every Makefile.
func TestHygieneFailsOnAQuotedPathOfCliOutsideAnImport(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("cli/version.go", "package main\n\nvar modulePath = \"@module@/cli\"\n")
	fixture.write("cli/Makefile", "install:\n\tgo install \"@module@/cli@latest\"\n")
	wantFindings(t, fixture.open().untaggedSubpackageFindings(t),
		"cli/version.go:3: the release's rewrite makes this \"@module@/v2026/cli\"",
		"cli/Makefile:2: the release's rewrite makes this \"@module@/v2026/cli\"")
}

// The control: what the rewrite versions correctly, and a line it leaves alone, which holds /vN.
func TestHygieneAllowsQuotedPathsTheRewriteKeeps(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("cli/paths.go", "package main\n\nvar paths = []string{\"@module@/protocol\", \"@module@/smtpproof\"}\n\n// \"@module@/mlsinterop\" beside example.com/x/v2\n")
	wantFindings(t, fixture.open().untaggedSubpackageFindings(t))
}

const (
	plantedBridgeProto = `syntax = "proto3";
package urnetwork.sidecar;
option go_package = "@module@/protocol/bridge";

message Signed {
  bytes body = 1;
}
`
	plantedConfigProto = `syntax = "proto3";
package urnetwork.sidecar;
option go_package = "@module@/protocol";

import "protocol/bridge/signed.proto";

message ConfigRecord {
  Signed signed = 1;
}
`
)

// protocol/Makefile's protoc line, over the fixture's own files. The plugin is the real go.mod's.
func generateProtos(t *testing.T, directory string, protoFiles ...string) {
	t.Helper()
	plugin, err := runGo("..", goEnvironment(), "tool", "-n", "protoc-gen-go")
	if err != nil {
		t.Fatal(err)
	}
	arguments := []string{
		"-I=.", "--plugin=protoc-gen-go=" + strings.TrimSpace(string(plugin)),
		"--go_out=.", "--go_opt=paths=source_relative",
	}
	command := exec.Command("protoc", append(arguments, protoFiles...)...)
	command.Dir = directory
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("protoc: %v\n%s", err, output)
	}
}

// A fixture with two generated files as §4.9 lays them out, and protobuf linked on every leg.
func newProtoFixture(t *testing.T) *fixture {
	t.Helper()
	fixture := newFixture(t)
	fixture.keepLegs("root linux/amd64")
	fixture.write("protocol/bridge/signed.proto", plantedBridgeProto)
	fixture.write("protocol/config.proto", plantedConfigProto)
	generateProtos(t, filepath.Join(fixture.directory, "sidecar"), "protocol/config.proto", "protocol/bridge/signed.proto")
	// config.pb.go is on the ios_extension leg's list, as the checkout's is, so protocol/Makefile writes no tag on it
	writeIosExtensionLegList(fixture, "protocol/config.pb.go")
	return fixture
}

// The control for the rows below: §4.9's layout, generated as §4.9 says, passes both rules.
func TestHygieneAllowsGeneratedCodeLaidOutAsSection49Says(t *testing.T) {
	repository := newProtoFixture(t).open()
	wantFindings(t, repository.registryFindings(t))
	wantFindings(t, repository.staleGeneratedFindings(t))
}

// config.proto redeclares a bridge type: the panic §4.9 warns of, in a binary linking both.
func TestHygieneFailsOnTwoFilesDeclaringOneMessage(t *testing.T) {
	fixture := newProtoFixture(t)
	fixture.write("protocol/config.proto", strings.Replace(plantedConfigProto, "import \"protocol/bridge/signed.proto\";\n", "", 1)+"\nmessage Signed {\n  bytes body = 1;\n}\n")
	fixture.edit("protocol/config.proto", "Signed signed = 1;", "bytes signed = 1;")
	generateProtos(t, filepath.Join(fixture.directory, "sidecar"), "protocol/config.proto")
	wantFindings(t, fixture.open().registryFindings(t), "linking every registering package failed")
}

// Generated from inside protocol/, a file takes connect's own name for it: frame.proto. The path
// collision only shows in a binary that links both, which is what sdk and server are.
func TestHygieneFailsOnAConflictWithConnect(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("root linux/amd64")
	fixture.writeSibling("connect/protocol/frame.proto", "syntax = \"proto3\";\npackage bringyour;\noption go_package = \"@connect@/protocol\";\n\nmessage Frame {\n  bytes body = 1;\n}\n")
	generateProtos(t, filepath.Join(fixture.directory, "connect", "protocol"), "frame.proto")
	fixture.writeSibling("connect/connect.go", "package connect\n\nimport (\n\t_ \"@connect@/protocol\"\n\t_ \"@glog@\"\n\t_ \"github.com/pion/sctp\"\n\t_ \"gvisor.dev/gvisor/pkg/tcpip\"\n)\n\nfunc Connect() {}\n")
	fixture.writeSibling("connect/go.mod", fixtureFiles["connect/go.mod"]+"\nrequire google.golang.org/protobuf v1.36.11\n")
	goSum, err := realGoSum()
	if err != nil {
		t.Fatal(err)
	}
	fixture.writeSibling("connect/go.sum", string(goSum))
	fixture.write("protocol/frame.proto", "syntax = \"proto3\";\npackage urnetwork.sidecar;\noption go_package = \"@module@/protocol\";\n\nmessage Ours {\n  bytes body = 1;\n}\n")
	generateProtos(t, filepath.Join(fixture.directory, "sidecar", "protocol"), "frame.proto")
	wantFindings(t, fixture.open().registryFindings(t), "linking every registering package failed")
}

// Nothing is linked twice, so nothing panics, but the name is §4.9's to keep: a file generated from
// protocol/ registers as config.proto, the shape of the collision above.
func TestHygieneFailsOnAProtoRegisteredOutsideItsPath(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("root linux/amd64")
	fixture.write("protocol/config.proto", "syntax = \"proto3\";\npackage urnetwork.sidecar;\noption go_package = \"@module@/protocol\";\n\nmessage ConfigRecord {\n  bytes body = 1;\n}\n")
	generateProtos(t, filepath.Join(fixture.directory, "sidecar", "protocol"), "config.proto")
	wantFindings(t, fixture.open().registryFindings(t), "protocol/config.proto does not register under that path")
}

func TestHygieneFailsOnAnotherProtoPackage(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("root linux/amd64")
	fixture.write("protocol/config.proto", "syntax = \"proto3\";\npackage bringyour;\noption go_package = \"@module@/protocol\";\n\nmessage ConfigRecord {\n  bytes body = 1;\n}\n")
	generateProtos(t, filepath.Join(fixture.directory, "sidecar"), "protocol/config.proto")
	wantFindings(t, fixture.open().registryFindings(t), "protocol/config.proto registers in package bringyour")
}

func TestHygieneFailsOnAProtoEditedAfterGeneration(t *testing.T) {
	fixture := newProtoFixture(t)
	fixture.edit("protocol/bridge/signed.proto", "bytes body = 1;", "bytes body = 1;\n  bytes more = 2;")
	wantFindings(t, fixture.open().staleGeneratedFindings(t), "protocol/bridge/signed.pb.go is stale")
}

func TestHygieneFailsOnAHandEditedPbGo(t *testing.T) {
	fixture := newProtoFixture(t)
	fixture.edit("protocol/config.pb.go", "type ConfigRecord struct {", "type ConfigRecord struct {\n\tPlanted int")
	wantFindings(t, fixture.open().staleGeneratedFindings(t), "protocol/config.pb.go is stale")
}

func TestHygieneFailsOnAMissingPbGo(t *testing.T) {
	fixture := newProtoFixture(t)
	fixture.remove("protocol/config.pb.go")
	wantFindings(t, fixture.open().staleGeneratedFindings(t), "protocol/config.proto has no generated file")
}

func TestHygieneFailsOnAnOrphanPbGo(t *testing.T) {
	fixture := newProtoFixture(t)
	fixture.remove("protocol/config.proto")
	wantFindings(t, fixture.open().staleGeneratedFindings(t), "protocol/config.pb.go has no .proto")
}

// §4.9 pins protoc-gen-go, so its header line stays compared; the protoc line does not.
func TestHygieneFailsOnAnotherPluginVersion(t *testing.T) {
	fixture := newProtoFixture(t)
	fixture.edit("protocol/config.pb.go", "protoc-gen-go v1.36.11", "protoc-gen-go v1.36.12")
	wantFindings(t, fixture.open().staleGeneratedFindings(t), "protocol/config.pb.go is stale")
}

func TestHygieneAllowsAnotherProtocVersion(t *testing.T) {
	fixture := newProtoFixture(t)
	data, err := os.ReadFile(filepath.Join(fixture.directory, "sidecar", "protocol", "config.pb.go"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.write("protocol/config.pb.go", protocVersionLinePattern.ReplaceAllString(string(data), "// \tprotoc        v9.99.9\n"))
	wantFindings(t, fixture.open().staleGeneratedFindings(t))
}

// Generated code with no generator here is unwatched code, and the rule says so.
func TestHygieneFailsOnGeneratedCodeItCannotRegenerate(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("other_gen.go", "// Code generated by othergen. DO NOT EDIT.\n\npackage sidecar\n")
	wantFindings(t, fixture.open().staleGeneratedFindings(t), "other_gen.go is generated, and this rule has no way to regenerate it")
}

// A go generate output the settings name passes only while the test holding it to its source is
// there: gone, it is unwatched again.
func TestHygieneFailsOnGeneratedCodeWhoseTestIsGone(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("mail_operators_gen.go", "// Code generated from mail_operators.yml by TestMailOperatorsGenIsCurrent. DO NOT EDIT.\n\npackage sidecar\n")
	wantFindings(t, fixture.open().staleGeneratedFindings(t),
		"mail_operators_gen.go is generated, and TestMailOperatorsGenIsCurrent, which holds it to its source, is missing")
	fixture.write("mail_label_test.go", "package sidecar\n\nimport \"testing\"\n\nfunc TestMailOperatorsGenIsCurrent(t *testing.T) {}\n")
	wantFindings(t, fixture.open().staleGeneratedFindings(t))
}

// A rule that cannot run has not passed: without protoc nothing shows the files are current.
func TestHygieneFailsOnAMissingProtoc(t *testing.T) {
	fixture := newProtoFixture(t)
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	binDirectory := t.TempDir()
	if err := os.Symlink(goPath, filepath.Join(binDirectory, "go")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDirectory)
	wantFindings(t, fixture.open().staleGeneratedFindings(t), "protoc is not on PATH")
}

// A planted stdlib entry in a local database, so the proof needs no network and no real
// vulnerability: every call of strings.ToUpper is vulnerable, in every version.
func writeVulnDatabase(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	const modified = "2026-11-01T00:00:00Z"
	files := map[string]any{
		"index/db.json": map[string]any{"modified": modified},
		"index/modules.json": []any{map[string]any{
			"path":  "stdlib",
			"vulns": []any{map[string]any{"id": "GO-2026-0001", "modified": modified}},
		}},
		"index/vulns.json": []any{map[string]any{"id": "GO-2026-0001", "modified": modified, "aliases": []any{}}},
		"ID/GO-2026-0001.json": map[string]any{
			"schema_version": "1.3.1",
			"id":             "GO-2026-0001",
			"modified":       modified,
			"published":      modified,
			"summary":        "A planted vulnerability",
			"details":        "Calling strings.ToUpper is planted as vulnerable.",
			"affected": []any{map[string]any{
				"package": map[string]any{"name": "stdlib", "ecosystem": "Go"},
				"ranges": []any{map[string]any{
					"type":   "SEMVER",
					"events": []any{map[string]any{"introduced": "0"}},
				}},
				"ecosystem_specific": map[string]any{
					"imports": []any{map[string]any{"path": "strings", "symbols": []any{"ToUpper"}}},
				},
			}},
			"database_specific": map[string]any{"url": "https://pkg.go.dev/vuln/GO-2026-0001"},
		},
	}
	for name, content := range files {
		data, err := json.Marshal(content)
		if err != nil {
			t.Fatal(err)
		}
		fullPath := filepath.Join(directory, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fullPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return "file://" + directory
}

// A leg reaching a vulnerable symbol fails, and a leg that does not reach it stays clean, so the
// finding is the tool's call analysis and not a blanket refusal.
func TestHygieneFailsOnAVulnerableCallOnALeg(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("root linux/amd64", "cli linux/amd64", "cli windows/amd64")
	fixture.settings.vulnDatabase = writeVulnDatabase(t)
	fixture.write("cli/planted_windows.go", "package main\n\nimport \"strings\"\n\nfunc init() {\n\tprintln(strings.ToUpper(\"planted\"))\n}\n")
	repository := fixture.open()
	wantFindings(t, repository.vulnFindings(repository.installGovulncheck(t)), "cli windows/amd64:\n")
}

// A clean scan and a scan that never ran must not read the same.
func TestHygieneFailsOnAnUnreachableVulnDatabase(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs("cli linux/amd64")
	fixture.settings.vulnDatabase = "file://" + filepath.Join(fixture.directory, "no-such-database")
	repository := fixture.open()
	wantFindings(t, repository.vulnFindings(repository.installGovulncheck(t)), "cli linux/amd64: govulncheck did not finish")
}
