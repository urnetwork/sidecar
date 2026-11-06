//go:build sidecar_check

// §4.7's hygiene row, the generated code: registry conflicts and stale .pb.go files. Both read what
// protoc-gen-go actually produced, not the .proto text. A duplicate path or name panics at init in
// whatever binary links both sides, so the registry rule links the same packages sdk and server do
// and runs the result, with the panic left on. The stale rule regenerates beside the committed files
// and compares bytes.

package check

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// The protobuf package every sidecar file declares (§4.9).
const sidecarProtoPackage = "urnetwork.sidecar"

// What a generated header says about protoc, the one line that varies by who ran it. The design
// pins protoc-gen-go, whose line stays compared, and not protoc: connect's own files carry two.
var protocVersionLinePattern = regexp.MustCompile(`(?m)^//\s+protoc\s+.*\n`)

// Files of a kind under the root module's protocol directory, relative to the module, sorted.
func (self *repository) protocolFiles(suffix string) ([]string, error) {
	files := []string{}
	err := filepath.WalkDir(filepath.Join(self.moduleDirectory, "protocol"), func(walkPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() && skippedDirectoryNames[entry.Name()] {
			return filepath.SkipDir
		}
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), suffix) {
			relativePath, err := filepath.Rel(self.moduleDirectory, walkPath)
			if err != nil {
				return err
			}
			files = append(files, filepath.ToSlash(relativePath))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(files)
	return files, nil
}

// The packages that register descriptors, as import paths: this repository's, connect's protocol,
// which every consumer links beside them, and any other package a host build reaches that imports
// protobuf's runtime.
func (self *repository) registeringPackages(t testing.TB) []string {
	t.Helper()
	generatedFiles, err := self.protocolFiles(".pb.go")
	if err != nil {
		t.Fatal(err)
	}
	packages := map[string]bool{}
	for _, generatedFile := range generatedFiles {
		directory := filepath.ToSlash(filepath.Dir(generatedFile))
		packages[self.modulePath+"/"+directory] = true
	}
	for _, require := range self.module(t, ".").file.Require {
		if firstPartyBase(require.Path) == connectBasePath {
			packages[require.Path+"/protocol"] = true
		}
	}
	host := &buildLeg{
		name: "host registry", moduleName: ".", goos: runtime.GOOS, goarch: runtime.GOARCH,
		patterns: allPatterns, class: classTest,
	}
	for _, listed := range self.closure(t, host) {
		if !listed.Standard && slices.Contains(listed.Imports, protobufBasePath+"/runtime/protoimpl") {
			packages[listed.ImportPath] = true
		}
	}
	sortedPackages := make([]string, 0, len(packages))
	for packagePath := range packages {
		sortedPackages = append(sortedPackages, packagePath)
	}
	slices.Sort(sortedPackages)
	return sortedPackages
}

// Links every registering package into one program and has it list what registered, with an
// overlay so the program never touches the tree. Exit 0 with a list means no conflict; a panic at
// init is the finding. GOLANG_PROTOBUF_REGISTRATION_CONFLICT is pinned to panic, because the warn
// setting of a developer's shell would turn the rule off.
func (self *repository) registryFindings(t testing.TB) []string {
	t.Helper()
	source := strings.Builder{}
	source.WriteString("package main\n\nimport (\n\t\"fmt\"\n\n")
	fmt.Fprintf(&source, "\t%q\n\t%q\n\n", protobufBasePath+"/reflect/protoreflect", protobufBasePath+"/reflect/protoregistry")
	for _, packagePath := range self.registeringPackages(t) {
		fmt.Fprintf(&source, "\t_ %q\n", packagePath)
	}
	source.WriteString(`)

func main() {
	protoregistry.GlobalFiles.RangeFiles(func(file protoreflect.FileDescriptor) bool {
		fmt.Printf("%s\t%s\n", file.Path(), file.Package())
		return true
	})
}
`)
	probeDirectory := t.TempDir()
	probePath := filepath.Join(probeDirectory, "main.go")
	if err := os.WriteFile(probePath, []byte(source.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	overlayPath := writeOverlay(t, probeDirectory, filepath.Join(self.moduleDirectory, "checkregistryprobe", "main.go"), probePath)
	output, err := runGo(self.moduleDirectory,
		goEnvironment("GOLANG_PROTOBUF_REGISTRATION_CONFLICT=panic"),
		"run", "-overlay="+overlayPath, "./checkregistryprobe")
	if err != nil {
		return []string{findingf("linking every registering package failed: %v", err)}
	}

	registered := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		filePath, protoPackage, found := strings.Cut(line, "\t")
		if found {
			registered[filePath] = protoPackage
		}
	}
	protoFiles, err := self.protocolFiles(".proto")
	if err != nil {
		t.Fatal(err)
	}
	findings := []string{}
	for _, protoFile := range protoFiles {
		protoPackage, found := registered[protoFile]
		if !found {
			findings = append(findings, findingf("%s does not register under that path; §4.9 runs protoc from the repo root", protoFile))
			continue
		}
		if protoPackage != sidecarProtoPackage {
			findings = append(findings, findingf("%s registers in package %s, and §4.9's is %s", protoFile, protoPackage, sidecarProtoPackage))
		}
	}
	self.report("the registry probe linked %d files, %d of them this repository's", len(registered), len(protoFiles))
	return findings
}

// An overlay file mapping one path that does not exist to one that does.
func writeOverlay(t testing.TB, directory string, virtualPath string, realPath string) string {
	t.Helper()
	data, err := json.Marshal(map[string]map[string]string{"Replace": {virtualPath: realPath}})
	if err != nil {
		t.Fatal(err)
	}
	overlayPath := filepath.Join(directory, "overlay.json")
	if err := os.WriteFile(overlayPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return overlayPath
}

// Regenerates into a temporary directory exactly as protocol/Makefile does, then compares against
// what is committed: a .proto with no output, a .pb.go with no .proto, or bytes that differ. protoc
// is required once a .proto exists, and its absence fails, because a rule that cannot run has not
// passed. On a release branch committed files carry the rewritten import paths and are never
// regenerated (§4.9), so the fresh output goes through the same rewrite before the comparison.
func (self *repository) staleGeneratedFindings(t testing.TB) []string {
	t.Helper()
	protoFiles, err := self.protocolFiles(".proto")
	if err != nil {
		t.Fatal(err)
	}
	generatedFiles, err := self.protocolFiles(".pb.go")
	if err != nil {
		t.Fatal(err)
	}
	findings := self.unregeneratedFindings(t)
	for _, generatedFile := range generatedFiles {
		if !slices.Contains(protoFiles, strings.TrimSuffix(generatedFile, ".pb.go")+".proto") {
			findings = append(findings, findingf("%s has no .proto", generatedFile))
		}
	}
	if len(protoFiles) == 0 {
		return findings
	}
	plugin, err := runGo(self.moduleDirectory, goEnvironment(), "tool", "-n", "protoc-gen-go")
	if err != nil {
		return append(findings, findingf("finding go.mod's protoc-gen-go: %v", err))
	}
	output := t.TempDir()
	arguments := []string{
		"-I=.", "--plugin=protoc-gen-go=" + strings.TrimSpace(string(plugin)),
		"--go_out=" + output, "--go_opt=paths=source_relative",
	}
	command := exec.Command("protoc", append(arguments, protoFiles...)...)
	command.Dir = self.moduleDirectory
	combined, err := command.CombinedOutput()
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return append(findings, "protoc is not on PATH, so nothing shows the generated files are current")
		}
		return append(findings, findingf("protoc: %v\n%s", err, combined))
	}
	normalize := func(data []byte) []byte {
		return protocVersionLinePattern.ReplaceAll(data, nil)
	}
	for _, protoFile := range protoFiles {
		generatedFile := strings.TrimSuffix(protoFile, ".proto") + ".pb.go"
		committed, err := os.ReadFile(filepath.Join(self.moduleDirectory, filepath.FromSlash(generatedFile)))
		if err != nil {
			findings = append(findings, findingf("%s has no generated file: %v", protoFile, err))
			continue
		}
		fresh, err := os.ReadFile(filepath.Join(output, filepath.FromSlash(generatedFile)))
		if err != nil {
			findings = append(findings, findingf("protoc wrote no %s: %v", generatedFile, err))
			continue
		}
		if self.releaseSuffix != "" {
			fresh = []byte(releaseRewrite(string(fresh), self.releaseSuffix))
		}
		if !bytes.Equal(normalize(committed), normalize(fresh)) {
			findings = append(findings, findingf("%s is stale; run make proto", generatedFile))
		}
	}
	return findings
}

// A generated file nothing here knows how to regenerate. Only protoc's output has a rule so far, so
// the first go generate output fails until this file learns its generator, rather than going stale
// unwatched. Read by Go's own marker line, which gofmt and the linters honor.
func (self *repository) unregeneratedFindings(t testing.TB) []string {
	t.Helper()
	findings := []string{}
	for _, file := range self.sourceFiles(t) {
		if strings.HasSuffix(file.path, ".pb.go") {
			continue
		}
		if ast.IsGenerated(file.syntax) {
			findings = append(findings, findingf("%s is generated, and this rule has no way to regenerate it", self.displayPath(file.path)))
		}
	}
	return findings
}

// build/all/run.sh:1560-1566 as this repository's release applies them to one module path: its
// exact quoted path and each subpackage, on a line not already carrying /vN. smtpproof's go first in
// the release, so a line naming it is skipped by the root's pass that follows.
func releaseRewritePath(content string, modulePath string, suffix string) string {
	quotedPathPattern := regexp.MustCompile(`"` + regexp.QuoteMeta(modulePath) + `([^"]*)"`)
	lines := strings.Split(content, "\n")
	for index, line := range lines {
		if !releaseVersionedLinePattern.MatchString(line) {
			lines[index] = quotedPathPattern.ReplaceAllString(line, `"`+modulePath+suffix+`$1"`)
		}
	}
	return strings.Join(lines, "\n")
}

// The rewrite of this repository's root path, which is all a generated file here names.
func releaseRewrite(content string, suffix string) string {
	return releaseRewritePath(content, sidecarBasePath, suffix)
}

// A line the release's subpackage pass leaves alone.
var releaseVersionedLinePattern = regexp.MustCompile(`/v[0-9]+`)
