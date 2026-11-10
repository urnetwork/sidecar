//go:build sidecar_check

// §4.7's legs row: what the ios_extension and sidecar_http legs must leave out, and §18.10's pruning
// rule on every leg that reaches a phone or a page.

package check

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
)

// The ios_extension leg's list (D-SDK-20; DESIGN-DETAILS 4.2.3), relative to the root module: the root and protocol
// files Apple's network extensions may link, which is the forwarding role's file closure. One path a line, sorted, from
// the root module, with # lines as comments. legs_closure_test.go computes it; this package only reads it.
const iosExtensionLegListPath = "check/testdata/ios_extension_leg.txt"

// A line of the list: a root file or a protocol file, never a test file or one in another directory.
var iosExtensionLegListEntryPattern = regexp.MustCompile(`^(protocol/)?[A-Za-z0-9][A-Za-z0-9_.-]*\.go$`)

// The list as a checkout holds it, with what is wrong with its form. A list that cannot be read is a finding, since a
// rule that read no list has not passed.
type iosExtensionLegList struct {
	files    map[string]bool
	findings []string
}

// Reads the list under the root module directory.
func readIosExtensionLegList(moduleDirectory string) *iosExtensionLegList {
	list := &iosExtensionLegList{files: map[string]bool{}}
	data, err := os.ReadFile(filepath.Join(moduleDirectory, filepath.FromSlash(iosExtensionLegListPath)))
	if err != nil {
		list.findings = append(list.findings, findingf("the ios_extension leg's list does not read: %v", err))
		return list
	}
	previous := ""
	for index, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		at := findingf("%s:%d", iosExtensionLegListPath, index+1)
		switch {
		case !iosExtensionLegListEntryPattern.MatchString(line) || strings.HasSuffix(line, "_test.go"):
			list.findings = append(list.findings, findingf("%s: %q is no root or protocol file the leg could compile", at, line))
			continue
		case list.files[line]:
			list.findings = append(list.findings, findingf("%s: %s is named twice", at, line))
		case line < previous:
			list.findings = append(list.findings, findingf("%s: %s is out of order after %s; the list is sorted, so its diff shows each change", at, line, previous))
		}
		list.files[line] = true
		previous = line
	}
	if len(list.files) == 0 && len(list.findings) == 0 {
		list.findings = append(list.findings, findingf("%s names no file", iosExtensionLegListPath))
	}
	return list
}

// Modules no file on the list imports, refused in the ios_extension legs' go list -deps by the module a package comes
// from, whole path elements, so a /v2 path counts: mail's servers and verifiers, DNS, ACME and its test server, the MCP
// sdk, brotli and yaml (DESIGN-DETAILS 4.2.3's rule 2).
var iosExtensionRefusedModules = []string{
	"github.com/andybalholm/brotli",
	"github.com/emersion/go-imap",
	"github.com/emersion/go-message",
	"github.com/emersion/go-smtp",
	"github.com/letsencrypt/pebble",
	"github.com/mholt/acmez",
	"github.com/miekg/dns",
	"github.com/mjl-/adns",
	"github.com/mjl-/mox",
	"github.com/modelcontextprotocol/go-sdk",
	"gopkg.in/yaml.v3",
}

// Packages refused there by import path, whatever module holds them: x/text's legacy encodings and x/net's HTML parser,
// whose tables a package-level variable roots past any dead-code pass, and the std packages that keep every exported
// method alive (pruningBreakers).
var iosExtensionRefusedPackages = []string{
	"golang.org/x/net/html",
	"golang.org/x/text/encoding",
	"html/template",
	"net/rpc",
	"text/template",
}

// The build line protocol/Makefile writes above a generated protocol file the list does not name.
const iosExtensionGeneratedTagLine = "//go:build !ios_extension\n\n"

// A generated file as protocol/Makefile leaves it: protoc's output, tagged when it is one of protocol's own files and
// the list does not name it. protocol/bridge is linked whole.
func iosExtensionTagGenerated(list *iosExtensionLegList, generatedFile string, data []byte) []byte {
	if path.Dir(generatedFile) != "protocol" || list.files[generatedFile] {
		return data
	}
	return append([]byte(iosExtensionGeneratedTagLine), data...)
}

// True when the rules read an ios_extension leg, the iOS extension's or the macOS slices'.
func (self *repository) readsIosExtensionLeg() bool {
	return slices.ContainsFunc(self.legs, func(leg *buildLeg) bool { return leg.hasTag(iosExtensionTag) })
}

// Mail libraries a page Worker has no use for, since it reads mail and neither receives, serves nor
// checks it (R-MAIL-13, MAIL.md's build legs). dependencies.yml's client class cannot say this, because
// that class also covers the root on every other leg. go-message is left out: MAIL-M7-11 puts its one
// file on every leg, so whether the Worker links it is that task's to settle.
var sidecarHttpRefusedMailModules = []string{
	"github.com/emersion/go-imap",
	"github.com/emersion/go-sasl",
	"github.com/emersion/go-smtp",
	"github.com/mjl-/adns",
	"github.com/mjl-/mox",
}

// std packages that hold a binary's exported methods alive, so the linker cannot prune them
// (sdk/build/mobile_method_pruning_test.go:12-22).
var pruningBreakers = []string{"net/rpc", "text/template", "html/template"}

// D-SDK-20 and DESIGN-DETAILS 4.2.3's rules 1 and 3: of this repository the ios_extension legs link device and
// protocol/bridge whole, and of the root and protocol only the files on the leg's list, and no other package. A root or
// protocol file either leg compiles that the list does not name fails with its fix, the tag; protocol/Makefile writes it
// on every generated file off the list. The list may name a file no leg compiles, so it shrinks by a deletion or a tag
// with no edit, and each such name is reported; it grows only in a commit that edits it, since nothing here writes it.
// Files are read as the legs compile them, so a file only the macOS slices build is seen.
func (self *repository) iosExtensionFindings(t testing.TB) []string {
	t.Helper()
	if !self.readsIosExtensionLeg() {
		return nil
	}
	list := readIosExtensionLegList(self.moduleDirectory)
	findings := slices.Clone(list.findings)
	compiled := map[string]bool{}
	for _, leg := range self.legs {
		if !leg.hasTag(iosExtensionTag) {
			continue
		}
		for _, listed := range self.closure(t, leg) {
			relative, ours := repositoryRelative(listed.ImportPath)
			if !ours || underPath(relative, "device") || underPath(relative, "protocol/bridge") {
				continue
			}
			if relative != "." && relative != "protocol" {
				findings = append(findings, findingf("%s links %s", leg.name, listed.ImportPath))
				continue
			}
			for _, goFile := range slices.Concat(listed.GoFiles, listed.CgoFiles) {
				name := goFile
				if relative == "protocol" {
					name = "protocol/" + goFile
				}
				compiled[name] = true
				if list.files[name] {
					continue
				}
				fix := "give it //go:build !ios_extension, or put it on the list in the commit that needs it there"
				if strings.HasSuffix(goFile, ".pb.go") {
					fix = "run make proto, which tags every generated file off the list"
				}
				findings = append(findings, findingf("%s compiles %s, which is not on %s: %s (DESIGN-DETAILS 4.2.3)",
					leg.name, name, iosExtensionLegListPath, fix))
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(list.files)) {
		if !compiled[name] {
			self.report("%s names %s, which no ios_extension leg compiles: the list may shrink by it", iosExtensionLegListPath, name)
		}
	}
	slices.Sort(findings)
	return findings
}

// What connect links on the leg by itself, connect and connect/protocol's go list -deps: the iOS extension's packages
// before sidecar was in it, which make size's baseline also keeps (size_test.go). A leg this cannot list is an error,
// since a rule that read no baseline has not run.
func (self *repository) iosExtensionBaselineImportPaths(t testing.TB, leg *buildLeg) (map[string]bool, error) {
	t.Helper()
	directory, err := self.legDirectory(leg)
	if err != nil {
		return nil, err
	}
	arguments := []string{"list", "-deps", "-tags=" + strings.Join(leg.tags, ",")}
	connected := false
	for _, require := range self.module(t, ".").file.Require {
		if firstPartyBase(require.Path) == connectBasePath {
			arguments = append(arguments, require.Path, require.Path+"/protocol")
			connected = true
		}
	}
	if !connected {
		return nil, fmt.Errorf("%s: the root module requires no connect, so there is no baseline to read", leg.name)
	}
	output, err := runGo(directory, leg.environment(), arguments...)
	if err != nil {
		return nil, err
	}
	importPaths := map[string]bool{}
	for _, line := range strings.Fields(string(output)) {
		importPaths[line] = true
	}
	return importPaths, nil
}

// DESIGN-DETAILS 4.2.3's rule 2: no ios_extension leg's go list -deps holds a package of a refused module or under a
// refused package beyond what connect links there by itself, so a file put on the list cannot bring one in, nor can a
// file a list file reaches. Connect's own closure is no part of the rule: the extension carries it with or without
// sidecar, and its uTLS links brotli on every extension leg.
func (self *repository) iosExtensionModuleFindings(t testing.TB) []string {
	t.Helper()
	findings := []string{}
	for _, leg := range self.legs {
		if !leg.hasTag(iosExtensionTag) {
			continue
		}
		baseline, err := self.iosExtensionBaselineImportPaths(t, leg)
		if err != nil {
			findings = append(findings, findingf("no refused module was read on %s: %v", leg.name, err))
			continue
		}
		for _, listed := range self.closure(t, leg) {
			if baseline[listed.ImportPath] {
				continue
			}
			refused := ""
			if listed.Module != nil {
				for _, module := range iosExtensionRefusedModules {
					if underPath(listed.Module.Path, module) {
						refused = module
					}
				}
			}
			for _, refusedPackage := range iosExtensionRefusedPackages {
				if underPath(listed.ImportPath, refusedPackage) {
					refused = refusedPackage
				}
			}
			if refused != "" {
				findings = append(findings, findingf("%s links %s, under %s, which the forwarding leg refuses (DESIGN-DETAILS 4.2.3)",
					leg.name, listed.ImportPath, refused))
			}
		}
	}
	slices.Sort(findings)
	return findings
}

// §18.10: the leg's closure holds no connect or gVisor package, nor the sctp fork that lives in
// connect's tree. Each is matched by the module the package comes from.
func (self *repository) sidecarHttpFindings(t testing.TB) []string {
	t.Helper()
	findings := []string{}
	for _, leg := range self.legs {
		if !leg.hasTag(sidecarHttpTag) {
			continue
		}
		for _, listed := range self.closure(t, leg) {
			if listed.Module == nil {
				continue
			}
			base := firstPartyBase(listed.Module.Path)
			if base == connectBasePath || base == sctpBasePath || base == gvisorBasePath {
				findings = append(findings, findingf("%s links %s", leg.name, listed.ImportPath))
			}
		}
	}
	slices.Sort(findings)
	return findings
}

// R-MAIL-13: the leg's closure holds none of sidecarHttpRefusedMailModules, so a mail_ file that links
// one and forgot !sidecar_http fails here. Each is matched by the module the package comes from, whole
// elements, so a /v2 path counts.
func (self *repository) sidecarHttpMailFindings(t testing.TB) []string {
	t.Helper()
	findings := []string{}
	for _, leg := range self.legs {
		if !leg.hasTag(sidecarHttpTag) {
			continue
		}
		for _, listed := range self.closure(t, leg) {
			if listed.Module == nil {
				continue
			}
			if slices.ContainsFunc(sidecarHttpRefusedMailModules, func(refused string) bool {
				return underPath(listed.Module.Path, refused)
			}) {
				findings = append(findings, findingf("%s links %s", leg.name, listed.ImportPath))
			}
		}
	}
	slices.Sort(findings)
	return findings
}

// §4.4, §18.10: no engine runs in the page Worker, so host_*.go carries !sidecar_http. Read off the
// root package's files as the leg compiles them.
func (self *repository) hostFileFindings(t testing.TB) []string {
	t.Helper()
	findings := []string{}
	for _, leg := range self.legs {
		if !leg.hasTag(sidecarHttpTag) {
			continue
		}
		for _, listed := range self.closure(t, leg) {
			if listed.ImportPath != self.modulePath {
				continue
			}
			for _, goFile := range listed.GoFiles {
				if strings.HasPrefix(goFile, "host_") {
					findings = append(findings, findingf("%s compiles %s, which must carry !%s", leg.name, goFile, sidecarHttpTag))
				}
			}
		}
	}
	return findings
}

// True for a leg §4.7's pruning row binds: ios, android or js, and gomobile's macOS slices, which
// sdk's own pruning test holds to the same list.
func (self *buildLeg) bindsPruning() bool {
	return self.goos == "ios" || self.goos == "android" || self.goos == "js" || self.hasTag(mobileBindTag)
}

// §4.7, §18.10: net/rpc and the template packages on a shipped ios, android or js leg. A test leg
// is out of it, since a test binary reaches no phone and Go's own tooling packages import them.
func (self *repository) pruningFindings(t testing.TB) []string {
	t.Helper()
	findings := []string{}
	for _, leg := range self.shippedLegs() {
		if !leg.bindsPruning() {
			continue
		}
		for _, listed := range self.closure(t, leg) {
			if slices.ContainsFunc(pruningBreakers, func(breaker string) bool {
				return underPath(listed.ImportPath, breaker)
			}) {
				findings = append(findings, findingf("%s links %s", leg.name, listed.ImportPath))
			}
		}
	}
	return findings
}

// §18.10's other pruning breaker: a reflect lookup the linker cannot read keeps every exported
// method. Each package of this repository that a leg above ships is type-checked as that leg compiles
// it, against the export data of what it imports, so a lookup counts however it is reached: called,
// held as a method value or expression and called later, promoted from an embedded field, or through
// an interface or type parameter of the same shape, in a file that need not import reflect. A file no
// such leg compiles reaches no phone or page and is not read. A leg that does not compile, or a package
// this cannot read, is a finding, since a rule that read nothing has not passed.
func (self *repository) reflectLookupFindings(t testing.TB) []string {
	t.Helper()
	legs := []*buildLeg{}
	for _, leg := range self.shippedLegs() {
		if !leg.bindsPruning() {
			continue
		}
		legs = append(legs, leg)
		if !leg.compilesOn(runtime.GOOS, runtime.GOARCH) {
			self.reportCgoOff(leg)
		}
	}
	slots := make(chan struct{}, max(self.settings.legCompileConcurrency, 1))
	findingLock := sync.Mutex{}
	// a file most legs compile is found once
	foundFindings := map[string]bool{}
	waitGroup := sync.WaitGroup{}
	for _, leg := range legs {
		waitGroup.Go(func() {
			slots <- struct{}{}
			defer func() { <-slots }()
			legFindings := self.legReflectLookupFindings(leg)
			func() {
				findingLock.Lock()
				defer findingLock.Unlock()
				for _, finding := range legFindings {
					foundFindings[finding] = true
				}
			}()
		})
	}
	waitGroup.Wait()
	return slices.Sorted(maps.Keys(foundFindings))
}

// The lookups in the leg's own packages, each type-checked as the leg compiles it. It runs off the
// test's goroutine, so what goes wrong comes back as a finding.
func (self *repository) legReflectLookupFindings(leg *buildLeg) []string {
	export := self.exportLeg(leg)
	if export.failure != "" {
		return []string{findingf("no reflect lookup was read on a leg that does not compile: %s", export.failure)}
	}
	importPathExportFiles := map[string]string{}
	for _, listed := range export.packages {
		importPathExportFiles[listed.ImportPath] = listed.Export
	}
	fileSet := token.NewFileSet()
	// one importer for the leg, which keeps each package it reads for the next
	exportImporter := importer.ForCompiler(fileSet, "gc", func(importPath string) (io.ReadCloser, error) {
		exportFile := importPathExportFiles[importPath]
		if exportFile == "" {
			return nil, fmt.Errorf("the leg compiled no export data for %s", importPath)
		}
		return os.Open(exportFile)
	})
	packageFindings := func(listed *exportedPackage) []string {
		// the cgo row allows no cgo file in a package a client leg ships
		if len(listed.CgoFiles) != 0 {
			return []string{findingf("%s: %s has cgo files, which this rule does not read", leg.name, listed.ImportPath)}
		}
		files := []*ast.File{}
		for _, goFile := range listed.GoFiles {
			syntax, err := parser.ParseFile(fileSet, filepath.Join(listed.Dir, goFile), nil, parser.SkipObjectResolution)
			if err != nil {
				return []string{findingf("%s: %v", leg.name, err)}
			}
			files = append(files, syntax)
		}
		info := &types.Info{Selections: map[*ast.SelectorExpr]*types.Selection{}}
		config := &types.Config{Importer: exportImporter, Sizes: types.SizesFor("gc", leg.goarch)}
		if _, err := config.Check(listed.ImportPath, fileSet, files, info); err != nil {
			return []string{findingf("%s: %s does not type-check: %v", leg.name, listed.ImportPath, err)}
		}
		lookupFindings := []string{}
		for selector, selection := range info.Selections {
			if selection.Kind() == types.FieldVal {
				continue
			}
			method := selection.Obj().(*types.Func)
			if isReflectLookup(method.Name(), method.Signature()) {
				position := fileSet.Position(selector.Sel.Pos())
				lookupFindings = append(lookupFindings, findingf("%s:%d: a dynamic reflect lookup, %s",
					self.displayPath(position.Filename), position.Line, method.Name()))
			}
		}
		return lookupFindings
	}
	findings := []string{}
	for _, listed := range export.packages {
		if _, ours := repositoryRelative(listed.ImportPath); ours {
			findings = append(findings, packageFindings(listed)...)
		}
	}
	return findings
}

// True for a method the linker cannot see past, whatever its receiver: by index, Method(int), or by
// name, MethodByName(string), answering a reflect.Method or reflect.Value first, which is the shape
// cmd/compile's usemethod marks on a call of any type's method (cmd/compile/internal/walk/expr.go); and
// the Methods iterators of reflect.Type and reflect.Value, which make the lookup by index inside
// (sdk/build/mobile_method_pruning_test.go:12-24). A constant name the linker could read counts as
// well: a name such as Methods keeps as much, and nothing here needs one.
func isReflectLookup(name string, signature *types.Signature) bool {
	namedIn := func(typ types.Type, packagePath string, names ...string) bool {
		named, ok := types.Unalias(typ).(*types.Named)
		if !ok || named.Obj().Pkg() == nil {
			return false
		}
		return named.Obj().Pkg().Path() == packagePath && slices.Contains(names, named.Obj().Name())
	}
	params := signature.Params()
	results := signature.Results()
	switch name {
	case "Method", "MethodByName":
		if params.Len() != 1 || (results.Len() != 1 && results.Len() != 2) {
			return false
		}
		wantKind := types.Int
		if name == "MethodByName" {
			wantKind = types.String
		}
		basic, ok := params.At(0).Type().Underlying().(*types.Basic)
		return ok && basic.Kind() == wantKind && namedIn(results.At(0).Type(), "reflect", "Method", "Value")
	case "Methods":
		if params.Len() != 0 || results.Len() != 1 {
			return false
		}
		sequence, ok := types.Unalias(results.At(0).Type()).(*types.Named)
		if !ok {
			return false
		}
		arguments := sequence.TypeArgs()
		switch {
		case namedIn(sequence, "iter", "Seq"):
			return arguments.Len() == 1 && namedIn(arguments.At(0), "reflect", "Method")
		case namedIn(sequence, "iter", "Seq2"):
			return arguments.Len() == 2 && namedIn(arguments.At(0), "reflect", "Method") &&
				namedIn(arguments.At(1), "reflect", "Value")
		}
	}
	return false
}
