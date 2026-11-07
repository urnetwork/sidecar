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
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
)

// std packages that hold a binary's exported methods alive, so the linker cannot prune them
// (sdk/build/mobile_method_pruning_test.go:12-22).
var pruningBreakers = []string{"net/rpc", "text/template", "html/template"}

// D-SDK-20: the leg's closure holds neither the root package nor protocol, and §4.9 words it as
// device/ and protocol/bridge only, so nothing else of this repository either. protocol/bridge sits
// under protocol's path and is what the leg is for, which is why these are read as whole packages.
func (self *repository) iosExtensionFindings(t testing.TB) []string {
	t.Helper()
	findings := []string{}
	for _, leg := range self.legs {
		if !leg.hasTag(iosExtensionTag) {
			continue
		}
		for _, listed := range self.closure(t, leg) {
			relative, ours := repositoryRelative(listed.ImportPath)
			if ours && !underPath(relative, "device") && !underPath(relative, "protocol/bridge") {
				findings = append(findings, findingf("%s links %s", leg.name, listed.ImportPath))
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
	exportFiles := map[string]string{}
	for _, listed := range export.packages {
		exportFiles[listed.ImportPath] = listed.Export
	}
	fileSet := token.NewFileSet()
	// one importer for the leg, which keeps each package it reads for the next
	exportImporter := importer.ForCompiler(fileSet, "gc", func(importPath string) (io.ReadCloser, error) {
		exportFile := exportFiles[importPath]
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
