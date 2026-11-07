//go:build sidecar_check

// §4.7's legs row: what the ios_extension and sidecar_http legs must leave out, and §18.10's pruning
// rule on every leg that reaches a phone or a page.

package check

import (
	"go/ast"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
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

// reflect's methods that keep every exported method: Method by index, MethodByName with a name the
// linker cannot read, and the Methods iterators, which call Method for each index
// (sdk/build/mobile_method_pruning_test.go:12-24).
var reflectLookupNames = []string{"Method", "MethodByName", "Methods"}

// §18.10's other pruning breaker: a reflect lookup the linker cannot read keeps every exported
// method. Read off the syntax of the packages the legs above ship, which is exact enough: only a
// file that imports reflect can make one. A call of one of reflectLookupNames counts, and so does a
// method expression such as reflect.Value.MethodByName, which can be called later. A method value
// held and called later is past what syntax tells from a field of the same name.
func (self *repository) reflectLookupFindings(t testing.TB) []string {
	t.Helper()
	findings := []string{}
	for _, file := range self.boundFiles(t) {
		first, _, _ := strings.Cut(file.packageName, "/")
		if file.isTest || strings.HasSuffix(filepath.Base(file.path), ".pb.go") {
			continue
		}
		if file.packageName != "." && first != "protocol" && first != "device" {
			continue
		}
		// the name the file gives reflect, "." for a dot import
		reflectName := ""
		for _, spec := range file.syntax.Imports {
			if importPath, err := strconv.Unquote(spec.Path.Value); err == nil && importPath == "reflect" {
				reflectName = "reflect"
				if spec.Name != nil {
					reflectName = spec.Name.Name
				}
			}
		}
		if reflectName == "" || reflectName == "_" {
			continue
		}
		// reflect.Value or reflect.Type, as a method expression's receiver spells it
		var namesReflectType func(expression ast.Expr) bool
		namesReflectType = func(expression ast.Expr) bool {
			switch typed := expression.(type) {
			case *ast.ParenExpr:
				return namesReflectType(typed.X)
			case *ast.StarExpr:
				return namesReflectType(typed.X)
			case *ast.SelectorExpr:
				packageName, ok := typed.X.(*ast.Ident)
				return ok && packageName.Name == reflectName && (typed.Sel.Name == "Value" || typed.Sel.Name == "Type")
			case *ast.Ident:
				return reflectName == "." && (typed.Name == "Value" || typed.Name == "Type")
			}
			return false
		}
		calledSelectors := map[*ast.SelectorExpr]bool{}
		ast.Inspect(file.syntax, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok {
				if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
					calledSelectors[selector] = true
				}
			}
			return true
		})
		ast.Inspect(file.syntax, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok || !slices.Contains(reflectLookupNames, selector.Sel.Name) {
				return true
			}
			if calledSelectors[selector] || namesReflectType(selector.X) {
				position := file.fileSet.Position(selector.Sel.Pos())
				findings = append(findings, findingf("%s:%d: a dynamic reflect lookup, %s", self.displayPath(file.path), position.Line, selector.Sel.Name))
			}
			return true
		})
	}
	return findings
}
