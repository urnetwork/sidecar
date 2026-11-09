//go:build sidecar_check

// The barrier inventory (TEST-M0-05; R-TEST-1, D-TEST-10): every testHookBarrier and testHookSecret site
// in every module's non-test code, by name and file, in testdata/barriers.txt, generated and committed.
// A site not in the file fails until it is regenerated, which shows a reviewer each new linearization
// point and each new hooked key in the diff; a schedule's Await or Release naming a barrier no site
// holds fails here, statically, where at run time it would only be a 10 s timeout.
//
// A barrier's name is a string literal or a constant holding one, in the call's package or another of
// this repository's, as the contract for schedule authors asks; a name the inventory cannot read is a
// finding, except where a hook forwards its own parameter. A key's kind only labels what the privacy
// harness scans for, so a secret site whose kind is chosen at run time is listed as *. barrier.go's runtime pattern stays the
// check on a name's form, so this does not repeat it.
//
// Regenerate with SIDECAR_REGENERATE_BARRIERS=1 go test -tags sidecar_check -run '^TestBarrierInventoryIsCurrent$' ./check

package check

import (
	"go/ast"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The inventory, relative to the root module.
const barrierInventoryPath = "testdata/barriers.txt"

const barrierInventoryHeader = `# Every testHookBarrier and testHookSecret site in this repository's non-test code, by name and file:
# "barrier <name> <file>" and "secret <kind> <file>", sorted (TEST-M0-05). Generated: a site not here
# fails make check until this file is regenerated, so each new linearization point and hooked key shows
# in review. Regenerate with
#   SIDECAR_REGENERATE_BARRIERS=1 go test -tags sidecar_check -run '^TestBarrierInventoryIsCurrent$' ./check
`

// The names a site may be called by, and what each reports.
var barrierHookKinds = map[string]string{
	"testHookBarrier": "barrier", "TestHookBarrier": "barrier",
	"testHookSecret": "secret", "TestHookSecret": "secret",
}

// A barrier name a schedule may wait on that no hook site fires: the fault runner's own event.
var barrierScheduleBuiltins = []string{"fault.fired"}

// The runner's package. Its own tests plant toy barriers through helpers and one barrier no site fires,
// which test the runner and its timeout; every row's schedule is a builder in a non-test file of it,
// which this checks with every other step (the contract for schedule authors).
const barrierRunnerPackage = "sidecartest/fault"

// One site, or a finding where the name could not be read.
type barrierSite struct {
	kind string
	name string
	file string
}

// Each package's string constants, by package name relative to its module with the module's name in
// front, then by constant name: what a site names when it names no literal.
func (self *repository) stringConstants(t testing.TB) map[string]map[string]string {
	t.Helper()
	constants := map[string]map[string]string{}
	for _, file := range self.sourceFiles(t) {
		for _, declaration := range file.syntax.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.CONST {
				continue
			}
			for _, spec := range general.Specs {
				valueSpec := spec.(*ast.ValueSpec)
				for index, name := range valueSpec.Names {
					if index >= len(valueSpec.Values) {
						continue
					}
					literal, ok := valueSpec.Values[index].(*ast.BasicLit)
					if !ok || literal.Kind != token.STRING {
						continue
					}
					value, err := strconv.Unquote(literal.Value)
					if err != nil {
						continue
					}
					if constants[file.packageName] == nil {
						constants[file.packageName] = map[string]string{}
					}
					constants[file.packageName][name.Name] = value
				}
			}
		}
	}
	return constants
}

// The package name, as stringConstants keys it, of each of this repository's imports in a file, by the
// name the file calls it.
func (self *repository) localImportNames(file *sourceFile) map[string]string {
	imports := map[string]string{}
	for _, spec := range file.syntax.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		var packageName string
		switch {
		case importPath == self.modulePath:
			packageName = "."
		case strings.HasPrefix(importPath, self.modulePath+"/"):
			packageName = strings.TrimPrefix(importPath, self.modulePath+"/")
		default:
			continue
		}
		name := path.Base(importPath)
		if packageName == "." {
			name = "sidecar"
		}
		if spec.Name != nil {
			name = spec.Name.Name
		}
		imports[name] = packageName
	}
	return imports
}

// The string an expression names: a literal, a constant of the file's package, or another package's
// constant through its import.
func (self *repository) constantString(expression ast.Expr, file *sourceFile, constants map[string]map[string]string) (string, bool) {
	switch value := expression.(type) {
	case *ast.BasicLit:
		if value.Kind != token.STRING {
			return "", false
		}
		text, err := strconv.Unquote(value.Value)
		return text, err == nil
	case *ast.Ident:
		text, ok := constants[file.packageName][value.Name]
		return text, ok
	case *ast.SelectorExpr:
		packageIdent, ok := value.X.(*ast.Ident)
		if !ok {
			return "", false
		}
		packageName, ok := self.localImportNames(file)[packageIdent.Name]
		if !ok {
			return "", false
		}
		text, ok := constants[packageName][value.Sel.Name]
		return text, ok
	}
	return "", false
}

// Every hook site in non-test code, and a finding for each whose name the inventory cannot read.
func (self *repository) barrierSites(t testing.TB) ([]barrierSite, []string) {
	t.Helper()
	constants := self.stringConstants(t)
	sites := []barrierSite{}
	findings := []string{}
	for _, file := range self.sourceFiles(t) {
		if file.isTest {
			continue
		}
		fileName := testRuleFileKey(file)
		for _, declaration := range file.syntax.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			parameters := map[string]bool{}
			for _, field := range function.Type.Params.List {
				for _, name := range field.Names {
					parameters[name.Name] = true
				}
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok || len(call.Args) != 2 {
					return true
				}
				var hookName string
				switch function := call.Fun.(type) {
				case *ast.Ident:
					hookName = function.Name
				case *ast.SelectorExpr:
					hookName = function.Sel.Name
				}
				kind, isHook := barrierHookKinds[hookName]
				if !isHook {
					return true
				}
				name, ok := self.constantString(call.Args[0], file, constants)
				if !ok {
					if ident, isIdent := call.Args[0].(*ast.Ident); isIdent && parameters[ident.Name] {
						// a hook forwarding its own parameter, as each package's tagged half does
						return true
					}
					if kind == "secret" {
						// a key's kind only labels what the harness scans for, so a site that picks it at
						// run time is listed under * and still shows in review
						sites = append(sites, barrierSite{kind: kind, name: "*", file: fileName})
						return true
					}
					findings = append(findings, findingf("%s:%d: %s's name is no literal or constant, so no inventory or schedule can name it",
						self.displayPath(file.path), file.fileSet.Position(call.Pos()).Line, hookName))
					return true
				}
				sites = append(sites, barrierSite{kind: kind, name: name, file: fileName})
				return true
			})
		}
	}
	return sites, findings
}

// The inventory's text for sites: its header, then one sorted line per site.
func barrierInventoryText(sites []barrierSite) string {
	lines := []string{}
	for _, site := range sites {
		lines = append(lines, site.kind+" "+site.name+" "+site.file)
	}
	slices.Sort(lines)
	lines = slices.Compact(lines)
	return barrierInventoryHeader + strings.Join(lines, "\n") + "\n"
}

// Whether the committed inventory is the one this checkout generates, and what differs.
func (self *repository) barrierInventoryFindings(t testing.TB) []string {
	t.Helper()
	sites, findings := self.barrierSites(t)
	want := barrierInventoryText(sites)
	committed, err := os.ReadFile(filepath.Join(self.moduleDirectory, barrierInventoryPath))
	if err != nil {
		return append(findings, findingf("reading %s: %v; regenerate it", barrierInventoryPath, err))
	}
	have := map[string]bool{}
	for _, line := range strings.Split(string(committed), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			have[line] = true
		}
	}
	wanted := map[string]bool{}
	for _, line := range strings.Split(want, "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			wanted[line] = true
			if !have[line] {
				findings = append(findings, findingf("%s is a site %s does not list: regenerate it, which shows the new site in review", line, barrierInventoryPath))
			}
		}
	}
	for line := range have {
		if !wanted[line] {
			findings = append(findings, findingf("%s lists %s, which no site holds now: regenerate it", barrierInventoryPath, line))
		}
	}
	if len(findings) == 0 && string(committed) != want {
		findings = append(findings, findingf("%s is out of order or its header changed: regenerate it", barrierInventoryPath))
	}
	slices.Sort(findings)
	return findings
}

// The barrier names a schedule's step waits on or releases: each Await and Release in a Step literal
// or an assignment to one, with its key cut, and the names a test fires itself through a barrier
// driver's Hit, per package.
func (self *repository) scheduleBarrierFindings(t testing.TB) []string {
	t.Helper()
	sites, _ := self.barrierSites(t)
	barriers := map[string]bool{}
	for _, site := range sites {
		if site.kind == "barrier" {
			barriers[site.name] = true
		}
	}
	constants := self.stringConstants(t)
	// names each package's tests fire on their own, as a toy store's schedule does
	hits := map[string]map[string]bool{}
	type named struct {
		file *sourceFile
		name string
		line int
	}
	waits := []named{}
	for _, file := range self.sourceFiles(t) {
		siteName := func(expression ast.Expr) (string, bool) {
			if call, ok := expression.(*ast.CallExpr); ok && 1 <= len(call.Args) {
				if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "BarrierSite" {
					return self.constantString(call.Args[0], file, constants)
				}
			}
			text, ok := self.constantString(expression, file, constants)
			if !ok {
				return "", false
			}
			name, _, _ := strings.Cut(text, "@")
			return name, true
		}
		record := func(expression ast.Expr) {
			if name, ok := siteName(expression); ok && name != "" {
				waits = append(waits, named{file: file, name: name, line: file.fileSet.Position(expression.Pos()).Line})
			}
		}
		recordField := func(field string, value ast.Expr) {
			switch field {
			case "Await":
				record(value)
			case "Release":
				if list, ok := value.(*ast.CompositeLit); ok {
					for _, element := range list.Elts {
						record(element)
					}
				}
			}
		}
		ast.Inspect(file.syntax, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.CallExpr:
				// a driver's Hit, or a hook a test calls itself, fires a site of the test's own
				calledName := ""
				switch function := value.Fun.(type) {
				case *ast.SelectorExpr:
					calledName = function.Sel.Name
				case *ast.Ident:
					calledName = function.Name
				}
				_, isHook := barrierHookKinds[calledName]
				if (calledName == "Hit" || (isHook && file.isTest)) && 1 <= len(value.Args) {
					if name, ok := siteName(value.Args[0]); ok {
						if hits[file.packageName] == nil {
							hits[file.packageName] = map[string]bool{}
						}
						hits[file.packageName][name] = true
					}
				}
			case *ast.CompositeLit:
				steps := []*ast.CompositeLit{}
				if isStepType(value.Type) {
					steps = append(steps, value)
				} else if array, ok := value.Type.(*ast.ArrayType); ok && isStepType(array.Elt) {
					// a slice of steps whose elements leave their type out
					for _, element := range value.Elts {
						if unary, ok := element.(*ast.UnaryExpr); ok && unary.Op == token.AND {
							element = unary.X
						}
						if step, ok := element.(*ast.CompositeLit); ok && step.Type == nil {
							steps = append(steps, step)
						}
					}
				}
				for _, step := range steps {
					for _, element := range step.Elts {
						if keyValue, ok := element.(*ast.KeyValueExpr); ok {
							if key, ok := keyValue.Key.(*ast.Ident); ok {
								recordField(key.Name, keyValue.Value)
							}
						}
					}
				}
			case *ast.AssignStmt:
				for index, left := range value.Lhs {
					if selector, ok := left.(*ast.SelectorExpr); ok && index < len(value.Rhs) {
						if selector.Sel.Name == "Await" {
							recordField("Await", value.Rhs[index])
						}
					}
				}
			}
			return true
		})
	}
	findings := []string{}
	for _, wait := range waits {
		if barriers[wait.name] || hits[wait.file.packageName][wait.name] || slices.Contains(barrierScheduleBuiltins, wait.name) {
			continue
		}
		if wait.file.isTest && wait.file.packageName == barrierRunnerPackage {
			// the runner's own tests plant toy barriers, and one no site fires to test the timeout
			continue
		}
		findings = append(findings, findingf("%s:%d: a schedule names barrier %q, which no testHookBarrier site holds and no test of its package fires: at run time it would only time out",
			self.displayPath(wait.file.path), wait.line, wait.name))
	}
	return findings
}

// Whether a literal's type is the fault package's Step, as fault's own files and its importers name it.
func isStepType(expression ast.Expr) bool {
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name == "Step"
	case *ast.SelectorExpr:
		return value.Sel.Name == "Step"
	case *ast.StarExpr:
		return isStepType(value.X)
	}
	return false
}

// The committed inventory is this checkout's, and every site's name is one it can read; with
// SIDECAR_REGENERATE_BARRIERS=1 it writes the file instead.
func TestBarrierInventoryIsCurrent(t *testing.T) {
	repository, err := thisCheckout()
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("SIDECAR_REGENERATE_BARRIERS") == "1" {
		sites, findings := repository.barrierSites(t)
		failFindings(t, "barriers", findings)
		if err := os.WriteFile(filepath.Join(repository.moduleDirectory, barrierInventoryPath), []byte(barrierInventoryText(sites)), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s: %d sites", barrierInventoryPath, len(sites))
		return
	}
	failFindings(t, "barriers", repository.barrierInventoryFindings(t))
}

// Every schedule's Await and Release names a barrier some site holds.
func TestScheduleBarriersAllExist(t *testing.T) {
	repository, err := thisCheckout()
	if err != nil {
		t.Fatal(err)
	}
	failFindings(t, "barriers", repository.scheduleBarrierFindings(t))
}
