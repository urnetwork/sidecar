//go:build sidecar_check

// §22.4's clock rule (D-TEST-10, R-TEST-1; plan-TEST-clock-seam): a non-test file in the root, an
// engine (a <svc>service and its children), mcp/ or device/ reads time only through a Clock, so a
// schedule moves every clock the fault program needs and no test sleeps. A reference to time's clock
// is a finding wherever it sits: called, or passed as a value, as `now = time.Now` would hand the
// wall clock on, in a file under any build constraint. Each exception is listed in the settings with
// the day it was granted and why, id.go's ULID first, and one that matches nothing any more fails
// too, so the list only shrinks.

package check

import (
	"go/ast"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// time's functions that read the wall clock or wait on it.
var wallClockFunctionNames = map[string]bool{
	"Now": true, "Since": true, "Until": true, "After": true, "AfterFunc": true,
	"NewTimer": true, "NewTicker": true, "Tick": true, "Sleep": true,
}

// One listed exception: a file of a bound package and the time function it may reference.
type wallClockException struct {
	// the day it was granted, yyyy-mm-dd
	since string
	why   string
}

// Whether the rule binds a package, by its name relative to its module with the module's name in
// front: the root, an engine and its children, mcp and device. A nested module's packages are cli/,
// smtpproof/ and mlsinterop/'s, which it does not bind.
func wallClockPackage(packageName string) bool {
	first, _, _ := strings.Cut(packageName, "/")
	return packageName == "." || first == "mcp" || first == "device" || strings.HasSuffix(first, "service")
}

// The key an exception is listed under: the file's name in its package, the root's files bare, then
// the time function, as "id.go time.Now". It reads the same on a release branch.
func wallClockExceptionKey(packageName string, fileName string, functionName string) string {
	if packageName != "." {
		fileName = path.Join(packageName, fileName)
	}
	return fileName + " time." + functionName
}

// Each reference to time's clock in a file the rule binds, with its key.
type wallClockReference struct {
	key  string
	site string
}

func (self *repository) wallClockReferences(t testing.TB) []wallClockReference {
	t.Helper()
	references := []wallClockReference{}
	for _, file := range self.sourceFiles(t) {
		if file.isTest || !wallClockPackage(file.packageName) {
			continue
		}
		// the name time is imported under in this file, aliases included
		timeNames := map[string]bool{}
		for _, spec := range file.syntax.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil || importPath != "time" {
				continue
			}
			name := "time"
			if spec.Name != nil {
				name = spec.Name.Name
			}
			timeNames[name] = true
		}
		if len(timeNames) == 0 {
			continue
		}
		ast.Inspect(file.syntax, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok || !wallClockFunctionNames[selector.Sel.Name] {
				return true
			}
			packageIdent, ok := selector.X.(*ast.Ident)
			if !ok || !timeNames[packageIdent.Name] {
				return true
			}
			references = append(references, wallClockReference{
				key:  wallClockExceptionKey(file.packageName, filepath.Base(file.path), selector.Sel.Name),
				site: findingf("%s:%d", self.displayPath(file.path), file.fileSet.Position(selector.Pos()).Line),
			})
			return true
		})
	}
	return references
}

// A reference to time's clock that no exception lists.
func (self *repository) wallClockFindings(t testing.TB) []string {
	t.Helper()
	findings := []string{}
	for _, reference := range self.wallClockReferences(t) {
		if _, listed := self.settings.wallClockExceptions[reference.key]; listed {
			continue
		}
		name := reference.key[strings.LastIndex(reference.key, " ")+1:]
		findings = append(findings, findingf("%s: %s reads the wall clock; read a sidecar.Clock (ServiceHost.Clock, SidecarSettings.Clock) instead", reference.site, name))
	}
	return findings
}

// Each listed exception still matches a reference in this checkout, so the list only shrinks.
func TestWallClockExceptionsAllStillMatch(t *testing.T) {
	repository := openThisCheckout(t)
	matched := map[string]bool{}
	for _, reference := range repository.wallClockReferences(t) {
		matched[reference.key] = true
	}
	keys := []string{}
	for key := range repository.settings.wallClockExceptions {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		exception := repository.settings.wallClockExceptions[key]
		if !matched[key] {
			t.Errorf("the clock rule's exception %q (since %s) matches nothing: remove it", key, exception.since)
		}
		if exception.since == "" || exception.why == "" {
			t.Errorf("the clock rule's exception %q has no date or no reason", key)
		}
	}
}
