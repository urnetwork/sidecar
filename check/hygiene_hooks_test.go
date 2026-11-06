//go:build sidecar_check

// §4.7's hygiene row, the test hooks (§22.4): a release leg built with sidecar_testhooks. A hook in
// a release is the worst thing this row guards: testHookSecret hands every key to whatever is
// installed, and testHookBarrier can hold a protocol step. So the rule has four readings, because a
// leg can come to link a hook in four ways:
//
//   - the leg asks for the tag (the leg table, the caller's GOFLAGS, a Makefile's build line);
//   - a file compiled on a release leg answers to the tag some other way (an || constraint);
//   - a package's pair is wrong, so its untagged half is not empty, which needs no tag at all. This
//     covers every package and module, not just the root: testhook.go tells each package that needs
//     hooks to keep its own pair, and a per-package copy is where such a mistake lands;
//   - a built artifact says it was built with the tag, whatever produced it.
//
// sidecar_leaktest is held the same way: that build leaks on purpose, for §22.7's self-test.

package check

import (
	"debug/buildinfo"
	"go/ast"
	"go/build/constraint"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Tags no shipped build may carry.
var unshippableTags = []string{sidecarTestHooksTag, sidecarLeakTestTag}

// The hook pair's names, each with the signature §22.4 gives it.
var hookSignatures = map[string][2]string{
	"testHookSecret":  {"kind string", "secret []byte"},
	"testHookBarrier": {"name string", "key string"},
}

// What the hook's tagged half forwards to, in the root.
var hookEntryPoints = map[string]string{
	"testHookSecret":  "TestHookSecret",
	"testHookBarrier": "TestHookBarrier",
}

// Names that exist only under the tag, and only in the root (testhook_enabled.go).
var tagOnlyRootNames = []string{"TestHookSecret", "TestHookBarrier", "SetTestHooks", "TestHooks"}

// True when no assignment of the other tags builds the expression without tag.
func requiresTag(expression constraint.Expr, tag string) bool {
	switch typed := expression.(type) {
	case *constraint.TagExpr:
		return typed.Tag == tag
	case *constraint.AndExpr:
		return requiresTag(typed.X, tag) || requiresTag(typed.Y, tag)
	case *constraint.OrExpr:
		return requiresTag(typed.X, tag) && requiresTag(typed.Y, tag)
	}
	return false
}

// True when no assignment of the other tags builds the expression with tag.
func excludesTag(expression constraint.Expr, tag string) bool {
	switch typed := expression.(type) {
	case *constraint.NotExpr:
		inner, ok := typed.X.(*constraint.TagExpr)
		return ok && inner.Tag == tag
	case *constraint.AndExpr:
		return excludesTag(typed.X, tag) || excludesTag(typed.Y, tag)
	case *constraint.OrExpr:
		return excludesTag(typed.X, tag) && excludesTag(typed.Y, tag)
	}
	return false
}

// True when tag turns the expression on somewhere: it occurs outside a negation.
func answersToTag(expression constraint.Expr, tag string, negated bool) bool {
	switch typed := expression.(type) {
	case *constraint.TagExpr:
		return typed.Tag == tag && !negated
	case *constraint.NotExpr:
		return answersToTag(typed.X, tag, !negated)
	case *constraint.AndExpr:
		return answersToTag(typed.X, tag, negated) || answersToTag(typed.Y, tag, negated)
	case *constraint.OrExpr:
		return answersToTag(typed.X, tag, negated) || answersToTag(typed.Y, tag, negated)
	}
	return false
}

// A shipped leg asking for a tag it may not have.
func (self *repository) legTagFindings() []string {
	findings := []string{}
	for _, leg := range self.shippedLegs() {
		for _, tag := range unshippableTags {
			if leg.hasTag(tag) {
				findings = append(findings, findingf("%s is a release leg built with %s", leg.name, tag))
			}
		}
	}
	return findings
}

// The caller's GOFLAGS, which every go command here clears so a leg stays what it names. A tag in
// it is a tag on whatever else that environment builds, the release's own steps included.
func callerGoflagsFindings(goflags string) []string {
	findings := []string{}
	for _, flag := range strings.Fields(goflags) {
		flag = strings.TrimLeft(flag, "-")
		value, isTags := strings.CutPrefix(flag, "tags=")
		if !isTags {
			continue
		}
		for _, tag := range unshippableTags {
			if slices.Contains(strings.Split(value, ","), tag) {
				findings = append(findings, findingf("GOFLAGS carries %s, so a release built here is built with it", tag))
			}
		}
	}
	return findings
}

// A file a shipped leg compiles that answers to the tag. Read from the leg's own file lists, so it
// covers the root's hook file, every per-package tagged half, and a file whose constraint would let
// it in without the tag being set. Only this repository's packages can hold one.
func (self *repository) legHookFileFindings(t testing.TB) []string {
	t.Helper()
	bySourcePath := map[string]*sourceFile{}
	for _, file := range self.sourceFiles(t) {
		bySourcePath[file.path] = file
	}
	findings := []string{}
	for _, leg := range self.shippedLegs() {
		for _, listed := range self.closure(t, leg) {
			if _, ours := repositoryRelative(listed.ImportPath); !ours {
				continue
			}
			for _, goFile := range listed.GoFiles {
				file, known := bySourcePath[filepath.Join(listed.Dir, goFile)]
				if !known || file.constraint == nil {
					continue
				}
				for _, tag := range unshippableTags {
					if answersToTag(file.constraint, tag, false) {
						findings = append(findings, findingf("%s links %s in %s, which answers to %s", leg.name, goFile, listed.ImportPath, tag))
					}
				}
			}
		}
	}
	return findings
}

// The parameters of a function declaration, as "name type" strings.
func parameterTexts(fields *ast.FieldList) []string {
	texts := []string{}
	if fields == nil {
		return texts
	}
	for _, field := range fields.List {
		typeText := ""
		switch typed := field.Type.(type) {
		case *ast.Ident:
			typeText = typed.Name
		case *ast.ArrayType:
			if element, ok := typed.Elt.(*ast.Ident); ok && typed.Len == nil {
				typeText = "[]" + element.Name
			}
		}
		for _, name := range field.Names {
			texts = append(texts, name.Name+" "+typeText)
		}
	}
	return texts
}

// One half of a package's pair: where it is and how it builds.
type hookDeclaration struct {
	file *sourceFile
	decl *ast.FuncDecl
}

// The import name the file gives the root package, or "".
func rootImportName(file *sourceFile) string {
	for _, spec := range file.syntax.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		if relative, ours := repositoryRelative(importPath); !ours || relative != "." {
			continue
		}
		if spec.Name != nil {
			return spec.Name.Name
		}
		return "sidecar"
	}
	return ""
}

// True when the function's whole body is one call of rootName.entry(firstParameter, secondParameter).
func forwardsTo(decl *ast.FuncDecl, rootName string, entry string, parameters []string) bool {
	if rootName == "" || decl.Body == nil || len(decl.Body.List) != 1 {
		return false
	}
	statement, ok := decl.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := statement.X.(*ast.CallExpr)
	if !ok || len(call.Args) != len(parameters) {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != entry {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok || receiver.Name != rootName {
		return false
	}
	for index, argument := range call.Args {
		name, ok := argument.(*ast.Ident)
		if !ok || name.Name != strings.Fields(parameters[index])[0] {
			return false
		}
	}
	return true
}

// Every package's pair, in every module, by reading all its non-test files. This is the only reading
// that needs no leg: a pair that is wrong is wrong in every build, and the package need not yet be
// linked by anything for the mistake to be waiting.
func (self *repository) hookPairFindings(t testing.TB) []string {
	t.Helper()
	findings := []string{}
	type packageHooks struct {
		tagged   map[string]hookDeclaration
		untagged map[string]hookDeclaration
	}
	packages := map[string]*packageHooks{}
	hooksOf := func(packageName string) *packageHooks {
		hooks, ok := packages[packageName]
		if !ok {
			hooks = &packageHooks{tagged: map[string]hookDeclaration{}, untagged: map[string]hookDeclaration{}}
			packages[packageName] = hooks
		}
		return hooks
	}
	for _, file := range self.sourceFiles(t) {
		if file.isTest {
			continue
		}
		display := self.displayPath(file.path)
		for _, decl := range file.syntax.Decls {
			switch typed := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range typed.Specs {
					names := []string{}
					switch specTyped := spec.(type) {
					case *ast.ValueSpec:
						for _, name := range specTyped.Names {
							names = append(names, name.Name)
						}
					case *ast.TypeSpec:
						names = append(names, specTyped.Name.Name)
					}
					for _, name := range names {
						if _, hook := hookSignatures[name]; hook {
							findings = append(findings, findingf("%s: %s is not a function, so it can hold something in a release build", display, name))
						}
						if slices.Contains(tagOnlyRootNames, name) && !(file.packageName == "." && file.tagOnly(sidecarTestHooksTag)) {
							findings = append(findings, findingf("%s: %s exists outside the root's tagged file", display, name))
						}
					}
				}
			case *ast.FuncDecl:
				if typed.Recv != nil {
					continue
				}
				name := typed.Name.Name
				if slices.Contains(tagOnlyRootNames, name) && !(file.packageName == "." && file.tagOnly(sidecarTestHooksTag)) {
					findings = append(findings, findingf("%s: %s exists outside the root's tagged file", display, name))
				}
				signature, hook := hookSignatures[name]
				if !hook {
					continue
				}
				parameters := parameterTexts(typed.Type.Params)
				if !slices.Equal(parameters, signature[:]) || typed.Type.Results != nil {
					findings = append(findings, findingf("%s: %s(%s) is not §22.4's signature", display, name, strings.Join(parameters, ", ")))
				}
				hooks := hooksOf(file.packageName)
				switch {
				case file.tagOnly(sidecarTestHooksTag):
					hooks.tagged[name] = hookDeclaration{file: file, decl: typed}
				case file.constraint != nil && excludesTag(file.constraint, sidecarTestHooksTag):
					hooks.untagged[name] = hookDeclaration{file: file, decl: typed}
				default:
					findings = append(findings, findingf("%s: %s builds with and without %s, so its body reaches a release", display, name, sidecarTestHooksTag))
				}
			}
		}
	}
	for packageName, hooks := range packages {
		for name, signature := range hookSignatures {
			untagged, hasUntagged := hooks.untagged[name]
			tagged, hasTagged := hooks.tagged[name]
			if !hasUntagged {
				findings = append(findings, findingf("%s keeps %s with no empty half under !%s", packageName, name, sidecarTestHooksTag))
			} else if len(untagged.decl.Body.List) != 0 {
				findings = append(findings, findingf("%s: %s has a body in the untagged build", self.displayPath(untagged.file.path), name))
			}
			if !hasTagged {
				findings = append(findings, findingf("%s keeps %s with no half under %s", packageName, name, sidecarTestHooksTag))
				continue
			}
			if packageName != "." && !forwardsTo(tagged.decl, rootImportName(tagged.file), hookEntryPoints[name], signature[:]) {
				findings = append(findings, findingf("%s: %s does not forward to the root's %s, as testhook.go has a package do", self.displayPath(tagged.file.path), name, hookEntryPoints[name]))
			}
		}
	}
	slices.Sort(findings)
	return findings
}

// A go test command, however the Makefile spells go.
var goTestCommandPattern = regexp.MustCompile(`(^|[^[:alnum:]_/-])(go|lowgo|\$\(GO\))\s+test\b`)

// A Makefile line carrying an unshippable tag that is not a go test line: go test is how the hooks
// are exercised, and anything else, a go build or a GOFLAGS export, makes something that can ship.
func (self *repository) makefileTagFindings(t testing.TB) []string {
	t.Helper()
	makefiles, err := filepath.Glob(filepath.Join(self.topDirectory, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	for _, module := range self.modules(t) {
		for _, pattern := range []string{"Makefile", "*/Makefile"} {
			matches, err := filepath.Glob(filepath.Join(module.directory, pattern))
			if err != nil {
				t.Fatal(err)
			}
			makefiles = append(makefiles, matches...)
		}
	}
	slices.Sort(makefiles)
	makefiles = slices.Compact(makefiles)
	findings := []string{}
	for _, makefile := range makefiles {
		data, err := os.ReadFile(makefile)
		if err != nil {
			t.Fatal(err)
		}
		for index, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") || goTestCommandPattern.MatchString(line) {
				continue
			}
			for _, tag := range unshippableTags {
				if strings.Contains(line, tag) {
					findings = append(findings, findingf("%s:%d: builds with %s", self.displayPath(makefile), index+1, tag))
				}
			}
		}
	}
	return findings
}

// What a built binary's own build info says, read with debug/buildinfo, which survives -s and -w.
// The rules above read how a leg is meant to be built; this reads how an artifact was.
func releaseBinaryFindings(binaryPath string) []string {
	info, err := buildinfo.ReadFile(binaryPath)
	if err != nil {
		return []string{findingf("%s: %v", binaryPath, err)}
	}
	findings := []string{}
	for _, setting := range info.Settings {
		if setting.Key != "-tags" {
			continue
		}
		for _, tag := range unshippableTags {
			if slices.Contains(strings.Split(setting.Value, ","), tag) {
				findings = append(findings, findingf("%s was built with %s", binaryPath, tag))
			}
		}
	}
	return findings
}
