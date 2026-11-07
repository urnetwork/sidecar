//go:build sidecar_check

// §4.7's hygiene row, the test hooks (§22.4): a release leg built with sidecar_testhooks. A hook in
// a release is the worst thing this row guards: testHookSecret hands every key to whatever is
// installed, and testHookBarrier can hold a protocol step. So the rule has four readings, because a
// leg can come to link a hook in four ways:
//
//   - the leg asks for the tag (the leg table, the host's GOFLAGS in the variable or a go env file,
//     a Makefile's build line);
//   - a file compiled on a release leg answers to the tag some other way (an || constraint);
//   - a package's pair is wrong, so its untagged half is not empty, which needs no tag at all. This
//     covers every package and module, not just the root: testhook.go tells each package that needs
//     hooks to keep its own pair, and a per-package copy is where such a mistake lands;
//   - a built artifact says it was built with the tag, whatever produced it.
//
// sidecar_leaktest is held the same way: that build leaks on purpose, for §22.7's self-test.

package check

import (
	"bytes"
	"debug/buildinfo"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/token"
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

// device/ may not import the root even under the tag (§4.4, D-SDK-20), so it is the one package whose
// tagged half forwards to nothing, and its tagged file holds an installer of its own: these two names
// and no others.
const deviceHooksPackage = "device"

var deviceInstallerNames = []string{"SetTestHooks", "TestHooks"}

// True for the file that may declare name, one of tagOnlyRootNames.
func (self *sourceFile) holdsEntryPoint(name string) bool {
	if !self.tagOnly(sidecarTestHooksTag) {
		return false
	}
	return self.packageName == "." || (self.packageName == deviceHooksPackage && slices.Contains(deviceInstallerNames, name))
}

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

// A tag in one place's GOFLAGS, read as whole words, because GOFLAGS may quote a -tags value.
func goflagsTagFindings(place string, goflags string) []string {
	findings := []string{}
	for _, tag := range unshippableTags {
		word := regexp.MustCompile(`(^|[^a-z0-9_])` + tag + `($|[^a-z0-9_])`)
		if word.MatchString(goflags) {
			findings = append(findings, findingf("GOFLAGS in %s carries %s, so a release built here is built with it", place, tag))
		}
	}
	return findings
}

// One place the go command takes GOFLAGS from, and what it holds there.
type goflagsSource struct {
	place   string
	goflags string
}

// Every place a go command on this host takes GOFLAGS from, each read by the go command itself in
// the caller's environment. The go command reads the variable, then while that is empty the go env
// file GOENV names, which go env -w writes, then while that holds none GOROOT's go.env. Every go
// command the rules run sets the variable, which hides both files from them, and a release step on
// this host need not run as make check does: it may leave the variable unset where lowgo sets it, or
// GOENV at its default. So each place is read on its own, the default go env file too when this
// environment moves GOENV, and a tag in any of them reaches some build here.
func hostGoflagsSources(directory string, environment []string) ([]goflagsSource, error) {
	variable := func(key string) string {
		value := ""
		for _, entry := range environment {
			if name, entryValue, found := strings.Cut(entry, "="); found && name == key {
				value = entryValue
			}
		}
		return value
	}
	// GOFLAGS with its variable empty, the go env file and GOROOT, as the go command reads them with
	// the overrides on top of the caller's environment
	read := func(overrides ...string) (goflags string, envFile string, goroot string, err error) {
		readEnvironment := append(slices.Clone(environment), "GOTOOLCHAIN=local", "GOFLAGS=")
		output, err := runGo(directory, append(readEnvironment, overrides...), "env", "GOFLAGS", "GOENV", "GOROOT")
		if err != nil {
			return "", "", "", err
		}
		lines := strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
		if len(lines) != 3 {
			return "", "", "", fmt.Errorf("go env GOFLAGS GOENV GOROOT printed %q", output)
		}
		return lines[0], lines[1], lines[2], nil
	}
	sources := []goflagsSource{{place: "the environment", goflags: variable("GOFLAGS")}}
	rootGoflags, _, goroot, err := read("GOENV=off")
	if err != nil {
		return nil, err
	}
	sources = append(sources, goflagsSource{place: filepath.Join(goroot, "go.env"), goflags: rootGoflags})
	userOverrides := [][]string{nil}
	if variable("GOENV") != "" {
		userOverrides = append(userOverrides, []string{"GOENV="})
	}
	for _, overrides := range userOverrides {
		goflags, envFile, _, err := read(overrides...)
		if err != nil {
			return nil, err
		}
		// a file holding no GOFLAGS reads as GOROOT's, which is already here
		if envFile != "off" && goflags != rootGoflags {
			sources = append(sources, goflagsSource{place: "the go env file " + envFile, goflags: goflags})
		}
	}
	return sources, nil
}

// An unshippable tag in any place a go command on this host takes GOFLAGS from.
func (self *repository) hostGoflagsFindings(environment []string) []string {
	sources, err := hostGoflagsSources(self.moduleDirectory, environment)
	if err != nil {
		return []string{findingf("reading where this host's go command takes GOFLAGS from: %v", err)}
	}
	findings := []string{}
	for _, source := range sources {
		findings = append(findings, goflagsTagFindings(source.place, source.goflags)...)
	}
	return findings
}

// A file a shipped leg compiles that answers to the tag. Read from the leg's own file lists, so it
// covers the root's hook file, every per-package tagged half, and a file whose constraint would let
// it in without the tag being set. Only this repository's packages can hold one. A cgo file is
// listed apart from the others, and compiled all the same.
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
			findings = append(findings, self.linkedFileFindings(t, leg.name, listed, bySourcePath)...)
		}
	}
	return findings
}

// One package of ours a leg links, file by file, against what the source walks read. A module of
// this repository that the leg takes at a tag comes from the module cache, as the root and smtpproof
// do for cli and mlsinterop on a release branch once sidecar_cli_release_edit drops their replaces.
// The tag holds this checkout's tree (run.sh's sidecar_release_publish proves it), so such a file is
// read as its checkout twin, and held to that twin's bytes.
func (self *repository) linkedFileFindings(t testing.TB, legName string, listed *listedPackage, bySourcePath map[string]*sourceFile) []string {
	t.Helper()
	directory := listed.Dir
	fromCache := false
	if listed.Module != nil && listed.Module.Dir != "" {
		for _, module := range self.modules(t) {
			if module.basePath != firstPartyBase(listed.Module.Path) || module.directory == listed.Module.Dir {
				continue
			}
			relative, err := filepath.Rel(listed.Module.Dir, listed.Dir)
			if err != nil || !filepath.IsLocal(relative) {
				return []string{findingf("%s links %s from %s, which is outside its module at %s", legName, listed.ImportPath, listed.Dir, listed.Module.Dir)}
			}
			directory = filepath.Join(module.directory, relative)
			fromCache = true
		}
	}
	findings := []string{}
	for _, goFile := range slices.Concat(listed.GoFiles, listed.CgoFiles) {
		file, known := bySourcePath[filepath.Join(directory, goFile)]
		if !known {
			// the walks skip testdata and the documents, but an import does not
			findings = append(findings, findingf("%s links %s in %s, which no source rule read", legName, goFile, listed.ImportPath))
			continue
		}
		if fromCache {
			linked, linkedErr := os.ReadFile(filepath.Join(listed.Dir, goFile))
			checkedOut, checkedOutErr := os.ReadFile(file.path)
			if linkedErr != nil || checkedOutErr != nil || !bytes.Equal(linked, checkedOut) {
				findings = append(findings, findingf("%s links %s in %s from %s, which is not this checkout's %s", legName, goFile, listed.ImportPath, listed.Dir, self.displayPath(file.path)))
				continue
			}
		}
		if file.constraint == nil {
			continue
		}
		for _, tag := range unshippableTags {
			if answersToTag(file.constraint, tag, false) {
				findings = append(findings, findingf("%s links %s in %s, which answers to %s", legName, goFile, listed.ImportPath, tag))
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
	// every declaration of each half: a package may split one by system, and each is then some
	// system's build, so holding only the last one read would leave the others unread
	type packageHooks struct {
		tagged   map[string][]hookDeclaration
		untagged map[string][]hookDeclaration
	}
	packages := map[string]*packageHooks{}
	hooksOf := func(packageName string) *packageHooks {
		hooks, ok := packages[packageName]
		if !ok {
			hooks = &packageHooks{tagged: map[string][]hookDeclaration{}, untagged: map[string][]hookDeclaration{}}
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
						if slices.Contains(tagOnlyRootNames, name) && !file.holdsEntryPoint(name) {
							findings = append(findings, findingf("%s: %s exists outside the root's tagged file", display, name))
						}
					}
				}
			case *ast.FuncDecl:
				name := typed.Name.Name
				if slices.Contains(tagOnlyRootNames, name) && !file.holdsEntryPoint(name) {
					findings = append(findings, findingf("%s: %s exists outside the root's tagged file", display, name))
				}
				signature, hook := hookSignatures[name]
				if !hook {
					continue
				}
				if typed.Recv != nil {
					findings = append(findings, findingf("%s: %s is a method, so no pair holds it empty in a release build", display, name))
					continue
				}
				parameters := parameterTexts(typed.Type.Params)
				if !slices.Equal(parameters, signature[:]) || typed.Type.Results != nil {
					findings = append(findings, findingf("%s: %s(%s) is not §22.4's signature", display, name, strings.Join(parameters, ", ")))
				}
				hooks := hooksOf(file.packageName)
				switch {
				case file.tagOnly(sidecarTestHooksTag):
					hooks.tagged[name] = append(hooks.tagged[name], hookDeclaration{file: file, decl: typed})
				case file.constraint != nil && excludesTag(file.constraint, sidecarTestHooksTag):
					hooks.untagged[name] = append(hooks.untagged[name], hookDeclaration{file: file, decl: typed})
				default:
					findings = append(findings, findingf("%s: %s builds with and without %s, so its body reaches a release", display, name, sidecarTestHooksTag))
				}
			}
		}
		findings = append(findings, innerHookNameFindings(file.syntax, display)...)
	}
	for packageName, hooks := range packages {
		for name, signature := range hookSignatures {
			if len(hooks.untagged[name]) == 0 {
				findings = append(findings, findingf("%s keeps %s with no empty half under !%s", packageName, name, sidecarTestHooksTag))
			}
			for _, untagged := range hooks.untagged[name] {
				// no body at all is not empty: go:linkname or assembly decides what it runs
				if untagged.decl.Body == nil {
					findings = append(findings, findingf("%s: %s has no body of its own in the untagged build", self.displayPath(untagged.file.path), name))
				} else if len(untagged.decl.Body.List) != 0 {
					findings = append(findings, findingf("%s: %s has a body in the untagged build", self.displayPath(untagged.file.path), name))
				}
			}
			if len(hooks.tagged[name]) == 0 {
				findings = append(findings, findingf("%s keeps %s with no half under %s", packageName, name, sidecarTestHooksTag))
			}
			for _, tagged := range hooks.tagged[name] {
				if packageName != "." && packageName != deviceHooksPackage && !forwardsTo(tagged.decl, rootImportName(tagged.file), hookEntryPoints[name], signature[:]) {
					findings = append(findings, findingf("%s: %s does not forward to the root's %s, as testhook.go has a package do", self.displayPath(tagged.file.path), name, hookEntryPoints[name]))
				}
			}
		}
	}
	slices.Sort(findings)
	return findings
}

// A hook's name declared anywhere below a file's top level: a struct or interface field, a parameter
// or result, or a local. Each holds what any code of the package may set, in a release too, and a
// call through it reaches no pair, so a hook's name belongs to the package's functions alone. The
// top level is hookPairFindings' own.
func innerHookNameFindings(syntax *ast.File, display string) []string {
	findings := []string{}
	topLevelSpecs := map[ast.Spec]bool{}
	for _, decl := range syntax.Decls {
		if genDecl, ok := decl.(*ast.GenDecl); ok {
			for _, spec := range genDecl.Specs {
				topLevelSpecs[spec] = true
			}
		}
	}
	isHookName := func(expression ast.Expr) (string, bool) {
		identifier, ok := expression.(*ast.Ident)
		if !ok {
			return "", false
		}
		_, hook := hookSignatures[identifier.Name]
		return identifier.Name, hook
	}
	local := func(expressions ...ast.Expr) {
		for _, expression := range expressions {
			if name, hook := isHookName(expression); hook {
				findings = append(findings, findingf("%s: %s is a local variable, so it can hold something in a release build", display, name))
			}
		}
	}
	ast.Inspect(syntax, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.Field:
			for _, name := range typed.Names {
				if _, hook := hookSignatures[name.Name]; hook {
					findings = append(findings, findingf("%s: %s is a field or parameter, so it can hold something in a release build", display, name.Name))
				}
			}
		case *ast.AssignStmt:
			if typed.Tok == token.DEFINE {
				local(typed.Lhs...)
			}
		case *ast.RangeStmt:
			if typed.Tok == token.DEFINE {
				local(typed.Key, typed.Value)
			}
		case *ast.ValueSpec:
			if !topLevelSpecs[typed] {
				for _, name := range typed.Names {
					local(name)
				}
			}
		}
		return true
	})
	return findings
}

// A go test command, however the Makefile spells go.
var goTestCommandPattern = regexp.MustCompile(`(^|[^[:alnum:]_/-])(go|lowgo|\$\(GO\))\s+test\b`)

// What ends one shell command on a Makefile line.
var shellCommandEndPattern = regexp.MustCompile(`&&|\|\||[;|]`)

// A shell command on a Makefile line carrying an unshippable tag that is not go test: go test is how
// the hooks are exercised, and anything else, a go build or a GOFLAGS export, makes something that
// can ship. Read per command, because go test excuses only itself, not a build beside it.
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
	findings := []string{}
	// what ships is also built outside this repository: sdk's gomobile, c-shared and wasm legs, and
	// the engines in each of server's services
	for _, makefile := range []string{"sdk/build/Makefile", "sdk/cgo/Makefile", "sdk/js/Makefile"} {
		makefiles = append(makefiles, self.siblingPath(makefile))
	}
	serverMakefiles, err := filepath.Glob(filepath.Join(self.siblingPath("server/cli"), "*", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	if len(serverMakefiles) == 0 {
		findings = append(findings, "no Makefile under server/cli, so nothing shows how the engines are built")
	}
	makefiles = append(makefiles, serverMakefiles...)
	slices.Sort(makefiles)
	makefiles = slices.Compact(makefiles)
	for _, makefile := range makefiles {
		data, err := os.ReadFile(makefile)
		if err != nil {
			findings = append(findings, findingf("reading a release build's Makefile: %v", err))
			continue
		}
		for index, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			for _, command := range shellCommandEndPattern.Split(line, -1) {
				if goTestCommandPattern.MatchString(command) {
					continue
				}
				for _, tag := range unshippableTags {
					if strings.Contains(command, tag) {
						findings = append(findings, findingf("%s:%d: builds with %s", self.displayPath(makefile), index+1, tag))
					}
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
