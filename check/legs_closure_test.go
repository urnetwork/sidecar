//go:build sidecar_check && sidecar_size

// The ios_extension leg's list, computed, never hand-picked (DESIGN-DETAILS 4.2.3; REPO-M4-01). The root's files are not
// layered, so the forwarding role's entry points need far more than their own files to compile, and the list is their
// file closure: from the seeds, each extension leg compiles the root and protocol with every other root and protocol
// file replaced by an empty one through -overlay, and the file declaring each undefined name joins, round after round,
// until the leg compiles. Two kinds of file join besides. One outside the closure whose init function, or whose package
// variable's initializer, reaches the closure's own functions or variables: leaving it out would change what the
// closure does with no compile error, and the config rule table registers by init. And one that declares nothing, a
// package's doc.go, which costs nothing. The two legs' closures make one list.
//
// This compiles the leg once a round and needs Xcode for the iOS one, so it runs beside make size, not in make check,
// which holds the list as written (legrows_test.go). Without the variable it compares the list with the closure: a file
// the closure needs and the list lacks fails, and one the list names past the closure is logged, the list being free to
// shrink. With it, it rewrites the list, whose diff then shows each file the commit adds or drops:
//
//	SIDECAR_REGENERATE_IOS_EXTENSION_LEG=1 make ios-extension-leg

package check

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The seeds until BRIDGE-M8-05 lands the Forwarder: the files DESIGN-DETAILS 4.7's REPO-M4-01 names, which hold the
// entry points 4.2.3 measured (the rows-only ConfigLog, sealed bodies and the head, the ACL state, gkm's deliveries,
// wraps and ladder, evs head reads, SidecarApi's token path and the poll).
var iosExtensionLegInterimSeeds = []string{
	"acl_eval.go", "acl_state.go", "api_client.go", "api_routes_core.go", "config_head.go", "config_rows_only.go",
	"config_seal.go", "evs_read.go", "gkm_api.go", "gkm_delivery.go", "gkm_keys.go", "push_poll.go",
}

// The list's header, which a rewrite writes above its sorted names.
const iosExtensionLegListHeader = `# The root and protocol files the ios_extension legs may link, by path from the root module, sorted: the
# forwarding role's file closure (D-SDK-20; DESIGN-DETAILS 4.2.3; REPO-M4-01). make check fails a root or protocol
# file either extension leg compiles that this list does not name; every other root file carries
# //go:build !ios_extension, and protocol/Makefile writes that tag on each generated file this list does not name.
# The list may shrink freely and grows only in a commit that edits it. It is computed, never hand-picked:
#   make ios-extension-leg                                         compares it with the closure
#   SIDECAR_REGENERATE_IOS_EXTENSION_LEG=1 make ios-extension-leg  rewrites it
`

// The closure's seeds among the root files a leg compiles: the Forwarder's and the compiler's once bridge_forward*.go
// exists, else the interim seeds.
func iosExtensionLegSeeds(rootFiles []string) []string {
	seeds := []string{}
	for _, rootFile := range rootFiles {
		compiler := strings.HasPrefix(rootFile, "bridge_compile") && !strings.HasSuffix(rootFile, "_test.go")
		if isForwardingEntryFile(rootFile) || compiler {
			seeds = append(seeds, rootFile)
		}
	}
	if !slices.ContainsFunc(seeds, isForwardingEntryFile) {
		return slices.Clone(iosExtensionLegInterimSeeds)
	}
	return seeds
}

// One file the closure may take: a root or protocol file the leg compiles once the ios_extension tag no longer
// leaves it out.
type closureFile struct {
	// as the list names it
	name string
	path string
	// "." or "protocol"
	packageName string
	clauseName  string
	syntax      *ast.File
}

// What a closure reads of its candidates, by package.
type closureDeclarations struct {
	// the files declaring each top-level name
	nameFiles map[string]map[string][]string
	// the files declaring each method, by its receiver's type name
	methodFiles map[string]map[string]map[string][]string
	// the top-level functions and variables, through which an init function reaches the closure's state
	values map[string]map[string]bool
}

// The receiver's type name, generic arguments and pointer aside.
func receiverTypeName(expression ast.Expr) string {
	if star, ok := expression.(*ast.StarExpr); ok {
		expression = star.X
	}
	switch typed := expression.(type) {
	case *ast.IndexExpr:
		expression = typed.X
	case *ast.IndexListExpr:
		expression = typed.X
	}
	if ident, ok := expression.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

// Indexes what each candidate declares.
func readClosureDeclarations(files map[string]*closureFile) *closureDeclarations {
	declarations := &closureDeclarations{
		nameFiles:   map[string]map[string][]string{".": {}, "protocol": {}},
		methodFiles: map[string]map[string]map[string][]string{".": {}, "protocol": {}},
		values:      map[string]map[string]bool{".": {}, "protocol": {}},
	}
	for _, name := range slices.Sorted(maps.Keys(files)) {
		file := files[name]
		packageName := file.packageName
		for _, decl := range file.syntax.Decls {
			switch typed := decl.(type) {
			case *ast.FuncDecl:
				if typed.Recv == nil {
					declarations.nameFiles[packageName][typed.Name.Name] = append(declarations.nameFiles[packageName][typed.Name.Name], name)
					declarations.values[packageName][typed.Name.Name] = true
					continue
				}
				typeName := receiverTypeName(typed.Recv.List[0].Type)
				if typeName == "" {
					continue
				}
				if declarations.methodFiles[packageName][typeName] == nil {
					declarations.methodFiles[packageName][typeName] = map[string][]string{}
				}
				declarations.methodFiles[packageName][typeName][typed.Name.Name] = append(declarations.methodFiles[packageName][typeName][typed.Name.Name], name)
			case *ast.GenDecl:
				for _, spec := range typed.Specs {
					switch specTyped := spec.(type) {
					case *ast.TypeSpec:
						declarations.nameFiles[packageName][specTyped.Name.Name] = append(declarations.nameFiles[packageName][specTyped.Name.Name], name)
					case *ast.ValueSpec:
						for _, ident := range specTyped.Names {
							if ident.Name == "_" {
								continue
							}
							declarations.nameFiles[packageName][ident.Name] = append(declarations.nameFiles[packageName][ident.Name], name)
							if typed.Tok == token.VAR {
								declarations.values[packageName][ident.Name] = true
							}
						}
					}
				}
			}
		}
	}
	return declarations
}

// A compiler error, as the go command prints one.
var closureErrorPattern = regexp.MustCompile(`^(\S+\.go):\d+:\d+: (.*)$`)

// What an error names that a stubbed file declares: a name, maybe qualified by the package it is looked up in; a
// method or field on a type, maybe qualified the same way; or a method an interface needs.
var (
	closureUndefinedPattern     = regexp.MustCompile(`^undefined: (?:(\w+)\.)?(\w+)$`)
	closureArrayLengthPattern   = regexp.MustCompile(`^undefined array length (\w+)`)
	closureNoMethodPattern      = regexp.MustCompile(`undefined \(type \*?(?:(\w+)\.)?(\w+)(?:\[[^\]]*\])? has no (?:field or )?method (\w+)`)
	closureMissingMethodPattern = regexp.MustCompile(`\*?(?:(\w+)\.)?(\w+)(?:\[[^\]]*\])? does not implement .*\(missing method (\w+)\)`)
)

// The files that declare what a failed round's errors name, by the file each error is in, and the error lines nothing
// declares.
func closureFilesNamed(output string, directory string, files map[string]*closureFile, declarations *closureDeclarations, protocolPath string) (map[string]bool, []string) {
	named := map[string]bool{}
	unresolved := []string{}
	for _, line := range strings.Split(output, "\n") {
		match := closureErrorPattern.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil {
			continue
		}
		errorPath := match[1]
		if filepath.IsAbs(errorPath) {
			if relativePath, err := filepath.Rel(directory, errorPath); err == nil {
				errorPath = relativePath
			}
		}
		errorFile := files[path.Clean(filepath.ToSlash(errorPath))]
		if errorFile == nil {
			unresolved = append(unresolved, line)
			continue
		}
		// the package a qualifier names, as the file imports it or as the checker prints a type
		packageOf := func(qualifier string) string {
			if qualifier == "" {
				return errorFile.packageName
			}
			if qualifier == "protocol" && errorFile.packageName == "." {
				return "protocol"
			}
			for _, spec := range errorFile.syntax.Imports {
				importPath, _ := strconv.Unquote(spec.Path.Value)
				importName := path.Base(importPath)
				if spec.Name != nil {
					importName = spec.Name.Name
				}
				if importName == qualifier && importPath == protocolPath {
					return "protocol"
				}
			}
			return ""
		}
		add := func(candidates []string) bool {
			for _, candidate := range candidates {
				named[candidate] = true
			}
			return len(candidates) != 0
		}
		resolved := false
		message := match[2]
		if parts := closureUndefinedPattern.FindStringSubmatch(message); parts != nil {
			if packageName := packageOf(parts[1]); packageName != "" {
				resolved = add(declarations.nameFiles[packageName][parts[2]])
			}
		} else if parts := closureArrayLengthPattern.FindStringSubmatch(message); parts != nil {
			resolved = add(declarations.nameFiles[errorFile.packageName][parts[1]])
		} else if parts := closureNoMethodPattern.FindStringSubmatch(message); parts != nil {
			if packageName := packageOf(parts[1]); packageName != "" {
				resolved = add(declarations.methodFiles[packageName][parts[2]][parts[3]])
			}
		} else if parts := closureMissingMethodPattern.FindStringSubmatch(message); parts != nil {
			if packageName := packageOf(parts[1]); packageName != "" {
				resolved = add(declarations.methodFiles[packageName][parts[2]][parts[3]])
			}
		}
		if !resolved {
			unresolved = append(unresolved, line)
		}
	}
	return named, unresolved
}

// The files outside members whose init function names a function or variable a member declares, or whose package
// variable's initializer calls one: each changes the closure's state at start, which no compile error shows missing.
func closureRegistrations(files map[string]*closureFile, declarations *closureDeclarations, members map[string]bool) []string {
	memberDeclares := func(packageName string, identifier string) bool {
		if !declarations.values[packageName][identifier] {
			return false
		}
		return slices.ContainsFunc(declarations.nameFiles[packageName][identifier], func(name string) bool { return members[name] })
	}
	registrations := []string{}
	for _, name := range slices.Sorted(maps.Keys(files)) {
		if members[name] {
			continue
		}
		file := files[name]
		reaches := false
		inspect := func(node ast.Node, callsOnly bool) {
			ast.Inspect(node, func(node ast.Node) bool {
				var ident *ast.Ident
				switch typed := node.(type) {
				case *ast.CallExpr:
					switch function := typed.Fun.(type) {
					case *ast.Ident:
						ident = function
					case *ast.SelectorExpr:
						ident, _ = function.X.(*ast.Ident)
					}
				case *ast.Ident:
					if !callsOnly {
						ident = typed
					}
				}
				if ident != nil && memberDeclares(file.packageName, ident.Name) {
					reaches = true
				}
				return true
			})
		}
		for _, decl := range file.syntax.Decls {
			switch typed := decl.(type) {
			case *ast.FuncDecl:
				if typed.Recv == nil && typed.Name.Name == "init" && typed.Body != nil {
					inspect(typed.Body, false)
				}
			case *ast.GenDecl:
				if typed.Tok != token.VAR {
					continue
				}
				for _, spec := range typed.Specs {
					for _, value := range spec.(*ast.ValueSpec).Values {
						inspect(value, true)
					}
				}
			}
		}
		if reaches {
			registrations = append(registrations, name)
		}
	}
	return registrations
}

// The leg's file closure from the seeds seedsOf picks among its root files, as the list names files. A round whose
// errors name nothing a stubbed file declares fails the test with the compiler's account, since a closure that cannot
// be computed has not been.
func (self *repository) iosExtensionLegClosure(t testing.TB, leg *buildLeg, seedsOf func(rootFiles []string) []string) (members []string, candidateCount int) {
	t.Helper()
	directory, err := self.legDirectory(leg)
	if err != nil {
		t.Fatal(err)
	}
	environment := leg.environment()
	switch {
	case !leg.compilesOn(runtime.GOOS, runtime.GOARCH):
		environment = append(environment, "CGO_ENABLED=0")
	case leg.cgoEnabled && leg.goos == "ios":
		environment, err = self.iosBuildEnvironment(leg)
		if err != nil {
			t.Fatalf("%s's closure compiles only with Xcode: %v", leg.name, err)
		}
	}
	// the files the leg would compile were the tag to leave none out
	tags := strings.Join(slices.DeleteFunc(slices.Clone(leg.tags), func(tag string) bool { return tag == iosExtensionTag }), ",")
	output, err := runGo(directory, environment, "list", "-tags="+tags, "-json=ImportPath,Name,Dir,GoFiles,CgoFiles", ".", "./protocol")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]*closureFile{}
	rootFiles := []string{}
	decoder := json.NewDecoder(bytes.NewReader(output))
	for {
		listed := &listedPackage{}
		if err := decoder.Decode(listed); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatal(err)
		}
		packageName := "."
		if listed.ImportPath != self.modulePath {
			packageName = "protocol"
		}
		for _, goFile := range slices.Concat(listed.GoFiles, listed.CgoFiles) {
			name := goFile
			if packageName == "protocol" {
				name = "protocol/" + goFile
			} else {
				rootFiles = append(rootFiles, goFile)
			}
			filePath := filepath.Join(listed.Dir, goFile)
			syntax, err := parser.ParseFile(token.NewFileSet(), filePath, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			files[name] = &closureFile{name: name, path: filePath, packageName: packageName, clauseName: syntax.Name.Name, syntax: syntax}
		}
	}
	declarations := readClosureDeclarations(files)
	memberSet := map[string]bool{}
	for _, seed := range seedsOf(rootFiles) {
		if files[seed] == nil {
			t.Fatalf("%s: the seed %s is no root file the leg compiles", leg.name, seed)
		}
		memberSet[seed] = true
	}
	for name, file := range files {
		if len(file.syntax.Decls) == 0 {
			memberSet[name] = true
		}
	}
	scratch := t.TempDir()
	stubPaths := map[string]string{}
	for _, file := range files {
		if stubPaths[file.clauseName] != "" {
			continue
		}
		stubPath := filepath.Join(scratch, file.clauseName+".go")
		if err := os.WriteFile(stubPath, []byte("package "+file.clauseName+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		stubPaths[file.clauseName] = stubPath
	}
	protocolPath := self.modulePath + "/protocol"
	overlayPath := filepath.Join(scratch, "overlay.json")
	for round := 1; ; round += 1 {
		replace := map[string]string{}
		for name, file := range files {
			if !memberSet[name] {
				replace[file.path] = stubPaths[file.clauseName]
			}
		}
		data, err := json.Marshal(map[string]map[string]string{"Replace": replace})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(overlayPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		_, buildErr := runGo(directory, environment, "build", "-overlay="+overlayPath, "-tags="+tags, "-gcflags=-e", "./protocol", ".")
		joined := []string{}
		if buildErr == nil {
			joined = closureRegistrations(files, declarations, memberSet)
		} else {
			named, unresolved := closureFilesNamed(buildErr.Error(), directory, files, declarations, protocolPath)
			for _, name := range slices.Sorted(maps.Keys(named)) {
				if !memberSet[name] {
					joined = append(joined, name)
				}
			}
			if len(joined) == 0 {
				t.Fatalf("%s: round %d does not compile, and no stubbed file declares what it lacks (%d lines unread):\n%v",
					leg.name, round, len(unresolved), buildErr)
			}
		}
		if len(joined) == 0 {
			break
		}
		for _, name := range joined {
			memberSet[name] = true
		}
	}
	return slices.Sorted(maps.Keys(memberSet)), len(files)
}

// The union of both extension legs' closures.
func (self *repository) iosExtensionLegClosures(t testing.TB, seedsOf func(rootFiles []string) []string) []string {
	t.Helper()
	union := map[string]bool{}
	for _, leg := range self.legs {
		if !leg.hasTag(iosExtensionTag) {
			continue
		}
		members, candidateCount := self.iosExtensionLegClosure(t, leg, seedsOf)
		t.Logf("%s: the closure takes %d of the %d root and protocol files the leg compiles untagged", leg.name, len(members), candidateCount)
		for _, name := range members {
			union[name] = true
		}
	}
	if len(union) == 0 {
		t.Fatal("no ios_extension leg was read, so no closure was computed")
	}
	return slices.Sorted(maps.Keys(union))
}

// The list holds the closure of this checkout, or, with SIDECAR_REGENERATE_IOS_EXTENSION_LEG=1, becomes it.
func TestIosExtensionLegListIsItsClosure(t *testing.T) {
	repository := openThisCheckout(t)
	closure := repository.iosExtensionLegClosures(t, iosExtensionLegSeeds)
	if os.Getenv("SIDECAR_REGENERATE_IOS_EXTENSION_LEG") == "1" {
		listPath := filepath.Join(repository.moduleDirectory, filepath.FromSlash(iosExtensionLegListPath))
		if err := os.WriteFile(listPath, []byte(iosExtensionLegListHeader+strings.Join(closure, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %d files to %s", len(closure), iosExtensionLegListPath)
		return
	}
	list := readIosExtensionLegList(repository.moduleDirectory)
	failFindings(t, "legs", list.findings)
	for _, name := range closure {
		if !list.files[name] {
			t.Errorf("the closure needs %s, which %s lacks: rewrite the list with SIDECAR_REGENERATE_IOS_EXTENSION_LEG=1 make ios-extension-leg and take the tag off the file", name, iosExtensionLegListPath)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(list.files)) {
		if !slices.Contains(closure, name) {
			t.Logf("the list may shrink by %s, which the closure no longer needs", name)
		}
	}
}

// A fixture's closure takes exactly what its seed needs to compile: a name, a protocol type, a method called and a
// method an interface needs, each in a file of its own, and the registrations that reach the seed's table; and nothing
// unreached, though it registers into a table of its own.
func TestIosExtensionLegClosureTakesWhatTheSeedNeeds(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs(iosExtensionLegName, macExtensionLegName)
	fixture.write("seed.go", `package sidecar

import "@module@/protocol"

var _ Namer = (*Thing)(nil)

func Seed() int {
	return helperValue + len(registry) + (&Thing{}).Size() + len((&protocol.Message{}).Describe())
}
`)
	fixture.write("helper.go", "package sidecar\n\nconst helperValue = 1\n\ntype Namer interface {\n\tName() string\n}\n")
	fixture.write("thing.go", "package sidecar\n\ntype Thing struct{}\n")
	fixture.write("thing_size.go", "package sidecar\n\nfunc (self *Thing) Size() int {\n\treturn 0\n}\n")
	fixture.write("thing_name.go", "package sidecar\n\nfunc (self *Thing) Name() string {\n\treturn \"\"\n}\n")
	fixture.write("registry.go", "package sidecar\n\nvar registry = map[string]int{}\n\nfunc register(name string) bool {\n\tregistry[name] = 1\n\treturn true\n}\n")
	fixture.write("registration.go", "package sidecar\n\nfunc init() {\n\tregister(\"by init\")\n}\n")
	fixture.write("registration_value.go", "package sidecar\n\nvar registered = register(\"by a variable\")\n")
	fixture.write("unrelated.go", "package sidecar\n\nvar unrelatedTable = map[string]int{}\n\nfunc init() {\n\tunrelatedTable[\"own\"] = 1\n}\n\nfunc Unrelated() {}\n")
	fixture.write("protocol/message.go", "package protocol\n\ntype Message struct {\n\tName string\n}\n")
	fixture.write("protocol/message_describe.go", "package protocol\n\nfunc (self *Message) Describe() string {\n\treturn self.Name\n}\n")
	fixture.write("protocol/other.go", "package protocol\n\ntype Other struct{}\n")
	closure := fixture.open().iosExtensionLegClosures(t, func(rootFiles []string) []string { return []string{"seed.go"} })
	want := []string{
		"helper.go", "protocol/doc.go", "protocol/message.go", "protocol/message_describe.go", "registration.go",
		"registration_value.go", "registry.go", "seed.go", "thing.go", "thing_name.go", "thing_size.go",
	}
	if !slices.Equal(closure, want) {
		t.Errorf("closure %v, want %v", closure, want)
	}
}

// Before BRIDGE-M8-05 the seeds are DESIGN-DETAILS 4.7's twelve files; once a bridge_forward*.go file exists, they are
// the Forwarder's files and the compiler's.
func TestIosExtensionLegSeedsFollowTheForwarder(t *testing.T) {
	rootFiles := []string{"acl_eval.go", "bridge_compile.go", "bridge_statement.go", "config_head.go"}
	if seeds := iosExtensionLegSeeds(rootFiles); !slices.Equal(seeds, iosExtensionLegInterimSeeds) {
		t.Errorf("seeds %v before the Forwarder", seeds)
	}
	rootFiles = append(rootFiles, "bridge_forward.go", "bridge_forward_sign.go", "bridge_forward_test.go")
	if seeds := iosExtensionLegSeeds(rootFiles); !slices.Equal(seeds, []string{"bridge_compile.go", "bridge_forward.go", "bridge_forward_sign.go"}) {
		t.Errorf("seeds %v with the Forwarder", seeds)
	}
}
