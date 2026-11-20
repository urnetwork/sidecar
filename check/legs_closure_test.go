//go:build sidecar_check && sidecar_size

// The ios_extension leg's list, computed, never hand-picked (DESIGN-DETAILS 4.2.3; REPO-M4-01). The root's files are not
// layered, so the forwarding role's entry points need far more than their own files to compile, and the list is their
// file closure: from the seeds, each extension leg compiles the root and protocol with every other root and protocol
// file replaced by an empty one through -overlay, and the file declaring each undefined name joins, round after round,
// until the leg compiles. Two kinds of file join besides. One outside the closure whose init function, or whose package
// variable's initializer, reaches the closure's own functions or variables: leaving it out would change what the
// closure does with no compile error, and the config rule table registers by init. And one that declares nothing, a
// package's doc.go, which costs nothing. The extension legs' closures, one per slice the extension's bind builds, make
// one list.
//
// A leg file is one only the leg's tag selects, such as rpc_search_leg.go (QD-988): the leg's stand-in for a file tagged
// off in its favor. The leg compiles it whatever the seeds need, so it is in the closure from the start, and in the
// rounds it compiles as a copy without its build line, so the closure takes what it declares from it and the file it
// stands in for stays out, with all that file alone needs. Should the closure need another name of that file, the file
// joins, the round fails on the names both declare, and the test fails: such a leg would not compile either.
//
// A deliberate seam is the registration that does not join (QD-1063, QD-1065): a file iosExtensionLegSeams names, a
// short reviewed list with each entry's reason, whose init sets a hook a closure file declares while its tag keeps it
// off the legs, since what it registers is no part of the forwarding role. Leaving it out changes what the closure
// does, and that change is the seam's purpose. The exemption is that narrow: a seam the leg compiles joins as any
// registration does, one whose name a member lacks joins for the name, and every other init joins as before. The
// list of seams is checked against the closure too: an entry the closure takes, or one no leg's closure leaves out,
// fails.
//
// This compiles each leg once a round and needs Xcode for the iOS ones, so it runs beside make size, not in make check,
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
	"go/build/constraint"
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

// A deliberate seam on the ios_extension legs: a file their tag leaves out though its init sets a hook a closure file
// declares.
type closureSeam struct {
	// as the list names files
	name string
	// what its init sets and what the legs go without, with the question that reviewed it
	reason string
}

// The legs' deliberate seams, in the order they were reviewed (QD-1063, QD-1065). Each hook exists so that the file
// setting it can stay off a leg, and none of these serves the forwarding role, which runs only IP and port forwarding
// (owner decision 197). An entry joins in the commit that reviews its seam, never to quiet the closure.
var iosExtensionLegSeams = []*closureSeam{
	{
		name:   "evs_read_provenance.go",
		reason: "init sets evs_read.go's evsProvenanceRead (QD-851, QD-1063): on the legs a read gives no provenance, so the forwarding role links no agent-subkey check",
	},
	{
		name:   "directory_card.go",
		reason: "init sets directory_client.go's directoryFoldFiles (QD-1065): on the legs a fold folds entries alone, judging and repairing no card or repo file",
	},
	{
		name:   "directory_format2.go",
		reason: "init sets directory_repo.go's directoryRepoWriter and directoryRepoMigrate (QD-1065): the legs write no format-2 carrier, every repo item going as an announce entry",
	},
	{
		name:   "directory_removal.go",
		reason: "init sets directory_client.go's directoryAfterRead (QD-1065): the legs raise no moderation alarm",
	},
	{
		name:   "directory_revoke.go",
		reason: "init sets directory_client.go's directoryErasureJudge (QD-1065): on the legs a reader judges none of the directory's erasures and takes every one",
	},
	{
		name:   "identity_cleanup.go",
		reason: "init registers the cleanup approval kind in identity_approvals.go's table (QD-1065): the legs register no cleanup approval kind",
	},
	{
		name:   "record_agent_body.go",
		reason: "init sets record_seal.go's recordAgentBodySealer, record_reader.go's recordAgentBodyOpener and record_writer.go's recordSidecarAgentSigner (QD-1065): on the legs every record entry seals version 1, and a version-2 entry reads generically, its agent body unopened",
	},
	{
		name:   "evs_read_erased.go",
		reason: "init sets evs_reconstruct.go's newEvsErasureJudge (question erased-slot-not-tamper-forwarding-leg-seam): the legs read no erasure ref, so there a key gone from its slot alarms tamper as it did before, and the forwarding role links no ERASE reader",
	},
}

// The list's header, which a rewrite writes above its sorted names.
const iosExtensionLegListHeader = `# The root and protocol files the ios_extension legs may link, by path from the root module, sorted: the
# forwarding role's file closure (D-SDK-20; DESIGN-DETAILS 4.2.3; REPO-M4-01). make check fails a root or protocol
# file either extension leg compiles that this list does not name; every other root file carries
# //go:build !ios_extension, and protocol/Makefile writes that tag on each generated file this list does not name.
# A file whose init sets a hook a file here declares is on it too, unless check/legs_closure_test.go's
# iosExtensionLegSeams names it as a deliberate seam, with its reason (QD-1063, QD-1065).
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
// One in seams, a deliberate seam the leg leaves out, is answered apart and does not join.
func closureRegistrations(files map[string]*closureFile, declarations *closureDeclarations, members map[string]bool, seams map[string]bool) (registrations []string, skippedSeams []string) {
	memberDeclares := func(packageName string, identifier string) bool {
		if !declarations.values[packageName][identifier] {
			return false
		}
		return slices.ContainsFunc(declarations.nameFiles[packageName][identifier], func(name string) bool { return members[name] })
	}
	registrations = []string{}
	skippedSeams = []string{}
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
		switch {
		case reaches && seams[name]:
			skippedSeams = append(skippedSeams, name)
		case reaches:
			registrations = append(registrations, name)
		}
	}
	return registrations, skippedSeams
}

// The leg's file closure from the seeds seedsOf picks among its root files, as the list names files, and the seams it
// left out, those of seams the leg does not compile which it would otherwise have taken as registrations. A round
// whose errors name nothing a stubbed file declares fails the test with the compiler's account, since a closure that
// cannot be computed has not been.
func (self *repository) iosExtensionLegClosure(t testing.TB, leg *buildLeg, seedsOf func(rootFiles []string) []string, seams []*closureSeam) (members []string, candidateCount int, skippedSeams []string) {
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
	// the root and protocol files a set of tags compiles, as the list names files
	listFiles := func(tags string) []*closureFile {
		output, err := runGo(directory, environment, "list", "-tags="+tags, "-json=ImportPath,Name,Dir,GoFiles,CgoFiles", ".", "./protocol")
		if err != nil {
			t.Fatal(err)
		}
		listedFiles := []*closureFile{}
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
				}
				filePath := filepath.Join(listed.Dir, goFile)
				syntax, err := parser.ParseFile(token.NewFileSet(), filePath, nil, parser.SkipObjectResolution)
				if err != nil {
					t.Fatal(err)
				}
				listedFiles = append(listedFiles, &closureFile{name: name, path: filePath, packageName: packageName, clauseName: syntax.Name.Name, syntax: syntax})
			}
		}
		return listedFiles
	}
	// the files the leg would compile were the tag to leave none out
	tags := strings.Join(slices.DeleteFunc(slices.Clone(leg.tags), func(tag string) bool { return tag == iosExtensionTag }), ",")
	files := map[string]*closureFile{}
	rootFiles := []string{}
	for _, file := range listFiles(tags) {
		files[file.name] = file
		if file.packageName == "." {
			rootFiles = append(rootFiles, file.name)
		}
	}
	// what the leg compiles with its tag, and of that its own files, which only its tag selects
	legFiles := []*closureFile{}
	legCompiled := map[string]bool{}
	for _, file := range listFiles(strings.Join(leg.tags, ",")) {
		legCompiled[file.name] = true
		if files[file.name] == nil {
			legFiles = append(legFiles, file)
		}
	}
	// the seams the leg's tag leaves out, which alone a round may skip as registrations: one the leg compiles registers
	// on the leg whatever its entry says
	seamSet := map[string]bool{}
	for _, seam := range seams {
		if !legCompiled[seam.name] {
			seamSet[seam.name] = true
		}
	}
	skippedSeamSet := map[string]bool{}
	memberSet := map[string]bool{}
	for _, seed := range seedsOf(rootFiles) {
		if files[seed] == nil {
			t.Fatalf("%s: the seed %s is no root file the leg compiles", leg.name, seed)
		}
		memberSet[seed] = true
	}
	scratch := t.TempDir()
	// each leg file's copy without its build line, which a round without the tag compiles in its place
	legFilePaths := map[string]string{}
	for index, file := range legFiles {
		data, err := os.ReadFile(file.path)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(data), "\n")
		for lineIndex, line := range lines {
			if constraint.IsGoBuild(line) || constraint.IsPlusBuild(line) {
				lines[lineIndex] = ""
			}
		}
		legFilePath := filepath.Join(scratch, "leg"+strconv.Itoa(index)+"_"+filepath.Base(file.path))
		if err := os.WriteFile(legFilePath, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
			t.Fatal(err)
		}
		legFilePaths[file.name] = legFilePath
		files[file.name] = file
		memberSet[file.name] = true
	}
	declarations := readClosureDeclarations(files)
	for name, file := range files {
		if len(file.syntax.Decls) == 0 {
			memberSet[name] = true
		}
	}
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
			} else if legFilePath := legFilePaths[name]; legFilePath != "" {
				replace[file.path] = legFilePath
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
			var skipped []string
			joined, skipped = closureRegistrations(files, declarations, memberSet, seamSet)
			for _, name := range skipped {
				skippedSeamSet[name] = true
			}
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
		// why each file is on the list: the round it joined in, for a name a member lacked or, the round having
		// compiled, as a registration
		reason := "for names its members lack"
		if buildErr == nil {
			reason = "as registrations into its members"
		}
		t.Logf("%s: round %d takes %d files %s: %s", leg.name, round, len(joined), reason, strings.Join(joined, " "))
		for _, name := range joined {
			memberSet[name] = true
		}
	}
	// a seam a later round took for a name its members lacked is in the closure, not left out
	skippedSeams = []string{}
	for _, name := range slices.Sorted(maps.Keys(skippedSeamSet)) {
		if !memberSet[name] {
			skippedSeams = append(skippedSeams, name)
		}
	}
	if len(skippedSeams) != 0 {
		t.Logf("%s: the closure leaves out the deliberate seams it would take as registrations: %s", leg.name, strings.Join(skippedSeams, " "))
	}
	return slices.Sorted(maps.Keys(memberSet)), len(files), skippedSeams
}

// The union of every extension leg's closure, and of the seams each left out. A seam with no reason, or named twice,
// fails the test before any leg compiles, since each is reviewed once, for its reason.
func (self *repository) iosExtensionLegClosures(t testing.TB, seedsOf func(rootFiles []string) []string, seams []*closureSeam) (closure []string, skippedSeams []string) {
	t.Helper()
	for index, seam := range seams {
		if strings.TrimSpace(seam.reason) == "" {
			t.Fatalf("the seam %s gives no reason: each is reviewed for what the legs go without", seam.name)
		}
		if slices.ContainsFunc(seams[:index], func(other *closureSeam) bool { return other.name == seam.name }) {
			t.Fatalf("the seam %s is named twice", seam.name)
		}
	}
	union := map[string]bool{}
	skippedUnion := map[string]bool{}
	for _, leg := range self.legs {
		if !leg.hasTag(iosExtensionTag) {
			continue
		}
		members, candidateCount, legSkippedSeams := self.iosExtensionLegClosure(t, leg, seedsOf, seams)
		t.Logf("%s: the closure takes %d of the %d root and protocol files the leg compiles untagged", leg.name, len(members), candidateCount)
		for _, name := range members {
			union[name] = true
		}
		for _, name := range legSkippedSeams {
			skippedUnion[name] = true
		}
	}
	if len(union) == 0 {
		t.Fatal("no ios_extension leg was read, so no closure was computed")
	}
	return slices.Sorted(maps.Keys(union)), slices.Sorted(maps.Keys(skippedUnion))
}

// What is wrong with seams once the closure and the seams its legs left out are known. An entry the closure takes is
// no seam, the legs compiling it or a member needing a name it declares. And an entry no leg's closure left out is an
// exemption nothing uses, its file gone or reaching the closure no more, which would hide the next init the file gains.
func closureSeamFindings(seams []*closureSeam, closure []string, skippedSeams []string) []string {
	findings := []string{}
	for _, seam := range seams {
		switch {
		case slices.Contains(closure, seam.name):
			findings = append(findings, findingf("the closure takes %s, a seam on iosExtensionLegSeams: an extension leg compiles it, or a member needs a name it declares, so the legs do not leave it out; give it its tag back and move the name out of it, or take it off the seams", seam.name))
		case !slices.Contains(skippedSeams, seam.name):
			findings = append(findings, findingf("no extension leg's closure leaves out %s, a seam on iosExtensionLegSeams: it is gone or no init or package variable of it reaches the closure, so take it off the seams, where it would hide the next init it gains", seam.name))
		}
	}
	return findings
}

// The list holds the closure of this checkout, or, with SIDECAR_REGENERATE_IOS_EXTENSION_LEG=1, becomes it; either
// way each seam on iosExtensionLegSeams must be one the closure leaves out.
func TestIosExtensionLegListIsItsClosure(t *testing.T) {
	repository := openThisCheckout(t)
	closure, skippedSeams := repository.iosExtensionLegClosures(t, iosExtensionLegSeeds, iosExtensionLegSeams)
	failFindings(t, "legs", closureSeamFindings(iosExtensionLegSeams, closure, skippedSeams))
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
	closure, _ := fixture.open().iosExtensionLegClosures(t, func(rootFiles []string) []string { return []string{"seed.go"} }, nil)
	want := []string{
		"helper.go", "protocol/doc.go", "protocol/message.go", "protocol/message_describe.go", "registration.go",
		"registration_value.go", "registry.go", "seed.go", "thing.go", "thing_name.go", "thing_size.go",
	}
	if !slices.Equal(closure, want) {
		t.Errorf("closure %v, want %v", closure, want)
	}
}

// A leg file, which only the legs' tag selects, is in the closure and stands in for the file tagged off in its favor: the
// closure takes the seed's name from it, and neither the file it replaces nor the protocol file only that one reads.
func TestIosExtensionLegClosureTakesALegFileForTheFileItReplaces(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs(iosExtensionLegName, macExtensionLegName)
	fixture.write("seed.go", "package sidecar\n\nfunc Seed() int {\n\treturn answer()\n}\n")
	fixture.write("answer.go", "//go:build !ios_extension\n\npackage sidecar\n\nimport \"@module@/protocol\"\n\nfunc answer() int {\n\treturn len((&protocol.Message{}).Name)\n}\n")
	fixture.write("answer_leg.go", "//go:build ios_extension\n\npackage sidecar\n\nfunc answer() int {\n\treturn 0\n}\n")
	fixture.write("protocol/message.go", "package protocol\n\ntype Message struct {\n\tName string\n}\n")
	closure, _ := fixture.open().iosExtensionLegClosures(t, func(rootFiles []string) []string { return []string{"seed.go"} }, nil)
	if want := []string{"answer_leg.go", "protocol/doc.go", "seed.go"}; !slices.Equal(closure, want) {
		t.Errorf("closure %v, want %v", closure, want)
	}
}

// Its twin: with no leg file, the closure takes the tagged file the seed needs and the protocol file that one reads.
func TestIosExtensionLegClosureTakesATaggedFileWithNoLegFile(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs(iosExtensionLegName, macExtensionLegName)
	fixture.write("seed.go", "package sidecar\n\nfunc Seed() int {\n\treturn answer()\n}\n")
	fixture.write("answer.go", "//go:build !ios_extension\n\npackage sidecar\n\nimport \"@module@/protocol\"\n\nfunc answer() int {\n\treturn len((&protocol.Message{}).Name)\n}\n")
	fixture.write("protocol/message.go", "package protocol\n\ntype Message struct {\n\tName string\n}\n")
	closure, _ := fixture.open().iosExtensionLegClosures(t, func(rootFiles []string) []string { return []string{"seed.go"} }, nil)
	if want := []string{"answer.go", "protocol/doc.go", "protocol/message.go", "seed.go"}; !slices.Equal(closure, want) {
		t.Errorf("closure %v, want %v", closure, want)
	}
}

// A seed reading two hooks, each set from init by a file of the same shape tagged off the legs: seam.go, the only file
// that reads protocol/provenance.go, and registration.go. With tagged false seam.go carries no tag, so the legs compile
// it.
func writeClosureSeamFixture(fixture *fixture, tagged bool) {
	fixture.write("seed.go", `package sidecar

var seamHook func() int

var registrationHook func() int

func Seed() int {
	total := 0
	for _, hook := range []func() int{seamHook, registrationHook} {
		if hook != nil {
			total += hook()
		}
	}
	return total
}
`)
	buildLine := "//go:build !ios_extension\n\n"
	seam := `package sidecar

import "@module@/protocol"

func init() {
	seamHook = func() int {
		return len((&protocol.Provenance{}).Signer)
	}
}
`
	if tagged {
		seam = buildLine + seam
	}
	fixture.write("seam.go", seam)
	fixture.write("registration.go", buildLine+"package sidecar\n\nfunc init() {\n\tregistrationHook = func() int {\n\t\treturn 1\n\t}\n}\n")
	fixture.write("protocol/provenance.go", "package protocol\n\ntype Provenance struct {\n\tSigner string\n}\n")
}

// The seams one fixture names.
var closureFixtureSeams = []*closureSeam{{name: "seam.go", reason: "a fixture's seam, whose hook the legs go without"}}

// A seam on the list, which the legs' tag leaves out, is left out with the protocol file only it reads, and is answered
// as left out; beside it an unlisted registration of the same shape still joins, so the rule's guard for every other
// init stays.
func TestIosExtensionLegClosureLeavesOutASeam(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs(iosExtensionLegName, macExtensionLegName)
	writeClosureSeamFixture(fixture, true)
	closure, skippedSeams := fixture.open().iosExtensionLegClosures(t, func(rootFiles []string) []string { return []string{"seed.go"} }, closureFixtureSeams)
	if want := []string{"protocol/doc.go", "registration.go", "seed.go"}; !slices.Equal(closure, want) {
		t.Errorf("closure %v, want %v", closure, want)
	}
	if want := []string{"seam.go"}; !slices.Equal(skippedSeams, want) {
		t.Errorf("seams left out %v, want %v", skippedSeams, want)
	}
	wantFindings(t, closureSeamFindings(closureFixtureSeams, closure, skippedSeams))
}

// Its twin: with the list naming no seam, the same file joins as a registration, with the protocol file it reads.
func TestIosExtensionLegClosureTakesARegistrationTheSeamsDoNotName(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs(iosExtensionLegName, macExtensionLegName)
	writeClosureSeamFixture(fixture, true)
	closure, skippedSeams := fixture.open().iosExtensionLegClosures(t, func(rootFiles []string) []string { return []string{"seed.go"} }, nil)
	if want := []string{"protocol/doc.go", "protocol/provenance.go", "registration.go", "seam.go", "seed.go"}; !slices.Equal(closure, want) {
		t.Errorf("closure %v, want %v", closure, want)
	}
	if len(skippedSeams) != 0 {
		t.Errorf("seams left out %v with none listed", skippedSeams)
	}
}

// A seam whose tag came off joins as any registration does, though the list names it: the legs compile it, so its init
// runs there whatever its entry says.
func TestIosExtensionLegClosureTakesASeamTheLegsCompile(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs(iosExtensionLegName, macExtensionLegName)
	writeClosureSeamFixture(fixture, false)
	closure, skippedSeams := fixture.open().iosExtensionLegClosures(t, func(rootFiles []string) []string { return []string{"seed.go"} }, closureFixtureSeams)
	if want := []string{"protocol/doc.go", "protocol/provenance.go", "registration.go", "seam.go", "seed.go"}; !slices.Equal(closure, want) {
		t.Errorf("closure %v, want %v", closure, want)
	}
	if len(skippedSeams) != 0 {
		t.Errorf("seams left out %v, though the legs compile the seam", skippedSeams)
	}
	wantFindings(t, closureSeamFindings(closureFixtureSeams, closure, skippedSeams), "the closure takes seam.go")
}

// A seam is exempt as a registration only: once a registration that joined needs a name the seam declares, the seam
// joins for it, with what it reads, and is no longer answered as left out.
func TestIosExtensionLegClosureTakesASeamForANameAMemberLacks(t *testing.T) {
	fixture := newFixture(t)
	fixture.keepLegs(iosExtensionLegName, macExtensionLegName)
	writeClosureSeamFixture(fixture, true)
	fixture.edit("seam.go", "func init() {", "func seamValue() int {\n\treturn 1\n}\n\nfunc init() {")
	fixture.edit("registration.go", "return 1", "return seamValue()")
	closure, skippedSeams := fixture.open().iosExtensionLegClosures(t, func(rootFiles []string) []string { return []string{"seed.go"} }, closureFixtureSeams)
	if want := []string{"protocol/doc.go", "protocol/provenance.go", "registration.go", "seam.go", "seed.go"}; !slices.Equal(closure, want) {
		t.Errorf("closure %v, want %v", closure, want)
	}
	if len(skippedSeams) != 0 {
		t.Errorf("seams left out %v, though the closure took the seam for a name", skippedSeams)
	}
	wantFindings(t, closureSeamFindings(closureFixtureSeams, closure, skippedSeams), "the closure takes seam.go")
}

// Of a list of seams, one the closure takes and one no leg's closure left out are each a finding, in the list's order,
// the first though one leg left it out; one left out and taken by none is no finding.
func TestIosExtensionLegSeamFindings(t *testing.T) {
	seams := []*closureSeam{
		{name: "left_out.go", reason: "a seam the legs leave out"},
		{name: "taken.go", reason: "a seam one leg leaves out and another takes"},
		{name: "unused.go", reason: "a seam whose file reaches the closure no more"},
	}
	findings := closureSeamFindings(seams, []string{"seed.go", "taken.go"}, []string{"left_out.go", "taken.go"})
	wantFindings(t, findings, "the closure takes taken.go", "no extension leg's closure leaves out unused.go")
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
