// Proves from source that the device role's hooks are empty without the sidecar_testhooks tag, and
// that the package reaches the root by no route. These run in both builds: they read the package
// through an explicit go/build context, which -tags does not reach. testhook_enabled_test.go is the
// twin showing the same call sites do act under the tag.

package device

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Stops compiling if either build's signature drifts from §22.4's.
var (
	_ func(kind string, secret []byte) = testHookSecret
	_ func(name string, key string)    = testHookBarrier
)

func TestHookFilesSplitOnTag(t *testing.T) {
	legs := []struct {
		goos   string
		goarch string
		tags   []string
	}{
		{goos: "darwin", goarch: "arm64"},
		{goos: "linux", goarch: "amd64"},
		{goos: "windows", goarch: "amd64"},
		{goos: "ios", goarch: "arm64", tags: []string{"ios_extension"}},
	}
	for _, leg := range legs {
		for _, tagged := range []bool{false, true} {
			buildContext := build.Default
			buildContext.GOOS = leg.goos
			buildContext.GOARCH = leg.goarch
			buildContext.BuildTags = slices.Clone(leg.tags)
			if tagged {
				buildContext.BuildTags = append(buildContext.BuildTags, "sidecar_testhooks")
			}

			emptyMatched, err := buildContext.MatchFile(".", "testhook.go")
			if err != nil {
				t.Fatal(err)
			}
			enabledMatched, err := buildContext.MatchFile(".", "testhook_enabled.go")
			if err != nil {
				t.Fatal(err)
			}
			if emptyMatched == tagged || enabledMatched != tagged {
				t.Errorf(
					"%s/%s tags %v: testhook.go %v, testhook_enabled.go %v",
					leg.goos, leg.goarch, buildContext.BuildTags, emptyMatched, enabledMatched,
				)
			}
		}
	}
}

func TestHooksEmptyWithoutTag(t *testing.T) {
	buildContext := build.Default
	buildContext.BuildTags = nil
	pkg, err := buildContext.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}

	fileSet := token.NewFileSet()
	hookFuncs := map[string]*ast.FuncDecl{}
	for _, goFile := range pkg.GoFiles {
		file, err := parser.ParseFile(fileSet, goFile, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		if goFile == "testhook.go" && len(file.Decls) != 2 {
			// an import, var or type here would be state the untagged build should not have
			t.Errorf("testhook.go has %d declarations, want the two hooks alone", len(file.Decls))
		}
		for _, decl := range file.Decls {
			switch typedDecl := decl.(type) {
			case *ast.FuncDecl:
				switch typedDecl.Name.Name {
				case "testHookSecret", "testHookBarrier":
					hookFuncs[typedDecl.Name.Name] = typedDecl
				case "SetTestHooks":
					t.Errorf("%s: SetTestHooks exists without the tag", goFile)
				}
			case *ast.GenDecl:
				for _, spec := range typedDecl.Specs {
					if typeSpec, ok := spec.(*ast.TypeSpec); ok && typeSpec.Name.Name == "TestHooks" {
						t.Errorf("%s: TestHooks exists without the tag", goFile)
					}
				}
			}
		}
	}

	for _, name := range []string{"testHookSecret", "testHookBarrier"} {
		hookFunc, ok := hookFuncs[name]
		if !ok {
			t.Errorf("%s is missing from the untagged build", name)
			continue
		}
		if file := fileSet.Position(hookFunc.Pos()).Filename; file != "testhook.go" {
			t.Errorf("%s is declared in %s, want testhook.go", name, file)
		}
		if statements := len(hookFunc.Body.List); statements != 0 {
			t.Errorf("%s has %d statements, want an empty body", name, statements)
		}
	}
}

// §4.4 and D-SDK-20 hold for the hook files too: the tagged half has an installer of its own rather
// than a forward to the root, so no build of this package links the root.
func TestNoBuildOfThePackageImportsTheRoot(t *testing.T) {
	for _, tags := range [][]string{nil, {"sidecar_testhooks"}} {
		buildContext := build.Default
		buildContext.BuildTags = tags
		pkg, err := buildContext.ImportDir(".", 0)
		if err != nil {
			t.Fatal(err)
		}
		fileSet := token.NewFileSet()
		for _, goFile := range pkg.GoFiles {
			file, err := parser.ParseFile(fileSet, goFile, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, spec := range file.Imports {
				importPath, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					t.Fatal(err)
				}
				rest, ours := strings.CutPrefix(importPath, "github.com/urnetwork/sidecar")
				if ours && rest != "/protocol/bridge" {
					t.Errorf("tags %v: %s imports %s", tags, goFile, importPath)
				}
			}
		}
	}
}
