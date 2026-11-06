// Proves from source that the hooks are empty without the sidecar_testhooks tag. These run in both
// builds: they read the package through an explicit go/build context, which -tags does not reach.
// testhook_enabled_test.go is the twin showing the same call sites do act under the tag.

package sidecar

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"slices"
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
		{goos: "js", goarch: "wasm", tags: []string{"sidecar_http"}},
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
				case "SetTestHooks", "TestHookSecret", "TestHookBarrier":
					t.Errorf("%s: %s exists without the tag", goFile, typedDecl.Name.Name)
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
