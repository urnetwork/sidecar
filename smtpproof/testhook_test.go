// Proves from source that this package's hooks are empty without the sidecar_testhooks tag. It runs
// in both builds: it reads the package through an explicit go/build context, which -tags does not
// reach. testhook_enabled_test.go is the twin showing the same call sites act under the tag.

package smtpproof

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"testing"
)

// Stops compiling if either build's signature drifts from §22.4's.
var (
	_ func(kind string, secret []byte) = testHookSecret
	_ func(name string, key string)    = testHookBarrier
)

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
		for _, importSpec := range file.Imports {
			// the root is linked here only under the tag
			if importSpec.Path.Value == `"github.com/urnetwork/sidecar"` {
				t.Errorf("%s imports the root in the untagged build", goFile)
			}
		}
		for _, decl := range file.Decls {
			if funcDecl, ok := decl.(*ast.FuncDecl); ok {
				switch funcDecl.Name.Name {
				case "testHookSecret", "testHookBarrier":
					hookFuncs[funcDecl.Name.Name] = funcDecl
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
