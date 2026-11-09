package sidecartest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The package's declarations, from its non-test files: type names, and function names qualified by
// their package when it is a child ("blobsuite.Run").
func storeSuiteDeclarations(t *testing.T) (typeNames []string, functionNames []string) {
	t.Helper()
	for _, directory := range []string{".", "blobsuite", "redissuite", "quotasuite"} {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(directory, name), nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			prefix := ""
			if directory != "." {
				prefix = directory + "."
			}
			for _, declaration := range file.Decls {
				switch declaration := declaration.(type) {
				case *ast.FuncDecl:
					if declaration.Recv == nil {
						functionNames = append(functionNames, prefix+declaration.Name.Name)
					}
				case *ast.GenDecl:
					for _, spec := range declaration.Specs {
						if typeSpec, ok := spec.(*ast.TypeSpec); ok && directory == "." {
							typeNames = append(typeNames, typeSpec.Name.Name)
						}
					}
				}
			}
		}
	}
	return typeNames, functionNames
}

var storeFakeTypePattern = regexp.MustCompile(`^Fake[A-Z][A-Za-z0-9]*Store$`)

// D-TEST-2: a Fake<Name>Store added to this package without a suite fails here, and every listed fake
// and suite exists.
func TestEveryStoreFakeHasASuite(t *testing.T) {
	typeNames, functionNames := storeSuiteDeclarations(t)
	fakes := StoreFakes()
	for _, typeName := range typeNames {
		if storeFakeTypePattern.MatchString(typeName) && !slices.Contains(fakes, typeName) {
			t.Errorf("%s is a store's fake and StoreFakes does not list it", typeName)
		}
	}
	for _, fake := range fakes {
		if !slices.Contains(typeNames, fake) {
			t.Errorf("StoreFakes lists %s, which this package does not declare", fake)
		}
	}
	for _, suite := range StoreSuites() {
		if !slices.Contains(functionNames, suite.Name) {
			t.Errorf("suite %s is no function of this package or its suites", suite.Name)
		}
	}
	for _, problem := range StoreSuiteProblems(StoreSuites(), fakes) {
		t.Error(problem)
	}
}

// The check bites: a store fake no suite runs on, and a suite naming nothing or a fake of no store.
func TestStoreSuiteProblemsNameAFakeWithNoSuite(t *testing.T) {
	suites := []*StoreSuite{
		{Name: "RunASuite", Fakes: []string{"FakeAStore"}},
		{Name: "RunAnEmptySuite"},
		{Name: "RunAStraySuite", Fakes: []string{"FakeClock"}},
	}
	problems := StoreSuiteProblems(suites, []string{"FakeAStore", "FakeBStore"})
	want := []string{
		"FakeBStore stands for a store and no suite holds it to the real one (D-TEST-2)",
		"RunAnEmptySuite names no fake it runs on at T2",
		"RunAStraySuite names FakeClock, which stands for no store",
	}
	if !slices.Equal(problems, want) {
		t.Errorf("problems %q, want %q", problems, want)
	}
	if problems := StoreSuiteProblems(suites[:1], []string{"FakeAStore"}); len(problems) != 0 {
		t.Errorf("a whole list has problems: %q", problems)
	}
}
