// Whether a gate entry's tests exist where it names them (TEST-M4-04; owner decision 548, QD-1081): a sweep names a
// test by repo, package, tags and name, and one that was renamed, or whose file's build tags drifted from the entry's,
// reads missing at the gate, never pass. A test in each repo holds its sweeps' entries with this, so the drift fails
// there first. It reads source files only, and builds nothing.

package fault

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
)

// One error for each name of test that no _test.go file of its package declares as a top-level function, or that only
// files go test does not build on this host with the entry's tags declare. repoDirectory is the checkout of
// test.Repo.
func GateTestDeclared(repoDirectory string, test *GateTest) []error {
	directory := filepath.Join(repoDirectory, test.Dir, filepath.FromSlash(test.Package))
	paths, err := filepath.Glob(filepath.Join(directory, "*_test.go"))
	if err != nil {
		return []error{err}
	}
	nameFiles := map[string][]string{}
	fileSet := token.NewFileSet()
	for _, path := range paths {
		file, err := parser.ParseFile(fileSet, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return []error{err}
		}
		for _, declaration := range file.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok && function.Recv == nil {
				nameFiles[function.Name.Name] = append(nameFiles[function.Name.Name], filepath.Base(path))
			}
		}
	}
	buildContext := build.Default
	if test.Tags != "" {
		buildContext.BuildTags = strings.Split(test.Tags, ",")
	}
	errs := []error{}
	for _, name := range test.Names {
		files := nameFiles[name]
		if len(files) == 0 {
			errs = append(errs, fmt.Errorf("%s's %s names %s, which no test file there declares", test.Repo, test.Package, name))
			continue
		}
		built := slices.ContainsFunc(files, func(file string) bool {
			match, err := buildContext.MatchFile(directory, file)
			return err == nil && match
		})
		if !built {
			errs = append(errs, fmt.Errorf("%s's %s names %s, declared in %v, which go test does not build here with tags %q", test.Repo, test.Package, name, files, test.Tags))
		}
	}
	return errs
}
