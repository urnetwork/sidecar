//go:build !js

// CODESTYLE's rules a reader of the root's source can hold, which make check's rows do not: each
// declaration carries a doc comment that does not repeat its name, every tunable says what it is, and
// a struct literal names its fields. Each rule is a function over parsed files, so a planted violation
// proves it as the real source does.

package sidecar

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"slices"
	"strings"
	"testing"
)

// What file declares with no doc comment, or with one that opens by repeating the name.
func commentFindings(file *ast.File) []string {
	findings := []string{}
	check := func(name string, doc *ast.CommentGroup) {
		if doc == nil {
			findings = append(findings, name+" has no doc comment")
		} else if strings.HasPrefix(doc.Text(), name+" ") {
			findings = append(findings, name+"'s comment repeats its name")
		}
	}
	for _, decl := range file.Decls {
		switch declaration := decl.(type) {
		case *ast.FuncDecl:
			check(declaration.Name.Name, declaration.Doc)
		case *ast.GenDecl:
			if declaration.Tok != token.TYPE {
				continue
			}
			for _, spec := range declaration.Specs {
				typeSpec := spec.(*ast.TypeSpec)
				if typeSpec.Doc != nil {
					check(typeSpec.Name.Name, typeSpec.Doc)
				} else {
					check(typeSpec.Name.Name, declaration.Doc)
				}
			}
		}
	}
	return findings
}

func TestEveryRootDeclarationHasADocComment(t *testing.T) {
	for goFile, file := range parseRootFiles(t) {
		for _, finding := range commentFindings(file) {
			t.Errorf("%s: %s", goFile, finding)
		}
	}
}

func TestCommentRuleCatchesPlantedViolations(t *testing.T) {
	file := parseSyntheticFile(t, `
func missing() {}
// missingToo does nothing.
func missingToo() {}
type Bare struct{}
// Bare2 is a thing.
type Bare2 struct{}
// Fine, and says something else.
func kept() {}
`)
	want := []string{
		"missing has no doc comment",
		"missingToo's comment repeats its name",
		"Bare has no doc comment",
		"Bare2's comment repeats its name",
	}
	if findings := commentFindings(file); !slices.Equal(findings, want) {
		t.Errorf("findings %q", findings)
	}
}

// Whether a field's type is a number a host tunes, as the field's declared type reads.
func isTunableType(expression ast.Expr) bool {
	switch fieldType := expression.(type) {
	case *ast.Ident:
		return slices.Contains([]string{"int", "int64", "float64", "SidecarRate"}, fieldType.Name)
	case *ast.SelectorExpr:
		return fieldType.Sel.Name == "Duration"
	case *ast.ArrayType:
		return isTunableType(fieldType.Elt)
	}
	return false
}

// A tunable in a settings struct with no comment of its own, or a field tagged settings:"zero" whose
// comment does not state what zero means, which is the promise settings.go's header makes for it.
func settingsCommentFindings(file *ast.File) []string {
	findings := []string{}
	ast.Inspect(file, func(node ast.Node) bool {
		typeSpec, ok := node.(*ast.TypeSpec)
		if !ok || !strings.HasPrefix(typeSpec.Name.Name, "Sidecar") {
			return true
		}
		structType, ok := typeSpec.Type.(*ast.StructType)
		if !ok {
			return true
		}
		for _, field := range structType.Fields.List {
			for _, name := range field.Names {
				if isTunableType(field.Type) && field.Doc == nil {
					findings = append(findings, typeSpec.Name.Name+"."+name.Name+" has no comment")
				}
				if field.Tag != nil && strings.Contains(field.Tag.Value, `settings:"zero"`) &&
					(field.Doc == nil || !strings.Contains(field.Doc.Text(), "Zero ")) {
					findings = append(findings, typeSpec.Name.Name+"."+name.Name+" does not say what zero means")
				}
			}
		}
		return true
	})
	return findings
}

func TestEveryTunableHasItsComment(t *testing.T) {
	settingsFileCount := 0
	for goFile, file := range parseRootFiles(t) {
		if !strings.HasPrefix(goFile, "settings") {
			continue
		}
		settingsFileCount += 1
		for _, finding := range settingsCommentFindings(file) {
			t.Errorf("%s: %s", goFile, finding)
		}
	}
	if settingsFileCount == 0 {
		t.Error("no settings files")
	}
}

func TestTunableRuleCatchesPlantedViolations(t *testing.T) {
	file := parseSyntheticFile(t, `
import "time"
type SidecarThings struct {
	// Five.
	Kept int
	Bare int64
	BareWait time.Duration
	BarePair [2]time.Duration
	// A path, not a number.
	Name string
	// Never says.
	Silent int `+"`settings:\"zero\"`"+`
	// Zero keeps it in memory.
	Stated int `+"`settings:\"zero\"`"+`
}
`)
	want := []string{
		"SidecarThings.Bare has no comment",
		"SidecarThings.BareWait has no comment",
		"SidecarThings.BarePair has no comment",
		"SidecarThings.Silent does not say what zero means",
	}
	if findings := settingsCommentFindings(file); !slices.Equal(findings, want) {
		t.Errorf("findings %q", findings)
	}
}

// Refuses every import, so a check of the root alone ignores what it cannot resolve. An imported
// struct's literal is what go vet's composites reads, so nothing falls between the two.
type noImporter struct{}

// Answers no package.
func (self noImporter) Import(path string) (*types.Package, error) {
	return nil, fmt.Errorf("no %s", path)
}

// Each struct literal in files with a value and no field name. Files of every leg go in together, and
// the type checker's complaints about what they declare twice do not change what a literal's type is.
func positionalLiterals(fileSet *token.FileSet, files []*ast.File) []string {
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}}
	config := types.Config{Importer: noImporter{}, Error: func(error) {}}
	config.Check("sidecar", fileSet, files, info)

	findings := []string{}
	for _, file := range files {
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.CompositeLit)
			if !ok || len(literal.Elts) == 0 {
				return true
			}
			if _, keyed := literal.Elts[0].(*ast.KeyValueExpr); keyed {
				return true
			}
			if typeAndValue, ok := info.Types[literal]; ok && typeAndValue.Type != nil {
				if _, isStruct := typeAndValue.Type.Underlying().(*types.Struct); isStruct {
					findings = append(findings, fileSet.Position(literal.Pos()).String())
				}
			}
			return true
		})
	}
	return findings
}

func TestRootStructLiteralsNameTheirFields(t *testing.T) {
	fileSet := token.NewFileSet()
	files := []*ast.File{}
	for _, goFile := range rootGoFiles(t) {
		file, err := parser.ParseFile(fileSet, goFile, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	for _, finding := range positionalLiterals(fileSet, files) {
		t.Errorf("%s: a struct literal with no field names", finding)
	}
}

func TestPositionalRuleCatchesPlantedViolations(t *testing.T) {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, "synthetic.go", `package sidecar
type pair struct{ a, b int }
var named = pair{a: 1, b: 2}
var positional = pair{1, 2}
var rows = []struct{ a, b int }{{a: 1, b: 2}, {1, 2}}
var list = []int{1, 2}
var table = map[string]int{"a": 1}
`, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"synthetic.go:4:18", "synthetic.go:5:47"}
	if findings := positionalLiterals(fileSet, []*ast.File{file}); !slices.Equal(findings, want) {
		t.Errorf("findings %q", findings)
	}
}
