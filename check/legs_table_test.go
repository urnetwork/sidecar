//go:build sidecar_check

// The every-leg runner's table against this package's (TEST-M1-07; D-TEST-1): sidecartest/legs runs the
// tests of the legs defaultBuildLegs names, and since this package is tagged and cannot be imported, the
// runner's table is read from its source. Every leg it runs is a leg here, with the same module, target,
// cgo and tags, and every test leg here, the sidecar_http js leg and each gomobile leg has a row there,
// so a leg added to either table and not the other fails.

package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The runner's source, relative to the root module.
const legRunnerTablePath = "sidecartest/legs/legs.go"

// One row of the runner's table, as its literal writes it.
type legRunnerRow struct {
	name   string
	module string
	goos   string
	goarch string
	cgo    bool
	tags   []string
	line   int
}

// The literals of DefaultLegs in source, or in fileName's file when source is nil, each a row.
func legRunnerRows(source any, fileName string) ([]*legRunnerRow, error) {
	fileSet := token.NewFileSet()
	syntax, err := parser.ParseFile(fileSet, fileName, source, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	rows := []*legRunnerRow{}
	for _, declaration := range syntax.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "DefaultLegs" || function.Body == nil {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			literal, ok := node.(*ast.CompositeLit)
			if !ok || literal.Type != nil {
				return true
			}
			row := &legRunnerRow{line: fileSet.Position(literal.Pos()).Line}
			for _, element := range literal.Elts {
				keyValue, ok := element.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := keyValue.Key.(*ast.Ident)
				if !ok {
					continue
				}
				switch value := keyValue.Value.(type) {
				case *ast.BasicLit:
					text, err := strconv.Unquote(value.Value)
					if err != nil {
						continue
					}
					switch key.Name {
					case "Name":
						row.name = text
					case "Module":
						row.module = text
					case "Goos":
						row.goos = text
					case "Goarch":
						row.goarch = text
					}
				case *ast.Ident:
					if key.Name == "Cgo" {
						row.cgo = value.Name == "true"
					}
				case *ast.CompositeLit:
					if key.Name == "Tags" {
						for _, tag := range value.Elts {
							if tagLiteral, ok := tag.(*ast.BasicLit); ok {
								if text, err := strconv.Unquote(tagLiteral.Value); err == nil {
									row.tags = append(row.tags, text)
								}
							}
						}
					}
				}
			}
			if row.name != "" {
				rows = append(rows, row)
			}
			return false
		})
	}
	return rows, nil
}

// Where the runner's table and this package's legs differ.
func legTableFindings(rows []*legRunnerRow, legs []*buildLeg) []string {
	findings := []string{}
	legsByName := map[string]*buildLeg{}
	for _, leg := range legs {
		legsByName[leg.name] = leg
	}
	runnerNames := map[string]bool{}
	for _, row := range rows {
		runnerNames[row.name] = true
		leg, found := legsByName[row.name]
		if !found {
			findings = append(findings, findingf("%s:%d: the runner runs %q, which is no leg of check/'s", legRunnerTablePath, row.line, row.name))
			continue
		}
		tags := slices.Sorted(slices.Values(row.tags))
		legTags := slices.Sorted(slices.Values(leg.tags))
		if row.module != leg.moduleName || row.goos != leg.goos || row.goarch != leg.goarch || row.cgo != leg.cgoEnabled || !slices.Equal(tags, legTags) {
			findings = append(findings, findingf("%s:%d: %s builds as %s %s/%s cgo %t tags %v, and check/'s leg as %s %s/%s cgo %t tags %v",
				legRunnerTablePath, row.line, row.name, row.module, row.goos, row.goarch, row.cgo, tags,
				leg.moduleName, leg.goos, leg.goarch, leg.cgoEnabled, legTags))
		}
	}
	for _, leg := range legs {
		runs := leg.test || leg.hasTag(sidecarHttpTag) || strings.HasPrefix(leg.name, "gomobile ")
		if runs && !runnerNames[leg.name] {
			findings = append(findings, findingf("check/'s leg %q has no row in %s, so no runner reports it", leg.name, legRunnerTablePath))
		}
	}
	return findings
}

// The runner's table matches this package's legs, both ways.
func TestLegRunnerTableMatchesCheck(t *testing.T) {
	repository, err := thisCheckout()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repository.moduleDirectory, legRunnerTablePath)
	rows, err := legRunnerRows(nil, path)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatalf("%s's DefaultLegs holds no row", legRunnerTablePath)
	}
	failFindings(t, "legs", legTableFindings(rows, defaultBuildLegs()))
}

// A runner row naming no leg, one building differently, and a test leg with no row each fail.
func TestLegRunnerTableFailsOnADrift(t *testing.T) {
	source := `package legs

func DefaultLegs() []*Leg {
	return []*Leg{
		{Name: "tests darwin/arm64", Module: ".", Goos: "darwin", Goarch: "arm64"},
		{Name: "tests js/wasm", Module: ".", Goos: "js", Goarch: "wasm", Tags: []string{"sidecar_http"}},
		{Name: "tests plan9/amd64", Module: ".", Goos: "plan9", Goarch: "amd64"},
	}
}
`
	rows, err := legRunnerRows(source, "legs.go")
	if err != nil {
		t.Fatal(err)
	}
	legs := []*buildLeg{}
	for _, leg := range defaultBuildLegs() {
		if leg.name == "tests darwin/arm64" || leg.name == "tests js/wasm" || leg.name == "tests windows/amd64" {
			legs = append(legs, leg)
		}
	}
	wantFindings(t, legTableFindings(rows, legs),
		`tests js/wasm builds as . js/wasm cgo false tags [sidecar_http]`,
		`the runner runs "tests plan9/amd64", which is no leg of check/'s`,
		`check/'s leg "tests windows/amd64" has no row`,
	)
}
