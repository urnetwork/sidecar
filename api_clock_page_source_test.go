//go:build !js

// Holds api_clock_page_test.go's copy of the lb's expose list to the pagestack fixture's, which a browser
// run answers with (sidecartest/cmd/pagestack), so the list the page Worker's clock tests run on is the
// one the fixture serves. Reads the source tree, so it runs on the host.

package sidecar

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

// The value of the string constant name in the Go file at goFile.
func sourceStringConstant(t *testing.T, goFile string, name string) string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), goFile, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.CONST {
			continue
		}
		for _, spec := range genDecl.Specs {
			valueSpec := spec.(*ast.ValueSpec)
			for i, ident := range valueSpec.Names {
				if ident.Name != name || len(valueSpec.Values) <= i {
					continue
				}
				literal, ok := valueSpec.Values[i].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					t.Fatalf("%s in %s is not a string literal", name, goFile)
				}
				value, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatal(err)
				}
				return value
			}
		}
	}
	t.Fatalf("no constant %s in %s", name, goFile)
	return ""
}

func TestPageWorkerExposeListIsThePagestackFixtures(t *testing.T) {
	fixtureList := sourceStringConstant(t, filepath.Join("sidecartest", "cmd", "pagestack", "main.go"), "pagestackCorsExposeHeaders")
	if fixtureList != testLbCorsExposeHeaders {
		t.Errorf("the pagestack fixture exposes %q, the page Worker's tests run on %q", fixtureList, testLbCorsExposeHeaders)
	}
	// the list before QD-776 is the same list less Date, so the two tests differ in that one word
	names := strings.Split(testLbCorsExposeHeaders, ",")
	if !slices.Contains(names, "Date") {
		t.Fatalf("the lb's list %q does not name Date", testLbCorsExposeHeaders)
	}
	before := slices.DeleteFunc(names, func(name string) bool { return name == "Date" })
	if strings.Join(before, ",") != testLbCorsExposeHeadersBeforeDate {
		t.Errorf("the list before Date is %q", testLbCorsExposeHeadersBeforeDate)
	}
}
