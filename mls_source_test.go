//go:build !js

// What mls_* must hold, read from its own source: one suite in production, and every secret through a
// hooked function. These parse the package's files, which a Worker has none of, so like style_test.go
// they run on the host alone.

package sidecar

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Nothing outside tests may name the classical suite, so production has exactly one.
func TestMlsProductionCodeBuildsOneSuite(t *testing.T) {
	paths, err := filepath.Glob("mls_*.go")
	if err != nil {
		t.Fatal(err)
	}
	fileSet := token.NewFileSet()
	suiteBuilds := 0
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fileSet, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if name, ok := call.Fun.(*ast.Ident); ok && name.Name == "newMlsCipherSuite" {
				suiteBuilds++
			}
			if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "DHKEM" {
				t.Errorf("%s: names a classical KEM", fileSet.Position(call.Pos()))
			}
			return true
		})
	}
	if suiteBuilds != 1 {
		t.Fatalf("%d suites built outside tests, want mlsSuite alone", suiteBuilds)
	}
}

// Basic credentials read only in the test binary, the way suite 0x0001 is built only there: no file
// that production builds, under any tag, sets the switch that lets them.
func TestMlsProductionCodeReadsNoBasicCredential(t *testing.T) {
	const name = "mlsTestReadsBasicCredentials"
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fileSet := token.NewFileSet()
	declared := 0
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fileSet, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.ValueSpec:
				for _, ident := range node.Names {
					if ident.Name == name {
						declared++
						if len(node.Values) != 0 {
							t.Errorf("%s: declared with a value", fileSet.Position(ident.Pos()))
						}
					}
				}
			case *ast.AssignStmt:
				for _, left := range node.Lhs {
					if ident, ok := left.(*ast.Ident); ok && ident.Name == name {
						t.Errorf("%s: set", fileSet.Position(ident.Pos()))
					}
				}
			case *ast.UnaryExpr:
				if ident, ok := node.X.(*ast.Ident); ok && node.Op == token.AND && ident.Name == name {
					t.Errorf("%s: its address taken", fileSet.Position(ident.Pos()))
				}
			}
			return true
		})
	}
	if declared != 1 {
		t.Fatalf("declared %d times", declared)
	}
}

// A key the hook never saw is a key the privacy harness cannot catch leaking (§22.7). So everything in
// the standard library that produces key material is reachable only from the few functions that hook
// it, and each of those does, and every caller names what it asks for with a literal.
func TestMlsSecretsComeOnlyThroughHookedFunctions(t *testing.T) {
	// the call that produces a secret, by the name it is selected under, and who may make it
	producers := map[string][]string{
		"Extract":        {"extract"},
		"Expand":         {"expandWithLabel"},
		"DeriveKeyPair":  {"deriveKemKey"},
		"GenerateKey":    {"generateKemKey", "generateSignatureKey"},
		"NewPrivateKey":  {"loadKemKey"},
		"NewKeyFromSeed": {"loadSignatureKey"},
		"Read":           {"generateSecret"},
		"Export":         {"externalInitSeal", "externalInitOpen"},
		"NewRecipient":   {"decryptWithLabel", "externalInitOpen"},
	}
	// the functions that take a kind, whose first argument must be a literal or their own kind
	kindTakers := []string{
		"extract", "expandWithLabel", "deriveSecret", "deriveTreeSecret", "decryptWithLabel", "generateSecret",
		"generateKemKey", "deriveKemKey", "loadKemKey", "generateSignatureKey", "loadSignatureKey", "exporter",
	}

	paths, err := filepath.Glob("mls_*.go")
	if err != nil {
		t.Fatal(err)
	}
	fileSet := token.NewFileSet()
	hookers := map[string]bool{}
	var producing []string
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fileSet, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			function, ok := decl.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				var name string
				switch fun := call.Fun.(type) {
				case *ast.Ident:
					name = fun.Name
				case *ast.SelectorExpr:
					name = fun.Sel.Name
				}
				if name == "testHookSecret" || name == "hookKemKey" {
					hookers[function.Name.Name] = true
				}
				if allowed, ok := producers[name]; ok {
					if !slices.Contains(allowed, function.Name.Name) {
						t.Errorf("%s: %s calls %s, which only %v may", fileSet.Position(call.Pos()), function.Name.Name, name, allowed)
					}
					producing = append(producing, function.Name.Name)
				}
				if slices.Contains(kindTakers, name) && 0 < len(call.Args) {
					switch arg := call.Args[0].(type) {
					case *ast.BasicLit:
						if arg.Kind != token.STRING {
							t.Errorf("%s: %s's kind is not a string", fileSet.Position(call.Pos()), name)
						}
					case *ast.Ident:
						if arg.Name != "kind" {
							t.Errorf("%s: %s's kind is %s, not a literal", fileSet.Position(call.Pos()), name, arg.Name)
						}
					case *ast.SelectorExpr:
						// deriveFromEpochSecret's table of literals
						if arg.Sel.Name != "kind" {
							t.Errorf("%s: %s's kind is not a literal", fileSet.Position(call.Pos()), name)
						}
					default:
						t.Errorf("%s: %s's kind is not a literal", fileSet.Position(call.Pos()), name)
					}
				}
				return true
			})
		}
	}
	for _, name := range producing {
		if !hookers[name] {
			t.Errorf("%s produces a secret and hooks nothing", name)
		}
	}
	if len(producing) < len(producers) {
		t.Errorf("found %d producers: the scan has stopped seeing them", len(producing))
	}
}

// expandWithLabel hooks what it expands unless its caller says not to, and only an AEAD nonce may say so (ledger
// QD-755): the three RFC 9420 derives, each of the suite's nonce length. Everything else it expands is a key or a
// secret, and passes true, so no key leaves the hook by this flag.
func TestMlsUnhooksOnlyItsAeadNonces(t *testing.T) {
	nonceKinds := []string{"ratchet_nonce", "sender_data_nonce", "welcome_nonce"}
	// the functions that take the flag, second, and their length, last
	flagTakers := []string{"expandWithLabel", "deriveTreeSecret"}

	paths, err := filepath.Glob("mls_*.go")
	if err != nil {
		t.Fatal(err)
	}
	fileSet := token.NewFileSet()
	unhookedKindCounts := map[string]int{}
	hookedCount := 0
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fileSet, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			function, ok := decl.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || !slices.Contains(flagTakers, selector.Sel.Name) {
					return true
				}
				where := fileSet.Position(call.Pos())
				if len(call.Args) < 3 {
					t.Errorf("%s: %s with %d arguments", where, selector.Sel.Name, len(call.Args))
					return true
				}
				kind := ""
				if literal, ok := call.Args[0].(*ast.BasicLit); ok && literal.Kind == token.STRING {
					kind = strings.Trim(literal.Value, `"`)
				}
				nonceLength := false
				if length, ok := call.Args[len(call.Args)-1].(*ast.SelectorExpr); ok && length.Sel.Name == "aeadNonceLength" {
					nonceLength = true
				}
				flag, ok := call.Args[1].(*ast.Ident)
				if !ok {
					t.Errorf("%s: %s's hook flag is not true, false or its caller's own", where, selector.Sel.Name)
					return true
				}
				switch flag.Name {
				case "true":
					hookedCount += 1
					if slices.Contains(nonceKinds, kind) || strings.Contains(kind, "nonce") || nonceLength {
						t.Errorf("%s: %s hooks a nonce, which the privacy capture refuses", where, selector.Sel.Name)
					}
				case "false":
					if !slices.Contains(nonceKinds, kind) {
						t.Errorf("%s: %s leaves %q unhooked, which only %v may be", where, selector.Sel.Name, kind, nonceKinds)
					}
					if !nonceLength {
						t.Errorf("%s: %s leaves %q unhooked at a length that is not the suite's nonce length", where, selector.Sel.Name, kind)
					}
					unhookedKindCounts[kind] += 1
				case "hook":
					// deriveTreeSecret alone hands its caller's flag on
					if function.Name.Name != "deriveTreeSecret" {
						t.Errorf("%s: %s hands on a hook flag it was given", where, function.Name.Name)
					}
				default:
					t.Errorf("%s: %s's hook flag is %s, not a literal", where, selector.Sel.Name, flag.Name)
				}
				return true
			})
		}
	}
	for _, kind := range nonceKinds {
		if unhookedKindCounts[kind] != 1 {
			t.Errorf("%s is derived unhooked %d times, want once", kind, unhookedKindCounts[kind])
		}
	}
	if hookedCount == 0 {
		t.Errorf("found no hooked expansion: the scan has stopped seeing them")
	}
}
