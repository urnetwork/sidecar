// The guard's reading of store keys, statically and at run time. Statically: every string the engine
// packages build a key from, by the shapes §11.8's and §19.7's keys have, so a builder that adds a family
// fails before anything runs. A key assembled so that no literal shows it is what CheckStores is for.
// At run time: a concrete key, reduced to the family it belongs to.
//
// A family is matched by its prefix, and Redis's by its suffix too, so {acl_}e and {acl_}q are
// separate: a bare {acl_} would cover both.

package sidecartest

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Where a family's literals live, from the top of the repository: every <svc>service, one level
// of child package included (owner rule 5).
var schemaGuardEngineGlobs = []string{"*service/*.go", "*service/*/*.go"}

// What stands for a value in a literal: a format verb, or the rest of a + chain.
const schemaGuardPlaceholder = "\x00"

// fmt's verbs a key builder uses.
var schemaGuardVerbPattern = regexp.MustCompile(`%[0-9.]*[sdxXvq]`)

// A Redis key's opening: a tag whose first word ends in an underscore, or {dns}, §12's one fixed tag.
var schemaGuardRedisLiteralPattern = regexp.MustCompile(`^\{([a-z]+_|dns\})`)

// An object key's opening: its first path element.
var schemaGuardObjectLiteralPattern = regexp.MustCompile(`^([a-z][a-z0-9]*)/`)

// Media type registries' top-level names: application/json is no key.
var schemaGuardMediaTypes = []string{"application", "audio", "font", "image", "message", "model", "multipart", "text", "video"}

// A family a literal builds.
type schemaGuardKeyLiteral struct {
	family MetadataFamily
	// True when the literal does not show its suffix, so any family under the tag may be meant: a
	// constant prefix reads this way, as "{evsq_" does, and so does a suffix built at run time.
	openEnded bool
	// the source text, with a placeholder as <>
	text string
	// file:line, from the top of the repository
	position string
}

// The object family a key is under.
func schemaGuardObjectFamily(key string) MetadataFamily {
	name, _, found := strings.Cut(key, "/")
	if !found {
		return MetadataFamily{Kind: MetadataFamilyObject, Name: key}
	}
	return MetadataFamily{Kind: MetadataFamilyObject, Name: name + "/"}
}

// The Redis family a key is under: its tag's first word, then what follows the tag up to and
// including a colon, past which a key is variable, as in {dns}serial:<root>.
func schemaGuardRedisFamily(key string) MetadataFamily {
	family := MetadataFamily{Kind: MetadataFamilyRedis, Name: key}
	if !strings.HasPrefix(key, "{") {
		return family
	}
	tagEnd := strings.IndexByte(key, '}')
	if tagEnd < 0 {
		return family
	}
	tag := key[1:tagEnd]
	if underscore := strings.IndexByte(tag, '_'); 0 <= underscore {
		tag = tag[:underscore+1]
	}
	suffix := key[tagEnd+1:]
	if colon := strings.IndexByte(suffix, ':'); 0 <= colon {
		suffix = suffix[:colon+1]
	}
	family.Name = "{" + tag + "}" + suffix
	return family
}

// The family text builds, if it reads as a key at all.
func schemaGuardClassifyLiteral(text string) (*schemaGuardKeyLiteral, bool) {
	text = schemaGuardVerbPattern.ReplaceAllString(text, schemaGuardPlaceholder)
	shown := strings.ReplaceAll(text, schemaGuardPlaceholder, "<>")
	if strings.ContainsAny(text, " \t\n") {
		return nil, false
	}
	if schemaGuardRedisLiteralPattern.MatchString(text) {
		family := schemaGuardRedisFamily(text)
		if strings.Contains(family.Name, schemaGuardPlaceholder) {
			// the tag or its suffix is built at run time, so all that shows is the family's start
			tagEnd := strings.IndexAny(text, "_}")
			name := "{" + strings.TrimSuffix(text[1:tagEnd+1], "}") + "}"
			return &schemaGuardKeyLiteral{
				family:    MetadataFamily{Kind: MetadataFamilyRedis, Name: name},
				openEnded: true,
				text:      shown,
			}, true
		}
		if !strings.Contains(text, "}") {
			return &schemaGuardKeyLiteral{
				family:    MetadataFamily{Kind: MetadataFamilyRedis, Name: text + "}"},
				openEnded: true,
				text:      shown,
			}, true
		}
		return &schemaGuardKeyLiteral{family: family, text: shown}, true
	}
	if match := schemaGuardObjectLiteralPattern.FindStringSubmatch(text); match != nil {
		if slices.Contains(schemaGuardMediaTypes, match[1]) {
			return nil, false
		}
		return &schemaGuardKeyLiteral{
			family: MetadataFamily{Kind: MetadataFamilyObject, Name: match[1] + "/"},
			text:   shown,
		}, true
	}
	return nil, false
}

// A string literal's value, or false.
func schemaGuardStringValue(expression ast.Expr) (string, bool) {
	literal, isLiteral := expression.(*ast.BasicLit)
	if !isLiteral || literal.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(literal.Value)
	if err != nil {
		return "", false
	}
	return value, true
}

// A + chain as one text, a placeholder for each operand that is no literal. Each node it read goes in
// used, so the chain is read once, as a whole.
func schemaGuardFlatten(expression ast.Expr, used map[ast.Node]bool) string {
	switch node := expression.(type) {
	case *ast.BinaryExpr:
		if node.Op == token.ADD {
			used[node] = true
			return schemaGuardFlatten(node.X, used) + schemaGuardFlatten(node.Y, used)
		}
	case *ast.ParenExpr:
		return schemaGuardFlatten(node.X, used)
	case *ast.BasicLit:
		if value, isString := schemaGuardStringValue(node); isString {
			used[node] = true
			return value
		}
	}
	return schemaGuardPlaceholder
}

// Every literal key in one file. Imports and struct tags hold strings, and neither is a key.
func schemaGuardFileLiterals(fileSet *token.FileSet, file *ast.File, relativePath string) []*schemaGuardKeyLiteral {
	literals := []*schemaGuardKeyLiteral{}
	add := func(text string, at token.Pos) {
		if literal, isKey := schemaGuardClassifyLiteral(text); isKey {
			literal.position = fmt.Sprintf("%s:%d", relativePath, fileSet.Position(at).Line)
			literals = append(literals, literal)
		}
	}
	used := map[ast.Node]bool{}
	ast.Inspect(file, func(node ast.Node) bool {
		if used[node] {
			return true
		}
		switch expression := node.(type) {
		case *ast.ImportSpec:
			return false
		case *ast.Field:
			if expression.Tag != nil {
				used[expression.Tag] = true
			}
		case *ast.BinaryExpr:
			if expression.Op == token.ADD {
				add(schemaGuardFlatten(expression, used), expression.Pos())
			}
		case *ast.BasicLit:
			if value, isString := schemaGuardStringValue(expression); isString {
				add(value, expression.Pos())
			}
		}
		return true
	})
	return literals
}

// Every key literal in the engine packages and the map's key_sources, in file order.
func (self *SchemaGuard) keyLiterals() ([]*schemaGuardKeyLiteral, error) {
	paths := []string{}
	for _, glob := range slices.Concat(schemaGuardEngineGlobs, self.fieldMap.KeySources) {
		matches, err := filepath.Glob(filepath.Join(self.sources.RootDirectory, glob))
		if err != nil {
			return nil, fmt.Errorf("key source %s: %w", glob, err)
		}
		paths = append(paths, matches...)
	}
	slices.Sort(paths)
	literals := []*schemaGuardKeyLiteral{}
	for _, path := range slices.Compact(paths) {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		fileSet := token.NewFileSet()
		file, err := parser.ParseFile(fileSet, path, source, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		relativePath, err := filepath.Rel(self.sources.RootDirectory, path)
		if err != nil {
			return nil, err
		}
		literals = append(literals, schemaGuardFileLiterals(fileSet, file, relativePath)...)
	}
	return literals, nil
}

// The live rows a literal's family belongs to. A literal that stops inside a tag belongs to every row
// naming a family under that tag.
func (self *SchemaGuard) literalRows(literal *schemaGuardKeyLiteral) []string {
	if !literal.openEnded {
		return self.familyRows[literal.family]
	}
	rowIds := []string{}
	for _, family := range slices.SortedFunc(maps.Keys(self.familyRows), func(a MetadataFamily, b MetadataFamily) int {
		return strings.Compare(a.Name, b.Name)
	}) {
		if family.Kind == MetadataFamilyRedis && strings.HasPrefix(family.Name, literal.family.Name) {
			rowIds = append(rowIds, self.familyRows[family]...)
		}
	}
	return rowIds
}

// Each key literal whose family no live row names, and each not_keys entry naming a literal now gone.
func (self *SchemaGuard) keyLiteralFindings(literals []*schemaGuardKeyLiteral) []string {
	findings := []string{}
	seenTexts := map[string]bool{}
	for _, literal := range literals {
		seenTexts[literal.text] = true
		if _, notKey := self.fieldMap.NotKeys[literal.text]; notKey {
			continue
		}
		if len(self.literalRows(literal)) == 0 {
			findings = append(findings, fmt.Sprintf("%s family %s, from %q at %s, is in no row of metadata_list.yml: §2.8 needs a row first (I-18), and a literal that is no key goes under not_keys in %s", literal.family.Kind, literal.family.Name, literal.text, literal.position, schemaGuardFieldsPath))
		}
	}
	for text := range self.fieldMap.NotKeys {
		if !seenTexts[text] {
			findings = append(findings, fmt.Sprintf("not_keys entry %q matches no literal", text))
		}
	}
	return findings
}
