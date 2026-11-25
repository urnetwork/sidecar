//go:build sidecar_check

// The support log's registry and its analyzer (DESIGN-COMPUTE §28.7, D-SUP-4, §18's Support row). support/registry.yml
// declares every code, field and enum the support log may hold, and the root's support_log_registry.go is generated
// from it, so these rules hold three things:
//
//   - the registry is well formed: unique names and numbers, every field typed, every enum and object declared, and
//     what it states only appended to (a number kept, never reused), as far as one tree can tell;
//   - support_log_registry.go is exactly what the registry generates, so a reviewer reads both diffs;
//   - every write to the support log, in every module of this repository, passes a code constant and, as its fields,
//     direct calls of the constructors that code declares: no spread, no variable code, no field built away from its
//     Event, no SupportLogField literal and no internal field builder outside the support log's own files. This is the
//     analyzer §28.7 asks for, which fails the build for any field that is not a declared type, so no string reaches
//     the ring the registry did not declare.
//
// The sdk, which writes the app's ring, holds its own files to the same rule in its own test
// (sdk/sidecar_support_log_vet_test.go), through the root's exported registry.
//
// Regenerate the root's file with
//   SIDECAR_REGENERATE_SUPPORT_LOG=1 go test -tags sidecar_check -run '^TestSupportLogRegistryIsCurrent$' ./check

package check

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The registry and the file generated from it, relative to the root module.
const (
	supportLogRegistryPath  = "support/registry.yml"
	supportLogGeneratedPath = "support_log_registry.go"
)

// The root's files that implement the support log and may build a field by hand: its own events go through
// encodeEvent's []SupportLogField, which the analyzer reads as it reads Event's.
var supportLogImplementationFiles = []string{"support_log.go", "support_log_bundle.go", supportLogGeneratedPath}

// The field types and token objects §28.7 names.
var (
	supportLogFieldTypes   = []string{"enum", "count", "duration", "size", "version", "boolean", "token"}
	supportLogTokenObjects = []string{"sidecar", "repo", "run", "agent", "enclave", "entry", "request"}
	supportLogSeverities   = []string{"info", "degraded", "failed"}
	supportLogNamePattern  = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)
	// the root's hand-written names a generated enum type must not take
	supportLogReservedEnumNames = []string{
		"code", "component", "field", "field_number", "severity", "writer", "args", "bundle", "bundle_args",
		"bundle_host", "bundle_header", "bundle_event", "bundle_document", "manifest", "code_count", "codes",
		"or_none", "directory", "registry_version", "bundle_format", "bundle_open",
	}
)

// The most fields one code declares: DefaultSupportSettings' EventMaxFieldCount, the ring's format limit.
const supportLogEventMaxFieldCount = 16

// support/registry.yml, as these rules read it: strictly, every key known.
type supportLogRegistry struct {
	Version    int                            `yaml:"version"`
	Buckets    *supportLogRegistryBuckets     `yaml:"buckets"`
	Components []*supportLogRegistryComponent `yaml:"components"`
	Enums      map[string][]string            `yaml:"enums"`
	Fields     []*supportLogRegistryField     `yaml:"fields"`
	Codes      []*supportLogRegistryCode      `yaml:"codes"`
}

type supportLogRegistryBuckets struct {
	Count    []*supportLogRegistryBucket `yaml:"count"`
	Duration []*supportLogRegistryBucket `yaml:"duration"`
	Size     []*supportLogRegistryBucket `yaml:"size"`
}

type supportLogRegistryBucket struct {
	Label string  `yaml:"label"`
	Max   *uint64 `yaml:"max"`
}

type supportLogRegistryComponent struct {
	Name   string `yaml:"name"`
	Number int    `yaml:"number"`
}

type supportLogRegistryField struct {
	Name   string `yaml:"name"`
	Number int    `yaml:"number"`
	Type   string `yaml:"type"`
	Enum   string `yaml:"enum"`
	Object string `yaml:"object"`
}

type supportLogRegistryCode struct {
	Component string   `yaml:"component"`
	Code      string   `yaml:"code"`
	Number    int      `yaml:"number"`
	Severity  string   `yaml:"severity"`
	Fields    []string `yaml:"fields"`
}

// The registry's text parsed strictly: an unknown key, a second document or a tab is refused.
func parseSupportLogRegistry(data []byte) (*supportLogRegistry, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	registry := &supportLogRegistry{}
	if err := decoder.Decode(registry); err != nil {
		return nil, fmt.Errorf("%s: %w", supportLogRegistryPath, err)
	}
	if err := decoder.Decode(&struct{}{}); err == nil {
		return nil, fmt.Errorf("%s holds a second document", supportLogRegistryPath)
	}
	return registry, nil
}

// What is wrong with the registry, each a finding.
func supportLogRegistryFindings(registry *supportLogRegistry) []string {
	findings := []string{}
	if registry.Version < 1 {
		findings = append(findings, findingf("%s's version is %d: it starts at 1", supportLogRegistryPath, registry.Version))
	}
	if registry.Buckets == nil {
		findings = append(findings, findingf("%s declares no buckets", supportLogRegistryPath))
	} else {
		for _, buckets := range []struct {
			name    string
			buckets []*supportLogRegistryBucket
		}{
			{name: "count", buckets: registry.Buckets.Count},
			{name: "duration", buckets: registry.Buckets.Duration},
			{name: "size", buckets: registry.Buckets.Size},
		} {
			if len(buckets.buckets) < 2 {
				findings = append(findings, findingf("the %s buckets need two at least", buckets.name))
				continue
			}
			labels := map[string]bool{}
			for i, bucket := range buckets.buckets {
				last := i == len(buckets.buckets)-1
				switch {
				case bucket.Label == "" || labels[bucket.Label]:
					findings = append(findings, findingf("the %s buckets' label %q is empty or repeated", buckets.name, bucket.Label))
				case last && bucket.Max != nil:
					findings = append(findings, findingf("the %s buckets' last, %q, has a max: it holds everything past the one before", buckets.name, bucket.Label))
				case !last && bucket.Max == nil:
					findings = append(findings, findingf("the %s buckets' %q has no max", buckets.name, bucket.Label))
				case !last && 0 < i && *bucket.Max <= *buckets.buckets[i-1].Max:
					findings = append(findings, findingf("the %s buckets' %q does not rise past the one before", buckets.name, bucket.Label))
				}
				labels[bucket.Label] = true
			}
		}
	}
	components := map[string]bool{}
	componentNumbers := map[int]bool{}
	for _, component := range registry.Components {
		if !supportLogNamePattern.MatchString(component.Name) || components[component.Name] {
			findings = append(findings, findingf("component %q is no snake_case name, or is repeated", component.Name))
		}
		if component.Number < 1 || componentNumbers[component.Number] {
			findings = append(findings, findingf("component %s's number %d is not positive, or is repeated", component.Name, component.Number))
		}
		components[component.Name] = true
		componentNumbers[component.Number] = true
	}
	enumsUsed := map[string]bool{}
	for _, name := range slices.Sorted(maps.Keys(registry.Enums)) {
		values := registry.Enums[name]
		if !supportLogNamePattern.MatchString(name) || slices.Contains(supportLogReservedEnumNames, name) {
			findings = append(findings, findingf("enum %q is no snake_case name, or takes a name the root's support log holds", name))
		}
		if len(values) == 0 {
			findings = append(findings, findingf("enum %s has no values", name))
		}
		seen := map[string]bool{}
		for _, value := range values {
			if !supportLogNamePattern.MatchString(value) || seen[value] {
				findings = append(findings, findingf("enum %s's value %q is no snake_case name, or is repeated", name, value))
			}
			seen[value] = true
		}
	}
	fields := map[string]*supportLogRegistryField{}
	fieldNumbers := map[int]bool{}
	for _, field := range registry.Fields {
		if !supportLogNamePattern.MatchString(field.Name) || fields[field.Name] != nil {
			findings = append(findings, findingf("field %q is no snake_case name, or is repeated", field.Name))
		}
		if field.Number < 1 || fieldNumbers[field.Number] {
			findings = append(findings, findingf("field %s's number %d is not positive, or is repeated", field.Name, field.Number))
		}
		if !slices.Contains(supportLogFieldTypes, field.Type) {
			findings = append(findings, findingf("field %s's type %q is none of %s", field.Name, field.Type, strings.Join(supportLogFieldTypes, ", ")))
		}
		if (field.Type == "enum") != (field.Enum != "") {
			findings = append(findings, findingf("field %s names an enum where its type is not enum, or is an enum naming none", field.Name))
		} else if field.Enum != "" {
			if _, ok := registry.Enums[field.Enum]; !ok {
				findings = append(findings, findingf("field %s's enum %s is not declared", field.Name, field.Enum))
			}
			enumsUsed[field.Enum] = true
		}
		if (field.Type == "token") != (field.Object != "") {
			findings = append(findings, findingf("field %s names an object where its type is not token, or is a token naming none", field.Name))
		} else if field.Object != "" && !slices.Contains(supportLogTokenObjects, field.Object) {
			findings = append(findings, findingf("field %s's object %q is none of %s", field.Name, field.Object, strings.Join(supportLogTokenObjects, ", ")))
		}
		fields[field.Name] = field
		fieldNumbers[field.Number] = true
	}
	for name := range registry.Enums {
		if !enumsUsed[name] {
			findings = append(findings, findingf("enum %s is no field's", name))
		}
	}
	codes := map[string]bool{}
	codeNumbers := map[int]bool{}
	for _, code := range registry.Codes {
		key := code.Component + "." + code.Code
		if !components[code.Component] {
			findings = append(findings, findingf("code %s's component is not declared", key))
		}
		if !supportLogNamePattern.MatchString(code.Code) || codes[key] {
			findings = append(findings, findingf("code %q is no snake_case name, or is repeated", key))
		}
		if code.Number < 1 || codeNumbers[code.Number] {
			findings = append(findings, findingf("code %s's number %d is not positive, or is repeated", key, code.Number))
		}
		if !slices.Contains(supportLogSeverities, code.Severity) {
			findings = append(findings, findingf("code %s's severity %q is none of %s", key, code.Severity, strings.Join(supportLogSeverities, ", ")))
		}
		if supportLogEventMaxFieldCount < len(code.Fields) {
			findings = append(findings, findingf("code %s declares %d fields, past the ring's %d", key, len(code.Fields), supportLogEventMaxFieldCount))
		}
		seen := map[string]bool{}
		for _, field := range code.Fields {
			if fields[field] == nil || seen[field] {
				findings = append(findings, findingf("code %s's field %s is not declared, or is repeated", key, field))
			}
			seen[field] = true
		}
		codes[key] = true
		codeNumbers[code.Number] = true
	}
	return findings
}

// snake_case as a Go name's part: support_log is SupportLog.
func supportLogCamel(name string) string {
	parts := strings.Split(name, "_")
	for i, part := range parts {
		if part != "" {
			parts[i] = strings.ToUpper(part[:1]) + part[1:]
		}
	}
	return strings.Join(parts, "")
}

// The Go names the generated file gives.
func supportLogCodeName(code *supportLogRegistryCode) string {
	return "SupportLogCode" + supportLogCamel(code.Component) + supportLogCamel(code.Code)
}

func supportLogFieldConstructorName(field string) string {
	return "SupportLogField" + supportLogCamel(field)
}

func supportLogFieldNumberName(field string) string {
	return "supportLogFieldNumber" + supportLogCamel(field)
}

func supportLogEnumTypeName(enum string) string {
	return "SupportLog" + supportLogCamel(enum)
}

// The root's support_log_registry.go, as the registry generates it, gofmt'd.
func generateSupportLogRegistry(registry *supportLogRegistry) ([]byte, error) {
	out := &bytes.Buffer{}
	line := func(format string, arguments ...any) {
		fmt.Fprintf(out, format+"\n", arguments...)
	}
	fields := map[string]*supportLogRegistryField{}
	for _, field := range registry.Fields {
		fields[field.Name] = field
	}
	usesTime := slices.ContainsFunc(registry.Fields, func(field *supportLogRegistryField) bool { return field.Type == "duration" })

	line("// Code generated from support/registry.yml by check/support_log_test.go. DO NOT EDIT.")
	line("")
	line("//go:build !ios_extension && !sidecar_http")
	line("")
	line("// The support log's registry, version %d (DESIGN-COMPUTE §28.7): its components, codes, enums and fields, and a", registry.Version)
	line("// constructor for each field, which is the only way to give Event a field. support/registry.yml is the source;")
	line("// regenerate this file with")
	line("//")
	line("//\tSIDECAR_REGENERATE_SUPPORT_LOG=1 go test -tags sidecar_check -run '^TestSupportLogRegistryIsCurrent$' ./check")
	line("")
	line("package sidecar")
	line("")
	if usesTime {
		line("import (")
		line("\t\"time\"")
		line(")")
		line("")
	}
	line("// The registry's version, which every bundle's header names.")
	line("const SupportLogRegistryVersion = %d", registry.Version)
	line("")
	line("// The registry's components.")
	line("const (")
	for _, component := range registry.Components {
		line("\tSupportLogComponent%s SupportLogComponent = %d", supportLogCamel(component.Name), component.Number)
	}
	line(")")
	line("")
	line("// The registry's codes, each with its severity and the fields it declares.")
	line("const (")
	for _, code := range registry.Codes {
		declared := "no fields"
		if 0 < len(code.Fields) {
			declared = strings.Join(code.Fields, ", ")
		}
		line("\t// %s.%s, %s: %s", code.Component, code.Code, code.Severity, declared)
		line("\t%s SupportLogCode = %d", supportLogCodeName(code), code.Number)
	}
	line(")")
	for _, name := range slices.Sorted(maps.Keys(registry.Enums)) {
		typeName := supportLogEnumTypeName(name)
		line("")
		line("// The registry's enum %s.", name)
		line("type %s uint32", typeName)
		line("")
		line("const (")
		for i, value := range registry.Enums[name] {
			line("\t%s%s %s = %d", typeName, supportLogCamel(value), typeName, i+1)
		}
		line(")")
	}
	line("")
	line("// The registry's fields' numbers.")
	line("const (")
	for _, field := range registry.Fields {
		line("\t%s SupportLogFieldNumber = %d", supportLogFieldNumberName(field.Name), field.Number)
	}
	line(")")
	for _, field := range registry.Fields {
		name := supportLogFieldConstructorName(field.Name)
		number := supportLogFieldNumberName(field.Name)
		line("")
		switch field.Type {
		case "enum":
			line("// %s: one of %s's values.", field.Name, field.Enum)
			line("func %s(value %s) SupportLogField {", name, supportLogEnumTypeName(field.Enum))
			line("\treturn supportLogEnumField(%s, uint32(value))", number)
		case "count":
			line("// %s: a count, kept as its bucket.", field.Name)
			line("func %s(count int64) SupportLogField {", name)
			line("\treturn supportLogCountField(%s, count)", number)
		case "duration":
			line("// %s: a duration, kept as its bucket.", field.Name)
			line("func %s(duration time.Duration) SupportLogField {", name)
			line("\treturn supportLogDurationField(%s, duration)", number)
		case "size":
			line("// %s: a size in bytes, kept as its class.", field.Name)
			line("func %s(byteCount int64) SupportLogField {", name)
			line("\treturn supportLogSizeField(%s, byteCount)", number)
		case "version":
			line("// %s: a version, kept only once it passes its format check.", field.Name)
			line("func %s(version string) SupportLogField {", name)
			line("\treturn supportLogVersionField(%s, version)", number)
		case "boolean":
			line("// %s: true or false.", field.Name)
			line("func %s(value bool) SupportLogField {", name)
			line("\treturn supportLogBooleanField(%s, value)", number)
		case "token":
			line("// %s: %s %s's id, kept only as an HMAC under the ring's key.", field.Name, supportLogArticle(field.Object), field.Object)
			line("func %s(id []byte) SupportLogField {", name)
			line("\treturn supportLogTokenField(%s, id)", number)
		}
		line("}")
	}
	line("")
	line("// The registry as tables, which Event and a bundle read.")
	line("var supportLogRegistry = &supportLogRegistryTable{")
	line("\tversion: %d,", registry.Version)
	for _, buckets := range []struct {
		name    string
		buckets []*supportLogRegistryBucket
	}{
		{name: "countBuckets", buckets: registry.Buckets.Count},
		{name: "durationBuckets", buckets: registry.Buckets.Duration},
		{name: "sizeBuckets", buckets: registry.Buckets.Size},
	} {
		line("\t%s: []supportLogBucket{", buckets.name)
		for _, bucket := range buckets.buckets {
			if bucket.Max == nil {
				line("\t\t{label: %s},", strconv.Quote(bucket.Label))
			} else {
				line("\t\t{label: %s, max: %d, bounded: true},", strconv.Quote(bucket.Label), *bucket.Max)
			}
		}
		line("\t},")
	}
	line("\tcomponents: map[SupportLogComponent]string{")
	for _, component := range registry.Components {
		line("\t\tSupportLogComponent%s: %s,", supportLogCamel(component.Name), strconv.Quote(component.Name))
	}
	line("\t},")
	line("\tenums: map[string][]string{")
	for _, name := range slices.Sorted(maps.Keys(registry.Enums)) {
		quoted := []string{}
		for _, value := range registry.Enums[name] {
			quoted = append(quoted, strconv.Quote(value))
		}
		line("\t\t%s: {%s},", strconv.Quote(name), strings.Join(quoted, ", "))
	}
	line("\t},")
	line("\tfields: map[SupportLogFieldNumber]*supportLogFieldRow{")
	for _, field := range registry.Fields {
		row := fmt.Sprintf("name: %s, fieldType: supportLogFieldType%s", strconv.Quote(field.Name), supportLogCamel(field.Type))
		if field.Enum != "" {
			row += ", enum: " + strconv.Quote(field.Enum)
		}
		if field.Object != "" {
			row += ", object: " + strconv.Quote(field.Object)
		}
		line("\t\t%s: {%s},", supportLogFieldNumberName(field.Name), row)
	}
	line("\t},")
	line("\tcodes: map[SupportLogCode]*supportLogCodeRow{")
	for _, code := range registry.Codes {
		numbers := []string{}
		for _, field := range code.Fields {
			numbers = append(numbers, supportLogFieldNumberName(field))
		}
		line("\t\t%s: {component: SupportLogComponent%s, name: %s, severity: SupportLogSeverity%s, fields: []SupportLogFieldNumber{%s}},",
			supportLogCodeName(code), supportLogCamel(code.Component), strconv.Quote(code.Code), supportLogCamel(code.Severity), strings.Join(numbers, ", "))
	}
	line("\t},")
	line("}")
	return format.Source(out.Bytes())
}

// a or an, before an object's name.
func supportLogArticle(word string) string {
	if word != "" && strings.ContainsRune("aeiou", rune(word[0])) {
		return "an"
	}
	return "a"
}

// The registry as the repository holds it: nil with no findings where it holds none, as a fixture does.
func (self *repository) supportLogRegistry() (*supportLogRegistry, []string) {
	data, err := os.ReadFile(filepath.Join(self.moduleDirectory, filepath.FromSlash(supportLogRegistryPath)))
	if errors.Is(err, os.ErrNotExist) {
		if _, err := os.Stat(filepath.Join(self.moduleDirectory, supportLogGeneratedPath)); err == nil {
			return nil, []string{findingf("%s exists and %s does not", supportLogGeneratedPath, supportLogRegistryPath)}
		}
		return nil, nil
	}
	if err != nil {
		return nil, []string{findingf("reading %s: %v", supportLogRegistryPath, err)}
	}
	registry, err := parseSupportLogRegistry(data)
	if err != nil {
		return nil, []string{err.Error()}
	}
	return registry, supportLogRegistryFindings(registry)
}

// The registry's findings and whether the generated file is what it generates.
func (self *repository) supportLogRegistryFindings() []string {
	registry, findings := self.supportLogRegistry()
	if registry == nil || 0 < len(findings) {
		return findings
	}
	want, err := generateSupportLogRegistry(registry)
	if err != nil {
		return []string{findingf("generating %s: %v", supportLogGeneratedPath, err)}
	}
	have, err := os.ReadFile(filepath.Join(self.moduleDirectory, supportLogGeneratedPath))
	if err != nil {
		return []string{findingf("reading %s: %v; regenerate it", supportLogGeneratedPath, err)}
	}
	if !bytes.Equal(have, want) {
		return []string{findingf("%s is not what %s generates: regenerate it", supportLogGeneratedPath, supportLogRegistryPath)}
	}
	return nil
}

// The name an expression is: an identifier, or a selector's name, with its package's name, or "" for neither.
func supportLogExpressionName(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return typed.Sel.Name
	case *ast.ParenExpr:
		return supportLogExpressionName(typed.X)
	}
	return ""
}

// Every write to the support log, in every non-test file of every module, held to the registry: the analyzer.
func (self *repository) supportLogEventFindings(t testing.TB) []string {
	t.Helper()
	registry, findings := self.supportLogRegistry()
	if 0 < len(findings) {
		return findings
	}
	codeFields := map[string][]string{}
	constructors := map[string]bool{}
	if registry != nil {
		for _, code := range registry.Codes {
			for _, field := range code.Fields {
				codeFields[supportLogCodeName(code)] = append(codeFields[supportLogCodeName(code)], supportLogFieldConstructorName(field))
			}
			if code.Fields == nil {
				codeFields[supportLogCodeName(code)] = []string{}
			}
		}
		for _, field := range registry.Fields {
			constructors[supportLogFieldConstructorName(field.Name)] = true
		}
	}
	internalBuilders := []string{
		"supportLogEnumField", "supportLogCountField", "supportLogDurationField", "supportLogSizeField",
		"supportLogVersionField", "supportLogBooleanField", "supportLogTokenField",
	}
	for _, file := range self.sourceFiles(t) {
		if file.isTest {
			continue
		}
		implementation := file.packageName == "." && slices.Contains(supportLogImplementationFiles, path.Base(filepath.ToSlash(file.path)))
		at := func(node ast.Node) string {
			return fmt.Sprintf("%s:%d", self.displayPath(file.path), file.fileSet.Position(node.Pos()).Line)
		}
		// each constructor call that is a direct field of a checked write, which a pass below then allows
		checked := map[ast.Node]bool{}
		check := func(call *ast.CallExpr, codeIndex int) {
			codeName := supportLogExpressionName(call.Args[codeIndex])
			declared, ok := codeFields[codeName]
			if !ok {
				findings = append(findings, findingf("%s: a support log write names %s, which is no code support/registry.yml declares", at(call), codeName))
				return
			}
			fieldExpressions := call.Args[codeIndex+1:]
			if call.Ellipsis.IsValid() {
				findings = append(findings, findingf("%s: %s's write spreads its fields: each must be a constructor call the analyzer reads", at(call), codeName))
				return
			}
			if len(fieldExpressions) == 1 {
				if literal, ok := fieldExpressions[0].(*ast.CompositeLit); ok {
					if _, list := literal.Type.(*ast.ArrayType); list {
						// the support log's own events, through encodeEvent's []SupportLogField
						fieldExpressions = literal.Elts
					}
				}
			}
			for _, expression := range fieldExpressions {
				fieldCall, ok := expression.(*ast.CallExpr)
				name := ""
				if ok {
					name = supportLogExpressionName(fieldCall.Fun)
				}
				if !ok || !slices.Contains(declared, name) {
					findings = append(findings, findingf("%s: %s's write passes a field that is no constructor %s declares", at(expression), codeName, codeName))
					continue
				}
				checked[fieldCall] = true
			}
		}
		ast.Inspect(file.syntax, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			for i, argument := range call.Args {
				if strings.HasPrefix(supportLogExpressionName(argument), "SupportLogCode") {
					if _, isConstant := codeFields[supportLogExpressionName(argument)]; isConstant || strings.HasPrefix(supportLogExpressionName(call.Fun), "Event") || supportLogExpressionName(call.Fun) == "encodeEvent" {
						check(call, i)
					}
					break
				}
			}
			return true
		})
		ast.Inspect(file.syntax, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.CallExpr:
				name := supportLogExpressionName(typed.Fun)
				switch {
				case constructors[name] && !checked[typed]:
					findings = append(findings, findingf("%s: %s builds a field away from a support log write, where the analyzer cannot hold it to a code", at(typed), name))
				case slices.Contains(internalBuilders, name) && !implementation:
					findings = append(findings, findingf("%s: %s is the support log's own builder, which only the generated constructors call", at(typed), name))
				}
			case *ast.CompositeLit:
				if supportLogExpressionName(typed.Type) == "SupportLogField" && !implementation {
					findings = append(findings, findingf("%s: a SupportLogField literal, which only the generated constructors build", at(typed)))
				}
			}
			return true
		})
	}
	slices.Sort(findings)
	return findings
}

// The registry is well formed, and support_log_registry.go is what it generates.
func TestSupportLogRegistryIsCurrent(t *testing.T) {
	repository, err := thisCheckout()
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("SIDECAR_REGENERATE_SUPPORT_LOG") == "1" {
		registry, findings := repository.supportLogRegistry()
		failFindings(t, "support log", findings)
		if registry == nil || 0 < len(findings) {
			t.FailNow()
		}
		generated, err := generateSupportLogRegistry(registry)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(repository.moduleDirectory, supportLogGeneratedPath), generated, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s: %d codes, %d fields", supportLogGeneratedPath, len(registry.Codes), len(registry.Fields))
		return
	}
	failFindings(t, "support log", repository.supportLogRegistryFindings())
}

// Every write to the support log in this repository passes a code constant and the constructors it declares.
func TestSupportLogEventsAreDeclared(t *testing.T) {
	repository, err := thisCheckout()
	if err != nil {
		t.Fatal(err)
	}
	failFindings(t, "support log", repository.supportLogEventFindings(t))
}

// A small registry for the planted tests: one component, one enum, three fields and two codes.
const plantedSupportLogRegistry = `version: 1
buckets:
  count:
    - {label: "0", max: 0}
    - {label: "1+"}
  duration:
    - {label: "<1s", max: 999}
    - {label: "1s+"}
  size:
    - {label: "0", max: 0}
    - {label: "1+"}
components:
  - {name: daemon, number: 1}
enums:
  stop_reason: [idle, failed]
fields:
  - {name: count, number: 1, type: count}
  - {name: stop_reason, number: 2, type: enum, enum: stop_reason}
  - {name: run, number: 3, type: token, object: run}
codes:
  - {component: daemon, code: started, number: 1, severity: info, fields: [count]}
  - {component: daemon, code: stopped, number: 2, severity: info, fields: [stop_reason, run]}
`

// A fixture with the planted registry and a file that writes through it as planted.
func plantSupportLogWrite(t *testing.T, body string) *repository {
	t.Helper()
	fixture := newFixture(t)
	fixture.write(supportLogRegistryPath, plantedSupportLogRegistry)
	fixture.write("daemon_planted.go", "package sidecar\n\nfunc plantedWrite(log SupportLogWriter, id []byte, code SupportLogCode, fields []SupportLogField) {\n"+body+"\n}\n")
	return fixture.open()
}

func TestSupportLogEventsPassAPlantedCleanWrite(t *testing.T) {
	repository := plantSupportLogWrite(t, "\tlog.Event(SupportLogCodeDaemonStopped, SupportLogFieldStopReason(SupportLogStopReasonIdle), SupportLogFieldRun(id))")
	wantFindings(t, repository.supportLogEventFindings(t))
}

func TestSupportLogEventsFailOnAFieldTheCodeDoesNotDeclare(t *testing.T) {
	repository := plantSupportLogWrite(t, "\tlog.Event(SupportLogCodeDaemonStarted, SupportLogFieldRun(id))")
	wantFindings(t, repository.supportLogEventFindings(t),
		"daemon_planted.go:4: SupportLogCodeDaemonStarted's write passes a field that is no constructor SupportLogCodeDaemonStarted declares",
		"daemon_planted.go:4: SupportLogFieldRun builds a field away from a support log write")
}

func TestSupportLogEventsFailOnAFieldThatIsNoConstructor(t *testing.T) {
	repository := plantSupportLogWrite(t, "\tlog.Event(SupportLogCodeDaemonStarted, fields[0])")
	wantFindings(t, repository.supportLogEventFindings(t), "daemon_planted.go:4: SupportLogCodeDaemonStarted's write passes a field that is no constructor")
}

func TestSupportLogEventsFailOnASpread(t *testing.T) {
	repository := plantSupportLogWrite(t, "\tlog.Event(SupportLogCodeDaemonStarted, fields...)")
	wantFindings(t, repository.supportLogEventFindings(t), "daemon_planted.go:4: SupportLogCodeDaemonStarted's write spreads its fields")
}

func TestSupportLogEventsFailOnACodeTheRegistryDoesNotDeclare(t *testing.T) {
	repository := plantSupportLogWrite(t, "\tlog.Event(SupportLogCodeDaemonCrashed, SupportLogFieldCount(1))")
	wantFindings(t, repository.supportLogEventFindings(t),
		"daemon_planted.go:4: SupportLogFieldCount builds a field away from a support log write",
		"daemon_planted.go:4: a support log write names SupportLogCodeDaemonCrashed, which is no code")
}

func TestSupportLogEventsFailOnAFieldBuiltAwayFromItsWrite(t *testing.T) {
	repository := plantSupportLogWrite(t, "\tfield := SupportLogFieldCount(3)\n\tlog.Event(SupportLogCodeDaemonStarted, field)")
	wantFindings(t, repository.supportLogEventFindings(t),
		"daemon_planted.go:4: SupportLogFieldCount builds a field away from a support log write",
		"daemon_planted.go:5: SupportLogCodeDaemonStarted's write passes a field that is no constructor")
}

func TestSupportLogEventsFailOnAFieldLiteral(t *testing.T) {
	repository := plantSupportLogWrite(t, "\tlog.Event(SupportLogCodeDaemonStarted, SupportLogField{})")
	wantFindings(t, repository.supportLogEventFindings(t),
		"daemon_planted.go:4: SupportLogCodeDaemonStarted's write passes a field that is no constructor",
		"daemon_planted.go:4: a SupportLogField literal")
}

func TestSupportLogEventsFailOnAnInternalBuilder(t *testing.T) {
	repository := plantSupportLogWrite(t, "\tlog.Event(SupportLogCodeDaemonStarted, supportLogCountField(1, 2))")
	wantFindings(t, repository.supportLogEventFindings(t),
		"daemon_planted.go:4: SupportLogCodeDaemonStarted's write passes a field that is no constructor",
		"daemon_planted.go:4: supportLogCountField is the support log's own builder")
}

func TestSupportLogRegistryFailsOnAPlantedRepeatedNumber(t *testing.T) {
	registry, err := parseSupportLogRegistry([]byte(strings.Replace(plantedSupportLogRegistry, "{name: run, number: 3", "{name: run, number: 2", 1)))
	if err != nil {
		t.Fatal(err)
	}
	wantFindings(t, supportLogRegistryFindings(registry), "field run's number 2 is not positive, or is repeated")
}

func TestSupportLogRegistryFailsOnAPlantedUndeclaredField(t *testing.T) {
	registry, err := parseSupportLogRegistry([]byte(strings.Replace(plantedSupportLogRegistry, "fields: [count]", "fields: [count, path]", 1)))
	if err != nil {
		t.Fatal(err)
	}
	wantFindings(t, supportLogRegistryFindings(registry), "code daemon.started's field path is not declared, or is repeated")
}

func TestSupportLogRegistryFailsOnAPlantedFreeTextType(t *testing.T) {
	registry, err := parseSupportLogRegistry([]byte(strings.Replace(plantedSupportLogRegistry, "{name: count, number: 1, type: count}", "{name: count, number: 1, type: string}", 1)))
	if err != nil {
		t.Fatal(err)
	}
	wantFindings(t, supportLogRegistryFindings(registry), "field count's type \"string\" is none of enum, count, duration, size, version, boolean, token")
}

func TestSupportLogRegistryRefusesAPlantedUnknownKey(t *testing.T) {
	if _, err := parseSupportLogRegistry([]byte(plantedSupportLogRegistry + "messages: [free]\n")); err == nil {
		t.Fatal("a registry with an unknown key parsed")
	}
}

func TestSupportLogRegistryFailsOnAPlantedStaleGeneratedFile(t *testing.T) {
	fixture := newFixture(t)
	fixture.write(supportLogRegistryPath, plantedSupportLogRegistry)
	fixture.write(supportLogGeneratedPath, "package sidecar\n")
	wantFindings(t, fixture.open().supportLogRegistryFindings(), "support_log_registry.go is not what support/registry.yml generates")
}

func TestSupportLogRegistryFailsOnAGeneratedFileWithoutItsRegistry(t *testing.T) {
	fixture := newFixture(t)
	fixture.write(supportLogGeneratedPath, "package sidecar\n")
	wantFindings(t, fixture.open().supportLogRegistryFindings(), "support_log_registry.go exists and support/registry.yml does not")
}

// The generated file compiles the registry's names as the analyzer reads them.
func TestSupportLogGeneratedNamesMatchTheAnalyzers(t *testing.T) {
	registry, err := parseSupportLogRegistry([]byte(plantedSupportLogRegistry))
	if err != nil {
		t.Fatal(err)
	}
	generated, err := generateSupportLogRegistry(registry)
	if err != nil {
		t.Fatal(err)
	}
	words := strings.Join(strings.Fields(string(generated)), " ")
	for _, name := range []string{"SupportLogCodeDaemonStarted SupportLogCode = 1", "func SupportLogFieldRun(id []byte) SupportLogField", "SupportLogStopReasonIdle SupportLogStopReason = 1"} {
		if !strings.Contains(words, name) {
			t.Errorf("the generated file lacks %q", name)
		}
	}
}
