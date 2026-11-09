//go:build sidecar_check

// D-TEST-4's registry (TEST-M1-10): "every 22.6 target ships seeds and, given a second implementation, a
// differential oracle". testdata/fuzz/registry.yml lists each §22.6 bullet with its func Fuzz targets, their
// owning tasks, seed directories and second implementations, and its header says what each field means. This
// rule holds the registry to the code and to §22.6's own text:
//
//   - a func Fuzz with no target in the registry fails, as does a target past its milestone with no func Fuzz;
//   - a target with no seeds fails, and so does a seeds directory that holds no file or a package's own corpus
//     directory the registry does not name;
//   - a crasher that sidecartest.CrasherSeed moved in names a regression test, which must exist, since §22.6
//     makes each crasher a seed and a regression test both;
//   - each §22.6 bullet has one row, by its bold words, and a second implementation or reference a target
//     names is one its package's tests import or declare.
//
// Fuzzing runs nowhere continuously (owner decision 101), so a seed that never runs is the whole risk. The
// static rule cannot see a seed loop over an empty directory, or a build tag that keeps a target out of every
// leg test.sh runs, so TestFuzzSeedsRunUnderTestSh runs each module's targets as test.sh does, with and
// without sidecar_testhooks, and fails a target no seed of which ran.
//
// This package imports no first-party package, so it reads the registry with its own types; nothing else
// reads the file.

package check

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Where the registry and what it is held to sit: the registry and fields.yml move with the root module on a
// release branch, and design/ stays at the repository's top (§4.9).
const (
	fuzzRegistryPath       = "testdata/fuzz/registry.yml"
	fuzzFieldsPath         = "testdata/metadata/fields.yml"
	fuzzSectionPath        = "design/source/sections/22-TEST.md"
	fuzzSectionHeading     = "### 22.6 "
	fuzzCorpusDirectory    = "testdata/fuzz"
	fuzzCrasherFileSuffix  = ".crashers"
	fuzzTestHooksTagForRun = sidecarTestHooksTag
)

var (
	fuzzOwnerPattern     = regexp.MustCompile(`^[A-Z][A-Z0-9]*-M([0-9]|10)-[0-9]{2}$`)
	fuzzMilestonePattern = regexp.MustCompile(`^M([0-9]|10)$`)
	fuzzTargetPattern    = regexp.MustCompile(`^Fuzz[A-Z0-9_][A-Za-z0-9_]*$`)
	fuzzTestPattern      = regexp.MustCompile(`^Test[A-Z0-9_][A-Za-z0-9_]*$`)
)

// One func Fuzz as the registry names it.
type fuzzRegistryTarget struct {
	Name      string   `yaml:"name"`
	Package   string   `yaml:"package"`
	Owner     string   `yaml:"owner"`
	Milestone string   `yaml:"milestone"`
	Seeds     []string `yaml:"seeds"`
	Second    []string `yaml:"second"`
	Reference string   `yaml:"reference"`
}

// One §22.6 bullet, or a target no bullet names.
type fuzzRegistryRow struct {
	Id           string                `yaml:"id"`
	Bullet       string                `yaml:"bullet"`
	Spec         string                `yaml:"spec"`
	Owner        string                `yaml:"owner"`
	Milestone    string                `yaml:"milestone"`
	Differential string                `yaml:"differential"`
	Targets      []*fuzzRegistryTarget `yaml:"targets"`
}

type fuzzRegistry struct {
	Landed string             `yaml:"landed"`
	Rows   []*fuzzRegistryRow `yaml:"rows"`
}

// The target's owner, its own or its row's.
func (self *fuzzRegistryTarget) owner(row *fuzzRegistryRow) string {
	if self.Owner != "" {
		return self.Owner
	}
	return row.Owner
}

// The target's milestone, its own or its row's.
func (self *fuzzRegistryTarget) milestone(row *fuzzRegistryRow) string {
	if self.Milestone != "" {
		return self.Milestone
	}
	return row.Milestone
}

// package name, the key a target and a declaration share
func fuzzTargetKey(packageName string, name string) string {
	return packageName + " " + name
}

// Parses the registry strictly: a field no entry has, a duplicate key, a tab or a second document fails.
func parseFuzzRegistry(data []byte) (*fuzzRegistry, error) {
	if index := bytes.IndexByte(data, '\t'); 0 <= index {
		return nil, fmt.Errorf("line %d holds a tab", 1+bytes.Count(data[:index], []byte("\n")))
	}
	registry := &fuzzRegistry{}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(registry); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("it holds no document")
		}
		return nil, err
	}
	if err := decoder.Decode(&yaml.Node{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("it holds a second document: %v", err)
	}
	return registry, nil
}

// The number in Mn, or -1.
func fuzzMilestoneNumber(milestone string) int {
	match := fuzzMilestonePattern.FindStringSubmatch(milestone)
	if match == nil {
		return -1
	}
	number, _ := strconv.Atoi(match[1])
	return number
}

// §22.6's bullets, by their bold words without the colon, in the section's order.
func fuzzSectionBullets(section []byte) ([]string, error) {
	bullets := []string{}
	inSection := false
	for _, line := range strings.Split(string(section), "\n") {
		if strings.HasPrefix(line, "### ") {
			inSection = strings.HasPrefix(line, fuzzSectionHeading)
			continue
		}
		if !inSection || !strings.HasPrefix(line, "- **") {
			continue
		}
		bold, _, found := strings.Cut(strings.TrimPrefix(line, "- **"), "**")
		if !found {
			return nil, fmt.Errorf("§22.6's bullet %q has no closing bold", line)
		}
		bullets = append(bullets, strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(bold), ":")))
	}
	if len(bullets) == 0 {
		return nil, fmt.Errorf("%s holds no bullet under %q", fuzzSectionPath, fuzzSectionHeading)
	}
	return bullets, nil
}

// A func Fuzz the go command runs as a target: no receiver, a name Fuzz followed by no lower-case letter, and
// one parameter of type *testing.F.
type fuzzDeclaration struct {
	name string
	file *sourceFile
	// the *testing.F parameter's name
	parameter string
	function  *ast.FuncDecl
}

// The package directory the declaration sits in.
func (self *fuzzDeclaration) directory() string {
	return filepath.Dir(self.file.path)
}

// The names testing is imported under in a file.
func testingImportNames(file *ast.File) map[string]bool {
	names := map[string]bool{}
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil || importPath != "testing" {
			continue
		}
		name := "testing"
		if spec.Name != nil {
			name = spec.Name.Name
		}
		names[name] = true
	}
	return names
}

// Whether a parameter's type is *testing.F under one of the names testing is imported as.
func isTestingF(expression ast.Expr, testingNames map[string]bool) bool {
	star, ok := expression.(*ast.StarExpr)
	if !ok {
		return false
	}
	selector, ok := star.X.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "F" {
		return false
	}
	packageIdent, ok := selector.X.(*ast.Ident)
	return ok && testingNames[packageIdent.Name]
}

// Every func Fuzz in this repository's test files, whatever their build constraints.
func (self *repository) fuzzDeclarations(t testing.TB) []*fuzzDeclaration {
	t.Helper()
	declarations := []*fuzzDeclaration{}
	for _, file := range self.sourceFiles(t) {
		if !file.isTest {
			continue
		}
		testingNames := testingImportNames(file.syntax)
		if len(testingNames) == 0 {
			continue
		}
		for _, decl := range file.syntax.Decls {
			function, ok := decl.(*ast.FuncDecl)
			if !ok || function.Recv != nil || !fuzzTargetPattern.MatchString(function.Name.Name) {
				continue
			}
			parameters := function.Type.Params.List
			if len(parameters) != 1 || len(parameters[0].Names) != 1 || !isTestingF(parameters[0].Type, testingNames) {
				continue
			}
			declarations = append(declarations, &fuzzDeclaration{
				name:      function.Name.Name,
				file:      file,
				parameter: parameters[0].Names[0].Name,
				function:  function,
			})
		}
	}
	return declarations
}

// Whether body adds a seed through parameter, itself or through a function of the same package it hands
// parameter to, followed to depth calls. A seed added in a loop counts here; whether the loop ran is
// TestFuzzSeedsRunUnderTestSh's to see.
func addsSeeds(body *ast.BlockStmt, parameter string, packageFunctions map[string]*ast.FuncDecl, depth int) bool {
	if body == nil || parameter == "" || parameter == "_" {
		return false
	}
	adds := false
	ast.Inspect(body, func(node ast.Node) bool {
		if adds {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "Add" {
			if receiver, ok := selector.X.(*ast.Ident); ok && receiver.Name == parameter {
				adds = true
				return false
			}
		}
		helperIdent, ok := call.Fun.(*ast.Ident)
		if !ok || depth <= 0 {
			return true
		}
		helper := packageFunctions[helperIdent.Name]
		if helper == nil || helper.Body == nil {
			return true
		}
		for index, argument := range call.Args {
			argumentIdent, ok := argument.(*ast.Ident)
			if !ok || argumentIdent.Name != parameter {
				continue
			}
			if helperParameter := parameterName(helper, index); addsSeeds(helper.Body, helperParameter, packageFunctions, depth-1) {
				adds = true
				return false
			}
		}
		return true
	})
	return adds
}

// The name of function's parameter at index, or "".
func parameterName(function *ast.FuncDecl, index int) string {
	position := 0
	for _, field := range function.Type.Params.List {
		for _, name := range field.Names {
			if position == index {
				return name.Name
			}
			position += 1
		}
		if len(field.Names) == 0 {
			position += 1
		}
	}
	return ""
}

// The regular files directly in directory, by name; nil when it does not exist.
func fuzzDirectoryFiles(directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names := []string{}
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			names = append(names, entry.Name())
		}
	}
	return names, nil
}

// The registry's findings over this checkout, and the targets still ahead of their milestones, which the
// run reports.
func (self *repository) fuzzRegistryFindings(t testing.TB) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(self.moduleDirectory, filepath.FromSlash(fuzzRegistryPath)))
	if err != nil {
		return []string{findingf("reading %s: %v", fuzzRegistryPath, err)}
	}
	registry, err := parseFuzzRegistry(data)
	if err != nil {
		return []string{findingf("%s: %v", fuzzRegistryPath, err)}
	}
	findings := []string{}

	// landed: the registry's and the schema guard's are one fact, which each gate's sweep raises in both
	landed := fuzzMilestoneNumber(registry.Landed)
	if landed < 0 {
		findings = append(findings, findingf("%s's landed %q is no milestone", fuzzRegistryPath, registry.Landed))
	}
	fieldsData, err := os.ReadFile(filepath.Join(self.moduleDirectory, filepath.FromSlash(fuzzFieldsPath)))
	if err != nil {
		findings = append(findings, findingf("reading %s: %v", fuzzFieldsPath, err))
	} else {
		fields := &struct {
			Landed string `yaml:"landed"`
		}{}
		if err := yaml.Unmarshal(fieldsData, fields); err != nil {
			findings = append(findings, findingf("%s: %v", fuzzFieldsPath, err))
		} else if fields.Landed != registry.Landed {
			findings = append(findings, findingf("%s's landed %s and %s's %s differ: a gate's sweep raises both", fuzzRegistryPath, registry.Landed, fuzzFieldsPath, fields.Landed))
		}
	}

	// §22.6's bullets, one row each
	section, err := os.ReadFile(filepath.Join(self.topDirectory, filepath.FromSlash(fuzzSectionPath)))
	if err != nil {
		findings = append(findings, findingf("reading §22.6: %v", err))
	} else if bullets, err := fuzzSectionBullets(section); err != nil {
		findings = append(findings, findingf("%v", err))
	} else {
		rowBullets := map[string][]string{}
		for _, row := range registry.Rows {
			if row.Bullet != "" {
				rowBullets[row.Bullet] = append(rowBullets[row.Bullet], row.Id)
				if !slices.Contains(bullets, row.Bullet) {
					findings = append(findings, findingf("row %s names the bullet %q, which §22.6 does not hold", row.Id, row.Bullet))
				}
			}
		}
		for _, bullet := range bullets {
			switch ids := rowBullets[bullet]; len(ids) {
			case 0:
				findings = append(findings, findingf("§22.6's bullet %q has no row in %s", bullet, fuzzRegistryPath))
			case 1:
			default:
				findings = append(findings, findingf("§22.6's bullet %q has %d rows: %s", bullet, len(ids), strings.Join(ids, ", ")))
			}
		}
	}

	declarations := self.fuzzDeclarations(t)
	declarationsByKey := map[string]*fuzzDeclaration{}
	for _, declaration := range declarations {
		key := fuzzTargetKey(declaration.file.packageName, declaration.name)
		if other, ok := declarationsByKey[key]; ok {
			findings = append(findings, findingf("%s is declared twice in %s, in %s and %s", declaration.name, declaration.file.packageName, self.displayPath(other.file.path), self.displayPath(declaration.file.path)))
			continue
		}
		declarationsByKey[key] = declaration
	}

	// each package's test files: their functions, by name, and their imports
	packageFunctions := map[string]map[string]*ast.FuncDecl{}
	packageImports := map[string][]string{}
	for _, file := range self.sourceFiles(t) {
		if !file.isTest {
			continue
		}
		directory := filepath.Dir(file.path)
		if packageFunctions[directory] == nil {
			packageFunctions[directory] = map[string]*ast.FuncDecl{}
		}
		for _, decl := range file.syntax.Decls {
			if function, ok := decl.(*ast.FuncDecl); ok && function.Recv == nil {
				packageFunctions[directory][function.Name.Name] = function
			}
		}
		for _, site := range file.imports() {
			packageImports[directory] = append(packageImports[directory], site.importPath)
		}
	}

	ids := map[string]bool{}
	registered := map[string]bool{}
	for _, row := range registry.Rows {
		if row.Id == "" || ids[row.Id] {
			findings = append(findings, findingf("a row's id %q is empty or used twice", row.Id))
		}
		ids[row.Id] = true
		if row.Bullet == "" && row.Spec == "" {
			findings = append(findings, findingf("row %s names neither a §22.6 bullet nor what asks for it", row.Id))
		}
		if !fuzzOwnerPattern.MatchString(row.Owner) {
			findings = append(findings, findingf("row %s's owner %q names no task", row.Id, row.Owner))
		}
		if fuzzMilestoneNumber(row.Milestone) < 0 {
			findings = append(findings, findingf("row %s's milestone %q is no milestone", row.Id, row.Milestone))
		}
		if len(row.Targets) == 0 {
			findings = append(findings, findingf("row %s names no target", row.Id))
		}
		differentialShown := false
		for _, target := range row.Targets {
			key := fuzzTargetKey(target.Package, target.Name)
			if registered[key] {
				findings = append(findings, findingf("%s in %s is in the registry twice", target.Name, target.Package))
			}
			registered[key] = true
			if !fuzzTargetPattern.MatchString(target.Name) {
				findings = append(findings, findingf("row %s's target %q is no fuzz target's name", row.Id, target.Name))
			}
			if target.Package == "" {
				findings = append(findings, findingf("%s names no package", target.Name))
			}
			if target.Owner != "" && !fuzzOwnerPattern.MatchString(target.Owner) {
				findings = append(findings, findingf("%s's owner %q names no task", target.Name, target.Owner))
			}
			milestone := fuzzMilestoneNumber(target.milestone(row))
			if milestone < 0 {
				findings = append(findings, findingf("%s's milestone %q is no milestone", target.Name, target.milestone(row)))
			}
			declaration := declarationsByKey[key]
			if declaration == nil {
				if 0 <= milestone && milestone <= landed {
					findings = append(findings, findingf("%s in %s (%s) is due by M%d, which has landed, and no func %s exists", target.Name, target.Package, target.owner(row), milestone, target.Name))
				} else {
					self.report("fuzz registry: %s in %s (%s, %s) has no func %s yet", target.Name, target.Package, target.owner(row), target.milestone(row), target.Name)
				}
				continue
			}
			directory := declaration.directory()

			// seeds: each named directory holds a file, the package's own corpus is named, and a target with
			// none named adds some in code
			named := map[string]bool{}
			for _, seeds := range target.Seeds {
				seedDirectory := filepath.Clean(filepath.Join(directory, filepath.FromSlash(seeds)))
				named[seedDirectory] = true
				files, err := fuzzDirectoryFiles(seedDirectory)
				switch {
				case err != nil:
					findings = append(findings, findingf("%s's seeds %s: %v", target.Name, seeds, err))
				case len(files) == 0:
					findings = append(findings, findingf("%s's seeds %s hold no file: empty seeds run nothing (D-TEST-4)", target.Name, seeds))
				}
			}
			corpus := filepath.Join(directory, filepath.FromSlash(fuzzCorpusDirectory), target.Name)
			corpusFiles, err := fuzzDirectoryFiles(corpus)
			if err != nil {
				findings = append(findings, findingf("%s's corpus: %v", target.Name, err))
			}
			if 0 < len(corpusFiles) && !named[filepath.Clean(corpus)] {
				findings = append(findings, findingf("%s's corpus %s/%s holds %d seeds the registry does not name", target.Name, fuzzCorpusDirectory, target.Name, len(corpusFiles)))
			}
			if len(target.Seeds) == 0 && len(corpusFiles) == 0 && !addsSeeds(declaration.function.Body, declaration.parameter, packageFunctions[directory], 3) {
				findings = append(findings, findingf("%s in %s has empty seeds: no f.Add, no corpus and none named (D-TEST-4)", target.Name, target.Package))
			}

			// a crasher is a seed and a regression test both (§22.6)
			findings = append(findings, self.fuzzCrasherFindings(declaration, packageFunctions[directory])...)

			// the second implementation and the reference, as the package's tests hold them
			for _, second := range target.Second {
				if !slices.ContainsFunc(packageImports[directory], func(importPath string) bool {
					return importPath == second || strings.HasPrefix(importPath, second+"/")
				}) {
					findings = append(findings, findingf("%s names the second implementation %s, and no test file of %s imports it", target.Name, second, target.Package))
				}
			}
			if target.Reference != "" && packageFunctions[directory][target.Reference] == nil {
				findings = append(findings, findingf("%s names the reference %s, which no test file of %s declares", target.Name, target.Reference, target.Package))
			}
			if 0 < len(target.Second) || target.Reference != "" {
				differentialShown = true
			}
		}
		if row.Differential != "" && !differentialShown {
			if milestone := fuzzMilestoneNumber(row.Milestone); 0 <= milestone && milestone <= landed {
				findings = append(findings, findingf("row %s's bullet names %s, and none of its targets compares against it (D-TEST-4)", row.Id, row.Differential))
			} else {
				self.report("fuzz registry: row %s's differential oracle (%s) is not written yet", row.Id, row.Differential)
			}
		}
	}

	for _, declaration := range declarations {
		if !registered[fuzzTargetKey(declaration.file.packageName, declaration.name)] {
			findings = append(findings, findingf("%s in %s (%s) has no target in %s", declaration.name, declaration.file.packageName, self.displayPath(declaration.file.path), fuzzRegistryPath))
		}
	}
	return findings
}

// What a target's crasher list says, against its corpus and its package's tests: each line names an entry the
// corpus holds and a regression test the package declares, and no list sits beside a target that does not
// exist. sidecartest.CrasherSeed writes both.
func (self *repository) fuzzCrasherFindings(declaration *fuzzDeclaration, functions map[string]*ast.FuncDecl) []string {
	crashersPath := filepath.Join(declaration.directory(), filepath.FromSlash(fuzzCorpusDirectory), declaration.name+fuzzCrasherFileSuffix)
	data, err := os.ReadFile(crashersPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return []string{findingf("%s: %v", self.displayPath(crashersPath), err)}
	}
	findings := []string{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for lineNumber := 1; scanner.Scan(); lineNumber += 1 {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || !fuzzTestPattern.MatchString(fields[1]) {
			findings = append(findings, findingf("%s:%d: %q is not an entry and its regression test", self.displayPath(crashersPath), lineNumber, line))
			continue
		}
		if _, err := os.Stat(filepath.Join(declaration.directory(), filepath.FromSlash(fuzzCorpusDirectory), declaration.name, fields[0])); err != nil {
			findings = append(findings, findingf("%s:%d: the crasher %s is not in %s's corpus, so it runs as no seed", self.displayPath(crashersPath), lineNumber, fields[0], declaration.name))
		}
		if functions[fields[1]] == nil {
			findings = append(findings, findingf("%s:%d: the crasher %s names the regression test %s, which %s's tests do not declare", self.displayPath(crashersPath), lineNumber, fields[0], fields[1], declaration.file.packageName))
		}
	}
	return findings
}

// Crasher lists with no target of their name beside them.
func (self *repository) fuzzOrphanCrasherFindings(t testing.TB) []string {
	t.Helper()
	targets := map[string]bool{}
	directories := map[string]bool{}
	for _, declaration := range self.fuzzDeclarations(t) {
		targets[filepath.Join(declaration.directory(), declaration.name)] = true
	}
	for _, file := range self.sourceFiles(t) {
		directories[filepath.Dir(file.path)] = true
	}
	findings := []string{}
	for _, directory := range slices.Sorted(maps.Keys(directories)) {
		paths, err := filepath.Glob(filepath.Join(directory, filepath.FromSlash(fuzzCorpusDirectory), "*"+fuzzCrasherFileSuffix))
		if err != nil {
			findings = append(findings, findingf("%v", err))
			continue
		}
		for _, crashersPath := range paths {
			name := strings.TrimSuffix(filepath.Base(crashersPath), fuzzCrasherFileSuffix)
			if !targets[filepath.Join(directory, name)] {
				findings = append(findings, findingf("%s lists crashers of %s, which this package does not declare", self.displayPath(crashersPath), name))
			}
		}
	}
	return findings
}

func TestFuzzRegistry(t *testing.T) {
	repository := openThisCheckout(t)
	failFindings(t, "fuzz registry", repository.fuzzRegistryFindings(t))
	failFindings(t, "fuzz registry", repository.fuzzOrphanCrasherFindings(t))
}

// One run of a module's targets, as go test -json reports it.
type fuzzSeedRun struct {
	// seeds that ran, by package import path and target
	seeds map[string]int
	// seeds and targets that failed
	failures []string
}

// One event of go test -json (test2json's TestEvent).
type goTestEvent struct {
	Action  string
	Package string
	Test    string
	Output  string
}

// Runs targets of the packages under moduleDirectory as test.sh's go test does, under tags, and counts the
// seeds that ran. A seed runs as a subtest named <target>/<entry>, whether it came from f.Add or from a
// corpus file.
func runFuzzSeeds(moduleDirectory string, packagePatterns []string, targets []string, tags string) (*fuzzSeedRun, error) {
	quoted := []string{}
	for _, target := range slices.Sorted(slices.Values(targets)) {
		quoted = append(quoted, regexp.QuoteMeta(target))
	}
	arguments := []string{"test", "-count=1", "-json", "-run", "^(" + strings.Join(slices.Compact(quoted), "|") + ")$"}
	if tags != "" {
		arguments = append(arguments, "-tags", tags)
	}
	arguments = append(arguments, packagePatterns...)
	command := exec.Command("go", arguments...)
	command.Dir = moduleDirectory
	command.Env = goEnvironment()
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	runErr := command.Run()
	run := &fuzzSeedRun{seeds: map[string]int{}}
	failedPackages := map[string]bool{}
	output := map[string]*strings.Builder{}
	scanner := bufio.NewScanner(&stdout)
	scanner.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		event := &goTestEvent{}
		if err := json.Unmarshal(line, event); err != nil {
			continue
		}
		target, seed, isSeed := strings.Cut(event.Test, "/")
		switch {
		case event.Action == "output" && event.Test == "":
			if output[event.Package] == nil {
				output[event.Package] = &strings.Builder{}
			}
			output[event.Package].WriteString(event.Output)
		case event.Action == "run" && isSeed:
			run.seeds[fuzzTargetKey(event.Package, target)] += 1
		case event.Action == "fail" && isSeed:
			run.failures = append(run.failures, findingf("%s: seed %s/%s failed under tags %q", event.Package, target, seed, tags))
		case event.Action == "fail" && event.Test == "":
			failedPackages[event.Package] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	for _, packagePath := range slices.Sorted(maps.Keys(failedPackages)) {
		text := ""
		if builder := output[packagePath]; builder != nil {
			text = lastLinesOf(builder.String(), 6)
		}
		run.failures = append(run.failures, findingf("%s failed under tags %q: %s", packagePath, tags, text))
	}
	if runErr != nil && len(run.seeds) == 0 && len(run.failures) == 0 {
		return nil, fmt.Errorf("go %s in %s: %w\n%s", strings.Join(arguments, " "), moduleDirectory, runErr, lastLinesOf(stderr.String(), 12))
	}
	return run, nil
}

// The last count lines of text, for a finding.
func lastLinesOf(text string, count int) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if count < len(lines) {
		lines = lines[len(lines)-count:]
	}
	return strings.Join(lines, "\n")
}

// What test.sh runs of each registered target: every module's targets, untagged and under
// sidecar_testhooks, as its race and testhooks phases run them. A target no seed of which ran under
// either is a finding, and so is a seed that failed.
func (self *repository) fuzzSeedRunFindings(t testing.TB) []string {
	t.Helper()
	modules := self.modules(t)
	// the module each declaration sits in, longest directory first so a nested module is not the root's
	longestFirst := slices.Clone(modules)
	slices.SortFunc(longestFirst, func(a *repositoryModule, b *repositoryModule) int {
		return len(b.directory) - len(a.directory)
	})
	type moduleTargets struct {
		module   *repositoryModule
		patterns map[string]bool
		targets  map[string]bool
		// import path and name of each declaration, the key go test's events give
		keys map[string]string
	}
	byModule := map[string]*moduleTargets{}
	for _, declaration := range self.fuzzDeclarations(t) {
		directory := declaration.directory()
		var owner *repositoryModule
		for _, module := range longestFirst {
			if directory == module.directory || strings.HasPrefix(directory, module.directory+string(filepath.Separator)) {
				owner = module
				break
			}
		}
		if owner == nil {
			continue
		}
		relative, err := filepath.Rel(owner.directory, directory)
		if err != nil {
			continue
		}
		entry := byModule[owner.directory]
		if entry == nil {
			entry = &moduleTargets{module: owner, patterns: map[string]bool{}, targets: map[string]bool{}, keys: map[string]string{}}
			byModule[owner.directory] = entry
		}
		pattern := "./" + filepath.ToSlash(relative)
		if relative == "." {
			pattern = "."
		}
		entry.patterns[pattern] = true
		entry.targets[declaration.name] = true
		importPath := owner.file.Module.Path
		if relative != "." {
			importPath += "/" + filepath.ToSlash(relative)
		}
		entry.keys[fuzzTargetKey(importPath, declaration.name)] = fuzzTargetKey(declaration.file.packageName, declaration.name)
	}
	findings := []string{}
	for _, moduleDirectory := range slices.Sorted(maps.Keys(byModule)) {
		entry := byModule[moduleDirectory]
		ran := map[string]int{}
		for _, tags := range []string{"", fuzzTestHooksTagForRun} {
			run, err := runFuzzSeeds(moduleDirectory, slices.Sorted(maps.Keys(entry.patterns)), slices.Collect(maps.Keys(entry.targets)), tags)
			if err != nil {
				findings = append(findings, findingf("%v", err))
				continue
			}
			for key, count := range run.seeds {
				ran[key] += count
			}
			findings = append(findings, run.failures...)
		}
		for _, key := range slices.Sorted(maps.Keys(entry.keys)) {
			if ran[key] == 0 {
				findings = append(findings, findingf("%s ran no seed under test.sh's go test, untagged or under %s: a seed that never runs is the whole risk (owner decision 101)", entry.keys[key], fuzzTestHooksTagForRun))
			}
		}
		self.report("fuzz seeds: %d targets in %s ran their seeds", len(entry.keys), self.displayPath(moduleDirectory))
	}
	return findings
}

func TestFuzzSeedsRunUnderTestSh(t *testing.T) {
	repository := openThisCheckout(t)
	failFindings(t, "fuzz seeds", repository.fuzzSeedRunFindings(t))
}

// A fixture's registry, fields.yml and §22.6, with one bullet and the targets given.
func plantFuzzRegistry(fixture *fixture, landed string, rows string) {
	fixture.write("testdata/metadata/fields.yml", "landed: "+landed+"\n")
	fixture.write(fuzzRegistryPath, "landed: "+landed+"\nrows:\n"+rows)
	fixture.writeSibling("sidecar/"+fuzzSectionPath, "## 22. Testing\n\n### 22.6 Fuzzing\n\n- **Envelope and bodies:** decoded equal.\n- **Planted parsers** (two of them): total.\n\nSeeds run.\n\n### 22.7 Scenarios\n\n- **Not a fuzz bullet:** ignored.\n")
}

// The clean fixture's rows: both bullets, one target each, seeds in code and in a corpus.
const plantedFuzzRows = `  - id: envelope
    bullet: "Envelope and bodies"
    owner: PROTO-M1-02
    milestone: M1
    targets:
      - {name: FuzzPlantedEnvelope, package: ".", seeds: [testdata/fuzz/FuzzPlantedEnvelope]}
  - id: parsers
    bullet: "Planted parsers"
    owner: MAIL-M7-11
    milestone: M7
    targets:
      - {name: FuzzPlantedParser, package: protocol}
`

// A root target whose seeds are a corpus, and a protocol target whose seeds are f.Add calls through a helper.
func plantFuzzTargets(fixture *fixture) {
	fixture.write("planted_fuzz_test.go", "package sidecar\n\nimport \"testing\"\n\nfunc FuzzPlantedEnvelope(f *testing.F) {\n\tf.Fuzz(func(t *testing.T, input []byte) {})\n}\n")
	fixture.write("testdata/fuzz/FuzzPlantedEnvelope/seed", "go test fuzz v1\n[]byte(\"seed\")\n")
	fixture.write("protocol/planted_fuzz_test.go", "package protocol\n\nimport \"testing\"\n\nfunc addPlantedSeeds(seeder *testing.F) {\n\tseeder.Add([]byte(\"a\"))\n}\n\nfunc FuzzPlantedParser(f *testing.F) {\n\taddPlantedSeeds(f)\n\tf.Fuzz(func(t *testing.T, input []byte) {})\n}\n")
}

func TestFuzzRegistryHoldsOnTheCleanFixture(t *testing.T) {
	fixture := newFixture(t)
	plantFuzzRegistry(fixture, "M2", plantedFuzzRows)
	plantFuzzTargets(fixture)
	wantFindings(t, fixture.open().fuzzRegistryFindings(t))
}

func TestFuzzRegistryFailsOnATargetWithNoRow(t *testing.T) {
	fixture := newFixture(t)
	plantFuzzRegistry(fixture, "M2", plantedFuzzRows)
	plantFuzzTargets(fixture)
	fixture.write("unlisted_fuzz_test.go", "package sidecar\n\nimport \"testing\"\n\nfunc FuzzUnlisted(f *testing.F) {\n\tf.Add(1)\n\tf.Fuzz(func(t *testing.T, n int) {})\n}\n")
	wantFindings(t, fixture.open().fuzzRegistryFindings(t), "FuzzUnlisted in . (unlisted_fuzz_test.go) has no target in testdata/fuzz/registry.yml")
}

// A target past its milestone with no func Fuzz fails; one ahead of it is reported, not failed.
func TestFuzzRegistryFailsOnATargetPastItsMilestone(t *testing.T) {
	fixture := newFixture(t)
	rows := plantedFuzzRows + "      - {name: FuzzLate, package: \".\", owner: CORE-M1-04, milestone: M1}\n      - {name: FuzzAhead, package: \".\", owner: MCP-M3-15, milestone: M3}\n"
	plantFuzzRegistry(fixture, "M2", rows)
	plantFuzzTargets(fixture)
	wantFindings(t, fixture.open().fuzzRegistryFindings(t), "FuzzLate in . (CORE-M1-04) is due by M1, which has landed, and no func FuzzLate exists")
}

func TestFuzzRegistryFailsOnEmptySeeds(t *testing.T) {
	fixture := newFixture(t)
	rows := plantedFuzzRows + "      - {name: FuzzSeedless, package: \".\"}\n      - {name: FuzzEmptyDirectory, package: \".\", seeds: [testdata/fuzz/empty]}\n"
	plantFuzzRegistry(fixture, "M2", rows)
	plantFuzzTargets(fixture)
	fixture.write("seedless_fuzz_test.go", "package sidecar\n\nimport \"testing\"\n\nfunc FuzzSeedless(f *testing.F) {\n\tf.Fuzz(func(t *testing.T, input []byte) {})\n}\n\nfunc FuzzEmptyDirectory(f *testing.F) {\n\tf.Fuzz(func(t *testing.T, input []byte) {})\n}\n")
	if err := os.MkdirAll(filepath.Join(fixture.directory, "sidecar", "testdata", "fuzz", "empty"), 0o700); err != nil {
		t.Fatal(err)
	}
	wantFindings(t, fixture.open().fuzzRegistryFindings(t),
		"FuzzSeedless in . has empty seeds",
		"FuzzEmptyDirectory's seeds testdata/fuzz/empty hold no file",
	)
}

// A corpus go test runs is named in the registry, so the registry's seed column says where every seed is.
func TestFuzzRegistryFailsOnAnUnnamedCorpus(t *testing.T) {
	fixture := newFixture(t)
	plantFuzzRegistry(fixture, "M2", plantedFuzzRows)
	plantFuzzTargets(fixture)
	fixture.write("protocol/testdata/fuzz/FuzzPlantedParser/crasher", "go test fuzz v1\n[]byte(\"x\")\n")
	wantFindings(t, fixture.open().fuzzRegistryFindings(t), "FuzzPlantedParser's corpus testdata/fuzz/FuzzPlantedParser holds 1 seeds the registry does not name")
}

// Every bullet has its row, and a row names only a bullet §22.6 holds.
func TestFuzzRegistryFailsOnABulletWithNoRow(t *testing.T) {
	fixture := newFixture(t)
	rows := strings.Replace(plantedFuzzRows, `bullet: "Planted parsers"`, `bullet: "Planted parser"`, 1)
	plantFuzzRegistry(fixture, "M2", rows)
	plantFuzzTargets(fixture)
	wantFindings(t, fixture.open().fuzzRegistryFindings(t),
		`row parsers names the bullet "Planted parser", which §22.6 does not hold`,
		`§22.6's bullet "Planted parsers" has no row`,
	)
}

func TestFuzzSectionBulletsAreTheBoldWords(t *testing.T) {
	bullets, err := fuzzSectionBullets([]byte("### 22.5 Other\n\n- **Before:** no.\n\n### 22.6 Fuzzing\n\n- **One, two:** x.\n- **Index files** (slots): y.\n- **`SearchRequest` and `SearchReply`** (pads): z.\n  - **nested:** not a bullet of the section's.\n\n### 22.7 After\n\n- **After:** no.\n"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"One, two", "Index files", "`SearchRequest` and `SearchReply`"}; !slices.Equal(bullets, want) {
		t.Fatalf("bullets %q, want %q", bullets, want)
	}
}

// A named second implementation is imported by the package's tests, and a named reference is declared there.
func TestFuzzRegistryFailsOnASecondImplementationNotImported(t *testing.T) {
	fixture := newFixture(t)
	rows := strings.Replace(plantedFuzzRows, "seeds: [testdata/fuzz/FuzzPlantedEnvelope]}", "seeds: [testdata/fuzz/FuzzPlantedEnvelope], second: [crypto/tls], reference: testReferenceEnvelope}", 1)
	plantFuzzRegistry(fixture, "M2", rows)
	plantFuzzTargets(fixture)
	wantFindings(t, fixture.open().fuzzRegistryFindings(t),
		"FuzzPlantedEnvelope names the second implementation crypto/tls, and no test file of . imports it",
		"FuzzPlantedEnvelope names the reference testReferenceEnvelope, which no test file of . declares",
	)
	fixture.write("planted_reference_test.go", "package sidecar\n\nimport \"crypto/tls\"\n\nvar _ = tls.VersionTLS13\n\nfunc testReferenceEnvelope(input []byte) bool {\n\treturn len(input) == 0\n}\n")
	wantFindings(t, fixture.open().fuzzRegistryFindings(t))
}

// A crasher names a regression test that exists, and an entry the corpus holds.
func TestFuzzRegistryFailsOnACrasherWithNoRegressionTest(t *testing.T) {
	fixture := newFixture(t)
	plantFuzzRegistry(fixture, "M2", plantedFuzzRows)
	plantFuzzTargets(fixture)
	fixture.write("testdata/fuzz/FuzzPlantedEnvelope.crashers", "seed TestPlantedEnvelopeRegression\nabsent TestPlantedEnvelopeRegression\n")
	wantFindings(t, fixture.open().fuzzRegistryFindings(t),
		"FuzzPlantedEnvelope.crashers:1: the crasher seed names the regression test TestPlantedEnvelopeRegression",
		"FuzzPlantedEnvelope.crashers:2: the crasher absent is not in FuzzPlantedEnvelope's corpus",
		"FuzzPlantedEnvelope.crashers:2: the crasher absent names the regression test TestPlantedEnvelopeRegression",
	)
	fixture.write("planted_regression_test.go", "package sidecar\n\nimport \"testing\"\n\nfunc TestPlantedEnvelopeRegression(t *testing.T) {}\n")
	fixture.write("testdata/fuzz/FuzzPlantedEnvelope.crashers", "seed TestPlantedEnvelopeRegression\n")
	wantFindings(t, fixture.open().fuzzRegistryFindings(t))
	fixture.write("testdata/fuzz/FuzzGone.crashers", "seed TestPlantedEnvelopeRegression\n")
	wantFindings(t, fixture.open().fuzzOrphanCrasherFindings(t), "FuzzGone.crashers lists crashers of FuzzGone, which this package does not declare")
}

// The registry and fields.yml carry one landed milestone.
func TestFuzzRegistryFailsWhenLandedParts(t *testing.T) {
	fixture := newFixture(t)
	plantFuzzRegistry(fixture, "M2", plantedFuzzRows)
	plantFuzzTargets(fixture)
	fixture.write("testdata/metadata/fields.yml", "landed: M3\n")
	wantFindings(t, fixture.open().fuzzRegistryFindings(t), "testdata/fuzz/registry.yml's landed M2 and testdata/metadata/fields.yml's M3 differ")
}

// The static rule sees f.Add in a loop and passes; only running the seeds shows the loop ran over nothing.
// The run also sees a seed that test.sh's legs never build: a target behind a tag test.sh does not set.
func TestFuzzSeedsFailOnALoopOverNothing(t *testing.T) {
	fixture := newFixture(t)
	rows := plantedFuzzRows + "      - {name: FuzzLoopsOverNothing, package: \".\", seeds: [testdata/fuzz/loop]}\n      - {name: FuzzNeverBuilt, package: \".\"}\n"
	plantFuzzRegistry(fixture, "M2", rows)
	plantFuzzTargets(fixture)
	fixture.write("testdata/fuzz/loop/README", "a file that is no seed\n")
	fixture.write("loop_fuzz_test.go", "package sidecar\n\nimport (\n\t\"os\"\n\t\"strings\"\n\t\"testing\"\n)\n\n"+
		"func FuzzLoopsOverNothing(f *testing.F) {\n\tentries, _ := os.ReadDir(\"testdata/fuzz/loop\")\n\tfor _, entry := range entries {\n\t\tif strings.HasSuffix(entry.Name(), \".seed\") {\n\t\t\tf.Add([]byte(entry.Name()))\n\t\t}\n\t}\n\tf.Fuzz(func(t *testing.T, input []byte) {})\n}\n")
	fixture.write("never_fuzz_test.go", "//go:build sidecar_never\n\npackage sidecar\n\nimport \"testing\"\n\nfunc FuzzNeverBuilt(f *testing.F) {\n\tf.Add(1)\n\tf.Fuzz(func(t *testing.T, n int) {})\n}\n")
	repository := fixture.open()
	wantFindings(t, repository.fuzzRegistryFindings(t))
	wantFindings(t, repository.fuzzSeedRunFindings(t),
		"FuzzLoopsOverNothing ran no seed under test.sh's go test",
		"FuzzNeverBuilt ran no seed under test.sh's go test",
	)
}
