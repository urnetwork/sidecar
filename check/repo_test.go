//go:build sidecar_check

// Reads a checkout of this repository: where its modules are, what their module files say and what
// its Go files declare. A repository is built over a real checkout or a fixture alike, in the
// development layout or a release branch's, so a rule never names a path on its own.
//
// Everything here is safe for concurrent use: rules run in parallel tests over one repository.

package check

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// First-party module paths. Each is spelled in two pieces because the release rewrites every quoted
// path of ours in every .go file (build/all/run.sh:1560-1566), which would turn a table here into
// the release's spelling and a fixture's text into a module nothing provides.
// TestNoQuotedFirstPartyPathHere holds that.
const (
	urnetworkPrefix    = "github.com/" + "urnetwork/"
	urfoundationPrefix = "github.com/" + "urfoundation/"

	sidecarBasePath = urnetworkPrefix + "sidecar"
	connectBasePath = urnetworkPrefix + "connect"
	glogBasePath    = urnetworkPrefix + "glog"
	serverBasePath  = urnetworkPrefix + "server"
	sdkBasePath     = urnetworkPrefix + "sdk"
	snBasePath      = urfoundationPrefix + "sn"
	warpBasePath    = urnetworkPrefix + "warp"

	// connect's replaced forks (§4.7)
	sctpBasePath   = "github.com/pion/sctp"
	gvisorBasePath = "gvisor.dev/gvisor"
	// the release replaces gVisor with this fork at a version (build/all/run.sh:1551)
	gvisorReleaseFork = urnetworkPrefix + "gvisor"

	protobufBasePath = "google.golang.org/protobuf"
	xTextBasePath    = "golang.org/x/text"
)

// The build tags the rules read.
const (
	sidecarTestHooksTag = "sidecar_testhooks"
	sidecarLeakTestTag  = "sidecar_leaktest"
	sidecarHttpTag      = "sidecar_http"
	mobileBindTag       = "sdk_mobile_bind"
	iosExtensionTag     = "ios_extension"
)

// Names the walks do not enter: git's objects, documents that hold no Go, and fixtures another
// test owns.
var skippedDirectoryNames = map[string]bool{
	".git":           true,
	"design":         true,
	"node_modules":   true,
	"research_notes": true,
	"testdata":       true,
}

// A path element of the release's kind, such as v2026.
var versionElementPattern = regexp.MustCompile(`^v[0-9]+$`)

// True when path is root or lies beneath it, by whole path elements.
func underPath(path string, root string) bool {
	return path == root || strings.HasPrefix(path, root+"/")
}

// A first-party path without the release's /vN elements, so github.com/... /sidecar/v2026/protocol
// compares equal to its development spelling. A third party's path is its name, /v3 included.
func firstPartyBase(importPath string) string {
	if !strings.HasPrefix(importPath, urnetworkPrefix) && !strings.HasPrefix(importPath, urfoundationPrefix) {
		return importPath
	}
	elements := strings.Split(importPath, "/")
	keptElements := make([]string, 0, len(elements))
	for _, element := range elements {
		if !versionElementPattern.MatchString(element) {
			keptElements = append(keptElements, element)
		}
	}
	return strings.Join(keptElements, "/")
}

// go mod edit -json's reading of one module file, the go command's own parser.
type moduleFile struct {
	Module struct {
		Path string
	}
	Go      string
	Require []struct {
		Path     string
		Version  string
		Indirect bool
	}
	Replace []struct {
		Old struct {
			Path    string
			Version string
		}
		New struct {
			Path    string
			Version string
		}
	}
	Tool []struct {
		Path string
	}
}

// One go.mod of this repository.
type repositoryModule struct {
	directory string
	// its path without the release's /vN elements
	basePath string
	// "." for the root module, else cli, smtpproof, mlsinterop or sidecarctl as it would be in
	// development
	relativeName string
	file         *moduleFile
}

// A Go file of this repository, whatever its build constraints.
type sourceFile struct {
	path string
	// the package's directory relative to its module, with the module's relativeName in front, so
	// "." is the root package and protocol/bridge reads the same on a release branch
	packageName string
	// the name in the package clause
	clauseName string
	isTest     bool
	// nil without a //go:build line
	constraint constraint.Expr
	syntax     *ast.File
	fileSet    *token.FileSet
}

// A checkout, as the rules read it.
type repository struct {
	settings *checkSettings
	legs     []*buildLeg
	// where the root go.mod is
	moduleDirectory string
	// the directory the nested modules sit in: moduleDirectory, or on a release branch its parent
	topDirectory string
	// from go.mod, so .../sidecar/v2026 on a release branch
	modulePath string
	// the directory next to the checkout that holds connect, sdk and the other siblings
	siblingsDirectory string
	// /v2026 on a release branch, else empty
	releaseSuffix string
	// goes to the test's log, for what a passing run should still say
	report func(format string, arguments ...any)

	stateLock sync.Mutex
	// each computed once; a rule reads them through the methods below
	closureLegOnces map[string]*legClosureOnce
	exportLegOnces  map[string]*legExportOnce
	modulesOnce     func() ([]*repositoryModule, error)
	sourceFilesOnce func() ([]*sourceFile, error)
	stdPackagesOnce func() (map[string]bool, error)
}

// Opens the checkout whose root module is in moduleDirectory.
func openRepository(moduleDirectory string, settings *checkSettings, legs []*buildLeg) (*repository, error) {
	moduleDirectory, err := filepath.Abs(moduleDirectory)
	if err != nil {
		return nil, err
	}
	// the go command reports physical paths, and an overlay only matches those
	moduleDirectory, err = filepath.EvalSymlinks(moduleDirectory)
	if err != nil {
		return nil, err
	}
	file, err := readModuleFile(filepath.Join(moduleDirectory, "go.mod"))
	if err != nil {
		return nil, err
	}
	if firstPartyBase(file.Module.Path) != sidecarBasePath {
		return nil, fmt.Errorf("%s is the module %s, not this repository's root", moduleDirectory, file.Module.Path)
	}
	self := &repository{
		settings:          settings,
		legs:              legs,
		moduleDirectory:   moduleDirectory,
		topDirectory:      moduleDirectory,
		modulePath:        file.Module.Path,
		siblingsDirectory: filepath.Dir(moduleDirectory),
		report:            func(string, ...any) {},
		closureLegOnces:   map[string]*legClosureOnce{},
		exportLegOnces:    map[string]*legExportOnce{},
	}
	if suffix := strings.TrimPrefix(file.Module.Path, sidecarBasePath); suffix != "" {
		// §4.9's release tree: v2026/ beside the nested modules, which stay in place
		self.releaseSuffix = suffix
		self.topDirectory = filepath.Dir(moduleDirectory)
		self.siblingsDirectory = filepath.Dir(self.topDirectory)
	}
	self.modulesOnce = sync.OnceValues(self.readModules)
	self.sourceFilesOnce = sync.OnceValues(self.readSourceFiles)
	self.stdPackagesOnce = sync.OnceValues(self.readStdPackages)
	return self, nil
}

// What goEnvironment sets, each to what every rule's go command runs with. GOENV=off keeps the
// caller's go env file, which go env -w writes, from every rule: the go command reads a setting from
// that file whenever its variable is empty, so clearing a variable alone hands the file's value to
// every leg.
var goEnvironmentSet = []string{"GOFLAGS=-trimpath", "GOWORK=off", "GOTOOLCHAIN=local", "GOENV=off"}

// What goEnvironment clears, so the go command takes its own default: everything that picks a target,
// selects files or changes how they compile. A leg sets GOOS, GOARCH and CGO_ENABLED again for itself.
var goEnvironmentCleared = []string{
	"GOOS", "GOARCH", "CGO_ENABLED", "GOEXPERIMENT", "GO111MODULE", "GOFIPS140",
	"GO386", "GOAMD64", "GOARM", "GOARM64", "GOMIPS", "GOMIPS64", "GOPPC64", "GORISCV64", "GOWASM",
	"GO_EXTLINK_ENABLED", "AR", "CC", "CXX", "FC", "GCCGO", "PKG_CONFIG",
	"CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS",
	"CGO_CFLAGS_ALLOW", "CGO_CFLAGS_DISALLOW", "CGO_CPPFLAGS_ALLOW", "CGO_CPPFLAGS_DISALLOW",
	"CGO_CXXFLAGS_ALLOW", "CGO_CXXFLAGS_DISALLOW", "CGO_FFLAGS_ALLOW", "CGO_FFLAGS_DISALLOW",
	"CGO_LDFLAGS_ALLOW", "CGO_LDFLAGS_DISALLOW",
}

// What goEnvironment keeps from the caller: which toolchain runs, and where modules are fetched from
// and kept. None of it changes what a leg is, since a module's bytes are held to go.sum wherever they
// came from, and a host may need its own.
var goEnvironmentKept = []string{
	"GOROOT", "GOTOOLDIR", "GOPATH", "GOMODCACHE", "GOCACHE", "GOCACHEPROG", "GOTMPDIR", "GOBIN",
	"GOPROXY", "GONOPROXY", "GOSUMDB", "GONOSUMDB", "GOPRIVATE", "GOINSECURE", "GOVCS", "GOAUTH",
}

// What the go command reports and never reads.
var goEnvironmentComputed = []string{"GOEXE", "GOGCCFLAGS", "GOHOSTARCH", "GOHOSTOS"}

// The environment every go command runs in. A leg is exactly what it names, so what the caller
// configured never reaches a build: GOFLAGS is the shared -trimpath and nothing else, the go env file
// is not read, and every setting that could change a closure or a compile is cleared.
// TestGoEnvironmentDecidesEveryGoSetting holds the lists above to the go command's own. A tag in the
// host's GOFLAGS, wherever the host keeps it, is read by hostGoflagsFindings instead.
func goEnvironment(extra ...string) []string {
	return goEnvironmentOver(os.Environ(), extra...)
}

// goEnvironment over a given caller's environment.
func goEnvironmentOver(base []string, extra ...string) []string {
	environment := slices.Clone(base)
	environment = append(environment, goEnvironmentSet...)
	for _, key := range goEnvironmentCleared {
		environment = append(environment, key+"=")
	}
	return append(environment, extra...)
}

// Runs the go command in directory and returns its stdout. stderr carries progress such as module
// downloads, and comes back only inside the error.
func runGo(directory string, environment []string, arguments ...string) ([]byte, error) {
	command := exec.Command("go", arguments...)
	command.Dir = directory
	command.Env = environment
	output, err := command.Output()
	if err != nil {
		stderr := ""
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			stderr = string(exitError.Stderr)
		}
		return nil, fmt.Errorf("go %s in %s: %w\n%s", strings.Join(arguments, " "), directory, err, stderr)
	}
	return output, nil
}

// One module file, through the go command.
func readModuleFile(goModPath string) (*moduleFile, error) {
	output, err := runGo(filepath.Dir(goModPath), goEnvironment(), "mod", "edit", "-json", goModPath)
	if err != nil {
		return nil, err
	}
	file := &moduleFile{}
	if err := json.Unmarshal(output, file); err != nil {
		return nil, fmt.Errorf("reading %s: %w", goModPath, err)
	}
	return file, nil
}

// Every module file in this checkout, by directory.
func (self *repository) modules(t testing.TB) []*repositoryModule {
	t.Helper()
	modules, err := self.modulesOnce()
	if err != nil {
		t.Fatal(err)
	}
	return modules
}

// The module that relativeName names, or nil.
func (self *repository) module(t testing.TB, relativeName string) *repositoryModule {
	t.Helper()
	for _, module := range self.modules(t) {
		if module.relativeName == relativeName {
			return module
		}
	}
	return nil
}

// Walks the top directory for module files. Each is read by the go command. A go.mod-shaped
// alternate module file counts too, because a build can name one with -modfile and no leg would
// see it.
func (self *repository) readModules() ([]*repositoryModule, error) {
	modules := []*repositoryModule{}
	err := filepath.WalkDir(self.topDirectory, func(walkPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if skippedDirectoryNames[entry.Name()] && walkPath != self.topDirectory {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Name() != "go.mod" && !strings.HasSuffix(entry.Name(), ".go.mod") {
			return nil
		}
		file, err := readModuleFile(walkPath)
		if err != nil {
			return err
		}
		basePath := firstPartyBase(file.Module.Path)
		relativeName := "."
		if basePath != sidecarBasePath {
			relativeName = strings.TrimPrefix(basePath, sidecarBasePath+"/")
		}
		modules = append(modules, &repositoryModule{
			directory:    filepath.Dir(walkPath),
			basePath:     basePath,
			relativeName: relativeName,
			file:         file,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(modules, func(a *repositoryModule, b *repositoryModule) int {
		return strings.Compare(a.directory, b.directory)
	})
	return modules, nil
}

// Every Go file in this checkout.
func (self *repository) sourceFiles(t testing.TB) []*sourceFile {
	t.Helper()
	files, err := self.sourceFilesOnce()
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// Parses every .go file of every module, build constraints aside. A file that no leg compiles is
// still read here, which is what lets the rules see an import behind a tag nobody sets.
func (self *repository) readSourceFiles() ([]*sourceFile, error) {
	modules, err := self.modulesOnce()
	if err != nil {
		return nil, err
	}
	// longest directory first, so a nested module's files are not read as the root's
	longestFirst := slices.Clone(modules)
	slices.SortFunc(longestFirst, func(a *repositoryModule, b *repositoryModule) int {
		return len(b.directory) - len(a.directory)
	})
	files := []*sourceFile{}
	err = filepath.WalkDir(self.topDirectory, func(walkPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if skippedDirectoryNames[entry.Name()] && walkPath != self.topDirectory {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") {
			return nil
		}
		directory := filepath.Dir(walkPath)
		var owner *repositoryModule
		for _, module := range longestFirst {
			if directory == module.directory || strings.HasPrefix(directory, module.directory+string(filepath.Separator)) {
				owner = module
				break
			}
		}
		if owner == nil {
			return fmt.Errorf("%s is in no module", walkPath)
		}
		fileSet := token.NewFileSet()
		syntax, err := parser.ParseFile(fileSet, walkPath, nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		relativeDirectory, err := filepath.Rel(owner.directory, directory)
		if err != nil {
			return err
		}
		packageName := path.Join(owner.relativeName, filepath.ToSlash(relativeDirectory))
		expression, err := fileConstraint(syntax)
		if err != nil {
			return fmt.Errorf("%s: %w", walkPath, err)
		}
		files = append(files, &sourceFile{
			path:        walkPath,
			packageName: packageName,
			clauseName:  syntax.Name.Name,
			isTest:      strings.HasSuffix(entry.Name(), "_test.go"),
			constraint:  expression,
			syntax:      syntax,
			fileSet:     fileSet,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

// The expression on a file's //go:build line, or nil. Only a comment above the package clause
// counts, as the go command reads it. The go command still honors // +build lines in a file with no
// //go:build line, and these rules read none, so such a file is refused rather than read as
// unconstrained: `// +build sidecar_testhooks linux` would put a file in every linux release with
// no rule seeing it answer to the tag. gofmt writes the //go:build line beside them.
func fileConstraint(syntax *ast.File) (constraint.Expr, error) {
	plusBuild := false
	for _, group := range syntax.Comments {
		if group.Pos() >= syntax.Package {
			break
		}
		for _, comment := range group.List {
			if constraint.IsGoBuild(comment.Text) {
				return constraint.Parse(comment.Text)
			}
			if constraint.IsPlusBuild(comment.Text) {
				plusBuild = true
			}
		}
	}
	if plusBuild {
		return nil, errors.New("a // +build line with no //go:build line, which the go command honors and these rules do not read; gofmt adds the //go:build line")
	}
	return nil, nil
}

// The file's name relative to the top directory, for a finding.
func (self *repository) displayPath(filePath string) string {
	relativePath, err := filepath.Rel(self.topDirectory, filePath)
	if err != nil {
		return filePath
	}
	return filepath.ToSlash(relativePath)
}

// The file's import paths with where each sits.
func (self *sourceFile) imports() []importSite {
	sites := make([]importSite, 0, len(self.syntax.Imports))
	for _, spec := range self.syntax.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		sites = append(sites, importSite{importPath: importPath, line: self.fileSet.Position(spec.Pos()).Line})
	}
	return sites
}

// One import declaration.
type importSite struct {
	importPath string
	line       int
}

// True for a test file in the external package of its directory. CODESTYLE's boundary: such a file
// is a separately compiled consumer, and its imports are not the package's. Only a _test.go file
// named for its directory's own package can claim that.
func (self *sourceFile) isExternalTest(files []*sourceFile) bool {
	if !self.isTest || !strings.HasSuffix(self.clauseName, "_test") {
		return false
	}
	internalName := strings.TrimSuffix(self.clauseName, "_test")
	for _, file := range files {
		if file.packageName == self.packageName && !file.isTest {
			return file.clauseName == internalName
		}
	}
	return true
}

// The standard library's import paths, as this toolchain knows them.
func (self *repository) stdPackages(t testing.TB) map[string]bool {
	t.Helper()
	packages, err := self.stdPackagesOnce()
	if err != nil {
		t.Fatal(err)
	}
	return packages
}

// go list std, which holds every system's packages at once.
func (self *repository) readStdPackages() (map[string]bool, error) {
	output, err := runGo(self.moduleDirectory, goEnvironment(), "list", "std")
	if err != nil {
		return nil, err
	}
	packages := map[string]bool{}
	for _, line := range strings.Fields(string(output)) {
		packages[line] = true
	}
	return packages, nil
}

// The path inside this repository that an import path names, in the form sourceFile.packageName
// uses, and whether it is one of ours. The element test keeps a module such as .../sidecar-extra out.
func repositoryRelative(importPath string) (string, bool) {
	base := firstPartyBase(importPath)
	if !underPath(base, sidecarBasePath) {
		return "", false
	}
	if base == sidecarBasePath {
		return ".", true
	}
	return strings.TrimPrefix(base, sidecarBasePath+"/"), true
}

// A file in a sibling checkout. On a release branch an earlier step has moved connect's tree, and a
// later one will move sdk's, into v2026/ (§4.9), so the moved place counts too. A nested module, such
// as sdk/js, stays where it was.
func (self *repository) siblingPath(relativePath string) string {
	direct := filepath.Join(self.siblingsDirectory, filepath.FromSlash(relativePath))
	if _, err := os.Stat(direct); err == nil || self.releaseSuffix == "" {
		return direct
	}
	sibling, rest, _ := strings.Cut(relativePath, "/")
	moved := filepath.Join(self.siblingsDirectory, sibling, strings.TrimPrefix(self.releaseSuffix, "/"), filepath.FromSlash(rest))
	if _, err := os.Stat(moved); err == nil {
		return moved
	}
	return direct
}

// The sibling checkout's go.mod, read by the go command, or an error naming it. Callers treat a
// missing sibling as a failure: these rules compare against the siblings, and a rule that cannot
// read them has not passed.
func (self *repository) siblingModuleFile(relativeDirectory string) (*moduleFile, error) {
	return readModuleFile(self.siblingPath(relativeDirectory + "/go.mod"))
}

// Fails the test with each finding, under the row's name.
func failFindings(t testing.TB, row string, findings []string) {
	t.Helper()
	for _, finding := range findings {
		t.Errorf("%s: %s", row, finding)
	}
}
