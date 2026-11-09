//go:build sidecar_check

// X9's ledger (§4.6, D-REPO-5, Q-REPO-2) as data, and the rules that read connect against it. Each row
// is REPO.md's "Connect changes" table: its disposition, the milestone it lands at, the task that builds
// it, the marker that shows it landed, the row it follows and the connect tests that show a client which
// does not opt in behaves as it always has. Connect is read through siblingPath, so the rules hold on a
// release tree, where connect's tree sits in v2026/, as on a branch. Nothing here edits connect.
//
// Two levels. Every make check fails on a shape §4.6 rejects, defers or leaves for later appearing in
// connect, on a connect proto that is not additive against connect's main, on a change landing before the
// row it follows, and on connect requiring sidecar. A landed marker no default-off test pins is only
// reported, as rowOff reports: a connect track lands without touching sidecar, so make check must not turn
// red for everyone on it. TestX9ReadyForMain is the gate build's sidecar-branches.zsh merge-out runs, with
// the gate's milestone: it turns that report into a failure, refuses C19's marker without FS-125's sweep
// in connect's own tests (§4.17), and refuses a row due by the gate whose marker has not landed, which is
// also what a renamed marker looks like.

package check

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

// What §4.6 decided for a row.
type x9Disposition string

const (
	x9Rejected x9Disposition = "rejected"
	x9Deferred x9Disposition = "deferred"
	// C4: after §18's HTTPS-only worker (owner decision 26)
	x9Later x9Disposition = "later"
	// C17: for the extension's streaming Worker only, after §18's spike
	x9DecidedAfterSpike x9Disposition = "decided after §18's spike"
	x9Lands             x9Disposition = "lands"
)

// What a row's marker names in connect.
type x9MarkerKind int

const (
	// a name connect or connect/protocol declares in a file that is not a test: a type, function, method,
	// constant, variable or struct field
	x9MarkerName x9MarkerKind = iota + 1
	// a file of connect's module
	x9MarkerFile
	// a field of a message in connect's protocol/*.proto
	x9MarkerProtoField
	// text in a document of connect's, for the rows that change no code
	x9MarkerDocument
)

// One row of §4.6.
type x9Row struct {
	id          string
	disposition x9Disposition
	// the milestone the row lands at; 0 when no plan lands it
	milestone int
	// the task or tasks that build it, or that hold it out
	task string
	// what shows the row landed in connect, read as markerKind says
	marker     string
	markerKind x9MarkerKind
	// for a document marker, the text the document holds once the row has landed
	markerText string
	// rows whose markers must land before this row's (§4.18)
	follows []string
	// connect's tests showing that a client which does not opt in behaves as it always has
	defaultOffTests []string
	// why a row that changes no client's behavior needs no default-off test
	defaultOffNotNeeded string
	// C19's: the test file in connect that holds FS-125's sweep, which must pass before connect's main (§4.17)
	sweepTestFile string
}

// §4.6's table, as REPO.md's "Connect changes" holds it.
var x9Rows = []x9Row{
	{id: "C1", disposition: x9Rejected, task: "held out by REPO-M0-04: §6 uses public id 21842"},
	{id: "C2", disposition: x9Rejected, task: "held out by REPO-M0-04: handlers see peer.ProvideMode and length"},
	{
		id: "C3", disposition: x9Lands, milestone: 1, task: "connect-m1; consumed by PROTO-M1-03",
		marker: "WithSubprotocolControlSource", markerKind: x9MarkerName,
		defaultOffTests: []string{
			"TestSourceRuleOptInsAreOffByDefault", "TestSubprotocolControlSourceDroppedWithoutOptIn",
			"TestDefaultClientP2pRouteAcceptsAnySource",
		},
	},
	{id: "C4", disposition: x9Later, task: "none: after §18's HTTPS-only worker (owner decision 26)"},
	{
		id: "C5", disposition: x9Lands, milestone: 4, task: "BRIDGE-M4-01, BRIDGE-M4-02",
		marker: "EgressHook", markerKind: x9MarkerName,
		defaultOffTests: []string{"TestEgressHookNilHookResolvesWithoutAllocation"},
	},
	{
		id: "C6a", disposition: x9Lands, milestone: 4, task: "BRIDGE-M4-03",
		marker: "DropSharedAddressSpace", markerKind: x9MarkerName,
		defaultOffTests: []string{"TestSharedAddressShadowCountsAndKeepsTheVerdict", "TestProviderShadowCountsSharedAddress"},
	},
	{id: "C6b", disposition: x9Rejected, task: "held out by REPO-M0-04: §17.10's providers end flows without a tun"},
	{id: "C7", disposition: x9Deferred, task: "held out by REPO-M0-04: TransferKey lanes suffice"},
	{
		id: "C8", disposition: x9Lands, milestone: 4, task: "SDK-M4-07",
		marker: "net_proxy_http.go", markerKind: x9MarkerFile,
		defaultOffTests: []string{"TestProxySettingsWithoutProtocolStaySocks5"},
	},
	{
		id: "C9", disposition: x9Lands, milestone: 5, task: "PROTO-M5-03 in connect, PROTO-M5-04 in server",
		marker: "ProvideMode_Service", markerKind: x9MarkerName,
		defaultOffTests: []string{
			"TestServiceSourceDefaultSettingsPassNothing", "TestProvideModeWireBytesAreUnchanged",
			"TestDefaultProvideSecretKeysOmitService",
		},
	},
	{id: "C10", disposition: x9Rejected, task: "held out by REPO-M0-04: owner decision 17, X8 (b) needs none"},
	{
		id: "C11", disposition: x9Lands, milestone: 1, task: "connect-m1, then each route's own task (QD-284)",
		marker: "api/bringyour.yml", markerKind: x9MarkerDocument, markerText: "/sidecar/bind",
		defaultOffNotNeeded: "a route's entry in the spec changes no client",
	},
	{
		id: "C12", disposition: x9Lands, milestone: 1, task: "connect-m1; consumed by PROTO-M1-03",
		marker: "SUBPROTOCOL.md", markerKind: x9MarkerDocument, markerText: "21842",
		defaultOffNotNeeded: "a document changes no client",
	},
	{
		id: "C13", disposition: x9Lands, milestone: 4, task: "PROTO-M4-01 in connect, PROTO-M4-02 in server, BRIDGE-M4-04",
		marker: "source_subject_client_id", markerKind: x9MarkerProtoField,
		defaultOffTests: []string{"TestContractsWithoutSealsReadEmpty", "TestContractClassUnsetAndUnknownReadAsUnset"},
	},
	{
		id: "C14", disposition: x9Lands, milestone: 4, task: "DNS-M4-01; filled by BRIDGE-M4-14 and SDK-M4-02",
		marker: "SetLocalZone", markerKind: x9MarkerName,
		defaultOffTests: []string{"TestUpgradeMuxLocalZoneNilKeepsTodaysBehavior"},
	},
	{
		id: "C15", disposition: x9Lands, milestone: 1, task: "connect-m1; consumed by PROTO-M1-04",
		marker: "VerifiedClientPublicKey", markerKind: x9MarkerName,
		defaultOffTests: []string{"TestPeerVerifiedClientKeyIsOffByDefault"},
	},
	{
		id: "C16", disposition: x9Lands, milestone: 4, task: "BRIDGE-M4-05; app hosts turn it on at BRIDGE-M8-01",
		marker: "StickyRequired", markerKind: x9MarkerName,
		defaultOffTests: []string{
			"TestStickyRequiredDefaultsOffAndLeavesTheOtherModes", "TestStickyRequiredOffFallsBackToPlaintextOnAForcedReset",
		},
	},
	{id: "C17", disposition: x9DecidedAfterSpike, task: "SDK-M2-01 measures; the owner decides, for the extension's streaming Worker only"},
	{
		id: "C18", disposition: x9Lands, milestone: 6, task: "BRIDGE-M6-01, PROTO-M6-01, ACL-M6-03",
		marker: "FriendsAndFamilyEgress", markerKind: x9MarkerName, follows: []string{"C13", "C5"},
		defaultOffTests: []string{"TestEgressShareOffKeepsPrivateDestinationsAnIncident"},
	},
	{
		id: "C19", disposition: x9Lands, milestone: 10, task: "PROTO-M10-02, PROTO-M10-03, PROTO-M10-04; FS-125 in PROTO-M10-05",
		marker: "SetPeerWindowAccounting", markerKind: x9MarkerName,
		defaultOffTests: []string{"TestPeerWindowOffReportsAreIdentical", "TestPeerWindowUnmarkedPairIsUnchanged"},
		sweepTestFile:   "transfer_peer_window_sweep_test.go",
	},
}

// The row with that id, or nil.
func x9RowById(id string) *x9Row {
	for index := range x9Rows {
		if x9Rows[index].id == id {
			return &x9Rows[index]
		}
	}
	return nil
}

// What C1 keeps unexported: §6 uses public id 21842, and the reserved range stays connect's own.
var x9ReservedRegistrationNames = []string{"registerReservedSubprotocol", "addReservedSubprotocolRawCallback"}

// The one SubprotocolListenerOption constructor C3 adds. C2's filters would be another.
const x9ListenerOptionType = "SubprotocolListenerOption"

var x9ListenerOptionConstructors = []string{"WithSubprotocolControlSource"}

// C6b's shape: a forwarder on connect's Tun.
var x9TunForwarderPattern = regexp.MustCompile(`(?i)^(new)?tun\w*forward|^forward\w*tun`)

// C10's shape: a push value of MessageType. connect's main already holds URmessage's 1000 block, which
// §4.6 does not concern, so only a value main lacks counts.
var x9PushValuePattern = regexp.MustCompile(`(?i)push`)

// One file of connect's, as the rules read it.
type x9ConnectFile struct {
	// relative to connect's module directory
	name    string
	imports []string
	// mentions a browser WebSocket, C4's carrier
	mentionsWebSocket bool
	// compiles for GOOS=js GOARCH=wasm with no tags
	onJs bool
	// compiles only there, of the targets the rule tries
	onlyOnJs bool
	// carries a //go:build line
	constrained bool
}

// What a scan of connect found, read once per repository.
type x9ConnectScan struct {
	// connect's module directory: connect/, or connect/v2026 on a release tree
	moduleDirectory string
	// connect's git checkout
	gitDirectory string
	// names connect and connect/protocol declare in files that are not tests
	declared map[string]bool
	// exported functions and methods by name, with the names of their result types
	resultTypes map[string][]string
	// TransferOptions's exported fields
	transferOptionFields []string
	files                []*x9ConnectFile
	// test functions declared in connect and connect/protocol, and the test files beside them
	testNames map[string]bool
	testFiles map[string][]string
	goMod     *moduleFile
	// the descriptor sets of protocol/*.proto at main and at HEAD, nil when either side has none
	mainDescriptors *descriptorpb.FileDescriptorSet
	headDescriptors *descriptorpb.FileDescriptorSet
	// what kept the scan from reading something; each is a finding of the rule that needed it
	problems []string
	// false when the checkout has no main branch to compare against
	hasMain bool
}

// The scan of this repository's connect, made once.
func (self *repository) connectScan(t testing.TB) *x9ConnectScan {
	t.Helper()
	scan, err := self.connectScanOnce()
	if err != nil {
		t.Fatal(err)
	}
	return scan
}

// Reads connect's sources, tests, go.mod and protos. A part it cannot read becomes a problem, never a pass.
func (self *repository) readConnectScan() (*x9ConnectScan, error) {
	goModPath := self.siblingPath("connect/go.mod")
	scan := &x9ConnectScan{
		moduleDirectory: filepath.Dir(goModPath),
		gitDirectory:    filepath.Join(self.siblingsDirectory, "connect"),
		declared:        map[string]bool{},
		resultTypes:     map[string][]string{},
		testNames:       map[string]bool{},
		testFiles:       map[string][]string{},
	}
	goMod, err := readModuleFile(goModPath)
	if err != nil {
		return nil, fmt.Errorf("x9 reads connect's go.mod: %w", err)
	}
	scan.goMod = goMod
	for _, packageDirectory := range []string{".", "protocol"} {
		if err := scan.readPackage(packageDirectory); err != nil {
			return nil, err
		}
	}
	scan.readDescriptors()
	return scan, nil
}

// The test names a file declares, by their func lines, without parsing the file.
var x9TestFuncPattern = regexp.MustCompile(`(?m)^func (Test\w+)\(`)

// Reads one of connect's package directories, not its subdirectories.
func (self *x9ConnectScan) readPackage(packageDirectory string) error {
	directory := filepath.Join(self.moduleDirectory, packageDirectory)
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("x9 reads %s: %w", directory, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		relativeName := filepath.ToSlash(filepath.Join(packageDirectory, name))
		fullPath := filepath.Join(directory, name)
		if strings.HasSuffix(name, "_test.go") {
			data, err := os.ReadFile(fullPath)
			if err != nil {
				return err
			}
			for _, match := range x9TestFuncPattern.FindAllSubmatch(data, -1) {
				self.testNames[string(match[1])] = true
				self.testFiles[relativeName] = append(self.testFiles[relativeName], string(match[1]))
			}
			if _, found := self.testFiles[relativeName]; !found {
				self.testFiles[relativeName] = []string{}
			}
			continue
		}
		fileSet := token.NewFileSet()
		syntax, err := parser.ParseFile(fileSet, fullPath, nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("x9 parses %s: %w", fullPath, err)
		}
		file := &x9ConnectFile{name: relativeName}
		for _, spec := range syntax.Imports {
			if importPath, err := strconv.Unquote(spec.Path.Value); err == nil {
				file.imports = append(file.imports, importPath)
			}
		}
		if expression, err := fileConstraint(syntax); err != nil {
			return fmt.Errorf("x9 reads %s: %w", fullPath, err)
		} else {
			file.constrained = expression != nil
		}
		data, err := os.ReadFile(fullPath)
		if err != nil {
			return err
		}
		file.mentionsWebSocket = bytes.Contains(bytes.ToLower(data), []byte("websocket"))
		matches := map[string]bool{}
		for _, target := range []string{"js/wasm", "linux/amd64", "darwin/arm64", "windows/amd64", "android/arm64", "ios/arm64"} {
			goos, goarch, _ := strings.Cut(target, "/")
			context := build.Default
			context.GOOS = goos
			context.GOARCH = goarch
			context.BuildTags = nil
			context.CgoEnabled = false
			match, err := context.MatchFile(directory, name)
			if err != nil {
				return fmt.Errorf("x9 matches %s for %s: %w", fullPath, target, err)
			}
			matches[target] = match
		}
		file.onJs = matches["js/wasm"]
		file.onlyOnJs = file.onJs
		for target, match := range matches {
			if target != "js/wasm" && match {
				file.onlyOnJs = false
			}
		}
		self.files = append(self.files, file)
		self.readDeclarations(syntax)
	}
	return nil
}

// Collects what a file declares, with the result types of its exported functions and TransferOptions's
// fields, which C2 and C7 read.
func (self *x9ConnectScan) readDeclarations(syntax *ast.File) {
	typeName := func(expression ast.Expr) string {
		for {
			switch typed := expression.(type) {
			case *ast.StarExpr:
				expression = typed.X
			case *ast.SelectorExpr:
				return typed.Sel.Name
			case *ast.Ident:
				return typed.Name
			case *ast.IndexExpr:
				expression = typed.X
			default:
				return ""
			}
		}
	}
	for _, decl := range syntax.Decls {
		switch typed := decl.(type) {
		case *ast.FuncDecl:
			self.declared[typed.Name.Name] = true
			if typed.Type.Results != nil {
				for _, result := range typed.Type.Results.List {
					self.resultTypes[typed.Name.Name] = append(self.resultTypes[typed.Name.Name], typeName(result.Type))
				}
			}
		case *ast.GenDecl:
			for _, spec := range typed.Specs {
				switch specTyped := spec.(type) {
				case *ast.TypeSpec:
					self.declared[specTyped.Name.Name] = true
					if interfaceType, ok := specTyped.Type.(*ast.InterfaceType); ok {
						for _, method := range interfaceType.Methods.List {
							for _, methodName := range method.Names {
								self.declared[methodName.Name] = true
							}
						}
						continue
					}
					structType, ok := specTyped.Type.(*ast.StructType)
					if !ok {
						continue
					}
					for _, field := range structType.Fields.List {
						for _, fieldName := range field.Names {
							self.declared[fieldName.Name] = true
							if specTyped.Name.Name == "TransferOptions" && fieldName.IsExported() {
								self.transferOptionFields = append(self.transferOptionFields, fieldName.Name)
							}
						}
					}
				case *ast.ValueSpec:
					for _, valueName := range specTyped.Names {
						self.declared[valueName.Name] = true
					}
				}
			}
		}
	}
}

// Builds a descriptor set of connect's protos at main and at HEAD with protoc. A checkout without main,
// or a protoc that cannot run, is a problem the proto rule reports.
func (self *x9ConnectScan) readDescriptors() {
	if _, err := runX9Git(self.gitDirectory, "rev-parse", "--verify", "--quiet", "refs/heads/main^{commit}"); err != nil {
		self.problems = append(self.problems, findingf("connect at %s has no main branch, so nothing shows its changes are additive against main", self.gitDirectory))
		return
	}
	self.hasMain = true
	listed, err := runX9Git(self.gitDirectory, "ls-tree", "--name-only", "main", "--", "protocol/")
	if err != nil {
		self.problems = append(self.problems, findingf("reading connect's protocol at main: %v", err))
		return
	}
	mainDirectory, err := os.MkdirTemp("", "x9-connect-main-")
	if err != nil {
		self.problems = append(self.problems, findingf("a directory for connect's main protos: %v", err))
		return
	}
	defer os.RemoveAll(mainDirectory)
	mainNames := []string{}
	for _, listedPath := range strings.Fields(string(listed)) {
		if !strings.HasSuffix(listedPath, ".proto") {
			continue
		}
		content, err := runX9Git(self.gitDirectory, "show", "main:"+listedPath)
		if err != nil {
			self.problems = append(self.problems, findingf("reading %s at connect's main: %v", listedPath, err))
			return
		}
		name := filepath.Base(listedPath)
		if err := os.WriteFile(filepath.Join(mainDirectory, name), content, 0o600); err != nil {
			self.problems = append(self.problems, findingf("writing %s: %v", name, err))
			return
		}
		mainNames = append(mainNames, name)
	}
	headDirectory := filepath.Join(self.moduleDirectory, "protocol")
	headPaths, err := filepath.Glob(filepath.Join(headDirectory, "*.proto"))
	if err != nil {
		self.problems = append(self.problems, findingf("listing connect's protos: %v", err))
		return
	}
	headNames := []string{}
	for _, headPath := range headPaths {
		headNames = append(headNames, filepath.Base(headPath))
	}
	if len(mainNames) == 0 && len(headNames) == 0 {
		return
	}
	describe := func(directory string, names []string) (*descriptorpb.FileDescriptorSet, error) {
		set := &descriptorpb.FileDescriptorSet{}
		if len(names) == 0 {
			return set, nil
		}
		output, err := os.CreateTemp("", "x9-descriptors-")
		if err != nil {
			return nil, err
		}
		output.Close()
		defer os.Remove(output.Name())
		command := exec.Command("protoc", append([]string{"-I=" + directory, "--descriptor_set_out=" + output.Name()}, names...)...)
		if combined, err := command.CombinedOutput(); err != nil {
			if errors.Is(err, exec.ErrNotFound) {
				return nil, errors.New("protoc is not on PATH")
			}
			return nil, fmt.Errorf("protoc in %s: %v\n%s", directory, err, combined)
		}
		data, err := os.ReadFile(output.Name())
		if err != nil {
			return nil, err
		}
		if err := proto.Unmarshal(data, set); err != nil {
			return nil, err
		}
		return set, nil
	}
	if self.mainDescriptors, err = describe(mainDirectory, mainNames); err != nil {
		self.problems = append(self.problems, findingf("connect's protos at main: %v, so nothing shows HEAD's are additive", err))
		return
	}
	if self.headDescriptors, err = describe(headDirectory, headNames); err != nil {
		self.problems = append(self.problems, findingf("connect's protos at HEAD: %v, so nothing shows they are additive", err))
		self.mainDescriptors = nil
	}
}

// git's stdout in directory, with stderr inside the error.
func runX9Git(directory string, arguments ...string) ([]byte, error) {
	command := exec.Command("git", arguments...)
	command.Dir = directory
	command.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_NO_LAZY_FETCH=1")
	output, err := command.Output()
	if err != nil {
		stderr := ""
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			stderr = string(exitError.Stderr)
		}
		return nil, fmt.Errorf("git %s in %s: %w %s", strings.Join(arguments, " "), directory, err, strings.TrimSpace(stderr))
	}
	return output, nil
}

// Whether a row's marker is in connect.
func (self *x9ConnectScan) landed(row *x9Row) bool {
	switch row.markerKind {
	case x9MarkerName:
		return self.declared[row.marker]
	case x9MarkerFile:
		_, err := os.Stat(filepath.Join(self.moduleDirectory, filepath.FromSlash(row.marker)))
		return err == nil
	case x9MarkerProtoField:
		if self.headDescriptors == nil {
			return false
		}
		found := false
		x9EachMessage(self.headDescriptors, func(fullName string, message *descriptorpb.DescriptorProto) {
			for _, field := range message.GetField() {
				if field.GetName() == row.marker {
					found = true
				}
			}
		})
		return found
	case x9MarkerDocument:
		data, err := os.ReadFile(filepath.Join(self.moduleDirectory, filepath.FromSlash(row.marker)))
		return err == nil && bytes.Contains(data, []byte(row.markerText))
	}
	return false
}

// The shapes §4.6 rejects, defers or leaves for later, each a finding when it appears in connect.
func (self *repository) x9ShapeFindings(t testing.TB) []string {
	scan := self.connectScan(t)
	findings := []string{}
	for _, name := range x9ReservedRegistrationNames {
		exported := strings.ToUpper(name[:1]) + name[1:]
		if scan.declared[exported] {
			findings = append(findings, findingf("C1: connect exports %s, and §4.6 rejects exported reserved-id registration", exported))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(scan.resultTypes)) {
		if !ast.IsExported(name) || slices.Contains(x9ListenerOptionConstructors, name) {
			continue
		}
		if slices.Contains(scan.resultTypes[name], x9ListenerOptionType) {
			findings = append(findings, findingf("C2: connect's %s makes a %s beyond %s, and §4.6 rejects provide-mode and size filters", name, x9ListenerOptionType, strings.Join(x9ListenerOptionConstructors, ", ")))
		}
	}
	for _, file := range scan.files {
		if file.onlyOnJs && file.mentionsWebSocket {
			findings = append(findings, findingf("C4: connect's %s is a js carrier over a browser WebSocket, which §4.6 leaves until §18's HTTPS-only worker", file.name))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(scan.declared)) {
		if ast.IsExported(name) && x9TunForwarderPattern.MatchString(name) {
			findings = append(findings, findingf("C6b: connect declares %s, a Tun forwarder §4.6 rejects", name))
		}
	}
	for _, field := range scan.transferOptionFields {
		if strings.Contains(strings.ToLower(field), "lane") {
			findings = append(findings, findingf("C7: TransferOptions.%s is a caller lane key, which §4.6 defers", field))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(scan.resultTypes)) {
		if !ast.IsExported(name) || !strings.Contains(strings.ToLower(name), "lane") {
			continue
		}
		for _, resultType := range scan.resultTypes[name] {
			if strings.HasPrefix(strings.ToLower(resultType), "transferoption") {
				findings = append(findings, findingf("C7: connect's %s is a send option carrying a caller lane key, which §4.6 defers", name))
			}
		}
	}
	if scan.headDescriptors != nil {
		mainValues := map[string]bool{}
		x9EachEnum(scan.mainDescriptors, func(fullName string, enum *descriptorpb.EnumDescriptorProto) {
			for _, value := range enum.GetValue() {
				mainValues[fullName+"."+value.GetName()] = true
			}
		})
		x9EachEnum(scan.headDescriptors, func(fullName string, enum *descriptorpb.EnumDescriptorProto) {
			if enum.GetName() != "MessageType" {
				return
			}
			for _, value := range enum.GetValue() {
				if x9PushValuePattern.MatchString(value.GetName()) && !mainValues[fullName+"."+value.GetName()] {
					findings = append(findings, findingf("C10: %s.%s is a push MessageType connect's main lacks, and §4.6 rejects one (owner decision 17)", fullName, value.GetName()))
				}
			}
		})
	}
	gvisorFiles := 0
	for _, file := range scan.files {
		if !slices.ContainsFunc(file.imports, func(importPath string) bool { return underPath(importPath, gvisorBasePath) }) {
			continue
		}
		gvisorFiles += 1
		if !file.onJs {
			findings = append(findings, findingf("C17: connect's %s imports gVisor and is left out of the js build, which gives connect a gVisor-free js build §4.6 has not decided", file.name))
		} else if file.constrained {
			findings = append(findings, findingf("C17: connect's %s imports gVisor under a build constraint, so a tag can give connect a gVisor-free js build §4.6 has not decided", file.name))
		}
	}
	if gvisorFiles == 0 && len(scan.files) != 0 {
		findings = append(findings, "C17: no file of connect's imports gVisor, so its js build is gVisor-free, which §4.6 has not decided")
	}
	return findings
}

// D-REPO-5's wire-compatible: connect's protos at HEAD keep every message, field and enum value main
// holds, at its number and type. A checkout without main fails here rather than passing.
func (self *repository) x9ProtoFindings(t testing.TB) []string {
	scan := self.connectScan(t)
	findings := slices.Clone(scan.problems)
	if scan.mainDescriptors == nil || scan.headDescriptors == nil {
		return findings
	}
	type fieldShape struct {
		number   int32
		kind     descriptorpb.FieldDescriptorProto_Type
		typeName string
		label    descriptorpb.FieldDescriptorProto_Label
	}
	headMessages := map[string]map[string]fieldShape{}
	headNumbers := map[string]map[int32]string{}
	x9EachMessage(scan.headDescriptors, func(fullName string, message *descriptorpb.DescriptorProto) {
		headMessages[fullName] = map[string]fieldShape{}
		headNumbers[fullName] = map[int32]string{}
		for _, field := range message.GetField() {
			headMessages[fullName][field.GetName()] = fieldShape{number: field.GetNumber(), kind: field.GetType(), typeName: field.GetTypeName(), label: field.GetLabel()}
			headNumbers[fullName][field.GetNumber()] = field.GetName()
		}
	})
	x9EachMessage(scan.mainDescriptors, func(fullName string, message *descriptorpb.DescriptorProto) {
		fields, found := headMessages[fullName]
		if !found {
			findings = append(findings, findingf("connect's HEAD removes message %s, which main holds (D-REPO-5)", fullName))
			return
		}
		for _, field := range message.GetField() {
			shape, found := fields[field.GetName()]
			switch {
			case !found:
				if other, taken := headNumbers[fullName][field.GetNumber()]; taken {
					findings = append(findings, findingf("connect's HEAD removes field %s.%s = %d, which main holds, and gives its number to %s (D-REPO-5)", fullName, field.GetName(), field.GetNumber(), other))
				} else {
					findings = append(findings, findingf("connect's HEAD removes field %s.%s = %d, which main holds (D-REPO-5)", fullName, field.GetName(), field.GetNumber()))
				}
			case shape.number != field.GetNumber():
				findings = append(findings, findingf("connect's HEAD renumbers field %s.%s from %d to %d (D-REPO-5)", fullName, field.GetName(), field.GetNumber(), shape.number))
			case shape.kind != field.GetType() || shape.typeName != field.GetTypeName() || shape.label != field.GetLabel():
				findings = append(findings, findingf("connect's HEAD retypes field %s.%s = %d (D-REPO-5)", fullName, field.GetName(), field.GetNumber()))
			}
		}
	})
	headEnums := map[string]map[string]int32{}
	x9EachEnum(scan.headDescriptors, func(fullName string, enum *descriptorpb.EnumDescriptorProto) {
		headEnums[fullName] = map[string]int32{}
		for _, value := range enum.GetValue() {
			headEnums[fullName][value.GetName()] = value.GetNumber()
		}
	})
	x9EachEnum(scan.mainDescriptors, func(fullName string, enum *descriptorpb.EnumDescriptorProto) {
		values, found := headEnums[fullName]
		if !found {
			findings = append(findings, findingf("connect's HEAD removes enum %s, which main holds (D-REPO-5)", fullName))
			return
		}
		for _, value := range enum.GetValue() {
			number, found := values[value.GetName()]
			switch {
			case !found:
				findings = append(findings, findingf("connect's HEAD removes enum value %s.%s = %d, which main holds (D-REPO-5)", fullName, value.GetName(), value.GetNumber()))
			case number != value.GetNumber():
				findings = append(findings, findingf("connect's HEAD renumbers enum value %s.%s from %d to %d (D-REPO-5)", fullName, value.GetName(), value.GetNumber(), number))
			}
		}
	})
	return findings
}

// Every message of a descriptor set, nested ones included, by full name.
func x9EachMessage(set *descriptorpb.FileDescriptorSet, visit func(fullName string, message *descriptorpb.DescriptorProto)) {
	var walk func(prefix string, messages []*descriptorpb.DescriptorProto)
	walk = func(prefix string, messages []*descriptorpb.DescriptorProto) {
		for _, message := range messages {
			fullName := prefix + "." + message.GetName()
			visit(fullName, message)
			walk(fullName, message.GetNestedType())
		}
	}
	for _, file := range set.GetFile() {
		walk(file.GetPackage(), file.GetMessageType())
	}
}

// Every enum of a descriptor set, nested ones included, by full name.
func x9EachEnum(set *descriptorpb.FileDescriptorSet, visit func(fullName string, enum *descriptorpb.EnumDescriptorProto)) {
	for _, file := range set.GetFile() {
		for _, enum := range file.GetEnumType() {
			visit(file.GetPackage()+"."+enum.GetName(), enum)
		}
	}
	x9EachMessage(set, func(fullName string, message *descriptorpb.DescriptorProto) {
		for _, enum := range message.GetEnumType() {
			visit(fullName+"."+enum.GetName(), enum)
		}
	})
}

// §4.18's order: a row's marker never lands before the markers of the rows it follows, C18's before C13's.
func (self *repository) x9OrderFindings(t testing.TB) []string {
	scan := self.connectScan(t)
	findings := []string{}
	for index := range x9Rows {
		row := &x9Rows[index]
		if row.marker == "" || !scan.landed(row) {
			continue
		}
		for _, followed := range row.follows {
			earlier := x9RowById(followed)
			if earlier == nil {
				findings = append(findings, findingf("%s follows %s, which is not a row of §4.6", row.id, followed))
				continue
			}
			if !scan.landed(earlier) {
				findings = append(findings, findingf("%s's marker %s is in connect before %s's %s, and §4.18 lands %s first", row.id, row.marker, earlier.id, earlier.marker, earlier.id))
			}
		}
	}
	return findings
}

// R-REPO-2: sidecar imports connect, never the reverse.
func (self *repository) x9ConnectRequireFindings(t testing.TB) []string {
	scan := self.connectScan(t)
	findings := []string{}
	for _, require := range scan.goMod.Require {
		if underPath(firstPartyBase(require.Path), sidecarBasePath) {
			findings = append(findings, findingf("connect's go.mod requires %s, and R-REPO-2 has sidecar import connect only", require.Path))
		}
	}
	for _, replace := range scan.goMod.Replace {
		if underPath(firstPartyBase(replace.Old.Path), sidecarBasePath) {
			findings = append(findings, findingf("connect's go.mod replaces %s, and R-REPO-2 has sidecar import connect only", replace.Old.Path))
		}
	}
	return findings
}

// Each landed marker whose row names no default-off test, or names one connect does not hold. A row that
// changes no client's behavior says why it needs none.
func (self *x9ConnectScan) defaultOffGaps() []string {
	gaps := []string{}
	for index := range x9Rows {
		row := &x9Rows[index]
		if row.marker == "" || row.defaultOffNotNeeded != "" || !self.landed(row) {
			continue
		}
		if len(row.defaultOffTests) == 0 {
			gaps = append(gaps, findingf("%s's marker %s is in connect, and its row names no default-off test", row.id, row.marker))
			continue
		}
		for _, name := range row.defaultOffTests {
			if !self.testNames[name] {
				gaps = append(gaps, findingf("%s's marker %s is in connect, and its default-off test %s is not in connect's tests", row.id, row.marker, name))
			}
		}
	}
	return gaps
}

// Reports a landed marker no default-off test pins, and fails nothing: a connect track lands without
// touching sidecar, so a branch build must not turn red on it. TestX9ReadyForMain fails on the same gaps.
func (self *repository) x9DefaultOffReport(t testing.TB) []string {
	gaps := self.connectScan(t).defaultOffGaps()
	if len(gaps) != 0 {
		self.report("x9: %d landed connect changes lack a default-off test, which merge-out's TestX9ReadyForMain refuses", len(gaps))
		for _, gap := range gaps {
			self.report("  x9: %s", gap)
		}
	}
	return nil
}

// What keeps connect's sidecar changes from reaching connect's main at the gate of milestone gate: every
// x9 finding, each default-off gap, C19 without FS-125's sweep, and a row due by the gate with no marker.
func (self *repository) x9ReadyForMainFindings(t testing.TB, gate int) []string {
	scan := self.connectScan(t)
	findings := []string{}
	findings = append(findings, self.x9ShapeFindings(t)...)
	findings = append(findings, self.x9ProtoFindings(t)...)
	findings = append(findings, self.x9OrderFindings(t)...)
	findings = append(findings, self.x9ConnectRequireFindings(t)...)
	findings = append(findings, scan.defaultOffGaps()...)
	for index := range x9Rows {
		row := &x9Rows[index]
		if row.disposition != x9Lands {
			continue
		}
		landed := scan.landed(row)
		if !landed && row.milestone <= gate {
			findings = append(findings, findingf("%s is due by M%d (%s), and its marker %s is not in connect", row.id, row.milestone, row.task, row.marker))
		}
		if landed && row.sweepTestFile != "" {
			if names, found := scan.testFiles[row.sweepTestFile]; !found || len(names) == 0 {
				findings = append(findings, findingf("%s's marker %s is in connect without FS-125's sweep in connect's own %s, which must pass before connect's main (§4.17)", row.id, row.marker, row.sweepTestFile))
			}
		}
	}
	return findings
}

// The gate's milestone, as merge-out passes it: M0 to M10.
const x9GateVariable = "SIDECAR_X9_GATE"

var x9GatePattern = regexp.MustCompile(`^M(10|[0-9])$`)

// The gate merge-out runs before any commit reaches connect's main (§4.8, D-REPO-5). Plain make check
// runs no gate and skips this, since neither a connect track nor an early row may turn a branch build
// red; merge-out sets SIDECAR_X9_GATE to the gate's milestone and needs this test's own pass line.
func TestX9ReadyForMain(t *testing.T) {
	gateName := os.Getenv(x9GateVariable)
	if gateName == "" {
		t.Skipf("%s names no gate; build's sidecar-branches.zsh merge-out sets it for the gate it merges", x9GateVariable)
	}
	match := x9GatePattern.FindStringSubmatch(gateName)
	if match == nil {
		t.Fatalf("%s is %q, not a milestone M0 to M10", x9GateVariable, gateName)
	}
	gate, _ := strconv.Atoi(match[1])
	// the checkout without its legs, which nothing here reads and merge-out would wait on
	repository, err := thisCheckout()
	if err != nil {
		t.Fatal(err)
	}
	repository.report = t.Logf
	failFindings(t, "x9 at "+gateName, repository.x9ReadyForMainFindings(t, gate))
}

// Every row of §4.6 is in the table once, with the fields its disposition needs.
func TestX9RowsAreSection46(t *testing.T) {
	want := []string{"C1", "C2", "C3", "C4", "C5", "C6a", "C6b", "C7", "C8", "C9", "C10", "C11", "C12", "C13", "C14", "C15", "C16", "C17", "C18", "C19"}
	got := []string{}
	for _, row := range x9Rows {
		got = append(got, row.id)
		switch row.disposition {
		case x9Lands:
			if row.milestone < 1 || row.milestone > 10 || row.marker == "" || row.markerKind == 0 || row.task == "" {
				t.Errorf("%s lands with no milestone, marker or task: %+v", row.id, row)
			}
			if len(row.defaultOffTests) == 0 && row.defaultOffNotNeeded == "" {
				t.Errorf("%s lands, and names neither a default-off test nor why it needs none", row.id)
			}
		case x9Rejected, x9Deferred, x9Later, x9DecidedAfterSpike:
			if row.marker != "" || row.milestone != 0 {
				t.Errorf("%s does not land on a plan, yet has a marker or milestone: %+v", row.id, row)
			}
		default:
			t.Errorf("%s has disposition %q", row.id, row.disposition)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("x9Rows is %v, and §4.6 is %v", got, want)
	}
	design, err := os.ReadFile(filepath.Join(openThisCheckout(t).topDirectory, "design", "source", "sections", "04-REPO.md"))
	if err != nil {
		t.Fatal(err)
	}
	rowPattern := regexp.MustCompile(`(?m)^\| (C[0-9]+[ab]?) \|`)
	designRows := []string{}
	for _, match := range rowPattern.FindAllSubmatch(design, -1) {
		designRows = append(designRows, string(match[1]))
	}
	if !slices.Equal(designRows, want) {
		t.Errorf("§4.6 now holds %v, so x9Rows needs the change", designRows)
	}
}

func TestX9(t *testing.T) {
	runRow(t, "x9")
}
