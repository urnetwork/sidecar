//go:build !js

// Proves §4.4's build rule: the sidecar_http js leg links no connect or gVisor package, every file
// that names one carries !sidecar_http, and every host_ file does whether it names one or not. These
// run on the host, where go and the source tree are, and read the leg through an explicit go/build
// context or `go list`, which -tags does not reach. It also runs that leg's tests in a Worker's shape,
// and holds the seams later tracks build on, each proved on a planted violation: NewSidecar runs
// validate, requests go through the transport files, and engines authenticate through the host.

package sidecar

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func sidecarHttpBuildContext() build.Context {
	buildContext := build.Default
	buildContext.GOOS = "js"
	buildContext.GOARCH = "wasm"
	buildContext.CgoEnabled = false
	buildContext.BuildTags = []string{"sidecar_http"}
	return buildContext
}

func rootGoFiles(t *testing.T) []string {
	t.Helper()
	goFiles, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(goFiles) == 0 {
		t.Fatal("no go files")
	}
	return goFiles
}

func namesConnect(importPath string) bool {
	return importPath == "github.com/urnetwork/connect" ||
		strings.HasPrefix(importPath, "github.com/urnetwork/connect/") ||
		strings.HasPrefix(importPath, "gvisor.dev/")
}

func TestEveryHostFileIsOffTheHttpLeg(t *testing.T) {
	buildContext := sidecarHttpBuildContext()
	hostFileCount := 0
	for _, goFile := range rootGoFiles(t) {
		if !strings.HasPrefix(goFile, "host_") {
			continue
		}
		hostFileCount += 1
		matched, err := buildContext.MatchFile(".", goFile)
		if err != nil {
			t.Fatal(err)
		}
		if matched {
			t.Errorf("%s builds on the sidecar_http leg", goFile)
		}
	}
	if hostFileCount == 0 {
		t.Error("no host_ files")
	}
}

func TestOnlyFilesOffTheHttpLegNameConnect(t *testing.T) {
	buildContext := sidecarHttpBuildContext()
	fileSet := token.NewFileSet()
	for _, goFile := range rootGoFiles(t) {
		file, err := parser.ParseFile(fileSet, goFile, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		matched, err := buildContext.MatchFile(".", goFile)
		if err != nil {
			t.Fatal(err)
		}
		for _, importSpec := range file.Imports {
			importPath, err := strconv.Unquote(importSpec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if matched && namesConnect(importPath) {
				t.Errorf("%s imports %s on the sidecar_http leg", goFile, importPath)
			}
		}
	}
}

// A blank import to hold the require must not outlive the first real one: connect_require.go's comment
// has it deleted in that change, and a second one would keep connect in go.mod by accident.
func TestConnectRequireHolderIsGone(t *testing.T) {
	if _, err := os.Stat("connect_require.go"); !os.IsNotExist(err) {
		t.Errorf("connect_require.go: %v", err)
	}
}

func goListDeps(t *testing.T, env []string, args ...string) []string {
	t.Helper()
	command := exec.Command("go", append([]string{"list", "-deps"}, args...)...)
	command.Env = append(os.Environ(), env...)
	output, err := command.Output()
	if err != nil {
		stderr := ""
		if exitError, ok := err.(*exec.ExitError); ok {
			stderr = string(exitError.Stderr)
		}
		t.Fatalf("go list: %v\n%s", err, stderr)
	}
	return strings.Fields(string(output))
}

// A Worker's globals, in node: no process, so net/http's fetch path runs, and a fetch that records what
// it is handed and then fails, so nothing leaves. The test binary's flags follow the two paths. It keeps
// the two exit rules of the toolchain's wasm_exec_node.js, which are the verdict's: node goes with the Go
// program, or a timer the runtime armed fires into a program that has gone and fails a passing run, and
// node never ends 0 with Go still running, or a suite that stalled would pass. Going with the program
// means dropping those timers and letting node end, where wasm_exec_node.js calls process.exit: that
// joins V8's workers, and one waiting on a collection the main thread will never run hangs it there,
// which a run allocating this much reaches about one time in ten.
//
// It also runs each GC cycle to its end before the program goes on, by the one variable it gives the
// program, GODEBUG=gcstoptheworld=1. js/wasm has one thread and no preemption, so the background mark
// worker runs only when the program blocks. Until then a cycle marks only in the assists that
// allocations pay, which fall far behind a loop of large blocks and stop altogether once the GC CPU
// limiter turns them off. Whatever a test allocates meanwhile is marked live, and the next cycle's
// goal is twice that: the leg's suite, whose largest test holds 65 MB live, grew to 2.8 GB of wasm's
// 4 GiB that way, and one run died of it partway, every test before it passing. The harness ends by
// reporting what linear memory grew to, which a program never gives back, so a run can be held to a
// bound.
const workerHarness = `
const fs = require("fs");
const nodeProcess = process;
const [wasmPath, wasmExecPath, ...testArgs] = nodeProcess.argv.slice(2);
delete globalThis.process;
require(wasmExecPath);
globalThis.workerFetchCalls = [];
globalThis.fetch = (url, options) => {
	globalThis.workerFetchCalls.push({url: url, authorization: options.headers.get("authorization")});
	return Promise.reject(new Error("the harness's fetch sends nothing"));
};
const go = new Go();
go.argv = [wasmPath, ...testArgs];
go.env = ` + workerHarnessGoEnv + `;
let memory = null;
go.exit = (code) => {
	nodeProcess.exitCode = code;
	console.error("worker harness: wasm memory " + memory.buffer.byteLength + " bytes");
	for (const timeout of go._scheduledTimeouts.values()) {
		clearTimeout(timeout);
	}
};
WebAssembly.instantiate(fs.readFileSync(wasmPath), go.importObject)
	.then((result) => {
		memory = result.instance.exports.mem;
		nodeProcess.on("exit", (code) => {
			if (code === 0 && !go.exited) {
				// an event of id 0 makes Go print the deadlock and its stacks, and exit
				go._pendingEvent = { id: 0 };
				go._resume();
			}
		});
		return go.run(result.instance);
	})
	.catch((err) => { console.error(err); nodeProcess.exit(1); });
`

// The environment the harness gives a program, where a Worker's has none: workerHarness says why.
const workerHarnessGoEnv = `{GODEBUG: "gcstoptheworld=1"}`

// The line the harness ends with, which names the bytes of linear memory the run grew to.
var workerHarnessMemoryPattern = regexp.MustCompile(`worker harness: wasm memory ([0-9]+) bytes`)

// Runs a js/wasm binary in the harness, with these arguments after its path.
func runInWorkerHarness(t *testing.T, wasmPath string, args ...string) ([]byte, error) {
	t.Helper()
	return runInHarness(t, workerHarness, wasmPath, args...)
}

// Runs a js/wasm binary in harness, which is workerHarness or a test's variant of it.
func runInHarness(t *testing.T, harness string, wasmPath string, args ...string) ([]byte, error) {
	t.Helper()
	// a failure and not a skip: a leg that did not run has not passed
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("the sidecar_http leg runs in node: %v", err)
	}
	goroot, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Fatal(err)
	}
	harnessPath := filepath.Join(t.TempDir(), "worker.js")
	if err := os.WriteFile(harnessPath, []byte(harness), 0o600); err != nil {
		t.Fatal(err)
	}
	wasmExecPath := filepath.Join(strings.TrimSpace(string(goroot)), "lib", "wasm", "wasm_exec.js")
	return exec.Command(node, append([]string{harnessPath, wasmPath, wasmExecPath}, args...)...).CombinedOutput()
}

// The bytes of linear memory a run in the harness grew to, or false when its output does not end the
// harness's way.
func workerHarnessMemoryByteCount(output []byte) (int64, bool) {
	match := workerHarnessMemoryPattern.FindSubmatch(output)
	if match == nil {
		return 0, false
	}
	byteCount, err := strconv.ParseInt(string(match[1]), 10, 64)
	return byteCount, err == nil
}

// Builds a one-file program for js/wasm, which the harness can then run.
func buildWorkerProgram(t *testing.T, source string) string {
	t.Helper()
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "main.go")
	wasmPath := filepath.Join(directory, "program.wasm")
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-o", wasmPath, sourcePath)
	build.Dir = directory
	build.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, output)
	}
	return wasmPath
}

// Ends the way its one argument names. armed exits with a runtime timer live in JS: when every goroutine
// is parked the scheduler hands the sleeper's timer to setTimeout, and main wakes from a JS callback due
// sooner, so the order is the event loop's and not the scheduler's.
const workerEndingProgram = `package main

import (
	"fmt"
	"os"
	"syscall/js"
	"time"
)

func main() {
	switch os.Args[1] {
	case "armed":
		go time.Sleep(50 * time.Millisecond)
		woken := make(chan struct{})
		wake := js.FuncOf(func(js.Value, []js.Value) any {
			close(woken)
			return nil
		})
		js.Global().Call("setTimeout", wake, 0)
		<-woken
		fmt.Println("ended")
		os.Exit(0)
	case "failed":
		fmt.Println("ended")
		os.Exit(3)
	case "stalled":
		fmt.Println("stalling")
		select {}
	}
}
`

// The harness's exit code is how its program ended, and the leg's verdict starts from it. A run that
// passed with a timer armed once failed here, and a run that stalled once passed. Each ending also
// reports linear memory, which the leg's bound reads.
func TestWorkerHarnessEndsAsItsProgramDoes(t *testing.T) {
	wasmPath := buildWorkerProgram(t, workerEndingProgram)

	cases := []struct {
		ending     string
		exitCode   int
		wantOutput string
	}{
		{ending: "armed", exitCode: 0, wantOutput: "ended"},
		{ending: "failed", exitCode: 3, wantOutput: "ended"},
		{ending: "stalled", exitCode: 2, wantOutput: "all goroutines are asleep"},
	}
	for _, c := range cases {
		output, err := runInWorkerHarness(t, wasmPath, c.ending)
		exitCode := 0
		if err != nil {
			exitError, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatalf("%s: %v", c.ending, err)
			}
			exitCode = exitError.ExitCode()
		}
		if exitCode != c.exitCode {
			t.Errorf("%s: exit code %d, want %d\n%s", c.ending, exitCode, c.exitCode, output)
		}
		if !strings.Contains(string(output), c.wantOutput) {
			t.Errorf("%s: no %q in\n%s", c.ending, c.wantOutput, output)
		}
		if _, ok := workerHarnessMemoryByteCount(output); !ok {
			t.Errorf("%s: no memory report in\n%s", c.ending, output)
		}
	}
}

// What a long test does to the runtime: it marks a heap of pointers, as every cycle must, while a loop
// that never blocks allocates 256 MiB of garbage in 64 KiB blocks.
const workerGcProgram = `package main

type node struct {
	next  *node
	links [7]*node
}

var live *node

var garbage []byte

func main() {
	for i := 0; i < 64*1024; i += 1 {
		live = &node{next: live}
	}
	for i := 0; i < 4*1024; i += 1 {
		garbage = make([]byte, 64*1024)
	}
}
`

// The harness's GC setting, both ways on one program. Under the harness each cycle ends where it
// starts, and the program needs about 12 MB, its 4 MiB heap of pointers and a little garbage. Without
// the setting the loop runs ahead of every cycle, each block a cycle saw allocated is marked live, and
// the program holds over 200 MB, nearly all the garbage it made: the leg's suite out of memory, in
// small. That half shows it is the setting the first half holds.
func TestWorkerHarnessFinishesEachGcCycleBeforeItsProgramGoesOn(t *testing.T) {
	wasmPath := buildWorkerProgram(t, workerGcProgram)
	memoryByteCount := func(harness string) int64 {
		t.Helper()
		output, err := runInHarness(t, harness, wasmPath)
		if err != nil {
			t.Fatalf("the program failed: %v\n%s", err, output)
		}
		byteCount, ok := workerHarnessMemoryByteCount(output)
		if !ok {
			t.Fatalf("no memory report in\n%s", output)
		}
		return byteCount
	}

	if byteCount := memoryByteCount(workerHarness); 64*1024*1024 < byteCount {
		t.Errorf("under the harness the program grew wasm memory to %d bytes: a cycle let it run on with its garbage", byteCount)
	}
	setEnv := "go.env = " + workerHarnessGoEnv + ";"
	unsetHarness := strings.Replace(workerHarness, setEnv, "go.env = {};", 1)
	if unsetHarness == workerHarness {
		t.Fatalf("the harness holds no %q to take out", setEnv)
	}
	if byteCount := memoryByteCount(unsetHarness); byteCount < 128*1024*1024 {
		t.Errorf("without the GC setting the program grew wasm memory to only %d bytes, so this no longer shows what the setting does", byteCount)
	}
}

// The whole sidecar_http suite on the leg itself, in a Worker's shape, which go_js_wasm_exec is not:
// under node's process global net/http never calls fetch, and what the page Worker's transport does
// with a url is a fetch matter (api_transport.go). So this is what proves §18.10's leg, and it names
// its fetch tests, the known answers for the mls_ and socket_ it keeps, mail's, tls's and evs's vectors, since a run
// that skipped them would still exit 0. The run is held to a quarter of wasm's 4 GiB, where it needs
// under 200 MB, so memory a change adds fails here by name rather than as an out-of-memory death on
// some later run.
func TestHttpLegPassesInAWorker(t *testing.T) {
	wasmPath := filepath.Join(t.TempDir(), "sidecar.test.wasm")

	build := exec.Command("go", "test", "-c", "-tags", "sidecar_http", "-o", wasmPath, ".")
	build.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go test -c: %v\n%s", err, output)
	}

	// these two read the source tree, which a Worker has no file system for
	skip := "^(TestHookFilesSplitOnTag|TestHooksEmptyWithoutTag)$"
	output, err := runInWorkerHarness(t, wasmPath, "-test.v", "-test.count=1", "-test.skip", skip)
	if err != nil {
		t.Fatalf("the leg's tests failed: %v\n%s", err, output)
	}
	for _, name := range []string{
		"TestWorkerFetchGetsNoRequestWithAnEmptyServiceUrl",
		"TestWorkerFetchTakesARelativeUrlFromNetHttp",
		"TestWorkerFetchGetsAnAbsoluteUrl",
		"TestValidSettingsPass",
		"TestAuthChainVectors",
		"TestMlsVectorFilesMatchUpstream",
		"TestMlsCryptoBasicsVectors",
		"TestMlsKeyScheduleVectors",
		"TestMlsSecretTreeVectors",
		"TestMlsTreeKemVectors",
		"TestXWingKatDecapsulationThroughHpke",
		"TestXWingKatEncapsulationThroughHpke",
		"TestSocketTokenVectors",
		"TestSocketSealVectors",
		"TestSocketSealDropVectors",
		"TestSocketTicketVectorsSign",
		"TestSocketTicketVectorsVerify",
		"TestSocketTicketVerifiesOverReceivedBytes",
		"TestSocketTicketVectorRefusals",
		"TestMailVectorsRoundTrip",
		"TestMailVectorsCoverEveryField",
		"TestMailVectorNames",
		"TestMailVectorMonths",
		"TestMailVectorClocks",
		"TestMailVectorOrders",
		"TestKeychainVectorsAreByteEqual",
		"TestKeychainVectorsOpen",
		"TestGkmLadderVectors",
		"TestGkmWrapAadVectors",
		"TestGkmWrapPathVectors",
		"TestEvsTokenVectors",
		"TestEvsDigestVectors",
		"TestEvsChainVectors",
		"TestEvsNfcAndNfdNamesAreTwoPaths",
		"TestEvsAnyReaderDerivesMainsRefId",
		"TestEvsMerkleKnownAnswers",
		"TestEvsPadmeTable",
		"TestUrMlsCredentialRoundTrip",
		"TestDpopVectorsAreByteEqual",
		"TestDpopVectorsVerify",
		"TestTlsKeyAttestationVectorsAreByteEqual",
		"TestTlsKeyAttestationVectorsVerify",
		"TestRefreshNotSentWithoutSigner",
		"TestEnrollRefusesBundle",
		"TestExchangeTokenPostsItsFormAndProof",
	} {
		if !strings.Contains(string(output), "--- PASS: "+name+" ") {
			t.Errorf("%s did not pass\n%s", name, output)
		}
	}
	memoryByteCount, ok := workerHarnessMemoryByteCount(output)
	if !ok {
		t.Errorf("no memory report in\n%s", output)
	} else if maxByteCount := int64(1024 * 1024 * 1024); maxByteCount < memoryByteCount {
		t.Errorf("the leg's tests grew wasm memory to %d bytes, past %d", memoryByteCount, maxByteCount)
	}
}

// Parses every root file that is not a test, on every leg at once, since a seam a leg's file skips is
// the flaw these look for.
func parseRootFiles(t *testing.T) map[string]*ast.File {
	t.Helper()
	files := map[string]*ast.File{}
	for _, goFile := range rootGoFiles(t) {
		if !strings.HasSuffix(goFile, "_test.go") {
			files[goFile] = parseGoFile(t, goFile)
		}
	}
	return files
}

func parseGoFile(t *testing.T, goFile string) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), goFile, nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func parseSyntheticFile(t *testing.T, src string) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "synthetic.go", "package sidecar\n"+src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

// Whether file declares a NewSidecar that never calls validate.
func newSidecarSkipsValidate(file *ast.File) bool {
	for _, decl := range file.Decls {
		function, ok := decl.(*ast.FuncDecl)
		if !ok || function.Recv != nil || function.Name.Name != "NewSidecar" || function.Body == nil {
			continue
		}
		validated := false
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok {
				if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "validate" {
					validated = true
				}
			}
			return true
		})
		if !validated {
			return true
		}
	}
	return false
}

// What keeps an empty url from the page Worker's fetch is settings.validate, so it holds only if every
// NewSidecar runs it. Nothing declares NewSidecar yet: CORE-M1-08 and CORE-M4-01 do, one per leg, and
// this fails either that leaves it out.
func TestNewSidecarRunsValidate(t *testing.T) {
	for goFile, file := range parseRootFiles(t) {
		if newSidecarSkipsValidate(file) {
			t.Errorf("%s: NewSidecar does not call settings.validate()", goFile)
		}
	}
}

func TestNewSidecarRuleCatchesAPlantedSkip(t *testing.T) {
	skipping := parseSyntheticFile(t, "func NewSidecar(settings *SidecarSettings) error { return nil }")
	if !newSidecarSkipsValidate(skipping) {
		t.Error("a NewSidecar with no validate passed")
	}
	calling := parseSyntheticFile(t, "func NewSidecar(settings *SidecarSettings) error { return settings.validate() }")
	if newSidecarSkipsValidate(calling) {
		t.Error("a NewSidecar calling validate failed")
	}
}

// The net/http names that reach its default transport, by-passing absoluteUrlTransport, found in file.
func defaultHttpNames(file *ast.File) []string {
	names := []string{}
	ast.Inspect(file, func(node ast.Node) bool {
		if selector, ok := node.(*ast.SelectorExpr); ok {
			if packageName, ok := selector.X.(*ast.Ident); ok && packageName.Name == "http" {
				switch selector.Sel.Name {
				case "DefaultTransport", "DefaultClient", "Get", "Head", "Post", "PostForm":
					names = append(names, selector.Sel.Name)
				}
			}
		}
		return true
	})
	return names
}

// Only the transport files may reach net/http's defaults: on the sidecar_http leg they are fetch, with
// no refusal of a relative url, and on a connect leg an unbound socket that can follow a tunnel's
// default route back into this process (CORE-M1-04).
func TestOnlyTheTransportFilesReachNetHttpDefaults(t *testing.T) {
	for goFile, file := range parseRootFiles(t) {
		if strings.HasPrefix(goFile, "api_transport") {
			continue
		}
		if names := defaultHttpNames(file); len(names) != 0 {
			t.Errorf("%s reaches http.%s", goFile, names[0])
		}
	}
}

func TestDefaultHttpRuleCatchesAPlantedCall(t *testing.T) {
	file := parseSyntheticFile(t, `import "net/http"
func f() { http.Post("/sidecar/bind", "", nil) }`)
	if names := defaultHttpNames(file); !slices.Equal(names, []string{"Post"}) {
		t.Errorf("names %q", names)
	}
}

// Whether file reads ServiceHost.Authenticator, which reaches round the checks in Authenticate.
func readsAuthenticatorField(file *ast.File) bool {
	found := false
	ast.Inspect(file, func(node ast.Node) bool {
		if selector, ok := node.(*ast.SelectorExpr); ok && selector.Sel.Name == "Authenticator" {
			found = true
		}
		return true
	})
	return found
}

// Engines come later, each in its <svc>service, and this fails the first to skip the checks.
func TestEnginesAuthenticateThroughTheHost(t *testing.T) {
	engineGoFiles, err := filepath.Glob("*service/*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, goFile := range engineGoFiles {
		if strings.HasSuffix(goFile, "_test.go") {
			continue
		}
		if readsAuthenticatorField(parseGoFile(t, goFile)) {
			t.Errorf("%s reads ServiceHost.Authenticator: call host.Authenticate", goFile)
		}
	}
	for goFile, file := range parseRootFiles(t) {
		if goFile != "host_auth.go" && readsAuthenticatorField(file) {
			t.Errorf("%s reads ServiceHost.Authenticator: call host.Authenticate", goFile)
		}
	}
}

func TestAuthenticatorRuleCatchesAPlantedRead(t *testing.T) {
	file := parseSyntheticFile(t, `func f(host *ServiceHost) { host.Authenticator.Authenticate(nil, "evs", "") }`)
	if !readsAuthenticatorField(file) {
		t.Error("a direct read passed")
	}
	file = parseSyntheticFile(t, `func f(host *ServiceHost) { host.Authenticate(nil, "evs", "") }`)
	if readsAuthenticatorField(file) {
		t.Error("the host's own call failed")
	}
}

// What `make check` will enforce from M1 (§4.7), on the whole transitive graph.
func TestHttpLegLinksNoConnectOrGvisor(t *testing.T) {
	deps := goListDeps(t, []string{"GOOS=js", "GOARCH=wasm"}, "-tags", "sidecar_http", ".")
	if !slices.Contains(deps, "github.com/urnetwork/sidecar") {
		t.Fatalf("deps %v", deps)
	}
	for _, dep := range deps {
		if namesConnect(dep) {
			t.Errorf("the sidecar_http leg links %s", dep)
		}
	}
}

// §4.5: engines never import server, so its libraries stay out of this module.
func TestRootLinksNoHostLibrary(t *testing.T) {
	deps := goListDeps(t, nil, ".")
	if !slices.Contains(deps, "github.com/urnetwork/connect") {
		t.Fatalf("the connect leg links no connect: %v", deps)
	}
	for _, dep := range deps {
		for _, refused := range []string{
			"github.com/urnetwork/server",
			"github.com/urnetwork/sdk",
			"github.com/redis/go-redis",
			"github.com/minio/minio-go",
			"github.com/prometheus/client_golang",
		} {
			if dep == refused || strings.HasPrefix(dep, refused+"/") {
				t.Errorf("the root links %s", dep)
			}
		}
	}
}
