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
// it is handed and then fails, so nothing leaves. The test binary's flags follow the two paths. It ends
// as the toolchain's wasm_exec_node.js does, whose two exit rules are the verdict's: node goes with the
// Go program, or a timer the runtime armed fires into a program that has gone and fails a passing run,
// and node never ends 0 with Go still running, or a suite that stalled would pass.
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
go.exit = (code) => nodeProcess.exit(code);
WebAssembly.instantiate(fs.readFileSync(wasmPath), go.importObject)
	.then((result) => {
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

// Runs a js/wasm binary in the harness, with these arguments after its path.
func runInWorkerHarness(t *testing.T, wasmPath string, args ...string) ([]byte, error) {
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
	if err := os.WriteFile(harnessPath, []byte(workerHarness), 0o600); err != nil {
		t.Fatal(err)
	}
	wasmExecPath := filepath.Join(strings.TrimSpace(string(goroot)), "lib", "wasm", "wasm_exec.js")
	return exec.Command(node, append([]string{harnessPath, wasmPath, wasmExecPath}, args...)...).CombinedOutput()
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
// passed with a timer armed once failed here, and a run that stalled once passed.
func TestWorkerHarnessEndsAsItsProgramDoes(t *testing.T) {
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "main.go")
	wasmPath := filepath.Join(directory, "ending.wasm")
	if err := os.WriteFile(sourcePath, []byte(workerEndingProgram), 0o600); err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-o", wasmPath, sourcePath)
	build.Dir = directory
	build.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, output)
	}

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
	}
}

// The whole sidecar_http suite on the leg itself, in a Worker's shape, which go_js_wasm_exec is not:
// under node's process global net/http never calls fetch, and what the page Worker's transport does
// with a url is a fetch matter (api_transport.go). So this is what proves §18.10's leg, and it names
// its fetch tests, the known answers for the mls_ and socket_ it keeps and mail's vectors, since a run
// that skipped them would still exit 0.
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
		"TestMailVectorsRoundTrip",
		"TestMailVectorsCoverEveryField",
		"TestMailVectorNames",
		"TestMailVectorMonths",
		"TestMailVectorClocks",
		"TestMailVectorOrders",
		"TestKeychainVectorsAreByteEqual",
		"TestKeychainVectorsOpen",
	} {
		if !strings.Contains(string(output), "--- PASS: "+name+" ") {
			t.Errorf("%s did not pass\n%s", name, output)
		}
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
