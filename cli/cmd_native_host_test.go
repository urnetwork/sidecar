package main

// ur native-host against an in-process daemon: what it relays and what it refuses at the relay, every Confirm method
// and every revocation among them; that no reply carries a secret; that stdout carries frames alone; and the manifests
// install-daemon writes, naming only URnetwork's ids, or none. Ids and paths are synthetic.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A synthetic Chromium extension id and Firefox add-on id.
const (
	testNativeHostChromeId  = "abcdefghijklmnopabcdefghijklmnop"
	testNativeHostFirefoxId = "sidecar-test@nativehost.example"
)

// The ids a test configures.
func testNativeHostIds() *nativeHostIds {
	return &nativeHostIds{Chrome: []string{testNativeHostChromeId}, Firefox: []string{testNativeHostFirefoxId}}
}

// What a test daemon's synthetic methods saw.
type testNativeHostCalls struct {
	stateLock sync.Mutex
	// method names called, in order
	methods []string
	// whether each call came confirmed
	confirmed []bool
}

func (self *testNativeHostCalls) record(method string, call *sidecar.DaemonCall) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.methods = append(self.methods, method)
	self.confirmed = append(self.confirmed, call.Confirmed)
}

func (self *testNativeHostCalls) snapshot() ([]string, []bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.methods), slices.Clone(self.confirmed)
}

// A daemon serving ur's own methods and synthetic ones: a read, a Confirm method, a revocation, and one answering a
// secret. Each synthetic call is recorded.
func startTestNativeHostDaemon(t *testing.T) (*testUrDaemon, *testNativeHostCalls) {
	t.Helper()
	calls := &testNativeHostCalls{}
	target := &testUrDaemonTarget{statusValue: sidecar.SidecarStatus{State: sidecar.SidecarStateOnline, Generation: 4}}
	daemon := startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		if err := registerUrDaemonMethods(daemon, "default", target, osKeyStoreKeyFile, func() []sidecar.SidecarHostCredentialStore { return nil }); err != nil {
			t.Fatal(err)
		}
		for _, method := range testNativeHostSyntheticMethods(calls) {
			if err := daemon.RegisterMethod(method); err != nil {
				t.Fatal(err)
			}
		}
	})
	return daemon, calls
}

// The synthetic methods, each recording its call.
func testNativeHostSyntheticMethods(calls *testNativeHostCalls) []*sidecar.DaemonMethod {
	recorded := func(name string, confirm bool, result any) *sidecar.DaemonMethod {
		return &sidecar.DaemonMethod{Name: name, Confirm: confirm, Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			calls.record(name, call)
			return result, nil
		}}
	}
	return []*sidecar.DaemonMethod{
		recorded("synthetic.read", false, map[string]string{"read": "ok"}),
		recorded("synthetic.approve", true, map[string]string{"approved": "yes"}),
		recorded("devices.revoke", true, map[string]string{"revoked": "yes"}),
		recorded("synthetic.devicerevoke.preview", false, map[string]string{"plan": "yes"}),
		recorded("synthetic.secret", false, &sidecar.SidecarEnrollCredential{AuthKey: "ur-authkey-synthetic-secret-value"}),
		recorded("synthetic.large", false, map[string]string{"blob": strings.Repeat("y", 200*1024)}),
	}
}

// Frames of the requests, as a browser writes them.
func testNativeHostFrames(t *testing.T, requests ...string) io.Reader {
	t.Helper()
	stream := &bytes.Buffer{}
	for _, request := range requests {
		if err := writeNativeHostFrame(stream, []byte(request)); err != nil {
			t.Fatal(err)
		}
	}
	return stream
}

// Every frame on stdout, each parsed as JSON, a chunked reply joined; fails if stdout holds anything else.
func testNativeHostReplies(t *testing.T, stdout []byte) []map[string]any {
	t.Helper()
	reader := bytes.NewReader(stdout)
	replies := []map[string]any{}
	chunked := []byte{}
	for {
		frame, err := readNativeHostFrame(reader, nativeHostMaxFrameByteCount)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("stdout holds more than frames: %v", err)
		}
		chunk := &nativeHostChunk{}
		if json.Unmarshal(frame, chunk) == nil && chunk.Chunk.Count != 0 {
			data, err := base64.StdEncoding.DecodeString(chunk.DataBase64)
			if err != nil {
				t.Fatal(err)
			}
			chunked = append(chunked, data...)
			if chunk.Chunk.Index+1 < chunk.Chunk.Count {
				continue
			}
			frame, chunked = chunked, []byte{}
		}
		reply := map[string]any{}
		if err := json.Unmarshal(frame, &reply); err != nil {
			t.Fatalf("a frame is not JSON: %q", frame)
		}
		replies = append(replies, reply)
	}
	return replies
}

// The error code and message of a reply, or 0 and "" for a result.
func testNativeHostError(reply map[string]any) (int, string) {
	rpcError, ok := reply["error"].(map[string]any)
	if !ok {
		return 0, ""
	}
	code, _ := rpcError["code"].(float64)
	message, _ := rpcError["message"].(string)
	return int(code), message
}

// Runs ur native-host as a browser starts it, on requests, with relayed as its allow-list when set, answering stdout's
// bytes, stderr's text and the exit code.
func runTestNativeHost(t *testing.T, socketPath string, relayed []string, arguments []string, requests ...string) ([]byte, string, int) {
	t.Helper()
	cli, stdout, stderr := newTestUrCli(socketPath)
	cli.nativeHostIds = func() (*nativeHostIds, error) { return testNativeHostIds(), nil }
	cli.stdin = testNativeHostFrames(t, requests...)
	// small enough that synthetic.large's reply goes as chunks
	cli.settings.NativeHostChunkByteCount = 64 * 1024
	saved := nativeHostRelayedMethods
	if relayed != nil {
		nativeHostRelayedMethods = relayed
	}
	defer func() {
		nativeHostRelayedMethods = saved
	}()
	code := cli.main(context.Background(), append([]string{"ur", "native-host"}, arguments...))
	return stdout.Bytes(), stderr.String(), code
}

// Every Confirm method the daemon serves, ur's own and a synthetic one, is refused at the relay and never reaches the
// daemon, even on the allow-list and even asking for confirmation; and the allow-list holds no Confirm method.
func TestNativeHostRefusesConfirmMethods(t *testing.T) {
	daemon, calls := startTestNativeHostDaemon(t)
	methods := urDaemonMethods("default", &testUrDaemonTarget{}, osKeyStoreKeyFile, nil)
	methods = append(methods, testNativeHostSyntheticMethods(&testNativeHostCalls{})...)
	confirmMethods := []string{}
	for _, method := range methods {
		if method.Confirm {
			confirmMethods = append(confirmMethods, method.Name)
		}
		if method.Confirm && slices.Contains(nativeHostRelayedMethods, method.Name) {
			t.Errorf("the native host's allow-list holds the Confirm method %s", method.Name)
		}
	}
	if !slices.Contains(confirmMethods, "synthetic.approve") {
		t.Fatalf("CONTROL FAILED: no Confirm method in %v", confirmMethods)
	}
	for _, name := range confirmMethods {
		// even a list naming the method relays it unconfirmed, so the daemon refuses it
		stdout, _, code := runTestNativeHost(t, daemon.socketPath, []string{name}, []string{"chrome-extension://" + testNativeHostChromeId + "/"},
			`{"jsonrpc":"2.0","id":1,"method":"`+name+`"}`,
			`{"jsonrpc":"2.0","id":2,"method":"`+name+`","ur_confirmed":true}`,
		)
		if code != urExitOk {
			t.Fatalf("%s: exit %d", name, code)
		}
		replies := testNativeHostReplies(t, stdout)
		if len(replies) != 2 {
			t.Fatalf("%s: %d replies", name, len(replies))
		}
		for _, reply := range replies {
			if code, _ := testNativeHostError(reply); code == 0 {
				t.Errorf("%s was answered: %v", name, reply)
			}
		}
	}
	methodsCalled, _ := calls.snapshot()
	for _, name := range confirmMethods {
		if slices.Contains(methodsCalled, name) {
			t.Errorf("the Confirm method %s ran", name)
		}
	}
	// and on the real list, none is even sent
	stdout, _, _ := runTestNativeHost(t, daemon.socketPath, nil, []string{"chrome-extension://" + testNativeHostChromeId + "/"},
		`{"jsonrpc":"2.0","id":3,"method":"synthetic.approve"}`)
	if code, message := testNativeHostError(testNativeHostReplies(t, stdout)[0]); code != -32601 || !strings.Contains(message, "does not relay") {
		t.Errorf("a Confirm method off the list answered %d %q", code, message)
	}
}

// A revocation is answered REVOKE_NOT_CAPABLE by the native host itself, whatever the list says, and never reaches the
// daemon.
func TestNativeHostAnswersRevokeNotCapable(t *testing.T) {
	daemon, calls := startTestNativeHostDaemon(t)
	stdout, _, code := runTestNativeHost(t, daemon.socketPath, []string{"devices.revoke", "synthetic.devicerevoke.preview"},
		[]string{"chrome-extension://" + testNativeHostChromeId + "/"},
		`{"jsonrpc":"2.0","id":1,"method":"devices.revoke","params":{"sidecar_id":"x"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"synthetic.devicerevoke.preview"}`,
	)
	if code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	for _, reply := range testNativeHostReplies(t, stdout) {
		if _, message := testNativeHostError(reply); message != nativeHostRevokeNotCapable {
			t.Errorf("a revocation answered %v", reply)
		}
	}
	if methods, _ := calls.snapshot(); len(methods) != 0 {
		t.Errorf("the daemon saw %v", methods)
	}
}

// The allow-list's methods are relayed unconfirmed with their results; anything else, a request with a field
// JSON-RPC does not have, and a malformed request are refused at the relay; a notification gets no answer.
func TestNativeHostRelaysOnlyItsAllowList(t *testing.T) {
	daemon, calls := startTestNativeHostDaemon(t)
	stdout, stderr, code := runTestNativeHost(t, daemon.socketPath, []string{urMethodStatus, "synthetic.read"},
		[]string{"/synthetic/manifest/network.ur.ur.json", testNativeHostFirefoxId},
		`{"jsonrpc":"2.0","id":1,"method":"status"}`,
		`{"jsonrpc":"2.0","id":"two","method":"synthetic.read","params":{"a":1}}`,
		`{"jsonrpc":"2.0","id":3,"method":"unlock","params":{"pass":"c3ludGhldGlj"}}`,
		`{"jsonrpc":"2.0","id":4,"method":"synthetic.read","ur_confirmed":true}`,
		`{"jsonrpc":"2.0","method":"synthetic.read"}`,
		`not json`,
		`{"jsonrpc":"1.0","id":5,"method":"status"}`,
	)
	if code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	replies := testNativeHostReplies(t, stdout)
	if len(replies) != 6 {
		t.Fatalf("%d replies: %v", len(replies), replies)
	}
	status, _ := replies[0]["result"].(map[string]any)
	if replies[0]["id"] != float64(1) || status == nil || status["state"] != "online" {
		t.Errorf("status replied %v", replies[0])
	}
	read, _ := replies[1]["result"].(map[string]any)
	if replies[1]["id"] != "two" || read == nil || read["read"] != "ok" {
		t.Errorf("the read replied %v", replies[1])
	}
	for i, wantCode := range map[int]int{2: -32601, 3: -32600, 4: -32600, 5: -32600} {
		if code, _ := testNativeHostError(replies[i]); code != wantCode {
			t.Errorf("reply %d: %v, not code %d", i, replies[i], wantCode)
		}
	}
	methods, confirmed := calls.snapshot()
	if !slices.Equal(methods, []string{"synthetic.read"}) || slices.Contains(confirmed, true) {
		t.Errorf("the daemon saw %v, confirmed %v", methods, confirmed)
	}
}

// No reply carries a secret: a method answering one is refused by the daemon's walk, and the native host relays only
// the refusal; nothing the daemon refused reaches stdout or stderr.
func TestRepliesHoldNoSecret(t *testing.T) {
	daemon, _ := startTestNativeHostDaemon(t)
	stdout, stderr, code := runTestNativeHost(t, daemon.socketPath, []string{"synthetic.secret"},
		[]string{"chrome-extension://" + testNativeHostChromeId + "/"},
		`{"jsonrpc":"2.0","id":1,"method":"synthetic.secret"}`,
	)
	if code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	replies := testNativeHostReplies(t, stdout)
	if len(replies) != 1 {
		t.Fatalf("%d replies", len(replies))
	}
	if code, _ := testNativeHostError(replies[0]); code == 0 || replies[0]["result"] != nil {
		t.Errorf("the secret's method replied %v", replies[0])
	}
	for _, leaked := range []string{"synthetic-secret-value", "ur-authkey"} {
		if bytes.Contains(stdout, []byte(leaked)) || strings.Contains(stderr, leaked) {
			t.Errorf("%q reached the extension's streams", leaked)
		}
	}
}

// stdout carries frames alone, through refusals, an unreachable daemon, a chunked reply and a frame that ends the
// session; the session's complaints go to stderr.
func TestNothingLoggedToStdout(t *testing.T) {
	daemon, _ := startTestNativeHostDaemon(t)
	stdout, stderr, _ := runTestNativeHost(t, daemon.socketPath, []string{"synthetic.large", "synthetic.read"},
		[]string{"chrome-extension://" + testNativeHostChromeId + "/"},
		`{"jsonrpc":"2.0","id":1,"method":"synthetic.large"}`,
		`{"jsonrpc":"2.0","id":2,"method":"nothing.registered"}`,
		`[1, 2]`,
	)
	replies := testNativeHostReplies(t, stdout)
	if len(replies) != 3 {
		t.Fatalf("%d replies", len(replies))
	}
	// the large reply came as chunks that joined to the whole result
	if result, _ := replies[0]["result"].(map[string]any); result == nil || len(result["blob"].(string)) != 200*1024 {
		t.Errorf("the large reply joined to %v", replies[0]["error"])
	}
	frameCount := 0
	for reader := bytes.NewReader(stdout); ; frameCount += 1 {
		if _, err := readNativeHostFrame(reader, nativeHostMaxFrameByteCount); err != nil {
			break
		}
	}
	if frameCount < 5 {
		t.Errorf("%d frames: the large reply was not chunked", frameCount)
	}

	// no daemon at all: each request is answered on stdout, the reason on stderr
	stdout, stderr, _ = runTestNativeHost(t, filepath.Join(shortTestDirectory(t), "none"), []string{"synthetic.read"},
		[]string{"chrome-extension://" + testNativeHostChromeId + "/"},
		`{"jsonrpc":"2.0","id":1,"method":"synthetic.read"}`,
	)
	replies = testNativeHostReplies(t, stdout)
	if code, message := testNativeHostError(replies[0]); len(replies) != 1 || code != sidecar.DaemonRpcFailed || message != "the daemon did not answer" {
		t.Errorf("with no daemon: %v", replies)
	}
	if !strings.Contains(stderr, "ur native-host") {
		t.Errorf("stderr %q", stderr)
	}

	// a garbage length ends the session with an error on stderr and nothing on stdout past the frames before it
	cli, stdoutBuffer, stderrBuffer := newTestUrCli(daemon.socketPath)
	cli.nativeHostIds = func() (*nativeHostIds, error) { return testNativeHostIds(), nil }
	garbage := make([]byte, 4)
	binary.NativeEndian.PutUint32(garbage, 0xfffffff0)
	cli.stdin = io.MultiReader(testNativeHostFrames(t, `{"jsonrpc":"2.0","id":1,"method":"status"}`), bytes.NewReader(garbage))
	if code := cli.main(context.Background(), []string{"ur", "native-host", "chrome-extension://" + testNativeHostChromeId + "/"}); code != urExitFailed {
		t.Errorf("a garbage length: exit %d", code)
	}
	if replies := testNativeHostReplies(t, stdoutBuffer.Bytes()); len(replies) != 1 || !strings.Contains(stderrBuffer.String(), "length refused") {
		t.Errorf("a garbage length: %v, %q", replies, stderrBuffer.String())
	}
}

// A browser that is not URnetwork's extension, or any browser while no id is configured, gets no frame and no relay.
func TestNativeHostServesOnlyOurExtension(t *testing.T) {
	daemon, calls := startTestNativeHostDaemon(t)
	for _, arguments := range [][]string{
		{"chrome-extension://ponmlkjihgfedcbaponmlkjihgfedcba/"},
		{"/synthetic/manifest/network.ur.ur.json", "other@nativehost.example"},
		{},
		{"--parent-window=7", "chrome-extension://ponmlkjihgfedcbaponmlkjihgfedcba/"},
	} {
		stdout, _, code := runTestNativeHost(t, daemon.socketPath, []string{"synthetic.read"}, arguments,
			`{"jsonrpc":"2.0","id":1,"method":"synthetic.read"}`)
		if code != urExitFailed || len(stdout) != 0 {
			t.Errorf("%v: exit %d, %d bytes", arguments, code, len(stdout))
		}
	}
	// Chrome on Windows adds its window
	stdout, _, code := runTestNativeHost(t, daemon.socketPath, []string{"synthetic.read"},
		[]string{"--parent-window=7", "chrome-extension://" + testNativeHostChromeId + "/"},
		`{"jsonrpc":"2.0","id":1,"method":"synthetic.read"}`)
	if code != urExitOk || len(testNativeHostReplies(t, stdout)) != 1 {
		t.Errorf("our extension on windows: exit %d", code)
	}

	cli, stdoutBuffer, _ := newTestUrCli(daemon.socketPath)
	cli.stdin = testNativeHostFrames(t, `{"jsonrpc":"2.0","id":1,"method":"status"}`)
	// the embedded ids, which are none until the release supplies them
	if code := cli.main(context.Background(), []string{"ur", "native-host", "chrome-extension://" + testNativeHostChromeId + "/"}); code != urExitFailed || stdoutBuffer.Len() != 0 {
		t.Errorf("with no ids configured: exit %d", code)
	}
	if methods, _ := calls.snapshot(); !slices.Equal(methods, []string{"synthetic.read"}) {
		t.Errorf("the daemon saw %v", methods)
	}
}

// Each OS's manifests name only URnetwork's ids, Chromium's family by origin and Firefox by add-on, with the launcher
// as their path, and the launcher runs this ur for the instance.
func TestManifestNamesOnlyOurIds(t *testing.T) {
	ids := testNativeHostIds()
	for _, env := range []*unitEnv{
		{goos: "darwin", home: "/Users/synthetic"},
		{goos: "linux", home: "/home/synthetic"},
		{goos: "windows"},
	} {
		stateDirectory := "/synthetic/state"
		executable := "/opt/synthetic/ur"
		if env.goos == "windows" {
			stateDirectory = `C:\Users\synthetic\AppData\Local\URnetwork\default`
			executable = `C:\Program Files\URnetwork\ur.exe`
		}
		plan, err := nativeHostPlanFor(env, stateDirectory, "default", executable, ids)
		if err != nil {
			t.Fatalf("%s: %v", env.goos, err)
		}
		manifestCount := 0
		var launcher string
		for _, file := range plan.files {
			if !strings.HasSuffix(file.path, ".json") {
				launcher = file.path
				if !strings.Contains(string(file.content), executable) || !strings.Contains(string(file.content), "--instance default native-host") {
					t.Errorf("%s: the launcher %q", env.goos, file.content)
				}
				continue
			}
			manifestCount += 1
			manifest := &nativeHostManifest{}
			if err := jsonUnmarshalStrict(file.content, manifest); err != nil {
				t.Fatalf("%s: %s: %v", env.goos, file.path, err)
			}
			if manifest.Name != nativeHostName || manifest.Type != "stdio" || manifest.Path != launcher {
				t.Errorf("%s: %s: %+v", env.goos, file.path, manifest)
			}
			if 0 < len(manifest.AllowedOrigins) {
				if !slices.Equal(manifest.AllowedOrigins, []string{"chrome-extension://" + testNativeHostChromeId + "/"}) || len(manifest.AllowedExtensions) != 0 {
					t.Errorf("%s: %s names %v", env.goos, file.path, manifest.AllowedOrigins)
				}
			} else if !slices.Equal(manifest.AllowedExtensions, []string{testNativeHostFirefoxId}) {
				t.Errorf("%s: %s names %v", env.goos, file.path, manifest.AllowedExtensions)
			}
			if strings.Contains(string(file.content), "*") {
				t.Errorf("%s: %s holds a wildcard", env.goos, file.path)
			}
		}
		switch env.goos {
		case "windows":
			// one manifest a family, with a registry key a browser
			if manifestCount != 2 || len(plan.install) != 5 || len(plan.uninstall) != 5 {
				t.Errorf("windows: %d manifests, %d keys", manifestCount, len(plan.install))
			}
			for _, command := range plan.install {
				if command[0] != "reg" || !strings.HasPrefix(command[2], `HKCU\Software\`) || !strings.HasSuffix(command[2], `\NativeMessagingHosts\`+nativeHostName) {
					t.Errorf("windows: %v", command)
				}
			}
		default:
			// Chrome, Chromium, Edge, Brave and Firefox
			if manifestCount != 5 || len(plan.install) != 0 {
				t.Errorf("%s: %d manifests", env.goos, manifestCount)
			}
		}
	}

	if _, err := parseNativeHostIds([]byte(`{"chrome": ["*"], "firefox": []}`)); err == nil {
		t.Error("a wildcard parsed as an extension id")
	}
	if _, err := parseNativeHostIds([]byte(`{"chrome": [], "firefox": ["not an id"]}`)); err == nil {
		t.Error("a malformed add-on id parsed")
	}
	if ids, err := embeddedNativeHostIds(); err != nil || ids == nil {
		t.Errorf("the embedded ids: %v", err)
	}
}

// With no id configured, which is the embedded data until the release supplies it, nothing is written or run, and
// install-daemon installs no manifest.
func TestNoManifestWithoutIds(t *testing.T) {
	for _, ids := range []*nativeHostIds{{}, {Chrome: []string{}, Firefox: []string{}}} {
		for _, goos := range []string{"darwin", "linux", "windows"} {
			plan, err := nativeHostPlanFor(&unitEnv{goos: goos, home: "/synthetic"}, "/synthetic/state", "default", "/synthetic/ur", ids)
			if err != nil || plan != nil {
				t.Errorf("%s: %+v, %v", goos, plan, err)
			}
		}
	}
	embedded, err := embeddedNativeHostIds()
	if err != nil {
		t.Fatal(err)
	}
	if 0 < len(embedded.Chrome)+len(embedded.Firefox) {
		t.Skip("the release supplied extension ids")
	}
	home := t.TempDir()
	cli, _, _ := newTestUrCli("")
	cli.instance = nativeHostInstance
	cli.stateDirectory = func(instance string) (string, error) { return filepath.Join(home, "state"), nil }
	plan, err := cli.nativeHostPlan(&unitEnv{goos: "linux", home: home}, "/synthetic/ur")
	if err != nil || plan != nil {
		t.Errorf("the embedded ids planned %+v, %v", plan, err)
	}
}

// install-daemon writes the default instance's manifests and launcher once, idempotently, and uninstall-daemon removes
// them; another instance writes none.
func TestInstallDaemonWritesTheManifests(t *testing.T) {
	home := t.TempDir()
	env := &unitEnv{goos: "linux", home: home}
	stateDirectory := filepath.Join(home, "state")
	ids := testNativeHostIds()
	plan, err := nativeHostPlanFor(env, stateDirectory, "default", "/synthetic/ur", ids)
	if err != nil {
		t.Fatal(err)
	}
	runner := func(ctx context.Context, name string, args ...string) error { return nil }
	for range 2 {
		if err := installNativeHostPlan(context.Background(), runner, plan); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range plan.files {
		content, err := os.ReadFile(file.path)
		if err != nil || !bytes.Equal(content, file.content) {
			t.Errorf("%s: %v", file.path, err)
		}
		info, err := os.Stat(file.path)
		if err == nil && info.Mode().Perm() != file.mode {
			t.Errorf("%s has mode %v", file.path, info.Mode().Perm())
		}
	}
	if err := uninstallNativeHostPlan(context.Background(), runner, plan); err != nil {
		t.Fatal(err)
	}
	for _, file := range plan.files {
		if _, err := os.Stat(file.path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s outlived the uninstall", file.path)
		}
	}

	cli, _, _ := newTestUrCli("")
	cli.instance = "work"
	cli.nativeHostIds = func() (*nativeHostIds, error) { return ids, nil }
	if plan, err := cli.nativeHostPlan(env, "/synthetic/ur"); err != nil || plan != nil {
		t.Errorf("another instance planned %+v, %v", plan, err)
	}
}
