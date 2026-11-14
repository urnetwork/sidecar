//go:build !js && !ios && !android && !sdk_mobile_bind

// Cloud agents (MCP-M4-02): the key rule of harness_cloud.go and what §16.9 holds beside it. No key is read from the
// environment, by behavior and by a scan of every environment read in ur's own source (CC4); the key file is taken
// once and removed, and refused unless it is its owner's alone; the committed connect step is one fixed command;
// server/mcp imports no sidecar package (D-MCP-7); and a session captured with nothing reachable spools, without a
// gap or a failed hook, and seals again once the writer does.

package mcp

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A key of the format's shape that admits nothing: test data, no real key.
const testCloudKey = harnessCloudKeyPrefix + "aaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// The files of ur's own source that may read the environment, by path under the module. A new reader is added here
// by the change that adds it, which is when someone looks at what it reads.
var testCloudEnvironmentReaders = []string{
	"cli/cmd_connect_cloud.go",
	"cli/commands.go",
	"cli/keychain_linux.go",
	"cli/unit_linux.go",
	"daemon_socket_unix.go",
	"identity_host_stores.go",
	"mcp/restore_point.go",
	"state_dir.go",
}

// Every non-test Go file of ur's own packages under root, the module's: the root package, mcp and cli.
func testCloudSourceFiles(t *testing.T, root string) []string {
	t.Helper()
	files := []string{}
	for _, directory := range []string{".", "mcp", "cli"} {
		entries, err := os.ReadDir(filepath.Join(root, directory))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			files = append(files, filepath.ToSlash(filepath.Join(directory, name)))
		}
	}
	if len(files) < 100 {
		t.Fatalf("only %d source files under %s: the scan is not reading ur's source", len(files), root)
	}
	return files
}

// CC4, and QD-041's rule: nothing reads a key from the agent's environment. An environment holding an auth key's
// prefix, in a value or a name, is one ur enrolls nothing under; an ordinary one is not. And in ur's own source the
// environment is read only by the files listed, none of them by a name that says key, token, secret or password.
func TestNoKeyInAgentEnv(t *testing.T) {
	ordinary := []string{"HOME=/home/agent", "PATH=/usr/bin:/bin", "HTTPS_PROXY=http://proxy.example.test:3128", "PS1=# ", "UR_INSTANCE=cloud"}
	if HarnessCloudEnvironmentHoldsKey(ordinary) || HarnessCloudEnvironmentHoldsKey(nil) {
		t.Error("an environment with no key reads as holding one")
	}
	holding := [][]string{
		append(slices.Clone(ordinary), "UR_AUTH_KEY="+testCloudKey),
		append(slices.Clone(ordinary), "SETUP_NOTE=run ur connect --token "+testCloudKey+" first"),
		append(slices.Clone(ordinary), harnessCloudKeyPrefix+"x=1"),
		{"ANYTHING=" + harnessCloudKeyPrefix},
	}
	for index, environ := range holding {
		if !HarnessCloudEnvironmentHoldsKey(environ) {
			t.Errorf("environment %d holds a key and reads as holding none", index)
		}
	}
	// the prefix is the format's: sidecar's own redaction covers a key by it
	if shown := sidecar.RedactAuthKey("key " + testCloudKey); strings.Contains(shown, testCloudKey) || !strings.HasPrefix(shown, "key "+harnessCloudKeyPrefix) {
		t.Errorf("the prefix is not the one sidecar covers a key by: %q", shown)
	}
	if strings.Contains(ErrHarnessCloudKeyEnvironment.Error(), harnessCloudKeyPrefix) {
		t.Error("the refusal names the key's text")
	}

	// the source: every read of the environment in ur's own packages
	root := ".."
	readers := map[string]bool{}
	fileSet := token.NewFileSet()
	for _, file := range testCloudSourceFiles(t, root) {
		parsed, err := parser.ParseFile(fileSet, filepath.Join(root, filepath.FromSlash(file)), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.SelectorExpr:
				if x, ok := node.X.(*ast.Ident); ok && (x.Name == "os" || x.Name == "syscall") &&
					slices.Contains([]string{"Getenv", "LookupEnv", "Environ", "ExpandEnv"}, node.Sel.Name) {
					readers[file] = true
				}
			case *ast.CallExpr:
				name := ""
				switch fun := node.Fun.(type) {
				case *ast.Ident:
					name = fun.Name
				case *ast.SelectorExpr:
					name = fun.Sel.Name
				}
				if lowered := strings.ToLower(name); lowered != "getenv" && lowered != "lookupenv" {
					return true
				}
				for _, arg := range node.Args {
					literal, ok := arg.(*ast.BasicLit)
					if !ok || literal.Kind != token.STRING {
						continue
					}
					variable, _ := strconv.Unquote(literal.Value)
					for _, word := range []string{"KEY", "TOKEN", "SECRET", "PASS", "AUTH"} {
						if strings.Contains(strings.ToUpper(variable), word) {
							t.Errorf("%s reads the environment's %s", file, variable)
						}
					}
				}
			}
			return true
		})
	}
	found := []string{}
	for file := range readers {
		found = append(found, file)
	}
	slices.Sort(found)
	if !slices.Equal(found, testCloudEnvironmentReaders) {
		t.Errorf("the files reading the environment:\n%s\nlisted:\n%s", strings.Join(found, "\n"), strings.Join(testCloudEnvironmentReaders, "\n"))
	}
}

// The key file is read once and gone: the key comes back without its line end, the file is removed, and a second
// take finds nothing.
func TestCloudKeyFileIsTakenOnce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no owner-only file mode")
	}
	path := filepath.Join(t.TempDir(), "authkey")
	if err := os.WriteFile(path, []byte(testCloudKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := TakeHarnessCloudKeyFile(path, nil)
	if err != nil || string(key) != testCloudKey {
		t.Fatalf("the key taken: %d bytes, %v", len(key), err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the key file is still there: %v", err)
	}
	if _, err := TakeHarnessCloudKeyFile(path, nil); !errors.Is(err, ErrHarnessCloudKeyFile) {
		t.Errorf("a second take: %v", err)
	}
	// a read-only file of its owner's is taken too
	if err := os.WriteFile(path, []byte(testCloudKey), 0o400); err != nil {
		t.Fatal(err)
	}
	if key, err := TakeHarnessCloudKeyFile(path, nil); err != nil || string(key) != testCloudKey {
		t.Errorf("a 0400 key file: %v", err)
	}
}

// A file that is not its owner's alone, a link, a directory, a relative path, an empty file and one longer than a key
// are refused by the one error, which names neither the path nor the key, and a file refused for what it is stays
// where it was.
func TestCloudKeyFileRefusals(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no owner-only file mode")
	}
	directory := t.TempDir()
	write := func(name string, content string, mode os.FileMode) string {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	settings := &sidecar.AuthKeySettings{MaxByteCount: len(testCloudKey)}
	target := write("target", testCloudKey, 0o600)
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	kept := map[string]string{
		"group-readable": write("group", testCloudKey, 0o640),
		"world-readable": write("world", testCloudKey, 0o604),
		"a link":         link,
		"a directory":    directory,
		"too long":       write("long", testCloudKey+"0123", 0o600),
	}
	for name, path := range kept {
		key, err := TakeHarnessCloudKeyFile(path, settings)
		if !errors.Is(err, ErrHarnessCloudKeyFile) || key != nil {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("%s: the refused file was removed: %v", name, err)
		}
	}
	if _, err := os.Lstat(target); err != nil {
		t.Errorf("the link's target was removed: %v", err)
	}
	for name, path := range map[string]string{
		"relative": "authkey",
		"missing":  filepath.Join(directory, "none"),
		"empty":    write("empty", "\n", 0o600),
	} {
		if key, err := TakeHarnessCloudKeyFile(path, settings); !errors.Is(err, ErrHarnessCloudKeyFile) || key != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if text := ErrHarnessCloudKeyFile.Error(); strings.Contains(text, directory) || strings.Contains(text, harnessCloudKeyPrefix) {
		t.Errorf("the refusal's text: %q", text)
	}
}

// The committed SessionStart step is one command of ur's path, the key file and the instance, each one shell word.
func TestCloudConnectCommand(t *testing.T) {
	if got := HarnessCloudConnectCommand("/usr/local/bin/ur", "/home/agent/.ur-authkey", ""); got != "/usr/local/bin/ur connect --token-file /home/agent/.ur-authkey --ephemeral" {
		t.Errorf("the command: %q", got)
	}
	got := HarnessCloudConnectCommand("/opt/my tools/ur", "/home/agent/key file", "cloud")
	if got != "'/opt/my tools/ur' connect --token-file '/home/agent/key file' --ephemeral --instance cloud" {
		t.Errorf("the quoted command: %q", got)
	}
	if words := harnessShellWords(got); len(words) != 7 || words[0] != "/opt/my tools/ur" || words[3] != "/home/agent/key file" {
		t.Errorf("the command's words: %q", words)
	}
	if strings.Contains(got, harnessCloudKeyPrefix) {
		t.Error("the committed command holds a key's prefix")
	}
}

// D-MCP-7: no URnetwork-hosted MCP serves sidecar tools, so server/mcp imports no sidecar package. The server
// repository is this one's sibling in every checkout that builds both; where it is absent there is nothing to read.
func TestServerMcpImportsNoSidecar(t *testing.T) {
	directory := filepath.Join("..", "..", "server", "mcp")
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("no server repository beside this one")
	}
	if err != nil {
		t.Fatal(err)
	}
	fileSet := token.NewFileSet()
	read := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		parsed, err := parser.ParseFile(fileSet, filepath.Join(directory, entry.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		read += 1
		for _, spec := range parsed.Imports {
			path, _ := strconv.Unquote(spec.Path.Value)
			if path == "github.com/urnetwork/sidecar" || strings.HasPrefix(path, "github.com/urnetwork/sidecar/") {
				t.Errorf("server/mcp/%s imports %s", entry.Name(), path)
			}
		}
	}
	if read == 0 {
		t.Fatal("server/mcp holds no Go file: the test read nothing")
	}
}

// A writer with nothing reachable: every draft waits in the spool while offline, and seals once it is not.
type testCloudSpoolingWriter struct {
	inner     *testRecordWriter
	stateLock sync.Mutex
	offline   bool
	spooled   []*sidecar.RecordDraft
}

func (self *testCloudSpoolingWriter) Append(draft *sidecar.RecordDraft) ([]*sidecar.RecordEntryRef, error) {
	spooled := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.offline {
			self.spooled = append(self.spooled, draft)
		}
		return self.offline
	}()
	if spooled {
		return []*sidecar.RecordEntryRef{{Spooled: true}}, nil
	}
	return self.inner.Append(draft)
}

func (self *testCloudSpoolingWriter) setOffline(offline bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.offline = offline
}

func (self *testCloudSpoolingWriter) spooledCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.spooled)
}

// Codex's agent phase blocks the internet, so ur's daemon spools: a session captured while the writer can seal
// nothing loses no event, fails no hook and counts no missed event, and its entries seal again once the writer does.
func TestOfflinePhaseSpools(t *testing.T) {
	env := newIngestTestEnv(t)
	writer := &testCloudSpoolingWriter{inner: env.writer, offline: true}
	env.ingest.detach()
	env.ingest = NewIngest(&IngestArgs{
		Server:    env.server,
		Writers:   func(network McpNetwork) (sidecar.RecordWriter, error) { return writer, nil },
		Redactors: func(network McpNetwork) (*sidecar.Redactor, error) { return env.redactor, nil },
		Record:    sidecar.DefaultSidecarSettings().Record,
	})
	harness := env.harnessIn(sidecartest.FakeHarnessCodex)
	steps := []error{
		harness.Hook(harness.Payload("s1", "UserPromptSubmit", map[string]any{"prompt": "Fix the build"})),
		harness.ToolCall("s1", true, "Bash", map[string]any{"command": "make"}),
		harness.ToolCall("s1", false, "Bash", map[string]any{"command": "make"}),
	}
	for index, err := range steps {
		if err != nil {
			t.Fatalf("offline step %d failed its hook: %v", index, err)
		}
	}
	runId := env.runOf("codex", "s1")
	offlineCount := writer.spooledCount()
	if offlineCount == 0 {
		t.Fatal("nothing was handed to the writer while offline")
	}
	if sealed := len(directoryAllDrafts(env.writer)); sealed != 0 {
		t.Fatalf("%d entries sealed while offline", sealed)
	}
	if env.hasGap(runId, sidecar.RecordCoverageGapMissedEvent) {
		t.Error("a spooled event was counted as missed")
	}

	// the phase ends: the writer seals again, and the run's later entries are sealed ones
	writer.setOffline(false)
	if err := harness.ToolCall("s1", false, "Bash", map[string]any{"command": "make test"}); err != nil {
		t.Fatal(err)
	}
	if writer.spooledCount() != offlineCount {
		t.Error("an entry spooled after the writer could seal")
	}
	if len(directoryAllDrafts(env.writer)) == 0 {
		t.Error("nothing sealed after the writer could seal")
	}
	if env.hasGap(runId, sidecar.RecordCoverageGapMissedEvent) {
		t.Error("an event was counted as missed")
	}
}
