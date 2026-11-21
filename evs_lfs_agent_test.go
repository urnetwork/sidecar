//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// The git-lfs transfer agent (EVS2-M10-25): its protocol on scripted lines (init answered {} first, upload and
// download completing, a missing object's error naming it, a progress event before a large object, a transfer before
// init refused, terminate); against this host's stock git-lfs, with this test binary as the agent over a directory
// store, a push uploading through the agent, `git lfs push --object-id`, a clone's checkout smudging through it, a
// pruned object left as its pointer with exit 0, and several agents at once; and the store's UploadFile touching what
// it holds and refusing an object past 2 GiB by name.

package sidecar

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// This test binary runs as the agent when git-lfs starts it with UR_TEST_LFS_AGENT_STORE set: a directory store,
// each object a file named by its oid.
func TestMain(m *testing.M) {
	if store := os.Getenv("UR_TEST_LFS_AGENT_STORE"); store != "" {
		appendFile := func(name string, line string) {
			file, err := os.OpenFile(filepath.Join(store, name), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
			if err == nil {
				fmt.Fprintln(file, line)
				file.Close()
			}
		}
		appendFile("agents.log", fmt.Sprint(os.Getpid()))
		gitDir := os.Getenv("GIT_DIR")
		if gitDir == "" {
			gitDir = ".git"
		}
		gitDir, _ = filepath.Abs(gitDir)
		os.Exit(RunEvsLfsAgent(context.Background(), &EvsLfsAgentArgs{
			Backend: &evsTestDirectoryBackend{dir: store}, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
			TempDir: filepath.Join(gitDir, "lfs", "tmp"),
		}))
	}
	os.Exit(m.Run())
}

// A store of files by oid in a directory, which several agent processes share.
type evsTestDirectoryBackend struct {
	dir string
}

func (self *evsTestDirectoryBackend) Upload(ctx context.Context, oid EvsLfsOid, size int64, path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if int64(len(content)) != size || EvsLfsOid(sha256.Sum256(content)) != oid {
		return fmt.Errorf("%w: %s", ErrEvsLfsObjectInvalid, oid)
	}
	return os.WriteFile(filepath.Join(self.dir, oid.String()), content, 0o600)
}

func (self *evsTestDirectoryBackend) Download(ctx context.Context, oid EvsLfsOid, size int64, path string) error {
	content, err := os.ReadFile(filepath.Join(self.dir, oid.String()))
	if errors.Is(err, os.ErrNotExist) {
		return &EvsLfsMissingError{Oid: oid}
	}
	if err != nil {
		return err
	}
	return os.WriteFile(path, content, 0o600)
}

// A backend holding objects in memory.
type evsTestMemoryBackend struct {
	stateLock sync.Mutex
	objects   map[EvsLfsOid][]byte
}

func (self *evsTestMemoryBackend) Upload(ctx context.Context, oid EvsLfsOid, size int64, path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.objects[oid] = content
	return nil
}

func (self *evsTestMemoryBackend) Download(ctx context.Context, oid EvsLfsOid, size int64, path string) error {
	self.stateLock.Lock()
	content, ok := self.objects[oid]
	self.stateLock.Unlock()
	if !ok {
		return &EvsLfsMissingError{Oid: oid}
	}
	return os.WriteFile(path, content, 0o600)
}

// The protocol on scripted lines: see the file header.
func TestEvsLfsAgentProtocol(t *testing.T) {
	dir := t.TempDir()
	content := []byte("object bytes")
	oid := EvsLfsOid(sha256.Sum256(content))
	source := filepath.Join(dir, "source")
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	backend := &evsTestMemoryBackend{objects: map[EvsLfsOid][]byte{}}
	absent := EvsLfsOid(sha256.Sum256([]byte("absent")))
	lines := []string{
		fmt.Sprintf(`{"event":"upload","oid":%q,"size":%d,"path":%q}`, oid, len(content), source),
		`{"event":"init","operation":"upload","remote":"origin","concurrent":true,"concurrenttransfers":3}`,
		fmt.Sprintf(`{"event":"upload","oid":%q,"size":%d,"path":%q,"action":null}`, oid, len(content), source),
		fmt.Sprintf(`{"event":"download","oid":%q,"size":%d}`, oid, len(content)),
		fmt.Sprintf(`{"event":"download","oid":%q,"size":5}`, absent),
		`{"event":"terminate"}`,
		`{"event":"init"}`,
	}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := RunEvsLfsAgent(context.Background(), &EvsLfsAgentArgs{
		Backend: backend, Stdin: strings.NewReader(strings.Join(lines, "\n") + "\n"), Stdout: stdout, Stderr: stderr,
		TempDir: filepath.Join(dir, "lfs", "tmp"), ProgressByteCount: int64(len(content)),
	})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	answers := []*evsLfsAgentMessage{}
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		if len(answers) == 1 {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(scanner.Bytes(), &fields); err != nil || fields == nil || len(fields) != 0 {
				t.Fatalf("init reply %q, want an empty object", scanner.Text())
			}
		}
		answer := &evsLfsAgentMessage{}
		if err := json.Unmarshal(scanner.Bytes(), answer); err != nil {
			t.Fatalf("an answer that is no JSON: %q", scanner.Text())
		}
		answers = append(answers, answer)
	}
	// before init: refused; init: {}; the upload: progress then complete; the download: progress then complete with a
	// path; the absent object: an error naming it; nothing after terminate
	if len(answers) != 7 {
		t.Fatalf("%d answers: %q", len(answers), stdout.String())
	}
	if answers[0].Error == nil {
		t.Fatalf("transfer before init: %+v", answers[0])
	}
	if answers[2].Event != "progress" || answers[3].Event != "complete" || answers[3].Error != nil || answers[3].Oid != oid.String() {
		t.Fatalf("the upload: %+v %+v", answers[2], answers[3])
	}
	if answers[5].Event != "complete" || answers[5].Path == "" {
		t.Fatalf("the download: %+v", answers[5])
	}
	if downloaded, err := os.ReadFile(answers[5].Path); err != nil || !bytes.Equal(downloaded, content) {
		t.Fatalf("the downloaded file: %v", err)
	}
	if answers[6].Error == nil || answers[6].Error.Code != evsLfsAgentCodeNotFound || !strings.Contains(answers[6].Error.Message, absent.String()) {
		t.Fatalf("the absent object: %+v", answers[6])
	}
	if bytes.Contains(stdout.Bytes(), []byte(source)) || bytes.Contains(stderr.Bytes(), []byte(source)) {
		t.Fatal("a path was echoed")
	}
}

// git with the agent's environment: no user config, and this test binary's store.
func evsTestLfsGit(t *testing.T, dir string, env []string, args ...string) (string, error) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = dir
	command.Env = append([]string{"HOME=" + filepath.Dir(dir), "GIT_CONFIG_NOSYSTEM=1", "PATH=" + os.Getenv("PATH"),
		"GIT_TERMINAL_PROMPT=0", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x.example", "GIT_COMMITTER_NAME=t",
		"GIT_COMMITTER_EMAIL=t@x.example"}, env...)
	out, err := command.CombinedOutput()
	return string(out), err
}

// This host's stock git-lfs moves objects through the agent: see the file header.
func TestEvsLfsAgentWithStockGitLfs(t *testing.T) {
	if _, err := exec.LookPath("git-lfs"); err != nil {
		t.Skip("no git-lfs on this host")
	}
	git := evsTestGitRunner(t)
	agentPath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	store := filepath.Join(root, "store")
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	env := []string{"UR_TEST_LFS_AGENT_STORE=" + store}
	run := func(dir string, args ...string) string {
		t.Helper()
		out, err := evsTestLfsGit(t, dir, env, args...)
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return out
	}
	remote := filepath.Join(root, "remote.git")
	run(root, "init", "-q", "--bare", remote)
	work := filepath.Join(root, "work")
	run(root, "init", "-q", "-b", "main", work)
	run(work, "lfs", "install", "--local")
	if err := EvsLfsConfigureClone(context.Background(), git, filepath.Join(work, ".git"), agentPath, "-test.run=^$"); err != nil {
		t.Fatal(err)
	}
	run(work, "lfs", "track", "*.bin")
	contents := map[string][]byte{}
	for i := 0; i < 5; i += 1 {
		name := fmt.Sprintf("object-%d.bin", i)
		contents[name] = evsTestContent(name, 20000+i)
		if err := os.WriteFile(filepath.Join(work, name), contents[name], 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run(work, "add", "-A")
	run(work, "commit", "-q", "-m", "objects")
	run(work, "remote", "add", "origin", remote)
	run(work, "push", "-q", "origin", "main")
	for name, content := range contents {
		oid := EvsLfsOid(sha256.Sum256(content))
		if stored, err := os.ReadFile(filepath.Join(store, oid.String())); err != nil || !bytes.Equal(stored, content) {
			t.Fatalf("%s did not reach the store through the agent: %v", name, err)
		}
	}
	// git lfs push --object-id uploads one object again through the agent
	first := EvsLfsOid(sha256.Sum256(contents["object-0.bin"]))
	os.Remove(filepath.Join(store, first.String()))
	run(work, "lfs", "push", "--object-id", "origin", first.String())
	if _, err := os.Stat(filepath.Join(store, first.String())); err != nil {
		t.Fatalf("git lfs push --object-id did not upload: %v", err)
	}
	// a clone configured before its checkout smudges through the agent
	clone := filepath.Join(root, "clone")
	run(root, "clone", "-q", "--no-checkout", remote, clone)
	run(clone, "lfs", "install", "--local")
	if err := EvsLfsConfigureClone(context.Background(), git, filepath.Join(clone, ".git"), agentPath, "-test.run=^$"); err != nil {
		t.Fatal(err)
	}
	run(clone, "checkout", "-q", "main")
	for name, content := range contents {
		if checkedOut, err := os.ReadFile(filepath.Join(clone, name)); err != nil || !bytes.Equal(checkedOut, content) {
			t.Fatalf("%s did not check out through the agent: %v", name, err)
		}
	}
	// a pruned object checks out as its pointer, exit 0, under lfs.skipdownloaderrors
	pruned := EvsLfsOid(sha256.Sum256(contents["object-1.bin"]))
	if err := os.Remove(filepath.Join(store, pruned.String())); err != nil {
		t.Fatal(err)
	}
	pointerClone := filepath.Join(root, "pointers")
	run(root, "clone", "-q", "--no-checkout", remote, pointerClone)
	run(pointerClone, "lfs", "install", "--local")
	if err := EvsLfsConfigureClone(context.Background(), git, filepath.Join(pointerClone, ".git"), agentPath, "-test.run=^$"); err != nil {
		t.Fatal(err)
	}
	out, err := evsTestLfsGit(t, pointerClone, env, "checkout", "main")
	if err != nil {
		t.Fatalf("a checkout with a pruned object failed: %v: %s", err, out)
	}
	checkedOut, err := os.ReadFile(filepath.Join(pointerClone, "object-1.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if pointer, ok := EvsLfsParsePointer(checkedOut, 1024); !ok || pointer.Oid != pruned {
		t.Fatalf("the pruned object checked out as %q", checkedOut)
	}
	agents, err := os.ReadFile(filepath.Join(store, "agents.log"))
	if err != nil || len(strings.Fields(string(agents))) < 3 {
		t.Fatalf("agent processes: %q %v", agents, err)
	}
}

// The store's UploadFile creates an object it does not hold, touches one it does with no upload, and refuses an object
// past 2 GiB by name before reading its file.
func TestEvsLfsStoreUploadFileTouchesWhatItHolds(t *testing.T) {
	lfs := newEvsTestLfsStore(t)
	ctx := context.Background()
	content, oid := evsTestLfsObject("agent object", 1200)
	path := filepath.Join(t.TempDir(), "object")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	lfs.writer.server.know(EvsLfsPath(oid))
	created, err := lfs.store.UploadFile(ctx, oid, int64(len(content)), path)
	if err != nil || created.Version != 1 {
		t.Fatalf("the first upload: %+v %v", created, err)
	}
	touched, err := lfs.store.UploadFile(ctx, oid, int64(len(content)), path)
	if err != nil || touched.Version != 2 {
		t.Fatalf("the second upload: %+v %v", touched, err)
	}
	if lfs.uploads() != 1 {
		t.Fatalf("a touch uploaded: %d uploads", lfs.uploads())
	}
	var tooLarge *EvsLfsTooLargeError
	if _, err := lfs.store.UploadFile(ctx, oid, 2*1024*1024*1024+1, "/nonexistent"); !errors.As(err, &tooLarge) {
		t.Fatalf("an object past 2 GiB: %v", err)
	}
	out := filepath.Join(t.TempDir(), "out")
	if err := os.WriteFile(out, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := lfs.store.DownloadFile(ctx, oid, out); err != nil {
		t.Fatal(err)
	}
	if downloaded, err := os.ReadFile(out); err != nil || !bytes.Equal(downloaded, content) {
		t.Fatalf("download: %v", err)
	}
	_ = io.Discard
}
