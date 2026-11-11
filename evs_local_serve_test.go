//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// EVS1-M2-38's root tests: `git clone ur://<net>/id:<repo>` with no prior mount (§11.20's added case), through this
// test binary standing as git-remote-ur on git's PATH and a real daemon whose git mode hands the session to
// EvsClient.ServeGit; a fetch and a push through the helper; the id forms <repo> takes; and the helper's protocol
// with git, capabilities answered with connect alone.

package sidecar

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The environment variable that turns this test binary into git-remote-ur (the helper process below).
const evsTestGitRemoteSocketVariable = "UR_TEST_GIT_REMOTE_SOCKET"

// Not a test: git runs this binary as git-remote-ur <remote> <url> through the script a test puts on its PATH, and it
// speaks the helper's protocol to the daemon whose socket the variable names.
func TestEvsGitRemoteHelperProcess(t *testing.T) {
	socket := os.Getenv(evsTestGitRemoteSocketVariable)
	if socket == "" {
		return
	}
	code := EvsGitRemoteHelper(context.Background(), &EvsGitRemoteHelperArgs{
		Url: os.Args[len(os.Args)-1],
		Dial: func(ctx context.Context, repo string, service string) (io.ReadWriteCloser, error) {
			client, err := DialDaemon(ctx, socket, &DaemonHello{Mode: DaemonModeGit, Version: testDaemonVersion, Repo: repo, Service: service})
			if err != nil {
				return nil, err
			}
			return &evsTestHookStream{ReadWriter: client.Stream(), client: client}, nil
		},
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
	})
	os.Exit(code)
}

// A daemon serving git's mode through the writer's client's ServeGit, its mounts' hooks installed, and a PATH holding
// git-remote-ur: the environment a client's git runs in.
func newEvsTestRemote(t *testing.T, publisher *evsTestPublisher) (*EvsMounts, []string) {
	t.Helper()
	client := publisher.writer.test.client
	mounts, err := NewEvsMounts(client, t.TempDir(), evsTestGitRunner(t))
	if err != nil {
		t.Fatal(err)
	}
	started := startTestDaemon(t, nil)
	if err := started.daemon.RegisterMode(DaemonModeGit, func(ctx context.Context, hello *DaemonHello, stream io.ReadWriter) error {
		_, repo, _ := strings.Cut(hello.Repo, "/")
		return client.ServeGit(ctx, &DaemonGitSession{Hello: hello, Repo: repo, Service: hello.Service, Stream: stream})
	}); err != nil {
		t.Fatal(err)
	}
	if err := started.daemon.RegisterMode(DaemonModeGitHook, func(ctx context.Context, hello *DaemonHello, stream io.ReadWriter) error {
		return mounts.ServeGitHook(ctx, hello.Service, stream)
	}); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := mounts.SetHookCommand([]string{binary, "-test.run=^TestEvsGitHookHelperProcess$", "--"},
		[]string{evsTestGitHookSocketVariable + "=" + started.socketPath}); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	script := "#!/bin/sh\nexec '" + binary + "' -test.run='^TestEvsGitRemoteHelperProcess$' -- \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "git-remote-ur"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return mounts, []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), evsTestGitRemoteSocketVariable + "=" + started.socketPath}
}

// §11.20's added case: a clone of ur://<net>/id:<repo> with no prior mount makes an implicit one, with no directory,
// replays main into it and serves it; a push through the helper goes through the hooks to evs, and a fetch brings it.
func TestEvsLocalServeCloneWithNoPriorMount(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	c1 := publisher.commit(map[string]string{"README": "hello\n"})
	if _, err := publisher.publish("main", &c1); err != nil {
		t.Fatal(err)
	}
	mounts, env := newEvsTestRemote(t, publisher)
	url := "ur://team.test/id:" + publisher.writer.world.repoId.String()
	dir := filepath.Join(t.TempDir(), "clone")
	if out, ok := evsTestGitWith(t, env, "clone", "-q", url, dir); !ok {
		t.Fatalf("the clone: %s", out)
	}
	if head := strings.TrimSpace(evsTestGit(t, dir, "rev-parse", "HEAD")); head != c1.String() {
		t.Fatalf("the clone's HEAD %s", head)
	}
	mount, ok := mounts.Get(publisher.writer.world.repoId)
	if !ok || mount.Dir != "" {
		t.Fatalf("the implicit mount %+v %v", mount, ok)
	}
	evsTestGit(t, dir, "config", "user.name", "agent one")
	evsTestGit(t, dir, "config", "user.email", publisher.email)
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("hello through the helper\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	publisher.writer.server.know("README")
	evsTestGit(t, dir, "commit", "-q", "-am", "through the helper")
	c2 := strings.TrimSpace(evsTestGit(t, dir, "rev-parse", "HEAD"))
	if out, ok := evsTestGitWith(t, env, "-C", dir, "push", "origin", "HEAD:refs/heads/main"); !ok {
		t.Fatalf("the push: %s", out)
	}
	if local, _ := mount.localRef(context.Background(), "refs/heads/main"); local == nil || local.String() != c2 {
		t.Fatalf("the mount's main %v", local)
	}
	other := filepath.Join(t.TempDir(), "other")
	if out, ok := evsTestGitWith(t, env, "clone", "-q", "--bare", url, other); !ok {
		t.Fatalf("a second clone: %s", out)
	}
	if out, ok := evsTestGitWith(t, env, "-C", other, "fetch", "-q", "origin"); !ok {
		t.Fatalf("a fetch: %s", out)
	}
	if head := strings.TrimSpace(evsTestGit(t, other, "rev-parse", "main")); head != c2 {
		t.Fatalf("the second clone's main %s", head)
	}
}

// The helper's protocol with git: capabilities answered with connect alone, a connect answered with an empty line,
// then git's bytes the session's both ways; a url of another form refused.
func TestEvsGitRemoteHelperProtocol(t *testing.T) {
	daemonSide, helperSide := evsTestPipePair()
	gitInput := strings.NewReader("capabilities\nconnect git-upload-pack\nwants\n")
	out := &bytes.Buffer{}
	dialed := ""
	done := make(chan int, 1)
	go func() {
		done <- EvsGitRemoteHelper(context.Background(), &EvsGitRemoteHelperArgs{
			Url: "ur://team.test/id:" + evsTestId("repo").String(),
			Dial: func(ctx context.Context, repo string, service string) (io.ReadWriteCloser, error) {
				dialed = repo + " " + service
				return helperSide, nil
			},
			Stdin: gitInput, Stdout: out, Stderr: io.Discard,
		})
	}()
	got := make([]byte, len("wants\n"))
	if _, err := io.ReadFull(daemonSide, got); err != nil || string(got) != "wants\n" {
		t.Fatalf("the session got %q %v", got, err)
	}
	daemonSide.Write([]byte("refs\n"))
	daemonSide.Close()
	if code := <-done; code != 0 {
		t.Fatalf("the helper exited %d", code)
	}
	if out.String() != "connect\n\n\nrefs\n" || dialed != "team.test/id:"+evsTestId("repo").String()+" git-upload-pack" {
		t.Fatalf("git saw %q, the daemon was dialed for %q", out.String(), dialed)
	}
	if code := EvsGitRemoteHelper(context.Background(), &EvsGitRemoteHelperArgs{Url: "https://example.invalid/x", Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: io.Discard}); code == 0 {
		t.Fatal("a url of another form was taken")
	}
}

// <repo>'s forms: id:<repo_id> dashed or as 32 hex digits; a display name refused, naming the id form.
func TestEvsGitRepoOfForms(t *testing.T) {
	repoId := evsTestId("repo")
	for _, form := range []string{"id:" + repoId.String(), "id:" + evsUrlId(repoId)} {
		if got, err := EvsGitRepoOf(form); err != nil || got != repoId {
			t.Errorf("%s: %v %v", form, got, err)
		}
	}
	if _, err := EvsGitRepoOf("project notes"); err == nil || !strings.Contains(err.Error(), "id:<repo_id>") {
		t.Errorf("a display name: %v", err)
	}
}

// Two ends of an in-memory session: what one writes the other reads, and a close ends the other's reads.
func evsTestPipePair() (io.ReadWriteCloser, io.ReadWriteCloser) {
	aReader, bWriter := io.Pipe()
	bReader, aWriter := io.Pipe()
	return &evsTestPipeEnd{reader: aReader, writer: aWriter}, &evsTestPipeEnd{reader: bReader, writer: bWriter}
}

// One end of evsTestPipePair.
type evsTestPipeEnd struct {
	reader *io.PipeReader
	writer *io.PipeWriter
}

func (self *evsTestPipeEnd) Read(p []byte) (int, error)  { return self.reader.Read(p) }
func (self *evsTestPipeEnd) Write(p []byte) (int, error) { return self.writer.Write(p) }
func (self *evsTestPipeEnd) Close() error {
	self.writer.Close()
	return nil
}
