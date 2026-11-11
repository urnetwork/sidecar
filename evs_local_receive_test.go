//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// EVS1-M2-36's tests (DESIGN-DETAILS 8.6's receive row), with stock git as the client pushing over git's local
// transport to a mount whose hooks exec this test binary as `ur git-hook`, which reaches a real daemon's git-hook mode:
// a push to main answered ok after evs commits it and the local ref moved; a sibling of a commit evs holds answered
// non-fast-forward; a push whose answer a kill lost resolved from the history at the restart; an attempt killed before
// its POST pending, then dead past its bound, with no statement sent again; an owned ref accepted at once, three
// pushes coalesced into one; a client's push to an import helper refused and its deletion taken; pre-receive's
// refusals; and git push --atomic refused before any write.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The environment variable that turns this test binary into `ur git-hook` (the helper process below).
const evsTestGitHookSocketVariable = "UR_TEST_GIT_HOOK_SOCKET"

// Not a test: the hooks a receive test installs exec this binary with -test.run naming it, the hook's name last, and
// it relays the hook to the daemon whose socket the variable names, then exits with the daemon's code.
func TestEvsGitHookHelperProcess(t *testing.T) {
	socket := os.Getenv(evsTestGitHookSocketVariable)
	if socket == "" {
		return
	}
	hook := os.Args[len(os.Args)-1]
	code := EvsGitHookRelay(context.Background(), &EvsGitHookRelayArgs{
		Hook: hook,
		Dial: func(ctx context.Context) (io.ReadWriteCloser, error) {
			client, err := DialDaemon(ctx, socket, &DaemonHello{Mode: DaemonModeGitHook, Version: testDaemonVersion, Service: hook})
			if err != nil {
				return nil, err
			}
			return &evsTestHookStream{ReadWriter: client.Stream(), client: client}, nil
		},
		Getenv: os.Getenv, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
	})
	os.Exit(code)
}

// A hook session's stream, closed with its client.
type evsTestHookStream struct {
	io.ReadWriter
	client *DaemonClient
}

func (self *evsTestHookStream) Close() error {
	return self.client.Close()
}

// The writer's device: the world writer's client, which signs, with a mount registry on its own state, a daemon whose
// git-hook mode serves the mount's hooks, and those hooks installed.
type evsTestReceiver struct {
	t         *testing.T
	publisher *evsTestPublisher
	mounts    *EvsMounts
	mount     *EvsLocalRepo
	socket    string
}

func newEvsTestReceiver(t *testing.T, publisher *evsTestPublisher) *evsTestReceiver {
	t.Helper()
	client := publisher.writer.test.client
	mounts, err := NewEvsMounts(client, t.TempDir(), evsTestGitRunner(t))
	if err != nil {
		t.Fatal(err)
	}
	mount, err := mounts.Add(context.Background(), publisher.writer.world.repoId, &EvsMountArgs{AgentLabel: "agent one"})
	if err != nil {
		t.Fatal(err)
	}
	started := startTestDaemon(t, nil)
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
	return &evsTestReceiver{t: t, publisher: publisher, mounts: mounts, mount: mount, socket: started.socketPath}
}

// A client's clone of the mount's bare repository, its committer this sidecar's client.
func (self *evsTestReceiver) clone() string {
	self.t.Helper()
	dir := filepath.Join(self.t.TempDir(), "clone")
	evsTestGit(self.t, filepath.Dir(dir), "clone", "-q", self.mount.BareDir, dir)
	evsTestGit(self.t, dir, "config", "user.name", "agent one")
	evsTestGit(self.t, dir, "config", "user.email", self.publisher.email)
	evsTestGit(self.t, dir, "config", "committer.name", "agent one")
	evsTestGit(self.t, dir, "config", "committer.email", self.publisher.email)
	return dir
}

// Commits files in a clone, answering the commit's oid; the files' paths are told to the stand-in.
func (self *evsTestReceiver) commit(dir string, files map[string]string) EvsGitOid {
	self.t.Helper()
	paths := []string{}
	for path, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			self.t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			self.t.Fatal(err)
		}
		paths = append(paths, path)
	}
	self.publisher.writer.server.know(paths...)
	evsTestGit(self.t, dir, "add", "-A")
	evsTestGit(self.t, dir, "commit", "-q", "-m", fmt.Sprint("commit ", time.Now().UnixNano()))
	oid, err := evsGitOidDecodeHex([]byte(strings.TrimSpace(evsTestGit(self.t, dir, "rev-parse", "HEAD"))))
	if err != nil {
		self.t.Fatal(err)
	}
	return oid
}

// Pushes args from a clone through a receive session, answering git's output and whether it succeeded.
func (self *evsTestReceiver) push(dir string, args ...string) (string, bool) {
	self.t.Helper()
	session, closeSession := self.mounts.OpenReceiveSession(self.mount, "")
	defer closeSession()
	gitPath, err := exec.LookPath("git")
	if err != nil {
		self.t.Skip("no system git")
	}
	command := exec.Command(gitPath, append([]string{"-C", dir, "push", "--porcelain"}, args...)...)
	command.Env = append([]string{"HOME=" + self.t.TempDir(), "GIT_CONFIG_NOSYSTEM=1", "PATH=" + os.Getenv("PATH")},
		self.mounts.ReceiveEnvironment(session)...)
	out, err := command.CombinedOutput()
	return string(out), err == nil
}

// The local ref gitRef of the mount, nil for none.
func (self *evsTestReceiver) local(gitRef string) *EvsGitOid {
	self.t.Helper()
	oid, err := self.mount.localRef(context.Background(), gitRef)
	if err != nil {
		self.t.Fatal(err)
	}
	return oid
}

// The world's head version of the ref of name.
func (self *evsTestReceiver) headVersion(name string) uint64 {
	world := self.publisher.writer.server.worldOf(self.publisher.ref(name).refId)
	world.stateLock.Lock()
	defer world.stateLock.Unlock()
	return uint64(len(world.commits))
}

// A push to main over stock git: pre-receive passes, proc-receive answers ok once evs committed the push and the local
// ref moved; the journal holds nothing; a second device's replay holds the commit.
func TestEvsLocalReceivePushToMain(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	receiver := newEvsTestReceiver(t, publisher)
	dir := receiver.clone()
	c1 := receiver.commit(dir, map[string]string{"README": "hello\n", "docs/plan.md": "plan\n"})
	out, ok := receiver.push(dir, "origin", "HEAD:refs/heads/main")
	if !ok {
		t.Fatalf("the push: %s", out)
	}
	if local := receiver.local("refs/heads/main"); local == nil || *local != c1 {
		t.Fatalf("main is %v", local)
	}
	if version := receiver.headVersion("main"); version != 1 {
		t.Fatalf("evs's head is at %d", version)
	}
	statuses, err := receiver.mount.receiver.JournalStatus()
	if err != nil || len(statuses) != 0 {
		t.Fatalf("the journal %+v %v", statuses, err)
	}
	device := newEvsTestDevice(t, publisher, "device b")
	device.replay("main")
	if local := device.local("refs/heads/main"); local == nil || *local != c1 {
		t.Fatalf("device b's main is %v", local)
	}
	// a second push on the first
	c2 := receiver.commit(dir, map[string]string{"README": "hello again\n"})
	if out, ok := receiver.push(dir, "origin", "HEAD:refs/heads/main"); !ok {
		t.Fatalf("the second push: %s", out)
	}
	if local := receiver.local("refs/heads/main"); local == nil || *local != c2 {
		t.Fatalf("main is %v", local)
	}
}

// Another device moved main on evs past what this mount applied: a push built on the tip this mount holds is answered
// non-fast-forward, as stock git's fetch-and-merge expects, and nothing is left in the journal.
func TestEvsLocalReceiveSiblingIsNonFastForward(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	c0 := publisher.commit(map[string]string{"a.txt": "zero\n"})
	if _, err := publisher.publish("main", &c0); err != nil {
		t.Fatal(err)
	}
	receiver := newEvsTestReceiver(t, publisher)
	if err := receiver.mount.sync.Replay(context.Background(), publisher.ref("main").refId); err != nil {
		t.Fatal(err)
	}
	c1 := publisher.commit(map[string]string{"a.txt": "one\n"}, c0)
	if _, err := publisher.publish("main", &c1); err != nil {
		t.Fatal(err)
	}
	dir := receiver.clone()
	receiver.commit(dir, map[string]string{"a.txt": "sibling\n"})
	out, ok := receiver.push(dir, "origin", "HEAD:refs/heads/main")
	if ok || !strings.Contains(out, "non-fast-forward") {
		t.Fatalf("a sibling push: %v %s", ok, out)
	}
	if statuses, _ := receiver.mount.receiver.JournalStatus(); len(statuses) != 0 {
		t.Fatalf("the journal %+v", statuses)
	}
}

// A kill after evs committed and before the local update leaves the attempt SENT; the restart resolves it committed
// from the history, settle moving the local ref (FS-5's kill case), with no statement sent again.
func TestEvsLocalReceiveKilledAfterTheCommit(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	receiver := newEvsTestReceiver(t, publisher)
	dir := receiver.clone()
	c1 := receiver.commit(dir, map[string]string{"a.txt": "one\n"})
	evsLocalReceiveKillHook = func(point string) error {
		if point == "publish.answer" {
			return errors.New("killed")
		}
		return nil
	}
	out, ok := receiver.push(dir, "origin", "HEAD:refs/heads/main")
	evsLocalReceiveKillHook = nil
	if ok {
		t.Fatalf("a killed push answered ok: %s", out)
	}
	posted := publisher.posted()
	if err := receiver.mount.receiver.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if local := receiver.local("refs/heads/main"); local == nil || *local != c1 {
		t.Fatalf("main after the restart is %v", local)
	}
	if statuses, _ := receiver.mount.receiver.JournalStatus(); len(statuses) != 0 {
		t.Fatalf("the journal after the restart %+v", statuses)
	}
	if publisher.posted() != posted {
		t.Fatal("the restart sent a statement again")
	}
}

// A kill after the attempt was journaled and before its POST: git hears remote outcome pending; the restart's resolve
// finds the head unmoved and keeps it pending, then past the attempt's bound and the margin calls it dead and deletes
// the update; nothing is sent again.
func TestEvsLocalReceiveKilledBeforeThePost(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	receiver := newEvsTestReceiver(t, publisher)
	dir := receiver.clone()
	receiver.commit(dir, map[string]string{"a.txt": "one\n"})
	evsLocalReceiveKillHook = func(point string) error {
		if point == "publish.sent" {
			return errors.New("killed")
		}
		return nil
	}
	out, ok := receiver.push(dir, "origin", "HEAD:refs/heads/main")
	evsLocalReceiveKillHook = nil
	if ok || !strings.Contains(out, "remote outcome pending") {
		t.Fatalf("a push killed before its post: %v %s", ok, out)
	}
	posted := publisher.posted()
	if err := receiver.mount.receiver.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	statuses, _ := receiver.mount.receiver.JournalStatus()
	if len(statuses) != 1 || !statuses[0].Pending {
		t.Fatalf("pending after the restart %+v", statuses)
	}
	publisher.writer.test.clock.advance(time.Hour)
	receiver.mount.receiver.resolveAll(context.Background())
	if statuses, _ := receiver.mount.receiver.JournalStatus(); len(statuses) != 0 {
		t.Fatalf("the dead attempt's update stands %+v", statuses)
	}
	if publisher.posted() != posted {
		t.Fatal("a statement was sent again")
	}
	if local := receiver.local("refs/heads/main"); local != nil {
		t.Fatalf("main moved to %v", local)
	}
}

// An owned ref is accepted at once, before evs: three pushes each answered ok and its local ref moved, then the queue
// publishes all three in one push, after which the journal is empty and evs's tip is the last.
func TestEvsLocalReceiveOwnedRefQueues(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	receiver := newEvsTestReceiver(t, publisher)
	sidecarId := publisher.writer.test.client.args.Identity().SidecarId
	owned := string(EvsOwnedRefName(sidecarId, "work"))
	dir := receiver.clone()
	var last EvsGitOid
	for i := range 3 {
		last = receiver.commit(dir, map[string]string{"a.txt": fmt.Sprint("version ", i, "\n")})
		if out, ok := receiver.push(dir, "origin", "HEAD:refs/heads/"+owned); !ok {
			t.Fatalf("push %d: %s", i, out)
		}
	}
	if local := receiver.local("refs/heads/" + owned); local == nil || *local != last {
		t.Fatalf("the owned ref is %v", local)
	}
	refId := publisher.ref(owned).refId
	if version := receiver.headVersion(owned); version != 0 {
		t.Fatalf("evs took the owned ref before the queue: %d", version)
	}
	if err := receiver.mount.receiver.publishQueued(context.Background(), refId); err != nil {
		t.Fatal(err)
	}
	if version := receiver.headVersion(owned); version != 1 {
		t.Fatalf("the queue's pushes: %d", version)
	}
	record, _ := receiver.mount.sync.GitRef(context.Background(), refId)
	if !evsOidEqual(record.Tip, &last) {
		t.Fatalf("evs's tip %v", record.Tip)
	}
	if statuses, _ := receiver.mount.receiver.JournalStatus(); len(statuses) != 0 {
		t.Fatalf("the journal %+v", statuses)
	}
}

// A client's push to an import helper ref is refused before the journal, and its deletion is taken.
func TestEvsLocalReceiveImportHelperTakesOnlyItsDeletion(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	receiver := newEvsTestReceiver(t, publisher)
	sidecarId := publisher.writer.test.client.args.Identity().SidecarId
	helper := string(EvsImportHelperRefName(sidecarId, EvsImportId{1, 2, 3, 4, 5, 6, 7, 8}, 1))
	dir := receiver.clone()
	c1 := receiver.commit(dir, map[string]string{"a.txt": "one\n"})
	out, ok := receiver.push(dir, "origin", "HEAD:refs/heads/"+helper)
	if ok || !strings.Contains(out, "import helper") {
		t.Fatalf("a push to a helper: %v %s", ok, out)
	}
	// the helper stands, as an import made it; a client's deletion is taken
	evsTestGit(t, receiver.mount.BareDir, "update-ref", "refs/heads/"+helper, c1.String())
	if out, ok := receiver.push(dir, "origin", ":refs/heads/"+helper); !ok {
		t.Fatalf("the helper's deletion: %s", out)
	}
	if local := receiver.local("refs/heads/" + helper); local != nil {
		t.Fatalf("the helper stands at %v", local)
	}
}

// pre-receive refuses the whole push, printing why: a commit whose committer is no client of this sidecar, with both
// config values and ur evs import named; and a ref outside refs/heads/ and refs/tags/.
func TestEvsLocalReceivePreReceiveRefusals(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	receiver := newEvsTestReceiver(t, publisher)
	dir := receiver.clone()
	evsTestGit(t, dir, "config", "committer.email", "someone@example.invalid")
	receiver.commit(dir, map[string]string{"a.txt": "foreign\n"})
	out, ok := receiver.push(dir, "origin", "HEAD:refs/heads/main")
	if ok || !strings.Contains(out, "someone@example.invalid") || !strings.Contains(out, SidecarCommitterEmail(publisher.writer.test.client.args.Identity().ClientId)) ||
		!strings.Contains(out, "ur evs import") {
		t.Fatalf("a foreign committer: %v %s", ok, out)
	}
	if version := receiver.headVersion("main"); version != 0 {
		t.Fatalf("evs took a refused push: %d", version)
	}
	other := receiver.clone()
	receiver.commit(other, map[string]string{"a.txt": "a note\n"})
	out, ok = receiver.push(other, "origin", "HEAD:refs/notes/x")
	if ok || !strings.Contains(out, "only refs/heads/ and refs/tags/") {
		t.Fatalf("a ref outside branches and tags: %v %s", ok, out)
	}
}

// git push --atomic fails before any write, since the mount advertises no atomic.
func TestEvsLocalReceiveAtomicFailsBeforeAnyWrite(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	receiver := newEvsTestReceiver(t, publisher)
	dir := receiver.clone()
	receiver.commit(dir, map[string]string{"a.txt": "one\n"})
	out, ok := receiver.push(dir, "--atomic", "origin", "HEAD:refs/heads/main", "HEAD:refs/heads/other")
	if ok {
		t.Fatalf("an atomic push: %s", out)
	}
	if version := receiver.headVersion("main"); version != 0 {
		t.Fatalf("evs took an atomic push: %d", version)
	}
}

// A mount whose host set no hook command refuses every push in its hooks, so receive-pack moves no ref evs never took.
func TestEvsLocalReceiveWithNoHookCommandRefuses(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	client := publisher.writer.test.client
	mounts, err := NewEvsMounts(client, t.TempDir(), evsTestGitRunner(t))
	if err != nil {
		t.Fatal(err)
	}
	mount, err := mounts.Add(context.Background(), publisher.writer.world.repoId, &EvsMountArgs{})
	if err != nil {
		t.Fatal(err)
	}
	receiver := &evsTestReceiver{t: t, publisher: publisher, mounts: mounts, mount: mount}
	dir := receiver.clone()
	receiver.commit(dir, map[string]string{"a.txt": "unhooked\n"})
	out, ok := receiver.push(dir, "origin", "HEAD:refs/heads/main")
	if ok || !strings.Contains(out, "only through the ur daemon") {
		t.Fatalf("an unhooked push: %v %s", ok, out)
	}
	if local := receiver.local("refs/heads/main"); local != nil {
		t.Fatalf("main moved to %v", local)
	}
}
