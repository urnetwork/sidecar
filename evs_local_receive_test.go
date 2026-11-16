//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// EVS1-M2-36's tests (DESIGN-DETAILS 8.6's receive row), with stock git as the client pushing over git's local
// transport to a mount whose hooks exec this test binary as `ur git-hook`, which reaches a real daemon's git-hook mode:
// a push to main answered ok after evs commits it and the local ref moved; a sibling of a commit evs holds answered
// non-fast-forward; a push whose answer a kill lost resolved from the history at the restart; an attempt killed before
// its POST pending, then dead past its bound, with no statement sent again; an owned ref accepted at once, three
// pushes coalesced into one; a client's push to an import helper refused and its deletion taken; pre-receive's
// refusals; and git push --atomic refused before any write. And EVS1-M6-06's (DESIGN-DETAILS 8.6's receive row as
// amended for section 16 and QD-801), with stock git on a device held to agents/build and docs/inner: ng prefix rule
// naming the path with no request to evs and no journal entry, for a file changed outside, git rm -r of an inherited
// directory on an overlay branch and a directory replacing a file; a two-ref push with one ref refused and one landing;
// the same push to an owned ref answered ok; prefix rule: pending; a push sealed again after 412 GATE_CLOSED under a
// narrower set refused at the second check and never sent; no shared base and not a shared branch's tip; main and a
// tag in one push landing, the tag after the branch and naming its new version, and with the branch refused the tag
// refused too; and, with no rule set, a push's branches published before its tags.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
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

// An owned ref's queue refused for good (SCOPE) holds: ur evs status's journal shows the code and the commits stay on
// the local ref; the queue waits while the local ref stands, and `ur evs retry` releases it, the next push landing.
func TestEvsLocalReceiveHeldQueueReleasedByRetry(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	receiver := newEvsTestReceiver(t, publisher)
	sidecarId := publisher.writer.test.client.args.Identity().SidecarId
	owned := string(EvsOwnedRefName(sidecarId, "held"))
	dir := receiver.clone()
	c1 := receiver.commit(dir, map[string]string{"a.txt": "held\n"})
	if out, ok := receiver.push(dir, "origin", "HEAD:refs/heads/"+owned); !ok {
		t.Fatalf("the push: %s", out)
	}
	refId := publisher.ref(owned).refId
	publisher.writer.server.stateLock.Lock()
	publisher.writer.server.pushRefusals = []*evsTestRefusal{{status: http.StatusForbidden, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE}}}
	publisher.writer.server.stateLock.Unlock()
	if err := receiver.mount.receiver.publishQueued(context.Background(), refId); err != nil {
		t.Fatal(err)
	}
	statuses, _ := receiver.mount.receiver.JournalStatus()
	if len(statuses) != 1 || statuses[0].HoldCode != "SCOPE" {
		t.Fatalf("the hold %+v", statuses)
	}
	if local := receiver.local("refs/heads/" + owned); local == nil || *local != c1 {
		t.Fatalf("the held commits left the local ref: %v", local)
	}
	// held while the local ref stands: the queue sends nothing
	posted := publisher.posted()
	if err := receiver.mount.receiver.publishQueued(context.Background(), refId); err != nil || publisher.posted() != posted {
		t.Fatalf("a held queue pushed: %v", err)
	}
	released, err := receiver.mount.receiver.Retry(context.Background(), nil)
	if err != nil || len(released) != 1 || string(released[0]) != owned {
		t.Fatalf("retry released %q %v", released, err)
	}
	if err := receiver.mount.receiver.publishQueued(context.Background(), refId); err != nil {
		t.Fatal(err)
	}
	if version := receiver.headVersion(owned); version != 1 {
		t.Fatalf("the retried queue's push: %d", version)
	}
	if statuses, _ := receiver.mount.receiver.JournalStatus(); len(statuses) != 0 {
		t.Fatalf("the journal after the retry %+v", statuses)
	}
}

// The receiving device as signer from here: the writer's client signs as it, and a clone's commits carry its client.
func (self *evsTestGitRules) receiverAs(signer *evsTestSigner) *evsTestReceiver {
	self.t.Helper()
	receiver := newEvsTestReceiver(self.t, self.publisher)
	client := self.publisher.writer.test.client
	as := &SidecarIdentity{NetworkId: testNetworkId, SidecarId: signer.sidecarId, ClientId: self.clientOf(signer)}
	client.args.Identity = func() *SidecarIdentity { return as }
	client.args.Sign = signer.sign
	self.publisher.email = self.clientOf(signer).String() + evsCommitterDomain
	return receiver
}

// The status line git printed for a ref: its reason after "[remote rejected]", or "ok" for one that landed.
func evsTestPushStatus(out string, gitRef string) string {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.SplitN(line, "\t", 3)
		if len(fields) < 3 || !strings.HasSuffix(fields[1], ":"+gitRef) {
			continue
		}
		if fields[0] == "!" {
			return strings.TrimSuffix(strings.TrimPrefix(fields[2], "[remote rejected] ("), ")")
		}
		return "ok"
	}
	return "absent"
}

// Removes paths from a clone's work tree with git rm -r, and commits.
func (self *evsTestReceiver) remove(dir string, paths ...string) EvsGitOid {
	self.t.Helper()
	evsTestGit(self.t, dir, append([]string{"rm", "-r", "-q"}, paths...)...)
	evsTestGit(self.t, dir, "commit", "-q", "-m", fmt.Sprint("remove ", time.Now().UnixNano()))
	oid, err := evsGitOidDecodeHex([]byte(strings.TrimSpace(evsTestGit(self.t, dir, "rev-parse", "HEAD"))))
	if err != nil {
		self.t.Fatal(err)
	}
	return oid
}

// A device held to its prefixes over stock git: each refusal names the path with no request to evs and leaves no
// journal entry, its local ref unmoved; one landing beside one refused in a two-ref push; an owned ref answered ok
// whatever it holds; a pending set answered pending.
func TestEvsLocalReceivePrefixRefusesOverStockGit(t *testing.T) {
	rules := newEvsTestGitRules(t)
	c1 := rules.commitAs(rules.admin, map[string]string{"README": "readme\n", "agents/build/out": "built\n", "docs/guide": "guide\n", "docs/more": "more\n"})
	rules.mustPublish(rules.admin, false, "main", &c1)
	rules.mustPublish(rules.admin, false, "feature", &c1)
	receiver := rules.receiverAs(rules.held)
	ctx := context.Background()
	for _, name := range []string{"main", "feature"} {
		if err := receiver.mount.sync.Replay(ctx, rules.publisher.ref(name).refId); err != nil {
			t.Fatal(err)
		}
	}
	dir := receiver.clone()
	evsTestGit(t, dir, "fetch", "-q", "origin", "feature:feature")
	refusedClean := func(label string, out string, gitRef string, want string) {
		t.Helper()
		if status := evsTestPushStatus(out, gitRef); status != want {
			t.Fatalf("%s: %q, want %q in %s", label, status, want, out)
		}
		statuses, _ := receiver.mount.receiver.JournalStatus()
		for _, status := range statuses {
			if "refs/heads/"+string(status.RefName) == gitRef {
				t.Fatalf("%s: the journal %+v", label, status)
			}
		}
	}
	// a file changed outside
	before := rules.requests()
	receiver.commit(dir, map[string]string{"README": "changed\n"})
	out, _ := receiver.push(dir, "origin", "HEAD:refs/heads/main")
	refusedClean("a file outside", out, "refs/heads/main", "prefix rule: README")
	if after := rules.requests(); after != before {
		t.Fatalf("requests %v, before %v", after, before)
	}
	if local := receiver.local("refs/heads/main"); local == nil || *local != c1 {
		t.Fatalf("main moved to %v", local)
	}
	// git rm -r of an inherited directory on the overlay branch feature, and a directory replacing a file
	evsTestGit(t, dir, "checkout", "-q", "feature")
	receiver.remove(dir, "docs")
	out, _ = receiver.push(dir, "origin", "HEAD:refs/heads/feature")
	refusedClean("git rm -r of an inherited directory", out, "refs/heads/feature", "prefix rule: docs/guide")
	evsTestGit(t, dir, "reset", "-q", "--hard", c1.String())
	receiver.remove(dir, "README")
	receiver.commit(dir, map[string]string{"README/inner": "x\n"})
	out, _ = receiver.push(dir, "origin", "HEAD:refs/heads/feature")
	refusedClean("a directory over a file", out, "refs/heads/feature", "prefix rule: README")
	// two refs in one push: main refused, feature landing with a change under the prefix
	evsTestGit(t, dir, "reset", "-q", "--hard", c1.String())
	under := receiver.commit(dir, map[string]string{"agents/build/out": "built two\n"})
	evsTestGit(t, dir, "checkout", "-q", "-b", "outside", c1.String())
	receiver.commit(dir, map[string]string{"README": "changed again\n"})
	out, _ = receiver.push(dir, "origin", "outside:refs/heads/main", under.String()+":refs/heads/feature")
	if main, feature := evsTestPushStatus(out, "refs/heads/main"), evsTestPushStatus(out, "refs/heads/feature"); main != "prefix rule: README" || feature != "ok" {
		t.Fatalf("a two-ref push: %q %q in %s", main, feature, out)
	}
	if local := receiver.local("refs/heads/feature"); local == nil || *local != under {
		t.Fatalf("feature is %v", local)
	}
	// the same change to an owned ref of this device is answered ok, before evs
	own := rules.ownedRef(rules.held, "scratch")
	out, _ = receiver.push(dir, "origin", "outside:refs/heads/"+own)
	if status := evsTestPushStatus(out, "refs/heads/"+own); status != "ok" {
		t.Fatalf("an owned ref: %q in %s", status, out)
	}
	// a set this device holds pending at its installed pin
	rules.file(7, AclPrefixSetPending, "agents/build")
	rules.world.config.setPin(7)
	evsTestGit(t, dir, "checkout", "-q", "feature")
	evsTestGit(t, dir, "reset", "-q", "--hard", under.String())
	receiver.commit(dir, map[string]string{"agents/build/out": "built three\n"})
	out, _ = receiver.push(dir, "origin", "HEAD:refs/heads/feature")
	refusedClean("a pending set", out, "refs/heads/feature", "prefix rule: pending")
}

// A push built under one set meets 412 GATE_CLOSED, and the set that its rebuild's state pins at holds the device to
// docs/inner alone: the second check refuses it with the path, and the rebuilt statement is never sent.
func TestEvsLocalReceivePrefixChecksAgainBeforeARebuiltStatement(t *testing.T) {
	rules := newEvsTestGitRules(t)
	c1 := rules.commitAs(rules.admin, map[string]string{"README": "readme\n", "agents/build/out": "built\n"})
	rules.mustPublish(rules.admin, false, "main", &c1)
	receiver := rules.receiverAs(rules.held)
	if err := receiver.mount.sync.Replay(context.Background(), rules.publisher.ref("main").refId); err != nil {
		t.Fatal(err)
	}
	dir := receiver.clone()
	receiver.commit(dir, map[string]string{"agents/build/out": "built two\n"})
	server := rules.publisher.writer.server
	server.stateLock.Lock()
	server.pushRefusals = evsTestClosedGate(1)
	server.stateLock.Unlock()
	sent := 0
	evsLocalReceiveKillHook = func(point string) error {
		if point == "publish.sent" {
			sent += 1
			if sent == 1 {
				// the first statement is built and journaled: a narrower set lands, and the device's state moves to
				// it before the rebuild
				rules.file(6, AclPrefixSetOpened, "docs/inner")
				rules.world.config.setPin(6)
			}
		}
		return nil
	}
	defer func() { evsLocalReceiveKillHook = nil }()
	before, _ := server.sentCounts()
	out, _ := receiver.push(dir, "origin", "HEAD:refs/heads/main")
	if status := evsTestPushStatus(out, "refs/heads/main"); status != "prefix rule: agents/build/out" {
		t.Fatalf("the rebuilt push: %q in %s", status, out)
	}
	if after, _ := server.sentCounts(); after != before+1 {
		t.Fatalf("%d statements sent, the refused one alone expected", after-before)
	}
}

// New shared refs from a held device (QD-801): a branch off main lands; one from an orphan history answers no shared
// base; a tag of an unpublished commit answers not a shared branch's tip; main and a tag of its new tip in one push
// land, the tag after the branch naming its new version; with the branch refused, its tag is refused too; each
// refusal before any request to evs.
func TestEvsLocalReceivePrefixNewSharedRefs(t *testing.T) {
	rules := newEvsTestGitRules(t)
	c1 := rules.commitAs(rules.admin, map[string]string{"README": "readme\n", "agents/build/out": "built\n"})
	rules.mustPublish(rules.admin, false, "main", &c1)
	receiver := rules.receiverAs(rules.held)
	if err := receiver.mount.sync.Replay(context.Background(), rules.publisher.ref("main").refId); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"feature", "lonely", "refs/tags/unpublished", "refs/tags/v1.0", "refs/tags/v2.0"} {
		// the stand-in serves a ref a client creates once it is made
		rules.publisher.ref(name)
	}
	dir := receiver.clone()
	branch := receiver.commit(dir, map[string]string{"agents/build/f": "f\n"})
	out, _ := receiver.push(dir, "origin", "HEAD:refs/heads/feature")
	if status := evsTestPushStatus(out, "refs/heads/feature"); status != "ok" {
		t.Fatalf("a branch off main: %q in %s", status, out)
	}
	before := rules.requests()
	evsTestGit(t, dir, "checkout", "-q", "--orphan", "lonely")
	evsTestGit(t, dir, "rm", "-r", "-q", "--cached", ".")
	receiver.commit(dir, map[string]string{"agents/build/g": "g\n", "src/x": "x\n"})
	out, _ = receiver.push(dir, "origin", "HEAD:refs/heads/lonely")
	if status := evsTestPushStatus(out, "refs/heads/lonely"); !strings.HasPrefix(status, "prefix rule: no shared base: ") {
		t.Fatalf("an orphan history: %q in %s", status, out)
	}
	evsTestGit(t, dir, "checkout", "-q", "-f", branch.String())
	unpublished := receiver.commit(dir, map[string]string{"agents/build/u": "u\n"})
	evsTestGit(t, dir, "tag", "unpublished", unpublished.String())
	out, _ = receiver.push(dir, "origin", "refs/tags/unpublished")
	if status := evsTestPushStatus(out, "refs/tags/unpublished"); status != "prefix rule: not a shared branch's tip: README" {
		t.Fatalf("a tag of an unpublished commit: %q in %s", status, out)
	}
	if after := rules.requests(); after != before {
		t.Fatalf("requests %v, before %v", after, before)
	}
	// main and a tag of its new tip in one push: the branch first, the tag naming its new version
	evsTestGit(t, dir, "checkout", "-q", "-B", "main", c1.String())
	next := receiver.commit(dir, map[string]string{"agents/build/out": "built two\n"})
	evsTestGit(t, dir, "tag", "v1.0", next.String())
	out, _ = receiver.push(dir, "origin", "main", "v1.0")
	if main, tag := evsTestPushStatus(out, "refs/heads/main"), evsTestPushStatus(out, "refs/tags/v1.0"); main != "ok" || tag != "ok" {
		t.Fatalf("main and v1.0: %q %q in %s", main, tag, out)
	}
	metadata := rules.publisher.metadata("refs/tags/v1.0", 1)
	sources := metadata.GetGit().GetSources()
	if len(sources) == 0 || Id(sources[0].GetRefId()) != rules.publisher.ref("main").refId || sources[0].GetVersion() != 2 {
		t.Fatalf("the tag's sources %v", sources)
	}
	// main refused, so its tag finds no proof and is refused too
	outside := receiver.commit(dir, map[string]string{"README": "changed\n"})
	evsTestGit(t, dir, "tag", "v2.0", outside.String())
	out, _ = receiver.push(dir, "origin", "main", "v2.0")
	if main, tag := evsTestPushStatus(out, "refs/heads/main"), evsTestPushStatus(out, "refs/tags/v2.0"); main != "prefix rule: README" || tag != "prefix rule: not a shared branch's tip: README" {
		t.Fatalf("main and v2.0: %q %q in %s", main, tag, out)
	}
}

// With no rule set, one push of two tags and two branches reports each status, the branches published first.
func TestEvsLocalReceivePublishesBranchesBeforeTags(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	receiver := newEvsTestReceiver(t, publisher)
	for _, name := range []string{"b2", "refs/tags/t1", "refs/tags/t2"} {
		publisher.ref(name)
	}
	dir := receiver.clone()
	c1 := receiver.commit(dir, map[string]string{"a.txt": "one\n"})
	evsTestGit(t, dir, "tag", "t1", c1.String())
	evsTestGit(t, dir, "tag", "t2", c1.String())
	evsTestGit(t, dir, "branch", "b2", c1.String())
	out, ok := receiver.push(dir, "origin", "refs/tags/t1", "HEAD:refs/heads/main", "refs/tags/t2", "b2:refs/heads/b2")
	if !ok {
		t.Fatalf("the push: %s", out)
	}
	tagIds := map[Id]bool{publisher.ref("refs/tags/t1").refId: true, publisher.ref("refs/tags/t2").refId: true}
	server := publisher.writer.server
	server.stateLock.Lock()
	posted := append([][]byte{}, server.postedStatements...)
	server.stateLock.Unlock()
	kinds := ""
	for _, statementBytes := range posted {
		statement, err := ParseEvsStatement(statementBytes)
		if err != nil {
			t.Fatal(err)
		}
		if tagIds[Id(statement.Push.GetRefId())] {
			kinds += "t"
		} else {
			kinds += "b"
		}
	}
	if kinds != "bbtt" {
		t.Fatalf("published in the order %q", kinds)
	}
}
