// ur keys rotate (KEYS-M2-26): the command reaches the key client's RotateRepo and nothing else, so its cause is the
// client's, a request unless a remove is due; it prints the generation and the cause, never a key; a repo id that
// does not parse reaches no daemon; and a refusal is shown as the client gave it.

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A daemon target whose rotations a test reads.
type testUrKeysTarget struct {
	testUrDaemonTarget
	rotated    []sidecar.Id
	generation uint64
	cause      sidecar.GkmCause
	err        error
}

func (self *testUrKeysTarget) rotateRepo(ctx context.Context, repoId sidecar.Id) (uint64, sidecar.GkmCause, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.rotated = append(self.rotated, repoId)
	return self.generation, self.cause, self.err
}

// A key client that answers RotateRepo with a key a test made and fails every other call, recording each.
type testUrGkmClient struct {
	key   *sidecar.EvsRepoKey
	calls []string
}

var errTestUrGkmCall = errors.New("a call ur keys rotate does not make")

func (self *testUrGkmClient) CurrentRepoKey(ctx context.Context, repoId sidecar.Id) (*sidecar.EvsRepoKey, error) {
	self.calls = append(self.calls, "CurrentRepoKey")
	return nil, errTestUrGkmCall
}

func (self *testUrGkmClient) RepoKey(ctx context.Context, repoId sidecar.Id, generation uint64) (*sidecar.EvsRepoKey, error) {
	self.calls = append(self.calls, "RepoKey")
	return nil, errTestUrGkmCall
}

func (self *testUrGkmClient) EnsureWritable(ctx context.Context, repoId sidecar.Id) (*sidecar.EvsRepoKey, error) {
	self.calls = append(self.calls, "EnsureWritable")
	return nil, errTestUrGkmCall
}

func (self *testUrGkmClient) DropKey(ctx context.Context, repoId sidecar.Id) (*sidecar.GkmDropKey, error) {
	self.calls = append(self.calls, "DropKey")
	return nil, errTestUrGkmCall
}

func (self *testUrGkmClient) CreateGroup(ctx context.Context, args *sidecar.GkmCreateGroupArgs) (*sidecar.EvsRepoKey, error) {
	self.calls = append(self.calls, "CreateGroup")
	return nil, errTestUrGkmCall
}

func (self *testUrGkmClient) RotateRepo(ctx context.Context, repoId sidecar.Id) (*sidecar.EvsRepoKey, error) {
	self.calls = append(self.calls, "RotateRepo "+repoId.String())
	if self.key == nil {
		return nil, sidecar.ErrGkmNotWriter
	}
	return self.key, nil
}

func (self *testUrGkmClient) AuthAdvanced(state sidecar.GkmAuthView) {
	self.calls = append(self.calls, "AuthAdvanced")
}

func (self *testUrGkmClient) ForgetRepo(ctx context.Context, repoId sidecar.Id) error {
	self.calls = append(self.calls, "ForgetRepo")
	return errTestUrGkmCall
}

// ur keys rotate prints the generation and cause the daemon answers, for the repo named.
func TestKeysRotatePrintsTheGenerationAndItsCause(t *testing.T) {
	repoId := sidecar.NewId()
	target := &testUrKeysTarget{generation: 7, cause: sidecar.GkmCauseRequest}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "keys", "rotate", repoId.String()}); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if len(target.rotated) != 1 || target.rotated[0] != repoId {
		t.Fatalf("the rotations asked: %v", target.rotated)
	}
	if shown := stdout.String(); !strings.Contains(shown, repoId.String()) || !strings.Contains(shown, "generation 7, cause request") ||
		strings.Contains(shown, "rewritten") {
		t.Errorf("a request's rotation printed %q", shown)
	}

	// a remove the client found due is named with what it means for the repo's files
	target.generation, target.cause = 8, sidecar.GkmCauseRemove
	stdout.Reset()
	if code := cli.main(context.Background(), []string{"ur", "keys", "rotate", repoId.String()}); code != urExitOk ||
		!strings.Contains(stdout.String(), "generation 8, cause remove") || !strings.Contains(stdout.String(), "ur evs rekey") {
		t.Errorf("a remove's rotation: exit %d, %q", code, stdout.String())
	}

	// a repo id that does not parse reaches no daemon, and a missing one is a usage error
	rotated := len(target.rotated)
	if code := cli.main(context.Background(), []string{"ur", "keys", "rotate", "not-an-id"}); code != urExitFailed || len(target.rotated) != rotated {
		t.Errorf("a malformed repo id: exit %d", code)
	}
	if code := cli.main(context.Background(), []string{"ur", "keys", "rotate"}); code != urExitUsage || len(target.rotated) != rotated {
		t.Errorf("no repo id: exit %d", code)
	}

	// a refusal is shown, and nothing is printed as claimed
	target.err = sidecar.ErrGkmNotWriter
	stdout.Reset()
	stderr.Reset()
	if code := cli.main(context.Background(), []string{"ur", "keys", "rotate", repoId.String()}); code != urExitFailed ||
		!strings.Contains(stderr.String(), sidecar.ErrGkmNotWriter.Error()) || stdout.Len() != 0 {
		t.Errorf("a refused rotation: exit %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
}

// The rotation is the key client's RotateRepo and no other call: the command carries no cause of its own, so a
// rotation it asks for is a request unless the client finds a remove due. The key itself goes no further than the
// generation and cause read from it.
func TestKeysRotateCallsRotateRepoAlone(t *testing.T) {
	repoId, groupId := sidecar.NewId(), sidecar.NewId()
	key, _, err := sidecar.NewGkmFirstGeneration(repoId, groupId, &sidecar.GkmGenerationArgs{
		Cause: sidecar.GkmCauseRequest, Auth: &bridge.AuthPin{Version: 1, Chain: make([]byte, 32)},
		Time: time.UnixMilli(1_900_000_000_000), HoldersSha256: make([]byte, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	gkm := &testUrGkmClient{key: key}
	generation, cause, err := urRotateRepo(context.Background(), gkm, repoId)
	if err != nil || generation != key.Generation() || cause != sidecar.GkmCauseRequest {
		t.Fatalf("the rotation: generation %d, cause %d, %v", generation, cause, err)
	}
	if len(gkm.calls) != 1 || gkm.calls[0] != "RotateRepo "+repoId.String() {
		t.Errorf("the key client's calls: %v", gkm.calls)
	}
	refusing := &testUrGkmClient{}
	if _, _, err := urRotateRepo(context.Background(), refusing, repoId); !errors.Is(err, sidecar.ErrGkmNotWriter) {
		t.Errorf("a refused rotation: %v", err)
	}
}

// keys.rotate is served only over a target with a key client, needs no confirmation, as a writer's own rotations do
// not, and refuses a call with no repo; and no host builds a key client yet, so the daemon's own target refuses.
func TestKeysRotateMethod(t *testing.T) {
	if methods := urKeysMethods(&testUrDaemonTarget{}); len(methods) != 0 {
		t.Error("a target with no key client serves keys.rotate")
	}
	target := &testUrKeysTarget{generation: 2, cause: sidecar.GkmCauseRequest}
	methods := urKeysMethods(target)
	if len(methods) != 1 || methods[0].Name != urMethodKeysRotate || methods[0].Confirm {
		t.Fatalf("the keys methods: %v", methods)
	}
	if _, err := methods[0].Handler(context.Background(), &sidecar.DaemonCall{}); err == nil || len(target.rotated) != 0 {
		t.Errorf("a rotation with no repo: %v", err)
	}
	for cause, name := range map[sidecar.GkmCause]string{sidecar.GkmCauseRemove: "remove", sidecar.GkmCauseRequest: "request", sidecar.GkmCauseSchedule: "schedule"} {
		if got := urGkmCauseName(cause); got != name {
			t.Errorf("cause %d prints %q", cause, got)
		}
	}
	// the daemon's own target: refused while no host builds a key client, and with no Sidecar either way
	network := &urDaemonNetwork{noSidecar: "not enrolled"}
	if _, _, err := network.rotateRepo(context.Background(), sidecar.NewId()); err == nil || (urDaemonGkmClient == nil && !errors.Is(err, errUrNoGkmClient)) {
		t.Errorf("a daemon with no key client or no Sidecar rotated: %v", err)
	}
}
