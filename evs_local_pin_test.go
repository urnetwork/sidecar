//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// The pin push of a git-mode ref (EVS1-M6-05; DESIGN-DETAILS 16.2.9 and 8.2.10 as amended; QD-802), through a mount's
// receiver over the stand-in evs, with the system git as evs_local_receive_test.go has it, whose receiver it builds on,
// so off Windows as that file is.

package sidecar

import (
	"bytes"
	"context"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// On a shared branch with a tip the pin push is the UPDATE of one tip: old_tip = new_tip, no FORCE, commit, blob, tag,
// source or change, committed on the version replay applied; it moves no local ref, here or on a device that replays
// it. A tag ref, a deleted branch and a branch stopped on this device take none, and nothing is posted for them.
func TestEvsLocalPinPushCommitsNoChangeAndMovesNoLocalRef(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	receiver := newEvsTestReceiver(t, publisher)
	dir := receiver.clone()
	// the stand-in serves the refs a test made
	publisher.ref("refs/tags/v1")
	publisher.ref("topic")
	c1 := receiver.commit(dir, map[string]string{"README": "hello\n"})
	if out, ok := receiver.push(dir, "origin", "HEAD:refs/heads/main", "HEAD:refs/tags/v1", "HEAD:refs/heads/topic"); !ok {
		t.Fatalf("the push: %s", out)
	}
	if out, ok := receiver.push(dir, "origin", ":refs/heads/topic"); !ok {
		t.Fatalf("the deletion: %s", out)
	}
	ctx := context.Background()
	repo := publisher.writer.repo
	posted := publisher.posted()
	result, err := repo.PinPush(ctx, []byte("main"))
	if err != nil || result.Skipped != "" || result.Version != 2 {
		t.Fatalf("main's pin push: %+v %v", result, err)
	}
	if publisher.posted() != posted+1 {
		t.Fatalf("%d statements for one pin push", publisher.posted()-posted)
	}
	metadata := publisher.metadata("main", 2)
	git := metadata.GetGit()
	if git.GetShape() != protocol.EvsGitShape_EVS_GIT_UPDATE || !bytes.Equal(git.GetOldTip(), c1[:]) || !bytes.Equal(git.GetNewTip(), c1[:]) ||
		len(metadata.GetCommits()) != 0 || len(git.GetTags()) != 0 || len(git.GetSources()) != 0 || len(git.GetBlobs()) != 0 {
		t.Fatalf("main's pin push carries %+v", metadata)
	}
	world := publisher.writer.server.worldOf(publisher.ref("main").refId)
	world.stateLock.Lock()
	pinned := world.commits[1].parsed
	world.stateLock.Unlock()
	if pinned.Push.GetFlags() != 0 || pinned.Push.GetChangeCount() != 0 {
		t.Fatalf("main's pin push: flags %#x, %d changes", pinned.Push.GetFlags(), pinned.Push.GetChangeCount())
	}
	if local := receiver.local("refs/heads/main"); local == nil || *local != c1 {
		t.Fatalf("main moved to %v", local)
	}
	device := newEvsTestDevice(t, publisher, "device b")
	device.replay("main")
	if local := device.local("refs/heads/main"); local == nil || *local != c1 {
		t.Fatalf("device b's main is %v", local)
	}
	// a name with no head: its world stands empty, so the stand-in answers it as evs answers a ref never made
	publisher.ref("never")
	for _, c := range []struct {
		name    string
		skipped EvsPinPushSkip
	}{
		{name: "refs/tags/v1", skipped: EvsPinPushSkipTag},
		{name: "topic", skipped: EvsPinPushSkipDeleted},
		{name: "never", skipped: EvsPinPushSkipNoHead},
	} {
		result, err := repo.PinPush(ctx, []byte(c.name))
		if err != nil || result.Skipped != c.skipped {
			t.Errorf("%s: %+v %v", c.name, result, err)
		}
	}
	// main stopped on this device at a refused version: its recovery binds it
	engine := receiver.mount.sync
	mainId := publisher.ref("main").refId
	ref, err := engine.state.gitRef(mainId)
	if err != nil {
		t.Fatal(err)
	}
	ref.StuckAt = ref.Version + 1
	if err := engine.state.writeGitRef(ref); err != nil {
		t.Fatal(err)
	}
	if result, err := repo.PinPush(ctx, []byte("main")); err != nil || result.Skipped != EvsPinPushSkipStopped {
		t.Errorf("a stopped ref: %+v %v", result, err)
	}
	if !publisher.writer.test.client.prefixRefStopped(publisher.writer.world.repoId, mainId) {
		t.Error("show does not find the stopped ref")
	}
	if publisher.posted() != posted+1 {
		t.Fatalf("a pin push to a ref it cannot bind posted")
	}
	// show over the same refs, under a set this device reads: the tag, the deleted branch and main, stopped here, each
	// listed apart, and the name with no head not at all
	repoWorld := publisher.writer.world
	signerId := repoWorld.signer.sidecarId
	set := &AclPrefixRuleSet{At: 1, Signer: signerId, State: AclPrefixSetOpened, Rules: []*protocol.PrefixRule{
		{Subject: signerId.Bytes(), Action: protocol.PrefixAction_PREFIX_ACTION_WRITE},
	}}
	repoWorld.config.stateLock.Lock()
	repoWorld.config.repo.PrefixRules = append(repoWorld.config.repo.PrefixRules, &protocol.AclRepoPrefixRulesRow{At: 1, Signer: signerId.Bytes()})
	repoWorld.config.stateLock.Unlock()
	client := publisher.writer.test.client
	client.EnablePrefixRules(&EvsPrefixRulesArgs{
		Sets: func(ctx context.Context, repoId Id) ([]*AclPrefixRuleSet, error) {
			return []*AclPrefixRuleSet{set}, nil
		},
		Settings: testAclPrefixSettingsOn(),
	})
	status, err := client.PrefixRulesStatus(ctx, repoWorld.repoId)
	if err != nil {
		t.Fatal(err)
	}
	bindings := evsPrefixTestBindings(status.Refs)
	if len(bindings) != 3 || bindings["main"] != EvsPrefixStopped || bindings["refs/tags/v1"] != EvsPrefixTag || bindings["topic"] != EvsPrefixDeleted {
		t.Errorf("show's refs: %v", bindings)
	}
}

// A git push built on the version before a pin push loses its turn to it and is built again on the pin push's version,
// never answered non-fast-forward: the pin push, an UPDATE of one tip that carries nothing, moves no tip (8.2.10's
// losing row, G7). An update that moved the tip is still the caller's non-fast-forward
// (TestEvsLocalPublishJudgesAHeadPastItsBase).
func TestEvsLocalPinPushIsCommitlessToAPushThatLosesItsTurn(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	c1 := publisher.commit(map[string]string{"a.txt": "a\n"})
	if _, err := publisher.publish("main", &c1); err != nil {
		t.Fatal(err)
	}
	stale := *publisher.ref("main")
	// the pin push as the local tier builds it: the UPDATE of one tip
	if result, err := publisher.publish("main", &c1); err != nil || result.Version != 2 || len(result.Commits) != 0 || result.Flags != 0 {
		t.Fatalf("the pin push: %+v %v", result, err)
	}
	*publisher.ref("main") = stale
	c2 := publisher.commit(map[string]string{"a.txt": "a two\n"}, c1)
	result, err := publisher.publish("main", &c2)
	if err != nil || result.Version != 3 {
		t.Fatalf("a push that lost its turn to a pin push: %+v %v", result, err)
	}
}
