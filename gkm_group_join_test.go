//go:build !sidecar_http

// QD-817's join on the fake gkm: member devices of a config group that hold no generation of the config repo and only
// an unconfirmed state, the one a joining device's config follower verified rows-only before it stands, take the config
// group's Welcome or wrap on it and open the config repo's keys; on that state every other act refuses, a seal, a
// commit, a rotation, an admission and any other repo's key, writing nothing at gkm, until a verified state is given.

package sidecar_test

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The calls a device sent gkm that write: a commit, a generation, a delivery, a Welcome, a group or a GroupInfo.
func (self *gkmFakeStore) writeCallCount(label string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	writes := []string{"CommitEpoch", "ClaimGeneration", "UploadWraps", "UploadRecoveryWraps", "UploadWelcome", "CreateGroup", "UploadGroupInfo"}
	count := 0
	for _, call := range self.calls {
		device, route, found := strings.Cut(call, ":")
		if found && device == label && slices.Contains(writes, route) {
			count += 1
		}
	}
	return count
}

// A config group KF1 formed at its creator's verified state, then a member device that holds no generation of the
// config repo and only an unconfirmed state: it takes its Welcome through JoinWelcomes once the first Add commit adds
// it, the keychain's wait closing, and opens the config repo's generation 1 by RepoKey and CurrentRepoKey; a wrapped
// member device opens its first wrap through CurrentRepoKey alike. On that state its write, commit, rotation, first
// wrap to another device, group creation and keys of another repo refuse with ErrGkmUnavailable, sending gkm no write;
// once a verified state is given, the write goes on.
func TestGkmClientJoinsTheConfigGroupOnAnUnconfirmedState(t *testing.T) {
	world, _ := newGkmCreateWorld(t, protocol.RepoKind_REPO_KIND_CONFIG)
	a := world.flows[world.a]
	created, err := a.client.CreateGroup(world.ctx, world.createArgs())
	if err != nil {
		t.Fatal(err)
	}
	world.groupId = created.GroupId()
	first := world.storedGeneration(world.log.Tip(), 1)

	// b, a writer of the config repo, and c, a reader the config group's creation wrapped to, hold only the follower's
	// rows-only state
	b, c := world.flows[world.b], world.flows[world.c]
	for _, flow := range []*gkmFlowDevice{b, c} {
		flow.unconfirmed = true
		flow.restart()
		if held, _ := flow.client.RepoKeyHeld(world.repoId); held {
			t.Fatalf("%s holds a generation of the config repo before its join", flow.label)
		}
	}

	// c's first wrap
	wrapped, err := c.client.CurrentRepoKey(world.ctx, world.repoId)
	if err != nil || !bytes.Equal(wrapped.Commitment(), first.Rotate.GetCommitment()) {
		t.Fatalf("c's first wrap on an unconfirmed state: %v", err)
	}

	// b's Welcome, once the first Add commit adds it
	for _, device := range []*gkmWorldDevice{world.b, world.p, world.x} {
		world.store.publishKeyPackages(device, 1, true)
	}
	if err := a.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	_, changed := b.client.RepoKeyHeld(world.repoId)
	joined, err := b.client.JoinWelcomes(world.ctx)
	if err != nil || !slices.Equal(joined, []sidecar.Id{world.repoId}) {
		t.Fatalf("b's join on an unconfirmed state: %v %v", joined, err)
	}
	select {
	case <-changed:
	default:
		t.Error("the keychain took the config repo's generation and its wait did not close")
	}
	if held, _ := b.client.RepoKeyHeld(world.repoId); !held {
		t.Fatal("b holds no generation of the config repo after its join")
	}
	key, err := b.client.RepoKey(world.ctx, world.repoId, 1)
	if err != nil || !bytes.Equal(key.Commitment(), first.Rotate.GetCommitment()) {
		t.Fatalf("b's generation 1 after its join: %v", err)
	}
	if current, err := b.client.CurrentRepoKey(world.ctx, world.repoId); err != nil || current.Generation() != 1 {
		t.Fatalf("b's current key after its join: %v", err)
	}

	// every other act refuses on the unconfirmed state, and none reaches gkm as a write
	writes := world.store.writeCallCount("b")
	otherRepoId := sidecar.NewId()
	refusals := map[string]error{}
	_, refusals["a seal"] = b.client.EnsureWritable(world.ctx, world.repoId)
	refusals["a commit"] = b.client.RunPending(world.ctx, world.repoId)
	_, refusals["a rotation"] = b.client.RotateRepo(world.ctx, world.repoId)
	refusals["an admission's first wrap"] = b.client.DeliverFirstWrap(world.ctx, world.repoId, world.x.id)
	_, refusals["a group's creation"] = b.client.CreateGroup(world.ctx, &sidecar.GkmCreateGroupArgs{RepoId: otherRepoId, Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	_, refusals["another repo's key"] = b.client.RepoKey(world.ctx, otherRepoId, 1)
	_, refusals["another repo's current key"] = b.client.CurrentRepoKey(world.ctx, otherRepoId)
	for act, err := range refusals {
		if !errors.Is(err, sidecar.ErrGkmUnavailable) {
			t.Errorf("%s on an unconfirmed state: %v", act, err)
		}
	}
	if count := world.store.writeCallCount("b"); count != writes {
		t.Errorf("b sent gkm %d writes on an unconfirmed state", count-writes)
	}

	// a verified state ends the joining
	b.client.AuthAdvanced(world.log.Tip())
	if _, err := b.client.EnsureWritable(world.ctx, world.repoId); errors.Is(err, sidecar.ErrGkmUnavailable) {
		t.Errorf("b's write once a verified state is given: %v", err)
	}
	// an unconfirmed state given after it changes nothing
	b.client.AuthUnconfirmed(world.log.Tip(), world.repoId)
	if _, err := b.client.RepoKey(world.ctx, otherRepoId, 1); errors.Is(err, sidecar.ErrGkmUnavailable) && strings.Contains(err.Error(), "unconfirmed") {
		t.Errorf("an unconfirmed state replaced the verified one: %v", err)
	}
}
