//go:build !sidecar_http

// Recovery on the fake gkm (KEYS-M2-24; §22.7's recovery rows, DESIGN-DETAILS 6.6's self-join row): a code-only
// device reading only its wraps before admission, a forged recovery wrap stopping at the anchor with head_alarm, the
// self-join's generation with a clean tree and its generation 0 over a lost device's leaf, recovery with no leaf
// online at 16 leaves or fewer and its wait above, the restored order anchoring on a ReaderWrap, and a rebind killed
// between its steps. FS-20 and FS-22 run in KEYS-M2-27 and KEYS-M2-28.

package sidecar_test

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var _ sidecar.GkmRecoveryApi = (*gkmFakeApi)(nil)

// The member's recovery wraps of generations gkm holds, under their claims' commitments.
func (self *gkmFakeApi) RecoveryWraps(ctx context.Context, memberId sidecar.Id, recoveryScope bool) (*protocol.GkmRecoveryWrapsReply, error) {
	reply := &protocol.GkmRecoveryWrapsReply{}
	route := "RecoveryWraps"
	if recoveryScope {
		route = "RecoveryWraps:recovery"
	}
	err := self.call(route, func() error {
		store := self.store
		prefix := "gkm/recovery/" + hex.EncodeToString(memberId.Bytes()) + "/"
		paths := []string{}
		for path := range store.pathRecoveryWraps {
			if strings.HasPrefix(path, prefix) {
				paths = append(paths, path)
			}
		}
		slices.Sort(paths)
		for _, path := range paths {
			parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
			if len(parts) != 4 {
				continue
			}
			groupIdBytes, _ := hex.DecodeString(parts[0])
			generation, _ := strconv.ParseUint(parts[1], 10, 64)
			commitmentPrefix, _ := hex.DecodeString(parts[2])
			bindingPrefix, _ := hex.DecodeString(parts[3])
			generations := store.groupGenerations[sidecar.Id(groupIdBytes)]
			if generation == 0 || uint64(len(generations)) < generation {
				continue
			}
			rotate := &protocol.GenRotate{}
			if err := proto.Unmarshal(generations[generation-1].GetBody(), rotate); err != nil || !bytes.HasPrefix(rotate.GetCommitment(), commitmentPrefix) {
				// a staged wrap of a lost claim is passed over
				continue
			}
			reply.Wraps = append(reply.Wraps, &protocol.GkmRecoveryWrap{
				GroupId: groupIdBytes, Generation: generation, CommitmentPrefix: commitmentPrefix, BindingPrefix: bindingPrefix,
				Ciphertext: bytes.Clone(store.pathRecoveryWraps[path]),
			})
		}
		return nil
	})
	return reply, err
}

// One re-wrap after a rebind: of the group's newest generation only, If-None-Match.
func (self *gkmFakeApi) UploadRecoveryWrap(ctx context.Context, repoId sidecar.Id, memberId sidecar.Id, wrap *protocol.GkmRecoveryWrap) error {
	return self.call("UploadRecoveryWrap", func() error {
		store := self.store
		groupId := sidecar.Id(wrap.GetGroupId())
		if uint64(len(store.groupGenerations[groupId])) != wrap.GetGeneration() {
			return gkmFakeRefusal(http.StatusConflict, nil)
		}
		path := fmt.Sprintf("gkm/recovery/%s/%s/%020d/%s/%s", hex.EncodeToString(memberId.Bytes()), hex.EncodeToString(groupId.Bytes()),
			wrap.GetGeneration(), hex.EncodeToString(wrap.GetCommitmentPrefix()), hex.EncodeToString(wrap.GetBindingPrefix()))
		if held, ok := store.pathRecoveryWraps[path]; ok && !bytes.Equal(held, wrap.GetCiphertext()) {
			return gkmFakeRefusal(http.StatusPreconditionFailed, nil)
		}
		store.pathRecoveryWraps[path] = bytes.Clone(wrap.GetCiphertext())
		return nil
	})
}

// Deletes every wrap of the member whose b8 names the binding.
func (self *gkmFakeApi) DeleteRecoveryWraps(ctx context.Context, memberId sidecar.Id, bindingPrefix []byte) error {
	return self.call("DeleteRecoveryWraps", func() error {
		store := self.store
		prefix := "gkm/recovery/" + hex.EncodeToString(memberId.Bytes()) + "/"
		for path := range store.pathRecoveryWraps {
			if strings.HasPrefix(path, prefix) && strings.HasSuffix(path, "/"+hex.EncodeToString(bindingPrefix)) {
				delete(store.pathRecoveryWraps, path)
			}
		}
		return nil
	})
}

// A group's epochs from epoch 0.
func (self *gkmFakeApi) EpochsFromStart(ctx context.Context, repoId sidecar.Id, groupId sidecar.Id) (*protocol.GkmEpochsReply, error) {
	reply := &protocol.GkmEpochsReply{}
	err := self.call("EpochsFromStart", func() error {
		for epoch, object := range self.store.groupEpochs[groupId] {
			if self.store.prunedBelowEpoch <= uint64(epoch) {
				reply.Epochs = append(reply.Epochs, &protocol.GkmEpochEntry{Epoch: uint64(epoch), Object: object})
			}
		}
		return nil
	})
	return reply, err
}

// The recovery wrap paths the store holds whose b8 names a binding, sorted.
func (self *gkmFakeStore) recoveryWrapsOf(bindingKeySha256 []byte) []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	paths := []string{}
	for path := range self.pathRecoveryWraps {
		if strings.HasSuffix(path, "/"+hex.EncodeToString(bindingKeySha256[:8])) {
			paths = append(paths, path)
		}
	}
	slices.Sort(paths)
	return paths
}

// The routes one device called, in order.
func (self *gkmFakeStore) callsOf(label string) []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	routes := []string{}
	for _, call := range self.calls {
		if route, ok := strings.CutPrefix(call, label+":"); ok {
			routes = append(routes, route)
		}
	}
	return routes
}

// A recovery key for a test, with its binding's digest.
func gkmTestRecoveryKey(t *testing.T, label string) (hpke.PrivateKey, []byte) {
	t.Helper()
	seed := sha256.Sum256([]byte("seed of " + label))
	privateKey, err := sidecar.LoadGkmDelegationKey(seed[:])
	if err != nil {
		t.Fatal(err)
	}
	keySha256 := sha256.Sum256([]byte("the Ed25519 key of " + label))
	return privateKey, keySha256[:]
}

// The engine world with a second member, n, who lost its only device, x, a leaf, and holds a recovery binding:
// generation 2, which a rotated to, carries n's RecoveryWrap, and epoch 2 the group's sealed GroupInfo. r is the
// device n's recovery key admits, a writer of the repo, not yet in any state.
type gkmRecoveryWorld struct {
	*gkmFlowWorld
	lostMemberId sidecar.Id
	binding      *sidecar.GkmRecoveryBinding
	r            *gkmFlowDevice
	// what the anchor check was given, in order
	anchored []*sidecar.EvsRepoKey
	// the anchor check's answer; nil passes a key whose commitment is the stored generation's
	anchorErr error
}

func newGkmRecoveryWorld(t *testing.T, kind protocol.RepoKind, restored bool) *gkmRecoveryWorld {
	world := &gkmRecoveryWorld{gkmFlowWorld: newGkmEngineWorld(t, kind), lostMemberId: sidecar.NewId()}
	privateKey, keySha256 := gkmTestRecoveryKey(t, "n")
	world.binding = &sidecar.GkmRecoveryBinding{MemberId: world.lostMemberId, PrivateKey: privateKey, KeySha256: keySha256}
	member := &bridge.MemberRow{
		MemberId: world.lostMemberId.Bytes(), RecoveryKeySha256: keySha256,
		Bindings: []*bridge.RecoveryBindingRow{{KeySha256: keySha256, Signer: world.x.id.Bytes(), At: 1}},
	}
	if restored {
		// a void restored this binding: a newer one stands voided above it, so it takes no wrap
		_, voidedKeySha256 := gkmTestRecoveryKey(t, "n's voided binding")
		member.Bindings = append([]*bridge.RecoveryBindingRow{{KeySha256: voidedKeySha256, Signer: world.x.id.Bytes(), At: 1}}, member.Bindings...)
	} else {
		world.recoveryKeys[world.lostMemberId] = &sidecar.GkmRecoveryKey{XwingPublicKey: privateKey.PublicKey().Bytes(), BindingKeySha256: keySha256}
	}
	world.members = append(world.members, member)
	world.x.row.MemberId = world.lostMemberId.Bytes()
	world.stateFor()
	if key, err := world.flows[world.a].client.RotateRepo(world.ctx, world.repoId); err != nil || key.Generation() != 2 {
		t.Fatalf("the rotation that wraps to n's recovery key: %v", err)
	}
	world.selfUpdates(world.a, 1)
	r := world.admit("r")
	r.row.MemberId = world.lostMemberId.Bytes()
	r.row.AdmissionSigners = [][]byte{keySha256}
	world.grant(true, r)
	world.r = world.flow(r)
	return world
}

// What CORE-M2-06's anchor check stands in for here: the key must be the one gkm's stored generation commits to.
func (self *gkmRecoveryWorld) args(restored bool) *sidecar.GkmRecoverArgs {
	return &sidecar.GkmRecoverArgs{
		Binding: self.binding, ConfigRepoId: self.repoId, Restored: restored,
		Anchor: func(ctx context.Context, key *sidecar.EvsRepoKey) error {
			self.anchored = append(self.anchored, key)
			return self.anchorErr
		},
	}
}

// The progress RunRecovery reports for the world's repo.
func (self *gkmRecoveryWorld) run(restored bool) *sidecar.GkmRecoveryRepo {
	self.t.Helper()
	progress, err := self.r.client.RunRecovery(self.ctx, self.args(restored))
	if err != nil {
		self.t.Fatalf("a recovery pass: %v", err)
	}
	for _, repo := range progress {
		if repo.RepoId == self.repoId {
			return repo
		}
	}
	self.t.Fatalf("a recovery pass reports nothing of the repo")
	return nil
}

// §22.7: until it is admitted a code-only device reads only its member's recovery wraps, under
// recovery:<member_id>, keeps the newest of its binding per group, and runs nothing else: no anchor, no join.
func TestACodeOnlyDeviceReadsOnlyItsWrapsBeforeAdmission(t *testing.T) {
	world := newGkmRecoveryWorld(t, protocol.RepoKind_REPO_KIND_GENERAL, false)
	r := world.r
	// a wrap of another binding of the member is not kept
	_, otherKeySha256 := gkmTestRecoveryKey(t, "another binding")
	for _, path := range world.store.recoveryWrapsOf(world.binding.KeySha256) {
		otherPath := strings.TrimSuffix(path, hex.EncodeToString(world.binding.KeySha256[:8])) + hex.EncodeToString(otherKeySha256[:8])
		world.store.pathRecoveryWraps[otherPath] = world.store.pathRecoveryWraps[path]
	}
	kept, err := r.client.FetchRecoveryWraps(world.ctx, world.binding, false)
	if err != nil || kept != 1 {
		t.Fatalf("the fetch before admission kept %d wraps: %v", kept, err)
	}
	if err := r.client.AnchorRecovery(world.ctx, world.args(false)); !errors.Is(err, sidecar.ErrGkmWait) {
		t.Errorf("an anchor before admission: %v", err)
	}
	if _, err := r.client.RunRecovery(world.ctx, world.args(false)); !errors.Is(err, sidecar.ErrGkmRecoveryNotAnchored) {
		t.Errorf("a recovery pass before the anchor: %v", err)
	}
	if calls := world.store.callsOf("r"); !slices.Equal(calls, []string{"RecoveryWraps:recovery"}) {
		t.Errorf("an unadmitted device called %v", calls)
	}
	if len(world.anchored) != 0 {
		t.Errorf("the anchor check ran before admission")
	}
	if _, _, found, _ := r.client.TestHeldGeneration(world.repoId, 2); found {
		t.Errorf("an unadmitted device holds a generation")
	}
}

// TestARecoverySelfJoinCarriesNoGenWrapOverLostLeaves, the clean half (DESIGN-DETAILS 6.6): with every leaf a key
// holder at the recovered device's state, its self-join carries the newest generation with its GenWrap, as a resync
// does, with no other leaf online; every other leaf then adopts it.
func TestARecoverySelfJoinCarriesTheNewestGenerationOverACleanTree(t *testing.T) {
	world := newGkmRecoveryWorld(t, protocol.RepoKind_REPO_KIND_GENERAL, false)
	r := world.r
	if _, err := r.client.FetchRecoveryWraps(world.ctx, world.binding, false); err != nil {
		t.Fatal(err)
	}
	view := world.stateFor()
	if err := r.client.AnchorRecovery(world.ctx, world.args(false)); err != nil {
		t.Fatalf("the anchor: %v", err)
	}
	gen2 := world.storedGeneration(view, 2)
	if len(world.anchored) != 1 || !bytes.Equal(world.anchored[0].Commitment(), gen2.Rotate.GetCommitment()) || world.anchored[0].Generation() != 2 {
		t.Fatalf("the anchor was not given the config group's RK_2")
	}
	if anchored, err := r.client.RecoveryAnchored(); err != nil || !anchored {
		t.Errorf("the anchor's phase was not kept: %v", err)
	}
	// the anchor passes once: a second call asks nothing
	if err := r.client.AnchorRecovery(world.ctx, world.args(false)); err != nil || len(world.anchored) != 1 {
		t.Errorf("the anchor ran again: %v", err)
	}
	progress := world.run(false)
	if !progress.SelfJoined || progress.GenerationZero || !progress.Leaf || progress.Generation != 2 || progress.Waiting != nil {
		t.Fatalf("the self-join over a clean tree: %+v", progress)
	}
	epochs := world.store.groupEpochs[world.groupId]
	joinEpoch := epochs[len(epochs)-1]
	if !sidecar.GkmCommitIsExternal(joinEpoch.GetCommit()) || len(joinEpoch.GetGenWrap()) == 0 || len(joinEpoch.GetSealedGroupInfo()) == 0 || joinEpoch.GetGroupInfoGeneration() != 2 {
		t.Errorf("the self-join's epoch is no external commit carrying generation 2")
	}
	if labels := world.rosterLabels(world.engineGroup(world.r.gkmWorldDevice)); strings.Join(labels, "") != "abcprx" {
		t.Errorf("the tree after the self-join: %v", labels)
	}
	// the ladder opened down to generation 1
	if key, _, found, err := r.client.TestHeldGeneration(world.repoId, 1); err != nil || !found || key == nil {
		t.Errorf("the recovered device holds no generation 1: %v", err)
	}
	for _, device := range []*gkmWorldDevice{world.a, world.b} {
		if err := world.flows[device].client.SyncRepo(world.ctx, world.repoId); err != nil {
			t.Fatalf("%s processes the self-join: %v", device.label, err)
		}
		if world.pinnedEpoch(device) != uint64(len(epochs)-1) {
			t.Errorf("%s did not adopt the self-join's epoch", device.label)
		}
	}
	for _, device := range world.devices {
		if alarms := world.flows[device].alarms; len(alarms) != 0 {
			t.Errorf("%s alarmed: %+v", device.label, alarms[0])
		}
	}
	// nothing more is due: a second pass commits nothing
	commits := world.store.callCount("CommitEpoch")
	if progress := world.run(false); progress.SelfJoined || world.store.callCount("CommitEpoch") != commits {
		t.Errorf("a second pass joined or committed again")
	}
}

// TestARecoverySelfJoinCarriesNoGenWrapOverLostLeaves (DESIGN-DETAILS 6.6; FS-20's unit): while the lost device's
// revoked leaf stands, the self-join is generation 0 with no GenWrap, its GroupInfo sealed under the newest
// generation the joiner holds; the recovered device's next commit removes that leaf, and the rotation after it,
// cause REMOVE, is the first new generation, which reaches the lost device by no delivery and no tree.
func TestARecoverySelfJoinCarriesNoGenWrapOverLostLeaves(t *testing.T) {
	world := newGkmRecoveryWorld(t, protocol.RepoKind_REPO_KIND_GENERAL, false)
	r := world.r
	world.revoke(world.x)
	view := world.stateFor()
	if err := r.client.AnchorRecovery(world.ctx, world.args(false)); err != nil {
		t.Fatalf("the anchor: %v", err)
	}
	before := len(world.store.groupEpochs[world.groupId])
	progress := world.run(false)
	if !progress.SelfJoined || !progress.GenerationZero || !progress.Leaf || progress.Waiting != nil {
		t.Fatalf("the self-join over a lost leaf: %+v", progress)
	}
	epochs := world.store.groupEpochs[world.groupId]
	if len(epochs) != before+2 {
		t.Fatalf("the self-join and its Remove made %d epochs", len(epochs)-before)
	}
	joinEpoch, removeEpoch := epochs[before], epochs[before+1]
	// the fake gkm reads no header of the fake's external commits: a commit is uploaded with no GenWrap only when
	// its staged header says generation 0, and every member's check below holds the two together
	if !sidecar.GkmCommitIsExternal(joinEpoch.GetCommit()) || len(joinEpoch.GetGenWrap()) != 0 {
		t.Errorf("the self-join's epoch carries a GenWrap of %d bytes", len(joinEpoch.GetGenWrap()))
	}
	if len(joinEpoch.GetSealedGroupInfo()) == 0 || joinEpoch.GetGroupInfoGeneration() != 2 {
		t.Errorf("the self-join's GroupInfo is not sealed under generation 2: %d", joinEpoch.GetGroupInfoGeneration())
	}
	if removeEpoch.GetHeader().GetGeneration() != 2 || len(removeEpoch.GetGenWrap()) == 0 {
		t.Errorf("the next commit carries generation %d", removeEpoch.GetHeader().GetGeneration())
	}
	if labels := world.rosterLabels(world.engineGroup(world.r.gkmWorldDevice)); strings.Join(labels, "") != "abcpr" {
		t.Errorf("the tree after the recovered device's next commit: %v", labels)
	}
	// the rotation after the Remove is the first new generation, and the lost device is no recipient of it
	if world.store.newestGeneration(world.groupId) != 3 {
		t.Fatalf("the newest generation is %d", world.store.newestGeneration(world.groupId))
	}
	gen3 := world.storedGeneration(view, 3)
	if sidecar.GkmCause(gen3.Rotate.GetCause()) != sidecar.GkmCauseRemove {
		t.Errorf("the rotation past the lost device: cause %d", gen3.Rotate.GetCause())
	}
	if leafWrap := gen3.Rotate.GetLeafWrap(); leafWrap == nil || leafWrap.GetEpoch() != uint64(before+1) {
		t.Errorf("the rotation's leaf_wrap does not name the clean epoch: %v", leafWrap)
	}
	if _, toLost := world.deliveryRecipients(3)["s:x"]; toLost {
		t.Errorf("a delivery of generation 3 to the lost device")
	}
	// the lost device, fetching everything, adopts the self-join's epoch, which hands it nothing, and is removed
	x := world.flows[world.x]
	if err := x.client.SyncRepo(world.ctx, world.repoId); err != nil {
		t.Logf("the lost device's sync: %v", err)
	}
	if key, _, found, _ := x.client.TestHeldGeneration(world.repoId, 3); found && key != nil {
		t.Errorf("the lost device opened generation 3")
	}
	// every other leaf adopts both epochs and opens generation 3 by its leaf_wrap
	for _, device := range []*gkmWorldDevice{world.a, world.b} {
		flow := world.flows[device]
		if err := flow.client.SyncRepo(world.ctx, world.repoId); err != nil {
			t.Fatalf("%s processes the recovery: %v", device.label, err)
		}
		if key, _, found, err := flow.client.TestHeldGeneration(world.repoId, 3); err != nil || !found || key == nil {
			t.Errorf("%s holds no key of generation 3: %v", device.label, err)
		}
		if len(flow.alarms) != 0 {
			t.Errorf("%s alarmed: %+v", device.label, flow.alarms[0])
		}
	}
	// the member's recovery identity is kept: generation 3 carries its RecoveryWrap
	if paths := world.store.recoveryWrapPaths(world.groupId, 3); len(paths) != 1 {
		t.Errorf("generation 3 carries %d recovery wraps", len(paths))
	}
}

// §22.7: a forged RecoveryWrap, one a server sealed to the member's public recovery key under a generation a forged
// log admits, fails §7.9's anchor: the device raises head_alarm (fork), keeps nothing of it, and acts no further,
// now or after a restart. An anchor check that could not run stops nothing.
func TestAForgedRecoveryWrapRaisesHeadAlarmAndStops(t *testing.T) {
	world := newGkmRecoveryWorld(t, protocol.RepoKind_REPO_KIND_GENERAL, false)
	r := world.r
	world.stateFor()
	// a wrap whose bytes do not open stops nothing and anchors nothing
	genuine := map[string][]byte{}
	for path, ciphertext := range world.store.pathRecoveryWraps {
		genuine[path] = ciphertext
		world.store.pathRecoveryWraps[path] = bytes.Repeat([]byte{1}, len(ciphertext))
	}
	if err := r.client.AnchorRecovery(world.ctx, world.args(false)); !errors.Is(err, sidecar.ErrGkmAuthentication) || len(world.anchored) != 0 {
		t.Fatalf("a wrap that does not open: %v", err)
	}
	for path, ciphertext := range genuine {
		world.store.pathRecoveryWraps[path] = ciphertext
	}
	// the check could not run: nothing is decided
	world.anchorErr = errors.New("the config head could not be fetched")
	if err := r.client.AnchorRecovery(world.ctx, world.args(false)); err == nil || errors.Is(err, sidecar.ErrGkmRecoveryStopped) {
		t.Fatalf("an anchor that could not run: %v", err)
	}
	if len(r.alarms) != 0 {
		t.Fatalf("an anchor that could not run alarmed")
	}
	// the head the wrap's key opens does not chain to a genesis this binding signed
	world.anchorErr = fmt.Errorf("%w: the head's genesis is not the one this binding signed", sidecar.ErrGkmRecoveryAnchor)
	if err := r.client.AnchorRecovery(world.ctx, world.args(false)); !errors.Is(err, sidecar.ErrGkmRecoveryStopped) || !errors.Is(err, sidecar.ErrGkmRecoveryAnchor) {
		t.Fatalf("a failed anchor: %v", err)
	}
	if len(r.alarms) != 1 || r.alarms[0].Kind != sidecar.GkmAlarmHead || r.alarms[0].Reason != sidecar.GkmRefusalFork || r.alarms[0].Generation != 2 {
		t.Fatalf("a failed anchor's alarm: %+v", r.alarms)
	}
	if _, _, found, _ := r.client.TestHeldGeneration(world.repoId, 2); found {
		t.Errorf("a failed anchor left its generation in the keychain")
	}
	// it acts no further, with a passing check too, and after a restart
	world.anchorErr = nil
	r.restart()
	if err := r.client.AnchorRecovery(world.ctx, world.args(false)); !errors.Is(err, sidecar.ErrGkmRecoveryStopped) {
		t.Errorf("an anchor after a stop: %v", err)
	}
	if _, err := r.client.RunRecovery(world.ctx, world.args(false)); !errors.Is(err, sidecar.ErrGkmRecoveryStopped) {
		t.Errorf("a recovery pass after a stop: %v", err)
	}
	if world.store.callCount("CommitEpoch") != 1 || slices.Contains(world.store.callsOf("r"), "CommitEpoch") {
		t.Errorf("a stopped recovery committed")
	}
	// a host with no anchor check recovers nothing
	other := newGkmRecoveryWorld(t, protocol.RepoKind_REPO_KIND_GENERAL, false)
	other.stateFor()
	args := other.args(false)
	args.Anchor = nil
	if err := other.r.client.AnchorRecovery(other.ctx, args); !errors.Is(err, sidecar.ErrGkmUnavailable) {
		t.Errorf("an anchor with no check installed: %v", err)
	}
}

// §22.7: recovery with no leaf online at 16 leaves or fewer joins from the newest epoch's inline GroupInfo; above 16
// leaves the self-join waits for one leaf online to write the current GroupInfo, asks for it, and joins once a leaf
// has answered.
func TestARecoverySelfJoinWaitsForALeafAboveSixteenLeaves(t *testing.T) {
	world := newGkmRecoveryWorld(t, protocol.RepoKind_REPO_KIND_GENERAL, false)
	r := world.r
	a := world.flows[world.a]
	world.stateFor()
	// 17 leaves: a's next commit seals no GroupInfo inline
	if err := a.client.SyncRepo(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	for count := 0; count < 11; count += 1 {
		world.admitReader("m"+strconv.Itoa(count), 1)
	}
	world.stateFor()
	if err := a.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatalf("a adds eleven devices: %v", err)
	}
	if roster := world.engineGroup(world.a).Roster(); len(roster) != 16 {
		t.Fatalf("the tree holds %d leaves", len(roster))
	}
	if err := r.client.AnchorRecovery(world.ctx, world.args(false)); err != nil {
		t.Fatalf("the anchor: %v", err)
	}
	// at 16 leaves the newest epoch's object holds the GroupInfo: the join needs no one, and makes the 17th leaf
	progress := world.run(false)
	if !progress.SelfJoined || progress.Waiting != nil {
		t.Fatalf("the self-join at 16 leaves, no leaf online: %+v", progress)
	}
	if roster := world.engineGroup(world.r.gkmWorldDevice).Roster(); len(roster) != 17 {
		t.Fatalf("the tree holds %d leaves", len(roster))
	}

	if err := a.client.SyncRepo(world.ctx, world.repoId); err != nil {
		t.Fatalf("a processes the self-join: %v", err)
	}
	world.selfUpdates(world.a, 1)

	// a second recovered device of the member now meets 17 leaves and no GroupInfo of the newest epoch
	s := world.admit("s")
	s.row.MemberId = world.lostMemberId.Bytes()
	s.row.AdmissionSigners = [][]byte{world.binding.KeySha256}
	world.grant(true, s)
	second := world.flow(s)
	world.stateFor()
	world.store.groupInfos = map[sidecar.Id]*protocol.GkmGroupInfoObject{}
	if err := second.client.AnchorRecovery(world.ctx, world.args(false)); err != nil {
		t.Fatalf("the second device's anchor: %v", err)
	}
	passes, err := second.client.RunRecovery(world.ctx, world.args(false))
	if err != nil || len(passes) != 1 || passes[0].SelfJoined || !errors.Is(passes[0].Waiting, sidecar.ErrGkmWait) {
		t.Fatalf("a self-join above 16 leaves with no GroupInfo: %+v %v", passes, err)
	}
	newest, _ := world.store.newestEpoch(world.groupId)
	if !slices.Contains(world.store.groupInfoWants, newest) {
		t.Errorf("the waiting self-join asked for no GroupInfo of epoch %d: %v", newest, world.store.groupInfoWants)
	}
	// one leaf online writes it
	if err := a.client.AnswerWant(world.ctx, world.repoId); err != nil {
		t.Fatalf("a leaf answers the want: %v", err)
	}
	passes, err = second.client.RunRecovery(world.ctx, world.args(false))
	if err != nil || len(passes) != 1 || !passes[0].SelfJoined || passes[0].Waiting != nil {
		t.Fatalf("the self-join once a leaf wrote the GroupInfo: %+v %v", passes, err)
	}
}

// §22.7: under a binding a void restored the device takes no RecoveryWrap: it anchors on the late ReaderWrap of the
// config group's current generation that a config writer gives it, waits while none has reached it, and commits
// nothing before the anchor passes; a forged ReaderWrap fails the anchor with head_alarm, and nothing is joined.
func TestTheRestoredOrderAnchorsOnAReaderWrapBeforeItSelfJoins(t *testing.T) {
	for _, forged := range []bool{false, true} {
		world := newGkmRecoveryWorld(t, protocol.RepoKind_REPO_KIND_CONFIG, true)
		r := world.r
		a := world.flows[world.a]
		world.stateFor()
		if paths := world.store.recoveryWrapPaths(world.groupId, 2); len(paths) != 0 {
			t.Fatalf("a restored binding took %d recovery wraps", len(paths))
		}
		if _, err := r.client.RunRecovery(world.ctx, world.args(true)); !errors.Is(err, sidecar.ErrGkmRecoveryNotAnchored) {
			t.Fatalf("a recovery pass before the anchor: %v", err)
		}
		if err := r.client.AnchorRecovery(world.ctx, world.args(true)); !errors.Is(err, sidecar.ErrGkmWait) || len(world.anchored) != 0 {
			t.Fatalf("an anchor with no ReaderWrap yet: %v", err)
		}
		if err := a.client.DeliverFirstWrap(world.ctx, world.repoId, world.r.id); err != nil {
			t.Fatalf("a config writer's late ReaderWrap: %v", err)
		}
		if slices.Contains(world.store.callsOf("r"), "CommitEpoch") {
			t.Fatalf("a commit before the anchor")
		}
		if forged {
			world.anchorErr = fmt.Errorf("%w: the head's genesis is not the one this binding signed", sidecar.ErrGkmRecoveryAnchor)
			if err := r.client.AnchorRecovery(world.ctx, world.args(true)); !errors.Is(err, sidecar.ErrGkmRecoveryStopped) {
				t.Fatalf("a forged ReaderWrap's anchor: %v", err)
			}
			if len(r.alarms) != 1 || r.alarms[0].Kind != sidecar.GkmAlarmHead {
				t.Errorf("a forged ReaderWrap's alarm: %+v", r.alarms)
			}
			if _, _, found, _ := r.client.TestHeldGeneration(world.repoId, 2); found {
				t.Errorf("a failed anchor left the ReaderWrap's generation in the keychain")
			}
			if _, err := r.client.RunRecovery(world.ctx, world.args(true)); !errors.Is(err, sidecar.ErrGkmRecoveryStopped) || slices.Contains(world.store.callsOf("r"), "CommitEpoch") {
				t.Errorf("a recovery pass after a failed anchor: %v", err)
			}
			continue
		}
		if err := r.client.AnchorRecovery(world.ctx, world.args(true)); err != nil {
			t.Fatalf("the anchor on the ReaderWrap: %v", err)
		}
		if len(world.anchored) != 1 || world.anchored[0].Generation() != 2 {
			t.Fatalf("the anchor was not given the ReaderWrap's RK_2")
		}
		progress := world.run(true)
		if !progress.SelfJoined || progress.GenerationZero || !progress.Leaf || progress.Waiting != nil {
			t.Fatalf("the self-join after the anchor: %+v", progress)
		}
	}
}

// §22.7's kill between rebind steps: a rebind wraps the group's newest generation to the new binding at its own b8,
// deletes the retired binding's wraps only once every new one stands, and then rotates; a kill after a wrap, before
// the delete, or before the claim leaves both bindings' wraps or the new one's alone, never neither, and the resumed
// rebind finishes. A compromise rebind's rotation is cause REMOVE.
func TestARebindSurvivesAKillBetweenItsSteps(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.flows[world.a]
	oldKey, oldKeySha256 := gkmTestRecoveryKey(t, "the first binding")
	newKey, newKeySha256 := gkmTestRecoveryKey(t, "the second binding")
	bind := func(privateKey hpke.PrivateKey, keySha256 []byte) *sidecar.GkmRecoveryKey {
		world.members[0].RecoveryKeySha256 = keySha256
		world.members[0].Bindings = append([]*bridge.RecoveryBindingRow{{KeySha256: keySha256, Signer: world.a.id.Bytes(), At: world.nextPosition()}}, world.members[0].Bindings...)
		recoveryKey := &sidecar.GkmRecoveryKey{XwingPublicKey: privateKey.PublicKey().Bytes(), BindingKeySha256: keySha256}
		world.recoveryKeys[world.memberId] = recoveryKey
		world.stateFor()
		return recoveryKey
	}
	bind(oldKey, oldKeySha256)
	if _, err := a.client.RotateRepo(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if len(world.store.recoveryWrapsOf(oldKeySha256)) != 1 {
		t.Fatalf("generation 2 carries no wrap to the first binding")
	}
	rebind := &sidecar.GkmRecoveryRebindArgs{MemberId: world.memberId, RetiredKeySha256: oldKeySha256}

	// the new binding has not landed: nothing is written
	rebind.New = &sidecar.GkmRecoveryKey{XwingPublicKey: newKey.PublicKey().Bytes(), BindingKeySha256: newKeySha256}
	if err := a.client.RebindRecovery(world.ctx, rebind); !errors.Is(err, sidecar.ErrGkmWait) || world.store.callCount("UploadRecoveryWrap") != 0 {
		t.Fatalf("a rebind before its statement landed: %v", err)
	}
	bind(newKey, newKeySha256)

	// a kill just after the new wrap's write: both bindings' wraps stand
	world.store.plant("UploadRecoveryWrap", false)
	if err := a.client.RebindRecovery(world.ctx, rebind); err == nil {
		t.Fatalf("the killed rebind answered")
	}
	if len(world.store.recoveryWrapsOf(oldKeySha256)) != 1 || len(world.store.recoveryWrapsOf(newKeySha256)) != 1 || world.store.callCount("DeleteRecoveryWraps") != 0 {
		t.Fatalf("after a kill past the wrap: %d old, %d new", len(world.store.recoveryWrapsOf(oldKeySha256)), len(world.store.recoveryWrapsOf(newKeySha256)))
	}
	// a kill before the delete: still both
	a.restart()
	world.store.plant("DeleteRecoveryWraps", true)
	if resumed, err := a.client.ResumeRecoveryRebind(world.ctx); !resumed || err == nil {
		t.Fatalf("the rebind killed at its delete: %v", err)
	}
	if len(world.store.recoveryWrapsOf(oldKeySha256)) != 1 || len(world.store.recoveryWrapsOf(newKeySha256)) != 1 {
		t.Fatalf("after a kill at the delete: %d old, %d new", len(world.store.recoveryWrapsOf(oldKeySha256)), len(world.store.recoveryWrapsOf(newKeySha256)))
	}
	// a kill before the rotation's claim: the retired wraps are gone, the new one stands
	a.restart()
	world.store.plantCount("ClaimGeneration", true, 3)
	if resumed, err := a.client.ResumeRecoveryRebind(world.ctx); !resumed || err == nil {
		t.Fatalf("the rebind killed at its claim: %v", err)
	}
	if len(world.store.recoveryWrapsOf(oldKeySha256)) != 0 || len(world.store.recoveryWrapsOf(newKeySha256)) < 1 || world.store.newestGeneration(world.groupId) != 2 {
		t.Fatalf("after a kill at the claim: %d old, %d new, generation %d", len(world.store.recoveryWrapsOf(oldKeySha256)), len(world.store.recoveryWrapsOf(newKeySha256)), world.store.newestGeneration(world.groupId))
	}
	a.restart()
	if resumed, err := a.client.ResumeRecoveryRebind(world.ctx); !resumed || err != nil {
		t.Fatalf("the resumed rebind: %v", err)
	}
	if resumed, err := a.client.ResumeRecoveryRebind(world.ctx); resumed || err != nil {
		t.Errorf("a finished rebind left its record: %v", err)
	}
	// the delete came after every wrap of the new binding
	calls := world.store.callsOf("a")
	if slices.Index(calls, "DeleteRecoveryWraps") < slices.Index(calls, "UploadRecoveryWrap") {
		t.Errorf("the retired binding's wraps were deleted before the new one's stood: %v", calls)
	}
	tip := world.log.Tip()
	gen3 := world.storedGeneration(tip, 3)
	if sidecar.GkmCause(gen3.Rotate.GetCause()) != sidecar.GkmCauseRequest {
		t.Errorf("a routine rebind's rotation: cause %d", gen3.Rotate.GetCause())
	}
	if paths := world.store.recoveryWrapPaths(world.groupId, 3); len(paths) != 1 || !strings.HasSuffix(paths[0], hex.EncodeToString(newKeySha256[:8])) {
		t.Errorf("generation 3's recovery wraps: %v", paths)
	}
	// the new binding's wrap of generation 2 opens to RK_2 under the new key
	reply, err := a.api.RecoveryWraps(world.ctx, world.memberId, false)
	if err != nil {
		t.Fatal(err)
	}
	opened := false
	for _, wrap := range reply.GetWraps() {
		if wrap.GetGeneration() != 2 {
			continue
		}
		key, err := sidecar.OpenGkmRecoveryWrap(wrap.GetCiphertext(), world.storedGeneration(tip, 2), &sidecar.GkmRecoveryArgs{
			MemberId: world.memberId, GroupId: world.groupId, BindingKeySha256: newKeySha256,
		}, newKey)
		opened = err == nil && key.Generation() == 2
	}
	if !opened {
		t.Errorf("the re-wrap of generation 2 does not open under the new binding")
	}

	// a compromise rebind, which shrinks every repo the member reads (§7.9): the rotation is cause REMOVE
	thirdKey, thirdKeySha256 := gkmTestRecoveryKey(t, "the third binding")
	world.repo.HoldersShrunkAt = world.nextPosition()
	compromise := &sidecar.GkmRecoveryRebindArgs{MemberId: world.memberId, New: bind(thirdKey, thirdKeySha256), RetiredKeySha256: newKeySha256, Compromise: true}
	if err := a.client.RebindRecovery(world.ctx, compromise); err != nil {
		t.Fatalf("a compromise rebind: %v", err)
	}
	gen4 := world.storedGeneration(world.log.Tip(), 4)
	if sidecar.GkmCause(gen4.Rotate.GetCause()) != sidecar.GkmCauseRemove {
		t.Errorf("a compromise rebind's rotation: cause %d", gen4.Rotate.GetCause())
	}
	if len(world.store.recoveryWrapsOf(newKeySha256)) != 0 || len(world.store.recoveryWrapsOf(thirdKeySha256)) == 0 {
		t.Errorf("after a compromise rebind: %d of the retired binding's wraps stand", len(world.store.recoveryWrapsOf(newKeySha256)))
	}
}
