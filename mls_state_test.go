// MLS state on disk (KEYS-M2-09): a group reloaded equal to the one driven, a staged commit surviving a kill at
// each point around staging, gkm's answer and adoption, a handshake generation never sealed twice, a store's
// AEAD failure refused rather than read as absence, no plaintext of a state on the medium, and a 1,000-leaf
// state streamed a node at a time with its memory recorded.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"runtime"
	"slices"
	"strings"
	"testing"
	"testing/cryptotest"
)

// A group loaded from disk is the one its member drives: one epoch, authenticator, tree, roster and KEK, and a
// commit made from the loaded one is one every other member follows.
func TestMlsStateReloadsEqualToTheLiveGroup(t *testing.T) {
	world := newMlsTestWorld(t)
	a, b, c := world.sidecar(nil), world.sidecar(nil), world.sidecar(nil)
	groups := mlsTestGroupOf(t, a, b, c)
	staged, err := groups[1].Commit(&MlsCommitArgs{Path: true, AuthenticatedData: []byte("update")})
	if err != nil {
		t.Fatal(err)
	}
	adopted, err := staged.Adopt()
	if err != nil {
		t.Fatal(err)
	}
	groups = mlsTestFollow(t, groups, 1, adopted, staged.Message())

	b.restart(t)
	loaded, err := b.engine.LoadGroup(groups[1].GroupId())
	if err != nil {
		t.Fatal(err)
	}
	mlsTestAgree(t, []MlsGroup{groups[1], loaded})
	live, reloaded := groups[1].(*mlsRealGroup).state, loaded.(*mlsRealGroup).state
	liveTree, err := mlsMarshal(live.tree)
	if err != nil {
		t.Fatal(err)
	}
	reloadedTree, err := mlsMarshal(reloaded.tree)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(liveTree, reloadedTree) || !bytes.Equal(live.encodedGroupContext, reloaded.encodedGroupContext) ||
		!bytes.Equal(live.interimTranscriptHash, reloaded.interimTranscriptHash) || !bytes.Equal(live.confirmationTag, reloaded.confirmationTag) {
		t.Error("the reloaded state differs")
	}
	if !slices.EqualFunc(groups[1].Roster(), loaded.Roster(), func(first MlsMember, second MlsMember) bool {
		return first.LeafIndex == second.LeafIndex && first.SidecarId == second.SidecarId && bytes.Equal(first.Credential, second.Credential)
	}) {
		t.Error("the reloaded roster differs")
	}

	next, err := loaded.Commit(&MlsCommitArgs{Removes: []uint32{groups[2].Self().LeafIndex}, Path: true, AuthenticatedData: []byte("from disk")})
	if err != nil {
		t.Fatal(err)
	}
	adopted, err = next.Adopt()
	if err != nil {
		t.Fatal(err)
	}
	mlsTestAgree(t, mlsTestFollow(t, groups[:2], 1, adopted, next.Message()))
}

// A kill after the draft is written and before gkm sees the commit: the restarted engine holds the epoch, and
// gkm's copy of the commit, once uploaded, is the draft, which adopts with its Welcome intact.
func TestMlsStateKillAfterStage(t *testing.T) {
	world := newMlsTestWorld(t)
	a, b, joiner := world.sidecar(nil), world.sidecar(nil), world.sidecar(nil)
	groups := mlsTestGroupOf(t, a, b)
	keyPackage, err := joiner.engine.CreateKeyPackage(false)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := groups[0].Commit(&MlsCommitArgs{Adds: [][]byte{keyPackage.Encoded}, Path: true, AuthenticatedData: []byte("add")})
	if err != nil {
		t.Fatal(err)
	}
	groupInfo, err := staged.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	message, welcome := staged.Message(), staged.Welcome()

	a.restart(t)
	held, err := a.engine.LoadGroup(groups[0].GroupId())
	if err != nil {
		t.Fatal(err)
	}
	if held.Epoch() != 1 {
		t.Fatalf("a restart holds epoch %d", held.Epoch())
	}
	resumed, err := held.Process(message)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resumed.Welcome(), welcome) || resumed.Committer().SidecarId != a.signer.sidecarId {
		t.Error("the resumed commit is not the draft")
	}
	adopted, err := resumed.Adopt()
	if err != nil {
		t.Fatal(err)
	}
	groups = mlsTestFollow(t, groups, 0, adopted, message)
	pending, err := joiner.engine.JoinWelcome(welcome)
	if err != nil {
		t.Fatal(err)
	}
	joined, err := pending.Complete(groupInfo)
	if err != nil {
		t.Fatal(err)
	}
	mlsTestAgree(t, append(groups, joined))
	if slices.ContainsFunc(a.store.(*mlsTestStore).paths(), func(path string) bool { return strings.HasSuffix(path, "/draft") }) {
		t.Error("the adopted draft stayed on disk")
	}
}

// A kill after staging where another's commit won the epoch: the restarted engine processes the winner as
// received, and adopting it drops the draft.
func TestMlsStateKillAfterStageWhereAnotherWon(t *testing.T) {
	world := newMlsTestWorld(t)
	a, b := world.sidecar(nil), world.sidecar(nil)
	groups := mlsTestGroupOf(t, a, b)
	if _, err := groups[0].Commit(&MlsCommitArgs{Path: true, AuthenticatedData: []byte("loser")}); err != nil {
		t.Fatal(err)
	}
	winner, err := groups[1].Commit(&MlsCommitArgs{Path: true, AuthenticatedData: []byte("winner")})
	if err != nil {
		t.Fatal(err)
	}
	adopted, err := winner.Adopt()
	if err != nil {
		t.Fatal(err)
	}

	a.restart(t)
	held, err := a.engine.LoadGroup(groups[0].GroupId())
	if err != nil {
		t.Fatal(err)
	}
	processed, err := held.Process(winner.Message())
	if err != nil {
		t.Fatal(err)
	}
	if processed.Committer().SidecarId != b.signer.sidecarId || processed.Welcome() != nil {
		t.Error("the winner read as this sidecar's draft")
	}
	followed, err := processed.Adopt()
	if err != nil {
		t.Fatal(err)
	}
	mlsTestAgree(t, []MlsGroup{adopted, followed})
	if slices.ContainsFunc(a.store.(*mlsTestStore).paths(), func(path string) bool { return strings.HasSuffix(path, "/draft") }) {
		t.Error("the loser's draft outlived the winner's adoption")
	}
}

// A kill inside adoption, after the epoch reached is written and before the state is: the restart holds the old
// epoch, refuses no join it should take, and the draft still adopts.
func TestMlsStateKillInsideAdopt(t *testing.T) {
	world := newMlsTestWorld(t)
	a, b := world.sidecar(nil), world.sidecar(nil)
	groups := mlsTestGroupOf(t, a, b)
	staged, err := groups[0].Commit(&MlsCommitArgs{Path: true, AuthenticatedData: []byte("update")})
	if err != nil {
		t.Fatal(err)
	}
	store := a.store.(*mlsTestStore)
	store.failWritesAfter(1)
	if _, err := staged.Adopt(); !errors.Is(err, errMlsTestStoreWrite) {
		t.Fatalf("the killed adoption: %v", err)
	}
	store.failWritesAfter(-1)

	a.restart(t)
	held, err := a.engine.LoadGroup(groups[0].GroupId())
	if err != nil {
		t.Fatal(err)
	}
	if held.Epoch() != 1 {
		t.Fatalf("the restart holds epoch %d", held.Epoch())
	}
	resumed, err := held.Process(staged.Message())
	if err != nil {
		t.Fatal(err)
	}
	adopted, err := resumed.Adopt()
	if err != nil {
		t.Fatal(err)
	}
	mlsTestAgree(t, mlsTestFollow(t, groups, 0, adopted, staged.Message()))
}

// A kill between a one-time KeyPackage's deletion and the group's write loses the join, never allows a second:
// the restarted engine holds no group and no longer opens the Welcome.
func TestMlsStateKillInsideJoin(t *testing.T) {
	world := newMlsTestWorld(t)
	creator, joiner := world.sidecar(nil), world.sidecar(nil)
	groups := mlsTestGroupOf(t, creator)
	keyPackage, err := joiner.engine.CreateKeyPackage(false)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := groups[0].Commit(&MlsCommitArgs{Adds: [][]byte{keyPackage.Encoded}, AuthenticatedData: []byte("add")})
	if err != nil {
		t.Fatal(err)
	}
	groupInfo, err := staged.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := staged.Adopt(); err != nil {
		t.Fatal(err)
	}
	pending, err := joiner.engine.JoinWelcome(staged.Welcome())
	if err != nil {
		t.Fatal(err)
	}
	store := joiner.store.(*mlsTestStore)
	store.failWritesAfter(1)
	if _, err := pending.Complete(groupInfo); err == nil {
		t.Fatal("the killed join completed")
	}
	store.failWritesAfter(-1)
	joiner.restart(t)
	if _, err := joiner.engine.LoadGroup(groups[0].GroupId()); !errors.Is(err, ErrMlsGroupUnknown) {
		t.Errorf("a half-done join left a group: %v", err)
	}
	if _, err := joiner.engine.JoinWelcome(staged.Welcome()); !errors.Is(err, ErrMlsNotMember) {
		t.Errorf("the used KeyPackage opened the Welcome again: %v", err)
	}
}

// The generation a member seals its commit at, read by another member from the commit's sender data.
func mlsTestSentGeneration(t *testing.T, receiver MlsGroup, message []byte) uint32 {
	t.Helper()
	decoded := &mlsMessage{}
	if err := mlsUnmarshal(message, decoded); err != nil {
		t.Fatal(err)
	}
	protection, err := receiver.(*mlsRealGroup).state.messageProtection()
	if err != nil {
		t.Fatal(err)
	}
	senderData, err := protection.openSenderData(decoded.privateMessage)
	if err != nil {
		t.Fatal(err)
	}
	return senderData.generation
}

// A member never seals two commits of one epoch at one handshake generation: not after a discard, not after a
// restart that dropped its in-memory ratchet, and not from two handles of the same epoch (§10.4: each AEAD key is
// used once).
func TestMlsStateHandshakeGenerationNeverRepeats(t *testing.T) {
	world := newMlsTestWorld(t)
	a, b := world.sidecar(nil), world.sidecar(nil)
	groups := mlsTestGroupOf(t, a, b)
	generations := []uint32{}
	record := func(staged MlsStagedCommit) {
		t.Helper()
		generations = append(generations, mlsTestSentGeneration(t, groups[1], staged.Message()))
	}

	first, err := groups[0].Commit(&MlsCommitArgs{Path: true, AuthenticatedData: []byte("first")})
	if err != nil {
		t.Fatal(err)
	}
	record(first)
	first.Discard()
	second, err := groups[0].Commit(&MlsCommitArgs{Path: true, AuthenticatedData: []byte("second")})
	if err != nil {
		t.Fatal(err)
	}
	record(second)

	a.restart(t)
	reloaded, err := a.engine.LoadGroup(groups[0].GroupId())
	if err != nil {
		t.Fatal(err)
	}
	third, err := reloaded.Commit(&MlsCommitArgs{Path: true, AuthenticatedData: []byte("third")})
	if err != nil {
		t.Fatal(err)
	}
	record(third)
	another, err := a.engine.LoadGroup(groups[0].GroupId())
	if err != nil {
		t.Fatal(err)
	}
	fourth, err := another.Commit(&MlsCommitArgs{Path: true, AuthenticatedData: []byte("fourth")})
	if err != nil {
		t.Fatal(err)
	}
	record(fourth)
	if !slices.Equal(generations, []uint32{0, 1, 2, 3}) {
		t.Errorf("generations %v", generations)
	}
	// the last one staged is the one that adopts, and the other member follows it
	adopted, err := fourth.Adopt()
	if err != nil {
		t.Fatal(err)
	}
	mlsTestAgree(t, mlsTestFollow(t, groups, 0, adopted, fourth.Message()))
}

// A real sealed store on a memory medium, unlocked, one network enrolled: the engine's files go through §5.9's
// AEAD.
func mlsTestSealedStore(t *testing.T) (SidecarStoreBackend, SidecarStore) {
	t.Helper()
	instance, backend, _ := enrolledInstance(t)
	return backend, instance.Store(&testNetworkId)
}

// A state whose sealed bytes were damaged is a failure, never an absence: the engine loads nothing, and a group
// whose reached epoch cannot be read is not created again over it (D-CORE-15).
func TestMlsStateAeadFailureIsRefused(t *testing.T) {
	world := newMlsTestWorld(t)
	backend, store := mlsTestSealedStore(t)
	member := world.sidecar(store)
	groups := mlsTestGroupOf(t, member)
	groupId := groups[0].GroupId()

	damage := func(suffix string) {
		t.Helper()
		entries, err := backend.List("")
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name, suffix) {
				content := readBackend(t, backend, entry.Name)
				content[len(content)-20] ^= 1
				putBackendFile(t, backend, entry.Name, content)
				return
			}
		}
		t.Fatalf("no %s on the medium", suffix)
	}
	damage("/" + gkmPathId(groupId) + "/state")
	member.restart(t)
	if _, err := member.engine.LoadGroup(groupId); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("a damaged state: %v", err)
	}
	damage("/" + gkmPathId(groupId) + "/reached")
	member.restart(t)
	if _, err := member.engine.CreateGroup(groupId, mlsTestUrGroup()); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("a group created over a damaged one: %v", err)
	}
}

// No byte of a group's secrets, keys or tree reaches the medium in the clear, temporary files included, which the
// sealed store's writes go through.
func TestMlsStateWritesNoPlaintext(t *testing.T) {
	world := newMlsTestWorld(t)
	backend, store := mlsTestSealedStore(t)
	member, other := world.sidecar(store), world.sidecar(nil)
	groups := mlsTestGroupOf(t, member, other)
	if _, err := groups[0].Commit(&MlsCommitArgs{Path: true, AuthenticatedData: []byte("draft")}); err != nil {
		t.Fatal(err)
	}
	state := groups[0].(*mlsRealGroup).state
	secrets := map[string][]byte{
		"exporter_secret": state.exporterSecret,
		"init_secret":     state.initSecret,
		"a leaf key":      state.tree.leafNode(state.ownLeaf()).encryptionKey[:64],
		"a credential":    state.tree.leafNode(state.ownLeaf()).credential.urMlsCredential[:48],
		"the signature seed": state.signatureKey.Seed(),
	}
	for path, content := range backendSnapshot(t, backend) {
		for name, secret := range secrets {
			if bytes.Contains(content, secret) {
				t.Errorf("%s holds %s in the clear", path, name)
			}
		}
	}
}

// A writer that keeps only the largest single write and the total, so a state's streaming shows in its call
// sizes.
type mlsTestWriteMeter struct {
	largest int
	total   int
}

func (self *mlsTestWriteMeter) Write(data []byte) (int, error) {
	self.largest = max(self.largest, len(data))
	self.total += len(data)
	return len(data), nil
}

// A reader over encoded that keeps the largest single read asked of it.
type mlsTestReadMeter struct {
	reader  *bytes.Reader
	largest int
}

func (self *mlsTestReadMeter) Read(buffer []byte) (int, error) {
	self.largest = max(self.largest, len(buffer))
	return self.reader.Read(buffer)
}

// A full 1,000-leaf state streams out a node at a time and back in from its sections, never a write past a few
// KB, and reloads equal; the memory both take is logged for KEYS-M2-31's sizes (§18.4).
func TestMlsStateStreamsAThousandLeafTree(t *testing.T) {
	suite := mlsSuite
	cryptotest.SetGlobalRandom(t, 5)
	memberCount := 1000
	groupId := gkmTestBytes("thousand", gkmIdByteCount)
	clients := make([]*mlsTestClient, memberCount)
	for index := range clients {
		clients[index] = mlsNewTestClient(t, suite, fmt.Sprintf("client-%d", index))
	}
	settings := defaultMlsGroupSettings()
	tree := newMlsRatchetTree(suite, settings.Tree, &clients[0].keyPackage.leafNode)
	for _, client := range clients[1:] {
		if _, err := tree.addLeaf(&client.keyPackage.leafNode); err != nil {
			t.Fatal(err)
		}
	}
	for leaf := 0; leaf < memberCount; leaf += 2 {
		prepared, err := tree.prepareUpdatePath(mlsLeafIndex(leaf), tree.leafNode(mlsLeafIndex(leaf)), clients[leaf].signatureKey, groupId)
		if err != nil {
			t.Fatal(err)
		}
		prepared.erase()
	}
	treeHash, err := tree.treeHash()
	if err != nil {
		t.Fatal(err)
	}
	extensions, err := mlsSubsetGroupExtensions(mlsTestUrGroup())
	if err != nil {
		t.Fatal(err)
	}
	// leaf 1 never updated, so its KeyPackage keys are the tree's
	own := mlsLeafIndex(1)
	state, err := newMlsGroupState(&mlsGroupStateArgs{
		suite:                 suite,
		settings:              settings,
		credentialValidator:   mlsAcceptBasicCredential,
		groupContext:          &mlsGroupContext{cipherSuite: suite.value, groupId: groupId, epoch: 7, treeHash: treeHash, confirmedTranscriptHash: gkmTestBytes("confirmed", 32), extensions: extensions},
		tree:                  tree,
		treeSecrets:           newMlsTreeSecrets(suite, own, clients[own].leafKey),
		signatureKey:          clients[own].signatureKey,
		interimTranscriptHash: gkmTestBytes("interim", 32),
		confirmationTag:       gkmTestBytes("tag", 32),
		epochSecrets: &mlsEpochSecrets{
			initSecret:         gkmTestBytes("init", 32),
			exporterSecret:     gkmTestBytes("exporter", 32),
			externalSecret:     gkmTestBytes("external", 32),
			encryptionSecret:   gkmTestBytes("encryption", 32),
			senderDataSecret:   gkmTestBytes("sender data", 32),
			epochAuthenticator: gkmTestBytes("authenticator", 32),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	meter := &mlsTestWriteMeter{}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	if err := mlsWriteGroupState(meter, state); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	writeAllocated := after.TotalAlloc - before.TotalAlloc
	if 16*1024 < meter.largest {
		t.Errorf("a single write of %d bytes: the tree did not stream", meter.largest)
	}

	buffer := &bytes.Buffer{}
	if err := mlsWriteGroupState(buffer, state); err != nil {
		t.Fatal(err)
	}
	encodedByteCount := buffer.Len()
	reader := &mlsTestReadMeter{reader: bytes.NewReader(buffer.Bytes())}
	buffer = nil
	runtime.GC()
	runtime.ReadMemStats(&before)
	reloaded, err := mlsReadGroupState(io.Reader(reader), suite, settings, mlsAcceptBasicCredential)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	readAllocated := after.TotalAlloc - before.TotalAlloc
	if 16*1024 < reader.largest {
		t.Errorf("a single read of %d bytes: the tree did not stream", reader.largest)
	}
	runtime.GC()
	var settled runtime.MemStats
	runtime.ReadMemStats(&settled)
	live := int64(settled.HeapAlloc) - int64(before.HeapAlloc)
	runtime.KeepAlive(reloaded)
	// reading allocates each section, its decoded copy, and the tree hash's encodings, which the check of the tree
	// against its GroupContext computes; none of them outlives its node
	t.Logf("a state of %d leaves: %d bytes, in %d-byte writes and %d-byte reads at most; writing allocated %d bytes, reading %d, and the loaded state keeps %d live",
		memberCount, encodedByteCount, meter.largest, reader.largest, writeAllocated, readAllocated, live)
	if 3*uint64(encodedByteCount) < writeAllocated || 8*uint64(encodedByteCount) < readAllocated {
		t.Errorf("a %d-byte state allocated %d writing and %d reading", encodedByteCount, writeAllocated, readAllocated)
	}
	reloadedHash, err := reloaded.tree.treeHash()
	if err != nil || !bytes.Equal(reloadedHash, treeHash) || !bytes.Equal(reloaded.epochAuthenticator, state.epochAuthenticator) {
		t.Errorf("the reloaded state differs: %v", err)
	}
}

// A state section past its bound, a cut file and bytes past the last section are each a failure.
func TestMlsStateRefusesDamagedSections(t *testing.T) {
	world := newMlsTestWorld(t)
	groups := mlsTestGroupOf(t, world.sidecar(nil))
	state := groups[0].(*mlsRealGroup).state
	buffer := &bytes.Buffer{}
	if err := mlsWriteGroupState(buffer, state); err != nil {
		t.Fatal(err)
	}
	encoded := buffer.Bytes()
	read := func(data []byte) error {
		reader := bytes.NewReader(data)
		if _, err := mlsReadGroupState(reader, mlsSuite, defaultMlsGroupSettings(), state.credentialValidator); err != nil {
			return err
		}
		return mlsReadStateEnd(reader)
	}
	if err := read(encoded); err != nil {
		t.Fatal(err)
	}
	huge := append([]byte{0xff, 0xff, 0xff, 0xff}, encoded[4:]...)
	for name, data := range map[string][]byte{
		"a section past its bound": huge,
		"a cut file":               encoded[:len(encoded)-3],
		"a byte past the end":      append(bytes.Clone(encoded), 0),
	} {
		if err := read(data); !errors.Is(err, ErrSidecarStoreFailed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Damages the bytes of the file at a path ending in suffix, past its first section, in a test store.
func mlsTestDamageTail(t *testing.T, store *mlsTestStore, suffix string) {
	t.Helper()
	store.shared.stateLock.Lock()
	defer store.shared.stateLock.Unlock()
	for path, content := range store.shared.pathContents {
		if strings.HasSuffix(path, suffix) {
			content[len(content)-10] ^= 1
			return
		}
	}
	t.Fatalf("no %s", suffix)
}

// Matching a commit against the draft reads the draft's header alone: with its next epoch damaged, another's commit
// still processes, while its own commit, whose draft must then be read whole, is refused rather than adopted from a
// damaged state.
func TestMlsStateDraftMatchReadsOnlyItsHeader(t *testing.T) {
	world := newMlsTestWorld(t)
	a, b := world.sidecar(nil), world.sidecar(nil)
	groups := mlsTestGroupOf(t, a, b)
	own, err := groups[0].Commit(&MlsCommitArgs{Path: true, AuthenticatedData: []byte("own")})
	if err != nil {
		t.Fatal(err)
	}
	mlsTestDamageTail(t, a.store.(*mlsTestStore), "/draft")
	if _, err := groups[0].Process(own.Message()); err == nil {
		t.Error("a draft with a damaged next epoch was taken")
	}
	other, err := groups[1].Commit(&MlsCommitArgs{Path: true, AuthenticatedData: []byte("other")})
	if err != nil {
		t.Fatal(err)
	}
	adopted, err := other.Adopt()
	if err != nil {
		t.Fatal(err)
	}
	mlsTestAgree(t, mlsTestFollow(t, groups, 1, adopted, other.Message()))
}
