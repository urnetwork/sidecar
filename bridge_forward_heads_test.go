// A VPN component's config head reading (SDK-M8-16; DESIGN-DETAILS 4.2.5's Compile, step 3; QD-814) on the root's
// fakes: the Forwarder reads a base's head at the state at that base through a reader that anchors, a head read that
// lacked a generation's key has the next compile list gkm, and the forwarding reader's keys and store answer as a read
// needs. The reader over a real engine is sidecartest's (forward_config_heads_world_test.go).

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"google.golang.org/protobuf/proto"
)

// The world's heads as a reader that anchors: each anchored read records its anchor, and a plain read is counted.
type testForwarderAnchorHeads struct {
	*testForwarderHeads
	plainReads atomic.Int64
	stateLock  sync.Mutex
	anchors    []ConfigHeadAnchor
}

func (self *testForwarderAnchorHeads) ReadConfigHead(ctx context.Context, configVersion uint64, configHeadSha256 []byte) (*ConfigHead, error) {
	self.plainReads.Add(1)
	return self.testForwarderHeads.ReadConfigHead(ctx, configVersion, configHeadSha256)
}

func (self *testForwarderAnchorHeads) ReadConfigHeadAtAnchor(ctx context.Context, configVersion uint64, configHeadSha256 []byte, anchor ConfigHeadAnchor) (*ConfigHead, error) {
	self.stateLock.Lock()
	self.anchors = append(self.anchors, anchor)
	self.stateLock.Unlock()
	return self.testForwarderHeads.ReadConfigHead(ctx, configVersion, configHeadSha256)
}

// A Forwarder starts each compile at its newest base, so a reader that anchors reads that base's head at the state at
// the base (QD-814): the base's own state, not the tip's, which names the network's genesis and admits the base's
// signer. No plain read is made.
func TestTheForwarderReadsTheHeadAtTheStateAtItsBase(t *testing.T) {
	world := newTestForwarderWorld(t)
	heads := &testForwarderAnchorHeads{testForwarderHeads: world.forwardHeads}
	world.heads = heads
	forwarder := world.forwarder()
	tip := world.net.log.State()
	if status := forwarder.Status(); status.CompileCount != 1 || !proto.Equal(status.CompiledPin, tip.Pin()) {
		t.Fatalf("status %+v", status)
	}
	heads.stateLock.Lock()
	anchors := slices.Clone(heads.anchors)
	heads.stateLock.Unlock()
	if len(anchors) != 1 || heads.plainReads.Load() != 0 {
		t.Fatalf("%d anchored reads and %d plain reads", len(anchors), heads.plainReads.Load())
	}
	anchor, ok := anchors[0].(*ConfigState)
	if !ok || anchor.Base() == nil || !proto.Equal(anchor.Base(), tip.Base()) {
		t.Fatalf("the anchor %T is not the state at the tip's base", anchors[0])
	}
	if tip.Pin().GetVersion() <= anchor.Pin().GetVersion() {
		t.Errorf("the anchor stands at %d, not at the base below the tip's %d", anchor.Pin().GetVersion(), tip.Pin().GetVersion())
	}
	if !proto.Equal(anchor.Genesis(), tip.Genesis()) || !bytes.Equal(anchor.IdentityKey(world.net.owner.sidecarId), tip.IdentityKey(world.net.owner.sidecarId)) {
		t.Error("the anchor names another genesis or does not admit the base's signer")
	}
}

// A push of the head sealed under a generation no body named leaves the head unread: the compile fails, the state in
// force stands, and its retry lists gkm past the generations held, opens that generation and compiles.
func TestAHeadThatLacksAGenerationListsGkmAtTheNextCompile(t *testing.T) {
	world := newTestForwarderWorld(t)
	world.rotate(world.recipient())
	world.bind(world.peer)
	armed := atomic.Bool{}
	world.forwardHeads.onRead = func(ctx context.Context) error {
		if armed.CompareAndSwap(true, false) {
			return fmt.Errorf("%w: %w: a push sealed under generation 2", ErrConfigHeadUnavailable, ErrGkmKeyMissing)
		}
		return nil
	}
	forwarder := world.forwarder()
	if forwarder.RepoKeyAt(1) == nil || forwarder.RepoKeyAt(2) != nil {
		t.Fatal("the first compile did not open generation 1 alone")
	}

	world.rotate(world.recipient())
	for _, name := range world.stored(forwarderHeadPrefix) {
		if err := world.forwardStore.Remove(name); err != nil {
			t.Fatal(err)
		}
	}
	world.gkm.stateLock.Lock()
	reads := world.gkm.generationsReadCount
	world.gkm.stateLock.Unlock()
	before := forwarder.Status()
	armed.Store(true)
	world.net.consentedMember("after the rotation")
	world.hint(forwarder)
	status := forwarder.Status()
	world.gkm.stateLock.Lock()
	listedWhileFailing := world.gkm.generationsReadCount - reads
	world.gkm.stateLock.Unlock()
	if status.CompileErrorCount != before.CompileErrorCount+1 || status.CompileCount != before.CompileCount || forwarder.RepoKeyAt(2) != nil ||
		listedWhileFailing != 0 || !proto.Equal(status.CompiledPin, before.CompiledPin) {
		t.Fatalf("after the head's read failed, gkm listed %d times: status %+v", listedWhileFailing, status)
	}

	world.advance(forwarder, world.settings.CompileRetryInterval)
	status = forwarder.Status()
	world.gkm.stateLock.Lock()
	listed := world.gkm.generationsReadCount - reads
	world.gkm.stateLock.Unlock()
	if listed != 1 || forwarder.RepoKeyAt(2) == nil || status.CompileCount <= before.CompileCount || !proto.Equal(status.CompiledPin, world.net.log.State().Pin()) {
		t.Errorf("the retry listed gkm %d times, opened generation 2: %t, status %+v", listed, forwarder.RepoKeyAt(2) != nil, status)
	}
}

// The forwarding reader's keys: each generation the store holds, with RK_1 beside it so the ref derives; the newest
// of the run from the first as the current; a generation not held, and any other repo, a missing key; and every call a
// read does not make refused.
func TestForwardingConfigKeysAnswerAReadsTwoCalls(t *testing.T) {
	world := newTestForwarderWorld(t)
	world.rotate(world.recipient())
	world.rotate(world.recipient())
	forwarder := world.forwarder()
	ctx := context.Background()
	repoId := world.net.configRepoId()
	if stored := forwarder.RepoKeyAt(2); stored == nil || stored.HoldsFirst() {
		t.Fatalf("the store's generation 2 is %v, holding RK_1: the test needs one that does not", stored)
	}
	keys := &forwardingConfigKeys{repoId: repoId, repoKeyAt: forwarder.RepoKeyAt, generationMaxCount: 16}
	second, err := keys.RepoKey(ctx, repoId, 2)
	if err != nil || second.Generation() != 2 || !second.HoldsFirst() {
		t.Fatalf("generation 2: %v, %v", second, err)
	}
	refKey, err := NewEvsRefKey(second)
	if err != nil {
		t.Fatalf("no ref derives from generation 2: %v", err)
	}
	first, _ := keys.RepoKey(ctx, repoId, 1)
	firstRefKey, _ := NewEvsRefKey(first)
	if mainId, _ := EvsRefId(refKey, EvsMainRefName); mainId != func() Id { id, _ := EvsRefId(firstRefKey, EvsMainRefName); return id }() {
		t.Error("the main ref's id differs by generation")
	}
	if current, err := keys.CurrentRepoKey(ctx, repoId); err != nil || current.Generation() != 2 || !current.HoldsFirst() {
		t.Errorf("the current key: %v, %v", current, err)
	}
	if _, err := keys.RepoKey(ctx, repoId, 3); !errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("generation 3, which the store does not hold: %v", err)
	}
	if _, err := keys.RepoKey(ctx, testConfigId("another repo"), 1); !errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("another repo: %v", err)
	}
	bounded := &forwardingConfigKeys{repoId: repoId, repoKeyAt: forwarder.RepoKeyAt, generationMaxCount: 1}
	if current, err := bounded.CurrentRepoKey(ctx, repoId); err != nil || current.Generation() != 1 {
		t.Errorf("the current key within a bound of 1: %v, %v", current, err)
	}
	none := &forwardingConfigKeys{repoId: repoId, repoKeyAt: forwarder.RepoKeyAt}
	if _, err := none.CurrentRepoKey(ctx, repoId); !errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("a bound of 0 holds a current key: %v", err)
	}
	if _, err := keys.EnsureWritable(ctx, repoId); !errors.Is(err, ErrGkmUnavailable) {
		t.Errorf("a write's key was answered: %v", err)
	}
	if _, err := keys.RotateRepo(ctx, repoId); !errors.Is(err, ErrGkmUnavailable) {
		t.Errorf("a rotation was answered: %v", err)
	}
	if _, err := keys.DropKey(ctx, repoId); !errors.Is(err, ErrGkmUnavailable) {
		t.Errorf("a drop key was answered: %v", err)
	}
}

// The forwarding reader's store: its records under the evs- names in two segments, beside the Forwarder's and never
// listing them, and no directory.
func TestForwarderSidecarStoreKeepsItsNamesApart(t *testing.T) {
	inner := newTestConfigClientStore()
	if err := testForwarderStoreWrite(inner, forwarderGenesisName, []byte("the Forwarder's")); err != nil {
		t.Fatal(err)
	}
	store := &forwarderSidecarStore{store: inner, prefix: forwardingConfigHeadsStorePrefix}
	if err := testForwarderStoreWrite(store, "pins/0123", []byte("a pin")); err != nil {
		t.Fatal(err)
	}
	if _, found := inner.files["evs-pins/0123"]; !found {
		t.Fatalf("the inner store holds %v", slices.Sorted(maps.Keys(inner.files)))
	}
	reader, err := store.Open("pins/0123")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(reader)
	reader.Close()
	if string(data) != "a pin" {
		t.Errorf("read back %q", data)
	}
	entries, err := store.List("")
	if err != nil || len(entries) != 1 || entries[0].Name != "pins/0123" {
		t.Errorf("listed %v, %v", entries, err)
	}
	if err := store.Remove("pins/0123"); err != nil {
		t.Fatal(err)
	}
	if entries, _ := store.List("pins/"); len(entries) != 0 {
		t.Errorf("listed %v after the removal", entries)
	}
	if _, err := store.Directory("mirror", ""); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("a directory: %v", err)
	}
	// a read's spilled chunk, three segments in the evs client, is two in the forwarding store, and reads back
	spillChunk := "spill/0123abcd/00000001"
	if err := testForwarderStoreWrite(store, spillChunk, []byte("a chunk")); err != nil {
		t.Fatal(err)
	}
	if _, found := inner.files["evs-spill/0123abcd-00000001"]; !found {
		t.Errorf("the spilled chunk is not held flattened: %v", slices.Sorted(maps.Keys(inner.files)))
	}
	if reader, err := store.Open(spillChunk); err != nil {
		t.Errorf("the spilled chunk does not open: %v", err)
	} else {
		data, _ := io.ReadAll(reader)
		reader.Close()
		if string(data) != "a chunk" {
			t.Errorf("the spilled chunk read back %q", data)
		}
	}
	if err := store.Remove(spillChunk); err != nil {
		t.Fatal(err)
	}
	for name := range inner.files {
		if 1 < strings.Count(name, "/") {
			t.Errorf("a record named %q past two segments", name)
		}
	}
	if entries, _ := inner.List(""); len(entries) != 1 || !strings.HasPrefix(entries[0].Name, forwarderGenesisName) {
		t.Errorf("the Forwarder's records are now %v", entries)
	}
}

// Writes one record through store.
func testForwarderStoreWrite(store interface {
	Create(name string) (SidecarStoreWriter, error)
}, name string, data []byte) error {
	writer, err := store.Create(name)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Commit()
}
