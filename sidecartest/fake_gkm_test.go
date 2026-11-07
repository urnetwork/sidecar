// FakeGkm round-trips real ladder objects through fake Blobs (KEYS-M2-04's test): its clients read every key back
// through Signed gen/<g> objects, a rewritten object refuses, a removed reader keeps what it held and opens nothing
// newer however far behind its own state is, a late delivery follows a holder's state and every delivery and
// generation is judged at its own pin, and the depositor rule holds as far as the fake sees.

package sidecartest

import (
	"bytes"
	"errors"
	"io"
	"maps"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One test network's fake gkm, its log and its sidecars.
type fakeGkmTestNet struct {
	t       *testing.T
	clock   *FakeClock
	blobs   *FakeBlobs
	gkm     *FakeGkm
	log     *FakeGkmAuthLog
	repoId  sidecar.Id
	signers map[string]*FakeGkmSigner
	clients map[string]sidecar.GkmClient
}

// A network whose repo of kind is read by readers and written by writers, named by label, with the sidecars others
// names, which its first state lets do neither.
func newFakeGkmTestNet(t *testing.T, kind protocol.RepoKind, readers []string, writers []string, others ...string) *fakeGkmTestNet {
	clock := NewFakeClock(DefaultClockStart())
	blobs := NewFakeBlobs(clock, nil, nil, nil)
	net := &fakeGkmTestNet{
		t:       t,
		clock:   clock,
		blobs:   blobs,
		gkm:     NewFakeGkm(clock, blobs, nil),
		log:     NewFakeGkmAuthLog(),
		repoId:  sidecar.NewId(),
		signers: map[string]*FakeGkmSigner{},
		clients: map[string]sidecar.GkmClient{},
	}
	for _, label := range slices.Concat(readers, writers, others, []string{"depositor"}) {
		if _, ok := net.signers[label]; !ok {
			signer := NewFakeGkmSigner()
			net.signers[label] = signer
			net.clients[label] = net.gkm.Client(signer.SidecarId, signer.Sign)
		}
	}
	net.advance(kind, readers, writers, 0)
	return net
}

// Appends a position at which readers read and writers write the repo, holders_shrunk_at at shrunkAt, and gives it to
// every client.
func (self *fakeGkmTestNet) advance(kind protocol.RepoKind, readers []string, writers []string, shrunkAt uint64) *FakeGkmAuthView {
	view := self.appendState(kind, readers, writers, shrunkAt)
	self.give(view, slices.Collect(maps.Keys(self.clients))...)
	return view
}

// Gives a state to the clients labels names, and no other, so the rest stay behind on the log.
func (self *fakeGkmTestNet) give(view *FakeGkmAuthView, labels ...string) {
	for _, label := range labels {
		self.clients[label].AuthAdvanced(view)
	}
}

// The generation label's client reads now, or why it reads none.
func (self *fakeGkmTestNet) current(label string) (uint64, error) {
	key, err := self.clients[label].CurrentRepoKey(self.t.Context(), self.repoId)
	if err != nil {
		return 0, err
	}
	return key.Generation(), nil
}

// The ladder's newest generation at gkm.
func (self *fakeGkmTestNet) newest() uint64 {
	_, generation, _ := self.gkm.Newest(self.repoId)
	return generation
}

// Appends a position as advance does, and gives it to no client.
func (self *fakeGkmTestNet) appendState(kind protocol.RepoKind, readers []string, writers []string, shrunkAt uint64) *FakeGkmAuthView {
	fixture := &FakeGkmAuthFixture{
		Rows:         FakeGkmAuthRows(&protocol.AclRepo{RepoId: self.repoId.Bytes(), Kind: kind, HoldersShrunkAt: shrunkAt}),
		IdentityKeys: map[sidecar.Id][]byte{},
		RepoReaders:  map[sidecar.Id][]sidecar.Id{},
		RepoWriters:  map[sidecar.Id][]sidecar.Id{},
	}
	for _, signer := range self.signers {
		fixture.IdentityKeys[signer.SidecarId] = signer.PublicKey()
	}
	for _, label := range readers {
		fixture.RepoReaders[self.repoId] = append(fixture.RepoReaders[self.repoId], self.signers[label].SidecarId)
	}
	for _, label := range writers {
		fixture.RepoWriters[self.repoId] = append(fixture.RepoWriters[self.repoId], self.signers[label].SidecarId)
	}
	return self.log.Append(fixture)
}

// The repo's group, created by label's client.
func (self *fakeGkmTestNet) create(label string, kind protocol.RepoKind) *sidecar.EvsRepoKey {
	self.t.Helper()
	key, err := self.clients[label].CreateGroup(self.t.Context(), &sidecar.GkmCreateGroupArgs{RepoId: self.repoId, Kind: kind})
	if err != nil {
		self.t.Fatal(err)
	}
	return key
}

// A gen/<g> object of the group, as the store holds it.
func (self *fakeGkmTestNet) generationObject(groupId sidecar.Id, generation uint64) []byte {
	self.t.Helper()
	cluster, err := self.blobs.FirstCluster()
	if err != nil {
		self.t.Fatal(err)
	}
	object, err := cluster.Get(self.t.Context(), sidecar.GkmGenerationPath(groupId, generation))
	if err != nil {
		self.t.Fatalf("gen/%d: %v", generation, err)
	}
	defer object.Body.Close()
	objectBytes, err := io.ReadAll(object.Body)
	if err != nil {
		self.t.Fatal(err)
	}
	return objectBytes
}

func TestFakeGkmRoundTripsRealLadderObjects(t *testing.T) {
	net := newFakeGkmTestNet(t, protocol.RepoKind_REPO_KIND_GENERAL, []string{"writer", "reader"}, []string{"writer"})
	ctx := t.Context()
	first := net.create("writer", protocol.RepoKind_REPO_KIND_GENERAL)
	if first.Generation() != 1 || first.Cause() != sidecar.GkmCauseRequest {
		t.Fatalf("generation %d of cause %d", first.Generation(), first.Cause())
	}
	for _, want := range []uint64{2, 3} {
		key, err := net.clients["writer"].RotateRepo(ctx, net.repoId)
		if err != nil {
			t.Fatal(err)
		}
		if key.Generation() != want || key.Cause() != sidecar.GkmCauseRequest {
			t.Fatalf("rotated to %d, cause %d", key.Generation(), key.Cause())
		}
	}
	groupId, newest, ok := net.gkm.Newest(net.repoId)
	if !ok || groupId != first.GroupId() || newest != 3 {
		t.Fatalf("gkm serves %s at %d", groupId, newest)
	}

	// Each generation is a real Signed GenRotate, at its path, under the writer's identity key.
	writer := net.signers["writer"]
	for generation := uint64(1); generation <= 3; generation += 1 {
		parsed, err := sidecar.ParseGenRotate(net.generationObject(groupId, generation), groupId, generation, func(signerId sidecar.Id) ([]byte, error) {
			if signerId != writer.SidecarId {
				return nil, errors.New("not the writer")
			}
			return writer.PublicKey(), nil
		})
		if err != nil {
			t.Fatalf("gen/%d: %v", generation, err)
		}
		if !bytes.Equal(parsed.Rotate.GetRepoId(), net.repoId.Bytes()) || parsed.Rotate.GetAuth().GetVersion() != 1 {
			t.Errorf("gen/%d states %v", generation, parsed.Rotate)
		}
	}

	// A reader reads every generation back through those objects, RK_1's ref at each.
	reader := net.clients["reader"]
	current, err := reader.CurrentRepoKey(ctx, net.repoId)
	if err != nil {
		t.Fatal(err)
	}
	if current.Generation() != 3 {
		t.Fatalf("the reader's current generation is %d", current.Generation())
	}
	firstRef, err := first.DeriveKey(sidecar.EvsKeyPurposeRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	for generation := uint64(1); generation <= 3; generation += 1 {
		key, err := reader.RepoKey(ctx, net.repoId, generation)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := key.DeriveKey(sidecar.EvsKeyPurposeRef, nil)
		if err != nil || !bytes.Equal(ref, firstRef) {
			t.Errorf("generation %d's ref: %v", generation, err)
		}
		if generation == 1 && !bytes.Equal(key.Commitment(), first.Commitment()) {
			t.Error("the reader opened another RK_1")
		}
	}
	fek, _ := current.DeriveKey(sidecar.EvsKeyPurposeFek, nil)
	writerCurrent, err := net.clients["writer"].CurrentRepoKey(ctx, net.repoId)
	if err != nil {
		t.Fatal(err)
	}
	writerFek, _ := writerCurrent.DeriveKey(sidecar.EvsKeyPurposeFek, nil)
	if !bytes.Equal(fek, writerFek) {
		t.Error("reader and writer hold different generation 3 keys")
	}
	if _, err := reader.RepoKey(ctx, net.repoId, 4); !errors.Is(err, sidecar.ErrGkmKeyMissing) {
		t.Errorf("a generation that does not exist: %v", err)
	}
	if violations := net.blobs.Violations(); len(violations) != 0 {
		t.Errorf("store rules broken: %v", violations)
	}
}

// A rewritten gen/<g> object refuses at every reader, as gkm's would: its signature fails, or its ladder link does.
func TestFakeGkmRefusesARewrittenGeneration(t *testing.T) {
	net := newFakeGkmTestNet(t, protocol.RepoKind_REPO_KIND_GENERAL, []string{"writer", "reader"}, []string{"writer"})
	ctx := t.Context()
	first := net.create("writer", protocol.RepoKind_REPO_KIND_GENERAL)
	for range 2 {
		if _, err := net.clients["writer"].RotateRepo(ctx, net.repoId); err != nil {
			t.Fatal(err)
		}
	}
	groupId := first.GroupId()
	cluster, err := net.blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	info, err := cluster.Head(ctx, sidecar.GkmGenerationPath(groupId, 2))
	if err != nil {
		t.Fatal(err)
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(net.generationObject(groupId, 2), signed); err != nil {
		t.Fatal(err)
	}
	signed.Body[len(signed.Body)-1] ^= 1
	rewritten, _ := proto.Marshal(signed)
	if _, err := cluster.PutIfMatch(ctx, sidecar.GkmGenerationPath(groupId, 2), info.Etag, rewritten, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := net.clients["reader"].RepoKey(ctx, net.repoId, 1); !errors.Is(err, sidecar.ErrGkmAuthentication) {
		t.Errorf("a rewritten gen/2: %v", err)
	}

	// Re-signed by someone the log does not admit, it refuses too.
	stranger := NewFakeGkmSigner()
	signed.Body[len(signed.Body)-1] ^= 1
	resigned, _ := stranger.Sign("gen-rotate", bridge.SignedType_SIGNED_GEN_ROTATE, signed.GetBody(), nil)
	resignedBytes, _ := proto.Marshal(resigned)
	info, _ = cluster.Head(ctx, sidecar.GkmGenerationPath(groupId, 2))
	if _, err := cluster.PutIfMatch(ctx, sidecar.GkmGenerationPath(groupId, 2), info.Etag, resignedBytes, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := net.clients["reader"].CurrentRepoKey(ctx, net.repoId); !errors.Is(err, sidecar.ErrGkmAuthentication) {
		t.Errorf("gen/2 signed by a stranger: %v", err)
	}
}

func TestFakeGkmRefusesWithoutAState(t *testing.T) {
	clock := NewFakeClock(DefaultClockStart())
	gkm := NewFakeGkm(clock, NewFakeBlobs(clock, nil, nil, nil), nil)
	signer := NewFakeGkmSigner()
	client := gkm.Client(signer.SidecarId, signer.Sign)
	ctx := t.Context()
	repoId := sidecar.NewId()
	calls := map[string]func() error{
		"CreateGroup": func() error {
			_, err := client.CreateGroup(ctx, &sidecar.GkmCreateGroupArgs{RepoId: repoId})
			return err
		},
		"CurrentRepoKey": func() error { _, err := client.CurrentRepoKey(ctx, repoId); return err },
		"RepoKey":        func() error { _, err := client.RepoKey(ctx, repoId, 1); return err },
		"EnsureWritable": func() error { _, err := client.EnsureWritable(ctx, repoId); return err },
		"RotateRepo":     func() error { _, err := client.RotateRepo(ctx, repoId); return err },
		"DropKey":        func() error { _, err := client.DropKey(ctx, repoId); return err },
	}
	for name, call := range calls {
		if err := call(); !errors.Is(err, sidecar.ErrGkmUnavailable) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A removal that shrinks the holders: the next writable generation is REMOVE, at the shrink's position, and the
// removed reader keeps generation 1 and opens nothing of generation 2.
func TestFakeGkmRotatesForAShrink(t *testing.T) {
	kind := protocol.RepoKind_REPO_KIND_GENERAL
	net := newFakeGkmTestNet(t, kind, []string{"writer", "reader", "removed"}, []string{"writer"})
	ctx := t.Context()
	first := net.create("writer", kind)
	if key, err := net.clients["writer"].EnsureWritable(ctx, net.repoId); err != nil || key.Generation() != 1 {
		t.Fatalf("a covered repo rotated: %v", err)
	}
	if key, err := net.clients["removed"].CurrentRepoKey(ctx, net.repoId); err != nil || key.Generation() != 1 {
		t.Fatalf("a reader at creation: %v", err)
	}

	shrink := net.advance(kind, []string{"writer", "reader"}, []string{"writer"}, 2)
	second, err := net.clients["writer"].EnsureWritable(ctx, net.repoId)
	if err != nil {
		t.Fatal(err)
	}
	if second.Generation() != 2 || second.Cause() != sidecar.GkmCauseRemove || second.Auth().GetVersion() != shrink.Pin().GetVersion() {
		t.Fatalf("generation %d, cause %d, at %d", second.Generation(), second.Cause(), second.Auth().GetVersion())
	}
	again, err := net.clients["writer"].EnsureWritable(ctx, net.repoId)
	if err != nil || again.Generation() != 2 {
		t.Fatalf("a covered repo rotated again: %v", err)
	}

	removed := net.clients["removed"]
	held, err := removed.CurrentRepoKey(ctx, net.repoId)
	if err != nil || held.Generation() != 1 || !bytes.Equal(held.Commitment(), first.Commitment()) {
		t.Errorf("the removed reader lost what it held: %v", err)
	}
	if _, err := removed.RepoKey(ctx, net.repoId, 2); !errors.Is(err, sidecar.ErrGkmKeyMissing) {
		t.Errorf("the removed reader opened generation 2: %v", err)
	}
	if key, err := net.clients["reader"].CurrentRepoKey(ctx, net.repoId); err != nil || key.Generation() != 2 {
		t.Errorf("a remaining reader: %v", err)
	}
	if err := removed.ForgetRepo(ctx, net.repoId); err != nil {
		t.Fatal(err)
	}
	if _, err := removed.CurrentRepoKey(ctx, net.repoId); !errors.Is(err, sidecar.ErrGkmKeyMissing) {
		t.Errorf("a forgotten repo's keys: %v", err)
	}
}

// The same shrink, which the removed reader's own client has not applied: its state still names it, but a late
// delivery is a holder's to make, at a state at or past the REMOVE generation's pin, and none names it (R-KEYS-4,
// I-15). So it keeps generation 1, gets nothing newer before or after it catches up, and never holds the newest, which
// would make the writer rotate again.
func TestFakeGkmGivesAStaleRemovedReaderNothingNewer(t *testing.T) {
	kind := protocol.RepoKind_REPO_KIND_GENERAL
	net := newFakeGkmTestNet(t, kind, []string{"writer", "reader", "removed"}, []string{"writer"})
	ctx := t.Context()
	net.create("writer", kind)
	if generation, err := net.current("removed"); err != nil || generation != 1 {
		t.Fatalf("a reader at creation reads %d: %v", generation, err)
	}

	shrink := net.appendState(kind, []string{"writer", "reader"}, []string{"writer"}, 2)
	net.give(shrink, "writer", "reader", "depositor")
	for round := range 3 {
		key, err := net.clients["writer"].EnsureWritable(ctx, net.repoId)
		if err != nil {
			t.Fatal(err)
		}
		if key.Generation() != 2 || key.Cause() != sidecar.GkmCauseRemove {
			t.Errorf("round %d: the writer seals to generation %d of cause %d", round, key.Generation(), key.Cause())
		}
		if generation, err := net.current("removed"); err != nil || generation != 1 {
			t.Errorf("round %d: the removed reader, behind on the log, reads generation %d: %v", round, generation, err)
		}
		if _, err := net.clients["removed"].RepoKey(ctx, net.repoId, 2); !errors.Is(err, sidecar.ErrGkmKeyMissing) {
			t.Errorf("round %d: the removed reader, behind on the log, opened generation 2: %v", round, err)
		}
	}
	if newest := net.newest(); newest != 2 {
		t.Errorf("the removed reader's asks drove the ladder to generation %d", newest)
	}

	net.give(shrink, "removed")
	if _, err := net.clients["removed"].RepoKey(ctx, net.repoId, 2); !errors.Is(err, sidecar.ErrGkmKeyMissing) {
		t.Errorf("caught up, the removed reader opened generation 2: %v", err)
	}
	if generation, err := net.current("removed"); err != nil || generation != 1 {
		t.Errorf("caught up, the removed reader reads generation %d: %v", generation, err)
	}
}

// A holder behind the REMOVE generation's pin cannot open its own delivery of it, so it delivers it to no one, not
// even a reader its older state still names, which would otherwise get the generation that excludes it.
func TestFakeGkmStaleHolderDeliversNothingItCannotOpen(t *testing.T) {
	kind := protocol.RepoKind_REPO_KIND_GENERAL
	net := newFakeGkmTestNet(t, kind, []string{"writer", "holder", "removed"}, []string{"writer"})
	ctx := t.Context()
	net.create("writer", kind)
	shrink := net.appendState(kind, []string{"writer", "holder"}, []string{"writer"}, 2)
	net.give(shrink, "writer")
	if key, err := net.clients["writer"].EnsureWritable(ctx, net.repoId); err != nil || key.Generation() != 2 {
		t.Fatalf("the REMOVE rotation: %v", err)
	}

	// the holder's staged delivery of generation 2 is above its tip, and its state names the removed reader
	if _, err := net.clients["removed"].RepoKey(ctx, net.repoId, 2); !errors.Is(err, sidecar.ErrGkmKeyMissing) {
		t.Errorf("a holder behind gen/2's pin delivered it to the removed reader: %v", err)
	}
	if _, err := net.clients["holder"].RepoKey(ctx, net.repoId, 2); !errors.Is(err, sidecar.ErrGkmAuthAhead) {
		t.Errorf("a holder opened a delivery above its tip: %v", err)
	}
	if generation, err := net.current("holder"); err != nil || generation != 1 {
		t.Errorf("a holder behind gen/2's pin reads generation %d: %v", generation, err)
	}

	net.give(shrink, "holder")
	if generation, err := net.current("holder"); err != nil || generation != 2 {
		t.Errorf("a caught-up holder reads generation %d: %v", generation, err)
	}
	if _, err := net.clients["removed"].RepoKey(ctx, net.repoId, 2); !errors.Is(err, sidecar.ErrGkmKeyMissing) {
		t.Errorf("the caught-up holder delivered generation 2 to the removed reader: %v", err)
	}
}

// A holder whose own state no longer lets it read delivers nothing, even though that state names the recipient: the
// signer of a late delivery must be a holder at its state (§10.9's late row).
func TestFakeGkmLateDeliveryNeedsADelivererThatReads(t *testing.T) {
	kind := protocol.RepoKind_REPO_KIND_GENERAL
	net := newFakeGkmTestNet(t, kind, []string{"writer", "dropped"}, []string{"writer"}, "added")
	net.create("writer", kind)
	// dropped stops reading and added starts; the writer, still at 1, does not name added
	moved := net.appendState(kind, []string{"writer", "added"}, []string{"writer"}, 2)
	net.give(moved, "dropped", "added")
	if _, err := net.current("added"); !errors.Is(err, sidecar.ErrGkmKeyMissing) {
		t.Errorf("a holder that reads no more delivered: %v", err)
	}
	net.give(moved, "writer")
	if generation, err := net.current("added"); err != nil || generation != 1 {
		t.Errorf("the writer's late delivery gives generation %d: %v", generation, err)
	}
}

// A reader added after a generation gets it late only once a holder's state names it: its own state naming it is
// not enough.
func TestFakeGkmLateDeliveryFollowsAHoldersState(t *testing.T) {
	kind := protocol.RepoKind_REPO_KIND_GENERAL
	net := newFakeGkmTestNet(t, kind, []string{"writer"}, []string{"writer"}, "added")
	net.create("writer", kind)
	added := net.appendState(kind, []string{"writer", "added"}, []string{"writer"}, 0)
	net.give(added, "added")
	if _, err := net.current("added"); !errors.Is(err, sidecar.ErrGkmKeyMissing) {
		t.Errorf("a late delivery no holder's state allows: %v", err)
	}
	net.give(added, "writer")
	if generation, err := net.current("added"); err != nil || generation != 1 {
		t.Errorf("a late delivery the writer's state allows gives generation %d: %v", generation, err)
	}
}

// A reader asks for a late delivery only once its own state names it, so before then it holds nothing, rather than a
// delivery it must wait to judge.
func TestFakeGkmReaderAsksOnlyOnceItsStateNamesIt(t *testing.T) {
	kind := protocol.RepoKind_REPO_KIND_GENERAL
	net := newFakeGkmTestNet(t, kind, []string{"writer"}, []string{"writer"}, "added")
	net.create("writer", kind)
	added := net.appendState(kind, []string{"writer", "added"}, []string{"writer"}, 0)
	net.give(added, "writer")
	if _, err := net.current("added"); !errors.Is(err, sidecar.ErrGkmKeyMissing) {
		t.Errorf("a reader that does not know it reads: %v", err)
	}
	net.give(added, "added")
	if generation, err := net.current("added"); err != nil || generation != 1 {
		t.Errorf("once it knows, it reads generation %d: %v", generation, err)
	}
}

// A staged delivery is judged at gen/<g>'s pin, never at the reader's tip: a reader behind it keeps reading the
// generation before, and waits for the new one (§10.9's judged row). Its asking meanwhile, while the writer is
// further on, never replaces that delivery with a later one it would have to wait longer for.
func TestFakeGkmJudgesAStagedDeliveryAtItsGenerationsPin(t *testing.T) {
	kind := protocol.RepoKind_REPO_KIND_GENERAL
	net := newFakeGkmTestNet(t, kind, []string{"writer", "reader"}, []string{"writer"})
	ctx := t.Context()
	net.create("writer", kind)
	second := net.appendState(kind, []string{"writer", "reader"}, []string{"writer"}, 0)
	third := net.appendState(kind, []string{"writer", "reader"}, []string{"writer"}, 0)
	net.give(second, "writer")
	if key, err := net.clients["writer"].RotateRepo(ctx, net.repoId); err != nil || key.Generation() != 2 {
		t.Fatalf("the rotation: %v", err)
	}
	net.give(third, "writer")

	if generation, err := net.current("reader"); err != nil || generation != 1 {
		t.Errorf("a reader behind gen/2's pin reads generation %d: %v", generation, err)
	}
	if _, err := net.clients["reader"].RepoKey(ctx, net.repoId, 2); !errors.Is(err, sidecar.ErrGkmAuthAhead) {
		t.Errorf("a reader behind gen/2's pin opened it: %v", err)
	}
	net.give(second, "reader")
	if generation, err := net.current("reader"); err != nil || generation != 2 {
		t.Errorf("a reader at gen/2's pin reads generation %d: %v", generation, err)
	}
}

// A late delivery is judged at its deliverer's state: a reader behind that state waits for it, and of two holders
// that may deliver, the one at the lower position does, so a reader there need not wait for the other's.
func TestFakeGkmJudgesALateDeliveryAtItsDeliverersState(t *testing.T) {
	kind := protocol.RepoKind_REPO_KIND_GENERAL
	net := newFakeGkmTestNet(t, kind, []string{"writer", "reader"}, []string{"writer"}, "first", "second")
	net.create("writer", kind)
	readers := []string{"writer", "reader", "first", "second"}
	two := net.appendState(kind, readers, []string{"writer"}, 0)
	three := net.appendState(kind, readers, []string{"writer"}, 0)

	// only the writer, at 3, names first, which is at 2
	net.give(two, "first")
	net.give(three, "writer")
	if _, err := net.current("first"); !errors.Is(err, sidecar.ErrGkmAuthAhead) {
		t.Errorf("a late delivery above the reader's tip: %v", err)
	}
	net.give(three, "first")
	if generation, err := net.current("first"); err != nil || generation != 1 {
		t.Errorf("once at the delivery's pin, the reader reads generation %d: %v", generation, err)
	}

	// the reader at 2 and the writer at 3 both name second, which is at 2
	net.give(two, "reader", "second")
	if generation, err := net.current("second"); err != nil || generation != 1 {
		t.Errorf("with a holder at its own position, a reader reads generation %d: %v", generation, err)
	}
}

// A writer behind the newest generation's pin waits for the log, rather than judge that generation's holders by its
// older state and rotate from it at a pin below its parent's (I-16; §10.6's claim checks). One that writes but does
// not read, and so holds no delivery, waits for the log first too, since it cannot judge gen/<g> before then.
func TestFakeGkmWriterBehindTheNewestGenerationWaits(t *testing.T) {
	kind := protocol.RepoKind_REPO_KIND_GENERAL
	writers := []string{"first", "second", "appender"}
	net := newFakeGkmTestNet(t, kind, []string{"first", "second"}, writers, "added")
	ctx := t.Context()
	net.create("first", kind)
	grown := net.appendState(kind, []string{"first", "second", "added"}, writers, 0)
	net.give(grown, "first")
	if key, err := net.clients["first"].RotateRepo(ctx, net.repoId); err != nil || key.Generation() != 2 {
		t.Fatalf("the rotation: %v", err)
	}

	// second, at 1, would see added, whom its state does not name, holding generation 2
	if _, err := net.clients["second"].EnsureWritable(ctx, net.repoId); !errors.Is(err, sidecar.ErrGkmAuthAhead) {
		t.Errorf("EnsureWritable behind gen/2's pin: %v", err)
	}
	if _, err := net.clients["second"].RotateRepo(ctx, net.repoId); !errors.Is(err, sidecar.ErrGkmAuthAhead) {
		t.Errorf("RotateRepo behind gen/2's pin: %v", err)
	}
	if _, err := net.clients["appender"].EnsureWritable(ctx, net.repoId); !errors.Is(err, sidecar.ErrGkmAuthAhead) {
		t.Errorf("a writer holding no delivery, behind gen/2's pin: %v", err)
	}
	if newest := net.newest(); newest != 2 {
		t.Errorf("a writer behind the log rotated, to generation %d", newest)
	}
	net.give(grown, "second")
	if key, err := net.clients["second"].EnsureWritable(ctx, net.repoId); err != nil || key.Generation() != 2 {
		t.Errorf("a caught-up writer: %v", err)
	}
}

// A writer that generation 2 was not delivered to has nothing to seal to or rotate from: it refuses, and is never
// handed generation 1, which a removed reader holds too (§8.12).
func TestFakeGkmWriterWithoutTheNewestGenerationRefuses(t *testing.T) {
	kind := protocol.RepoKind_REPO_KIND_GENERAL
	net := newFakeGkmTestNet(t, kind, []string{"writer", "other", "removed"}, []string{"writer", "other"})
	ctx := t.Context()
	net.create("writer", kind)
	// other keeps writing but stops reading, as removed does, so generation 2 goes to the writer alone
	net.advance(kind, []string{"writer"}, []string{"writer", "other"}, 2)
	if key, err := net.clients["writer"].EnsureWritable(ctx, net.repoId); err != nil || key.Generation() != 2 {
		t.Fatalf("the REMOVE rotation: %v", err)
	}
	if key, err := net.clients["other"].EnsureWritable(ctx, net.repoId); !errors.Is(err, sidecar.ErrGkmKeyMissing) {
		t.Errorf("a writer holding only generation 1 was given a key to seal to: %v, %v", key, err)
	}
	if _, err := net.clients["other"].RotateRepo(ctx, net.repoId); !errors.Is(err, sidecar.ErrGkmKeyMissing) {
		t.Errorf("a writer not holding generation 2 rotated from it: %v", err)
	}
	if newest := net.newest(); newest != 2 {
		t.Errorf("the ladder reached generation %d", newest)
	}
}

// A writer added back after a REMOVE generation waits for that generation's late delivery, and is not handed the
// generation before it meanwhile.
func TestFakeGkmReaddedWriterWaitsForTheNewestGeneration(t *testing.T) {
	kind := protocol.RepoKind_REPO_KIND_GENERAL
	net := newFakeGkmTestNet(t, kind, []string{"writer", "other", "removed"}, []string{"writer", "other"})
	ctx := t.Context()
	net.create("writer", kind)
	net.advance(kind, []string{"writer"}, []string{"writer"}, 2)
	if key, err := net.clients["writer"].EnsureWritable(ctx, net.repoId); err != nil || key.Generation() != 2 {
		t.Fatalf("the REMOVE rotation: %v", err)
	}
	// other is back, which the writer, generation 2's one holder, has not applied
	back := net.appendState(kind, []string{"writer", "other"}, []string{"writer", "other"}, 2)
	net.give(back, "other")
	if key, err := net.clients["other"].EnsureWritable(ctx, net.repoId); !errors.Is(err, sidecar.ErrGkmKeyMissing) {
		t.Errorf("a writer with no delivery of generation 2 was given a key to seal to: %v, %v", key, err)
	}
	net.give(back, "writer")
	if key, err := net.clients["other"].EnsureWritable(ctx, net.repoId); err != nil || key.Generation() != 2 {
		t.Errorf("once the writer's state names it: %v", err)
	}
}

// What a client no longer retains it does not judge (§10.9's judged row): a delivery and a newest generation pinned
// before its retention point still serve.
func TestFakeGkmJudgesNoPinBeforeRetention(t *testing.T) {
	kind := protocol.RepoKind_REPO_KIND_GENERAL
	net := newFakeGkmTestNet(t, kind, []string{"writer", "reader"}, []string{"writer"})
	ctx := t.Context()
	net.create("writer", kind)
	net.advance(kind, []string{"writer", "reader"}, []string{"writer"}, 0)
	net.advance(kind, []string{"writer", "reader"}, []string{"writer"}, 0)
	net.log.Retain(3)
	if generation, err := net.current("reader"); err != nil || generation != 1 {
		t.Errorf("a delivery pinned before retention: %d, %v", generation, err)
	}
	if key, err := net.clients["writer"].EnsureWritable(ctx, net.repoId); err != nil || key.Generation() != 1 {
		t.Errorf("a newest generation pinned before retention: %v", err)
	}
}

// §8.12's invariant, which no holders_shrunk_at needs to trigger: a generation a non-reader holds is never written
// to, and the one that replaces it is REMOVE.
func TestFakeGkmNeverSealsToANonReadersGeneration(t *testing.T) {
	kind := protocol.RepoKind_REPO_KIND_GENERAL
	net := newFakeGkmTestNet(t, kind, []string{"writer", "removed"}, []string{"writer"})
	ctx := t.Context()
	net.create("writer", kind)
	net.advance(kind, []string{"writer"}, []string{"writer"}, 0)
	key, err := net.clients["writer"].EnsureWritable(ctx, net.repoId)
	if err != nil {
		t.Fatal(err)
	}
	if key.Generation() != 2 || key.Cause() != sidecar.GkmCauseRemove {
		t.Errorf("generation %d of cause %d", key.Generation(), key.Cause())
	}
}

func TestFakeGkmRotatesOnSchedule(t *testing.T) {
	kind := protocol.RepoKind_REPO_KIND_GENERAL
	net := newFakeGkmTestNet(t, kind, []string{"writer"}, []string{"writer"})
	ctx := t.Context()
	net.create("writer", kind)
	net.clock.Advance(30*24*time.Hour - time.Millisecond)
	if key, err := net.clients["writer"].EnsureWritable(ctx, net.repoId); err != nil || key.Generation() != 1 {
		t.Fatalf("rotated before 30 days: %v", err)
	}
	net.clock.Advance(time.Millisecond)
	key, err := net.clients["writer"].EnsureWritable(ctx, net.repoId)
	if err != nil {
		t.Fatal(err)
	}
	if key.Generation() != 2 || key.Cause() != sidecar.GkmCauseSchedule {
		t.Errorf("generation %d of cause %d", key.Generation(), key.Cause())
	}
}

func TestFakeGkmRefusesANonWriter(t *testing.T) {
	kind := protocol.RepoKind_REPO_KIND_GENERAL
	net := newFakeGkmTestNet(t, kind, []string{"writer", "reader"}, []string{"writer"})
	ctx := t.Context()
	net.create("writer", kind)
	if _, err := net.clients["reader"].EnsureWritable(ctx, net.repoId); !errors.Is(err, sidecar.ErrGkmNotWriter) {
		t.Errorf("EnsureWritable: %v", err)
	}
	if _, err := net.clients["reader"].RotateRepo(ctx, net.repoId); !errors.Is(err, sidecar.ErrGkmNotWriter) {
		t.Errorf("RotateRepo: %v", err)
	}
	if _, err := net.clients["writer"].CreateGroup(ctx, &sidecar.GkmCreateGroupArgs{RepoId: net.repoId, Kind: kind}); !errors.Is(err, errFakeGkmRefused) {
		t.Errorf("a second group for the repo: %v", err)
	}
}

// §10.5's depositor rule on the fake: the newest generation's drop key, never one that misses a shrink or has
// lapsed, and none for a kind that takes no deposits.
func TestFakeGkmDropKeyKeepsTheDepositorRule(t *testing.T) {
	kind := protocol.RepoKind_REPO_KIND_VAULT
	net := newFakeGkmTestNet(t, kind, []string{"writer", "reader"}, []string{"writer"})
	ctx := t.Context()
	first := net.create("writer", kind)
	depositor := net.clients["depositor"]
	dropKey, err := depositor.DropKey(ctx, net.repoId)
	if err != nil {
		t.Fatal(err)
	}
	dropPrivateKey, err := first.DropKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if dropKey.Generation != 1 || !bytes.Equal(dropKey.PublicKey, dropPrivateKey.PublicKey().Bytes()) ||
		!bytes.Equal(dropKey.Commitment, first.Commitment()) || dropKey.GroupId != first.GroupId() {
		t.Errorf("drop key %+v", dropKey)
	}
	if !dropKey.NotAfter.Equal(net.clock.Now().Add(90 * 24 * time.Hour).Truncate(time.Millisecond)) {
		t.Errorf("drop key lapses at %s", dropKey.NotAfter)
	}

	net.advance(kind, []string{"writer"}, []string{"writer"}, 2)
	if _, err := depositor.DropKey(ctx, net.repoId); !errors.Is(err, sidecar.ErrGkmWait) {
		t.Errorf("a drop key missing a shrink: %v", err)
	}
	if _, err := net.clients["writer"].EnsureWritable(ctx, net.repoId); err != nil {
		t.Fatal(err)
	}
	covering, err := depositor.DropKey(ctx, net.repoId)
	if err != nil {
		t.Fatal(err)
	}
	if covering.Generation != 2 || bytes.Equal(covering.PublicKey, dropKey.PublicKey) {
		t.Errorf("the covering drop key %+v", covering)
	}
	net.clock.Advance(90 * 24 * time.Hour)
	if _, err := depositor.DropKey(ctx, net.repoId); !errors.Is(err, sidecar.ErrGkmWait) {
		t.Errorf("a lapsed drop key: %v", err)
	}

	general := newFakeGkmTestNet(t, protocol.RepoKind_REPO_KIND_GENERAL, []string{"writer"}, []string{"writer"})
	general.create("writer", protocol.RepoKind_REPO_KIND_GENERAL)
	if _, err := general.clients["depositor"].DropKey(ctx, general.repoId); !errors.Is(err, sidecar.ErrGkmKeyMissing) {
		t.Errorf("a kind that takes no deposits: %v", err)
	}
}

// A state below one a client holds changes nothing (I-16).
func TestFakeGkmTakesNoLowerState(t *testing.T) {
	kind := protocol.RepoKind_REPO_KIND_GENERAL
	net := newFakeGkmTestNet(t, kind, []string{"writer"}, []string{"writer"})
	ctx := t.Context()
	older := net.log.Tip()
	net.advance(kind, []string{"writer"}, []string{"writer"}, 0)
	net.clients["writer"].AuthAdvanced(older)
	key := net.create("writer", kind)
	if key.Auth().GetVersion() != 2 {
		t.Errorf("created at %d, below the newest state", key.Auth().GetVersion())
	}
	if _, err := net.clients["writer"].EnsureWritable(ctx, net.repoId); err != nil {
		t.Fatal(err)
	}
}
