// FakeGkm round-trips real ladder objects through fake Blobs (KEYS-M2-04's test): its clients read every key back
// through Signed gen/<g> objects, a rewritten object refuses, a removed reader keeps what it held and opens nothing
// newer, and the depositor rule holds as far as the fake sees.

package sidecartest

import (
	"bytes"
	"errors"
	"io"
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

// A network whose repo of kind is read by readers and written by writers, named by label.
func newFakeGkmTestNet(t *testing.T, kind protocol.RepoKind, readers []string, writers []string) *fakeGkmTestNet {
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
	for _, label := range append(append(append([]string{}, readers...), writers...), "depositor") {
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
	view := self.log.Append(fixture)
	for _, client := range self.clients {
		client.AuthAdvanced(view)
	}
	return view
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
