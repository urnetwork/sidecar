// Full mirrors end to end (EVSB-M2-19; §11.13's contents, status and erasure rows): a reader's sidecar.EvsMirror syncs
// a record-class repo through evsservice's engine on the epoch world (evs_epoch_world_test.go) and holds every
// statement, record, segment and slot a committed push names; coverage on the world's fake clock reads full only
// with every ref at most an hour behind its head, nothing missing and a hash check under 7 days old; an ERASE taken
// from the erasure ref removes the slot copy before the next sync reads anything else, and the slot evs emptied
// counts as erased; a slot evs no longer serves leaves the mirror partial, naming it.

package sidecartest

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A record repo with a small and a large entry, each of whose chains keeps its key in a slot of its own, and the small
// entry's slot: slot ids are random, so the cluster's sorted keys do not say which is whose.
func newMirrorWorld(t *testing.T) (*epochWorld, *epochDevice, sidecar.Id) {
	t.Helper()
	world := newEpochWorldOf(t, protocol.RepoKind_REPO_KIND_RECORD)
	writer := world.device("w", nil)
	if _, err := writer.write("ledger/a", bytes.Repeat([]byte("an entry of the ledger; "), 300)); err != nil {
		t.Fatalf("the small entry: %v", err)
	}
	smallSlots := epochNewSlots(nil, world.slotKeys())
	if len(smallSlots) != 1 {
		t.Fatalf("%d slots after the small entry", len(smallSlots))
	}
	if _, err := writer.write("ledger/b", bytes.Repeat([]byte("a larger entry; "), 20000)); err != nil {
		t.Fatalf("the large entry: %v", err)
	}
	return world, writer, smallSlots[0]
}

func newWorldMirror(t *testing.T, world *epochWorld, device *epochDevice) *sidecar.EvsMirror {
	t.Helper()
	mirror, err := sidecar.NewEvsMirror(device.client, world.repoId, nil)
	if err != nil {
		t.Fatal(err)
	}
	return mirror
}

// The keys a mirror's family holds.
func mirrorKeys(t *testing.T, mirror *sidecar.EvsMirror, family sidecar.EvsMirrorFamily) []sidecar.EvsMirrorKey {
	t.Helper()
	keys, err := mirror.Store().List(family, nil)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func TestEvsMirrorHoldsEveryObjectAPushNames(t *testing.T) {
	world, _, _ := newMirrorWorld(t)
	reader := world.device("r", nil)
	mirror := newWorldMirror(t, world, reader)
	result, err := mirror.Sync(world.ctx)
	if err != nil {
		t.Fatal(err)
	}
	refId := world.mainRefId(reader)
	head := world.head(refId)
	ref, ok, err := mirror.Store().Ref(refId)
	if err != nil || !ok || ref.Version != head.GetVersion() {
		t.Fatalf("the mirrored ref %+v %v, the head at %d", ref, err, head.GetVersion())
	}
	if result.VersionCount != int(head.GetVersion()) || result.MissingCount != 0 {
		t.Fatalf("the sync: %+v", result)
	}
	statements, err := mirror.Store().List(sidecar.EvsMirrorStatements, &refId)
	if err != nil || len(statements) != int(head.GetVersion()) {
		t.Fatalf("%d statements held, %v", len(statements), err)
	}
	if records := mirrorKeys(t, mirror, sidecar.EvsMirrorRecords); len(records) != int(head.GetVersion()) {
		t.Errorf("%d records held for %d one-part pushes", len(records), head.GetVersion())
	}
	// every slot the cluster holds, as its wrapped bytes
	slotKeys := world.slotKeys()
	heldSlots := mirrorKeys(t, mirror, sidecar.EvsMirrorSlots)
	if len(slotKeys) != 2 || len(heldSlots) != len(slotKeys) {
		t.Fatalf("%d slots held of the cluster's %d", len(heldSlots), len(slotKeys))
	}
	for _, key := range heldSlots {
		object, err := world.cluster.Get(world.ctx, evsservice.SlotKey(world.repoId, sidecar.Id(key.ObjectId)))
		if err != nil {
			t.Fatal(err)
		}
		stored, _ := readAllAndClose(object)
		reader, err := mirror.Store().Open(key)
		if err != nil {
			t.Fatal(err)
		}
		held := make([]byte, len(stored)+1)
		count, _ := reader.Read(held)
		reader.Close()
		if !bytes.Equal(held[:count], stored) {
			t.Errorf("slot %x held as other bytes", key.ObjectId)
		}
	}
	if segments := mirrorKeys(t, mirror, sidecar.EvsMirrorSegments); len(segments) == 0 {
		t.Error("no segment held for the large entry")
	}
	// a second sync takes nothing more
	again, err := mirror.Sync(world.ctx)
	if err != nil || again.VersionCount != 0 || again.ObjectCount != 0 {
		t.Errorf("a second sync: %+v %v", again, err)
	}
	// with no hash check yet the mirror is partial, saying so, and full once one runs
	coverage, err := mirror.Coverage(world.ctx)
	if err != nil || coverage.Full || !strings.Contains(strings.Join(coverage.Reasons, ";"), "no hash check") {
		t.Fatalf("before a check: %+v %v", coverage, err)
	}
	check, err := mirror.Check(world.ctx)
	if err != nil || 0 < len(check.Failures) || check.ObjectCount == 0 {
		t.Fatalf("the check: %+v %v", check, err)
	}
	if coverage, err := mirror.Coverage(world.ctx); err != nil || !coverage.Full {
		t.Fatalf("after a check: %+v %v", coverage, err)
	}
}

// §11.13's status row on the fake clock: a ref an hour behind, and a check a week old, read partial.
func TestEvsMirrorCoverageStatesOnAFakeClock(t *testing.T) {
	world, writer, _ := newMirrorWorld(t)
	reader := world.device("r", nil)
	mirror := newWorldMirror(t, world, reader)
	if _, err := mirror.Sync(world.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := mirror.Check(world.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.write("ledger/c", []byte("a later entry")); err != nil {
		t.Fatal(err)
	}
	// behind by a version under an hour old: still full
	world.clock.Advance(59 * time.Minute)
	coverage, err := mirror.Coverage(world.ctx)
	if err != nil || !coverage.Full {
		t.Fatalf("59 min behind: %+v %v", coverage, err)
	}
	world.clock.Advance(2 * time.Minute)
	coverage, err = mirror.Coverage(world.ctx)
	if err != nil || coverage.Full || len(coverage.Refs) != 1 || coverage.Refs[0].Mirrored || coverage.Refs[0].FirstMissingAt.IsZero() {
		t.Fatalf("61 min behind: %+v %v", coverage, err)
	}
	if reasons := strings.Join(coverage.Reasons, ";"); !strings.Contains(reasons, "1 versions behind") {
		t.Errorf("the reasons: %s", reasons)
	}
	if _, err := mirror.Sync(world.ctx); err != nil {
		t.Fatal(err)
	}
	if coverage, err := mirror.Coverage(world.ctx); err != nil || !coverage.Full {
		t.Fatalf("synced again: %+v %v", coverage, err)
	}
	// a week without a check
	world.clock.Advance(7*24*time.Hour + time.Minute)
	if _, err := mirror.Sync(world.ctx); err != nil {
		t.Fatal(err)
	}
	coverage, err = mirror.Coverage(world.ctx)
	if err != nil || coverage.Full || !strings.Contains(strings.Join(coverage.Reasons, ";"), "no hash check since") {
		t.Fatalf("a week after the check: %+v %v", coverage, err)
	}
	if _, err := mirror.Check(world.ctx); err != nil {
		t.Fatal(err)
	}
	if coverage, err := mirror.Coverage(world.ctx); err != nil || !coverage.Full {
		t.Fatalf("checked again: %+v %v", coverage, err)
	}
}

// §11.13's erasure row: an ERASE the next sync takes, from the erasure ref before any other ref, removes the slot copy
// it covers; evs emptied that slot, so it counts as erased and the mirror stays full.
func TestEvsMirrorAppliesAnErasureBeforeTheNextSync(t *testing.T) {
	world, writer, smallSlot := newMirrorWorld(t)
	mirrorWorldAdmin(world, "w")
	reader := world.device("r", nil)
	mirror := newWorldMirror(t, world, reader)
	if _, err := mirror.Sync(world.ctx); err != nil {
		t.Fatal(err)
	}
	oldSlot := smallSlot
	if held, err := mirror.Store().Has(sidecar.EvsMirrorSlotKey(oldSlot.Bytes())); err != nil || !held {
		t.Fatalf("the slot before its erasure: %v %v", held, err)
	}
	erased := []*sidecar.EvsErasedKey{{SlotId: oldSlot, KeyIndex: 0}}
	erasureId := sidecar.NewId()
	if _, err := writer.repo.Closure(world.ctx, &sidecar.EvsClosureArgs{
		ErasureId: erasureId, Writes: []*sidecar.EvsPathWrite{{Path: "ledger/a", Content: bytes.NewReader([]byte("the ledger with the entry gone"))}}, Erased: erased,
	}); err != nil {
		t.Fatalf("the CLOSURE: %v", err)
	}
	if _, err := writer.repo.Erase(world.ctx, &sidecar.EvsEraseArgs{ErasureId: erasureId, Keys: erased, Complete: true}); err != nil {
		t.Fatalf("the ERASE: %v", err)
	}
	result, err := mirror.Sync(world.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.ErasureCount != 1 || result.RemovedSlotCount != 1 {
		t.Fatalf("the sync after the ERASE: %+v", result)
	}
	if held, err := mirror.Store().Has(sidecar.EvsMirrorSlotKey(oldSlot.Bytes())); err != nil || held {
		t.Fatalf("the erased slot's copy: %v %v", held, err)
	}
	// the erasure ref is mirrored like any other, so the ERASE's signer's device keeps it
	erasureRefId := sidecar.EvsErasureRefId(world.repoId)
	if ref, ok, err := mirror.Store().Ref(erasureRefId); err != nil || !ok || ref.Version == 0 {
		t.Fatalf("the erasure ref: %+v %v %v", ref, ok, err)
	}
	if _, err := mirror.Check(world.ctx); err != nil {
		t.Fatal(err)
	}
	coverage, err := mirror.Coverage(world.ctx)
	if err != nil || !coverage.Full || coverage.MissingCount != 0 || coverage.StaleSlotCount != 0 {
		t.Fatalf("after the ERASE: %+v %v", coverage, err)
	}
	// and a mirror first synced after the ERASE never holds the erased slot
	fresh := newWorldMirror(t, world, world.device("m", nil))
	if _, err := fresh.Sync(world.ctx); err != nil {
		t.Fatal(err)
	}
	if held, err := fresh.Store().Has(sidecar.EvsMirrorSlotKey(oldSlot.Bytes())); err != nil || held {
		t.Errorf("a fresh mirror holds the erased slot: %v %v", held, err)
	}
	if coverage, err := fresh.Coverage(world.ctx); err != nil || coverage.MissingCount != 0 {
		t.Errorf("a fresh mirror's coverage: %+v %v", coverage, err)
	}
}

// A slot evs no longer serves, with no ERASE behind it, leaves the mirror partial and the ref below the push naming
// it; once it is back, the next sync holds it and the ref reaches its head.
func TestEvsMirrorReportsAMissingSlotPartial(t *testing.T) {
	world, _, _ := newMirrorWorld(t)
	keys := world.slotKeys()
	lost := keys[len(keys)-1]
	object, err := world.cluster.Get(world.ctx, lost)
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := readAllAndClose(object)
	if err := world.cluster.Delete(world.ctx, lost); err != nil {
		t.Fatal(err)
	}
	reader := world.device("r", nil)
	mirror := newWorldMirror(t, world, reader)
	result, err := mirror.Sync(world.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.MissingCount != 1 {
		t.Fatalf("the sync: %+v", result)
	}
	if _, err := mirror.Check(world.ctx); err != nil {
		t.Fatal(err)
	}
	coverage, err := mirror.Coverage(world.ctx)
	if err != nil || coverage.Full || coverage.MissingCount != 1 || coverage.Missing[0].Family != sidecar.EvsMirrorSlots {
		t.Fatalf("with a slot missing: %+v %v", coverage, err)
	}
	if reasons := strings.Join(coverage.Reasons, ";"); !strings.Contains(reasons, "1 slot") {
		t.Errorf("the reasons: %s", reasons)
	}
	refId := world.mainRefId(reader)
	head := world.head(refId)
	if ref, _, _ := mirror.Store().Ref(refId); ref != nil && head.GetVersion() <= ref.Version {
		t.Fatalf("the ref raised past a missing slot: %+v of %d", ref, head.GetVersion())
	}
	if _, err := world.cluster.PutIfNoneMatch(world.ctx, lost, stored, nil); err != nil {
		t.Fatal(err)
	}
	if result, err := mirror.Sync(world.ctx); err != nil || result.MissingCount != 0 {
		t.Fatalf("the sync once the slot is back: %+v %v", result, err)
	}
	if ref, _, _ := mirror.Store().Ref(refId); ref == nil || ref.Version != head.GetVersion() {
		t.Fatalf("the ref after the slot came back: %+v", ref)
	}
	if coverage, err := mirror.Coverage(world.ctx); err != nil || !coverage.Full {
		t.Fatalf("with the slot back: %+v %v", coverage, err)
	}
}

// A mirrored segment whose bytes rotted on disk fails the next hash check and reads partial.
func TestEvsMirrorCheckFindsARottedSegment(t *testing.T) {
	world, _, _ := newMirrorWorld(t)
	reader := world.device("r", nil)
	mirror := newWorldMirror(t, world, reader)
	if _, err := mirror.Sync(world.ctx); err != nil {
		t.Fatal(err)
	}
	segments := mirrorKeys(t, mirror, sidecar.EvsMirrorSegments)
	if len(segments) == 0 {
		t.Fatal("no segment held")
	}
	name, _ := segments[0].Name()
	// another file under the segment's name, as a disk would leave it: the store's seal is the file's own
	repoStore, err := reader.store.Directory("mirror/"+sidecar.EvsKeyId(world.repoId), "")
	if err != nil {
		t.Fatal(err)
	}
	writer, err := repoStore.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	writer.Write([]byte("bytes that are not the segment"))
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	check, err := mirror.Check(world.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(check.Failures) != 1 || !strings.Contains(check.Failures[0], "not its id") {
		t.Fatalf("the check: %+v", check)
	}
	coverage, err := mirror.Coverage(world.ctx)
	if err != nil || coverage.Full || len(coverage.CheckFailures) != 1 {
		t.Fatalf("after a failed check: %+v %v", coverage, err)
	}
}

// The world's view advanced with label among the repo's admins, as its access log's RepoAdmins would hold it, so
// readers take its ERASEs (§11.8's refs table: the erasure ref takes a repo admin's pushes alone).
func mirrorWorldAdmin(world *epochWorld, label string) {
	fixture := &FakeGkmAuthFixture{
		Rows: FakeGkmAuthRows(&protocol.AclRepo{
			RepoId: world.repoId.Bytes(), Kind: world.kind,
			Admins: []*protocol.AclRepoAdminRow{{SidecarId: world.signers[label].SidecarId.Bytes()}},
		}),
		IdentityKeys:       map[sidecar.Id][]byte{},
		RepoReaders:        map[sidecar.Id][]sidecar.Id{},
		RepoWriters:        map[sidecar.Id][]sidecar.Id{},
		RepoReaderExpiries: map[sidecar.Id]map[sidecar.Id]time.Time{},
	}
	sidecarIds := []sidecar.Id{}
	for _, each := range epochWorldLabels {
		signer := world.signers[each]
		fixture.IdentityKeys[signer.SidecarId] = signer.PublicKey()
		sidecarIds = append(sidecarIds, signer.SidecarId)
		fixture.RepoReaders[world.repoId] = append(fixture.RepoReaders[world.repoId], signer.SidecarId)
	}
	sidecarRows, memberRow := FakeGkmAuthMemberDevices(world.memberId, sidecarIds...)
	fixture.Rows.Sidecars = sidecarRows
	fixture.Rows.Members = []*bridge.MemberRow{memberRow}
	for _, each := range []string{"w", "v", "m"} {
		fixture.RepoWriters[world.repoId] = append(fixture.RepoWriters[world.repoId], world.signers[each].SidecarId)
	}
	view := world.log.Append(fixture)
	world.stateLock.Lock()
	world.view = view
	devices := slices.Clone(world.devices)
	world.stateLock.Unlock()
	world.gate.stateLock.Lock()
	world.gate.view = view
	world.gate.stateLock.Unlock()
	for _, device := range devices {
		device.gkm.AuthAdvanced(view)
	}
}

func readAllAndClose(object *sidecar.BlobObject) ([]byte, error) {
	defer object.Body.Close()
	buffer := &bytes.Buffer{}
	_, err := buffer.ReadFrom(object.Body)
	return buffer.Bytes(), err
}

// A gkm client that gives no key for one generation while refusing is set.
type mirrorRefusingGkm struct {
	sidecar.GkmClient
	generation uint64
	refusing   *bool
}

func (self *mirrorRefusingGkm) RepoKey(ctx context.Context, repoId sidecar.Id, generation uint64) (*sidecar.EvsRepoKey, error) {
	if *self.refusing && generation == self.generation {
		return nil, errors.New("no key for this generation")
	}
	return self.GkmClient.RepoKey(ctx, repoId, generation)
}

// The RK ladder is §11.13's: a generation gkm gives no key for leaves the mirror partial, at the sync that found it
// and at every later one until gkm gives it, though no new version names it again.
func TestEvsMirrorNamesAMissingKeyUntilGkmGivesIt(t *testing.T) {
	world, _, _ := newMirrorWorld(t)
	reader := world.device("r", nil)
	refusing := true
	gkm := &mirrorRefusingGkm{GkmClient: reader.gkm, generation: 1, refusing: &refusing}
	identity := &sidecar.SidecarIdentity{
		NetworkId: world.networkId, SidecarId: reader.signer.SidecarId, ClientId: world.clientId, Generation: 1, IdentityPublicKey: reader.signer.PublicKey(),
	}
	client, err := sidecar.NewEvsClient(&sidecar.EvsClientArgs{
		NetworkId: world.networkId,
		EvsUrl:    "https://evs.example",
		Transport: &epochTransport{world: world, device: reader},
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			connectSidecarId := connect.Id(reader.signer.SidecarId)
			return world.host.Authenticator.Issue(&sidecar.Principal{
				NetworkId: connect.Id(world.networkId), ClientId: connect.Id(world.clientId), SidecarId: &connectSidecarId,
				Audience: evsservice.EvsAudience, Scopes: scopes, IssuedAt: world.clock.Now(), ExpiresAt: world.clock.Now().Add(15 * time.Minute),
			}), nil
		},
		Sign:     sidecar.EvsSignFunction(reader.signer.Sign),
		Identity: func() *sidecar.SidecarIdentity { return identity },
		Gkm:      gkm,
		Store:    NewFakeStore().Root(),
		Config:   func() sidecar.GkmAuthView { return world.currentView() },
		Clock:    &epochDeviceClock{clock: world.clock},
		Log:      sidecar.NewNoopLogger(),
		Settings: sidecar.DefaultEvsSettings(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	mirror, err := sidecar.NewEvsMirror(client, world.repoId, nil)
	if err != nil {
		t.Fatal(err)
	}
	for sync := range 2 {
		if _, err := mirror.Sync(world.ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := mirror.Check(world.ctx); err != nil {
			t.Fatal(err)
		}
		coverage, err := mirror.Coverage(world.ctx)
		if err != nil || coverage.Full || len(coverage.KeyGenerationsMissing) != 1 {
			t.Fatalf("sync %d with generation 1's key withheld: %+v %v", sync, coverage, err)
		}
	}
	refusing = false
	if _, err := mirror.Sync(world.ctx); err != nil {
		t.Fatal(err)
	}
	if coverage, err := mirror.Coverage(world.ctx); err != nil || !coverage.Full {
		t.Fatalf("once gkm gives the key: %+v %v", coverage, err)
	}
}
