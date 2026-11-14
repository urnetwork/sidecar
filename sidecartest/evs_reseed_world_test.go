// A re-seed end to end (EVSB-M2-20; §11.13's re-seed row, §19.10's repos step; FS-41's storage clauses on T2): the
// epoch world's site is lost, every cluster with it, and a repo admin's sidecar.EvsRepo.Reseed sends its mirror back
// through evsservice's POST .../reseed on a new, empty site running with reseed on. The history returns as the
// devices signed it, under the same chain; a fresh reader reads it; a device whose pin lies above the returned head
// takes it only under the admin's EvsReseed, which its own read takes from the frame evs serves after the head, and
// then finds the unmirrored entry gone; and a stale mirror's slot copy returns without the key an ERASE the site holds
// covers.

package sidecartest

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
)

// A site loss: a new host with empty clusters and an empty Redis takes the world's place, evs on it with reseed on,
// and the repo placed afresh and active, as §19.10 has it before its history returns. The devices, their stores and
// the authorization log stand.
func (self *epochWorld) loseSite() {
	t := self.t
	t.Helper()
	hostSettings := DefaultFakeHostSettings()
	hostSettings.Blobs.MetadataClusterIds = []string{"meta-1"}
	hostSettings.Blobs.Report = func(violation string) { t.Errorf("blobs: %s", violation) }
	host := NewFakeHost(self.ctx, self.clock, nil, nil, hostSettings)
	RegisterEvsTwins(host.Redis)
	network := connect.Id(self.networkId).String()
	if err := host.Gates.Set(fmt.Sprintf("sidecar:\n  evs: {enabled: true, networks: [%q]}\n  reseed: true\n", network)); err != nil {
		t.Fatal(err)
	}
	host.Quota.SetBalance(connect.Id(self.networkId), 1<<40)
	cluster, err := host.Blobs.Cluster("meta-1")
	if err != nil {
		t.Fatal(err)
	}
	usage, err := evsservice.NewUsageBatcher(self.ctx, host.ServiceHost(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(usage.Close)
	quota, err := evsservice.NewQuotaGate(self.ctx, host.ServiceHost(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(quota.Close)
	receiptKey := sha256.Sum256([]byte("epoch world receipt key after the loss"))
	receiptKeys, err := evsservice.NewReceiptKeys([]*evsservice.ReceiptKey{{KeyId: 2, Key: receiptKey[:], IssueFrom: self.clock.Now().Add(-48 * time.Hour)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	settings := evsservice.DefaultEvsSettings()
	settings.BatchFlushDelay = 0
	settings.PushUnknownRereadInterval = 0
	settings.RepoCacheTtl = 0
	engine, err := evsservice.NewEvsEngine(self.ctx, host.ServiceHost(), settings, &evsservice.EvsEngineDeps{
		AuthState: &depositAuthState{networkId: self.networkId, kind: self.kind},
		Uploads:   &evsservice.EvsUploadDeps{Keys: receiptKeys, Quota: quota, Usage: usage},
		GateViews: self.gate,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	placeBytes, err := (&sidecar.EvsRepoPlace{ClusterId: "meta-1", CreatorSidecarId: self.signers["w"].SidecarId}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.PutIfNoneMatch(self.ctx, sidecar.EvsPlaceKey(self.repoId), placeBytes, nil); err != nil {
		t.Fatal(err)
	}
	repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
		RepoId: self.repoId.Bytes(), Kind: self.kind, State: protocol.EvsRepoState_EVS_REPO_ACTIVE,
		Format: sidecar.EvsRepoFormat1, NetworkId: self.networkId.Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.PutIfNoneMatch(self.ctx, evsservice.RepoKey(self.repoId), repoBytes, nil); err != nil {
		t.Fatal(err)
	}
	// §19.10 returns the groups before any repo: gkm's objects, which this world's fake gkm keeps on the lost site
	for startAfter := ""; ; {
		objects, more, err := self.cluster.List(self.ctx, "gkm/", startAfter, 1000)
		if err != nil {
			t.Fatal(err)
		}
		for _, info := range objects {
			object, err := self.cluster.Get(self.ctx, info.Key)
			if err != nil {
				t.Fatal(err)
			}
			body, err := readAllAndClose(object)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cluster.PutIfNoneMatch(self.ctx, info.Key, body, nil); err != nil {
				t.Fatal(err)
			}
			startAfter = info.Key
		}
		if !more {
			break
		}
	}
	self.host, self.cluster, self.engine = host, cluster, engine
}

// A slot's bytes as the world's cluster holds them, nil for one it does not hold.
func (self *epochWorld) slotBytes(slotId sidecar.Id) []byte {
	self.t.Helper()
	object, err := self.cluster.Get(self.ctx, evsservice.SlotKey(self.repoId, slotId))
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil
	}
	if err != nil {
		self.t.Fatal(err)
	}
	stored, err := readAllAndClose(object)
	if err != nil {
		self.t.Fatal(err)
	}
	return stored
}

// A re-seed from device's mirror, and then the step 8s of the commits it made, waited out. The world's transport
// waits them out after a push; a re-seeded push is committed by the reseed route, whose reply, like a push's, comes
// before its step 8 (the push sequence and hints, then the head cache). While a commit's step 8 has not cached its
// head, a read that is not fresh, from a device pinned no higher than the head an earlier commit cached, is served
// that earlier head (§11.9's cache row): it verifies, and what the later commit wrote reads as absent. A device that
// needs the newest reads fresh or past a hint; these tests read what the re-seed returned, so they wait.
func (self *epochWorld) reseed(device *epochDevice, args *sidecar.EvsReseedArgs) (*sidecar.EvsReseedResult, error) {
	result, err := device.repo.Reseed(self.ctx, args)
	for {
		started, finished, changed := self.engine.StepEights()
		if started == finished {
			break
		}
		<-changed
	}
	return result, err
}

// A ref of a re-seed's result.
func reseedRefOf(t *testing.T, result *sidecar.EvsReseedResult, refId sidecar.Id) *sidecar.EvsReseedRef {
	t.Helper()
	for _, ref := range result.Refs {
		if ref.RefId == refId {
			return ref
		}
	}
	t.Fatalf("the re-seed names no ref %s", refId)
	return nil
}

// The mirror's history returns under its own chain, with its segments and slots, and a fresh reader reads it; the
// entry written after the mirror's last sync is lost, which the writer's device, pinned above the returned head,
// accepts only under the admin's EvsReseed; and a second re-seed changes nothing.
func TestEvsReseedReturnsAMirroredRepoEndToEnd(t *testing.T) {
	world, writer, _ := newMirrorWorld(t)
	mirrorWorldAdmin(world, "w")
	small := bytes.Repeat([]byte("an entry of the ledger; "), 300)
	large := bytes.Repeat([]byte("a larger entry; "), 20000)
	mirror := newWorldMirror(t, world, writer)
	if _, err := mirror.Sync(world.ctx); err != nil {
		t.Fatal(err)
	}
	refId := world.mainRefId(writer)
	mirrored := world.head(refId)
	// the writer reads an entry at the mirrored head, so its read record of the path is pinned there: after the loss
	// its read of that path asks from the record's pin, at which evs serves no statement, and then from the ref's
	if content, _, err := writer.read("ledger/a"); err != nil || !bytes.Equal(content, small) {
		t.Fatalf("the writer's read before the loss: %d bytes, %v", len(content), err)
	}
	slotIds := epochNewSlots(nil, world.slotKeys())
	slots := map[sidecar.Id][]byte{}
	for _, slotId := range slotIds {
		slots[slotId] = world.slotBytes(slotId)
	}
	// written after the mirror's last sync: no copy survives the site
	if _, err := writer.write("ledger/c", []byte("an entry no mirror holds")); err != nil {
		t.Fatal(err)
	}
	if lost := world.head(refId); lost.GetVersion() != mirrored.GetVersion()+1 {
		t.Fatalf("the head at %d before the loss, the mirror at %d", lost.GetVersion(), mirrored.GetVersion())
	}
	// and read, so the writer's device is pinned at it
	if _, _, err := writer.read("ledger/c"); err != nil {
		t.Fatal(err)
	}
	if pin, pinned, err := writer.client.Pins().Pin(world.repoId, refId); err != nil || !pinned || pin.Version != mirrored.GetVersion()+1 {
		t.Fatalf("the writer's pin before the loss: %+v %v %v", pin, pinned, err)
	}

	world.loseSite()
	// the history first, with no EvsReseed over it
	result, err := world.reseed(writer, &sidecar.EvsReseedArgs{IncidentId: []byte("incident 41")})
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range result.Refs {
		if ref.Stopped != nil || ref.FileError != nil {
			t.Fatalf("ref %s stopped at %d of %d: %v; its EvsReseed: %v", ref.RefId, ref.Version, ref.MirrorVersion, ref.Stopped, ref.FileError)
		}
	}
	for _, slot := range result.Slots {
		t.Errorf("slot %s was not taken: %v", slot.SlotId, slot.Refused)
	}
	main := reseedRefOf(t, result, refId)
	if main.Version != mirrored.GetVersion() || !bytes.Equal(main.Chain[:], mirrored.GetChain()) || main.Filed {
		t.Fatalf("the main ref returned to %d, filed %v; the mirror held %d", main.Version, main.Filed, mirrored.GetVersion())
	}
	if result.SlotCount != len(slots) || result.SegmentCount == 0 {
		t.Fatalf("%d slots and %d segments sent, of %d slots", result.SlotCount, result.SegmentCount, len(slots))
	}
	// the head the new site holds is the mirrored one: same version, same chain, never re-signed
	returned := world.head(refId)
	if returned.GetVersion() != mirrored.GetVersion() || !bytes.Equal(returned.GetChain(), mirrored.GetChain()) || !bytes.Equal(returned.GetPushId(), mirrored.GetPushId()) {
		t.Fatalf("the returned head is at %d", returned.GetVersion())
	}
	for slotId, before := range slots {
		if after := world.slotBytes(slotId); !bytes.Equal(after, before) {
			t.Errorf("slot %s returned as other bytes", slotId)
		}
	}

	// a device that never read the repo reads the returned history
	reader := world.device("r", nil)
	for path, want := range map[string][]byte{"ledger/a": small, "ledger/b": large} {
		content, _, err := reader.read(path)
		if err != nil || !bytes.Equal(content, want) {
			t.Fatalf("a fresh reader's %s: %d bytes, %v", path, len(content), err)
		}
	}
	if _, _, err := reader.read("ledger/c"); err == nil {
		t.Fatal("the entry no mirror held came back")
	}

	// the writer's device is pinned at the lost head: the returned one is below its pin, refused as a fork, and its
	// pin stays where it was
	lostVersion := mirrored.GetVersion() + 1
	if _, _, err := writer.read("ledger/a"); !errors.Is(err, sidecar.ErrEvsHeadForked) {
		t.Fatalf("a read below the pin: %v", err)
	}
	// a statement no repo admin signed, served with the head, lowers nothing
	reseedKey := evsservice.ReseedKey(world.repoId, refId)
	returnedChain := [sha256.Size]byte(returned.GetChain())
	forged, err := sidecar.SignEvsReseed(world.signers["v"].Sign, world.repoId, refId, returned.GetVersion(), returnedChain, []byte("incident 41"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.cluster.PutIfNoneMatch(world.ctx, reseedKey, forged, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := writer.read("ledger/a"); !errors.Is(err, sidecar.ErrEvsHeadForked) {
		t.Fatalf("a read below the pin under a non-admin's EvsReseed: %v", err)
	}
	// nor does an admin's statement of another head
	other, err := sidecar.SignEvsReseed(world.signers["w"].Sign, world.repoId, refId, returned.GetVersion()-1, returnedChain, []byte("incident 41"))
	if err != nil {
		t.Fatal(err)
	}
	if err := world.cluster.Delete(world.ctx, reseedKey); err != nil {
		t.Fatal(err)
	}
	if _, err := world.cluster.PutIfNoneMatch(world.ctx, reseedKey, other, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := writer.read("ledger/a"); !errors.Is(err, sidecar.ErrEvsHeadForked) {
		t.Fatalf("a read below the pin under an EvsReseed of another head: %v", err)
	}
	if pin, pinned, err := writer.client.Pins().Pin(world.repoId, refId); err != nil || !pinned || pin.Version != lostVersion || pin.Loss != nil {
		t.Fatalf("the writer's pin after the refused statements: %+v %v %v", pin, pinned, err)
	}
	if err := world.cluster.Delete(world.ctx, reseedKey); err != nil {
		t.Fatal(err)
	}

	// the admin files the EvsReseed over the returned head: everything is there already, and nothing else changes
	again, err := world.reseed(writer, &sidecar.EvsReseedArgs{IncidentId: []byte("incident 41"), SignReseed: true})
	if err != nil || !again.Whole() {
		t.Fatalf("a second re-seed: %+v, %v", again, err)
	}
	if filed := reseedRefOf(t, again, refId); !filed.Filed || filed.FileError != nil {
		t.Fatalf("the EvsReseed was not filed: %v", filed.FileError)
	}
	if after := world.head(refId); after.GetVersion() != returned.GetVersion() || !bytes.Equal(after.GetChain(), returned.GetChain()) {
		t.Fatalf("a second re-seed moved the head to %d", after.GetVersion())
	}
	// evs serves it after the head, and the writer's own read takes the shorter history under it, kept as a loss
	content, _, err := writer.read("ledger/a")
	if err != nil || !bytes.Equal(content, small) {
		t.Fatalf("the writer's read under the EvsReseed: %d bytes, %v", len(content), err)
	}
	pin, pinned, err := writer.client.Pins().Pin(world.repoId, refId)
	if err != nil || !pinned || pin.Version != returned.GetVersion() || !bytes.Equal(pin.Chain[:], returned.GetChain()) {
		t.Fatalf("the writer's pin under the EvsReseed: %+v %v %v", pin, pinned, err)
	}
	if pin.Loss == nil || pin.Loss.FromVersion != lostVersion || !bytes.Equal(pin.Loss.IncidentId, []byte("incident 41")) {
		t.Fatalf("the loss the pin keeps: %+v", pin.Loss)
	}
	// the entry the incident lost does not come back. The writer's read record of it, made at the lost head, still
	// refuses the path: whether an EvsReseed lowers a ref's read records with its pin is not settled (question
	// evs-reseed-route-read-records), so the record stands and the read fails closed
	if _, _, err := writer.read("ledger/c"); !errors.Is(err, sidecar.ErrEvsEntryRefused) {
		t.Fatalf("the lost entry's read by its writer: %v", err)
	}
	if content, _, err := writer.read("ledger/b"); err != nil || !bytes.Equal(content, large) {
		t.Fatalf("the writer's ledger/b under the EvsReseed: %d bytes, %v", len(content), err)
	}
	// and the repo takes pushes again on the returned head
	if _, err := world.device("v", nil).write("ledger/d", []byte("written after the recovery")); err != nil {
		t.Fatalf("a push after the re-seed: %v", err)
	}
}

// An entry erased after a stale mirror's sync stays erased: the admin's mirror returns the ERASE first, and the stale
// mirror's slot copy, which still holds the erased key, is stored without it, or not at all when it held no other.
func TestEvsReseedKeepsAnErasedKeyOutOfAStaleMirrorsSlotEndToEnd(t *testing.T) {
	world, writer, smallSlot := newMirrorWorld(t)
	mirrorWorldAdmin(world, "w")
	stale := world.device("m", nil)
	staleMirror := newWorldMirror(t, world, stale)
	if _, err := staleMirror.Sync(world.ctx); err != nil {
		t.Fatal(err)
	}
	if held, err := staleMirror.Store().Has(sidecar.EvsMirrorSlotKey(smallSlot.Bytes())); err != nil || !held {
		t.Fatalf("the stale mirror's slot copy: %v %v", held, err)
	}
	// the erasure, after the stale mirror's sync
	erased := []*sidecar.EvsErasedKey{{SlotId: smallSlot, KeyIndex: 0}}
	erasureId := sidecar.NewId()
	if _, err := writer.repo.Closure(world.ctx, &sidecar.EvsClosureArgs{
		ErasureId: erasureId, Writes: []*sidecar.EvsPathWrite{{Path: "ledger/a", Content: bytes.NewReader([]byte("the ledger with the entry gone"))}}, Erased: erased,
	}); err != nil {
		t.Fatalf("the CLOSURE: %v", err)
	}
	if _, err := writer.repo.Erase(world.ctx, &sidecar.EvsEraseArgs{ErasureId: erasureId, Keys: erased, Complete: true}); err != nil {
		t.Fatalf("the ERASE: %v", err)
	}
	mirror := newWorldMirror(t, world, writer)
	if _, err := mirror.Sync(world.ctx); err != nil {
		t.Fatal(err)
	}
	refId := world.mainRefId(writer)
	erasureRefId := sidecar.EvsErasureRefId(world.repoId)
	mirrored := world.head(refId)

	world.loseSite()
	result, err := world.reseed(writer, &sidecar.EvsReseedArgs{IncidentId: []byte("incident 41")})
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range result.Refs {
		if ref.Stopped != nil {
			t.Fatalf("ref %s stopped at %d of %d: %v", ref.RefId, ref.Version, ref.MirrorVersion, ref.Stopped)
		}
	}
	if len(result.Refs) == 0 || result.Refs[0].RefId != erasureRefId || result.Refs[0].Version == 0 {
		t.Fatalf("the erasure ref did not go first: %+v", result.Refs)
	}
	if returned := world.head(refId); returned.GetVersion() != mirrored.GetVersion() || !bytes.Equal(returned.GetChain(), mirrored.GetChain()) {
		t.Fatalf("the returned head is at %d, the mirror held %d", returned.GetVersion(), mirrored.GetVersion())
	}
	if world.slotBytes(smallSlot) != nil {
		t.Fatal("the admin's mirror returned the erased slot")
	}

	// the stale mirror: its history is there already, and its slot copy still holds the erased key
	staleResult, err := world.reseed(stale, &sidecar.EvsReseedArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if ref := reseedRefOf(t, staleResult, refId); ref.Stopped != nil || ref.Version != ref.MirrorVersion {
		t.Fatalf("the stale mirror's ref stopped at %d of %d: %v", ref.Version, ref.MirrorVersion, ref.Stopped)
	}
	for _, slot := range staleResult.Slots {
		t.Errorf("the stale mirror's slot %s was refused: %v", slot.SlotId, slot.Refused)
	}
	if stored := world.slotBytes(smallSlot); stored != nil {
		slot, err := sidecar.EvsDecodeSlotObject(stored)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range slot.GetKeys() {
			if key.GetKeyIndex() == 0 {
				t.Fatal("the erased key came back from a stale mirror")
			}
		}
	}
	// the closure's rewrite reads; the erased entry's old bytes do not come back with it
	reader := world.device("r", nil)
	content, _, err := reader.read("ledger/a")
	if err != nil || !bytes.Equal(content, []byte("the ledger with the entry gone")) {
		t.Fatalf("the closed path after the re-seed: %q, %v", content, err)
	}
}
