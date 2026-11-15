// QD-819 end to end on the epoch world (question push-record-no-slot-bodies-part-slot-bodies): a record-class write of
// 1,100 files through sidecar.EvsRepo.WritePaths goes as one push in parts, a slot for each file's chain, whose seal
// carries every body and whose parts carry none. After a CLOSURE and an ERASE of one file's key, no stored object holds
// the erased key, in the batches, the parcel evacuation moves the records to or the pack the nightly pass makes of it,
// no record or part evs serves holds it, and no copy a reader's mirror keeps, synced before the ERASE and after it,
// holds it. And WritePaths splits a write whose slot bodies pass one push's into pushes each within them, while a
// single path or a CLOSURE past them fails closed, nothing sent.

package sidecartest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
)

// The stored objects, on the world's metadata cluster and its segment cluster, whose bytes hold secret.
func (self *epochWorld) storedHolding(secret []byte) []string {
	self.t.Helper()
	segmentCluster, err := self.host.Blobs.SegmentCluster()
	if err != nil {
		self.t.Fatal(err)
	}
	holding := []string{}
	for _, cluster := range []sidecar.BlobCluster{self.cluster, segmentCluster} {
		for startAfter, more := "", true; more; {
			var infos []*sidecar.BlobInfo
			infos, more, err = cluster.List(self.ctx, "", startAfter, 1000)
			if err != nil {
				self.t.Fatal(err)
			}
			for _, info := range infos {
				startAfter = info.Key
				object, err := cluster.Get(self.ctx, info.Key)
				if err != nil {
					self.t.Fatal(err)
				}
				content, err := io.ReadAll(object.Body)
				object.Body.Close()
				if err != nil {
					self.t.Fatal(err)
				}
				if bytes.Contains(content, secret) {
					holding = append(holding, cluster.ClusterId()+":"+info.Key)
				}
			}
		}
	}
	return holding
}

// The keys under prefix on clusterId's cluster.
func (self *epochWorld) clusterKeys(clusterId string, prefix string) []string {
	self.t.Helper()
	cluster, err := self.host.Blobs.Cluster(clusterId)
	if err != nil {
		self.t.Fatal(err)
	}
	keys := []string{}
	for startAfter, more := "", true; more; {
		var infos []*sidecar.BlobInfo
		infos, more, err = cluster.List(self.ctx, prefix, startAfter, 1000)
		if err != nil {
			self.t.Fatal(err)
		}
		for _, info := range infos {
			keys = append(keys, info.Key)
			startAfter = info.Key
		}
	}
	return keys
}

// Evacuation's hourly run over meta-1, 25 h 2 min past every write, its records going to a parcel while the repo's
// aged material stays under packByteCount; then, when idlePack, the nightly pass a week on, which packs the idle
// repo's parcels.
func (self *epochWorld) evacuate(packByteCount int64, idlePack bool) {
	self.t.Helper()
	settings := evsservice.DefaultEvacuatorSettings()
	settings.SpoolDirectory = self.t.TempDir()
	settings.PackByteCount = packByteCount
	self.clock.Advance(25*time.Hour + 2*time.Minute)
	evacuator, err := evsservice.NewEvacuator(self.host.ServiceHost(), &evsservice.EvacuatorDeps{Settings: settings})
	if err != nil {
		self.t.Fatal(err)
	}
	if result, err := evacuator.Run(self.ctx, self.cluster.ClusterId()); err != nil || result.HasBatches {
		self.t.Fatalf("evacuation: %v (%+v)", err, result)
	}
	if !idlePack {
		return
	}
	self.clock.Advance(6 * 24 * time.Hour)
	pass, err := evsservice.NewNightlyPass(self.host.ServiceHost(), &evsservice.NightlyPassDeps{
		Evacuator:          settings,
		SegmentClusterBusy: func(ctx context.Context, clusterId string) bool { return false },
	})
	if err != nil {
		self.t.Fatal(err)
	}
	if result, err := pass.Run(self.ctx, self.cluster.ClusterId(), "", ""); err != nil {
		self.t.Fatalf("the nightly pass: %v (%+v)", err, result)
	}
}

// One POST .../read of request as label's device, an r token of the clock's now: the reply's bytes.
func (self *epochWorld) readAs(label string, request *protocol.EvsReadRequest) []byte {
	self.t.Helper()
	sidecarId := connect.Id(self.signers[label].SidecarId)
	token := self.host.Authenticator.Issue(&sidecar.Principal{
		NetworkId: connect.Id(self.networkId), ClientId: connect.Id(self.clientId), SidecarId: &sidecarId,
		Audience: evsservice.EvsAudience, Scopes: []string{"repo:" + self.repoId.String() + ":r"},
		IssuedAt: self.clock.Now(), ExpiresAt: self.clock.Now().Add(15 * time.Minute),
	})
	bodyBytes, err := proto.Marshal(request)
	if err != nil {
		self.t.Fatal(err)
	}
	httpRequest := httptest.NewRequestWithContext(self.ctx, http.MethodPost, "/evs/v1/repos/"+sidecar.EvsKeyId(self.repoId)+"/read", bytes.NewReader(bodyBytes))
	httpRequest.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	self.engine.Handler().ServeHTTP(recorder, httpRequest)
	if recorder.Code != http.StatusOK {
		self.t.Fatalf("read: status %d", recorder.Code)
	}
	return recorder.Body.Bytes()
}

// The bytes of every object a mirror's family holds.
func mirrorHeld(t *testing.T, mirror *sidecar.EvsMirror, family sidecar.EvsMirrorFamily) [][]byte {
	t.Helper()
	held := [][]byte{}
	for _, key := range mirrorKeys(t, mirror, family) {
		reader, err := mirror.Store().Open(key)
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, content)
	}
	return held
}

// A record-class write of 1,100 files goes as one push in parts whose parts carry no slot body, and an ERASE of one
// file's key leaves that key nowhere: before it the slot alone stores it; after the CLOSURE and the ERASE no batch,
// parcel or pack stores it, no record evs serves of the push, its seal's or a part's, holds it, and no record copy a
// reader's mirror keeps holds it, the mirror synced before the ERASE and again after it dropping the erased slot's
// copy. Every file but the closed one still reads back, and the closed one reads its new content.
func TestEvsSlotKeyedPushInPartsLeavesAnErasedKeyNowhere(t *testing.T) {
	world := newEpochWorldOf(t, protocol.RepoKind_REPO_KIND_RECORD)
	writer := world.device("w", nil)
	files := map[string][]byte{}
	for i := range 1100 {
		files[fmt.Sprintf("ledger/e-%05d", i)] = []byte(fmt.Sprintf("entry %d of the ledger", i))
	}
	written, err := writer.writePaths(files)
	if err != nil {
		t.Fatalf("the write: %v", err)
	}
	refId := world.mainRefId(writer)
	head := world.head(refId)
	window, err := evsservice.EvsHeadWindow(head)
	if err != nil || head.GetVersion() != 1 || written.Version != 1 || len(window) != 1 {
		t.Fatalf("the write committed at %d, head at %d: %v", written.Version, head.GetVersion(), err)
	}
	seal, err := evsservice.NewRecordLocator(world.host.Blobs, nil).ReadRecord(world.ctx, world.cluster, world.repoId, refId, window[0].Place)
	if err != nil {
		t.Fatal(err)
	}
	sealRecord, err := sidecar.ParseEvsBatchRecord(seal)
	if err != nil || sealRecord.Type != protocol.EvsBatchRecordType_EVS_BATCH_SEAL {
		t.Fatalf("the push's record: %v", err)
	}
	statementBytes, sealParts, err := sidecar.ParseEvsSealRecordBody(sealRecord.Body)
	if err != nil || len(sealParts) < 2 {
		t.Fatalf("the seal names %d parts: %v", len(sealParts), err)
	}
	if slots := epochNewSlots(nil, world.slotKeys()); len(slots) != len(files) {
		t.Fatalf("%d slots for %d new chains", len(slots), len(files))
	}

	// the key of one file's chain, its slot's one key
	erasedPath := "ledger/e-00007"
	erased, err := writer.repo.SlotKeysOf(world.ctx, nil, []string{erasedPath})
	if err != nil || len(erased) != 1 {
		t.Fatalf("the file's slot keys %v: %v", erased, err)
	}
	object, err := world.cluster.Get(world.ctx, evsservice.SlotKey(world.repoId, erased[0].SlotId))
	if err != nil {
		t.Fatal(err)
	}
	slotBytes, err := readAllAndClose(object)
	if err != nil {
		t.Fatal(err)
	}
	slot, err := sidecar.EvsDecodeSlotObject(slotBytes)
	if err != nil || len(slot.GetKeys()) != 1 {
		t.Fatalf("the slot: %v", err)
	}
	wrapped := slot.GetKeys()[0].GetWrapped()
	slotKey := world.cluster.ClusterId() + ":" + evsservice.SlotKey(world.repoId, erased[0].SlotId)
	if holding := world.storedHolding(wrapped); len(holding) != 1 || holding[0] != slotKey {
		t.Fatalf("the key stored in %v, its slot alone wanted", holding)
	}

	reader := world.device("r", nil)
	mirror := newWorldMirror(t, world, reader)
	if _, err := mirror.Sync(world.ctx); err != nil {
		t.Fatal(err)
	}
	if records := mirrorHeld(t, mirror, sidecar.EvsMirrorRecords); len(records) != len(sealParts)+1 {
		t.Fatalf("the mirror holds %d records, want the seal's and %d parts'", len(records), len(sealParts))
	}
	for _, record := range mirrorHeld(t, mirror, sidecar.EvsMirrorRecords) {
		if bytes.Contains(record, wrapped) {
			t.Fatal("a mirrored record holds the file's key before any ERASE")
		}
	}

	erasureId := sidecar.NewId()
	closed := []byte("the entry gone")
	if _, err := writer.repo.Closure(world.ctx, &sidecar.EvsClosureArgs{
		ErasureId: erasureId, Writes: []*sidecar.EvsPathWrite{{Path: erasedPath, Content: bytes.NewReader(closed)}}, Erased: erased,
	}); err != nil {
		t.Fatalf("the CLOSURE: %v", err)
	}
	if _, err := writer.repo.Erase(world.ctx, &sidecar.EvsEraseArgs{ErasureId: erasureId, Keys: erased, Complete: true}); err != nil {
		t.Fatalf("the ERASE: %v", err)
	}
	if synced, err := mirror.Sync(world.ctx); err != nil || synced.ErasureCount != 1 {
		t.Fatalf("the sync after the ERASE: %+v %v", synced, err)
	}

	statement, err := sidecar.ParseEvsStatement(statementBytes)
	if err != nil {
		t.Fatal(err)
	}
	pushes := []*protocol.EvsReadPush{}
	for part := range uint32(len(sealParts) + 1) {
		pushes = append(pushes, &protocol.EvsReadPush{PushId: statement.Push.GetPushId(), Version: 1, Part: part})
	}
	requireNowhere := func(stage string) {
		t.Helper()
		if holding := world.storedHolding(wrapped); len(holding) != 0 {
			t.Fatalf("%s: the erased key is stored in %v", stage, holding)
		}
		reply := world.readAs("r", &protocol.EvsReadRequest{RefId: refId.Bytes(), Pushes: pushes})
		if bytes.Contains(reply, wrapped) {
			t.Fatalf("%s: a served record holds the erased key", stage)
		}
		frames := sidecar.NewEvsReadFrames(bytes.NewReader(reply))
		served := 0
		for {
			frame, err := frames.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("%s: the read's frames: %v", stage, err)
			}
			if object := frame.GetObject(); object.GetKind() == protocol.EvsReadObjectKind_EVS_READ_OBJECT_BATCH_RECORD && !object.GetMissing() {
				served += 1
			}
		}
		if served != len(sealParts)+1 {
			t.Fatalf("%s: %d records served, want the seal's and %d parts'", stage, served, len(sealParts))
		}
		for _, family := range []sidecar.EvsMirrorFamily{sidecar.EvsMirrorRecords, sidecar.EvsMirrorSlots} {
			for _, held := range mirrorHeld(t, mirror, family) {
				if bytes.Contains(held, wrapped) {
					t.Fatalf("%s: the mirror's %s copies hold the erased key", stage, family)
				}
			}
		}
	}
	requireNowhere("in the batches")
	world.evacuate(64*1024*1024, false)
	if parcels := world.clusterKeys(world.cluster.ClusterId(), "hp/"); len(parcels) == 0 {
		t.Fatal("evacuation wrote no parcel")
	}
	requireNowhere("in a parcel")
	world.evacuate(64*1024*1024, true)
	segmentCluster, err := world.host.Blobs.SegmentCluster()
	if err != nil {
		t.Fatal(err)
	}
	if packs := world.clusterKeys(segmentCluster.ClusterId(), "pack/"); len(packs) == 0 {
		t.Fatal("the nightly pass wrote no pack")
	}
	requireNowhere("in a pack")

	// a mirror first synced now holds it nowhere either, and the files read as they stand
	fresh := newWorldMirror(t, world, world.device("m", nil))
	if _, err := fresh.Sync(world.ctx); err != nil {
		t.Fatal(err)
	}
	for _, family := range []sidecar.EvsMirrorFamily{sidecar.EvsMirrorRecords, sidecar.EvsMirrorSlots} {
		for _, held := range mirrorHeld(t, fresh, family) {
			if bytes.Contains(held, wrapped) {
				t.Fatalf("a fresh mirror's %s copies hold the erased key", family)
			}
		}
	}
	freshReader := world.device("r", nil)
	for _, path := range []string{"ledger/e-00000", "ledger/e-01099", erasedPath} {
		want := files[path]
		if path == erasedPath {
			want = closed
		}
		if content, _, err := freshReader.read(path); err != nil || !bytes.Equal(content, want) {
			t.Fatalf("%s: %q %v", path, content, err)
		}
	}
}

// A write whose new slots' bodies pass one push's (EvsSettings.PushSlotBodiesByteCount; QD-819) splits into pushes
// each within them: 100 record-class files, a slot each of 82 B framed, under a bound of 3 KiB, go as four pushes of
// 25, nothing sent past the bound, and the result names the last push's version and every write's path version. Each
// push's slots, as stored, fit the bound, and every file reads back.
func TestEvsWriteSplitsPastOnePushsSlotBodies(t *testing.T) {
	world := newEpochWorldOf(t, protocol.RepoKind_REPO_KIND_RECORD)
	bound := 3 * 1024
	writer := world.device("w", func(settings *sidecar.EvsSettings) { settings.PushSlotBodiesByteCount = bound })
	files := map[string][]byte{}
	for i := range 100 {
		files[fmt.Sprintf("ledger/s-%03d", i)] = []byte(fmt.Sprintf("split entry %d", i))
	}
	written, err := writer.writePaths(files)
	if err != nil {
		t.Fatalf("the write: %v", err)
	}
	refId := world.mainRefId(writer)
	head := world.head(refId)
	if written.Version != 4 || head.GetVersion() != 4 || len(written.PathVersions) != len(files) {
		t.Fatalf("committed at %d, head at %d, %d path versions", written.Version, head.GetVersion(), len(written.PathVersions))
	}
	for i, version := range written.PathVersions {
		// each half's paths at the version of the push that created them
		if want := uint64(i/25) + 1; version != want {
			t.Fatalf("path %d at version %d, want %d", i, version, want)
		}
	}
	window, err := evsservice.EvsHeadWindow(head)
	if err != nil || len(window) != 4 {
		t.Fatalf("window: %d entries, %v", len(window), err)
	}
	locator := evsservice.NewRecordLocator(world.host.Blobs, nil)
	for _, entry := range window {
		recordBytes, err := locator.ReadRecord(world.ctx, world.cluster, world.repoId, refId, entry.Place)
		if err != nil {
			t.Fatal(err)
		}
		record, err := sidecar.ParseEvsBatchRecord(recordBytes)
		if err != nil {
			t.Fatal(err)
		}
		statementBytes, payloadBytes, err := sidecar.ParseEvsPushRecordBody(record.Body)
		if err != nil {
			t.Fatalf("a split push's record: %v", err)
		}
		statement, err := sidecar.ParseEvsStatement(statementBytes)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := sidecar.EvsCheckRecordPayload(statement, payloadBytes)
		if err != nil {
			t.Fatal(err)
		}
		bodies := 0
		for _, object := range payload.NewObjects {
			if object.Kind != protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT {
				continue
			}
			stored, err := world.cluster.Get(world.ctx, evsservice.SlotKey(world.repoId, sidecar.Id(object.Id)))
			if err != nil {
				t.Fatal(err)
			}
			slotBytes, err := readAllAndClose(stored)
			if err != nil {
				t.Fatal(err)
			}
			bodies += 4 + len(slotBytes)
		}
		if bodies == 0 || bound < bodies {
			t.Fatalf("a split push carried %d bytes of slot bodies, the bound %d", bodies, bound)
		}
	}
	reader := world.device("r", nil)
	for path, content := range files {
		if read, _, err := reader.read(path); err != nil || !bytes.Equal(read, content) {
			t.Fatalf("%s: %q %v", path, read, err)
		}
	}
}

// What cannot split fails closed past the bound, nothing sent: a write of one path, and a CLOSURE, whose erased list
// must equal the ERASE after it, each answer ErrEvsSlotBodiesTooLarge with no head moved and no segment uploaded.
func TestEvsWritePastOnePushsSlotBodiesThatCannotSplitFailsClosed(t *testing.T) {
	world := newEpochWorldOf(t, protocol.RepoKind_REPO_KIND_RECORD)
	segmentCluster, err := world.host.Blobs.SegmentCluster()
	if err != nil {
		t.Fatal(err)
	}
	// two files written within the default bound
	roomy := world.device("v", nil)
	if _, err := roomy.writePaths(map[string][]byte{"ledger/a": []byte("entry a"), "ledger/b": []byte("entry b")}); err != nil {
		t.Fatal(err)
	}
	refId := world.mainRefId(roomy)
	segments := len(world.clusterKeys(segmentCluster.ClusterId(), "seg/"))
	tight := world.device("w", func(settings *sidecar.EvsSettings) { settings.PushSlotBodiesByteCount = 64 })
	if _, err := tight.write("ledger/one", []byte("one entry")); !errors.Is(err, sidecar.ErrEvsSlotBodiesTooLarge) {
		t.Fatalf("a write of one path past the bound: %v", err)
	}
	requireNothingSent := func(label string) {
		t.Helper()
		if head := world.head(refId); head.GetVersion() != 1 {
			t.Fatalf("%s moved the head to %d", label, head.GetVersion())
		}
		if after := len(world.clusterKeys(segmentCluster.ClusterId(), "seg/")); after != segments {
			t.Fatalf("%s uploaded %d segments", label, after-segments)
		}
	}
	requireNothingSent("the refused write")
	erased, err := roomy.repo.SlotKeysOf(world.ctx, nil, []string{"ledger/a", "ledger/b"})
	if err != nil || len(erased) != 2 {
		t.Fatalf("the slot keys %v: %v", erased, err)
	}
	_, err = tight.repo.Closure(world.ctx, &sidecar.EvsClosureArgs{
		ErasureId: sidecar.NewId(), Erased: erased, Writes: []*sidecar.EvsPathWrite{
			{Path: "ledger/a", Content: bytes.NewReader([]byte("a closed"))}, {Path: "ledger/b", Content: bytes.NewReader([]byte("b closed"))},
		},
	})
	if !errors.Is(err, sidecar.ErrEvsSlotBodiesTooLarge) {
		t.Fatalf("a CLOSURE past the bound: %v", err)
	}
	requireNothingSent("the refused CLOSURE")
}
