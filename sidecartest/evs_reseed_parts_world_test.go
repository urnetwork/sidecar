// A push in parts re-seeded end to end (QD-818, QD-836; EVSB-M2-20, §11.13's re-seed row, FS-41's storage clauses on
// T2): the epoch world's writer pushes 1,100 files in one push, which goes in parts, between two one-part pushes; a
// mirror holds the push's seal and each part's record; the site is lost; and the repo admin's sidecar.EvsRepo.Reseed
// sends the push back a part a call, then its seal naming the places those calls answered. The ref returns under its
// own chain, the push in parts as a seal naming a reseed record per part; a fresh reader reads and lists what it wrote;
// an export of the re-seeded ref verifies every version; and a mirror synced from the new site holds it and checks
// clean.

package sidecartest

import (
	"bytes"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
)

// The record at the place the head's window names for version.
func (self *epochWorld) recordAt(head *protocol.EvsHead, version uint64) *sidecar.EvsBatchRecord {
	self.t.Helper()
	window, err := evsservice.EvsHeadWindow(head)
	if err != nil {
		self.t.Fatal(err)
	}
	index := int(version - evsservice.EvsHeadWindowFirstVersion(head))
	if index < 0 || len(window) <= index {
		self.t.Fatalf("version %d is not in the window", version)
	}
	return self.recordAtPlace(window[index].Place)
}

// The record at place on the world's cluster.
func (self *epochWorld) recordAtPlace(place *protocol.EvsPlace) *sidecar.EvsBatchRecord {
	self.t.Helper()
	record, err := evsservice.ReadRecord(self.ctx, evsservice.NewRecordCache(evsservice.DefaultEvsSettings()), self.cluster, place)
	if err != nil {
		self.t.Fatal(err)
	}
	return record
}

func TestEvsReseedReturnsAPushInPartsEndToEnd(t *testing.T) {
	world := newEpochWorld(t)
	mirrorWorldAdmin(world, "w")
	writer := world.device("w", nil)
	if _, err := writer.write("first", []byte("written before the push in parts")); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for i := 0; i < 1100; i += 1 {
		files[fmt.Sprintf("bulk/f-%04d", i)] = []byte(fmt.Sprintf("file %d of the push in parts", i))
	}
	if _, err := writer.writePaths(files); err != nil {
		t.Fatalf("the push in parts: %v", err)
	}
	if _, err := writer.write("bulk/f-0007", []byte("written again after the push in parts")); err != nil {
		t.Fatal(err)
	}
	refId := world.mainRefId(writer)
	lost := world.head(refId)
	if lost.GetVersion() != 3 || world.recordAt(lost, 2).Type != protocol.EvsBatchRecordType_EVS_BATCH_SEAL {
		t.Fatalf("the lost site's head at %d, version 2 not sealed in parts", lost.GetVersion())
	}
	mirror := newWorldMirror(t, world, writer)
	if synced, err := mirror.Sync(world.ctx); err != nil || synced.MissingCount != 0 {
		t.Fatalf("the mirror's sync: %+v, %v", synced, err)
	}

	world.loseSite()
	result, err := world.reseed(writer, &sidecar.EvsReseedArgs{IncidentId: []byte("incident 818")})
	if err != nil || !result.Whole() {
		t.Fatalf("the re-seed: %+v, %v", result, err)
	}
	main := reseedRefOf(t, result, refId)
	if main.Version != lost.GetVersion() || !bytes.Equal(main.Chain[:], lost.GetChain()) {
		t.Fatalf("the main ref returned to %d of %d", main.Version, lost.GetVersion())
	}
	returned := world.head(refId)
	if returned.GetVersion() != lost.GetVersion() || !bytes.Equal(returned.GetChain(), lost.GetChain()) || !bytes.Equal(returned.GetPushId(), lost.GetPushId()) {
		t.Fatalf("the returned head is at %d", returned.GetVersion())
	}
	seal := world.recordAt(returned, 2)
	_, sealParts, err := sidecar.ParseEvsSealRecordBody(seal.Body)
	if err != nil || seal.Type != protocol.EvsBatchRecordType_EVS_BATCH_SEAL || len(sealParts) < 2 {
		t.Fatalf("version 2 returned as type %s with %d parts: %v", seal.Type, len(sealParts), err)
	}
	for i, sealPart := range sealParts {
		if part := world.recordAtPlace(sealPart.Place); !sidecar.EvsReseedRecordHoldsPart(part) {
			t.Fatalf("part %d returned as type %s", i+1, part.Type)
		}
	}

	// a device that never read the repo reads and lists what the push in parts wrote
	reader := world.device("r", nil)
	for _, path := range []string{"first", "bulk/f-0000", "bulk/f-0549", "bulk/f-1099", "bulk/f-0007"} {
		want := files[path]
		switch path {
		case "first":
			want = []byte("written before the push in parts")
		case "bulk/f-0007":
			want = []byte("written again after the push in parts")
		}
		if content, _, err := reader.read(path); err != nil || !bytes.Equal(content, want) {
			t.Fatalf("a fresh reader's %s: %q, %v", path, content, err)
		}
	}
	if names, err := reader.list("bulk"); err != nil || len(names) != len(files) {
		t.Fatalf("a fresh reader's listing of bulk: %d names, %v", len(names), err)
	}

	// an export of the re-seeded ref rebuilds every version, the push in parts from its reseed records
	exported, err := reader.repo.Export(world.ctx, &sidecar.EvsExportArgs{Dir: filepath.Join(t.TempDir(), "export.git")})
	if err != nil {
		t.Fatalf("the export: %v", err)
	}
	if len(exported.Refs) != 1 || exported.Refs[0].Versions != returned.GetVersion() || exported.Refs[0].Tip == (sidecar.EvsGitOid{}) || len(exported.Refs[0].Refused) != 0 {
		t.Fatalf("the export: %+v", exported.Refs)
	}

	// and a mirror synced from the new site holds the re-seeded ref whole and checks clean
	fresh := newWorldMirror(t, world, reader)
	synced, err := fresh.Sync(world.ctx)
	if err != nil || synced.MissingCount != 0 || synced.VersionCount != int(returned.GetVersion()) {
		t.Fatalf("a fresh mirror's sync: %+v, %v", synced, err)
	}
	if held, ok, err := fresh.Store().Ref(refId); err != nil || !ok || held.Version != returned.GetVersion() {
		t.Fatalf("the fresh mirror holds %+v, %v", held, err)
	}
	if records := mirrorKeys(t, fresh, sidecar.EvsMirrorRecords); len(records) != int(returned.GetVersion())+len(sealParts) {
		t.Fatalf("the fresh mirror holds %d records, want %d", len(records), int(returned.GetVersion())+len(sealParts))
	}
	check, err := fresh.Check(world.ctx)
	if err != nil || len(check.Failures) != 0 {
		t.Fatalf("the fresh mirror's check: %+v, %v", check, err)
	}
}
