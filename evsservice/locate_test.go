package evsservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A repo's ref on meta-1 with one batch written, and a locator over the fake clusters.
type locateFixture struct {
	t        *testing.T
	ctx      context.Context
	blobs    *sidecartest.FakeBlobs
	meta     sidecar.BlobCluster
	repoId   sidecar.Id
	refId    sidecar.Id
	batch    *containerTestBatch
	locator  *RecordLocator
	segments *SegmentLocator
}

func newLocateFixture(t *testing.T) *locateFixture {
	ctx := sidecar.WithWriteClass(t.Context(), sidecar.WriteClassP2)
	blobs := sidecartest.NewFakeBlobs(nil, nil, nil, nil)
	meta, err := blobs.Cluster("meta-1")
	if err != nil {
		t.Fatal(err)
	}
	repoId := testIdFrom("locate repo")
	refId := testIdFrom("locate ref")
	batch := newContainerTestBatch(t, 4000, 1, repoId, refId, 10, []protocol.EvsBatchRecordType{
		protocol.EvsBatchRecordType_EVS_BATCH_PART, protocol.EvsBatchRecordType_EVS_BATCH_SEAL,
	})
	if _, err := meta.PutIfNoneMatch(ctx, batch.key, batch.bytes, nil); err != nil {
		t.Fatal(err)
	}
	return &locateFixture{
		t:        t,
		ctx:      ctx,
		blobs:    blobs,
		meta:     meta,
		repoId:   repoId,
		refId:    refId,
		batch:    batch,
		locator:  NewRecordLocator(blobs, nil),
		segments: NewSegmentLocator(blobs),
	}
}

// Builds and writes a container of kind holding the batch's records, its entries after it.
func (self *locateFixture) evacuate(kind protocol.EvsContainerKind) *Container {
	self.t.Helper()
	container, err := BuildContainer(kind, self.batch.records, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	if err := WriteContainer(self.ctx, self.blobs, self.meta, self.repoId, container); err != nil {
		self.t.Fatal(err)
	}
	return container
}

func (self *locateFixture) deleteBatch() {
	self.t.Helper()
	if err := self.meta.Delete(self.ctx, self.batch.key); err != nil {
		self.t.Fatal(err)
	}
}

// Reads every record of the batch through the locator and checks its bytes.
func (self *locateFixture) readAll() error {
	for _, record := range self.batch.records {
		recordBytes, err := self.locator.ReadRecord(self.ctx, self.meta, self.repoId, self.refId, record.Place)
		if err != nil {
			return err
		}
		if !bytes.Equal(recordBytes, record.Bytes) {
			self.t.Fatal("the locator read other bytes")
		}
	}
	return nil
}

// While the batch stands its records come from it, by place.
func TestRecordLocatorReadsTheBatchWhileItStands(t *testing.T) {
	fixture := newLocateFixture(t)
	if err := fixture.readAll(); err != nil {
		t.Fatal(err)
	}
	if lists := fixture.blobs.RequestCount("meta-1", string(sidecartest.FaultOpList)); lists != 0 {
		t.Fatalf("%d LISTs for records whose batch stands", lists)
	}
}

// The batch gone, each record, a part by its place included, comes from the container pidx/ names.
func TestRecordLocatorFindsMovedRecordsInPidx(t *testing.T) {
	for _, kind := range []protocol.EvsContainerKind{protocol.EvsContainerKind_EVS_CONTAINER_PARCEL, protocol.EvsContainerKind_EVS_CONTAINER_PACK} {
		fixture := newLocateFixture(t)
		fixture.evacuate(kind)
		fixture.deleteBatch()
		if err := fixture.readAll(); err != nil {
			t.Fatalf("kind %d: %v", kind, err)
		}
	}
}

// A record a pack and a parcel both name is read from the pack.
func TestRecordLocatorTakesAPackOverAParcel(t *testing.T) {
	fixture := newLocateFixture(t)
	fixture.evacuate(protocol.EvsContainerKind_EVS_CONTAINER_PARCEL)
	fixture.evacuate(protocol.EvsContainerKind_EVS_CONTAINER_PACK)
	fixture.deleteBatch()
	getOp := string(sidecartest.FaultOpGet)
	before := fixture.blobs.RequestCount("meta-1", getOp)
	if err := fixture.readAll(); err != nil {
		t.Fatal(err)
	}
	// on meta-1 the batch's two 404s and one GET of each container's entry, and no read of the parcel: every
	// record came from the pack on seg-1
	if got := fixture.blobs.RequestCount("meta-1", getOp) - before; got != len(fixture.batch.records)+2 {
		t.Fatalf("%d reads on meta-1, want the batch's %d and two entries", got, len(fixture.batch.records))
	}
	if got := fixture.blobs.RequestCount("seg-1", getOp); got != len(fixture.batch.records) {
		t.Fatalf("%d range reads of the pack", got)
	}
}

// FS-11's locator clause: a reader that listed pidx/ and found nothing, paused there while a pack is published
// and the batch deleted, finds the record on one relist.
func TestRecordLocatorFindsARecordOnOneRelist(t *testing.T) {
	fixture := newLocateFixture(t)
	record := fixture.batch.records[1]
	// the reader's negative lookup: the batch is gone, and pidx/ holds nothing yet
	fixture.deleteBatch()
	if _, err := fixture.locator.ReadRecord(fixture.ctx, fixture.meta, fixture.repoId, fixture.refId, record.Place); !errors.Is(err, sidecar.ErrBlobNotFound) {
		t.Fatalf("a record nothing holds: %v", err)
	}
	// meanwhile a container and its entries are published
	fixture.evacuate(protocol.EvsContainerKind_EVS_CONTAINER_PACK)
	lists := fixture.blobs.RequestCount("meta-1", string(sidecartest.FaultOpList))
	recordBytes, err := fixture.locator.ReadRecord(fixture.ctx, fixture.meta, fixture.repoId, fixture.refId, record.Place)
	if err != nil || !bytes.Equal(recordBytes, record.Bytes) {
		t.Fatalf("after a cached miss: %v", err)
	}
	if got := fixture.blobs.RequestCount("meta-1", string(sidecartest.FaultOpList)) - lists; got != 1 {
		t.Fatalf("%d relists, want one", got)
	}
}

// A cached entry whose container was deleted, a parcel the pack replaced, drops the cache and relists once.
func TestRecordLocatorRelistsWhenANamedContainerIsGone(t *testing.T) {
	fixture := newLocateFixture(t)
	parcel := fixture.evacuate(protocol.EvsContainerKind_EVS_CONTAINER_PARCEL)
	fixture.deleteBatch()
	if err := fixture.readAll(); err != nil {
		t.Fatal(err)
	}
	// the pack replaces the parcel: its entries first, then the parcel and its entries go
	fixture.evacuate(protocol.EvsContainerKind_EVS_CONTAINER_PACK)
	if err := fixture.meta.Delete(fixture.ctx, parcel.Key(fixture.repoId)); err != nil {
		t.Fatal(err)
	}
	keys, _, err := parcel.EntryKeys(fixture.repoId)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if err := fixture.meta.Delete(fixture.ctx, key); err != nil {
			t.Fatal(err)
		}
	}
	if err := fixture.readAll(); err != nil {
		t.Fatalf("after the parcel went: %v", err)
	}
}

// A pack's log page is read once log/ has gone.
func TestRecordLocatorReadsALogPageFromItsPack(t *testing.T) {
	fixture := newLocateFixture(t)
	container, err := BuildContainer(protocol.EvsContainerKind_EVS_CONTAINER_PACK, fixture.batch.records, []*ContainerLogPage{{RefId: fixture.refId, Page: 0, Bytes: []byte("a log page")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteContainer(fixture.ctx, fixture.blobs, fixture.meta, fixture.repoId, container); err != nil {
		t.Fatal(err)
	}
	pageBytes, err := fixture.locator.ReadLogPage(fixture.ctx, fixture.meta, fixture.repoId, fixture.refId, 0)
	if err != nil || string(pageBytes) != "a log page" {
		t.Fatalf("page %q %v", pageBytes, err)
	}
	if _, err := fixture.locator.ReadLogPage(fixture.ctx, fixture.meta, fixture.repoId, fixture.refId, 1); !errors.Is(err, sidecar.ErrBlobNotFound) {
		t.Fatalf("a page no pack holds: %v", err)
	}
}

// A rerun reuses what an earlier run wrote: the container's equal bytes and its create-only entries.
func TestWriteContainerWritesTheContainerFirstAndResumes(t *testing.T) {
	fixture := newLocateFixture(t)
	container, err := BuildContainer(protocol.EvsContainerKind_EVS_CONTAINER_PARCEL, fixture.batch.records, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteContainer(fixture.ctx, fixture.blobs, fixture.meta, fixture.repoId, container); err != nil {
		t.Fatal(err)
	}
	if err := WriteContainer(fixture.ctx, fixture.blobs, fixture.meta, fixture.repoId, container); err != nil {
		t.Fatalf("a rerun: %v", err)
	}
	keys, _, err := container.EntryKeys(fixture.repoId)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.meta.Head(fixture.ctx, container.Key(fixture.repoId)); err != nil {
		t.Fatalf("parcel: %v", err)
	}
	for _, key := range keys {
		if _, err := fixture.meta.Head(fixture.ctx, key); err != nil {
			t.Fatalf("entry %s: %v", key, err)
		}
	}
}

// seg/ answers while the segment stands; after, an empty spidx/ leaves it gone, and a page there, which format 1
// never writes, is refused rather than read.
func TestSegmentLocatorReadsSegAndRefusesAnSpidxPage(t *testing.T) {
	fixture := newLocateFixture(t)
	segmentBytes := []byte("segment bytes")
	segmentId := sha256.Sum256(segmentBytes)
	segmentCluster, err := fixture.blobs.SegmentCluster()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := segmentCluster.PutStream(fixture.ctx, SegmentKey(fixture.repoId, segmentId), bytes.NewReader(segmentBytes), int64(len(segmentBytes)), segmentId[:]); err != nil {
		t.Fatal(err)
	}
	object, err := fixture.segments.OpenSegment(fixture.ctx, fixture.meta, fixture.repoId, segmentId, 8, 5)
	if err != nil {
		t.Fatal(err)
	}
	object.Body.Close()
	missing := sha256.Sum256([]byte("missing"))
	if _, err := fixture.segments.OpenSegment(fixture.ctx, fixture.meta, fixture.repoId, missing, 0, 0); !errors.Is(err, sidecar.ErrBlobNotFound) {
		t.Fatalf("a missing segment: %v", err)
	}
	if _, err := fixture.meta.PutIfNoneMatch(fixture.ctx, SpidxKey(fixture.repoId, 0), []byte("page"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.segments.OpenSegment(fixture.ctx, fixture.meta, fixture.repoId, missing, 0, 0); !errors.Is(err, ErrEvsSpidxUnsupported) {
		t.Fatalf("with an spidx page: %v", err)
	}
}
