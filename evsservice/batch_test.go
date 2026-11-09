package evsservice

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A batch writer over one fake host's clusters, writing through the budget's wrapper.
type batchFixture struct {
	t        *testing.T
	ctx      context.Context
	clock    *sidecartest.FakeClock
	host     *sidecartest.FakeHost
	settings *EvsSettings
	records  *RecordCache
	writer   *BatchWriter
	// a ctx the budget passed, as a push's step 6 holds
	paidCtx context.Context
}

func newBatchFixture(t *testing.T, adjust func(settings *EvsSettings)) *batchFixture {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	hostSettings := sidecartest.DefaultFakeHostSettings()
	hostSettings.Blobs.MetadataClusterIds = []string{"meta-1", "meta-2"}
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, hostSettings)
	settings := DefaultEvsSettings()
	if adjust != nil {
		adjust(settings)
	}
	records := NewRecordCache(settings)
	writer := NewBatchWriter(ctx, clock, NewBudgetedBlobs(host.Blobs), records, settings, sidecar.NewNoopLogger())
	grant, err := host.Budget.AdmitP1(ctx, "meta-1", connectNetworkId(), sidecar.WriteCost{ImmediateByteCount: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(grant.Close)
	return &batchFixture{t: t, ctx: ctx, clock: clock, host: host, settings: settings, records: records, writer: writer, paidCtx: grant.Context()}
}

// A record of a push with a body of byteCount bytes.
func testRecord(label string, byteCount int) *sidecar.EvsBatchRecord {
	body := make([]byte, byteCount)
	copy(body, label)
	return &sidecar.EvsBatchRecord{
		Type: protocol.EvsBatchRecordType_EVS_BATCH_PUSH, RepoId: testId("repo"), RefId: testId("ref"),
		PushId: testId(label), SignerSidecarId: testId("signer"), TimeMs: 1, Body: body,
	}
}

// One Append's answer.
type appendResult struct {
	place *protocol.EvsPlace
	err   error
}

// Appends record to clusterId on a goroutine of its own.
func (self *batchFixture) appendAsync(clusterId string, record *sidecar.EvsBatchRecord) chan *appendResult {
	results := make(chan *appendResult, 1)
	go func() {
		place, err := self.writer.Append(self.paidCtx, clusterId, record)
		results <- &appendResult{place: place, err: err}
	}()
	return results
}

// Waits until count records have joined a batch.
func (self *batchFixture) awaitAppended(count int) {
	for {
		appended, changed := self.writer.Appended()
		if count <= appended {
			return
		}
		select {
		case <-changed:
		case <-time.After(10 * time.Second):
			self.t.Fatalf("%d of %d records appended", appended, count)
		}
	}
}

// Waits for an append's answer.
func awaitResult(t *testing.T, results chan *appendResult) *appendResult {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(10 * time.Second):
		t.Fatal("an append never answered")
		return nil
	}
}

// Waits for a fired fault plan.
func awaitFired(t *testing.T, fired <-chan struct{}) {
	t.Helper()
	select {
	case <-fired:
	case <-time.After(10 * time.Second):
		t.Fatal("a fault never fired")
	}
}

// The network every batch test's budget is admitted under.
func connectNetworkId() [16]byte {
	return testId("network-a")
}

func TestBatchUnderLightLoadIsWrittenAtOnce(t *testing.T) {
	fixture := newBatchFixture(t, nil)
	place, err := fixture.writer.Append(fixture.paidCtx, "meta-1", testRecord("push-1", 100))
	if err != nil {
		t.Fatal(err)
	}
	if fixture.writer.WriteCount() != 1 {
		t.Errorf("%d writes", fixture.writer.WriteCount())
	}
	if place.GetMinute() != BatchMinute(fixture.clock.Now()) || place.GetInstance() != fixture.writer.Instance() {
		t.Errorf("place %v", place)
	}
	cluster, _ := fixture.host.Blobs.Cluster("meta-1")
	object, err := cluster.Get(fixture.ctx, PlaceBatchKey(place))
	if err != nil {
		t.Fatal(err)
	}
	defer object.Body.Close()
	batchBytes, _ := io.ReadAll(object.Body)
	batch, err := sidecar.ParseEvsBatch(batchBytes)
	if err != nil || len(batch.Records) != 1 || batch.Records[0].PushId != testId("push-1") {
		t.Errorf("batch %v %v", batch, err)
	}
}

// §11.8's flush row: under load a batch waits for its oldest record's 20 ms, gathering every record that came
// meanwhile.
func TestBatchUnderLoadWaitsItsFlushDelay(t *testing.T) {
	fixture := newBatchFixture(t, func(settings *EvsSettings) {
		// every cluster counts as loaded
		settings.BatchLightLoadRecordCount = 1
	})
	results := []chan *appendResult{}
	for _, label := range []string{"push-1", "push-2", "push-3"} {
		results = append(results, fixture.appendAsync("meta-1", testRecord(label, 100)))
	}
	fixture.awaitAppended(3)
	fixture.clock.Advance(19 * time.Millisecond)
	if fixture.writer.WriteCount() != 0 {
		t.Fatal("written before its delay")
	}
	fixture.clock.Advance(time.Millisecond)
	places := []*protocol.EvsPlace{}
	for _, result := range results {
		answer := awaitResult(t, result)
		if answer.err != nil {
			t.Fatal(answer.err)
		}
		places = append(places, answer.place)
	}
	if fixture.writer.WriteCount() != 1 {
		t.Errorf("%d writes for one batch", fixture.writer.WriteCount())
	}
	for _, place := range places[1:] {
		if PlaceBatchKey(place) != PlaceBatchKey(places[0]) {
			t.Error("records of one delay in two batches")
		}
	}
}

// §11.8's flush row: a batch reaching 256 KiB is written at once, and a record over 256 KiB is a batch alone.
func TestBatchIsWrittenAtItsBoundAndABigRecordAlone(t *testing.T) {
	fixture := newBatchFixture(t, func(settings *EvsSettings) {
		settings.BatchLightLoadRecordCount = 1
	})
	first := fixture.appendAsync("meta-1", testRecord("push-1", 120*1024))
	fixture.awaitAppended(1)
	second := fixture.appendAsync("meta-1", testRecord("push-2", 120*1024))
	fixture.awaitAppended(2)
	if fixture.writer.WriteCount() != 0 {
		t.Fatal("written below its bound")
	}
	// the third does not fit beside them: the first batch goes now, the third opens the next
	third := fixture.appendAsync("meta-1", testRecord("push-3", 120*1024))
	fixture.awaitAppended(3)
	for _, results := range []chan *appendResult{first, second} {
		if answer := awaitResult(t, results); answer.err != nil {
			t.Fatal(answer.err)
		}
	}
	if fixture.writer.WriteCount() != 1 {
		t.Errorf("%d writes", fixture.writer.WriteCount())
	}
	// a record past 256 KiB is a batch alone, written at once though the cluster is loaded
	big := fixture.appendAsync("meta-1", testRecord("push-big", 300*1024))
	if answer := awaitResult(t, big); answer.err != nil || answer.place.GetOffset() != sidecar.EvsBatchHeaderByteCount {
		t.Fatalf("a big record: %v", answer)
	}
	fixture.clock.Advance(20 * time.Millisecond)
	if answer := awaitResult(t, third); answer.err != nil {
		t.Fatal(answer.err)
	}
	if _, err := fixture.writer.Append(fixture.paidCtx, "meta-1", testRecord("push-huge", 1024*1024)); !errors.Is(err, sidecar.ErrEvsPushInvalid) {
		t.Errorf("a record no batch holds: %v", err)
	}
}

// §11.8's flush row: at most two batch writes in flight per process and cluster; a due batch waits for a slot.
func TestBatchKeepsAtMostTwoWritesInFlight(t *testing.T) {
	fixture := newBatchFixture(t, func(settings *EvsSettings) {
		settings.BatchFlushDelay = 0
	})
	faults := fixture.host.Blobs.Faults()
	firedChannels := []<-chan struct{}{}
	for nth := 1; nth <= 2; nth += 1 {
		fired, err := faults.Add(&sidecartest.FaultPlan{
			Op: sidecartest.FaultOpPut, KeyPrefix: "pb/", Nth: nth, Result: sidecartest.Delay, Delay: sidecartest.DelayInNetwork,
		})
		if err != nil {
			t.Fatal(err)
		}
		firedChannels = append(firedChannels, fired)
	}
	results := []chan *appendResult{}
	for _, label := range []string{"push-1", "push-2"} {
		results = append(results, fixture.appendAsync("meta-1", testRecord(label, 100)))
	}
	for _, fired := range firedChannels {
		awaitFired(t, fired)
	}
	results = append(results, fixture.appendAsync("meta-1", testRecord("push-3", 100)))
	fixture.awaitAppended(3)
	if fixture.writer.WriteCount() != 2 {
		t.Fatalf("%d writes in flight", fixture.writer.WriteCount())
	}
	if delivered := fixture.host.Blobs.DeliverDelayed("meta-1", "pb/"); delivered != 2 {
		t.Fatalf("%d delivered", delivered)
	}
	for _, result := range results {
		if answer := awaitResult(t, result); answer.err != nil {
			t.Fatal(answer.err)
		}
	}
	if fixture.writer.WriteCount() != 3 {
		t.Errorf("%d writes", fixture.writer.WriteCount())
	}
}

// FS-57's first half: a batch PUT applied and its response dropped is read back, and its records stand.
func TestBatchPutAppliedAndItsResponseDroppedIsWritten(t *testing.T) {
	fixture := newBatchFixture(t, nil)
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpPut, KeyPrefix: "pb/", Result: sidecartest.ApplyThenDrop}); err != nil {
		t.Fatal(err)
	}
	place, err := fixture.writer.Append(fixture.paidCtx, "meta-1", testRecord("push-1", 100))
	if err != nil {
		t.Fatal(err)
	}
	cluster, _ := fixture.host.Blobs.Cluster("meta-1")
	record, err := ReadRecord(fixture.ctx, NewRecordCache(fixture.settings), cluster, place)
	if err != nil || record.PushId != testId("push-1") {
		t.Errorf("record %v %v", record, err)
	}
	// and one whose first send never landed is sent again with the same bytes
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpPut, KeyPrefix: "pb/", Result: sidecartest.FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.writer.Append(fixture.paidCtx, "meta-1", testRecord("push-2", 100)); err != nil {
		t.Errorf("after a lost send: %v", err)
	}
}

// FS-57: with the store unreachable during the batch write, every waiter is answered, nothing written.
func TestBatchStoreUnreachableAnswersEveryWaiter(t *testing.T) {
	fixture := newBatchFixture(t, func(settings *EvsSettings) {
		settings.BatchLightLoadRecordCount = 1
	})
	for _, op := range []string{sidecartest.FaultOpPut, sidecartest.FaultOpGet} {
		if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{Op: op, KeyPrefix: "pb/", Result: sidecartest.FailBeforeApply, Repeat: -1}); err != nil {
			t.Fatal(err)
		}
	}
	first := fixture.appendAsync("meta-1", testRecord("push-1", 100))
	second := fixture.appendAsync("meta-1", testRecord("push-2", 100))
	fixture.awaitAppended(2)
	fixture.clock.Advance(20 * time.Millisecond)
	for _, results := range []chan *appendResult{first, second} {
		if answer := awaitResult(t, results); !errors.Is(answer.err, ErrEvsBatchUnwritten) {
			t.Errorf("a waiter got %v", answer.err)
		}
	}
	for key := range fixture.host.Blobs.Dump() {
		t.Errorf("written: %s", key)
	}
}

// §11.8's write row: other bytes at the batch's key are a fault that alarms, and nothing of this batch stands.
func TestBatchOtherBytesAtItsKeyRefuseTheBatch(t *testing.T) {
	fixture := newBatchFixture(t, nil)
	cluster, _ := fixture.host.Blobs.Cluster("meta-1")
	key := BatchKey(BatchMinute(fixture.clock.Now()), fixture.writer.Instance(), 0)
	if _, err := cluster.PutIfNoneMatch(fixture.ctx, key, []byte("another process's batch"), nil); err != nil {
		t.Fatal(err)
	}
	_, err := fixture.writer.Append(fixture.paidCtx, "meta-1", testRecord("push-1", 100))
	if !errors.Is(err, ErrEvsBatchUnwritten) || !errors.Is(err, sidecar.ErrBlobImmutableMismatch) {
		t.Errorf("over other bytes: %v", err)
	}
}

func TestBatchRefusesARecordWhoseRequestNeverSpent(t *testing.T) {
	fixture := newBatchFixture(t, nil)
	if _, err := fixture.writer.Append(fixture.ctx, "meta-1", testRecord("push-1", 100)); !errors.Is(err, ErrWriteUnbudgeted) {
		t.Errorf("an unbudgeted record: %v", err)
	}
	record := testRecord("push-1", 100)
	record.Type = protocol.EvsBatchRecordType(9)
	if _, err := fixture.writer.Append(fixture.paidCtx, "meta-1", record); !errors.Is(err, sidecar.ErrEvsPushInvalid) {
		t.Errorf("a record of no type: %v", err)
	}
}

// Each process holds one open batch per metadata cluster, for repos placed there.
func TestBatchKeepsOneOpenBatchPerCluster(t *testing.T) {
	fixture := newBatchFixture(t, func(settings *EvsSettings) {
		settings.BatchLightLoadRecordCount = 1
	})
	first := fixture.appendAsync("meta-1", testRecord("push-1", 100))
	second := fixture.appendAsync("meta-2", testRecord("push-2", 100))
	fixture.awaitAppended(2)
	fixture.clock.Advance(20 * time.Millisecond)
	firstPlace := awaitResult(t, first).place
	secondPlace := awaitResult(t, second).place
	if fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpPut) != 1 || fixture.host.Blobs.RequestCount("meta-2", sidecartest.FaultOpPut) != 1 {
		t.Error("records crossed clusters")
	}
	if PlaceBatchKey(firstPlace) == PlaceBatchKey(secondPlace) {
		t.Error("one key on two clusters")
	}
}

// §11.8's read and cache rows: a record read by range at its place, then from the process's cache; an evacuated
// batch says so.
func TestReadRecordByRangeThenFromTheCache(t *testing.T) {
	fixture := newBatchFixture(t, nil)
	place, err := fixture.writer.Append(fixture.paidCtx, "meta-1", testRecord("push-1", 100))
	if err != nil {
		t.Fatal(err)
	}
	cluster, _ := fixture.host.Blobs.Cluster("meta-1")
	// the writer's own cache holds what it wrote
	if _, err := ReadRecord(fixture.ctx, fixture.records, cluster, place); err != nil {
		t.Fatal(err)
	}
	if _, readCount, _ := fixture.records.Counts(); readCount != 0 {
		t.Errorf("the writer's cache read the store %d times", readCount)
	}
	cache := NewRecordCache(fixture.settings)
	for i := 0; i < 2; i += 1 {
		record, err := ReadRecord(fixture.ctx, cache, cluster, place)
		if err != nil || record.PushId != testId("push-1") {
			t.Fatalf("read %d: %v %v", i, record, err)
		}
	}
	if hitCount, readCount, _ := cache.Counts(); hitCount != 1 || readCount != 1 {
		t.Errorf("%d hits and %d reads", hitCount, readCount)
	}
	gone := &protocol.EvsPlace{Minute: place.GetMinute() - 1500, Instance: 1, Seq: 1, Offset: 32, Length: 100}
	if _, err := ReadRecord(fixture.ctx, cache, cluster, gone); !errors.Is(err, ErrEvsRecordEvacuated) {
		t.Errorf("an evacuated batch: %v", err)
	}
	// a place past its batch's end, or naming no whole record, is no record
	short := &protocol.EvsPlace{Minute: place.GetMinute(), Instance: place.GetInstance(), Seq: place.GetSeq(), Offset: place.GetOffset(), Length: place.GetLength() - 1}
	if _, err := ReadRecord(fixture.ctx, cache, cluster, short); !errors.Is(err, sidecar.ErrEvsPushInvalid) {
		t.Errorf("a short place: %v", err)
	}
}

// A cached record holds its own bytes, not a slice of its whole batch, so the cache's byte bound counts what it pins.
func TestBatchCachesEachRecordApartFromItsBatch(t *testing.T) {
	fixture := newBatchFixture(t, func(settings *EvsSettings) {
		settings.BatchLightLoadRecordCount = 1
	})
	first := fixture.appendAsync("meta-1", testRecord("push-1", 100))
	second := fixture.appendAsync("meta-1", testRecord("push-2", 100))
	fixture.awaitAppended(2)
	fixture.clock.Advance(20 * time.Millisecond)
	places := []*protocol.EvsPlace{awaitResult(t, first).place, awaitResult(t, second).place}
	for _, place := range places {
		cached, ok := fixture.records.Get("meta-1", place)
		if !ok || len(cached) != int(place.GetLength()) {
			t.Fatalf("not cached: %v", place)
		}
		// a slice of the batch would reach to its end, past both records
		if 2*len(cached) <= cap(cached) {
			t.Errorf("a cached record of %d bytes pins %d", len(cached), cap(cached))
		}
	}
}
