package evsservice

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"maps"
	"math"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One write to a count store.
type fakeNightlyCountWrite struct {
	networkId       sidecar.Id
	storedByteCount int64
}

// T2's NightlyCountStore: each network's count as network_quota_state holds it, and every write in order. Safe for
// concurrent use.
type fakeNightlyCounts struct {
	stateLock sync.Mutex
	counts    map[sidecar.Id]int64
	writes    []fakeNightlyCountWrite
	// every write fails with this, when set
	failure error
}

func newFakeNightlyCounts() *fakeNightlyCounts {
	return &fakeNightlyCounts{counts: map[sidecar.Id]int64{}}
}

func (self *fakeNightlyCounts) SetStoredByteCount(ctx context.Context, networkId sidecar.Id, storedByteCount int64) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.failure != nil {
		return self.failure
	}
	self.counts[networkId] = storedByteCount
	self.writes = append(self.writes, fakeNightlyCountWrite{networkId: networkId, storedByteCount: storedByteCount})
	return nil
}

func (self *fakeNightlyCounts) NetworkIdsWithStoredByteCount(ctx context.Context, after *sidecar.Id, limit int) ([]sidecar.Id, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	networkIds := []sidecar.Id{}
	for _, networkId := range slices.SortedFunc(maps.Keys(self.counts), func(a sidecar.Id, b sidecar.Id) int { return bytes.Compare(a[:], b[:]) }) {
		if self.counts[networkId] <= 0 || (after != nil && bytes.Compare(networkId[:], after[:]) <= 0) {
			continue
		}
		if len(networkIds) == limit {
			break
		}
		networkIds = append(networkIds, networkId)
	}
	return networkIds, nil
}

// Sets a count as an earlier night or usage batches left it, with no write recorded.
func (self *fakeNightlyCounts) hold(networkId sidecar.Id, storedByteCount int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.counts[networkId] = storedByteCount
}

func (self *fakeNightlyCounts) count(networkId sidecar.Id) int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.counts[networkId]
}

// Writes so far, by network, and how many each took.
func (self *fakeNightlyCounts) written() (map[sidecar.Id]int64, map[sidecar.Id]int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	values := map[sidecar.Id]int64{}
	writeCounts := map[sidecar.Id]int{}
	for _, write := range self.writes {
		values[write.networkId] = write.storedByteCount
		writeCounts[write.networkId] += 1
	}
	return values, writeCounts
}

func (self *fakeNightlyCounts) clearWrites() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.writes = nil
}

// A night's sums on a fake Redis, with two metadata clusters of four shards each.
type nightlyCloseFixture struct {
	t           *testing.T
	ctx         context.Context
	clock       *sidecartest.FakeClock
	host        *sidecartest.FakeHost
	settings    *NightlyPassSettings
	sums        *NightlySums
	counts      *fakeNightlyCounts
	night       int64
	shardFields []string
	// called once every shard has reported, before the sums are read
	afterReported func()
}

func newNightlyCloseFixture(t *testing.T) *nightlyCloseFixture {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	hostSettings := sidecartest.DefaultFakeHostSettings()
	hostSettings.Redis.Report = func(violation string) { t.Errorf("redis: %s", violation) }
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, hostSettings)
	sidecartest.RegisterEvsTwins(host.Redis)
	settings := DefaultNightlyPassSettings()
	sums, err := NewNightlySums(host.Redis, settings)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &nightlyCloseFixture{
		t:        t,
		ctx:      ctx,
		clock:    clock,
		host:     host,
		settings: settings,
		sums:     sums,
		counts:   newFakeNightlyCounts(),
		night:    clock.Now().UnixMilli(),
	}
	for _, clusterId := range []string{"meta-1", "meta-2"} {
		for _, shard := range []string{"0", "1", "2", "3"} {
			fixture.shardFields = append(fixture.shardFields, NightlyShardField(clusterId, shard))
		}
	}
	return fixture
}

func (self *nightlyCloseFixture) report(clusterId string, shard string, networkByteCounts map[sidecar.Id]int64) {
	self.t.Helper()
	if err := self.sums.Report(self.ctx, self.night, clusterId, shard, networkByteCounts); err != nil {
		self.t.Fatal(err)
	}
}

func (self *nightlyCloseFixture) args() []byte {
	return EvsNightlyCloseArgsBytes(&EvsNightlyCloseArgs{Night: self.night, ShardFields: self.shardFields})
}

// One run of the closing job, which must end clean.
func (self *nightlyCloseFixture) close() *NightlyCloseResult {
	self.t.Helper()
	result, err := RunNightlyClose(self.ctx, self.host.ServiceHost(), &NightlyCloseDeps{
		Counts:        self.counts,
		Settings:      self.settings,
		afterReported: self.afterReported,
	}, self.args())
	if err != nil {
		self.t.Fatalf("close: %v (%+v)", err, result)
	}
	return result
}

// The closing job's requests the queue holds, for this night.
func (self *nightlyCloseFixture) pendingCloses() []*sidecar.TaskRequest {
	requests := []*sidecar.TaskRequest{}
	for _, request := range self.host.Tasks.Pending() {
		if request.Name == EvsNightlyCloseTaskName {
			requests = append(requests, request)
		}
	}
	return requests
}

// A shard's sums go back whole from Redis: each network's count, in id order, and a shard with no network reads as
// reported with none.
func TestNightlySumsRoundTripAShardsCounts(t *testing.T) {
	fixture := newNightlyCloseFixture(t)
	networkA, networkB := testId("network a"), testId("network b")
	fixture.report("meta-1", "0", map[sidecar.Id]int64{networkA: 100, networkB: 1 << 40})
	fixture.report("meta-1", "1", map[sidecar.Id]int64{})

	counts, found, err := fixture.sums.Read(fixture.ctx, fixture.night, "meta-1", "0")
	if err != nil || !found || len(counts) != 2 || counts[networkA] != 100 || counts[networkB] != 1<<40 {
		t.Fatalf("shard 0: %v %t %v", counts, found, err)
	}
	counts, found, err = fixture.sums.Read(fixture.ctx, fixture.night, "meta-1", "1")
	if err != nil || !found || len(counts) != 0 {
		t.Fatalf("the empty shard: %v %t %v", counts, found, err)
	}
	if _, found, err := fixture.sums.Read(fixture.ctx, fixture.night, "meta-1", "2"); err != nil || found {
		t.Fatalf("a shard that never reported: %t %v", found, err)
	}
	missing, err := fixture.sums.Missing(fixture.ctx, fixture.night, fixture.shardFields)
	if err != nil || len(missing) != 6 || slices.Contains(missing, "meta-1:0") || slices.Contains(missing, "meta-1:1") {
		t.Fatalf("missing %v %v", missing, err)
	}
	// the night's one key, under evs-9's family, holding nothing but the shards' fields
	dump := fixture.host.Redis.Dump()
	if len(dump) != 1 {
		t.Fatalf("keys %v", slices.Collect(maps.Keys(dump)))
	}
	if _, ok := dump[NightlySumsKey(fixture.night)]; !ok {
		t.Fatalf("keys %v", slices.Collect(maps.Keys(dump)))
	}
}

// A rerun shard replaces its sums: a network it no longer counts is gone, and nothing adds to what it wrote.
func TestNightlySumsRerunReplacesAShardsSums(t *testing.T) {
	fixture := newNightlyCloseFixture(t)
	networkA, networkB := testId("network a"), testId("network b")
	fixture.report("meta-1", "0", map[sidecar.Id]int64{networkA: 100, networkB: 7})
	fixture.report("meta-1", "0", map[sidecar.Id]int64{networkA: 30})
	counts, found, err := fixture.sums.Read(fixture.ctx, fixture.night, "meta-1", "0")
	if err != nil || !found || len(counts) != 1 || counts[networkA] != 30 {
		t.Fatalf("after a rerun: %v %t %v", counts, found, err)
	}
}

// The night's key lives NightlySumsTtl from its first write, which a later write leaves: a night whose first shard
// reported 48 h ago is gone whole.
func TestNightlySumsLiveTheirTtlFromTheNightsFirstWrite(t *testing.T) {
	fixture := newNightlyCloseFixture(t)
	fixture.report("meta-1", "0", map[sidecar.Id]int64{testId("network a"): 1})
	fixture.clock.Advance(47 * time.Hour)
	fixture.report("meta-1", "1", map[sidecar.Id]int64{testId("network b"): 2})
	fixture.clock.Advance(time.Hour - time.Millisecond)
	if missing, err := fixture.sums.Missing(fixture.ctx, fixture.night, fixture.shardFields[:2]); err != nil || len(missing) != 0 {
		t.Fatalf("before 48 h: %v %v", missing, err)
	}
	fixture.clock.Advance(time.Millisecond)
	if missing, err := fixture.sums.Missing(fixture.ctx, fixture.night, fixture.shardFields[:2]); err != nil || len(missing) != 2 {
		t.Fatalf("at 48 h: %v %v", missing, err)
	}
	if len(fixture.host.Redis.Dump()) != 0 {
		t.Fatal("a key outlived its ttl")
	}

	settings := DefaultNightlyPassSettings()
	settings.NightlySumsTtl = 48*time.Hour + time.Second
	if err := settings.Validate(); !errors.Is(err, ErrNightlyPassSettings) {
		t.Fatalf("a ttl past §2.8's: %v", err)
	}
}

// A shard's value is whole entries of an id and a count, in rising id order: anything else is unread, and a
// negative count is never written.
func TestNightlySumsValueRefusesBytesOfAnotherShape(t *testing.T) {
	networkA, networkB := testId("network a"), testId("network b")
	value, err := encodeNightlySums(map[sidecar.Id]int64{networkB: 2, networkA: 1})
	if err != nil || len(value) != 2*evsNightlySumsEntryByteCount {
		t.Fatalf("%x %v", value, err)
	}
	counts, err := decodeNightlySums(value)
	if err != nil || len(counts) != 2 || counts[networkA] != 1 || counts[networkB] != 2 {
		t.Fatalf("%v %v", counts, err)
	}
	if _, err := encodeNightlySums(map[sidecar.Id]int64{networkA: -1}); !errors.Is(err, ErrNightlySumsValue) {
		t.Fatalf("a negative count: %v", err)
	}
	entry := func(networkId sidecar.Id, byteCount uint64) []byte {
		return binary.BigEndian.AppendUint64(slices.Clone(networkId[:]), byteCount)
	}
	first, second := entry(networkA, 1), entry(networkB, 2)
	if bytes.Compare(networkA[:], networkB[:]) > 0 {
		first, second = second, first
	}
	for name, bad := range map[string][]byte{
		"a cut entry":         first[:evsNightlySumsEntryByteCount-1],
		"out of order":        slices.Concat(second, first),
		"a network twice":     slices.Concat(first, first),
		"a count past int64s": entry(networkA, math.MaxInt64+1),
	} {
		if _, err := decodeNightlySums(bad); !errors.Is(err, ErrNightlySumsValue) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Two clusters by four shards combine to one write per network, its sum over every shard of every cluster, and a
// network with a count that no shard summed is written zero; a network with no count and no sum is not written.
func TestNightlyCloseCombinesEveryShardOfEveryClusterToOneWritePerNetwork(t *testing.T) {
	fixture := newNightlyCloseFixture(t)
	networkA, networkB, gone := testId("network a"), testId("network b"), testId("network gone")
	fixture.counts.hold(networkA, 5)
	fixture.counts.hold(gone, 900)
	want := map[sidecar.Id]int64{networkA: 0, networkB: 0}
	for index, field := range fixture.shardFields {
		clusterId, shard := field[:len("meta-1")], field[len("meta-1:"):]
		counts := map[sidecar.Id]int64{networkA: int64(10 * (index + 1))}
		if index%3 == 0 {
			counts[networkB] = int64(1000 + index)
		}
		if index == 5 {
			counts = map[sidecar.Id]int64{}
		}
		for networkId, byteCount := range counts {
			want[networkId] += byteCount
		}
		fixture.report(clusterId, shard, counts)
	}
	want[gone] = 0

	result := fixture.close()
	if result.Waiting || result.Unfinished || result.Lost || result.SetCount != 2 || result.ZeroCount != 1 {
		t.Fatalf("result %+v", result)
	}
	values, writeCounts := fixture.counts.written()
	if !maps.Equal(values, want) {
		t.Fatalf("wrote %v, want %v", values, want)
	}
	for networkId, writeCount := range writeCounts {
		if writeCount != 1 {
			t.Fatalf("%s written %d times", networkId, writeCount)
		}
	}
	if len(fixture.pendingCloses()) != 0 {
		t.Fatal("a finished night asked again")
	}
}

// The closing job run twice writes the same: it reads the same sums and makes the same absolute writes.
func TestNightlyCloseRunTwiceWritesTheSame(t *testing.T) {
	fixture := newNightlyCloseFixture(t)
	networkA := testId("network a")
	fixture.counts.hold(testId("network gone"), 3)
	for index, field := range fixture.shardFields {
		fixture.report(field[:len("meta-1")], field[len("meta-1:"):], map[sidecar.Id]int64{networkA: int64(index)})
	}
	fixture.close()
	first, _ := fixture.counts.written()
	fixture.counts.clearWrites()
	second := fixture.close()
	again, _ := fixture.counts.written()
	// the zeroed network holds no count the second time, so only the sum is written again
	if second.SetCount != 1 || second.ZeroCount != 0 || again[networkA] != first[networkA] || fixture.counts.count(networkA) != 28 {
		t.Fatalf("first %v, again %v (%+v)", first, again, second)
	}
}

// A shard that has not reported holds the night: the job asks again in NightlyCloseRetryInterval, writing nothing,
// until the night is NightlySumsTtl old, and then ends writing nothing, so the old counts stand.
func TestNightlyCloseWaitsForAMissingShardThenLeavesTheOldCount(t *testing.T) {
	fixture := newNightlyCloseFixture(t)
	networkA := testId("network a")
	fixture.counts.hold(networkA, 77)
	for _, field := range fixture.shardFields[:7] {
		fixture.report(field[:len("meta-1")], field[len("meta-1:"):], map[sidecar.Id]int64{networkA: 1})
	}

	result := fixture.close()
	if !result.Waiting || result.Unfinished || !slices.Equal(result.MissingShardFields, []string{"meta-2:3"}) {
		t.Fatalf("result %+v", result)
	}
	pending := fixture.pendingCloses()
	if len(pending) != 1 || !pending[0].RunAt.Equal(fixture.clock.Now().Add(10*time.Minute)) ||
		pending[0].OnceKey != EvsNightlyCloseTaskRequest(&EvsNightlyCloseArgs{Night: fixture.night}, time.Time{}, nil).OnceKey {
		t.Fatalf("pending %+v", pending)
	}
	if values, _ := fixture.counts.written(); len(values) != 0 || fixture.counts.count(networkA) != 77 {
		t.Fatalf("a waiting night wrote %v", values)
	}

	fixture.clock.Advance(48*time.Hour - time.Millisecond)
	if result := fixture.close(); !result.Waiting {
		t.Fatalf("just under 48 h: %+v", result)
	}
	fixture.clock.Advance(time.Millisecond)
	// the night's key outlived nothing: every shard reads as missing now, and the night ends
	result = fixture.close()
	if result.Waiting || !result.Unfinished || result.SetCount != 0 || result.ZeroCount != 0 {
		t.Fatalf("at 48 h: %+v", result)
	}
	if values, _ := fixture.counts.written(); len(values) != 0 || fixture.counts.count(networkA) != 77 {
		t.Fatalf("an unfinished night wrote %v", values)
	}
}

// A reported shard whose sums are gone is a lost night: with its key expired past the night's ttl, and with the key
// lost between the check that every shard reported and the read, nothing is written and the old count stands.
func TestNightlyCloseWritesNothingWhenAReportedShardsSumsAreGone(t *testing.T) {
	fixture := newNightlyCloseFixture(t)
	networkA := testId("network a")
	fixture.counts.hold(networkA, 77)
	for _, field := range fixture.shardFields {
		fixture.report(field[:len("meta-1")], field[len("meta-1:"):], map[sidecar.Id]int64{networkA: 1})
	}
	fixture.afterReported = func() { fixture.host.Redis.LoseKeys(NightlySumsKey(fixture.night)) }
	result := fixture.close()
	if !result.Lost || result.SetCount != 0 || result.ZeroCount != 0 || len(fixture.pendingCloses()) != 0 {
		t.Fatalf("lost between the reads: %+v", result)
	}
	if values, _ := fixture.counts.written(); len(values) != 0 || fixture.counts.count(networkA) != 77 {
		t.Fatalf("a lost night wrote %v", values)
	}

	expired := newNightlyCloseFixture(t)
	expired.counts.hold(networkA, 77)
	for _, field := range expired.shardFields {
		expired.report(field[:len("meta-1")], field[len("meta-1:"):], map[sidecar.Id]int64{networkA: 1})
	}
	expired.clock.Advance(48 * time.Hour)
	result = expired.close()
	if !result.Unfinished || result.SetCount != 0 || len(expired.pendingCloses()) != 0 {
		t.Fatalf("expired: %+v", result)
	}
	if values, _ := expired.counts.written(); len(values) != 0 || expired.counts.count(networkA) != 77 {
		t.Fatalf("an expired night wrote %v", values)
	}
}

// A count store this build lacks ends the job with nothing written and no error; one that fails is the run's error,
// after every other network was tried, and the rerun writes them all.
func TestNightlyCloseOnAStoreThatFails(t *testing.T) {
	fixture := newNightlyCloseFixture(t)
	networkA, networkB := testId("network a"), testId("network b")
	for _, field := range fixture.shardFields {
		fixture.report(field[:len("meta-1")], field[len("meta-1:"):], map[sidecar.Id]int64{networkA: 1, networkB: 2})
	}
	fixture.counts.failure = ErrNightlyCountsUnavailable
	if result := fixture.close(); !result.CountsUnavailable || result.SetCount != 0 {
		t.Fatalf("unavailable: %+v", result)
	}
	failure := errors.New("postgres is away")
	fixture.counts.failure = failure
	result, err := RunNightlyClose(fixture.ctx, fixture.host.ServiceHost(), &NightlyCloseDeps{Counts: fixture.counts, Settings: fixture.settings}, fixture.args())
	if !errors.Is(err, failure) || result.SetCount != 0 {
		t.Fatalf("failing: %+v %v", result, err)
	}
	fixture.counts.failure = nil
	if result := fixture.close(); result.SetCount != 2 || fixture.counts.count(networkA) != 8 || fixture.counts.count(networkB) != 16 {
		t.Fatalf("the rerun: %+v", result)
	}
}

func TestEvsNightlyCloseArgsRoundTrip(t *testing.T) {
	args := &EvsNightlyCloseArgs{Night: 1762819200123, ShardFields: []string{"meta-1:0", "meta-1:1", "meta-2:"}}
	parsed, ok := ParseEvsNightlyCloseArgs(EvsNightlyCloseArgsBytes(args))
	if !ok || parsed.Night != args.Night || !slices.Equal(parsed.ShardFields, args.ShardFields) {
		t.Fatalf("%+v %t", parsed, ok)
	}
	for _, bad := range []string{"", "1762819200123", "night\nmeta-1:0", "0\nmeta-1:0", "1762819200123\nmeta-1:0\n"} {
		if _, ok := ParseEvsNightlyCloseArgs([]byte(bad)); ok {
			t.Errorf("%q read as a closing job's args", bad)
		}
	}
	request := EvsNightlyCloseTaskRequest(args, time.Time{}, nil)
	other := EvsNightlyCloseTaskRequest(&EvsNightlyCloseArgs{Night: args.Night + 1, ShardFields: args.ShardFields}, time.Time{}, nil)
	if request.Name != EvsNightlyCloseTaskName || request.OnceKey == other.OnceKey || request.MaxTime <= 0 {
		t.Fatalf("requests %+v %+v", request, other)
	}
}
