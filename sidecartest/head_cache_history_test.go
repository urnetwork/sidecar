package sidecartest

import (
	"bytes"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// The head cache's put script as evsservice names it; the twin answers it by Name alone.
var headCachePutScriptForTest = &sidecar.RedisScript{Name: evsHeadCachePutScriptName, Source: "-- the twin runs"}

type headCacheRecorderFixture struct {
	clock      *FakeClock
	faults     *FaultQueue
	redis      *FakeRedis
	storeCount int
	recorder   *HeadCacheRecorder
	recorded   sidecar.Redis
}

// A fake Redis with evs's twins, wrapped by a recorder whose blob history count the test sets.
func newHeadCacheRecorderFixture(t *testing.T) *headCacheRecorderFixture {
	clock := NewFakeClock(DefaultClockStart())
	faults := NewFaultQueue()
	redis := NewFakeRedis(t.Context(), clock, faults, nil, nil)
	t.Cleanup(redis.Close)
	RegisterEvsTwins(redis)
	fixture := &headCacheRecorderFixture{clock: clock, faults: faults, redis: redis}
	fixture.recorder = NewHeadCacheRecorder(clock, func() int { return fixture.storeCount })
	fixture.recorded = fixture.recorder.Wrap(redis)
	return fixture
}

// The cache's put of entry as ref's version, as HeadCache.Write runs it.
func (self *headCacheRecorderFixture) put(t *testing.T, key string, ref string, version string, entry []byte) *sidecar.RedisReply {
	t.Helper()
	reply, err := self.recorded.RunScript(t.Context(), headCachePutScriptForTest, []string{key}, []string{ref, version, string(entry), "600000"})
	if err != nil {
		t.Fatal(err)
	}
	return reply
}

// The cache's own requests are kept, each with what it carried or answered, its times and the blob history's count at
// its call and at its answer; a put the script declines is kept as kept, and a get of a field the key lacks as absent.
func TestHeadCacheRecorderKeepsTheCachesRequests(t *testing.T) {
	fixture := newHeadCacheRecorderFixture(t)
	start := fixture.clock.Now()
	fixture.storeCount = 7
	if reply := fixture.put(t, "{evsh_r}", "f", "3", []byte("entry 3")); reply.Integer != 1 {
		t.Fatalf("the put replied %d", reply.Integer)
	}
	fixture.clock.Advance(time.Minute)
	fixture.storeCount = 9
	if reply := fixture.put(t, "{evsh_r}", "f", "2", []byte("entry 2")); reply.Integer != 0 {
		t.Fatalf("a lower version's put replied %d", reply.Integer)
	}
	value, found, err := fixture.recorded.HashGet(t.Context(), "{evsh_r}", "f")
	if err != nil || !found || !bytes.Equal(value, []byte("entry 3")) {
		t.Fatalf("the get answered %q %t %v", value, found, err)
	}
	if _, found, err := fixture.recorded.HashGet(t.Context(), "{evsh_r}", "g"); err != nil || found {
		t.Fatalf("a field never put answered %t %v", found, err)
	}
	history := fixture.recorder.History()
	if len(history) != 4 || fixture.recorder.Count() != 4 {
		t.Fatalf("%d requests kept, %d counted", len(history), fixture.recorder.Count())
	}
	expected := []struct {
		op      HeadCacheHistoryOp
		field   string
		entry   string
		outcome HeadCacheOutcome
		at      time.Time
		store   int
	}{
		{op: HeadCacheHistoryPut, field: "f", entry: "entry 3", outcome: HeadCacheOutcomeOk, at: start, store: 7},
		{op: HeadCacheHistoryPut, field: "f", entry: "entry 2", outcome: HeadCacheOutcomeKept, at: start.Add(time.Minute), store: 9},
		{op: HeadCacheHistoryGet, field: "f", entry: "entry 3", outcome: HeadCacheOutcomeOk, at: start.Add(time.Minute), store: 9},
		{op: HeadCacheHistoryGet, field: "g", entry: "", outcome: HeadCacheOutcomeAbsent, at: start.Add(time.Minute), store: 9},
	}
	for i, c := range expected {
		entry := history[i]
		if entry.Op != c.op || entry.Key != "{evsh_r}" || entry.Field != c.field || string(entry.Entry) != c.entry || entry.Outcome != c.outcome {
			t.Errorf("request %d: %s %s %s %q %s", i, entry.Op, entry.Key, entry.Field, entry.Entry, entry.Outcome)
		}
		if !entry.Invoked.Equal(c.at) || !entry.Returned.Equal(c.at) || entry.StoreInvoked != c.store || entry.StoreReturned != c.store {
			t.Errorf("request %d: called %s at %d, answered %s at %d", i, entry.Invoked, entry.StoreInvoked, entry.Returned, entry.StoreReturned)
		}
	}
	// a copy is the caller's own
	history[0].Entry[0] = 'x'
	if again := fixture.recorder.History(); string(again[0].Entry) != "entry 3" {
		t.Errorf("a change to a copy reached the record: %q", again[0].Entry)
	}
}

// Every other request passes through unkept: another family's key, a ref's version field, another script, and an
// oracle's look under InspectContext.
func TestHeadCacheRecorderKeepsNothingElse(t *testing.T) {
	fixture := newHeadCacheRecorderFixture(t)
	fixture.put(t, "{evsh_r}", "f", "3", []byte("entry 3"))
	if err := fixture.recorded.HashSet(t.Context(), "{evsq_r}", map[string][]byte{"f": []byte("other")}); err != nil {
		t.Fatal(err)
	}
	if value, found, err := fixture.recorded.HashGet(t.Context(), "{evsq_r}", "f"); err != nil || !found || string(value) != "other" {
		t.Fatalf("another family's get answered %q %t %v", value, found, err)
	}
	if value, found, err := fixture.recorded.HashGet(t.Context(), "{evsh_r}", "v:f"); err != nil || !found || string(value) != "3" {
		t.Fatalf("the version field answered %q %t %v", value, found, err)
	}
	if _, err := fixture.recorded.RunScript(t.Context(), &sidecar.RedisScript{Name: evsNightlySumsWriteScriptName}, []string{"{evsn_1}"}, []string{"f", "1", "600000"}); err != nil {
		t.Fatal(err)
	}
	if value, found, err := fixture.recorded.HashGet(InspectContext(t.Context()), "{evsh_r}", "f"); err != nil || !found || string(value) != "entry 3" {
		t.Fatalf("an inspecting get answered %q %t %v", value, found, err)
	}
	if history := fixture.recorder.History(); len(history) != 1 || history[0].Op != HeadCacheHistoryPut {
		t.Fatalf("kept %d requests: %v", len(history), history)
	}
}

// A request with no answer is kept as such: a put whose write failed before it applied is unknown, as one whose
// answer was lost would be, and a get that failed is failed, answering no entry.
func TestHeadCacheRecorderKeepsAFailedRequest(t *testing.T) {
	fixture := newHeadCacheRecorderFixture(t)
	if _, err := fixture.faults.Add(&FaultPlan{Op: FaultOpRedis, KeyPrefix: "{evsh_r}", Result: FailBeforeApply, Repeat: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.recorded.RunScript(t.Context(), headCachePutScriptForTest, []string{"{evsh_r}"}, []string{"f", "3", "entry 3", "600000"}); err == nil {
		t.Fatal("the failed put answered")
	}
	if _, _, err := fixture.recorded.HashGet(t.Context(), "{evsh_r}", "f"); err == nil {
		t.Fatal("the failed get answered")
	}
	history := fixture.recorder.History()
	if len(history) != 2 || history[0].Outcome != HeadCacheOutcomeUnknown || history[1].Outcome != HeadCacheOutcomeFailed || history[1].Entry != nil {
		t.Fatalf("kept %v", history)
	}
	if string(history[0].Entry) != "entry 3" {
		t.Errorf("the failed put kept %q", history[0].Entry)
	}
}

// Wrapping a Redis the recorder already wraps returns it as it is, so a host given back to AddEngines records each
// request once; nil stays nil.
func TestHeadCacheRecorderWrapsOnce(t *testing.T) {
	fixture := newHeadCacheRecorderFixture(t)
	if again := fixture.recorder.Wrap(fixture.recorded); again != fixture.recorded {
		t.Error("a second wrap made another recorder's layer")
	}
	if fixture.recorder.Wrap(nil) != nil {
		t.Error("nil wrapped into something")
	}
	other := NewHeadCacheRecorder(fixture.clock, func() int { return 0 })
	if other.Wrap(fixture.recorded) == fixture.recorded {
		t.Error("another recorder took this one's layer as its own")
	}
}

// The Net keeps the head cache's requests of every engine on its host beside the blob history, each request once
// though a test hands the host back to AddEngines, the actor its caller ran as and the blob history's count with it.
func TestNetRecordsTheHeadCacheOfItsEngines(t *testing.T) {
	net := newTestNet(t)
	RegisterEvsTwins(net.Fakes().Redis)
	host := *net.Host()
	net.AddEngines(&host)
	cluster, err := net.Host().Blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.PutIfNoneMatch(t.Context(), "head/a/_", []byte("v1"), nil); err != nil {
		t.Fatal(err)
	}
	actor := net.Actors().Actor(t.Context(), "evs1")
	if _, err := net.Host().Redis.RunScript(actor.Context(), headCachePutScriptForTest, []string{"{evsh_a}"}, []string{"f", "1", "entry 1", "600000"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := net.Host().Redis.HashGet(actor.Context(), "{evsh_a}", "f"); err != nil {
		t.Fatal(err)
	}
	history := net.HeadCacheHistory()
	if len(history) != 2 || net.HeadCacheHistoryCount() != 2 {
		t.Fatalf("kept %d requests, counted %d", len(history), net.HeadCacheHistoryCount())
	}
	for _, entry := range history {
		if entry.Actor != "evs1" || entry.StoreInvoked != 1 || entry.StoreReturned != 1 || entry.Outcome != HeadCacheOutcomeOk {
			t.Errorf("kept %s by %q at store counts %d and %d, %s", entry.Op, entry.Actor, entry.StoreInvoked, entry.StoreReturned, entry.Outcome)
		}
	}
}
