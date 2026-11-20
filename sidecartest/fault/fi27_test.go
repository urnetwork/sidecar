// FI-27's cached-head clause (QD-1146; fi27.go's fi27CachedRead) on records built by hand: what lets a reuse copy
// validated on a cached head through, and every way a record falls short of it. FS-91 (c)'s schedule runs the clause
// on the engine's own records (fs91_test.go).

package fault

import (
	"encoding/binary"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A head cache entry in evsservice/head_cache.go's layout, written apart from the oracle's reading of it.
func fi27TestCacheEntry(t *testing.T, version uint64, etag string, head *protocol.EvsHead) []byte {
	t.Helper()
	headBytes, err := proto.Marshal(head)
	if err != nil {
		t.Fatal(err)
	}
	entry := binary.BigEndian.AppendUint64(nil, version)
	// the push sequence and cached_ms, which the oracle does not read
	entry = binary.BigEndian.AppendUint64(entry, 7)
	entry = binary.BigEndian.AppendUint64(entry, uint64(head.GetWrittenMs()))
	entry = binary.BigEndian.AppendUint16(entry, uint16(len(etag)))
	entry = append(entry, etag...)
	return append(entry, headBytes...)
}

// A record in which a copy's push read a cached head below its DROP: the source ref s's head at version 3, written at
// the clock's start and put into the cache then; the DROP at version 4; the copy's attempt arriving on evs2, whose
// step 4 reads s's entry 2 min on; and the copy's head write right after.
type fi27CachedReadFixture struct {
	start        time.Time
	blobHistory  []*sidecartest.BlobHistoryEntry
	cacheHistory []*sidecartest.HeadCacheHistoryEntry
	terms        *fi27CachedReadTerms
	settings     *Fi27Settings
}

func newFi27CachedReadFixture(t *testing.T) *fi27CachedReadFixture {
	start := sidecartest.DefaultClockStart()
	read := start.Add(2 * time.Minute)
	entry := fi27TestCacheEntry(t, 3, "etag-3", &protocol.EvsHead{Version: 3, WrittenMs: start.UnixMilli()})
	blobHistory := []*sidecartest.BlobHistoryEntry{
		{ClusterId: "meta-1", Op: sidecartest.BlobHistoryPutIfMatch, Key: "head/r/s", WriteEtag: "etag-3", Outcome: sidecartest.BlobOutcomeOk, Invoked: start, Returned: start},
		{ClusterId: "meta-1", Op: sidecartest.BlobHistoryPutIfMatch, Key: "head/r/s", WriteEtag: "etag-4", Outcome: sidecartest.BlobOutcomeOk, Invoked: start.Add(time.Second), Returned: start.Add(time.Second)},
		{ClusterId: "meta-1", Op: sidecartest.BlobHistoryPutIfMatch, Key: "head/r/c", WriteEtag: "etag-copy", Outcome: sidecartest.BlobOutcomeOk, Invoked: read, Returned: read},
	}
	cacheHistory := []*sidecartest.HeadCacheHistoryEntry{
		{Actor: "evs1", Op: sidecartest.HeadCacheHistoryPut, Key: "{evsh_r}", Field: "s", Entry: entry, Outcome: sidecartest.HeadCacheOutcomeOk, Invoked: start, Returned: start, StoreInvoked: 1, StoreReturned: 1},
		{Actor: "evs2", Op: sidecartest.HeadCacheHistoryGet, Key: "{evsh_r}", Field: "s", Entry: entry, Outcome: sidecartest.HeadCacheOutcomeOk, Invoked: read, Returned: read, StoreInvoked: 2, StoreReturned: 2},
	}
	return &fi27CachedReadFixture{
		start:        start,
		blobHistory:  blobHistory,
		cacheHistory: cacheHistory,
		terms: &fi27CachedReadTerms{
			instance: "evs2", cacheArrival: 1, cacheKey: "{evsh_r}", cacheField: "s", clusterId: "meta-1", headKey: "head/r/s",
			dropVersion: 4, copyIndex: 2, copyWrite: blobHistory[2],
		},
		settings: DefaultFi27Settings(),
	}
}

// The read the fixture's get is.
func (self *fi27CachedReadFixture) get() *sidecartest.HeadCacheHistoryEntry {
	return self.cacheHistory[1]
}

// The get answers entry, which a put of it at at carried and a head write of its ETag at at wrote.
func (self *fi27CachedReadFixture) answer(entry []byte, etag string, at time.Time) {
	self.blobHistory[0] = &sidecartest.BlobHistoryEntry{
		ClusterId: "meta-1", Op: sidecartest.BlobHistoryPutIfMatch, Key: "head/r/s", WriteEtag: etag, Outcome: sidecartest.BlobOutcomeOk, Invoked: at, Returned: at,
	}
	self.cacheHistory[0].Entry = entry
	self.cacheHistory[0].Invoked = at
	self.cacheHistory[0].Returned = at
	self.get().Entry = entry
}

func (self *fi27CachedReadFixture) read() *sidecartest.HeadCacheHistoryEntry {
	return fi27CachedRead(self.cacheHistory, self.blobHistory, self.terms, self.settings)
}

// The copy's push read a head below the DROP from the cache, 2 min after that head's write, and its head write came
// at once: the read lets it through.
func TestFi27CachedReadLetsAFreshEntryBelowTheDropThrough(t *testing.T) {
	fixture := newFi27CachedReadFixture(t)
	if read := fixture.read(); read != fixture.get() {
		t.Fatalf("the copy's cached read did not let it through: %v", read)
	}
}

// A cached head showing the DROP, at its version or above, lets nothing through: a push validated on it that
// committed anyway is the bug FI-27's fence catches.
func TestFi27CachedReadRefusesAHeadShowingTheDrop(t *testing.T) {
	for _, version := range []uint64{4, 5} {
		fixture := newFi27CachedReadFixture(t)
		etag := "etag-shows-the-drop"
		fixture.answer(fi27TestCacheEntry(t, version, etag, &protocol.EvsHead{Version: version, WrittenMs: fixture.start.UnixMilli()}), etag, fixture.start)
		if read := fixture.read(); read != nil {
			t.Errorf("a cached head at version %d, the DROP at 4, let the copy through", version)
		}
	}
}

// The entry must be younger than the cache's age at the read's answer: §11.9's 10 min after its head's write, and not
// a moment more.
func TestFi27CachedReadRefusesAnEntryPastTheCacheAge(t *testing.T) {
	cases := []struct {
		age     time.Duration
		through bool
	}{
		{age: 10*time.Minute - time.Millisecond, through: true},
		{age: 10 * time.Minute, through: false},
		{age: 11 * time.Minute, through: false},
	}
	for _, c := range cases {
		fixture := newFi27CachedReadFixture(t)
		at := fixture.start.Add(c.age)
		fixture.get().Invoked = at
		fixture.get().Returned = at
		fixture.terms.copyWrite.Invoked = at
		if read := fixture.read(); (read != nil) != c.through {
			t.Errorf("an entry %s old at its read let the copy through: %t", c.age, read != nil)
		}
	}
	// and as FI-27's settings name it
	fixture := newFi27CachedReadFixture(t)
	fixture.settings.HeadCacheServeAge = time.Minute
	if read := fixture.read(); read != nil {
		t.Error("an entry 2 min old let the copy through with a cache age of 1 min")
	}
}

// An entry's age counts from the earliest of its head's write, the head's written_ms and its put: a put that came 11
// min after its head's write serves no longer, a written_ms stamped past the head's write does not stretch it, and a
// head with no written_ms never serves.
func TestFi27CachedReadAgesAnEntryFromItsHeadsWrite(t *testing.T) {
	// put 11 min after the head's write, read 1 s after the put
	fixture := newFi27CachedReadFixture(t)
	late := fixture.start.Add(11 * time.Minute)
	fixture.cacheHistory[0].Invoked = late
	fixture.cacheHistory[0].Returned = late
	fixture.get().Invoked = late.Add(time.Second)
	fixture.get().Returned = late.Add(time.Second)
	fixture.terms.copyWrite.Invoked = late.Add(time.Second)
	if read := fixture.read(); read != nil {
		t.Error("an entry put 11 min after its head's write let the copy through")
	}

	// written_ms 9 min past the head's write, read 10 min after that write
	fixture = newFi27CachedReadFixture(t)
	entry := fi27TestCacheEntry(t, 3, "etag-3", &protocol.EvsHead{Version: 3, WrittenMs: fixture.start.Add(9 * time.Minute).UnixMilli()})
	fixture.answer(entry, "etag-3", fixture.start)
	at := fixture.start.Add(10 * time.Minute)
	fixture.get().Invoked = at
	fixture.get().Returned = at
	fixture.terms.copyWrite.Invoked = at
	if read := fixture.read(); read != nil {
		t.Error("a written_ms past the head's write stretched the entry's age")
	}

	// no written_ms
	fixture = newFi27CachedReadFixture(t)
	fixture.answer(fi27TestCacheEntry(t, 3, "etag-3", &protocol.EvsHead{Version: 3}), "etag-3", fixture.start)
	if read := fixture.read(); read != nil {
		t.Error("a head with no written_ms let the copy through")
	}
}

// The copy's head write must come within step 7's 5 s of the read's call, and not a moment more.
func TestFi27CachedReadHoldsTheCopyToTheWindow(t *testing.T) {
	cases := []struct {
		after   time.Duration
		through bool
	}{
		{after: 5 * time.Second, through: true},
		{after: 5*time.Second + time.Millisecond, through: false},
	}
	for _, c := range cases {
		fixture := newFi27CachedReadFixture(t)
		fixture.terms.copyWrite.Invoked = fixture.get().Invoked.Add(c.after)
		if read := fixture.read(); (read != nil) != c.through {
			t.Errorf("a head write %s after the read let the copy through: %t", c.after, read != nil)
		}
	}
}

// Only the copy's own read counts: a get on its instance after the attempt arrived, answered before the copy's head
// write was issued, of the source ref's entry in the repo's key, that answered an entry.
func TestFi27CachedReadTakesOnlyTheCopysOwnRead(t *testing.T) {
	cases := []struct {
		name  string
		apply func(fixture *fi27CachedReadFixture)
	}{
		{name: "a get before the attempt arrived", apply: func(fixture *fi27CachedReadFixture) { fixture.terms.cacheArrival = 2 }},
		{name: "another instance's get", apply: func(fixture *fi27CachedReadFixture) { fixture.get().Actor = "evs1" }},
		{name: "a get answered after the copy's head write", apply: func(fixture *fi27CachedReadFixture) { fixture.get().StoreReturned = 3 }},
		{name: "another ref's entry", apply: func(fixture *fi27CachedReadFixture) { fixture.get().Field = "t" }},
		{name: "another repo's key", apply: func(fixture *fi27CachedReadFixture) { fixture.get().Key = "{evsh_q}" }},
		{name: "a put, not a get", apply: func(fixture *fi27CachedReadFixture) { fixture.get().Op = sidecartest.HeadCacheHistoryPut }},
		{name: "a get of an absent field", apply: func(fixture *fi27CachedReadFixture) {
			fixture.get().Outcome = sidecartest.HeadCacheOutcomeAbsent
			fixture.get().Entry = nil
		}},
		{name: "a failed get", apply: func(fixture *fi27CachedReadFixture) {
			fixture.get().Outcome = sidecartest.HeadCacheOutcomeFailed
			fixture.get().Entry = nil
		}},
		{name: "a get with no answer yet", apply: func(fixture *fi27CachedReadFixture) { fixture.get().Outcome = "" }},
	}
	for _, c := range cases {
		fixture := newFi27CachedReadFixture(t)
		c.apply(fixture)
		if read := fixture.read(); read != nil {
			t.Errorf("%s let the copy through", c.name)
		}
	}
}

// The entry must be one the record shows written: a head write of its ETag that may have taken effect, on the source
// ref's head key, and a put of its bytes the script did not decline; and an entry at all, its version its head's.
func TestFi27CachedReadNeedsTheEntrysWrites(t *testing.T) {
	cases := []struct {
		name  string
		apply func(fixture *fi27CachedReadFixture)
	}{
		{name: "no head write of its ETag", apply: func(fixture *fi27CachedReadFixture) { fixture.blobHistory[0].WriteEtag = "etag-other" }},
		{name: "a head write of another ref", apply: func(fixture *fi27CachedReadFixture) { fixture.blobHistory[0].Key = "head/r/t" }},
		{name: "a head write its condition refused", apply: func(fixture *fi27CachedReadFixture) {
			fixture.blobHistory[0].Outcome = sidecartest.BlobOutcomePrecondition
		}},
		{name: "no put of its bytes", apply: func(fixture *fi27CachedReadFixture) { fixture.cacheHistory[0].Entry = []byte("another entry") }},
		{name: "only a put the script declined", apply: func(fixture *fi27CachedReadFixture) {
			fixture.cacheHistory[0].Outcome = sidecartest.HeadCacheOutcomeKept
		}},
		{name: "an entry whose version is not its head's", apply: func(fixture *fi27CachedReadFixture) {
			fixture.answer(fi27TestCacheEntry(t, 2, "etag-3", &protocol.EvsHead{Version: 3, WrittenMs: fixture.start.UnixMilli()}), "etag-3", fixture.start)
		}},
		{name: "bytes that are no entry", apply: func(fixture *fi27CachedReadFixture) { fixture.answer([]byte("no entry"), "etag-3", fixture.start) }},
	}
	for _, c := range cases {
		fixture := newFi27CachedReadFixture(t)
		c.apply(fixture)
		if read := fixture.read(); read != nil {
			t.Errorf("%s let the copy through", c.name)
		}
	}
	// a put whose answer was lost, and a head write whose answer was lost, may each have taken effect
	fixture := newFi27CachedReadFixture(t)
	fixture.cacheHistory[0].Outcome = sidecartest.HeadCacheOutcomeUnknown
	fixture.blobHistory[0].Outcome = sidecartest.BlobOutcomeUnknown
	if read := fixture.read(); read != fixture.get() {
		t.Error("writes whose answers were lost did not count")
	}
}

// The entry's layout read back: its version, its ETag and its head; a short entry, an ETag past its end and a head
// that does not parse are no entry.
func TestFi27ParseCacheEntry(t *testing.T) {
	encoded := fi27TestCacheEntry(t, 3, "etag-3", &protocol.EvsHead{Version: 3, WrittenMs: 1234})
	entry, ok := fi27ParseCacheEntry(encoded)
	if !ok || entry.version != 3 || entry.etag != "etag-3" || entry.head.GetVersion() != 3 || entry.head.GetWrittenMs() != 1234 {
		t.Fatalf("read back %v %t", entry, ok)
	}
	if _, ok := fi27ParseCacheEntry(encoded[:25]); ok {
		t.Error("an entry short of its fixed part parsed")
	}
	etagPastTheEnd := append([]byte{}, encoded[:26]...)
	binary.BigEndian.PutUint16(etagPastTheEnd[24:26], 200)
	if _, ok := fi27ParseCacheEntry(etagPastTheEnd); ok {
		t.Error("an entry whose ETag runs past its end parsed")
	}
	notAHead := append(append([]byte{}, encoded[:26+len("etag-3")]...), 0xff, 0xff, 0xff)
	if _, ok := fi27ParseCacheEntry(notAHead); ok {
		t.Error("an entry whose head does not parse parsed")
	}
}
