// §6.5's reassembly and §22.5's chunk limits on the receiving side: what completes, what drops a group,
// which cap refuses a body, and that every path gives its reservation back. Time is a clock the test
// moves, and a wait on it ends only when the test moves it.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	testPeerA = Id{0xA}
	testPeerB = Id{0xB}
)

// One wait on a testEnvelopeClock.
type testEnvelopeClockWait struct {
	at   time.Time
	fire chan time.Time
}

// A subprotocolClock a test moves. Advance fires the waits it reaches, and awaitWaitCount is how a test
// learns that a goroutine has reached its next wait, with no sleep. Safe for concurrent use.
type testEnvelopeClock struct {
	stateLock sync.Mutex
	now       time.Time
	waits     []testEnvelopeClockWait
	// After calls so far
	waitCount *MonitorValue[int]
}

// Starts at a fixed time, so a trace repeats.
func newTestEnvelopeClock() *testEnvelopeClock {
	return &testEnvelopeClock{
		now:       time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
		waitCount: NewMonitorValue(0),
	}
}

// The time the test last moved to.
func (self *testEnvelopeClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

// Fires when the test moves the clock past timeout from now.
func (self *testEnvelopeClock) After(timeout time.Duration) <-chan time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	fire := make(chan time.Time, 1)
	self.waits = append(self.waits, testEnvelopeClockWait{at: self.now.Add(timeout), fire: fire})
	self.waitCount.Update(func(waitCount int) int {
		return waitCount + 1
	})
	return fire
}

// Moves the clock and fires every wait it reaches.
func (self *testEnvelopeClock) Advance(timeout time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.now = self.now.Add(timeout)
	self.waits = slices.DeleteFunc(self.waits, func(wait testEnvelopeClockWait) bool {
		if self.now.Before(wait.at) {
			return false
		}
		wait.fire <- self.now
		return true
	})
}

// Blocks until After has been called count times.
func (self *testEnvelopeClock) awaitWaitCount(count int) {
	for {
		waitCount, notify := self.waitCount.Get()
		if count <= waitCount {
			return
		}
		<-notify
	}
}

// What a test reaches into: a running reassembler, its budget and its clock.
type testReassembly struct {
	reassembler *reassembler
	budget      *SubprotocolBudget
	clock       *testEnvelopeClock
}

// A reassembler that closes with the test, inside a budget of memoryBudgetByteCount.
func newTestReassembly(t testing.TB, settings *SidecarProtocolSettings, memoryBudgetByteCount int64) *testReassembly {
	t.Helper()
	budget := NewSubprotocolBudget(settings, memoryBudgetByteCount)
	clock := newTestEnvelopeClock()
	reassembler := newReassembler(context.Background(), settings, budget, clock, nil)
	t.Cleanup(reassembler.close)
	return &testReassembly{reassembler: reassembler, budget: budget, clock: clock}
}

// The default settings inside the desktop's budget.
func newDefaultTestReassembly(t testing.TB) *testReassembly {
	t.Helper()
	return newTestReassembly(t, DefaultSidecarProtocolSettings(), 128*1024*1024)
}

// Bytes held for bodies now.
func (self *testReassembly) heldByteCount() int64 {
	return self.budget.currentUsage().reassemblyByteCount
}

// Fails the test unless nothing is held: no reservation, no group and no empty peer left behind.
func (self *testReassembly) requireEmpty(t testing.TB) {
	t.Helper()
	if held := self.heldByteCount(); held != 0 {
		t.Errorf("the budget holds %d B", held)
	}
	func() {
		self.reassembler.stateLock.Lock()
		defer self.reassembler.stateLock.Unlock()
		if peerCount := len(self.reassembler.sourceIdPeers); peerCount != 0 {
			t.Errorf("%d peers left", peerCount)
		}
	}()
	if groupCount := self.reassembler.groupCount.Value(); groupCount != 0 {
		t.Errorf("%d groups counted", groupCount)
	}
}

// Offers a chunk that must go on waiting.
func (self *testReassembly) offerPending(t testing.TB, source Id, envelope *protocol.Envelope) {
	t.Helper()
	whole, err := self.reassembler.offer(source, envelope)
	if whole != nil || err != nil {
		t.Fatalf("chunk %d: whole %v, err %v", envelope.GetChunk().GetIndex(), whole != nil, err)
	}
}

// Offers a chunk that must fail with want, with nothing handed over.
func (self *testReassembly) offerFails(t testing.TB, source Id, envelope *protocol.Envelope, want error) {
	t.Helper()
	whole, err := self.reassembler.offer(source, envelope)
	if whole != nil || !errors.Is(err, want) {
		t.Fatalf("chunk %d: whole %v, err %v, want %v", envelope.GetChunk().GetIndex(), whole != nil, err, want)
	}
}

// Offers every envelope, requiring the last to complete a body, which it returns.
func (self *testReassembly) offerAll(t testing.TB, source Id, envelopes []*protocol.Envelope) *protocol.Envelope {
	t.Helper()
	for _, envelope := range envelopes[:len(envelopes)-1] {
		self.offerPending(t, source, envelope)
	}
	whole, err := self.reassembler.offer(source, envelopes[len(envelopes)-1])
	if whole == nil || err != nil {
		t.Fatalf("the final chunk: whole %v, err %v", whole != nil, err)
	}
	return whole
}

// A first chunk declaring byteCount, for a test of what it reserves: the rest need never arrive.
func testFirstChunk(t testing.TB, requestId uint64, byteCount int) *protocol.Envelope {
	t.Helper()
	header := testEnvelopeHeader()
	header.RequestId = requestId
	return testChunks(t, header, make([]byte, byteCount))[0]
}

func TestEveryLayoutComesBackWhole(t *testing.T) {
	reassembly := newDefaultTestReassembly(t)
	for _, byteCount := range []int{
		MaxEnvelopeBodyByteCount + 1,
		MaxEnvelopeBodyByteCount + MaxFinalChunkBodyByteCount,
		MaxEnvelopeBodyByteCount + MaxFinalChunkBodyByteCount + 1,
		2*MaxEnvelopeBodyByteCount - 1,
		2 * MaxEnvelopeBodyByteCount,
		2*MaxEnvelopeBodyByteCount + 1,
		16 * 1024,
		64 * 1024,
		256 * 1024,
	} {
		header := testEnvelopeHeader()
		body := testEnvelopeBody(byteCount)
		whole := reassembly.offerAll(t, testPeerA, testChunks(t, header, body))
		header.Body = body
		if !proto.Equal(whole, header) {
			t.Errorf("%d B came back with a different header or body", byteCount)
		}
		reassembly.requireEmpty(t)
	}
	if stats := reassembly.reassembler.currentStats(); stats != (reassemblyStats{completedCount: 9}) {
		t.Errorf("stats %+v", stats)
	}
}

// A rebuilt envelope's flags are the sender's, with no MORE left over from its chunks, and its body is
// its own, so a chunk's buffer can go back the moment offer returns.
func TestWholeBodyOwesNothingToItsChunks(t *testing.T) {
	reassembly := newDefaultTestReassembly(t)
	header := testEnvelopeHeader()
	header.Flags = EnvelopeFlagResponse | EnvelopeFlagError
	body := testEnvelopeBody(MaxEnvelopeBodyByteCount + 1)
	envelopes := testChunks(t, header, slices.Clone(body))
	whole := reassembly.offerAll(t, testPeerA, envelopes)
	if whole.Flags != EnvelopeFlagResponse|EnvelopeFlagError || whole.Chunk != nil {
		t.Errorf("flags %d, chunk %v", whole.Flags, whole.Chunk)
	}
	for _, envelope := range envelopes {
		clear(envelope.Body)
	}
	if !slices.Equal(whole.Body, body) {
		t.Error("the body shares bytes with a chunk")
	}
}

func TestPlainEnvelopePassesStraightThrough(t *testing.T) {
	reassembly := newDefaultTestReassembly(t)
	envelope := testChunks(t, testEnvelopeHeader(), []byte("short"))[0]
	whole, err := reassembly.reassembler.offer(testPeerA, envelope)
	if err != nil || whole != envelope {
		t.Fatalf("whole %v, err %v", whole, err)
	}
	reassembly.requireEmpty(t)
}

// MORE promises a next chunk, which a plain envelope cannot have.
func TestMoreWithNoChunkIsDropped(t *testing.T) {
	reassembly := newDefaultTestReassembly(t)
	envelope := testChunks(t, testEnvelopeHeader(), []byte("short"))[0]
	envelope.Flags |= EnvelopeFlagMore
	reassembly.offerFails(t, testPeerA, envelope, errReassemblyDropped)
}

// Each way a chunk can leave §6.5's layout, offered after a healthy first chunk: it drops the group and
// gives the reservation back. TestEveryLayoutComesBackWhole is the positive twin, these chunks unchanged.
func TestChunkOffItsLayoutDropsTheGroup(t *testing.T) {
	cases := []struct {
		name string
		// which of the body's three chunks is offered, changed
		index  int
		mutate func(envelope *protocol.Envelope)
	}{
		{name: "a total no chunked body has", index: 1, mutate: func(envelope *protocol.Envelope) {
			envelope.Chunk.TotalByteCount = MaxEnvelopeBodyByteCount
		}},
		{name: "a count the length does not fix", index: 1, mutate: func(envelope *protocol.Envelope) {
			envelope.Chunk.Count += 1
		}},
		{name: "an index past the count", index: 1, mutate: func(envelope *protocol.Envelope) {
			envelope.Chunk.Index = envelope.Chunk.Count
		}},
		{name: "a short chunk", index: 1, mutate: func(envelope *protocol.Envelope) {
			envelope.Body = envelope.Body[:MaxEnvelopeBodyByteCount-1]
		}},
		{name: "a long final chunk", index: 2, mutate: func(envelope *protocol.Envelope) {
			envelope.Body = append(slices.Clone(envelope.Body), 0)
		}},
		{name: "no more on a chunk before the final", index: 1, mutate: func(envelope *protocol.Envelope) {
			envelope.Flags &^= EnvelopeFlagMore
		}},
		{name: "more on the final chunk", index: 2, mutate: func(envelope *protocol.Envelope) {
			envelope.Flags |= EnvelopeFlagMore
		}},
		{name: "a hash before the final chunk", index: 1, mutate: func(envelope *protocol.Envelope) {
			envelope.Chunk.Sha256 = make([]byte, 32)
		}},
		{name: "no hash on the final chunk", index: 2, mutate: func(envelope *protocol.Envelope) {
			envelope.Chunk.Sha256 = nil
		}},
		{name: "a short hash on the final chunk", index: 2, mutate: func(envelope *protocol.Envelope) {
			envelope.Chunk.Sha256 = envelope.Chunk.Sha256[:31]
		}},
	}
	for _, c := range cases {
		reassembly := newDefaultTestReassembly(t)
		envelopes := testChunks(t, testEnvelopeHeader(), testEnvelopeBody(2*MaxEnvelopeBodyByteCount+100))
		reassembly.offerPending(t, testPeerA, envelopes[0])
		changed := proto.Clone(envelopes[c.index]).(*protocol.Envelope)
		c.mutate(changed)
		if whole, err := reassembly.reassembler.offer(testPeerA, changed); whole != nil || !errors.Is(err, errReassemblyDropped) {
			t.Errorf("%s: whole %v, err %v", c.name, whole != nil, err)
		}
		reassembly.requireEmpty(t)
	}
}

// §6.5's layout as a table, each chunk read alone, with every chunk of a true body as the positive twin.
func TestChunkLayoutIsWhatTheLengthFixes(t *testing.T) {
	byteCount := 2*MaxEnvelopeBodyByteCount + 100
	envelopes := testChunks(t, testEnvelopeHeader(), testEnvelopeBody(byteCount))
	for i, envelope := range envelopes {
		if !chunkFitsLayout(envelope) {
			t.Errorf("chunk %d of a true body does not fit", i)
		}
	}
	emptyFinal := testChunks(t, testEnvelopeHeader(), testEnvelopeBody(2*MaxEnvelopeBodyByteCount))
	if final := emptyFinal[len(emptyFinal)-1]; len(final.Body) != 0 || !chunkFitsLayout(final) {
		t.Errorf("an empty final chunk of %d B does not fit", len(final.Body))
	}

	hash := envelopes[2].Chunk.Sha256
	cases := []struct {
		name  string
		flags uint32
		chunk *protocol.Chunk
		body  []byte
	}{
		{
			name:  "a whole body in one chunk",
			chunk: &protocol.Chunk{Count: 1, TotalByteCount: 100, Sha256: hash},
			body:  make([]byte, 100),
		},
		{
			name:  "a body of 4,016 B, which rides no chunk",
			flags: EnvelopeFlagMore,
			chunk: &protocol.Chunk{Count: 2, TotalByteCount: MaxEnvelopeBodyByteCount},
			body:  make([]byte, MaxEnvelopeBodyByteCount),
		},
		{
			name:  "a chunk past the end, holding what a chunk there would",
			flags: EnvelopeFlagMore,
			chunk: &protocol.Chunk{Index: 3, Count: 3, TotalByteCount: uint32(byteCount)},
		},
		{
			name:  "no hash on the final chunk",
			chunk: &protocol.Chunk{Index: 2, Count: 3, TotalByteCount: uint32(byteCount)},
			body:  make([]byte, 100),
		},
		{
			name:  "a short hash on the final chunk",
			chunk: &protocol.Chunk{Index: 2, Count: 3, TotalByteCount: uint32(byteCount), Sha256: hash[:31]},
			body:  make([]byte, 100),
		},
		{
			name:  "a hash before the final chunk",
			flags: EnvelopeFlagMore,
			chunk: &protocol.Chunk{Index: 1, Count: 3, TotalByteCount: uint32(byteCount), Sha256: hash},
			body:  make([]byte, MaxEnvelopeBodyByteCount),
		},
	}
	for _, c := range cases {
		if chunkFitsLayout(&protocol.Envelope{Flags: c.flags, Chunk: c.chunk, Body: c.body}) {
			t.Errorf("%s fits", c.name)
		}
	}
}

// A first chunk off its layout is dropped before it reserves a byte, and it ends the group it would have
// restarted, since the sender of that group has moved on.
func TestFirstChunkOffItsLayoutReservesNothing(t *testing.T) {
	reassembly := newDefaultTestReassembly(t)
	envelopes := testChunks(t, testEnvelopeHeader(), testEnvelopeBody(MaxEnvelopeBodyByteCount+1))
	changed := proto.Clone(envelopes[0]).(*protocol.Envelope)
	changed.Chunk.TotalByteCount = 1
	reassembly.offerFails(t, testPeerA, changed, errReassemblyDropped)
	reassembly.requireEmpty(t)

	reassembly.offerPending(t, testPeerA, envelopes[0])
	reassembly.offerFails(t, testPeerA, changed, errReassemblyDropped)
	reassembly.requireEmpty(t)
}

// A body that rides no chunk must not start a group that could hold a reservation, whatever its chunk
// claims: 4,016 B is the longest plain body and a chunked one starts past it.
func TestBodyThatFitsOneEnvelopeStartsNoGroup(t *testing.T) {
	reassembly := newDefaultTestReassembly(t)
	envelope := testChunks(t, testEnvelopeHeader(), testEnvelopeBody(MaxEnvelopeBodyByteCount))[0]
	envelope.Flags |= EnvelopeFlagMore
	envelope.Chunk = &protocol.Chunk{Count: 2, TotalByteCount: MaxEnvelopeBodyByteCount}
	reassembly.offerFails(t, testPeerA, envelope, errReassemblyDropped)
	reassembly.requireEmpty(t)
}

// Reading 4: every chunk repeats what the first fixed, and a mismatch drops the group. Each change
// keeps §6.5's layout, so what drops it is the repeat.
func TestChunkThatDoesNotRepeatItsGroupDropsIt(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(envelope *protocol.Envelope)
	}{
		{name: "version", mutate: func(envelope *protocol.Envelope) { envelope.Version += 1 }},
		{name: "type", mutate: func(envelope *protocol.Envelope) { envelope.Type += 1 }},
		{name: "flags", mutate: func(envelope *protocol.Envelope) { envelope.Flags |= EnvelopeFlagError }},
		{name: "stream id", mutate: func(envelope *protocol.Envelope) { envelope.StreamId += 1 }},
		{name: "timeout", mutate: func(envelope *protocol.Envelope) { envelope.TimeoutMs += 1 }},
		{name: "total", mutate: func(envelope *protocol.Envelope) { envelope.Chunk.TotalByteCount += 1 }},
	}
	for _, c := range cases {
		reassembly := newDefaultTestReassembly(t)
		envelopes := testChunks(t, testEnvelopeHeader(), testEnvelopeBody(2*MaxEnvelopeBodyByteCount+100))
		reassembly.offerPending(t, testPeerA, envelopes[0])
		changed := proto.Clone(envelopes[1]).(*protocol.Envelope)
		c.mutate(changed)
		if !chunkFitsLayout(changed) {
			t.Fatalf("%s: left the layout, so this proves nothing", c.name)
		}
		if whole, err := reassembly.reassembler.offer(testPeerA, changed); whole != nil || !errors.Is(err, errReassemblyDropped) {
			t.Errorf("%s: whole %v, err %v", c.name, whole != nil, err)
		}
		reassembly.requireEmpty(t)
	}
}

// Only the next index goes in: a skip and a repeat both mean the sequence broke, so neither is patched.
func TestOnlyTheNextIndexExtendsAGroup(t *testing.T) {
	cases := []struct {
		name    string
		indexes []int
	}{
		{name: "a skip", indexes: []int{0, 2}},
		{name: "a repeat", indexes: []int{0, 1, 1}},
		{name: "a step back", indexes: []int{0, 1, 2, 1}},
	}
	for _, c := range cases {
		reassembly := newDefaultTestReassembly(t)
		envelopes := testChunks(t, testEnvelopeHeader(), testEnvelopeBody(3*MaxEnvelopeBodyByteCount+100))
		last := len(c.indexes) - 1
		for _, index := range c.indexes[:last] {
			reassembly.offerPending(t, testPeerA, envelopes[index])
		}
		reassembly.offerFails(t, testPeerA, envelopes[c.indexes[last]], errReassemblyDropped)
		reassembly.requireEmpty(t)
	}
}

// What follows a dropped group finds nothing, so it stays dropped and costs nothing.
func TestChunkWithNoGroupIsDropped(t *testing.T) {
	reassembly := newDefaultTestReassembly(t)
	envelopes := testChunks(t, testEnvelopeHeader(), testEnvelopeBody(2*MaxEnvelopeBodyByteCount+100))
	reassembly.offerFails(t, testPeerA, envelopes[1], errReassemblyDropped)
	reassembly.offerFails(t, testPeerA, envelopes[2], errReassemblyDropped)
	reassembly.requireEmpty(t)
}

func TestHashMismatchDropsTheBody(t *testing.T) {
	reassembly := newDefaultTestReassembly(t)
	envelopes := testChunks(t, testEnvelopeHeader(), testEnvelopeBody(2*MaxEnvelopeBodyByteCount+100))
	changed := proto.Clone(envelopes[1]).(*protocol.Envelope)
	changed.Body[7] ^= 1
	reassembly.offerPending(t, testPeerA, envelopes[0])
	reassembly.offerPending(t, testPeerA, changed)
	reassembly.offerFails(t, testPeerA, envelopes[2], errReassemblyDropped)
	reassembly.requireEmpty(t)
	if stats := reassembly.reassembler.currentStats(); stats.completedCount != 0 || stats.droppedCount != 1 {
		t.Errorf("stats %+v", stats)
	}
}

// Reading 1: a sender resends whole after a sequence exit, which reaches a partial group as a fresh index
// 0. The old reservation goes, so a restart never holds two.
func TestFreshIndexZeroRestartsTheGroup(t *testing.T) {
	reassembly := newDefaultTestReassembly(t)
	body := testEnvelopeBody(2*MaxEnvelopeBodyByteCount + 100)
	envelopes := testChunks(t, testEnvelopeHeader(), body)
	reassembly.offerPending(t, testPeerA, envelopes[0])
	reassembly.offerPending(t, testPeerA, envelopes[1])

	whole := reassembly.offerAll(t, testPeerA, envelopes)
	if !slices.Equal(whole.Body, body) {
		t.Error("the restart kept bytes from before it")
	}
	reassembly.requireEmpty(t)
}

func TestRestartReservesItsOwnLength(t *testing.T) {
	reassembly := newDefaultTestReassembly(t)
	long := testChunks(t, testEnvelopeHeader(), testEnvelopeBody(3*MaxEnvelopeBodyByteCount))
	short := testChunks(t, testEnvelopeHeader(), testEnvelopeBody(MaxEnvelopeBodyByteCount+1))

	reassembly.offerPending(t, testPeerA, long[0])
	if held := reassembly.heldByteCount(); held != 3*MaxEnvelopeBodyByteCount {
		t.Fatalf("holds %d B", held)
	}
	reassembly.offerPending(t, testPeerA, short[0])
	if held := reassembly.heldByteCount(); held != MaxEnvelopeBodyByteCount+1 {
		t.Fatalf("holds %d B after the restart", held)
	}
}

// A restart past the caps still ends the group before it, and a peer at its cap restarts freely, since
// the group it replaces leaves room for itself.
func TestRestartAtACapReplacesItsGroup(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	byteCount := 2 * MaxEnvelopeBodyByteCount
	settings.ReassemblyPeerByteCount = int64(byteCount)
	settings.ReassemblyProcessByteCount = int64(byteCount)
	settings.ReassemblyPeerCount = 1
	reassembly := newTestReassembly(t, settings, int64(byteCount))

	first := testFirstChunk(t, 1, byteCount)
	reassembly.offerPending(t, testPeerA, first)
	reassembly.offerPending(t, testPeerA, first)
	if held := reassembly.heldByteCount(); held != int64(byteCount) {
		t.Fatalf("holds %d B", held)
	}
	reassembly.offerFails(t, testPeerA, testFirstChunk(t, 1, byteCount+1), errReassemblyExhausted)
	reassembly.requireEmpty(t)
}

// (source, request_id, RESPONSE): a peer's request and its response to ours can share an id, as can two
// peers' requests, and each is its own body. Their chunks interleave here to show it.
func TestGroupsKeyOnSourceIdAndResponse(t *testing.T) {
	reassembly := newDefaultTestReassembly(t)
	byteCount := MaxEnvelopeBodyByteCount + 100

	requestBody := testEnvelopeBody(byteCount)
	responseBody := slices.Repeat([]byte{0xEE}, byteCount)
	otherPeerBody := slices.Repeat([]byte{0xDD}, byteCount)

	response := testEnvelopeHeader()
	response.Flags |= EnvelopeFlagResponse
	requests := testChunks(t, testEnvelopeHeader(), requestBody)
	responses := testChunks(t, response, responseBody)
	otherPeers := testChunks(t, testEnvelopeHeader(), otherPeerBody)

	reassembly.offerPending(t, testPeerA, requests[0])
	reassembly.offerPending(t, testPeerA, responses[0])
	reassembly.offerPending(t, testPeerB, otherPeers[0])
	if held := reassembly.heldByteCount(); held != int64(3*byteCount) {
		t.Fatalf("holds %d B", held)
	}
	for _, c := range []struct {
		source Id
		final  *protocol.Envelope
		body   []byte
	}{
		{source: testPeerB, final: otherPeers[1], body: otherPeerBody},
		{source: testPeerA, final: responses[1], body: responseBody},
		{source: testPeerA, final: requests[1], body: requestBody},
	} {
		whole, err := reassembly.reassembler.offer(c.source, c.final)
		if err != nil || !slices.Equal(whole.GetBody(), c.body) {
			t.Errorf("whole %v, err %v", whole != nil, err)
		}
	}
	reassembly.requireEmpty(t)
}

func TestBodyOverItsCapIsRefused(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	settings.ReassemblyMaxBodyByteCount = 3 * MaxEnvelopeBodyByteCount
	reassembly := newTestReassembly(t, settings, 128*1024*1024)

	reassembly.offerAll(t, testPeerA, testChunks(t, testEnvelopeHeader(), testEnvelopeBody(3*MaxEnvelopeBodyByteCount)))
	reassembly.requireEmpty(t)

	first := testFirstChunk(t, 1, 3*MaxEnvelopeBodyByteCount+1)
	_, err := reassembly.reassembler.offer(testPeerA, first)
	if code, ok := envelopeErrorCode(err); !ok || code != protocol.ErrorCode_ERR_RESOURCE_EXHAUSTED {
		t.Fatalf("err %v", err)
	}
	reassembly.requireEmpty(t)
}

// A setting past 1 MiB is validate's to refuse, and a reassembler handed one anyway holds the protocol's
// maximum, as every peer does.
func TestProtocolMaximumHoldsOverTheSetting(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	settings.ReassemblyMaxBodyByteCount = 2 * MaxReassemblyBodyByteCount
	settings.ReassemblyPeerByteCount = 4 * MaxReassemblyBodyByteCount
	settings.ReassemblyProcessByteCount = 4 * MaxReassemblyBodyByteCount
	reassembly := newTestReassembly(t, settings, 128*1024*1024)

	reassembly.offerPending(t, testPeerA, testFirstChunk(t, 1, MaxReassemblyBodyByteCount))
	// chunkBody refuses a body this long, so its first chunk is written out here
	over := testFirstChunk(t, 2, MaxReassemblyBodyByteCount)
	_, _, chunkCount := chunkLayout(MaxReassemblyBodyByteCount + 1)
	over.Chunk.TotalByteCount = MaxReassemblyBodyByteCount + 1
	over.Chunk.Count = uint32(chunkCount)
	reassembly.offerFails(t, testPeerA, over, errReassemblyExhausted)
}

// The count cap, with a peer's room back the moment a body completes, and no effect on another peer.
func TestPeerCountCapRefusesItsNextBody(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	settings.ReassemblyPeerCount = 2
	reassembly := newTestReassembly(t, settings, 128*1024*1024)
	byteCount := MaxEnvelopeBodyByteCount + 1

	header := testEnvelopeHeader()
	envelopes := testChunks(t, header, testEnvelopeBody(byteCount))
	reassembly.offerPending(t, testPeerA, envelopes[0])
	reassembly.offerPending(t, testPeerA, testFirstChunk(t, 2, byteCount))
	reassembly.offerFails(t, testPeerA, testFirstChunk(t, 3, byteCount), errReassemblyExhausted)
	reassembly.offerPending(t, testPeerB, testFirstChunk(t, 3, byteCount))

	if whole, err := reassembly.reassembler.offer(testPeerA, envelopes[1]); whole == nil || err != nil {
		t.Fatalf("whole %v, err %v", whole != nil, err)
	}
	reassembly.offerPending(t, testPeerA, testFirstChunk(t, 3, byteCount))
}

func TestPeerByteCapRefusesItsNextBody(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	settings.ReassemblyPeerByteCount = 2 * 5000
	reassembly := newTestReassembly(t, settings, 128*1024*1024)

	reassembly.offerPending(t, testPeerA, testFirstChunk(t, 1, 5000))
	reassembly.offerFails(t, testPeerA, testFirstChunk(t, 2, 5001), errReassemblyExhausted)
	reassembly.offerPending(t, testPeerA, testFirstChunk(t, 2, 5000))
	if held := reassembly.heldByteCount(); held != 2*5000 {
		t.Fatalf("holds %d B", held)
	}
	reassembly.offerPending(t, testPeerB, testFirstChunk(t, 3, 5000))
}

// The process cap counts every peer, so it refuses one that is under its own.
func TestProcessCapRefusesAcrossPeers(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	settings.ReassemblyProcessByteCount = 2 * 5000
	reassembly := newTestReassembly(t, settings, 128*1024*1024)

	reassembly.offerPending(t, testPeerA, testFirstChunk(t, 1, 5000))
	reassembly.offerFails(t, testPeerB, testFirstChunk(t, 2, 5001), errReassemblyExhausted)
	reassembly.offerPending(t, testPeerB, testFirstChunk(t, 2, 5000))
	reassembly.offerFails(t, Id{0xC}, testFirstChunk(t, 3, 4017), errReassemblyExhausted)
	if held := reassembly.heldByteCount(); held != 2*5000 {
		t.Fatalf("holds %d B", held)
	}
}

// §5's budget sits above the process caps, so what else the process holds narrows them.
func TestMemoryBudgetRefusesUnderTheProcessCap(t *testing.T) {
	reassembly := newTestReassembly(t, DefaultSidecarProtocolSettings(), 6000)
	reassembly.offerPending(t, testPeerA, testFirstChunk(t, 1, 5000))
	reassembly.offerFails(t, testPeerB, testFirstChunk(t, 2, 5000), errReassemblyExhausted)
}

// One budget, two reassemblers, as a host running two networks has: the process cap holds across both.
func TestProcessCapHoldsAcrossSubprotocolsSharingABudget(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	settings.ReassemblyProcessByteCount = 5000
	first := newTestReassembly(t, settings, 128*1024*1024)
	second := newReassembler(context.Background(), settings, first.budget, first.clock, nil)
	t.Cleanup(second.close)

	first.offerPending(t, testPeerA, testFirstChunk(t, 1, 5000))
	if whole, err := second.offer(testPeerA, testFirstChunk(t, 1, 5000)); whole != nil || !errors.Is(err, errReassemblyExhausted) {
		t.Fatalf("whole %v, err %v", whole != nil, err)
	}
}

// One answer per body: a refused first chunk leaves no group, so what follows it is dropped quietly.
func TestLaterChunksOfARefusedBodyAreDropped(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	settings.ReassemblyPeerByteCount = 5000
	reassembly := newTestReassembly(t, settings, 128*1024*1024)

	envelopes := testChunks(t, testEnvelopeHeader(), testEnvelopeBody(2*MaxEnvelopeBodyByteCount+100))
	reassembly.offerFails(t, testPeerA, envelopes[0], errReassemblyExhausted)
	reassembly.offerFails(t, testPeerA, envelopes[1], errReassemblyDropped)
	reassembly.offerFails(t, testPeerA, envelopes[2], errReassemblyDropped)
	reassembly.requireEmpty(t)
	if stats := reassembly.reassembler.currentStats(); stats.refusedCount != 1 || stats.droppedCount != 2 {
		t.Errorf("stats %+v", stats)
	}
}

// §22.5: a peer that declares 1 MiB and stalls holds what its caps give it and no more, a healthy peer
// goes on meanwhile, and the timeout hands the bytes back.
func TestStalledPeerLeavesAHealthyPeerProceeding(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	settings.ReassemblyMaxBodyByteCount = MaxReassemblyBodyByteCount
	reassembly := newTestReassembly(t, settings, 128*1024*1024)
	stalled := Id{0x5}
	healthy := Id{0x6}

	// two 1 MiB bodies fill the peer's 2 MiB, and the third, inside every other cap, is refused
	reassembly.offerPending(t, stalled, testFirstChunk(t, 1, MaxReassemblyBodyByteCount))
	reassembly.offerPending(t, stalled, testFirstChunk(t, 2, MaxReassemblyBodyByteCount))
	reassembly.offerFails(t, stalled, testFirstChunk(t, 3, MaxReassemblyBodyByteCount), errReassemblyExhausted)
	if held := reassembly.heldByteCount(); held != settings.ReassemblyPeerByteCount {
		t.Fatalf("the stalled peer holds %d B", held)
	}

	body := testEnvelopeBody(64 * 1024)
	header := testEnvelopeHeader()
	header.RequestId = 1
	whole := reassembly.offerAll(t, healthy, testChunks(t, header, body))
	if !slices.Equal(whole.Body, body) {
		t.Fatal("the healthy body changed")
	}
	if held := reassembly.heldByteCount(); held != settings.ReassemblyPeerByteCount {
		t.Fatalf("holds %d B after the healthy body", held)
	}

	reassembly.clock.Advance(settings.ReassemblyIdleTimeout)
	if timeout := reassembly.reassembler.expire(); timeout != 0 {
		t.Fatalf("a group is left, due in %v", timeout)
	}
	reassembly.requireEmpty(t)
}

// Eight stalled peers can fill the process cap, which is the cap working: the ninth is refused rather
// than the process growing, and every byte is back after the timeout.
func TestProcessCapHoldsAgainstManyStalledPeers(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	settings.ReassemblyMaxBodyByteCount = MaxReassemblyBodyByteCount
	reassembly := newTestReassembly(t, settings, 128*1024*1024)

	for peer := range 8 {
		source := Id{0x10, byte(peer)}
		reassembly.offerPending(t, source, testFirstChunk(t, 1, MaxReassemblyBodyByteCount))
		reassembly.offerPending(t, source, testFirstChunk(t, 2, MaxReassemblyBodyByteCount))
	}
	if held := reassembly.heldByteCount(); held != settings.ReassemblyProcessByteCount {
		t.Fatalf("holds %d B", held)
	}
	reassembly.offerFails(t, Id{0x11}, testFirstChunk(t, 1, MaxEnvelopeBodyByteCount+1), errReassemblyExhausted)

	reassembly.clock.Advance(settings.ReassemblyIdleTimeout)
	reassembly.reassembler.expire()
	reassembly.requireEmpty(t)
	reassembly.offerPending(t, Id{0x11}, testFirstChunk(t, 1, MaxEnvelopeBodyByteCount+1))
}

// Idle means since the last chunk: a group that keeps arriving keeps its reservation past the timeout
// from its first chunk, and goes exactly one timeout after its last.
func TestDeadlineFollowsTheLastChunk(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	timeout := settings.ReassemblyIdleTimeout
	reassembly := newDefaultTestReassembly(t)
	envelopes := testChunks(t, testEnvelopeHeader(), testEnvelopeBody(3*MaxEnvelopeBodyByteCount))

	reassembly.offerPending(t, testPeerA, envelopes[0])
	reassembly.clock.Advance(timeout - time.Nanosecond)
	reassembly.offerPending(t, testPeerA, envelopes[1])
	reassembly.clock.Advance(timeout - time.Nanosecond)
	if due := reassembly.reassembler.expire(); due != time.Nanosecond {
		t.Fatalf("due in %v", due)
	}
	if held := reassembly.heldByteCount(); held == 0 {
		t.Fatal("expired before its time")
	}
	reassembly.clock.Advance(time.Nanosecond)
	if due := reassembly.reassembler.expire(); due != 0 {
		t.Fatalf("due in %v", due)
	}
	reassembly.requireEmpty(t)
	if stats := reassembly.reassembler.currentStats(); stats.expiredCount != 1 {
		t.Errorf("stats %+v", stats)
	}
}

// run sleeps to the earliest deadline, whichever group the map gives it first, or a group outlives its
// timeout by as long as the latest one has left.
func TestExpireAnswersTheEarliestDeadline(t *testing.T) {
	reassembly := newDefaultTestReassembly(t)
	timeout := DefaultSidecarProtocolSettings().ReassemblyIdleTimeout
	for peer := range 8 {
		reassembly.offerPending(t, Id{0x30, byte(peer)}, testFirstChunk(t, 1, 5000))
		reassembly.clock.Advance(time.Second)
	}
	if due := reassembly.reassembler.expire(); due != timeout-8*time.Second {
		t.Errorf("due in %v", due)
	}
}

// The deadline is a rule of offer as well as of the sweep, so run's timing never decides whether a late
// chunk counts.
func TestChunkPastItsDeadlineIsDroppedBeforeTheSweep(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	reassembly := newDefaultTestReassembly(t)
	envelopes := testChunks(t, testEnvelopeHeader(), testEnvelopeBody(2*MaxEnvelopeBodyByteCount+100))
	reassembly.offerPending(t, testPeerA, envelopes[0])
	reassembly.clock.Advance(settings.ReassemblyIdleTimeout)
	reassembly.offerFails(t, testPeerA, envelopes[1], errReassemblyDropped)
	reassembly.requireEmpty(t)
	if stats := reassembly.reassembler.currentStats(); stats.expiredCount != 1 || stats.droppedCount != 1 {
		t.Errorf("stats %+v", stats)
	}
}

// So too a cap: what has expired does not count against a first chunk, sweep or no sweep.
func TestCapsNeverCountAnExpiredGroup(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	settings.ReassemblyPeerCount = 1
	reassembly := newTestReassembly(t, settings, 128*1024*1024)
	reassembly.offerPending(t, testPeerA, testFirstChunk(t, 1, 5000))
	reassembly.clock.Advance(settings.ReassemblyIdleTimeout)
	reassembly.offerPending(t, testPeerA, testFirstChunk(t, 2, 5000))
	if held := reassembly.heldByteCount(); held != 5000 {
		t.Fatalf("holds %d B", held)
	}
}

// run with nothing but the clock: it sleeps to the first deadline, expires that group alone, and sleeps
// to the next. Reaching its second wait is what says the first expiry is done.
func TestRunExpiresGroupsOnTheClock(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	timeout := settings.ReassemblyIdleTimeout
	reassembly := newDefaultTestReassembly(t)

	reassembly.offerPending(t, testPeerA, testFirstChunk(t, 1, 5000))
	reassembly.clock.awaitWaitCount(1)
	reassembly.clock.Advance(timeout / 3)
	reassembly.offerPending(t, testPeerB, testFirstChunk(t, 2, 6000))
	reassembly.clock.Advance(timeout - timeout/3)
	reassembly.clock.awaitWaitCount(2)

	if stats := reassembly.reassembler.currentStats(); stats.expiredCount != 1 {
		t.Errorf("stats %+v", stats)
	}
	if held := reassembly.heldByteCount(); held != 6000 {
		t.Errorf("holds %d B", held)
	}
}

// A chunk that moved the deadline leaves run's wait early, so run wakes, finds nothing due and sleeps
// the rest, with the group and its next chunk unharmed.
func TestRunSleepsAgainWhenTheDeadlineMoved(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	timeout := settings.ReassemblyIdleTimeout
	reassembly := newDefaultTestReassembly(t)
	body := testEnvelopeBody(2*MaxEnvelopeBodyByteCount + 100)
	envelopes := testChunks(t, testEnvelopeHeader(), body)

	reassembly.offerPending(t, testPeerA, envelopes[0])
	reassembly.clock.awaitWaitCount(1)
	reassembly.clock.Advance(timeout / 2)
	reassembly.offerPending(t, testPeerA, envelopes[1])
	reassembly.clock.Advance(timeout - timeout/2)
	reassembly.clock.awaitWaitCount(2)

	whole, err := reassembly.reassembler.offer(testPeerA, envelopes[2])
	if err != nil || !slices.Equal(whole.GetBody(), body) {
		t.Fatalf("whole %v, err %v", whole != nil, err)
	}
	reassembly.requireEmpty(t)
}

// With its last group gone run sets no timer, and the next group still wakes it, whichever of the two
// gets there first: exactly one more wait follows, and it is the new group's.
func TestRunWakesForAGroupAfterGoingEmpty(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	reassembly := newDefaultTestReassembly(t)

	reassembly.offerPending(t, testPeerA, testFirstChunk(t, 1, 5000))
	reassembly.clock.awaitWaitCount(1)
	reassembly.clock.Advance(settings.ReassemblyIdleTimeout)
	reassembly.offerPending(t, testPeerB, testFirstChunk(t, 2, 6000))
	reassembly.clock.awaitWaitCount(2)

	reassembly.clock.Advance(settings.ReassemblyIdleTimeout - time.Nanosecond)
	if held := reassembly.heldByteCount(); held != 6000 {
		t.Errorf("holds %d B", held)
	}
	if waitCount := reassembly.clock.waitCount.Value(); waitCount != 2 {
		t.Errorf("%d waits", waitCount)
	}
}

func TestCloseGivesEveryReservationBack(t *testing.T) {
	reassembly := newDefaultTestReassembly(t)
	reassembly.offerPending(t, testPeerA, testFirstChunk(t, 1, 5000))
	reassembly.offerPending(t, testPeerB, testFirstChunk(t, 2, 6000))
	reassembly.reassembler.close()
	reassembly.requireEmpty(t)

	reassembly.offerFails(t, testPeerA, testFirstChunk(t, 3, 5000), errReassemblyExhausted)
	reassembly.requireEmpty(t)
}

// The owner's context is the other way down, and it holds no reservation either.
func TestCanceledContextGivesEveryReservationBack(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	budget := NewSubprotocolBudget(settings, 128*1024*1024)
	ctx, cancel := context.WithCancel(context.Background())
	reassembler := newReassembler(ctx, settings, budget, newTestEnvelopeClock(), nil)
	if _, err := reassembler.offer(testPeerA, testFirstChunk(t, 1, 5000)); err != nil {
		t.Fatal(err)
	}
	cancel()
	<-reassembler.runDone
	if held := budget.currentUsage().reassemblyByteCount; held != 0 {
		t.Errorf("holds %d B", held)
	}
}

// Whatever the interleaving across peers, the caps hold and every byte comes back. The race detector
// reads this one more closely than its assertions do.
func TestConcurrentPeersBalanceTheBudget(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	settings.ReassemblyProcessByteCount = 5 * 5000
	reassembly := newTestReassembly(t, settings, 128*1024*1024)
	body := testEnvelopeBody(5000)
	var peers sync.WaitGroup
	for peer := range 8 {
		peers.Add(1)
		go func() {
			defer peers.Done()
			source := Id{0x20, byte(peer)}
			for round := range 200 {
				header := testEnvelopeHeader()
				header.RequestId = uint64(round + 1)
				envelopes, err := chunkBody(header, body)
				if err != nil {
					t.Error(err)
					return
				}
				if _, err := reassembly.reassembler.offer(source, envelopes[0]); err != nil {
					// a cap's refusal is the only way out of a first chunk here
					if !errors.Is(err, errReassemblyExhausted) {
						t.Error(err)
					}
					continue
				}
				if whole, err := reassembly.reassembler.offer(source, envelopes[1]); err != nil || !slices.Equal(whole.GetBody(), body) {
					t.Errorf("whole %v, err %v", whole != nil, err)
				}
			}
		}()
	}
	peers.Wait()
	reassembly.requireEmpty(t)
}

// A chunk that drops its group answers nothing, so a log line at this level is all a person gets, and
// it names the peer by its opaque id and nothing of the body.
func TestDropLogsTheReasonAtItsLevel(t *testing.T) {
	log := &testEnvelopeLog{}
	settings := DefaultSidecarProtocolSettings()
	reassembler := newReassembler(
		context.Background(), settings, NewSubprotocolBudget(settings, 128*1024*1024), newTestEnvelopeClock(), log,
	)
	t.Cleanup(reassembler.close)
	if _, err := reassembler.offer(testPeerA, testChunks(t, testEnvelopeHeader(), testEnvelopeBody(5000))[1]); !errors.Is(err, errReassemblyDropped) {
		t.Fatalf("err %v", err)
	}
	if len(log.lines) != 1 || !strings.Contains(log.lines[0], testPeerA.String()) || !strings.Contains(log.lines[0], "no group") {
		t.Fatalf("logged %q", log.lines)
	}
}

// A Logger that keeps what a level-1 guard lets through.
type testEnvelopeLog struct {
	noopLogger
	lines []string
}

// Enabled at every level, so a guarded line reaches Infof.
func (self *testEnvelopeLog) V(level int32) Verbose {
	return testEnvelopeVerbose{}
}

// Keeps the line.
func (self *testEnvelopeLog) Infof(format string, args ...any) {
	self.lines = append(self.lines, fmt.Sprintf(format, args...))
}

// A level that is always on.
type testEnvelopeVerbose struct {
	noopVerbose
}

// Says yes.
func (self testEnvelopeVerbose) Enabled() bool {
	return true
}
