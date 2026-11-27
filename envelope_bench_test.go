//go:build !sidecar_http && !js && !sidecar_testhooks && !race

package sidecar

// §22.5's §6 row "receive allocs" as testdata/budgets.yml's receive-allocs row runs it (PROTO-M5-05; D-PROTO-11):
// one verified peer's request from connect's typed delivery, a fresh Envelope from connect's reflection factory
// and envelopeCodec's decode, through the real inline handler to its source's worker and its dispatch, on
// production's protocol settings. §22.5 names no number, so the row's limit is PROTO-M1-11's recorded baseline,
// testdata/receive_allocs.json's request figure: no regression. What it measures is the data for D-PROTO-11's
// pooled codec, which is built only if §22 shows it worthwhile (External).
//
// A benchmark counts the allocations of the whole process, so the window opens only once every goroutine but
// the benchmark's own is parked. The fixture's connect client publishes its key when it starts, on goroutines of
// its own (EncryptionSessionManager's publish, through ControlSync and the send sequence to ControlId it opens):
// up to about 200 allocations of that fell in the window, as far as load delayed them, and read 20 at tip-check
// fcd6fd90, though the receive path's own 18 a request never rose.

import (
	"bytes"
	"context"
	"reflect"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

func BenchmarkSubprotocolReceive(b *testing.B) {
	fixture := newTestSubprotocol(b, nil)
	sourceId := connect.NewId()
	fixture.verify(sourceId, "peer")
	envelopeBytes, err := proto.Marshal(testRequest(testFreeMessageType, make([]byte, testReceiveAllocsBodyByteCount)))
	if err != nil {
		b.Fatal(err)
	}
	dispatched := make(chan struct{})
	remove, err := fixture.subprotocol.setMessageTypeDispatch(testFreeMessageType, func(ctx context.Context, message *subprotocolMessage) {
		dispatched <- struct{}{}
	})
	if err != nil {
		b.Fatal(err)
	}
	envelopeType := reflect.TypeFor[protocol.Envelope]()
	source := connect.SourceId(sourceId)
	peer := testNetworkPeer("peer")
	receive := func() {
		envelope := reflect.New(envelopeType).Interface().(*protocol.Envelope)
		if err := (envelopeCodec{}).Unmarshal(envelopeBytes, envelope); err != nil {
			b.Fatal(err)
		}
		fixture.subprotocol.receive(source, envelope, peer)
		<-dispatched
	}
	// the source's worker and queue exist before the measure, as on a live peer
	receive()
	// what the fixture started on goroutines of its own has reached its waits, so the window counts none of it
	testAwaitOtherGoroutinesParked(b, nil)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		receive()
	}
	b.StopTimer()
	remove()
	fixture.closeBalanced(b)
}

// Waits until no goroutine of the process but the caller runs, failing tb with what still runs past
// testSubprotocolAwaitTimeout. holds says whether a poll's stanzas of the goroutines not parked hold the wait; nil,
// any of them does, as a measure of the whole process's allocations needs. Each poll stops the world for every
// goroutine's state, which is exact where the scheduler's sampled counts are not, and the caller yields between
// polls, so what it waits for runs. A parked goroutine stays parked until something wakes it, a timer among them,
// so this settles what runs now, not what a timer starts later; and a goroutine that sits for good in a system
// call, as os/signal's receiver does, holds the wait until it fails, naming it. The dump is read in place and its
// buffer kept, so the polls leave next to no garbage to bring a GC into the window that follows.
func testAwaitOtherGoroutinesParked(tb testing.TB, holds func(stanzas [][]byte) bool) {
	tb.Helper()
	if holds == nil {
		holds = func(stanzas [][]byte) bool {
			return 0 < len(stanzas)
		}
	}
	deadline := time.After(testSubprotocolAwaitTimeout)
	dump := make([]byte, 1024*1024)
	for {
		byteCount := runtime.Stack(dump, true)
		if byteCount == len(dump) {
			// the dump filled the buffer, so it may have been cut short: take it again in one twice the size
			dump = make([]byte, 2*len(dump))
			continue
		}
		stanzas := testActiveGoroutines(dump[:byteCount])
		if !holds(stanzas) {
			return
		}
		select {
		case <-deadline:
			tb.Fatalf("goroutines still run after %s:\n\n%s", testSubprotocolAwaitTimeout, bytes.Join(stanzas, []byte("\n\n")))
		default:
		}
		runtime.Gosched()
	}
}

// The stanzas of a runtime.Stack dump of every goroutine whose goroutine is not parked, leaving out the first,
// the caller's own, each a slice of dump. Parked is a wait on a channel, a select, a lock, a condition, a timer or
// I/O. Running, runnable and preempted goroutines, and those copying their stacks, in a system call or waiting out
// a GC assist, are on their way and may allocate at any moment, and so may one whose stanza has no header this
// reads.
func testActiveGoroutines(dump []byte) [][]byte {
	var stanzas [][]byte
	first := true
	for rest := bytes.TrimSpace(dump); 0 < len(rest); {
		stanza, next, _ := bytes.Cut(rest, []byte("\n\n"))
		rest = bytes.TrimLeft(next, "\n")
		if first {
			first = false
			continue
		}
		// goroutine 7 [chan receive, 2 minutes, locked to thread]:
		header, _, _ := bytes.Cut(stanza, []byte("\n"))
		_, state, ok := bytes.Cut(header, []byte(" ["))
		if ok {
			state, _, ok = bytes.Cut(state, []byte("]"))
		}
		if !ok || !bytes.HasPrefix(header, []byte("goroutine ")) {
			stanzas = append(stanzas, stanza)
			continue
		}
		state, _, _ = bytes.Cut(state, []byte(","))
		// a bubble's or the leak profile's note, as in "chan receive (durable)"
		state, _, _ = bytes.Cut(state, []byte(" ("))
		switch string(state) {
		case "running", "runnable", "preempted", "copystack", "syscall", "GC assist wait":
			stanzas = append(stanzas, stanza)
		}
	}
	return stanzas
}

// Each state a goroutine's header shows reads as parked or not, the caller's own stanza is left out, and a stanza
// whose header does not read is never taken for parked.
func TestActiveGoroutinesReadsEachState(t *testing.T) {
	caller := "goroutine 1 [running]:\nmain.measure()\n\t/src/main/measure.go:12 +0x24"
	other := func(state string) string {
		return "goroutine 2 [" + state + "]:\nmain.work()\n\t/src/main/work.go:7 +0x1c"
	}
	for _, c := range []struct {
		state  string
		parked bool
	}{
		{state: "running", parked: false},
		{state: "runnable", parked: false},
		{state: "running, locked to thread", parked: false},
		{state: "preempted", parked: false},
		{state: "copystack", parked: false},
		{state: "syscall, 3 minutes", parked: false},
		{state: "GC assist wait", parked: false},
		{state: "chan receive", parked: true},
		{state: "chan send, 2 minutes", parked: true},
		{state: "select", parked: true},
		{state: "select (no cases)", parked: true},
		{state: "chan receive (durable)", parked: true},
		{state: "sleep", parked: true},
		{state: "semacquire", parked: true},
		{state: "sync.Mutex.Lock", parked: true},
		{state: "sync.Cond.Wait", parked: true},
		{state: "IO wait, 9 minutes", parked: true},
	} {
		active := testActiveGoroutines([]byte(caller + "\n\n" + other(c.state) + "\n"))
		switch {
		case c.parked && len(active) != 0:
			t.Errorf("[%s] read as not parked: %q", c.state, active)
		case !c.parked && (len(active) != 1 || string(active[0]) != other(c.state)):
			t.Errorf("[%s] read as parked: %q", c.state, active)
		}
	}
	if active := testActiveGoroutines([]byte(caller + "\n")); len(active) != 0 {
		t.Errorf("the caller's own stanza was counted: %q", active)
	}
	unread := "no header here\nmain.work()"
	if active := testActiveGoroutines([]byte(caller + "\n\n" + unread + "\n")); len(active) != 1 || string(active[0]) != unread {
		t.Errorf("a stanza with no header read as parked: %q", active)
	}
}

// Spins, never parking, until released.
func testSpinUntil(released *atomic.Bool) {
	for !released.Load() {
		runtime.Gosched()
	}
}

// The window waits for a goroutine that still runs, as the fixture's connect client's publish ran beside the
// benchmark's window, and opens once it is gone: the spinner is released only from inside the wait's own poll
// that found it running, so a wait that returned while it ran would never have seen it. Only this test's own
// goroutines hold the wait, the spinner's stack naming the test, so one another test left running does not.
func TestAwaitOtherGoroutinesParkedWaitsForARunningGoroutine(t *testing.T) {
	released := &atomic.Bool{}
	spun := make(chan struct{})
	go func() {
		defer close(spun)
		testSpinUntil(released)
	}()
	// a wait that fails leaves no spinner behind
	t.Cleanup(func() {
		released.Store(true)
		<-spun
	})
	seen := false
	testAwaitOtherGoroutinesParked(t, func(stanzas [][]byte) bool {
		held := false
		for _, stanza := range stanzas {
			if !bytes.Contains(stanza, []byte("sidecar.TestAwaitOtherGoroutinesParkedWaitsForARunningGoroutine")) {
				continue
			}
			held = true
			if bytes.Contains(stanza, []byte("sidecar.testSpinUntil(")) {
				seen = true
				released.Store(true)
			}
		}
		return held
	})
	if !seen {
		t.Fatal("the wait returned while the spinning goroutine ran")
	}
	select {
	case <-spun:
	default:
		t.Fatal("the wait returned before the spinning goroutine ended")
	}
}

// A goroutine parked on a channel does not hold the window: the wait returns while it is still parked, and it
// goes on once released. Only this test's own goroutine holds the wait, as above.
func TestAwaitOtherGoroutinesParkedTakesAParkedGoroutineAsSettled(t *testing.T) {
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-release
	}()
	testAwaitOtherGoroutinesParked(t, func(stanzas [][]byte) bool {
		for _, stanza := range stanzas {
			if bytes.Contains(stanza, []byte("sidecar.TestAwaitOtherGoroutinesParkedTakesAParkedGoroutineAsSettled")) {
				return true
			}
		}
		return false
	})
	select {
	case <-done:
		t.Fatal("the parked goroutine ended before its release")
	default:
	}
	close(release)
	testAwait(t, done, "the released goroutine's end")
}
