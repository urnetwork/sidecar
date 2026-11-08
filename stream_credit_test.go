// §6.7's credit: BUSY when a peer's credit is short with a healthy sibling stream still running, the
// opener's local refusal, an edge's budget growing with its streams, the process's cap, the window's
// maximum as a share of the peer's credit, and the smaller windows above half of GOMEMLIMIT.

package sidecar

import (
	"errors"
	"math"
	"runtime/debug"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

func TestStreamBusyWhenCreditIsShortWithAHealthySibling(t *testing.T) {
	settings := testStreamSettings()
	// room for one stream's minimum window and a second's initial window, not its minimum
	settings.StreamPeerCreditByteCount = settings.StreamMinWindowByteCount + settings.StreamInitialWindowByteCount
	acceptorCredit := newTestStreamCredit(settings, false)
	open := func(streamId uint64) (*streamState, *streamState) {
		opener, window, err := newStreamOpener(streamId, newTestStreamCredit(settings, false), 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		acceptor, frames := newStreamAcceptor(streamId, acceptorCredit, &protocol.StreamOpen{Window: window})
		if frames.reject != nil {
			t.Fatalf("stream %d refused at the open", streamId)
		}
		return opener, acceptor
	}
	healthyOpener, healthy := open(2)
	frames, err := healthy.accept()
	if err != nil {
		t.Fatal(err)
	}
	testStreamDeliver(t, healthyOpener, frames)

	busyOpener, busy := open(4)
	frames, err = busy.accept()
	rejectErr := &streamRejectError{}
	if frames.reject == nil || readStreamRejectCode(frames.reject.GetCode()) != protocol.StreamRejectCode_SR_BUSY || !errors.As(err, &rejectErr) {
		t.Fatalf("second accept %+v: %v", frames, err)
	}
	testStreamDeliver(t, busyOpener, frames)
	if busy.credit.committed() != settings.StreamMinWindowByteCount {
		t.Fatalf("the refused stream kept credit: %d held", busy.credit.committed())
	}
	// the sibling still moves its bytes and windows
	for range 20 {
		testStreamSend(t, healthyOpener, healthy, testStreamBytes(8000))
		if got := testStreamDrain(t, healthy, healthyOpener); len(got) != 8000 {
			t.Fatalf("the sibling read %d", len(got))
		}
	}
	// and once it ends, a new stream gets its window
	testStreamDeliver(t, healthyOpener, healthy.reset(protocol.StreamResetCode_RST_CANCELLED))
	_, again := open(6)
	if frames, err := again.accept(); err != nil || frames.accept == nil {
		t.Fatalf("after the sibling ended: %+v, %v", frames, err)
	}
}

func TestStreamOpenerFailsLocallyWithoutCredit(t *testing.T) {
	settings := testStreamSettings()
	settings.StreamPeerCreditByteCount = settings.StreamMinWindowByteCount
	credit := newTestStreamCredit(settings, false)
	if _, _, err := newStreamOpener(2, credit, 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := newStreamOpener(4, credit, 0, 0); !errors.Is(err, errStreamCreditExhausted) {
		t.Fatalf("err %v", err)
	}
	if credit.committed() != settings.StreamMinWindowByteCount || credit.streamCount != 1 {
		t.Fatalf("committed %d over %d streams", credit.committed(), credit.streamCount)
	}
	if code, ok := envelopeErrorCode(errStreamCreditExhausted); ok {
		t.Fatalf("the refusal maps to %s here, which the wire layer answers locally", code)
	}
}

// An edge's peer budget grows with its streams, so one slow visitor holding its window cannot stall the
// rest; only the process's credit bounds it.
func TestStreamEdgeBudgetGrowsWithItsStreams(t *testing.T) {
	settings := testStreamSettings()
	settings.StreamPeerCreditByteCount = 2 * settings.StreamMinWindowByteCount
	streamCount := 3 * int(settings.StreamPeerCreditByteCount/settings.StreamMinWindowByteCount)

	edge := newTestStreamCredit(settings, true)
	member := newTestStreamCredit(settings, false)
	edgeOpened, memberOpened := 0, 0
	for streamId := range streamCount {
		edgeStream, _ := newStreamAcceptor(uint64(2*streamId+1), edge, &protocol.StreamOpen{Window: 1 << 16})
		if _, err := edgeStream.accept(); err == nil {
			edgeOpened += 1
		}
		memberStream, _ := newStreamAcceptor(uint64(2*streamId+1), member, &protocol.StreamOpen{Window: 1 << 16})
		if _, err := memberStream.accept(); err == nil {
			memberOpened += 1
		}
	}
	if edgeOpened != streamCount {
		t.Errorf("the edge opened %d of %d", edgeOpened, streamCount)
	}
	if memberOpened != int(settings.StreamPeerCreditByteCount/settings.StreamMinWindowByteCount) {
		t.Errorf("a member opened %d", memberOpened)
	}

	// the process's credit still bounds an edge
	settings = testStreamSettings()
	settings.StreamProcessCreditByteCount = 4 * settings.StreamMinWindowByteCount
	budget := NewSubprotocolBudget(settings, 64*1024*1024)
	bounded := newStreamCredit(settings, budget, true, func() bool { return false })
	opened := 0
	for streamId := range 10 {
		stream, _ := newStreamAcceptor(uint64(2*streamId+1), bounded, &protocol.StreamOpen{Window: 1 << 16})
		if _, err := stream.accept(); err == nil {
			opened += 1
		}
	}
	if opened != 4 || budget.currentUsage().creditByteCount != settings.StreamProcessCreditByteCount {
		t.Errorf("opened %d within the process's credit, %d held", opened, budget.currentUsage().creditByteCount)
	}
}

func TestStreamMaxWindowIsAShareOfThePeersCredit(t *testing.T) {
	settings := testStreamSettings()
	settings.StreamPeerCreditByteCount = 512 * 1024
	if got := newTestStreamCredit(settings, false).maxWindowByteCount(); got != 64*1024 {
		t.Errorf("an eighth of 512 KiB: %d", got)
	}
	settings.StreamPeerCreditByteCount = 8 * 1024 * 1024
	if got := newTestStreamCredit(settings, false).maxWindowByteCount(); got != settings.StreamMaxWindowByteCount {
		t.Errorf("past the maximum: %d", got)
	}
	settings.StreamPeerCreditByteCount = 64 * 1024
	if got := newTestStreamCredit(settings, false).maxWindowByteCount(); got != settings.StreamMinWindowByteCount {
		t.Errorf("below the minimum: %d", got)
	}
}

func TestStreamWindowsAreSmallerUnderMemoryPressure(t *testing.T) {
	settings := testStreamSettings()
	pressed := newStreamCredit(settings, NewSubprotocolBudget(settings, 64*1024*1024), false, func() bool { return true })
	_, window, err := newStreamOpener(2, pressed, 0, 0)
	if err != nil || window != uint32(settings.StreamPressureMinWindowByteCount) {
		t.Fatalf("window %d: %v", window, err)
	}
	acceptor, _ := newStreamAcceptor(3, pressed, &protocol.StreamOpen{Window: 1 << 16})
	if frames, err := acceptor.accept(); err != nil || frames.accept.GetWindow() != uint32(settings.StreamPressureMinWindowByteCount) {
		t.Fatalf("accept %+v: %v", frames, err)
	}
}

func TestStreamMemoryPressureReadsGomemlimit(t *testing.T) {
	previous := debug.SetMemoryLimit(math.MaxInt64)
	defer debug.SetMemoryLimit(previous)
	if streamMemoryPressure() {
		t.Error("pressure with no limit")
	}
	// a limit any test process passes half of
	debug.SetMemoryLimit(1024 * 1024)
	pressed := streamMemoryPressure()
	debug.SetMemoryLimit(math.MaxInt64)
	if !pressed {
		t.Error("no pressure above half of the limit")
	}
}

func TestStreamCreditNeverGoesNegative(t *testing.T) {
	settings := testStreamSettings()
	credit := newTestStreamCredit(settings, false)
	if !credit.commit(1000) {
		t.Fatal("commit")
	}
	credit.release(5000)
	if credit.committed() != 0 || credit.budget.currentUsage().creditByteCount != 0 {
		t.Fatalf("committed %d, budget %d", credit.committed(), credit.budget.currentUsage().creditByteCount)
	}
	credit.closeStream()
	if credit.streamCount != 0 {
		t.Fatal("stream count below zero")
	}
}
