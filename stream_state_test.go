// §6.7's stream rules on a pair of states wired by hand: the open and its answers, the offset and
// final-size table with each PROTOCOL case beside its positive twin, window growth and its floor, data
// before the accept held then discarded, half-close both ways, resets, the zero rule, early data and ids.

package sidecar

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// Windows small enough that a few frames reach each bound.
func testStreamSettings() *SidecarProtocolSettings {
	settings := DefaultSidecarProtocolSettings()
	settings.StreamInitialWindowByteCount = 16 * 1024
	settings.StreamMinWindowByteCount = 32 * 1024
	settings.StreamMaxWindowByteCount = 128 * 1024
	settings.StreamPeerCreditByteCount = 1024 * 1024
	settings.StreamProcessCreditByteCount = 4 * 1024 * 1024
	settings.StreamPressureMinWindowByteCount = 16 * 1024
	return settings
}

// A peer's credit inside a budget of its own, under no memory pressure.
func newTestStreamCredit(settings *SidecarProtocolSettings, edge bool) *streamCredit {
	budget := NewSubprotocolBudget(settings, 64*1024*1024)
	return newStreamCredit(settings, budget, edge, func() bool { return false })
}

// An opener and its acceptor, each granting credit from its own budget.
type testStreamPair struct {
	opener   *streamState
	acceptor *streamState
}

// A pair opened with earlyData, not yet accepted.
func newTestStreamPair(t *testing.T, settings *SidecarProtocolSettings, earlyData []byte) *testStreamPair {
	t.Helper()
	opener, window, err := newStreamOpener(2, newTestStreamCredit(settings, false), 0, len(earlyData))
	if err != nil {
		t.Fatal(err)
	}
	acceptor, frames := newStreamAcceptor(2, newTestStreamCredit(settings, false), &protocol.StreamOpen{Window: window, EarlyData: earlyData})
	if frames.reject != nil || frames.reset != nil {
		t.Fatalf("open refused: %+v", frames)
	}
	return &testStreamPair{opener: opener, acceptor: acceptor}
}

// A pair opened and accepted.
func newTestOpenStreamPair(t *testing.T, settings *SidecarProtocolSettings) *testStreamPair {
	t.Helper()
	pair := newTestStreamPair(t, settings, nil)
	frames, err := pair.acceptor.accept()
	if err != nil {
		t.Fatal(err)
	}
	testStreamDeliver(t, pair.opener, frames)
	return pair
}

// Delivers frames to a stream in their order, answering what the receiver sends back and the first error
// any frame gave.
func testStreamDeliver(t *testing.T, to *streamState, frames streamFrames) (streamFrames, error) {
	t.Helper()
	answer := streamFrames{}
	var firstErr error
	take := func(reply streamFrames, err error) {
		if reply.reset != nil {
			answer.reset = reply.reset
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if frames.accept != nil {
		take(to.receiveAccept(frames.accept))
	}
	if frames.reject != nil {
		take(to.receiveReject(frames.reject))
	}
	for _, data := range frames.data {
		take(to.receiveData(data))
	}
	if frames.window != nil {
		take(to.receiveWindow(frames.window))
	}
	if frames.close != nil {
		take(to.receiveClose(frames.close))
	}
	if frames.reset != nil {
		take(to.receiveReset(frames.reset))
	}
	return answer, firstErr
}

// Writes p from one side and delivers it to the other, failing unless all of it fit.
func testStreamSend(t *testing.T, from *streamState, to *streamState, p []byte) {
	t.Helper()
	frames, n, err := from.write(p)
	if err != nil || n != len(p) {
		t.Fatalf("wrote %d of %d: %v", n, len(p), err)
	}
	if _, err := testStreamDeliver(t, to, frames); err != nil {
		t.Fatal(err)
	}
}

// Reads everything buffered at from, delivering each window to its peer, and answers the bytes.
func testStreamDrain(t *testing.T, from *streamState, peer *streamState) []byte {
	t.Helper()
	read := []byte{}
	buffer := make([]byte, 5000)
	for {
		frames, n, err := from.read(buffer)
		read = append(read, buffer[:n]...)
		if frames.window != nil {
			if _, err := testStreamDeliver(t, peer, frames); err != nil {
				t.Fatal(err)
			}
		}
		if n == 0 || err != nil {
			return read
		}
	}
}

// Synthetic bytes, distinct at every offset.
func testStreamBytes(count int) []byte {
	p := make([]byte, count)
	for i := range p {
		p[i] = byte(i*7 + i/251)
	}
	return p
}

// Whether err is a reset with code, from the side local says.
func testStreamResetWith(err error, code protocol.StreamResetCode, local bool) bool {
	resetErr := &streamResetError{}
	return errors.As(err, &resetErr) && resetErr.code == code && resetErr.local == local
}

func TestStreamOpenAcceptAndDataBothWays(t *testing.T) {
	settings := testStreamSettings()
	early := testStreamBytes(1500)
	pair := newTestStreamPair(t, settings, early)
	if pair.opener.sentOffset != 1500 || pair.acceptor.receivedOffset != 1500 {
		t.Fatalf("early data at %d, %d", pair.opener.sentOffset, pair.acceptor.receivedOffset)
	}
	// StreamData may follow at once, before the accept, within the acceptor's initial window
	more := testStreamBytes(9000)
	testStreamSend(t, pair.opener, pair.acceptor, more)
	frames, err := pair.acceptor.accept()
	if err != nil || frames.accept == nil {
		t.Fatalf("accept %+v: %v", frames, err)
	}
	if frames.accept.GetWindow() != uint32(settings.StreamMinWindowByteCount) {
		t.Errorf("window %d", frames.accept.GetWindow())
	}
	testStreamDeliver(t, pair.opener, frames)
	if pair.opener.phase != streamPhaseOpen || pair.opener.sendMaxOffset != uint64(settings.StreamMinWindowByteCount) {
		t.Fatalf("opener phase %d, may send to %d", pair.opener.phase, pair.opener.sendMaxOffset)
	}
	if got := testStreamDrain(t, pair.acceptor, pair.opener); !bytes.Equal(got, append(bytes.Clone(early), more...)) {
		t.Fatal("the acceptor read other bytes")
	}
	reply := testStreamBytes(20000)
	testStreamSend(t, pair.acceptor, pair.opener, reply)
	if got := testStreamDrain(t, pair.opener, pair.acceptor); !bytes.Equal(got, reply) {
		t.Fatal("the opener read other bytes")
	}
}

// §6.7's offsets row: each case that resets with PROTOCOL beside the twin that does not.
func TestStreamOffsetRules(t *testing.T) {
	settings := testStreamSettings()
	window := uint64(settings.StreamMinWindowByteCount)
	data := func(offset uint64, count int) *protocol.StreamData {
		return &protocol.StreamData{Offset: offset, Data: testStreamBytes(count)}
	}
	cases := []struct {
		name     string
		frames   func(pair *testStreamPair) []func() (streamFrames, error)
		protocol bool
	}{
		{name: "data to max_offset", frames: func(pair *testStreamPair) []func() (streamFrames, error) {
			return testStreamFill(pair, window)
		}},
		{name: "data past max_offset", protocol: true, frames: func(pair *testStreamPair) []func() (streamFrames, error) {
			return append(testStreamFill(pair, window-1), func() (streamFrames, error) { return pair.acceptor.receiveData(data(window-1, 2)) })
		}},
		{name: "data repeating bytes received", frames: func(pair *testStreamPair) []func() (streamFrames, error) {
			return []func() (streamFrames, error){
				func() (streamFrames, error) { return pair.acceptor.receiveData(data(0, 1000)) },
				func() (streamFrames, error) { return pair.acceptor.receiveData(data(500, 1000)) },
			}
		}},
		{name: "data skipping ahead", protocol: true, frames: func(pair *testStreamPair) []func() (streamFrames, error) {
			return []func() (streamFrames, error){
				func() (streamFrames, error) { return pair.acceptor.receiveData(data(0, 1000)) },
				func() (streamFrames, error) { return pair.acceptor.receiveData(data(1001, 10)) },
			}
		}},
		{name: "data of 4000 B", frames: func(pair *testStreamPair) []func() (streamFrames, error) {
			return []func() (streamFrames, error){func() (streamFrames, error) { return pair.acceptor.receiveData(data(0, 4000)) }}
		}},
		{name: "data of 4001 B", protocol: true, frames: func(pair *testStreamPair) []func() (streamFrames, error) {
			return []func() (streamFrames, error){func() (streamFrames, error) { return pair.acceptor.receiveData(data(0, 4001)) }}
		}},
		{name: "final at the bytes received", frames: func(pair *testStreamPair) []func() (streamFrames, error) {
			return []func() (streamFrames, error){
				func() (streamFrames, error) { return pair.acceptor.receiveData(data(0, 1000)) },
				func() (streamFrames, error) {
					return pair.acceptor.receiveClose(&protocol.StreamClose{FinalOffset: 1000})
				},
			}
		}},
		{name: "final below the bytes received", protocol: true, frames: func(pair *testStreamPair) []func() (streamFrames, error) {
			return []func() (streamFrames, error){
				func() (streamFrames, error) { return pair.acceptor.receiveData(data(0, 1000)) },
				func() (streamFrames, error) {
					return pair.acceptor.receiveClose(&protocol.StreamClose{FinalOffset: 999})
				},
			}
		}},
		{name: "final at max_offset", frames: func(pair *testStreamPair) []func() (streamFrames, error) {
			return []func() (streamFrames, error){func() (streamFrames, error) {
				return pair.acceptor.receiveClose(&protocol.StreamClose{FinalOffset: window})
			}}
		}},
		{name: "final past max_offset", protocol: true, frames: func(pair *testStreamPair) []func() (streamFrames, error) {
			return []func() (streamFrames, error){func() (streamFrames, error) {
				return pair.acceptor.receiveClose(&protocol.StreamClose{FinalOffset: window + 1})
			}}
		}},
		{name: "final repeated", frames: func(pair *testStreamPair) []func() (streamFrames, error) {
			return []func() (streamFrames, error){
				func() (streamFrames, error) {
					return pair.acceptor.receiveClose(&protocol.StreamClose{FinalOffset: 2000})
				},
				func() (streamFrames, error) {
					return pair.acceptor.receiveClose(&protocol.StreamClose{FinalOffset: 2000})
				},
			}
		}},
		{name: "final changed", protocol: true, frames: func(pair *testStreamPair) []func() (streamFrames, error) {
			return []func() (streamFrames, error){
				func() (streamFrames, error) {
					return pair.acceptor.receiveClose(&protocol.StreamClose{FinalOffset: 2000})
				},
				func() (streamFrames, error) {
					return pair.acceptor.receiveClose(&protocol.StreamClose{FinalOffset: 2001})
				},
			}
		}},
		{name: "data to the final size", frames: func(pair *testStreamPair) []func() (streamFrames, error) {
			return []func() (streamFrames, error){
				func() (streamFrames, error) {
					return pair.acceptor.receiveClose(&protocol.StreamClose{FinalOffset: 2000})
				},
				func() (streamFrames, error) { return pair.acceptor.receiveData(data(0, 2000)) },
			}
		}},
		{name: "data past the final size", protocol: true, frames: func(pair *testStreamPair) []func() (streamFrames, error) {
			return []func() (streamFrames, error){
				func() (streamFrames, error) {
					return pair.acceptor.receiveClose(&protocol.StreamClose{FinalOffset: 2000})
				},
				func() (streamFrames, error) { return pair.acceptor.receiveData(data(0, 2001)) },
			}
		}},
		{name: "consumed at what was sent", frames: func(pair *testStreamPair) []func() (streamFrames, error) {
			return []func() (streamFrames, error){
				func() (streamFrames, error) {
					frames, _, err := pair.acceptor.write(testStreamBytes(300))
					return frames, err
				},
				func() (streamFrames, error) {
					return pair.acceptor.receiveWindow(&protocol.StreamWindow{ConsumedOffset: 300, MaxOffset: 100000})
				},
			}
		}},
		{name: "consumed past what was sent", protocol: true, frames: func(pair *testStreamPair) []func() (streamFrames, error) {
			return []func() (streamFrames, error){
				func() (streamFrames, error) {
					frames, _, err := pair.acceptor.write(testStreamBytes(300))
					return frames, err
				},
				func() (streamFrames, error) {
					return pair.acceptor.receiveWindow(&protocol.StreamWindow{ConsumedOffset: 301, MaxOffset: 100000})
				},
			}
		}},
	}
	for _, c := range cases {
		pair := newTestOpenStreamPair(t, settings)
		var reset *protocol.StreamReset
		var lastErr error
		for _, frame := range c.frames(pair) {
			frames, err := frame()
			if frames.reset != nil {
				reset = frames.reset
			}
			if err != nil {
				lastErr = err
			}
		}
		if got := reset != nil && readStreamResetCode(reset.GetCode()) == protocol.StreamResetCode_RST_PROTOCOL && errors.Is(lastErr, errStreamProtocol); got != c.protocol {
			t.Errorf("%s: reset %v, err %v", c.name, reset, lastErr)
		}
		if c.protocol && (pair.acceptor.phase != streamPhaseDone || pair.acceptor.credit.committed() != 0) {
			t.Errorf("%s: a reset stream kept its credit", c.name)
		}
	}
}

// Frames filling the acceptor's window to count bytes.
func testStreamFill(pair *testStreamPair, count uint64) []func() (streamFrames, error) {
	frames := []func() (streamFrames, error){}
	for offset := uint64(0); offset < count; offset += MaxStreamDataByteCount {
		size := min(count-offset, MaxStreamDataByteCount)
		at := offset
		frames = append(frames, func() (streamFrames, error) {
			return pair.acceptor.receiveData(&protocol.StreamData{Offset: at, Data: testStreamBytes(int(size))})
		})
	}
	return frames
}

func TestStreamWindowGrowsWhileTheReaderKeepsUp(t *testing.T) {
	settings := testStreamSettings()
	pair := newTestOpenStreamPair(t, settings)
	windows := []uint64{}
	maxOffsets := []uint64{}
	chunk := testStreamBytes(4000)
	for range 200 {
		frames, n, err := pair.opener.write(chunk)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Fatal("stalled with a reader that keeps up")
		}
		testStreamDeliver(t, pair.acceptor, frames)
		// the reader takes everything at once: it keeps up
		buffer := make([]byte, 64*1024)
		readFrames, _, err := pair.acceptor.read(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if window := readFrames.window; window != nil {
			windows = append(windows, window.GetMaxOffset()-window.GetConsumedOffset())
			maxOffsets = append(maxOffsets, window.GetMaxOffset())
			testStreamDeliver(t, pair.opener, readFrames)
		}
	}
	if len(windows) == 0 {
		t.Fatal("no window sent")
	}
	for i, window := range windows {
		if window < uint64(settings.StreamMinWindowByteCount) || uint64(settings.StreamMaxWindowByteCount) < window {
			t.Errorf("window %d outside its bounds", window)
		}
		if 0 < i && (window < windows[i-1] || maxOffsets[i] < maxOffsets[i-1]) {
			t.Errorf("window %d after %d, max_offset %d after %d", window, windows[i-1], maxOffsets[i], maxOffsets[i-1])
		}
	}
	if windows[len(windows)-1] != uint64(settings.StreamMaxWindowByteCount) {
		t.Errorf("grew to %d, not %d", windows[len(windows)-1], settings.StreamMaxWindowByteCount)
	}
	// the credit held is the window's room
	if committed := pair.acceptor.credit.committed(); committed != int64(pair.acceptor.maxOffset-pair.acceptor.consumedOffset) {
		t.Errorf("committed %d, room %d", committed, pair.acceptor.maxOffset-pair.acceptor.consumedOffset)
	}
}

func TestStreamWindowHoldsItsFloorForASlowReader(t *testing.T) {
	settings := testStreamSettings()
	pair := newTestOpenStreamPair(t, settings)
	buffer := make([]byte, 1000)
	for range 100 {
		frames, _, err := pair.opener.write(testStreamBytes(4000))
		if err != nil {
			t.Fatal(err)
		}
		testStreamDeliver(t, pair.acceptor, frames)
		// the reader takes a quarter of each write, so bytes pile up
		readFrames, _, err := pair.acceptor.read(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if window := readFrames.window; window != nil {
			if window.GetMaxOffset()-window.GetConsumedOffset() != uint64(settings.StreamMinWindowByteCount) {
				t.Fatalf("a slow reader's window %d", window.GetMaxOffset()-window.GetConsumedOffset())
			}
			testStreamDeliver(t, pair.opener, readFrames)
		}
	}
	// the sender never passed the window, and the buffer never passed what is committed
	if uint64(pair.acceptor.credit.committed()) < uint64(pair.acceptor.buffer.len()) || pair.acceptor.maxOffset < pair.acceptor.receivedOffset {
		t.Fatal("past the window")
	}
}

func TestStreamDataBeforeTheAcceptIsDiscardedOnReject(t *testing.T) {
	settings := testStreamSettings()
	pair := newTestStreamPair(t, settings, testStreamBytes(2000))
	frames, n, err := pair.opener.write(testStreamBytes(32 * 1024))
	if err != nil || n != int(settings.StreamInitialWindowByteCount)-2000 {
		t.Fatalf("wrote %d before the accept: %v", n, err)
	}
	testStreamDeliver(t, pair.acceptor, frames)
	if held := pair.acceptor.buffer.len(); held != settings.StreamInitialWindowByteCount {
		t.Fatalf("held %d", held)
	}
	if committed := pair.acceptor.credit.committed(); committed != settings.StreamInitialWindowByteCount {
		t.Fatalf("committed %d", committed)
	}
	rejectFrames, err := pair.acceptor.reject(protocol.StreamRejectCode_SR_DENIED, 0)
	if rejectFrames.reject == nil || readStreamRejectCode(rejectFrames.reject.GetCode()) != protocol.StreamRejectCode_SR_DENIED || err == nil {
		t.Fatalf("reject %+v: %v", rejectFrames, err)
	}
	if pair.acceptor.buffer.len() != 0 || pair.acceptor.credit.committed() != 0 || pair.acceptor.credit.budget.currentUsage().creditByteCount != 0 {
		t.Fatal("the rejected stream kept its bytes or credit")
	}
	if _, err := testStreamDeliver(t, pair.opener, rejectFrames); err == nil {
		t.Fatal("the opener took the reject as nothing")
	}
	rejectErr := &streamRejectError{}
	if _, _, err := pair.opener.read(make([]byte, 10)); !errors.As(err, &rejectErr) || rejectErr.code != protocol.StreamRejectCode_SR_DENIED || rejectErr.local {
		t.Fatalf("opener reads %v", err)
	}
	if pair.opener.credit.committed() != 0 {
		t.Fatal("the opener kept its credit")
	}
}

func TestStreamHalfCloseBothWays(t *testing.T) {
	settings := testStreamSettings()
	pair := newTestOpenStreamPair(t, settings)
	request := testStreamBytes(10000)
	testStreamSend(t, pair.opener, pair.acceptor, request)
	closeFrames, err := pair.opener.closeWrite()
	if err != nil || closeFrames.close.GetFinalOffset() != 10000 {
		t.Fatalf("close %+v: %v", closeFrames, err)
	}
	testStreamDeliver(t, pair.acceptor, closeFrames)
	if _, _, err := pair.opener.write([]byte{1}); !errors.Is(err, errStreamClosed) {
		t.Fatalf("write after close: %v", err)
	}
	if got := testStreamDrain(t, pair.acceptor, pair.opener); !bytes.Equal(got, request) {
		t.Fatal("request")
	}
	if _, _, err := pair.acceptor.read(make([]byte, 10)); err != io.EOF {
		t.Fatalf("the acceptor reads %v at the end", err)
	}
	// the acceptor's half still runs
	reply := testStreamBytes(30000)
	testStreamSend(t, pair.acceptor, pair.opener, reply)
	closeFrames, _ = pair.acceptor.closeWrite()
	testStreamDeliver(t, pair.opener, closeFrames)
	if got := testStreamDrain(t, pair.opener, pair.acceptor); !bytes.Equal(got, reply) {
		t.Fatal("reply")
	}
	for _, stream := range []*streamState{pair.opener, pair.acceptor} {
		if stream.phase != streamPhaseDone || stream.err != nil || stream.credit.committed() != 0 {
			t.Fatalf("role %d: phase %d, err %v, committed %d", stream.role, stream.phase, stream.err, stream.credit.committed())
		}
		if _, _, err := stream.read(make([]byte, 10)); err != io.EOF {
			t.Errorf("role %d reads %v after the end", stream.role, err)
		}
		if _, _, err := stream.write([]byte{1}); !errors.Is(err, errStreamDone) {
			t.Errorf("role %d writes %v after the end", stream.role, err)
		}
	}
	// every byte acked as delivered
	if pair.opener.peerConsumedOffset != 10000 || pair.acceptor.peerConsumedOffset != 30000 {
		t.Errorf("acked %d and %d", pair.opener.peerConsumedOffset, pair.acceptor.peerConsumedOffset)
	}
}

func TestStreamResetEndsBothSidesAndGivesBackCredit(t *testing.T) {
	settings := testStreamSettings()
	pair := newTestOpenStreamPair(t, settings)
	testStreamSend(t, pair.opener, pair.acceptor, testStreamBytes(5000))
	resetFrames := pair.acceptor.reset(protocol.StreamResetCode_RST_CANCELLED)
	if resetFrames.reset == nil || resetFrames.reset.GetFinalOffset() != 0 {
		t.Fatalf("reset %+v", resetFrames)
	}
	if !testStreamResetWith(pair.acceptor.err, protocol.StreamResetCode_RST_CANCELLED, true) || pair.acceptor.credit.committed() != 0 {
		t.Fatal("the resetting side")
	}
	_, err := testStreamDeliver(t, pair.opener, resetFrames)
	if !testStreamResetWith(err, protocol.StreamResetCode_RST_CANCELLED, false) || pair.opener.credit.committed() != 0 {
		t.Fatalf("the reset side: %v", err)
	}
	if _, _, err := pair.opener.read(make([]byte, 10)); !testStreamResetWith(err, protocol.StreamResetCode_RST_CANCELLED, false) {
		t.Fatalf("read after the reset: %v", err)
	}
	// frames still in flight after a reset change nothing
	if frames, err := pair.opener.receiveData(&protocol.StreamData{Offset: 0, Data: []byte{1}}); err != nil || frames.reset != nil {
		t.Fatal("a late frame")
	}
}

// §6.11's zero rule: a zero or unknown reject is INVALID, a zero or unknown reset PROTOCOL, never retry
// or drain.
func TestStreamZeroCodesAreProtocolErrors(t *testing.T) {
	settings := testStreamSettings()
	for _, code := range []uint32{0, 6, 0xFFFFFFFF} {
		pair := newTestStreamPair(t, settings, nil)
		_, err := testStreamDeliver(t, pair.opener, streamFrames{reject: &protocol.StreamReject{Code: code}})
		rejectErr := &streamRejectError{}
		if !errors.As(err, &rejectErr) || rejectErr.code != protocol.StreamRejectCode_SR_INVALID {
			t.Errorf("reject %d: %v", code, err)
		}
	}
	for _, code := range []uint32{0, 9, 0xFFFFFFFF} {
		pair := newTestOpenStreamPair(t, settings)
		_, err := testStreamDeliver(t, pair.acceptor, streamFrames{reset: &protocol.StreamReset{Code: code}})
		if !testStreamResetWith(err, protocol.StreamResetCode_RST_PROTOCOL, false) {
			t.Errorf("reset %d: %v", code, err)
		}
	}
	// a known code passes as itself, BUSY's retry included
	pair := newTestStreamPair(t, settings, nil)
	_, err := testStreamDeliver(t, pair.opener, streamFrames{reject: &protocol.StreamReject{Code: uint32(protocol.StreamRejectCode_SR_BUSY), RetryAfterMs: 500}})
	rejectErr := &streamRejectError{}
	if !errors.As(err, &rejectErr) || rejectErr.code != protocol.StreamRejectCode_SR_BUSY || rejectErr.retryAfterMs != 500 {
		t.Errorf("busy: %v", err)
	}
	// and this side never sends a zero
	pair = newTestStreamPair(t, settings, nil)
	if frames, _ := pair.acceptor.reject(protocol.StreamRejectCode_SR_UNSPECIFIED, 0); frames.reject.GetCode() != uint32(protocol.StreamRejectCode_SR_INVALID) {
		t.Errorf("sent reject %d", frames.reject.GetCode())
	}
	pair = newTestOpenStreamPair(t, settings)
	if frames := pair.opener.reset(protocol.StreamResetCode_RST_UNSPECIFIED); frames.reset.GetCode() != uint32(protocol.StreamResetCode_RST_PROTOCOL) {
		t.Errorf("sent reset %d", frames.reset.GetCode())
	}
}

func TestStreamResetWithABadFinalSizeReadsAsProtocol(t *testing.T) {
	settings := testStreamSettings()
	pair := newTestOpenStreamPair(t, settings)
	testStreamSend(t, pair.opener, pair.acceptor, testStreamBytes(3000))
	_, err := testStreamDeliver(t, pair.acceptor, streamFrames{reset: &protocol.StreamReset{Code: uint32(protocol.StreamResetCode_RST_DRAINING), FinalOffset: 2000}})
	if !testStreamResetWith(err, protocol.StreamResetCode_RST_PROTOCOL, false) {
		t.Fatalf("err %v", err)
	}
}

func TestStreamFramesOutOfTheirPhaseResetWithProtocol(t *testing.T) {
	settings := testStreamSettings()
	// an acceptor sends nothing before it accepts
	for _, frames := range []streamFrames{
		{data: []*protocol.StreamData{{Offset: 0, Data: []byte{1}}}},
		{close: &protocol.StreamClose{FinalOffset: 0}},
	} {
		pair := newTestStreamPair(t, settings, nil)
		if answer, err := testStreamDeliver(t, pair.opener, frames); answer.reset == nil || !errors.Is(err, errStreamProtocol) {
			t.Errorf("before the accept: %v", err)
		}
	}
	// an accept or reject after the open was answered
	pair := newTestOpenStreamPair(t, settings)
	if answer, err := testStreamDeliver(t, pair.opener, streamFrames{accept: &protocol.StreamAccept{Window: 1}}); answer.reset == nil || !errors.Is(err, errStreamProtocol) {
		t.Errorf("a second accept: %v", err)
	}
	pair = newTestOpenStreamPair(t, settings)
	if answer, err := testStreamDeliver(t, pair.opener, streamFrames{reject: &protocol.StreamReject{Code: 1}}); answer.reset == nil || !errors.Is(err, errStreamProtocol) {
		t.Errorf("a late reject: %v", err)
	}
	// and an acceptor that has not accepted writes nothing
	pair = newTestStreamPair(t, settings, nil)
	if _, _, err := pair.acceptor.write([]byte{1}); !errors.Is(err, errStreamNotAccepted) {
		t.Errorf("acceptor write: %v", err)
	}
}

func TestStreamEarlyDataBounds(t *testing.T) {
	settings := testStreamSettings()
	credit := newTestStreamCredit(settings, false)
	if _, _, err := newStreamOpener(2, credit, 0, MaxStreamEarlyDataByteCount+1); !errors.Is(err, errStreamEarlyData) {
		t.Errorf("past 2,048 B: %v", err)
	}
	if _, _, err := newStreamOpener(2, credit, 1000, 1001); !errors.Is(err, errStreamEarlyData) {
		t.Errorf("past the acceptor's window: %v", err)
	}
	if credit.committed() != 0 {
		t.Fatal("a refused open committed credit")
	}
	if _, window, err := newStreamOpener(2, credit, 1000, 1000); err != nil || window != uint32(settings.StreamMinWindowByteCount) {
		t.Errorf("within it: %d, %v", window, err)
	}
	// an acceptor refuses a StreamOpen whose early data passes its bounds
	for _, early := range [][]byte{testStreamBytes(MaxStreamEarlyDataByteCount + 1)} {
		acceptor, frames := newStreamAcceptor(3, newTestStreamCredit(settings, false), &protocol.StreamOpen{Window: 1 << 16, EarlyData: early})
		if frames.reset == nil || readStreamResetCode(frames.reset.GetCode()) != protocol.StreamResetCode_RST_PROTOCOL || acceptor.credit.committed() != 0 {
			t.Errorf("acceptor took %d B early", len(early))
		}
	}
}

func TestStreamIdsNeverRepeat(t *testing.T) {
	low, high := Id{0x01}, Id{0x02}
	lowIds, err := newStreamIds(low, high)
	if err != nil {
		t.Fatal(err)
	}
	highIds, _ := newStreamIds(high, low)
	for want := uint64(2); want <= 10; want += 2 {
		if streamId, _ := lowIds.open(); streamId != want {
			t.Fatalf("low side opened %d, want %d", streamId, want)
		}
	}
	for want := uint64(1); want <= 9; want += 2 {
		streamId, _ := highIds.open()
		if streamId != want {
			t.Fatalf("high side opened %d, want %d", streamId, want)
		}
		if err := lowIds.accept(streamId); err != nil {
			t.Fatalf("low side refused %d: %v", streamId, err)
		}
	}
	// a repeat, a lower id, and this side's own parity are each a reuse
	for _, streamId := range []uint64{9, 7, 12} {
		if err := lowIds.accept(streamId); !errors.Is(err, errStreamIdReused) {
			t.Errorf("%d: %v", streamId, err)
		}
	}
	if err := lowIds.accept(15); err != nil {
		t.Errorf("a gap is no reuse: %v", err)
	}
	if _, err := newStreamIds(low, low); !errors.Is(err, errStreamIdsSelf) {
		t.Errorf("self: %v", err)
	}
	spent := &streamIds{next: 0xFFFFFFFFFFFFFFFE, peerNext: 1}
	if streamId, err := spent.open(); err != nil || streamId != 0xFFFFFFFFFFFFFFFE {
		t.Fatalf("the last id: %d, %v", streamId, err)
	}
	if _, err := spent.open(); !errors.Is(err, errStreamIdsExhausted) {
		t.Errorf("past the last id: %v", err)
	}
}

// An opener that closes before the acceptor answers has fixed its final size, so the accept commits
// nothing past it: the credit held stays the room up to the final size (found by FuzzStreamState).
func TestStreamAcceptAfterTheOpenerClosedCommitsNothingMore(t *testing.T) {
	settings := testStreamSettings()
	pair := newTestStreamPair(t, settings, testStreamBytes(384))
	closeFrames, err := pair.opener.closeWrite()
	if err != nil {
		t.Fatal(err)
	}
	testStreamDeliver(t, pair.acceptor, closeFrames)
	if committed := pair.acceptor.credit.committed(); committed != 384 {
		t.Fatalf("committed %d once the final size is known", committed)
	}
	frames, err := pair.acceptor.accept()
	if err != nil || frames.accept == nil {
		t.Fatalf("accept %+v: %v", frames, err)
	}
	if committed := pair.acceptor.credit.committed(); committed != 384 {
		t.Fatalf("the accept committed %d", committed)
	}
	testStreamDeliver(t, pair.opener, frames)
	if got := testStreamDrain(t, pair.acceptor, pair.opener); len(got) != 384 || pair.acceptor.credit.committed() != 0 {
		t.Fatalf("read %d, committed %d", len(got), pair.acceptor.credit.committed())
	}
}
