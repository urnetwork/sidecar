//go:build !js

// §22.6's stream state-machine target, whose seeds in testdata/fuzz/FuzzStreamState run as ordinary
// tests under go test. Not on the js leg, whose worker cannot open the seed directory.

package sidecar

import (
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// What one byte of FuzzStreamState's script does.
const (
	testStreamOpOpenerWrite = iota
	testStreamOpAcceptorWrite
	testStreamOpToAcceptor
	testStreamOpToOpener
	testStreamOpOpenerRead
	testStreamOpAcceptorRead
	testStreamOpAnswer
	testStreamOpClose
	testStreamOpReset
	testStreamOpCount
)

// The bounds §6.7 sets on one stream, which every event must keep: nothing past max_offset or a known
// final size, a buffer no larger than the credit behind it, credit that matches the budget and is all
// back once the stream is done, and a sender never past the peer's window.
func testStreamBounds(t *testing.T, stream *streamState) {
	t.Helper()
	if stream.phase == streamPhaseDone {
		if stream.committed != 0 || stream.buffer.len() != 0 || stream.credit.committed() != 0 {
			t.Fatalf("role %d done holding %d committed, %d buffered", stream.role, stream.committed, stream.buffer.len())
		}
	} else {
		room := stream.maxOffset
		if stream.finalKnown {
			room = stream.finalOffset
		}
		if stream.maxOffset < stream.receivedOffset || (stream.finalKnown && stream.finalOffset < stream.receivedOffset) {
			t.Fatalf("role %d received %d past max %d or final %d", stream.role, stream.receivedOffset, stream.maxOffset, stream.finalOffset)
		}
		if stream.committed != int64(room-stream.consumedOffset) || stream.committed < stream.buffer.len() {
			t.Fatalf("role %d committed %d, room %d, buffered %d", stream.role, stream.committed, room-stream.consumedOffset, stream.buffer.len())
		}
		if stream.credit.committed() != stream.committed {
			t.Fatalf("role %d credit %d, stream %d", stream.role, stream.credit.committed(), stream.committed)
		}
	}
	if stream.credit.budget.currentUsage().creditByteCount != stream.credit.committed() {
		t.Fatalf("role %d budget %d, credit %d", stream.role, stream.credit.budget.currentUsage().creditByteCount, stream.credit.committed())
	}
	if stream.sendMaxOffset < stream.sentOffset {
		t.Fatalf("role %d sent %d past the window %d", stream.role, stream.sentOffset, stream.sendMaxOffset)
	}
}

// §22.6: whatever an opener and an acceptor do, and however the frames between them are bent, nothing
// lands past max_offset, memory stays within each side's credit, and once the frames flow true both
// sides reach the end, closed or reset, with every byte of credit back: they converge or reset. A bent
// frame can lose bytes no receiver can tell were sent, since repeating bytes is allowed, and so stall a
// stream, as any sender that stops can; a stalled stream ends by the reset the wire layer's timeout
// sends (PROTO-M5-02), and with no frame bent every run must converge on its own.
func FuzzStreamState(f *testing.F) {
	f.Add([]byte{testStreamOpOpenerWrite, 40, testStreamOpToAcceptor, 0, testStreamOpAnswer, 0, testStreamOpToOpener, 0, testStreamOpAcceptorRead, 80})
	f.Add([]byte{testStreamOpOpenerWrite, 200, testStreamOpToAcceptor, 1, testStreamOpToAcceptor, 3, testStreamOpReset, 0})
	f.Fuzz(func(t *testing.T, script []byte) {
		next := func() byte {
			if len(script) == 0 {
				return 0
			}
			b := script[0]
			script = script[1:]
			return b
		}
		settings := testStreamSettings()
		early := testStreamBytes(int(next()) * 8)
		opener, window, err := newStreamOpener(2, newTestStreamCredit(settings, false), 0, len(early))
		if err != nil {
			t.Fatal(err)
		}
		acceptor, frames := newStreamAcceptor(2, newTestStreamCredit(settings, false), &protocol.StreamOpen{Window: window, EarlyData: early})
		toOpener := []streamFrames{frames}
		toAcceptor := []streamFrames{}
		// bends a frame the way the script's byte says, or leaves it true
		bent := false
		bend := func(frames streamFrames, how byte) streamFrames {
			if how%8 != 0 && how%8 < 6 {
				bent = true
			}
			switch how % 8 {
			case 1:
				for _, data := range frames.data {
					data.Offset += uint64(next())
				}
			case 2:
				for _, data := range frames.data {
					data.Data = data.Data[:len(data.Data)/2]
				}
			case 3:
				if frames.close != nil {
					frames.close.FinalOffset += uint64(next()) - 128
				}
			case 4:
				if frames.window != nil {
					frames.window.MaxOffset += uint64(next()) * 1024
					frames.window.ConsumedOffset += uint64(next())
				}
			case 5:
				for _, data := range frames.data {
					data.Offset -= min(data.Offset, uint64(next()))
				}
			}
			return frames
		}
		deliver := func(to *streamState, queue *[]streamFrames, outbox *[]streamFrames, how byte) {
			if len(*queue) == 0 {
				return
			}
			frames := bend((*queue)[0], how)
			*queue = (*queue)[1:]
			answer, _ := testStreamDeliver(t, to, frames)
			if answer.reset != nil {
				*outbox = append(*outbox, answer)
			}
		}
		read := func(from *streamState, outbox *[]streamFrames, count int) {
			frames, _, _ := from.read(make([]byte, count))
			if frames.window != nil {
				*outbox = append(*outbox, frames)
			}
		}
		write := func(from *streamState, outbox *[]streamFrames, count int) {
			frames, _, _ := from.write(testStreamBytes(count))
			if len(frames.data) != 0 {
				*outbox = append(*outbox, frames)
			}
		}

		for 0 < len(script) {
			switch next() % testStreamOpCount {
			case testStreamOpOpenerWrite:
				write(opener, &toAcceptor, int(next())*100)
			case testStreamOpAcceptorWrite:
				write(acceptor, &toOpener, int(next())*100)
			case testStreamOpToAcceptor:
				deliver(acceptor, &toAcceptor, &toOpener, next())
			case testStreamOpToOpener:
				deliver(opener, &toOpener, &toAcceptor, next())
			case testStreamOpOpenerRead:
				read(opener, &toAcceptor, int(next())*100)
			case testStreamOpAcceptorRead:
				read(acceptor, &toOpener, int(next())*100)
			case testStreamOpAnswer:
				if next()%4 == 0 {
					frames, _ := acceptor.reject(protocol.StreamRejectCode(next()%6), 0)
					toOpener = append(toOpener, frames)
				} else {
					frames, _ := acceptor.accept()
					toOpener = append(toOpener, frames)
				}
			case testStreamOpClose:
				if next()%2 == 0 {
					frames, _ := opener.closeWrite()
					toAcceptor = append(toAcceptor, frames)
				} else {
					frames, _ := acceptor.closeWrite()
					toOpener = append(toOpener, frames)
				}
			case testStreamOpReset:
				if next()%2 == 0 {
					toAcceptor = append(toAcceptor, opener.reset(protocol.StreamResetCode(next()%9)))
				} else {
					toOpener = append(toOpener, acceptor.reset(protocol.StreamResetCode(next()%9)))
				}
			}
			testStreamBounds(t, opener)
			testStreamBounds(t, acceptor)
		}

		// converge: the frames flow true, the acceptor answers, both sides read everything and close
		for round := 0; ; round += 1 {
			if 200 < round {
				if !bent {
					t.Fatalf("no end: opener phase %d, acceptor phase %d", opener.phase, acceptor.phase)
				}
				toAcceptor = append(toAcceptor, opener.reset(protocol.StreamResetCode_RST_PEER_TIMEOUT))
				toOpener = append(toOpener, acceptor.reset(protocol.StreamResetCode_RST_PEER_TIMEOUT))
			}
			if acceptor.phase == streamPhaseOpening {
				frames, _ := acceptor.accept()
				toOpener = append(toOpener, frames)
			}
			for 0 < len(toAcceptor) || 0 < len(toOpener) {
				deliver(acceptor, &toAcceptor, &toOpener, 0)
				deliver(opener, &toOpener, &toAcceptor, 0)
			}
			read(opener, &toAcceptor, 64*1024)
			read(acceptor, &toOpener, 64*1024)
			for _, stream := range []*streamState{opener, acceptor} {
				if stream.phase != streamPhaseDone && !stream.sendClosed && !(stream.role == streamRoleAcceptor && stream.phase == streamPhaseOpening) {
					frames, _ := stream.closeWrite()
					if stream == opener {
						toAcceptor = append(toAcceptor, frames)
					} else {
						toOpener = append(toOpener, frames)
					}
				}
			}
			testStreamBounds(t, opener)
			testStreamBounds(t, acceptor)
			if opener.phase == streamPhaseDone && acceptor.phase == streamPhaseDone && len(toAcceptor) == 0 && len(toOpener) == 0 {
				break
			}
		}
		if opener.credit.committed() != 0 || acceptor.credit.committed() != 0 {
			t.Fatal("credit left once both ended")
		}
	})
}
