// ComputeStream: an SSE response on a route flagged Streams (§14.2's Host row, §6.6's streaming). Opening one clears
// the status server's write deadline through http.ResponseController, since sidecarhost.Run's server bounds a
// response's writes at 30 s (its read bound needs nothing: net/http clears it once the request's body is read, when its
// background read of the connection starts); sets X-Accel-Buffering: no; and answers 200 with text/event-stream. From then on one writer goroutine owns the connection: it writes each frame the handler sends and,
// whenever StreamCommentInterval passes with nothing written, an SSE comment, which keeps the lb's stall timeouts from
// closing a stream whose provider is thinking. The stream ends when the handler closes it, the client leaves, or the
// request's context ends at the drain's bound (engine.go).
//
// Send blocks until its frame is written or the stream has ended, so a slow client holds back its own handler and no
// one else's. Safe for one handler goroutine; the writer is the stream's own.

package computeservice

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// What an SSE response travels as.
const computeContentTypeEventStream = "text/event-stream"

// An SSE comment line, which every client skips: the keep-alive.
var computeStreamComment = []byte(":\n\n")

// The stream has ended: closed, its client gone, or its request's context over.
var ErrComputeStreamEnded = errors.New("compute stream ended")

// One frame on its way to the writer, and where its outcome goes.
type computeStreamFrame struct {
	bytes  []byte
	result chan error
}

// One SSE response. See the file header.
type ComputeStream struct {
	request    *ComputeRequest
	controller *http.ResponseController
	frames     chan *computeStreamFrame
	closed     chan struct{}
	closeOnce  sync.Once
	// closed once the writer has exited
	done chan struct{}
}

// Opens the request's stream. false once it has answered a refusal instead: a route the design does not stream, a
// request already answered, or deadlines the server would not clear.
func (self *ComputeRequest) Stream() (*ComputeStream, bool) {
	if self.answered {
		return nil, false
	}
	if !self.route.Streams {
		self.engine.alarm("stream_route", "route %s opened a stream, which the design does not give it", self.route.Name)
		self.Unavailable()
		return nil, false
	}
	controller := http.NewResponseController(self.writer)
	// a writer with no deadline of its own has none to clear
	if err := controller.SetWriteDeadline(time.Time{}); err != nil && !errors.Is(err, http.ErrNotSupported) {
		self.engine.alarm("stream_deadline", "route %s could not clear the server's write deadline", self.route.Name)
		self.Unavailable()
		return nil, false
	}
	header := self.writer.Header()
	header.Set("Content-Type", computeContentTypeEventStream)
	header.Set("Cache-Control", "no-cache")
	header.Set("X-Accel-Buffering", "no")
	self.answered = true
	self.status = http.StatusOK
	self.writer.WriteHeader(http.StatusOK)
	if err := controller.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
		// the client is gone: the writer below finds the same and ends at once
		self.engine.log.V(1).Info("[compute] a stream's first flush failed")
	}
	stream := &ComputeStream{
		request:    self,
		controller: controller,
		frames:     make(chan *computeStreamFrame),
		closed:     make(chan struct{}),
		done:       make(chan struct{}),
	}
	self.engine.metrics.streams.Add(1, self.route.Name)
	// ended and joined before the request finishes, so nothing writes after the handler returns
	self.stream = stream
	go stream.run()
	return stream, true
}

// The frame for one event: an event line where event is not empty, then each line of data as a data line, then the
// blank line that ends it. An event or data that would break the framing is an error.
func computeStreamEventBytes(event string, data []byte) ([]byte, error) {
	if strings.ContainsAny(event, "\r\n") {
		return nil, errors.New("an SSE event name holds a line break")
	}
	if bytes.IndexByte(data, '\r') >= 0 {
		return nil, errors.New("SSE data holds a carriage return")
	}
	frame := &bytes.Buffer{}
	if event != "" {
		fmt.Fprintf(frame, "event: %s\n", event)
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		frame.WriteString("data: ")
		frame.Write(line)
		frame.WriteByte('\n')
	}
	frame.WriteByte('\n')
	return frame.Bytes(), nil
}

// Writes one event and waits until it is written. ErrComputeStreamEnded once the stream has ended.
func (self *ComputeStream) Send(event string, data []byte) error {
	frameBytes, err := computeStreamEventBytes(event, data)
	if err != nil {
		return err
	}
	frame := &computeStreamFrame{bytes: frameBytes, result: make(chan error, 1)}
	select {
	case self.frames <- frame:
	case <-self.done:
		return ErrComputeStreamEnded
	}
	// the writer answers every frame it takes before it does anything else
	return <-frame.result
}

// Ends the stream and waits for its writer to exit. Safe more than once.
func (self *ComputeStream) Close() {
	self.closeOnce.Do(func() { close(self.closed) })
	<-self.done
}

// A channel that closes once the stream has ended, for a handler that waits on its provider.
func (self *ComputeStream) Done() <-chan struct{} {
	return self.done
}

// The writer: each frame as it comes, a comment after StreamCommentInterval of silence, until the stream ends.
func (self *ComputeStream) run() {
	defer close(self.done)
	clock := self.request.engine.clock
	interval := self.request.engine.settings.StreamCommentInterval
	requestKey := sidecar.EvsKeyId(self.request.RequestId)
	for {
		var comment <-chan time.Time
		if 0 < interval {
			comment = clock.After(interval)
		}
		select {
		case <-self.closed:
			return
		case <-self.request.Ctx.Done():
			return
		case frame := <-self.frames:
			err := self.write(frame.bytes)
			frame.result <- err
			if err != nil {
				return
			}
		case <-comment:
			testHookBarrier(BarrierComputeStreamCommentBefore, requestKey)
			err := self.write(computeStreamComment)
			testHookBarrier(BarrierComputeStreamCommentAfter, requestKey)
			if err != nil {
				return
			}
		}
	}
}

// Writes and flushes one frame. An error means the client cannot be written to, and the stream ends.
func (self *ComputeStream) write(frameBytes []byte) error {
	if _, err := self.request.writer.Write(frameBytes); err != nil {
		return fmt.Errorf("%w: %w", ErrComputeStreamEnded, err)
	}
	if err := self.controller.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return fmt.Errorf("%w: %w", ErrComputeStreamEnded, err)
	}
	return nil
}
