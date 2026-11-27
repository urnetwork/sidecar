//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// A call's answer as its callers receive it (DESIGN-COMPUTE §8.5's keepalive and retries rows; D-GW-5; GW-M12-03): the
// front's producer writes it from the router's events, and each caller follows it onto its own connection, the first
// caller and, through the call table (gateway_retry.go), a retry that joins the call.
//
//	head       the answer's status and type, decided once: a stream's 200 text/event-stream at the router's first event
//	           (or once GatewaySettings.FirstEventWait passes), else an error's status and JSON, or a whole JSON body's
//	frames     what follows the head, in order, each written whole: a stream's server-sent events, or one body. They
//	           are kept for the call's life, so a caller that joins late reads every frame from the first; the terminal
//	           frame is appended whatever becomes of the callers, so a joined retry sees it (§8.5)
//	follow     a caller writes the head and each frame as it lands, flushing each, and on a stream a keepalive
//	           (`: ping`, or Messages' ping event) once it has written nothing for GatewaySettings.KeepaliveInterval,
//	           read off the gateway's Clock; it stops at the end, at its context's end, or at a write that fails (its
//	           harness left), answering whether every frame reached it
//	framing    an event of Responses and Messages is "event: <type>" and "data: <json>" (Open Responses: the event
//	           field equals the body's type, and no id); a chunk of Chat Completions is "data: <json>" alone; a comment
//	           is ": <text>"; each ends with a blank line
//
// gatewayAnswer is safe for concurrent use: the producer appends under stateLock, and each follower reads a snapshot
// under it and writes outside it.

package sidecar

import (
	"context"
	"net/http"
	"slices"
	"sync"
	"time"
)

// The server-sent events' framing and content types: format values.
const (
	gatewayContentTypeEventStream = "text/event-stream"
	gatewaySseKeepaliveComment    = ": ping\n\n"
)

// An event frame: "event: <name>", "data: <data>", and a blank line.
func gatewaySseEvent(name string, data []byte) []byte {
	frame := make([]byte, 0, len("event: \ndata: \n\n")+len(name)+len(data))
	frame = append(frame, "event: "...)
	frame = append(frame, name...)
	frame = append(frame, "\ndata: "...)
	frame = append(frame, data...)
	return append(frame, "\n\n"...)
}

// A data frame: "data: <data>" and a blank line.
func gatewaySseData(data []byte) []byte {
	frame := make([]byte, 0, len("data: \n\n")+len(data))
	frame = append(frame, "data: "...)
	frame = append(frame, data...)
	return append(frame, "\n\n"...)
}

// One call's answer (see the file header).
type gatewayAnswer struct {
	stateLock sync.Mutex
	// set once by head
	headed      bool
	status      int
	contentType string
	retryAfter  string
	streaming   bool
	frames      [][]byte
	byteCount   int
	ended       bool
	// closed and replaced at each change, which followers wait on
	changed chan struct{}
}

// An answer with no head yet.
func newGatewayAnswer() *gatewayAnswer {
	return &gatewayAnswer{changed: make(chan struct{})}
}

// Wakes the followers. Called with stateLock held, after a change.
func (self *gatewayAnswer) notifyWithLock() {
	close(self.changed)
	self.changed = make(chan struct{})
}

// Decides the head: a stream's, or a whole answer's status and type. A second head is ignored.
func (self *gatewayAnswer) head(status int, contentType string, retryAfter string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.headed {
		return
	}
	self.headed = true
	self.status, self.contentType, self.retryAfter = status, contentType, retryAfter
	self.streaming = contentType == gatewayContentTypeEventStream
	self.notifyWithLock()
}

// Whether the head is decided.
func (self *gatewayAnswer) isHeaded() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.headed
}

// Appends frames, each whole. Nothing is appended after the end.
func (self *gatewayAnswer) append(frames ...[]byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.ended {
		return
	}
	for _, frame := range frames {
		self.frames = append(self.frames, frame)
		self.byteCount += len(frame)
	}
	self.notifyWithLock()
}

// Ends the answer: no frame follows.
func (self *gatewayAnswer) end() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.ended {
		return
	}
	self.ended = true
	self.notifyWithLock()
}

// Whether the answer ended.
func (self *gatewayAnswer) isEnded() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.ended
}

// The bytes the frames hold so far.
func (self *gatewayAnswer) size() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.byteCount
}

// A copy of the answer whole, for keeping: its head, frames and whether it ended.
type gatewayAnswerSnapshot struct {
	Headed      bool     `json:"headed"`
	Status      int      `json:"status"`
	ContentType string   `json:"content_type"`
	RetryAfter  string   `json:"retry_after,omitempty"`
	Frames      [][]byte `json:"frames"`
	Ended       bool     `json:"ended"`
}

// The answer as it stands.
func (self *gatewayAnswer) snapshot() *gatewayAnswerSnapshot {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return &gatewayAnswerSnapshot{
		Headed:      self.headed,
		Status:      self.status,
		ContentType: self.contentType,
		RetryAfter:  self.retryAfter,
		Frames:      slices.Clone(self.frames),
		Ended:       self.ended,
	}
}

// An ended answer from what was kept of one.
func gatewayAnswerOf(snapshot *gatewayAnswerSnapshot) *gatewayAnswer {
	answer := newGatewayAnswer()
	answer.head(snapshot.Status, snapshot.ContentType, snapshot.RetryAfter)
	answer.append(snapshot.Frames...)
	answer.end()
	return answer
}

// How a caller follows an answer onto its connection.
type gatewayFollow struct {
	clock Clock
	// Non-positive sends none.
	keepalive time.Duration
	// The frame a keepalive is: gatewaySseKeepaliveComment, or Messages' ping event.
	keepaliveFrame []byte
	// Each frame's write, before the next is read; a test steers it.
	written func(frame []byte)
}

// Writes the answer onto writer as it lands (see the file header's follow row): true once the head and every frame,
// the terminal among them, were written and flushed; false where ctx ended or a write failed first.
func (self *gatewayAnswer) follow(ctx context.Context, writer http.ResponseWriter, follow *gatewayFollow) bool {
	controller := http.NewResponseController(writer)
	headerWritten := false
	next := 0
	write := func(frame []byte) bool {
		if _, err := writer.Write(frame); err != nil {
			return false
		}
		if err := controller.Flush(); err != nil && err != http.ErrNotSupported {
			return false
		}
		if follow.written != nil {
			follow.written(frame)
		}
		return true
	}
	for {
		headed, status, contentType, retryAfter, streaming, frames, ended, changed := func() (bool, int, string, string, bool, [][]byte, bool, chan struct{}) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.headed, self.status, self.contentType, self.retryAfter, self.streaming, self.frames[next:], self.ended, self.changed
		}()
		if headed && !headerWritten {
			header := writer.Header()
			header.Set("Content-Type", contentType)
			if streaming {
				header.Set("Cache-Control", "no-cache")
			}
			if retryAfter != "" {
				header.Set("Retry-After", retryAfter)
			}
			writer.WriteHeader(status)
			headerWritten = true
			if err := controller.Flush(); err != nil && err != http.ErrNotSupported {
				return false
			}
		}
		if headed {
			for _, frame := range frames {
				if !write(frame) {
					return false
				}
				next++
			}
			if ended {
				return true
			}
		}
		var keepalive <-chan time.Time
		if headed && streaming && 0 < follow.keepalive && 0 < len(follow.keepaliveFrame) {
			keepalive = follow.clock.After(follow.keepalive)
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return false
		case <-keepalive:
			if !write(follow.keepaliveFrame) {
				return false
			}
		}
	}
}
