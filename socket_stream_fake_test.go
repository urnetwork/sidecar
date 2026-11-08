//go:build !sidecar_http

// An in-memory socketStream pair, what listeners and dialers build and test on until §6's streams land
// (socket_stream.go). Each direction holds at most a credit's worth of bytes, so a writer blocks as on a
// real stream, and every promise of the seam holds: FIN, close, reset and net.Conn's deadlines, which
// are wall-clock times by net.Conn's definition and so the one place here that reads the wall clock.

package sidecar

import (
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// One direction of a pipe: what one end wrote and the other has not read.
type socketPipeDirection struct {
	buffer []byte
	// the writer sent FIN
	finished bool
	// the reader stopped reading, so what arrives is dropped
	readerClosed bool
}

// What both ends share.
type socketPipe struct {
	capacity int

	stateLock sync.Mutex
	// closed and replaced at each change, so a waiting end reads the state again
	changed chan struct{}
	// [0] carries end 0's writes to end 1, [1] the other way
	directions [2]*socketPipeDirection
	// the end that reset, -1 for none, and the code
	resetIndex int
	resetCode  protocol.StreamResetCode
}

// One end of a pipe.
type socketPipeEnd struct {
	pipe  *socketPipe
	index int
	// under pipe.stateLock
	readDeadline  time.Time
	writeDeadline time.Time
	closed        bool
	writeClosed   bool
}

var _ socketStream = (*socketPipeEnd)(nil)

// Two connected ends, each direction holding at most capacity bytes.
func newSocketStreamPipe(capacity int) (*socketPipeEnd, *socketPipeEnd) {
	pipe := &socketPipe{
		capacity:   capacity,
		changed:    make(chan struct{}),
		directions: [2]*socketPipeDirection{{}, {}},
		resetIndex: -1,
	}
	return &socketPipeEnd{pipe: pipe, index: 0}, &socketPipeEnd{pipe: pipe, index: 1}
}

// Wakes every waiting end.
func (self *socketPipe) notifyWithLock() {
	close(self.changed)
	self.changed = make(chan struct{})
}

// Waits for a change or for deadline, a zero deadline being none.
func socketPipeWait(changed chan struct{}, deadline time.Time) {
	if deadline.IsZero() {
		<-changed
		return
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-changed:
	case <-timer.C:
	}
}

// Whether deadline has passed, a zero deadline never.
func socketPipeExpired(deadline time.Time) bool {
	return !deadline.IsZero() && !time.Now().Before(deadline)
}

// The reset both ends see, or nil.
func (self *socketPipeEnd) resetErrWithLock() error {
	if self.pipe.resetIndex < 0 {
		return nil
	}
	return &socketStreamResetError{Code: self.pipe.resetCode, Local: self.pipe.resetIndex == self.index}
}

// See socketStream.
func (self *socketPipeEnd) Read(b []byte) (int, error) {
	for {
		self.pipe.stateLock.Lock()
		in := self.pipe.directions[1-self.index]
		if err := self.resetErrWithLock(); err != nil {
			self.pipe.stateLock.Unlock()
			return 0, err
		}
		if self.closed {
			self.pipe.stateLock.Unlock()
			return 0, net.ErrClosed
		}
		if socketPipeExpired(self.readDeadline) {
			self.pipe.stateLock.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
		if len(b) == 0 {
			self.pipe.stateLock.Unlock()
			return 0, nil
		}
		if 0 < len(in.buffer) {
			n := copy(b, in.buffer)
			in.buffer = in.buffer[n:]
			self.pipe.notifyWithLock()
			self.pipe.stateLock.Unlock()
			return n, nil
		}
		if in.finished {
			self.pipe.stateLock.Unlock()
			return 0, io.EOF
		}
		changed := self.pipe.changed
		deadline := self.readDeadline
		self.pipe.stateLock.Unlock()
		socketPipeWait(changed, deadline)
	}
}

// See socketStream.
func (self *socketPipeEnd) Write(b []byte) (int, error) {
	written := 0
	for {
		self.pipe.stateLock.Lock()
		out := self.pipe.directions[self.index]
		if err := self.resetErrWithLock(); err != nil {
			self.pipe.stateLock.Unlock()
			return written, err
		}
		if self.closed || self.writeClosed {
			self.pipe.stateLock.Unlock()
			return written, net.ErrClosed
		}
		if socketPipeExpired(self.writeDeadline) {
			self.pipe.stateLock.Unlock()
			return written, os.ErrDeadlineExceeded
		}
		if written == len(b) {
			self.pipe.stateLock.Unlock()
			return written, nil
		}
		if out.readerClosed {
			// a reader that stopped reading drops what arrives, credit returned at once
			self.pipe.stateLock.Unlock()
			return len(b), nil
		}
		if room := self.pipe.capacity - len(out.buffer); 0 < room {
			n := min(room, len(b)-written)
			out.buffer = append(out.buffer, b[written:written+n]...)
			written += n
			self.pipe.notifyWithLock()
			self.pipe.stateLock.Unlock()
			continue
		}
		changed := self.pipe.changed
		deadline := self.writeDeadline
		self.pipe.stateLock.Unlock()
		socketPipeWait(changed, deadline)
	}
}

// See socketStream.
func (self *socketPipeEnd) CloseWrite() error {
	self.pipe.stateLock.Lock()
	defer self.pipe.stateLock.Unlock()
	if err := self.resetErrWithLock(); err != nil {
		return err
	}
	if self.closed {
		return net.ErrClosed
	}
	self.writeClosed = true
	self.pipe.directions[self.index].finished = true
	self.pipe.notifyWithLock()
	return nil
}

// See socketStream.
func (self *socketPipeEnd) Close() error {
	self.pipe.stateLock.Lock()
	defer self.pipe.stateLock.Unlock()
	if self.closed {
		return net.ErrClosed
	}
	self.closed = true
	self.pipe.directions[self.index].finished = true
	in := self.pipe.directions[1-self.index]
	in.readerClosed = true
	in.buffer = nil
	self.pipe.notifyWithLock()
	return nil
}

// See socketStream.
func (self *socketPipeEnd) Reset(code protocol.StreamResetCode) error {
	self.pipe.stateLock.Lock()
	defer self.pipe.stateLock.Unlock()
	if 0 <= self.pipe.resetIndex {
		return nil
	}
	self.pipe.resetIndex = self.index
	self.pipe.resetCode = code
	for _, direction := range self.pipe.directions {
		direction.buffer = nil
	}
	self.pipe.notifyWithLock()
	return nil
}

// See socketStream.
func (self *socketPipeEnd) SetReadDeadline(t time.Time) error {
	self.pipe.stateLock.Lock()
	defer self.pipe.stateLock.Unlock()
	self.readDeadline = t
	self.pipe.notifyWithLock()
	return nil
}

// See socketStream.
func (self *socketPipeEnd) SetWriteDeadline(t time.Time) error {
	self.pipe.stateLock.Lock()
	defer self.pipe.stateLock.Unlock()
	self.writeDeadline = t
	self.pipe.notifyWithLock()
	return nil
}
