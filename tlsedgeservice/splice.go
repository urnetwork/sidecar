// §13.5's step 6: the visitor's bytes to the listener's stream and back, untouched, under §6's credit,
// which the stream's Write waits on. A visitor's FIN maps to StreamClose (CloseWrite) and a listener's
// StreamClose to a FIN, so each half closes by itself; a visitor's reset maps to StreamReset and a
// listener's StreamReset to a reset of the visitor's connection.
//
// Each chunk is spent from the network's lease before it moves (lease.go) and drawn from its endpoint's
// bandwidth bucket (§13.9), the splice waiting out a draw's debt on the engine's clock.
//
// A spliced connection ends, once, when both halves have closed, when either side resets, when no byte
// has moved for idle_timeout_s, at its grant's expire_time_millis, on a kill of its name, when its
// network's lease runs out (RST_QUOTA), and at a drain's or a close's reset. Whatever ends it closes both
// sides, which is what stops the two copies.

package tlsedgeservice

import (
	"errors"
	"io"
	"net"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// Closes the visitor's connection so that its peer sees a reset rather than a clean end, where the
// socket can say so.
func tlsEdgeConnReset(conn net.Conn) {
	inner := conn
	if proxied, ok := conn.(*ProxyHeaderConn); ok {
		inner = proxied.Conn
	}
	if lingerer, ok := inner.(interface{ SetLinger(sec int) error }); ok {
		lingerer.SetLinger(0)
	}
	conn.Close()
}

// Ends the connection, once: the first reason stands. A clean end closes both sides; a listener's reset
// resets the visitor; anything else resets the stream with code and the visitor with it.
func (self *tlsEdgeConnection) end(reason string, code protocol.StreamResetCode) {
	self.endOnce.Do(func() {
		self.endReason = reason
		close(self.ended)
		switch reason {
		case tlsStreamEndClosed:
			self.stream.Close()
			self.conn.Close()
		case tlsStreamEndListenerReset:
			self.stream.Close()
			tlsEdgeConnReset(self.conn)
		case tlsStreamEndVisitorReset:
			self.stream.Reset(code)
			self.conn.Close()
		default:
			self.stream.Reset(code)
			tlsEdgeConnReset(self.conn)
		}
	})
}

// Accounts one chunk before it moves: the lease, then the bandwidth bucket. False when the connection
// ended instead.
func (self *tlsEdgeConnection) admitChunk(byteCount int) bool {
	service := self.service
	select {
	case <-self.ended:
		return false
	default:
	}
	// a byte that arrived is activity, whether or not its write has finished
	self.lastActiveNanos.Store(service.clock.Now().UnixNano())
	if !service.leases.Spend(self.lease, byteCount) {
		self.end(tlsStreamEndQuota, protocol.StreamResetCode_RST_QUOTA)
		return false
	}
	if bucket := self.hold.Bandwidth(); bucket != nil {
		if wait := bucket.Draw(byteCount, service.clock.Now()); 0 < wait {
			select {
			case <-self.ended:
				return false
			case <-service.clock.After(wait):
			}
		}
	}
	return true
}

// Counts one chunk that moved.
func (self *tlsEdgeConnection) movedChunk(byteCount int, direction string) {
	self.byteCount.Add(int64(byteCount))
	self.service.metrics.bytes.Add(float64(byteCount), direction)
}

// Visitor to listener, until the visitor's FIN, which half-closes the stream, or an end.
func (self *tlsEdgeConnection) copyToListener() {
	buffer := make([]byte, self.service.settings.SpliceBufferByteCount)
	for {
		n, err := self.conn.Read(buffer)
		if 0 < n {
			if !self.admitChunk(n) {
				return
			}
			if _, writeErr := self.stream.Write(buffer[:n]); writeErr != nil {
				self.end(tlsStreamEndListenerReset, protocol.StreamResetCode_RST_UNSPECIFIED)
				return
			}
			self.movedChunk(n, tlsByteDirectionToListener)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				// FIN maps to StreamClose
				if self.stream.CloseWrite() != nil {
					self.end(tlsStreamEndListenerReset, protocol.StreamResetCode_RST_UNSPECIFIED)
				}
				return
			}
			// RST maps to StreamReset
			self.end(tlsStreamEndVisitorReset, protocol.StreamResetCode_RST_CANCELLED)
			return
		}
	}
}

// Listener to visitor, until the listener's StreamClose, which half-closes the visitor's connection, or
// an end.
func (self *tlsEdgeConnection) copyToVisitor() {
	buffer := make([]byte, self.service.settings.SpliceBufferByteCount)
	for {
		n, err := self.stream.Read(buffer)
		if 0 < n {
			if !self.admitChunk(n) {
				return
			}
			if _, writeErr := self.conn.Write(buffer[:n]); writeErr != nil {
				self.end(tlsStreamEndVisitorReset, protocol.StreamResetCode_RST_CANCELLED)
				return
			}
			self.movedChunk(n, tlsByteDirectionToVisitor)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				// StreamClose maps to FIN
				writeCloser, ok := self.conn.(interface{ CloseWrite() error })
				if !ok || writeCloser.CloseWrite() != nil {
					// a connection that cannot half-close ends whole
					self.end(tlsStreamEndClosed, protocol.StreamResetCode_RST_UNSPECIFIED)
				}
				return
			}
			// StreamReset maps to RST
			self.end(tlsStreamEndListenerReset, protocol.StreamResetCode_RST_UNSPECIFIED)
			return
		}
	}
}

// Runs both copies until both have returned, ending the connection when no byte has moved for
// idle_timeout_s. Returns with the connection ended and both sides closed.
func (self *tlsEdgeConnection) splice() {
	service := self.service
	idleTimeout := service.settings.IdleTimeout
	// armed before a byte can move, so a byte that moved says the wait is set
	idle := service.clock.After(idleTimeout)
	done := make(chan struct{}, 2)
	go func() {
		self.copyToListener()
		done <- struct{}{}
	}()
	go func() {
		self.copyToVisitor()
		done <- struct{}{}
	}()
	for doneCount := 0; doneCount < 2; {
		select {
		case <-done:
			doneCount += 1
		case <-idle:
			idleFor := service.clock.Now().UnixNano() - self.lastActiveNanos.Load()
			if int64(idleTimeout) <= idleFor {
				self.end(tlsStreamEndIdle, protocol.StreamResetCode_RST_PEER_TIMEOUT)
				// a nil channel never fires: the copies return now that both sides are closed
				idle = nil
			} else {
				idle = service.clock.After(idleTimeout - time.Duration(idleFor))
			}
		}
	}
	// both halves closed by themselves, unless something ended it first
	self.end(tlsStreamEndClosed, protocol.StreamResetCode_RST_UNSPECIFIED)
}
