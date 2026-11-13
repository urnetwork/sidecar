// How the engine ends. A deploy drains (§13.5's drain_s): the listeners close, connections in flight run
// on for up to DrainTimeout, and what is still open then is reset, streams with RST_DRAINING. A drain
// then sends the last usage window and the last connection records, each inside FlushTimeout, so a
// deploy bills what it moved and records what it served. Close ends everything at once: it writes the
// records it holds and drops the open usage window, as a kill would (under-billing, never
// double-billing, §20.6).

package tlsedgeservice

import (
	"context"
	"net"

	"github.com/urnetwork/sidecar/protocol"
)

// The listeners Serve holds, marking the engine draining or closed first so that none is added after.
func (self *TlsEdgeService) stopListeners(closed bool) []net.Listener {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if closed {
		self.closed = true
	} else {
		self.draining = true
	}
	listeners := []net.Listener{}
	for listener := range self.liveListeners {
		listeners = append(listeners, listener)
	}
	return listeners
}

// Resets every connection still open: a spliced one's stream with RST_DRAINING and its visitor with it,
// and one still setting up by closing it, which its setup then finds. A connection that finishes its
// setup after this ends itself (addSplice).
func (self *TlsEdgeService) resetConnections(reason string) {
	connections := func() []net.Conn {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.drainReset = true
		connections := []net.Conn{}
		for conn := range self.liveConnections {
			connections = append(connections, conn)
		}
		return connections
	}()
	for _, connection := range self.splices(nil) {
		connection.end(reason, protocol.StreamResetCode_RST_DRAINING)
	}
	for _, conn := range connections {
		conn.Close()
	}
}

// A context for a last write, bounded by FlushTimeout on the engine's clock and not by the engine's own
// context, which may have ended.
func (self *TlsEdgeService) flushContext() (context.Context, func()) {
	flushCtx, cancel := context.WithCancel(context.Background())
	stop := self.clock.AfterFunc(self.settings.FlushTimeout, cancel)
	return flushCtx, func() {
		stop()
		cancel()
	}
}

// See sidecar.Engine: takes no new connection, closing the listeners Serve holds, waits up to drain_s
// for the connections in flight, resets what remains, and then sends the last usage window and
// connection records.
func (self *TlsEdgeService) Drain() {
	for _, listener := range self.stopListeners(false) {
		listener.Close()
	}
	done := make(chan struct{})
	go func() {
		self.connectionGroup.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-self.ctx.Done():
		self.resetConnections(tlsStreamEndEngineClosed)
		<-done
	case <-self.clock.After(self.settings.DrainTimeout):
		self.resetConnections(tlsStreamEndDrain)
		<-done
	}
	if self.usage != nil {
		func() {
			flushCtx, cancel := self.flushContext()
			defer cancel()
			// what it cannot send inside the bound is dropped at Close, counted by the batcher
			self.usage.Drain(flushCtx)
		}()
	}
	func() {
		flushCtx, cancel := self.flushContext()
		defer cancel()
		self.records.flush(flushCtx)
	}()
}

// See sidecar.Engine: ends everything at once and waits for the loops. Safe after Drain and more than
// once.
func (self *TlsEdgeService) Close() {
	listeners := self.stopListeners(true)
	self.cancel()
	for _, listener := range listeners {
		listener.Close()
	}
	self.resetConnections(tlsStreamEndEngineClosed)
	self.loopGroup.Wait()
	self.connectionGroup.Wait()
	if self.usage != nil {
		self.usage.Close()
	}
	func() {
		flushCtx, cancel := self.flushContext()
		defer cancel()
		self.records.flush(flushCtx)
	}()
}
