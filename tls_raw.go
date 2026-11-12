//go:build !sidecar_http && !ios_extension

// §13.7's raw forward (D-TLS-13, R-TLS-7, FI-11): for a registration whose AppMode is raw, the decrypted bytes of the
// visitor's TLS connection go to the local service over TCP, for the declared ALPN ids or none. Its grant is public,
// where the service authenticates its own visitors, or link, where the handshake already required a client
// certificate whose SPKI SHA-256 is the grant's pin over TLS 1.3 (tls_dispatch.go). The audience check runs once
// more here, on this device's evaluation as it stands after the handshake, and only its pass opens the target, so
// no byte moves before it, whatever the ALPN.
//
// The splice keeps TCP's half-close both ways: the visitor's close_notify or FIN ends the target's write side, and
// the target's FIN sends close_notify and the stream's FIN, each direction reading on; an error either way ends both
// at once. The stream ends at its grant's expiry (the listener's timer, §9.9) and on a policy change that drops the
// grant (D-SOCK-14), both of which reset it under the splice.

package sidecar

import (
	"io"
	"net"
	"sync"
)

// The raw route, from the audience check to the splice's end.
func (self *TlsFront) serveRaw(conn *TlsFrontConn) {
	pass := self.audience.checkRaw(conn)
	if pass == nil {
		return
	}
	target, err := conn.openTarget(self.ctx, pass)
	if err != nil {
		return
	}
	tlsFrontSplice(conn, target)
}

// Copies both directions until both end: see the file header.
func tlsFrontSplice(conn *TlsFrontConn, target net.Conn) {
	abortOnce := sync.Once{}
	abort := func() {
		abortOnce.Do(func() {
			target.Close()
			conn.close()
		})
	}
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		if _, err := io.Copy(target, conn.tlsConn); err != nil {
			abort()
			return
		}
		tlsFrontCloseWrite(target)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		if _, err := io.Copy(conn.tlsConn, target); err != nil {
			abort()
			return
		}
		conn.closeWrite()
	}()
	<-done
	<-done
	abort()
}

// Ends conn's write side where it has one, else closes it.
func tlsFrontCloseWrite(conn net.Conn) {
	if halfCloser, ok := conn.(interface{ CloseWrite() error }); ok {
		halfCloser.CloseWrite()
		return
	}
	conn.Close()
}
