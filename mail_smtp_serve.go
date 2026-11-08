//go:build !sidecar_http

// The one place the root reaches go-smtp's ServeConn, so one file touches the fork (D-MAIL-3, §15.5).
// A receiver or the platform listener has finished TLS before its session starts, and RFC 3207 §4.2
// has the server say nothing first. go-smtp takes connections only through Serve, whose greet always
// writes a 220, and a conn wrapped to dodge that is no longer a *tls.Conn, so TLSConnectionState fails
// and REQUIRETLS is never advertised. Neither is a fallback.
//
// The root names no symbol of the fork, because §4.9's release fixture builds it with no replaces,
// against upstream go-smtp. It asks a server for mailSmtpConnServer instead, which upstream's lacks,
// so there a session refuses, closed (QD-193). The fork is not in the tree yet and this file links no
// go-smtp, so today every real session refuses.
//
// Off the sidecar_http leg, since a page Worker reads mail and never receives it (R-MAIL-13).

package sidecar

import (
	"crypto/tls"
	"errors"
)

// No session can start on a connection already inside TLS. To a sender this is a receiver that went
// away, so its mail stays in its own queue and it retries, which is the closed direction here: a 250
// is never given and a second 220 is never written.
var errMailSmtpServeRefused = errors.New("mail smtp session refused")

// What the fork adds to *smtp.Server, over its ServeConn(conn, ServeConnOptions{AfterStartTls: true}):
// a session on a connection whose handshake is done, with no greeting first. Returns when the session
// ends, on Server.Close and Shutdown as Serve's connections do.
type mailSmtpConnServer interface {
	ServeTlsConn(conn *tls.Conn) error
}

// Runs one session on conn, whose TLS handshake is done. server is the *smtp.Server to run it on, and
// anything without mailSmtpConnServer refuses. Takes conn, which is closed by the time this returns on
// every path, so neither a refusal nor a session's end leaves a connection behind its caller.
func mailSmtpServe(server any, conn *tls.Conn) error {
	// nothing is written on a refusal: a sender may read any byte as the 220 it must not get
	defer conn.Close()
	connServer, ok := server.(mailSmtpConnServer)
	if !ok {
		return errMailSmtpServeRefused
	}
	return connServer.ServeTlsConn(conn)
}
