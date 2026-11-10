//go:build !sidecar_http && !ios_extension

// The one place the root reaches go-smtp's fork (D-MAIL-3, §15.5). A receiver or the platform listener
// has finished TLS before its session starts, and RFC 3207 §4.2 has the server say nothing first.
// go-smtp takes connections only through Serve, whose greet always writes a 220, and a conn wrapped to
// dodge that is no longer a *tls.Conn, so TLSConnectionState fails and REQUIRETLS is never advertised.
// Neither is a fallback.
//
// third_party/go-smtp adds ServeConn(conn, ServeConnOptions{AfterStartTls: true}) and ServeTlsConn
// over it, and every module that links the root replaces go-smtp with it (QD-193). The root still names
// no symbol of the fork, because §4.9's release fixture builds it with no replaces, against upstream
// go-smtp. It asks the *smtp.Server for mailSmtpConnServer instead, which upstream's lacks, so there a
// session refuses, closed.
//
// Off the sidecar_http leg, since a page Worker reads mail and never receives it (R-MAIL-13).

package sidecar

import (
	"crypto/tls"
	"errors"

	"github.com/emersion/go-smtp"
)

// No session can start on a connection already inside TLS. To a sender this is a receiver that went
// away, so its mail stays in its own queue and it retries, which is the closed direction here: a 250
// is never given and a second 220 is never written.
var errMailSmtpServeRefused = errors.New("mail smtp session refused")

// What the fork adds to *smtp.Server, over its ServeConn(conn, ServeConnOptions{AfterStartTls: true}):
// a session on a connection whose handshake is done, with no greeting first. Returns when the session
// ends, on Server.Close and Shutdown as Serve's connections do, and refuses with smtp.ErrServerClosed
// once the server is closed.
type mailSmtpConnServer interface {
	ServeTlsConn(conn *tls.Conn) error
}

// Runs one session on conn, whose TLS handshake is done, on server, which comes from smtp.NewServer.
// Exported for the engines, which cannot reach mailSmtpServe: mxedgeservice's platform listener. A nil
// server refuses, since a nil *smtp.Server has the fork's method and would fail inside it.
func MailSmtpServe(server *smtp.Server, conn *tls.Conn) error {
	if server == nil {
		return mailSmtpServe(nil, conn)
	}
	return mailSmtpServe(server, conn)
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
