//go:build !sidecar_http

// The one place the root reaches go-smtp's ServeConn, so one file touches the fork (D-MAIL-3, §15.5).
// A receiver or the platform listener has finished TLS before its session starts, and RFC 3207 §4.2
// has the server say nothing first. go-smtp takes connections only through Serve, whose greet always
// writes a 220, and a conn wrapped to dodge that is no longer a *tls.Conn, so TLSConnectionState fails
// and REQUIRETLS is never advertised. Neither is a fallback.
//
// There is no ServeConn to call yet: plan-MAIL-go-smtp-fork asks where the patch may live, since §4.7
// allows no replace for it. Until that is answered every session here refuses. This links no go-smtp,
// and the signature grows what the session needs when the answer lands.
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

// Runs one session on conn, whose TLS handshake is done, with no greeting first. Takes conn, which is
// closed by the time this returns, so a refusal leaves no session open behind its caller.
func mailSmtpServe(conn *tls.Conn) error {
	// nothing is written before the close: a sender may read any byte as the 220 it must not get
	conn.Close()
	return errMailSmtpServeRefused
}
