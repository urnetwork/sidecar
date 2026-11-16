// The edge's own dialog with an MX before TLS (§14.4's pre-TLS, D-SMTP-1): the banner, EHLO with the
// sending address's PTR name (HELO = PTR, owner decision 124), STARTTLS, and its 220, after which the
// sidecar's first bytes, a ClientHello, go to the MX through the splice. Nothing the sidecar sent goes
// forward before that 220, and an octet the MX sends behind the 220, before the ClientHello, fails the MX:
// it would reach the session inside TLS (§22.6, the CVE-2011-0411 class). An octet still on its way is
// not in the buffer yet, and the splice then reads it as a TLS record, which E1 refuses.
//
// The pre-TLS keywords are hints only: STARTTLS voids them (RFC 3207 §4.2), and Z8 proves the post-TLS
// reply. A 421 banner backs that MX off (§14.4). No reply text reaches a log or the send record.

package smtpedgeservice

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

var (
	// The banner refused, not 220.
	errSmtpPreTlsBanner = errors.New("smtp pre-tls: the banner refuses")
	// A 421 banner: the MX asks to be left alone for a while (§14.4).
	errSmtpPreTlsBackoff = errors.New("smtp pre-tls: a 421 banner")
	// EHLO refused.
	errSmtpPreTlsEhlo = errors.New("smtp pre-tls: EHLO refused")
	// EHLO's reply offers no STARTTLS: an MX that answered and cannot take TLS.
	errSmtpPreTlsNoStartTls = errors.New("smtp pre-tls: no STARTTLS offered")
	// STARTTLS refused, as a 454.
	errSmtpPreTlsStartTlsRefused = errors.New("smtp pre-tls: STARTTLS refused")
	// Octets behind STARTTLS's 220.
	errSmtpPreTlsInjected = errors.New("smtp pre-tls: octets after STARTTLS's 220")
)

// Runs the dialog on conn, which the dial has just opened, and returns the EHLO reply's keywords, conn
// left where the ClientHello goes next. Every error leaves conn to be closed.
func smtpPreTls(conn io.ReadWriter, heloName string, settings *SmtpEdgeSettings) ([]string, error) {
	parser := newSmtpReplyParser(conn, settings)
	banner, err := parser.next()
	if err != nil {
		return nil, err
	}
	switch {
	case banner.code == 421:
		return nil, errSmtpPreTlsBackoff
	case banner.code != 220:
		return nil, fmt.Errorf("%w: %d", errSmtpPreTlsBanner, banner.code)
	}
	if _, err := conn.Write([]byte("EHLO " + heloName + "\r\n")); err != nil {
		return nil, err
	}
	ehlo, err := parser.next()
	if err != nil {
		return nil, err
	}
	if ehlo.code != 250 {
		return nil, fmt.Errorf("%w: %d", errSmtpPreTlsEhlo, ehlo.code)
	}
	// the first line names the server; each later line is a keyword and its parameters
	keywords := ehlo.lines[1:]
	startTls := false
	for _, keyword := range keywords {
		fields := strings.Fields(keyword)
		startTls = startTls || (len(fields) == 1 && strings.EqualFold(fields[0], "STARTTLS"))
	}
	if !startTls {
		return nil, errSmtpPreTlsNoStartTls
	}
	// anything an MX sent ahead of our STARTTLS is as fatal as anything behind its 220
	if 0 < parser.buffered() {
		return nil, errSmtpPreTlsInjected
	}
	if _, err := conn.Write([]byte("STARTTLS\r\n")); err != nil {
		return nil, err
	}
	ready, err := parser.next()
	if err != nil {
		return nil, err
	}
	if ready.code != 220 {
		return nil, fmt.Errorf("%w: %d", errSmtpPreTlsStartTlsRefused, ready.code)
	}
	if 0 < parser.buffered() {
		return nil, errSmtpPreTlsInjected
	}
	return keywords, nil
}
