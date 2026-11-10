// The 25 banner probe (§12.6, §15.4; DNS-M7-01). Each round an edge connects to each router
// interface's TCP probe.smtp_port, at each family's address, as a sender does, and passes only on the
// greeting a sender's first read gets from a server that will take its mail: one reply, every line
// with code 220 and ended by CRLF (RFC 5321 §4.2, §3.1). mxedge greets with one such line naming
// mx.bringyour.com (owner decision 16). It greets 421 while it drains or a source is over its caps,
// and 554 a listed source (§15.4), and each of those fails the probe, as do a silence past
// probe.timeout_s, a close, a TLS record, a bare LF, a line past RFC 5321's 512 bytes and a greeting
// past probe.smtp_banner_bytes.
//
// The probe writes nothing: no EHLO and no QUIT, so it never takes SMTP past the banner. It reads the
// greeting to its last line and closes, so it reaches no STARTTLS, routes nothing, and leaves mxedge no
// closed handshake to remember (§15.4).
//
// A failure counts against the address on probe.smtp_port alone, apart from tlsedge's ports, so the
// banner takes an address out of router answers, each mx host (§12.7), and out of nothing else; and
// tlsedge's alert takes it out of user names and not out of mx (probe.go).

package dnsservice

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/urnetwork/sidecar"
)

// RFC 5321 §4.5.3.1.5: the longest reply line, its CRLF included.
const dnsSmtpReplyLineMaxByteCount = 512

// RFC 5321 §4.2.2: the greeting of a server ready to take mail.
const dnsSmtpReplyServiceReady = "220"

// RFC 5321 §4.2: what ends a reply line, and what follows the code on a line that is not the last.
const (
	dnsSmtpLineEnd          = "\r\n"
	dnsSmtpContinuationMark = '-'
	dnsSmtpLastLineMark     = ' '
)

// Whether reader greets as a server ready to take mail: one reply whose every line carries code 220
// and ends in CRLF, its last line the code alone or the code and a space, in at most maxByteCount
// bytes. Reads up to the reply's last line and nothing past it, so a server that goes on talking
// holds the probe no longer.
func dnsSmtpBannerPasses(reader io.Reader, maxByteCount int) bool {
	lines := bufio.NewReaderSize(io.LimitReader(reader, int64(maxByteCount)), dnsSmtpReplyLineMaxByteCount)
	for {
		// a line past 512 bytes fills the buffer, and a greeting past the bound or a reader that ends
		// first leaves the line unended: each an error
		line, err := lines.ReadSlice('\n')
		if err != nil {
			return false
		}
		text, ok := bytes.CutSuffix(line, []byte(dnsSmtpLineEnd))
		if !ok || !bytes.HasPrefix(text, []byte(dnsSmtpReplyServiceReady)) {
			return false
		}
		codeByteCount := len(dnsSmtpReplyServiceReady)
		if len(text) == codeByteCount || text[codeByteCount] == dnsSmtpLastLineMark {
			return true
		}
		if text[codeByteCount] != dnsSmtpContinuationMark {
			return false
		}
	}
}

// One banner probe of address, passing only on a ready greeting within timeout on clock. It writes
// nothing, and closes once the greeting's last line is read.
func dnsSmtpProbeOnce(
	ctx context.Context,
	clock sidecar.Clock,
	timeout time.Duration,
	dialer DnsProbeDialer,
	address netip.AddrPort,
	maxByteCount int,
) bool {
	return dnsProbeExchange(ctx, clock, timeout, dialer, address, func(conn net.Conn) bool {
		return dnsSmtpBannerPasses(conn, maxByteCount)
	})
}
