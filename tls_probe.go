//go:build !ios_extension

// §13.10 step 3's target probe (TLS-M5-23; R-TLS-7, R-CTX-22, I-9): before a publish listens, the daemon looks at the
// local service it would put on a public name, and refuses two kinds of target a publish must never reach:
//
//   - the daemon's own API or MCP port, which would hand a visitor the daemon;
//   - a target that answers like an agent UI: §16.5's two named UIs, MCP Inspector and OpenClaw
//     (plan-TLS-small-readings #9), by a small versioned table of what each answers.
//
// A refusal is recorded through Record with its reason alone, never the target's answer. A target that does not
// answer at all is no refusal: the publish listens and the front holds it not serving until the port answers
// (§13.7).
//
// The probe sends one plain GET / to a loopback or local address the caller named, reads the answer to a bound, and
// keeps none of it. It follows no redirect and sends no credential. A target that is not HTTP answers nothing the
// table knows, which is not a match.

package sidecar

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

// The probe refused the target: it is the daemon's own port, or it answers like an agent UI.
var ErrTlsProbeRefused = errors.New("tls publish: the target is refused")

// Why the probe refused a target.
type TlsProbeRefusal string

const (
	// The daemon's API or MCP port.
	TlsProbeRefusalDaemonPort TlsProbeRefusal = "daemon_port"
	// A target that answers like an agent UI.
	TlsProbeRefusalAgentUi TlsProbeRefusal = "agent_ui"
)

// The fingerprint table's version, raised with each change to it.
const tlsProbeFingerprintVersion = 1

// What one agent UI answers a GET / with: every mark, folded to lowercase, found in the answer's headers and the
// start of its body.
type tlsProbeFingerprint struct {
	// The UI, for the record.
	name  string
	marks []string
}

// §16.5's two named agent UIs (plan-TLS-small-readings #9). Each mark is lowercase.
var tlsProbeFingerprints = []*tlsProbeFingerprint{
	{name: "mcp-inspector", marks: []string{"<title>mcp inspector</title>"}},
	{name: "openclaw", marks: []string{"<title>openclaw"}},
}

// What tlsProbeTarget takes.
type tlsProbeArgs struct {
	// The local service, <ip>:<port>.
	LocalAddress string
	// The daemon's API and MCP ports on this host, each refused on every local address.
	DaemonPorts []int
	// ProbeTimeout and ProbeResponseMaxByteCount. nil takes the defaults.
	Settings *SidecarTlsSettings
	// Dials the target. nil dials TCP.
	Dial func(ctx context.Context, address string) (net.Conn, error)
	// Called with each refusal's reason. nil records none.
	Record func(refusal TlsProbeRefusal)
}

// What the probe found of a target it did not refuse.
type tlsProbeResult struct {
	// The target took a connection.
	Reachable bool
}

// Probes the target. An error wrapping ErrTlsProbeRefused is a refusal, recorded; any other is args that cannot be
// probed.
func tlsProbeTarget(ctx context.Context, args *tlsProbeArgs) (*tlsProbeResult, error) {
	if args == nil {
		return nil, fmt.Errorf("%w: no probe args", errInvalidSettings)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultSidecarTlsSettings()
	}
	target, err := netip.ParseAddrPort(args.LocalAddress)
	if err != nil || target.Port() == 0 {
		return nil, fmt.Errorf("%w: a target is <ip>:<port>", errInvalidSettings)
	}
	refuse := func(refusal TlsProbeRefusal) error {
		if args.Record != nil {
			args.Record(refusal)
		}
		return fmt.Errorf("%w: %s", ErrTlsProbeRefused, refusal)
	}
	if slices.Contains(args.DaemonPorts, int(target.Port())) {
		return nil, refuse(TlsProbeRefusalDaemonPort)
	}
	dial := args.Dial
	if dial == nil {
		dial = func(ctx context.Context, address string) (net.Conn, error) {
			dialer := &net.Dialer{}
			return dialer.DialContext(ctx, "tcp", address)
		}
	}
	probeCtx, cancel := context.WithTimeout(ctx, settings.ProbeTimeout)
	defer cancel()
	conn, err := dial(probeCtx, target.String())
	if err != nil {
		return &tlsProbeResult{}, nil
	}
	defer conn.Close()
	if deadline, ok := probeCtx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	answer := tlsProbeAnswer(conn, target, settings.ProbeResponseMaxByteCount)
	if tlsProbeMatches(answer) {
		return nil, refuse(TlsProbeRefusalAgentUi)
	}
	return &tlsProbeResult{Reachable: true}, nil
}

// The target's answer to one GET /, its headers and the start of its body, folded to lowercase. Empty for a target
// that answers no HTTP.
func tlsProbeAnswer(conn net.Conn, target netip.AddrPort, maxByteCount int) []byte {
	request := "GET / HTTP/1.1\r\nHost: " + target.String() + "\r\nAccept: text/html\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		return nil
	}
	limited := io.LimitReader(conn, int64(maxByteCount))
	response, err := http.ReadResponse(bufio.NewReader(limited), nil)
	if err != nil {
		return nil
	}
	defer response.Body.Close()
	answer := &bytes.Buffer{}
	response.Header.Write(answer)
	// a body cut short by the bound or the deadline is still what the target said
	io.Copy(answer, response.Body)
	return bytes.ToLower(answer.Bytes())
}

// Whether answer holds every mark of some agent UI's fingerprint.
func tlsProbeMatches(answer []byte) bool {
	if len(answer) == 0 {
		return false
	}
	text := string(answer)
	for _, fingerprint := range tlsProbeFingerprints {
		matched := 0 < len(fingerprint.marks)
		for _, mark := range fingerprint.marks {
			if !strings.Contains(text, mark) {
				matched = false
			}
		}
		if matched {
			return true
		}
	}
	return false
}
