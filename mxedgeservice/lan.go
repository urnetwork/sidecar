// The router's LAN listener (D-SMTP-13, X6, X7; MAIL-M9-05): an MX on the router's own lb interfaces is a URnetwork
// receiver's (§15.4), and a sending host cannot hairpin to its own lb address, so smtpedge reaches the router over the
// host LAN (SMTP-M9-14's smtpLanDialer), writing a PROXY v1 line that names the sending address, as the lb's stream
// port would.
//
//	sources  only smtpedge's hosts reach the port: a connection whose socket's peer is in none of mxedge.yml's
//	         lan_sources is closed unanswered, before a byte is read, so no other LAN host can name a sender in a
//	         PROXY line or spend another's caps
//	proxy    then the same PROXY header listener as the lb's port, which the host wraps over this one
//	         (server/mxedgehost), so the engine's RemoteAddr is the sending address the line names
//	session  and from there a normal sender: the same banner, the same per-sender and per-network caps keyed by that
//	         address, the same pre-TLS dialog and the same splice, TLS still ending at the receiver. Nothing is skipped
//
// lan_port 0 opens no LAN listener. Nothing here logs an address (I-13). Safe for concurrent use.

package mxedgeservice

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
)

// A LAN listener asked for with no source allowed to reach it.
var ErrMxLanSourcesRequired = errors.New("mxedge lan: a lan_port needs lan_sources")

// The LAN listener over a bound TCP listener: see the file header. Its refusals are counted.
type MxLanListener struct {
	net.Listener
	sources []netip.Prefix
	// connections closed for a source not listed
	refusedCount atomic.Uint64
}

// The LAN listener over listener, admitting settings' lan_sources alone. ErrMxLanSourcesRequired for none.
func NewMxLanListener(listener net.Listener, settings *MxEdgeSettings) (*MxLanListener, error) {
	if settings == nil || len(settings.LanSources) == 0 {
		return nil, ErrMxLanSourcesRequired
	}
	sources := make([]netip.Prefix, 0, len(settings.LanSources))
	for _, source := range settings.LanSources {
		if !source.IsValid() {
			return nil, fmt.Errorf("%w: a source that is no prefix", ErrMxEdgeSettingsRefused)
		}
		sources = append(sources, source.Masked())
	}
	return &MxLanListener{Listener: listener, sources: sources}, nil
}

// The next connection from a listed source; one from any other is closed unanswered and the wait goes on.
func (self *MxLanListener) Accept() (net.Conn, error) {
	for {
		conn, err := self.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if self.admits(conn.RemoteAddr()) {
			return conn, nil
		}
		self.refusedCount.Add(1)
		conn.Close()
	}
}

// Whether addr, a socket's peer, is in a listed source.
func (self *MxLanListener) admits(addr net.Addr) bool {
	addrPort, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return false
	}
	address := addrPort.Addr().Unmap()
	return slices.ContainsFunc(self.sources, func(source netip.Prefix) bool { return source.Contains(address) })
}

// Connections closed for a source not listed, so far.
func (self *MxLanListener) RefusedCount() uint64 {
	return self.refusedCount.Load()
}
