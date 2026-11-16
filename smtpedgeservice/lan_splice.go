// The LAN splice to mxedge (D-SMTP-13, X6, X7; SMTP-M9-14): an MX on one of mxedge's router interfaces is a
// URnetwork receiver's (§15.4), and a sending host cannot hairpin to its own lb address, so the edge dials
// mxedge's LAN listener instead and writes a PROXY v1 line naming the sending address and the dialed router
// interface, as the lb's stream port would (§15.4, MAIL-M9-05). Everything after is as for any MX: the banner,
// EHLO with the sending address's PTR name, STARTTLS, then the sidecar's TLS spliced through to the receiver,
// with the same proofs. The router takes it as a normal sender, with its caps and its banner path, and TLS
// still ends at the receiving sidecar: nothing here reads past the PROXY line, and no plaintext path appears.
//
// Safe for concurrent use.

package smtpedgeservice

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"

	"github.com/urnetwork/sidecar"
)

// A router interface's MX with no LAN listener named (SmtpEdgeSettings.RouterLanAddress).
var errSmtpLanUnset = errors.New("smtp lan splice: no router LAN listener")

// How a LAN connection is opened: a net.Dialer's in production, a stub router's in a test.
type SmtpLanDial func(ctx context.Context, address netip.AddrPort) (net.Conn, error)

// The LAN dial, as a sidecar.SmtpMxDialer the connector uses for a router interface's MX.
type smtpLanDialer struct {
	settings *SmtpEdgeSettings
	dial     SmtpLanDial
}

var _ sidecar.SmtpMxDialer = (*smtpLanDialer)(nil)

// The dialer over dial, net.Dialer's when nil, or nil when settings name no router interface.
func newSmtpLanDialer(settings *SmtpEdgeSettings, dial SmtpLanDial) *smtpLanDialer {
	if len(settings.RouterInterfaces) == 0 {
		return nil
	}
	if dial == nil {
		dial = func(ctx context.Context, address netip.AddrPort) (net.Conn, error) {
			dialer := &net.Dialer{}
			return dialer.DialContext(ctx, "tcp4", address.String())
		}
	}
	return &smtpLanDialer{settings: settings, dial: dial}
}

// Whether mxAddress is one of mxedge's router interfaces.
func (self *smtpLanDialer) routes(mxAddress netip.Addr) bool {
	return self != nil && slices.Contains(self.settings.RouterInterfaces, mxAddress.Unmap())
}

// See sidecar.SmtpMxDialer: the LAN listener, then the PROXY v1 line (the haproxy PROXY protocol's version 1)
// naming sendingAddress as the source and mxAddress, the router interface, as the destination on MxPort.
func (self *smtpLanDialer) DialMx(ctx context.Context, sendingAddress netip.Addr, mxAddress netip.Addr) (net.Conn, error) {
	if !self.settings.RouterLanAddress.IsValid() {
		return nil, errSmtpLanUnset
	}
	if !self.settings.isSendingAddress(sendingAddress) || !self.routes(mxAddress) {
		return nil, fmt.Errorf("%w: not a sending address to a router interface", errSmtpMxDialRefused)
	}
	conn, err := self.dial(ctx, self.settings.RouterLanAddress)
	if err != nil {
		return nil, err
	}
	sourcePort := 0
	if local, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		sourcePort = local.Port
	}
	line := fmt.Sprintf("PROXY TCP4 %s %s %d %d\r\n", sendingAddress.Unmap(), mxAddress.Unmap(), sourcePort, self.settings.MxPort)
	if _, err := conn.Write([]byte(line)); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}
