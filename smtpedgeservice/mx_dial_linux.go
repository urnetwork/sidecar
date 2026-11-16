//go:build linux

// The edge's real dial (§14.9's shape): TCP from one of the host's sending addresses to the MX on MxPort,
// source-routed by that address's fwmark (plan-SMTP-small-readings#18), set with SO_MARK, which needs
// cap_net_admin on the binary (plan-OPS-small-readings#14: warp's allowlists extended to smtpedge alone).
// A fwmark of 0 is the block's own mark, which warp already applies, so no SO_MARK is set.
// Only the edge dials an MX, and only an address the connector found dialable (owner decision 34;
// R-SMTP-9). Other platforms refuse (mx_dial_other.go).

package smtpedgeservice

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/urnetwork/sidecar"
)

var _ sidecar.SmtpMxDialer = (*SmtpMxNetDialer)(nil)

// Safe for concurrent use.
type SmtpMxNetDialer struct {
	settings *SmtpEdgeSettings
}

func NewSmtpMxNetDialer(settings *SmtpEdgeSettings) *SmtpMxNetDialer {
	return &SmtpMxNetDialer{settings: settings}
}

// See sidecar.SmtpMxDialer. sendingAddress must be one of settings' sending addresses, and mxAddress
// dialable, or the dial is refused before a socket opens.
func (self *SmtpMxNetDialer) DialMx(ctx context.Context, sendingAddress netip.Addr, mxAddress netip.Addr) (net.Conn, error) {
	fwmark, err := smtpSendingFwmark(self.settings, sendingAddress, mxAddress)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{
		LocalAddr: net.TCPAddrFromAddrPort(netip.AddrPortFrom(sendingAddress.Unmap(), 0)),
		Control: func(network string, address string, rawConn syscall.RawConn) error {
			if fwmark == 0 {
				return nil
			}
			var markErr error
			if err := rawConn.Control(func(fd uintptr) {
				markErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, fwmark)
			}); err != nil {
				return err
			}
			if markErr != nil {
				return fmt.Errorf("smtp mx dial: SO_MARK: %w", markErr)
			}
			return nil
		},
	}
	return dialer.DialContext(ctx, "tcp4", netip.AddrPortFrom(mxAddress.Unmap(), uint16(self.settings.MxPort)).String())
}
