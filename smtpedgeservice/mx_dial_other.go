//go:build !linux

// The real dial needs SO_MARK, which only Linux has (mx_dial_linux.go), so elsewhere every dial is
// refused and the edge reaches no MX: a host other than the sending hosts never sends mail.

package smtpedgeservice

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/urnetwork/sidecar"
)

var _ sidecar.SmtpMxDialer = (*SmtpMxNetDialer)(nil)

// A dial on a platform with no fwmark.
var errSmtpMxDialUnsupported = errors.New("smtp mx dial: only linux binds a sending address by fwmark")

// Safe for concurrent use.
type SmtpMxNetDialer struct {
	settings *SmtpEdgeSettings
}

func NewSmtpMxNetDialer(settings *SmtpEdgeSettings) *SmtpMxNetDialer {
	return &SmtpMxNetDialer{settings: settings}
}

// Refuses, after the checks the linux dial makes, so both refuse the same bad input alike.
func (self *SmtpMxNetDialer) DialMx(ctx context.Context, sendingAddress netip.Addr, mxAddress netip.Addr) (net.Conn, error) {
	if _, err := smtpSendingFwmark(self.settings, sendingAddress, mxAddress); err != nil {
		return nil, err
	}
	return nil, errSmtpMxDialUnsupported
}
