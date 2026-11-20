//go:build !sidecar_http && !js && !ios_extension

// The bridge smtp_edge_net_test.go's external test reaches a daemon's ur/smtpedge stream through: the stream
// sidecarSmtpEdgeDialer builds over each dialed conn (newSidecarSmtpEdgeStream), on a PlatformDialOn's ur/ dial in
// place of the Sidecar's sockets component. Tests only.

package sidecar

import (
	"context"
)

// An SmtpEdgeDialer whose streams are dial's ur/smtpedge streams, each the daemon's own stream over its conn, the
// parts, SHTS and outcome going through subprotocol, under settings.
func NewSmtpEdgeDialerOn(dial *PlatformDialOn, subprotocol *Subprotocol, settings *SmtpSenderSettings) SmtpEdgeDialer {
	return &platformSmtpEdgeDialer{dial: dial, subprotocol: subprotocol, settings: settings}
}

// See NewSmtpEdgeDialerOn.
type platformSmtpEdgeDialer struct {
	dial        *PlatformDialOn
	subprotocol *Subprotocol
	settings    *SmtpSenderSettings
}

// See SmtpEdgeDialer: sidecarSmtpEdgeDialer's, past its Sidecar.Dial.
func (self *platformSmtpEdgeDialer) DialSmtpEdge(ctx context.Context) (SmtpEdgeStream, error) {
	conn, err := self.dial.Dial(ctx, SmtpEdgeAddress)
	if err != nil {
		return nil, err
	}
	stream, err := newSidecarSmtpEdgeStream(conn, self.subprotocol, self.settings)
	if err != nil {
		return nil, err
	}
	return stream, nil
}
