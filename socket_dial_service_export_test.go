//go:build !sidecar_http && !js

// The bridge socket_dial_service_net_test.go's external test reaches a ur/ dial through: the dialer on one dispatcher
// with a scripted Find and the service's ticket key, which production builds from the sockets component's registrar
// (SocketComponent.dialer). Tests only.

package sidecar

import (
	"context"
)

// A ur/ dialer on one dispatcher, for the external tests.
type PlatformDialOn struct {
	dialer *socketDialer
	// one signal for each Service hold released, which a stream's end brings on a goroutine of its own
	Released chan struct{}
}

// A dialer for the client clientId of networkId on subprotocol, holding ur/ tickets to ticketKeys and to
// urnetworkEdge as the registrar's newest answer would name them, its Finds answered by find.
func NewPlatformDialOn(
	subprotocol *Subprotocol,
	networkId Id,
	clientId Id,
	urnetworkEdge Id,
	ticketKeys []*SocketTicketKey,
	find func(ctx context.Context, args *SocketFindArgs) (*SocketFindResult, error),
) *PlatformDialOn {
	opener := &testServiceOpener{
		subprotocolSocketOpener: &subprotocolSocketOpener{subprotocol: subprotocol},
		released:                make(chan struct{}, 1024),
	}
	return &PlatformDialOn{
		dialer: &socketDialer{
			settings:      DefaultSidecarSocketSettings(),
			clock:         clockOrReal(nil),
			random:        socketDialRandom,
			networkId:     networkId,
			clientId:      clientId,
			urnetworkEdge: &urnetworkEdge,
			admission:     &socketAdmissionState{known: true, ticketKeys: ticketKeys, urnetworkEdge: &urnetworkEdge},
			find:          newSocketFindClient(find),
			opener:        opener,
		},
		Released: opener.released,
	}
}

// Sidecar.Dial's path for address on this dialer.
func (self *PlatformDialOn) Dial(ctx context.Context, address string) (*SocketConn, error) {
	parsed, err := ParseSocketAddress(address)
	if err != nil {
		return nil, err
	}
	return self.dialer.dial(ctx, parsed, nil, false)
}
