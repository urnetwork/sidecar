//go:build !sidecar_http

// §9.9's SocketAddress, which names connect.Id, so it stays off the sidecar_http leg. The grammar it
// parses by is socket_name.go's, on every leg.

package sidecar

import (
	"github.com/urnetwork/connect"
)

// [<net>:]<name> (§9.4). What a label means is settled once per call and stored as the network id
// (D-SOCK-1), so a rename or a reclaim moves nothing.
type SocketAddress struct {
	// Set once resolved.
	NetworkId *connect.Id
	// "" is the caller's network, and a ur/ name's urnetwork-edge.
	NetworkLabel string
	// Canonical, and possibly reserved: Listen and Dial act on ParseSocketName's namespace.
	Name string
}

// Text to an unresolved address, with its net and name folded. The error never repeats the text.
func ParseSocketAddress(text string) (*SocketAddress, error) {
	networkLabel, name, err := parseSocketAddressText(text)
	if err != nil {
		return nil, err
	}
	return &SocketAddress{
		NetworkLabel: networkLabel,
		Name:         name,
	}, nil
}

// The canonical text, which ParseSocketAddress reads back to an equal address. It holds the name in
// the clear, so it never goes to a log or a server (I-13).
func (self *SocketAddress) String() string {
	if self.NetworkLabel == "" {
		return self.Name
	}
	return self.NetworkLabel + ":" + self.Name
}
