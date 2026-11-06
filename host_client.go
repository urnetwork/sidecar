//go:build !sidecar_http

// ServiceHost.ServiceClient: the jwt and urls an engine builds its connect clients from. An edge's
// clients are platform clients in the urnetwork-edge network (§6.10.1): tlsedge runs K of them a
// process (§13.6), and smtpedge and mxedge's router one (§14.9, §15).

package sidecar

import (
	"context"

	"github.com/urnetwork/connect"
)

// What connect.ClientAuth and the platform transport need for one platform client. A source that
// cannot fill every field answers an error: a zero ClientId or an empty url is never a success.
type ServiceClientAuth struct {
	// The same for a given clientIndex for the process's life, since sockets ties a listener's edge
	// streams to one of the caller's K clients (§9.6).
	ClientId connect.Id
	// A secret: never log it (I-7).
	ByJwt string
	// Absolute, as SidecarSettings's are.
	ApiUrl string
	// Absolute, ws or wss.
	PlatformUrl string
}

// Where an engine gets its platform clients' credentials, which only the host holds.
type ServiceClientSource interface {
	// One of the engine's platform clients, clientIndex from 0 up to the K its settings say. Call it
	// again at each reconnect, since a later answer may carry a newer jwt for the same client.
	ServiceClient(ctx context.Context, clientIndex int) (*ServiceClientAuth, error)
}
