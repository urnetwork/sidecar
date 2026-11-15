//go:build !sidecar_http && !ios_extension

// ServiceHost.ServiceClient: the jwt and urls an engine builds its connect clients from. An edge's
// clients are platform clients in the urnetwork-edge network (§6.10.1): tlsedge runs K of them a
// process (§13.6), and smtpedge and mxedge's router one (§14.9, §15).
//
// The types are operator-core's (owner decision 251).

package sidecar

import (
	operator "github.com/urnetwork/operator-core"
)

// What connect.ClientAuth and the platform transport need for one platform client. A source that
// cannot fill every field answers an error: a zero ClientId or an empty url is never a success.
type ServiceClientAuth = operator.ServiceClientAuth

// Where an engine gets its platform clients' credentials, which only the host holds.
type ServiceClientSource = operator.ServiceClientSource
