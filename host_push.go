//go:build !sidecar_http && !ios_extension

// ServiceHost.Push: an owning service's half of §6.8's server push. Hints are lossy state sync, not a
// mailbox: a client that misses one resyncs, so a failed Hint costs latency only, and the caller
// counts it and goes on. Hint carries ids, kinds and versions, never content.
//
// ClientHint and Push are operator-core's (owner decision 251).

package sidecar

import (
	operator "github.com/urnetwork/operator-core"
)

// What changed, for every client a Hint names.
type ClientHint = operator.ClientHint

// How an owning service tells clients something changed.
type Push = operator.Push
