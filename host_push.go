//go:build !sidecar_http

// ServiceHost.Push: an owning service's half of §6.8's server push. Hints are lossy state sync, not a
// mailbox: a client that misses one resyncs, so a failed Hint costs latency only, and the caller
// counts it and goes on. Hint carries ids, kinds and versions, never content.

package sidecar

import (
	"context"

	"github.com/urnetwork/connect"
)

// What changed, for every client a Hint names.
type ClientHint struct {
	// §6.8's registry: core, team, sock, mail, tls, dns, gkm, gkm:<group_id>, evs:<repo_id>.
	Topic string
	// The owner's version for the topic, which never lowers a stored one. It stays exact from here
	// to the client, a canonical decimal string in Redis and its scripts, since evs's push sequence
	// is near 1.8 x 10^18, past what a Lua number holds (D-PROTO-12).
	Version uint64
	// The owner's MessageType (§6.11), or 0.
	Kind uint32
	// That message, at most 256 B: ids, kinds, versions, never content. May be dropped when a
	// resident coalesces.
	Body []byte
	// Wake the client now, whatever its live key says: §15.6's router on a receiver miss, and POST
	// /sidecar/wake (§18.7's step 2).
	Forced bool
}

type Push interface {
	// For each client, one script on its slot of {scp_<C>}: raises ver, adds the hint and INCRs n,
	// which is what triggers its resident's publisher, the gkm topic's clock rule included (§6.8).
	// Then, for a client holding a wake token and a topic of mail, team, evs or core, §18.7's
	// separate enqueue, whose failure leaves the hint state as it is. An error means at least one
	// client's script failed. No script spans two clients, so none is atomic across them.
	Hint(ctx context.Context, clientIds []connect.Id, hint *ClientHint) error
	// Hint for owners that know sidecars and not clients, as gkm does: §7.9's rows name sidecar_ids,
	// and client generations change with no log entry (§5.8). The host resolves each to its current
	// client. A hint that misses a device mid-change is covered by its hourly resync.
	HintSidecars(ctx context.Context, sidecarIds []connect.Id, hint *ClientHint) error
}
