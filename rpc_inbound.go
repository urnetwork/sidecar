// §8's hook on the subprotocol's inline path (§6.6's threading), on every leg: ACL's AclEngine fills
// it, and the file that engine lives in names no connect type, so neither does this one. The
// dispatcher (rpc_subprotocol.go) asks it last of its inline checks, after the identity gate, so it
// hears only about a verified peer's envelopes and the Hello exchange that verifies one.

package sidecar

import (
	"github.com/urnetwork/sidecar/protocol"
)

// One inbound envelope, as the hook is told of it: a value, so asking costs no allocation.
type SubprotocolInbound struct {
	// The source client, as connect authenticated it.
	SourceId Id
	// Envelope.type. Not one of §6.11's names when the peer sent a number it does not hold.
	MessageType protocol.MessageType
	// Envelope.stream_id: 0 outside streams.
	StreamId uint64
	// Whether it answers a call or a stream this side opened, rather than asking something of it.
	Response bool
}

// Decides one inbound envelope on connect's receive goroutine, so it must not block, allocate or do
// I/O, and must take no lock a packet path needs (I-12). True admits the envelope; false refuses it,
// a request with PERMISSION_DENIED. Safe for concurrent use.
//
// It is a required field of SubprotocolEnv: nil is refused at construction and never read as allow.
type SubprotocolInboundFunction func(inbound SubprotocolInbound) bool

// Admits every envelope the inline checks before it admitted, applying no policy at all. M1 runs on
// this, when no network yet has an ACL document and §8's disclosed default for untagged sources is
// allow-all (I-10), so what stands between a peer and a component is the identity gate alone. ACL's
// AclEngine.AllowInbound takes its place from M2.
func SubprotocolInboundWithoutPolicy(inbound SubprotocolInbound) bool {
	return true
}
