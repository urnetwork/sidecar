//go:build !sidecar_http && !ios_extension

// ServiceHost.Abuse: a network's §21.7 standing and its network_verified, as §8's contract gate and
// §12-§15's gates read them (D-ABUSE-4). api keeps both in Postgres (network_abuse_state,
// network_verified; ABUSE-M5-07), and an inline packet or frame path never queries Postgres (I-12), so
// a gate reads them from memory that the host fills off the path: server's model.NewAbuseGate in a
// process that holds Postgres, and plan-SOCK-gate-data's internal route in one that does not. Engines
// cannot import server, so the interface lives in operator-core, beside the others a ServiceHost
// holds, and ACL's gate view, TLS's listen facts, DNS's record writes and SMTP's send gate all read
// this one shape.
//
// Every answer fails closed. ok false means the host has not loaded the network, and a gate refuses on
// it, never passes: a miss is the host's cue to load the network off the path, never the gate's to
// wait or to ask Postgres. A standing this build does not know refuses too (AbuseStanding.Known), and
// a host that sets no gate has loaded no network (ServiceHost.AbuseOrUnloaded). These facts only take
// away: a server originates only denials (I-4), so a gate passes on them nothing that a network's
// signed grants do not already allow.

package sidecar

import (
	"github.com/urnetwork/connect"
	operator "github.com/urnetwork/operator-core"
)

// A network's standing and verification, from memory: operator-core's (owner decision 251). A method
// does no I/O and never blocks, so it may be called on an inline packet or frame path.
type AbuseGate = operator.AbuseGate

// The gate of a host that set none: no network is loaded, so every gate that reads it refuses.
type UnloadedAbuseGate struct{}

// Not loaded, for every network.
func (self UnloadedAbuseGate) Standing(networkId connect.Id) (AbuseStanding, bool) {
	return "", false
}

// Not loaded, for every network.
func (self UnloadedAbuseGate) Verified(networkId connect.Id) (bool, bool) {
	return false, false
}
