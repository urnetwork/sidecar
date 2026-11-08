// SocketGate: what the newest verified projection allows, which is the only thing the service consults
// before it writes a lease or signs a ticket (§9.10, D-SOCK-14, X3). SOCK-M5-07's production gate wraps
// ACL-M2-13's AclGateCache, as C-09 has it, and reads §8's evaluator alone; until it lands a host has
// only ClosedSocketGate, which allows nothing and is never ready, and tests use a fake.
//
// Every answer comes from memory: a gate never reads a store or Postgres on a call (I-12), and a network
// it has not loaded answers ErrSocketGateUnloaded, which the engine turns into unavailable, never an
// allow. The subject is the authenticated caller, never a claim's sidecar, since Find shows claims to
// dialers (§9.5). Safe for concurrent use.

package socketsservice

import (
	"context"
	"errors"

	"github.com/urnetwork/connect"
)

// The gate holds no verified projection for the network yet, or its source is down and it has none to
// keep serving (plan-SOCK-gate-data). The engine answers unavailable with retry_after_ms.
var ErrSocketGateUnloaded = errors.New("socket gate has no projection for the network")

// Who asks, about which name. Exactly one of Name and NameToken is set.
type SocketGateRequest struct {
	// The network that holds the name: the caller's own, or urnetwork-edge for ur/ (D-SOCK-1).
	NetworkId connect.Id
	// The authenticated caller and its network. An edge's Find runs as autogroup:public on tls/
	// (§9.10), which the gate reads from this network being urnetwork-edge.
	CallerClientId  connect.Id
	CallerNetworkId connect.Id
	// The caller's §8 subject, from its token's ur_subject_client_id, else its own client.
	SubjectClientId connect.Id
	// The caller's sidecar, when its token names one (plan-SOCK-client-auth's sidecar_id claim).
	SidecarId *connect.Id
	// An edge name in the clear (tls/, smtp/, ur/), or a blinded name's token path.
	Name      string
	NameToken []byte
}

// A gate's answer. A refusal carries nothing else, and a ticket or a lease is made only from an allow.
type SocketGateVerdict struct {
	Allowed bool
	// The grant that allows it, from the projection or a requested grant's GrantActivate (§7.9): what a
	// ticket carries for receipts and revocation (§9.6).
	GrantId []byte
	// The authorization log position n of the projection that answered, at or after any GrantActivate
	// the allow rests on: a ticket's policy_version.
	PolicyVersion uint64
	// When the grant ends, in milliseconds, 0 for never: a ticket's grant_expire_time_millis.
	GrantExpireMillis uint64
}

// §9.10's gates, from the newest verified projection.
type SocketGate interface {
	// Whether the gate has a projection source and has loaded what it serves from: the host's
	// readiness (§19.4). A gate that never loaded stays not ready.
	Ready() bool
	// listen on the name (§8), a registration's check after its claim (§9.5).
	MayListen(ctx context.Context, request *SocketGateRequest) (*SocketGateVerdict, error)
	// dial on the name (§8), a Find's step 2 before its group is read (§9.6).
	MayDial(ctx context.Context, request *SocketGateRequest) (*SocketGateVerdict, error)
	// publish on the name's dns host (§13.9), which an edge's tls/ Find needs beside MayDial (§9.10).
	MayPublish(ctx context.Context, request *SocketGateRequest) (*SocketGateVerdict, error)
	// The identity key a sidecar's claims verify under, from the projection's SidecarRow (§9.5), and
	// whether the projection holds a live row for it.
	IdentityKey(ctx context.Context, networkId connect.Id, sidecarId connect.Id) (publicKey []byte, found bool, err error)
	// Whether §20.7's OverLimit set marks the network spent, from the 5 s snapshot (§9.6's step 3). A
	// network over storage alone is not spent here.
	Spent(networkId connect.Id) bool
}

// What a host has until SOCK-M5-07's gate lands: never ready, allowing nothing, every network
// unloaded, and every network spent. It is the closed direction of every check, so an engine built on
// it serves no lease and signs no ticket.
type ClosedSocketGate struct{}

var _ SocketGate = ClosedSocketGate{}

// Never.
func (self ClosedSocketGate) Ready() bool {
	return false
}

// ErrSocketGateUnloaded, always.
func (self ClosedSocketGate) MayListen(ctx context.Context, request *SocketGateRequest) (*SocketGateVerdict, error) {
	return nil, ErrSocketGateUnloaded
}

// ErrSocketGateUnloaded, always.
func (self ClosedSocketGate) MayDial(ctx context.Context, request *SocketGateRequest) (*SocketGateVerdict, error) {
	return nil, ErrSocketGateUnloaded
}

// ErrSocketGateUnloaded, always.
func (self ClosedSocketGate) MayPublish(ctx context.Context, request *SocketGateRequest) (*SocketGateVerdict, error) {
	return nil, ErrSocketGateUnloaded
}

// ErrSocketGateUnloaded, always.
func (self ClosedSocketGate) IdentityKey(ctx context.Context, networkId connect.Id, sidecarId connect.Id) ([]byte, bool, error) {
	return nil, false, ErrSocketGateUnloaded
}

// Every network, so nothing is signed for anyone.
func (self ClosedSocketGate) Spent(networkId connect.Id) bool {
	return true
}
