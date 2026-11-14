// SocketGate: what the newest verified projection allows, which is the only thing the service consults
// before it writes a lease or signs a ticket (§9.10, D-SOCK-14, X3). SocketProjectionGate
// (gate_projection.go) is the production gate: it wraps ACL-M2-13's AclGateCache, as C-09 has it, and reads
// §8's evaluator alone. ClosedSocketGate allows nothing and is never ready, and tests use a fake.
//
// Every answer comes from memory: a gate never reads a store or Postgres on a call (I-12), and a network
// it has not loaded answers ErrSocketGateUnloaded, which the engine turns into unavailable, never an
// allow. The subject is the authenticated caller, never a claim's sidecar, since Find shows claims to
// dialers (§9.5). Safe for concurrent use.
//
// Positions (DESIGN-DETAILS 13.2.3, which governs). A route judges everything on one SocketGateView, one
// network's state at one authorization log position, and stamps what it writes with that position. View
// answers only while the network is fresh: once the gate has had evidence for GateBehindGrace that the log
// passed what it holds, and has not verified the new entries, View answers ErrSocketGateBehind for that
// network alone (QD-655). Observe is how the engine hands the gate evidence it met in the store: a fence, a
// lease or a pair floor at a position above the view's. SocketProjectionGate times the grace and loads; the
// interface and ClosedSocketGate's closed answers are here so the routes build on them.

package socketsservice

import (
	"context"
	"errors"
	"time"

	"github.com/urnetwork/connect"
)

// The gate holds no verified projection for the network yet, or its source is down and it has none to
// keep serving (plan-SOCK-gate-data). The engine answers unavailable with retry_after_ms.
var ErrSocketGateUnloaded = errors.New("socket gate has no projection for the network")

// The gate has had evidence for longer than its grace that the network's log passed the state it holds,
// and has not verified the new entries (DESIGN-DETAILS 13.2.3, QD-655). The engine answers unavailable with
// retry_after_ms for that network, and other networks serve on.
var ErrSocketGateBehind = errors.New("socket gate is behind the network's log")

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

// One network's state at one position, immutable: what a registration page or a Find judges everything on
// (DESIGN-DETAILS 13.2.3). Every answer is from memory. Safe for concurrent use.
type SocketGateView interface {
	// The authorization log position of the state: a lease's pv and a ticket's policy_version.
	Position() uint64
	// listen on the name (§8) at now, a grant that has run out by time refusing.
	MayListen(request *SocketGateRequest, now time.Time) *SocketGateVerdict
	// dial on the name (§8) at now.
	MayDial(request *SocketGateRequest, now time.Time) *SocketGateVerdict
	// publish on the name's dns host (§13.9) at now.
	MayPublish(request *SocketGateRequest, now time.Time) *SocketGateVerdict
	// The identity key a sidecar's claims verify under, from the state's SidecarRow (§9.5), and whether the
	// state holds a live row for it.
	IdentityKey(sidecarId connect.Id) (publicKey []byte, found bool)
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
	// The network's newest state while it is fresh: ErrSocketGateUnloaded for a network the gate holds
	// nothing of, ErrSocketGateBehind past the grace. The ctx methods above are each a View and one call
	// on it.
	View(networkId connect.Id) (SocketGateView, error)
	// Evidence from the store that the network's log reached position: a removal's fence, a lease a fresher
	// process admitted, or a pair floor. A position at or below the state's is no evidence. Does no I/O.
	Observe(networkId connect.Id, position uint64)
}

// What a gate that follows the authorization log takes beside SocketGate (DESIGN-DETAILS 13.2.3): the host's
// one key-event subscriber reaches it through the engine's ProjectionChanged and ProjectionsResync, and the
// engine gives it the revocation sweep's queue. SocketProjectionGate implements it; a gate that does not is
// told nothing, and the engine sweeps nothing. Safe for concurrent use.
type SocketGateFollower interface {
	// The {acl_<networkId>}v key event: evidence that the network's log moved, for a network this process
	// serves. Never blocks and does no I/O, so the subscriber's callback may call it.
	Changed(networkId connect.Id)
	// The subscriber resubscribed, so events in the gap are gone: the gate checks each loaded network's
	// {acl_}v on a worker of its own and takes a differing one as evidence. Never blocks.
	Resync()
	// What the gate calls, on its own goroutine, once a load raised a network's position past an entry that
	// may narrow a socket verdict (socketEntryMayNarrow): the revocation sweep's queue, which must not block.
	OnNarrowed(callback func(networkId connect.Id, position uint64))
}

// What a host has with no projection source: never ready, allowing nothing, every network unloaded, and every
// network spent. It is the closed direction of every check, so an engine built on it serves no lease and signs
// no ticket.
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

// ErrSocketGateUnloaded, always.
func (self ClosedSocketGate) View(networkId connect.Id) (SocketGateView, error) {
	return nil, ErrSocketGateUnloaded
}

// Nothing: a gate that loads nothing has nothing to load sooner.
func (self ClosedSocketGate) Observe(networkId connect.Id, position uint64) {}
