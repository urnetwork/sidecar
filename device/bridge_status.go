// What a bridge shows (§18.6's Status, §17.11's `ur bridge`, §17.17's waits): plain data, so the sdk can mirror it over
// the device RPC and `ur bridge` can print it. It names states, counts, prefixes of this network's own block and
// classes of fault, never a key, a name or a client's address (I-13).

package device

import (
	"net/netip"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What a bridge waits on, as `ur bridge` shows it (§17.17).
type BridgeWaitKind string

const (
	// No verified state yet: every private destination and exit denies (§17.8's pending).
	BridgeWaitState BridgeWaitKind = "state"
	// A link waits for its sidecar role to sign its window clients' delegations (§17.17's keyless sender).
	BridgeWaitDelegation BridgeWaitKind = "delegation"
	// A link builds: its target's binding is fetched and checked, and its window clients signed for.
	BridgeWaitLink BridgeWaitKind = "link"
)

// One kind of wait, and how many wait on it.
type BridgeWait struct {
	Kind  BridgeWaitKind
	Count int
}

// Why a bridge holds back something its posture has in force. Each names a class of fault, never a value (I-13).
type BridgeAlarmKind string

const (
	// The state in force carries rules that do not parse: the bridge holds none of them, which opens nothing.
	BridgeAlarmRulesRefused BridgeAlarmKind = "rules_refused"
	// Contracts whose sealed subject their delegation's subject does not bind, which the hook refused (§17.9's verify
	// row, plan-BRIDGE-small-readings #17's principal_mismatch).
	BridgeAlarmPrincipalMismatch BridgeAlarmKind = "principal_mismatch"
	// A local /32 the physical path needs is a host's overlay address, so this device reaches that host on its LAN
	// instead: an admin should cycle the block (§17.4, D-BRIDGE-16).
	BridgeAlarmCarvedAddress BridgeAlarmKind = "carved_address"
	// A subnet route overlaps a local network, which wins until a remap or a block change; the route is dropped from
	// the table and the export (§17.7's sender conflicts).
	BridgeAlarmRouteConflict BridgeAlarmKind = "route_conflict"
)

// One alarm, with what failed in words that carry no key, id or address.
type BridgeAlarm struct {
	Kind   BridgeAlarmKind
	Reason string
}

// A bridge's state at one moment.
type BridgeStatus struct {
	// §17.8's state in force, and whether its rows hold an ACL document.
	State       PostureState
	HasDocument bool
	// The newest verified pin's position, 0 before the first state.
	PinN uint64
	// The provider hook's table and the generation it has published (§17.6), and the delegations it has checked a
	// signature of, one per contract.
	PolicyProfile          BridgePolicyProfile
	PolicyGeneration       uint64
	PrincipalVerifiedCount uint64

	// The network's block, the block a change replaced and when that one stops draining; invalid before a state names
	// one (§17.4).
	Block                   netip.Prefix
	PreviousBlock           netip.Prefix
	PreviousBlockDrainUntil time.Time
	// This host's overlay addresses.
	Addresses []netip.Addr

	// The rows of the rules in force.
	EntryCount   int
	MapCount     int
	ServedCount  int
	SubjectCount int
	// Rows draining at the last check of the clock: links, maps and served prefixes.
	DrainingCount int
	// Rows past their expiry or their drain at the last check of the clock, which stop admitting anything new.
	ExpiredCount int

	// The sender's pin table (§17.5): the pairs it holds now, and the picks since the bridge started that found it full
	// and routed by the hash, unpinned, refusing nothing (owner decision 66). An unpinned pair counts once a packet.
	PinnedPairCount   int
	UnpinnedPickCount uint64

	// The sender's links (§17.5): open now, and building or asked for.
	LinkOpenCount     int
	LinkBuildingCount int
	// Rejects written into the tun since the bridge started, and those its buckets, an unanswerable packet or no
	// receive kept back (§17.5's rejects row).
	RejectSentCount   uint64
	RejectUnsentCount uint64
	// Entries answering with rejects since they lost their last advertiser (§17.8's revocation row), and subnet routes
	// dropped for overlapping a local network (§17.7).
	HeldRejectCount    int
	RouteConflictCount int
	// This device's own default route, from the state in force: unspecified keeps today's, as auto does (§17.9's
	// egress spec). `ur tun` routes the default into the tun only under exits.
	EgressMode bridge.BridgeEgressMode

	// §12.9's private names the state in force holds, and `ur tun`'s resolver's queries since the bridge started:
	// answered from them, passed to the host's resolver, and dropped as malformed or past its queue.
	NameCount             int
	ResolverAnsweredCount uint64
	ResolverPassedCount   uint64
	ResolverDroppedCount  uint64

	// What the bridge waits on.
	Waits []BridgeWait
	// What the posture's last call refused or found, and what the bridge itself holds back.
	PostureAlarms []PostureAlarm
	Alarms        []BridgeAlarm
}
