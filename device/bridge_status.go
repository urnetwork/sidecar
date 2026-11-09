// What a bridge shows (§18.6's Status, §17.11's `ur bridge`, §17.17's waits): plain data, so the sdk can mirror it over
// the device RPC and `ur bridge` can print it. It names states, counts, prefixes of this network's own block and
// classes of fault, never a key, a name or a client's address (I-13).

package device

import (
	"net/netip"
	"time"
)

// What a bridge waits on, as `ur bridge` shows it (§17.17).
type BridgeWaitKind string

const (
	// No verified state yet: every private destination and exit denies (§17.8's pending).
	BridgeWaitState BridgeWaitKind = "state"
	// A link waits for its sidecar role to sign its window clients' delegations (§17.17's keyless sender).
	BridgeWaitDelegation BridgeWaitKind = "delegation"
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

	// The sender's pin table (§17.5): the pairs it holds, and the pairs routed by the hash, unpinned, because it was
	// full (owner decision 66), since the bridge started.
	PinnedPairCount   int
	UnpinnedPairCount uint64

	// What the bridge waits on.
	Waits []BridgeWait
	// What the posture's last call refused or found, and what the bridge itself holds back.
	PostureAlarms []PostureAlarm
	Alarms        []BridgeAlarm
}
