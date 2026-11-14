// §17.6's provider hook, device.BridgeEgressPolicy (D-BRIDGE-3, D-BRIDGE-4): connect's EgressHook (C5) on a host's or an
// sdk provider's LocalUserNat, deciding each new flow once, before its dial, by the verified state the bridge
// publishes. ResolveEgress is a pure function of the published state, the flow and the clock: inline, non-blocking,
// with no I/O, no lock and no allocation (R-BRIDGE-9, I-12). It reads compiled rows, never an AclEngine
// (plan-BRIDGE-small-readings #12).
//
// Publish builds the next immutable state off the packet path and swaps it in by one atomic pointer store; its
// generation is a field of the state, so PolicyGeneration is one atomic load. Before the first Publish the policy
// denies every flow. D-BRIDGE-21's order, publish before CloseFlows, is the bridge's (bridge_state.go).
//
// The table, in its order, before rules 0 to 8 (bridge_egress_rules.go):
//
//	sdk provider    legacy: every flow passes, as with no hook (§17.8's legacy); every mode but Network and Service
//	                passes to today's public-only rules (plan-BRIDGE-small-readings #7)
//	host            every mode but Network and FriendsAndFamily denies (#7)
//	both            a contract class other than data denies, control and unset alike (#6, D-PROTO-18); Service denies
//	host            no verified principal, or its subject revoked or suspended here, denies (D-BRIDGE-17); not sealed
//	                denies (D-PROTO-6); FriendsAndFamily denies until shares land (BRIDGE-M6-05)
//	both            pending, legacy at a host and rules that did not parse deny every Network flow (§17.8)
//
// The sdk provider skips the principal and Sealed rows and rules 1 to 3 and 6 until C16, keeping rules 0, 4, 5, 7 and 8
// and the block deny (§17.6's sdk exit NAT). Its subject is C13's sealed client id resolved through
// BridgeRuleSubject.client_ids; one no row binds is another client (§8.4), untagged, which holds the rows
// autogroup:untagged holds here, BridgeRules.untagged, and none when the rules carry no such field
// (bridge-m4-09-other-client-rows, DESIGN-DETAILS 12.2.2). Every such client shares the zero subject id in its rule
// tags, so the bridge can end their flows together.
//
// A Deny is never an Incident. A Pass or Map of a flow with a principal holds the flow for the link's idles, 600 s for
// TCP and 5 min otherwise (§17.5's idle row), and every other flow keeps its NAT's.
//
// Safe for concurrent use.

package device

import (
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"slices"
	"sync/atomic"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Which of §17.6's tables a policy runs.
type BridgePolicyProfile int

const (
	// A sidecar-owned host: Required, every flow from a principal a customer signed (D-BRIDGE-5, D-BRIDGE-17). The zero
	// value, so a policy nothing configured runs the stricter table.
	BridgePolicyProfileHost BridgePolicyProfile = 0
	// The sdk's exit NAT until C16, whose sources may be plaintext (the file's comment).
	BridgePolicyProfileSdkProvider BridgePolicyProfile = 1
)

// The name `ur bridge` shows.
func (self BridgePolicyProfile) String() string {
	switch self {
	case BridgePolicyProfileHost:
		return "host"
	case BridgePolicyProfileSdkProvider:
		return "sdk_provider"
	default:
		return "unknown"
	}
}

// The rules a tag names that carry no rule id: one byte holding the rule's number (plan-BRIDGE-small-readings #11),
// which for rule 3 the hosted address follows (bridgeHostedRuleId). Each pseudo rule id is shorter than a rule id's 32
// bytes, so none can equal one.
const (
	// Rule 3: a hosted address.
	BridgeRuleHosted byte = 3
	// Rule 4: the allow-all with no document.
	BridgeRuleAllowAll byte = 4
	// Rule 7: an exit.
	BridgeRuleExit byte = 7
)

// Rule 3's rule id for a hosted address: BridgeRuleHosted, then the address's four bytes, most significant first, so
// the (subject, 3) pairs split by address and an old address's drain end closes that address's flows alone
// (bridge-m4-11-rule-three-tags, DESIGN-DETAILS 12.2.2). A hosted address is IPv4; any other leaves the four bytes zero.
func bridgeHostedRuleId(addr netip.Addr) [5]byte {
	ruleId := [5]byte{BridgeRuleHosted}
	if addr.Is4() {
		octets := addr.As4()
		copy(ruleId[1:], octets[:])
	}
	return ruleId
}

// The tag of a (subject, rule) pair (plan-BRIDGE-small-readings #11): the big-endian uint64 of the first 8 bytes of
// SHA-256(subject_id || rule_id), a rule id being a map's or route's 32 bytes, for rules 4 and 7 one byte holding the
// rule's number, and for rule 3 that byte and the hosted address's four (DESIGN-DETAILS 12.2.2). The engine enumerates
// a subject's or a rule's tags from these without tracking issued flows. Allocates nothing for a rule id of up to 32
// bytes.
func BridgeRuleTag(subjectId connect.Id, ruleId []byte) uint64 {
	if bridgeRuleRuleIdByteCount < len(ruleId) {
		digest := sha256.Sum256(append(subjectId[:], ruleId...))
		return binary.BigEndian.Uint64(digest[:8])
	}
	var buffer [16 + bridgeRuleRuleIdByteCount]byte
	copy(buffer[:16], subjectId[:])
	n := copy(buffer[16:], ruleId)
	digest := sha256.Sum256(buffer[:16+n])
	return binary.BigEndian.Uint64(digest[:8])
}

// The tag of a (subject, rule) pair for the flows a forwarding key admitted (DESIGN-DETAILS 4.2.5): the big-endian
// uint64 of the first 8 bytes of SHA-256(subject_id || delegation_id || rule_id), delegation_id being the forwarding
// Delegation's 32 bytes. It is BridgeRuleTag's input with the Delegation between, which is longer than any (subject,
// rule) pair's, so the two never meet, and a DelegationRevoke or a supersession ends these flows and none the subject's
// identity key admitted. Allocates nothing for a rule id of up to 32 bytes.
func BridgeForwardRuleTag(subjectId connect.Id, delegationId [sha256.Size]byte, ruleId []byte) uint64 {
	if bridgeRuleRuleIdByteCount < len(ruleId) {
		digest := sha256.Sum256(slices.Concat(subjectId[:], delegationId[:], ruleId))
		return binary.BigEndian.Uint64(digest[:8])
	}
	var buffer [16 + sha256.Size + bridgeRuleRuleIdByteCount]byte
	copy(buffer[:16], subjectId[:])
	copy(buffer[16:], delegationId[:])
	n := copy(buffer[16+sha256.Size:], ruleId)
	digest := sha256.Sum256(buffer[:16+sha256.Size+n])
	return binary.BigEndian.Uint64(digest[:8])
}

// What a policy is built from: what the posture has in force and what the device knows of itself.
type BridgePolicyInput struct {
	// §17.8's state in force.
	State PostureState
	// The verified state while enforcing, nil otherwise: its identities and daemon listeners. Its rules are read from
	// Rules, never parsed again.
	BridgeState *bridge.BridgeState
	// BridgeState.rules as ParseBridgeRules returned them. Nil while enforcing means they were refused, which denies
	// every Network flow, as pending does.
	Rules *bridge.BridgeRules
	// Verified entries since the state's pin, and the bridge's own revocations (Bridge.Revoke), each narrowing the
	// state until one confirms or reverses it.
	Overlay []PostureOverlayEntry
	// This network and this device's sidecar_id (PostureDecision), which a delegation must name.
	NetworkId []byte
	SidecarId []byte
	// This device's own addresses, its interfaces' among them, for rule 0, which never dials a daemon listener on
	// any of them (D-BRIDGE-19). Nil while unknown, which rule 0 reads as every address, so a daemon port is refused
	// on every destination until the device has given them (Bridge.SetLocalAddresses, BRIDGE-M4-13).
	LocalAddresses []netip.Addr
}

// The provider hook. See the file's comment.
type BridgeEgressPolicy struct {
	profile  BridgePolicyProfile
	settings *BridgeSettings
	clock    Clock

	// the published state, swapped whole; never nil
	state atomic.Pointer[bridgePolicyState]

	// delegations VerifyPrincipal checked a signature of, and contracts whose sealed subject the delegation's subject
	// does not bind, which §17.9's verify row alarms on
	principalVerifiedCount atomic.Uint64
	principalMismatchCount atomic.Uint64

	// which forwarding Delegation's key admitted a principal (bridge_principal.go)
	forwardPrincipals bridgeForwardPrincipals
}

var _ connect.EgressHook = (*BridgeEgressPolicy)(nil)

// A policy that denies every flow until its first Publish. Nil settings are the defaults.
func NewBridgeEgressPolicy(profile BridgePolicyProfile, settings *BridgeSettings) *BridgeEgressPolicy {
	if settings == nil {
		settings = DefaultBridgeSettings()
	}
	self := &BridgeEgressPolicy{
		profile:  profile,
		settings: settings,
		clock:    settings.clock(),
	}
	self.state.Store(newBridgePolicyState(&BridgePolicyInput{State: PosturePending}, 0, settings))
	return self
}

// The table this policy runs.
func (self *BridgeEgressPolicy) Profile() BridgePolicyProfile {
	return self.profile
}

// Builds the next state from input and swaps it in, returning its generation, one above the last. Off the packet path:
// it reads and indexes every row. Takes no lock: a swap is a compare-and-swap on the state it built on, so concurrent
// publishes each get their own generation, and the caller, the bridge, orders its inputs.
func (self *BridgeEgressPolicy) Publish(input *BridgePolicyInput) uint64 {
	for {
		previous := self.state.Load()
		next := newBridgePolicyState(input, previous.generation+1, self.settings)
		testHookBarrier("bridge_egress.publish.before", "")
		if self.state.CompareAndSwap(previous, next) {
			testHookBarrier("bridge_egress.publish.after", "")
			return next.generation
		}
	}
}

// connect.EgressHook: the published generation, one atomic load.
func (self *BridgeEgressPolicy) PolicyGeneration() uint64 {
	return self.state.Load().generation
}

// connect.EgressHook (C18): false, so FriendsAndFamily flows to private destinations keep today's public-only rules.
// Only a sidecar-owned Required host holding a share grant turns it on, and shares land at M6 (BRIDGE-M6-05).
func (self *BridgeEgressPolicy) FriendsAndFamilyEgress() bool {
	return false
}

// connect.EgressHook: decides one flow by the published state. See the file's comment.
func (self *BridgeEgressPolicy) ResolveEgress(flow *connect.EgressFlow) connect.EgressDecision {
	state := self.state.Load()
	if flow == nil {
		return connect.EgressDecision{Verdict: connect.EgressVerdictDeny, PolicyGeneration: state.generation}
	}
	var forwardDelegationId *[sha256.Size]byte
	if delegationId, ok := self.forwardPrincipals.delegationId(flow.Principal); ok {
		forwardDelegationId = &delegationId
	}
	return state.resolve(self.profile, self.settings, flow, forwardDelegationId, self.clock.Now())
}

// The counts VerifyPrincipal keeps, for a status.
func (self *BridgeEgressPolicy) principalCounts() (verifiedCount uint64, mismatchCount uint64) {
	return self.principalVerifiedCount.Load(), self.principalMismatchCount.Load()
}
