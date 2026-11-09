// §18.6's posture: what the keyless device role enforces for one network, one state machine with §17.8's engine
// (D-SDK-13, D-BRIDGE-18), which device.Bridge embeds and turns into enforcement. It persists in the network process's
// own store and is restored, synchronously, before the first packet.
//
//	legacy     no sidecar role has enrolled for the network here: today's behavior, no hook
//	pending    an anchor and no verified state: every Network source is denied loopback, LAN, link-local, overlay and
//	           served-prefix destinations and every exit; maps and hosted addresses refuse
//	enforcing  a verified BridgeState and the verified entries after it; {doc} §17.6's rules, {nodoc} owner decisions
//	           50, 105 and 120's allow-all
//
// legacy -> pending on SetPending. pending -> enforcing on the first state its log verifies. doc -> nodoc only on a
// verified base above the document_seen_at latch, the newest pin at which has_document was true, whose rows say
// has_document = false. Any -> legacy only on this sidecar's own sign-out: a Signed SidecarRevoke of its id, signed
// by that id under the key its Pending carried, which wipes the store (plan-SDK-pending-sidecar-id).
//
// DP1 is the point of all of it: after a device's first verified state, no restart, delay, unsigned input, lower pin
// or chain break lowers enforcement, and what fails to verify leaves the state as it was and alarms. A store that
// exists and does not verify is pending, never legacy.
//
// A BridgeState itself is unsigned, so the log vouches for it (posture_verify.go): its newest base, checked as
// bridge.VerifyBaseKeyless checks one (§7.9's keyless rule), and every entry after that base chaining to the state's
// pin. Between states the role applies the log's SidecarRevoke, MemberRevoke, Suspend, Unsuspend, GrantRevoke and
// BridgeWithdraw entries as an overlay, verified by their signers' identity keys in the base's rows with protocol/bridge's
// types alone, which the next state confirms or reverses (owner decisions 185, 187, 189). Verification is offline: it
// reads the anchor, the store and what it is given, and never a network or a clock.
//
// Rows reach 4 MiB, and the iOS tunnel's growth budget is 1 MiB (§18.4), so rows stream to the store, hashed as they
// pass, and only has_document and the config writers' keys stay in memory; another signer is found by reading the
// stored rows again.
//
// A Posture is safe for concurrent use. Each call runs whole before the next, store I/O included, so call it off the
// packet path; Decision only reads what is in force.

package device

import (
	"errors"
	"io"
	"sync"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One of §17.8's states. The zero value is pending, so a posture nothing has decided denies.
type PostureState int32

const (
	// An anchor and no verified state, or a store that does not verify: private destinations and exits deny.
	PosturePending PostureState = 0
	// No sidecar role has enrolled for the network here, or its own sign-out wiped the posture.
	PostureLegacy PostureState = 1
	// A verified state whose rows have has_document = true: §17.6's rules.
	PostureEnforcingDocument PostureState = 2
	// A verified state whose rows have has_document = false, entered only on a verified base: the allow-all.
	PostureEnforcingNoDocument PostureState = 3
)

// The name §17.8 writes.
func (self PostureState) String() string {
	switch self {
	case PosturePending:
		return "pending"
	case PostureLegacy:
		return "legacy"
	case PostureEnforcingDocument:
		return "enforcing_doc"
	case PostureEnforcingNoDocument:
		return "enforcing_nodoc"
	default:
		return "unknown"
	}
}

// Whether a verified state is in force.
func (self PostureState) Enforcing() bool {
	return self == PostureEnforcingDocument || self == PostureEnforcingNoDocument
}

// Why a posture refused something, as a status shows it. Each names a class of fault and never a value (I-13).
type PostureAlarmKind string

const (
	// The store exists and a record could not be read or decoded: pending, never legacy.
	PostureAlarmStoreUnreadable PostureAlarmKind = "store_unreadable"
	// The store read, and what it holds does not verify against the anchor: pending, never legacy.
	PostureAlarmStoreUnverified PostureAlarmKind = "store_unverified"
	// A write to the store failed, so nothing it would have recorded is in force.
	PostureAlarmStoreFailed PostureAlarmKind = "store_failed"
	// A Pending or state for another network or genesis than the anchor.
	PostureAlarmAnchor PostureAlarmKind = "anchor"
	// A state below the last one, or an entry below the pin.
	PostureAlarmLowerPin PostureAlarmKind = "lower_pin"
	// An entry that does not chain from the pin, or a state off the verified chain.
	PostureAlarmChainBreak PostureAlarmKind = "chain_break"
	// A base that does not verify, or is no config writer's.
	PostureAlarmBaseRefused PostureAlarmKind = "base_refused"
	// A statement this role applies whose signature or signer does not verify; it is not applied.
	PostureAlarmStatementRefused PostureAlarmKind = "statement_refused"
	// A state whose has_document disagrees with the verified rows: an unsigned has_document changes nothing.
	PostureAlarmDocument PostureAlarmKind = "document"
	// An entry or rows past a bound, or that do not decode.
	PostureAlarmMalformed PostureAlarmKind = "malformed"
)

// One refusal, at the log position it concerns, 0 for none.
type PostureAlarm struct {
	Kind PostureAlarmKind
	N    uint64
	// What failed, in words that carry no key, id or path.
	Reason string
}

// What an overlay entry does to the state in force.
type PostureOverlayKind int32

const (
	// Revokes a sidecar: Id is its sidecar_id.
	PostureOverlaySidecarRevoke PostureOverlayKind = iota + 1
	// Revokes a member and so every device of it: Id is its member_id.
	PostureOverlayMemberRevoke
	// Suspends a subject until an Unsuspend naming SuspendId: Id is the subject.
	PostureOverlaySuspend
	// Revokes a grant: Id is its grant_id.
	PostureOverlayGrantRevoke
	// Withdraws a bridge rule, resetting or draining by WithdrawMode: Id is its rule_id.
	PostureOverlayBridgeWithdraw
)

// A verified log entry after the state's pin that narrows it (§17.8's device roles), in force until a state at or
// past its position confirms or reverses it.
type PostureOverlayEntry struct {
	Kind PostureOverlayKind
	// The log position of the entry carrying it.
	N  uint64
	Id []byte
	// A Suspend's suspend_id, which only an Unsuspend naming it lifts.
	SuspendId    []byte
	WithdrawMode bridge.BridgeWithdrawMode
	// §7.9's presence row covers it, and this role, which parses no KeyRegister, applied it on its identity
	// signature alone: only the next state, which checks the countersignature, makes it final.
	Covered bool
	// A Suspend's signer's class, which an Unsuspend must meet (§8.8): 1 owner or sponsor, 2 admin.
	suspendClass int
}

// What a posture has in force, which device.Bridge publishes (BRIDGE-M4-11). Callers must not change what it holds.
type PostureDecision struct {
	State PostureState
	// The verified state while enforcing: its rules, names, identities, share keys and listeners. Nil otherwise.
	BridgeState *bridge.BridgeState
	// What verified entries after BridgeState's pin add, oldest first.
	Overlay []PostureOverlayEntry
	// The newest verified pin, nil before the first state.
	Pin *bridge.AuthPin
	// What this call refused or found, oldest first.
	Alarms []PostureAlarm
	// Whether this call changed what is in force: false means there is nothing to republish.
	Changed bool
}

// A run of the authorization log (§7.9): what vouches for a state, or what extends a posture between states.
type PostureLog struct {
	// AuthEntry bytes as proj/<network_id>/<n>/_ holds them, verbatim, at consecutive positions, oldest first. For a
	// state, its newest base and every entry after it through the state's pin, or, from an enforcing posture, every
	// entry after the posture's pin through it. Between states, the entries after the posture's pin.
	Entries [][]byte
	// Streams the ProjectionRows a base among Entries names (projrows/<network_id>/<rows_sha256>/_), read once and to
	// its end. Nil when no base is among Entries.
	OpenRows func(rowsSha256 []byte) (io.ReadCloser, error)
}

// The posture's tunables. Values are policy, not protocol: §8.8's 4 MiB rows bound and §7.9's formats are constants.
type PostureSettings struct {
	// The bytes one log entry may take: an AuthEntry with its one Signed statement or base. Larger ones are malformed.
	EntryMaxByteCount int
	// The entries since the base a posture keeps. Past this a delta is refused until a state brings a newer base;
	// §7.9's fold keeps the tail near 1,024 entries while any config writer runs.
	EntriesMaxCount int
	// The bytes one MemberRow or SidecarRow may take while rows stream. Larger ones are malformed.
	RowMaxByteCount int
	// The bytes each read of a streamed record takes.
	ReadByteCount int
	// The bytes the manifest may take, share certificates included.
	ManifestMaxByteCount int
	// The bytes the stored BridgeState may take.
	StateMaxByteCount int
	// The overlay entries a posture holds between states. Past this a delta is refused until the next state.
	OverlayMaxCount int
	// The share certificates a posture keeps.
	ShareCertMaxCount int
}

// The defaults: room for §7.9's tails at two fold spans and a Team's 5,000 admissions.
func DefaultPostureSettings() *PostureSettings {
	return &PostureSettings{
		EntryMaxByteCount:    256 * 1024,
		EntriesMaxCount:      16 * 1024,
		RowMaxByteCount:      64 * 1024,
		ReadByteCount:        32 * 1024,
		ManifestMaxByteCount: 1024 * 1024,
		StateMaxByteCount:    8 * 1024 * 1024,
		OverlayMaxCount:      4 * 1024,
		ShareCertMaxCount:    1024,
	}
}

var (
	// The posture is legacy, so there is no anchor to verify against: a state needs a Pending first.
	ErrPostureLegacy = errors.New("posture is legacy")
	// What was given did not verify, or failed a check; the posture is as it was, and an alarm says why.
	ErrPostureRefused = errors.New("posture refused")
	// The store failed, so nothing new is in force.
	ErrPostureStore = errors.New("posture store failed")
)

// One network's posture. See the file's comment.
type Posture struct {
	store    PostureStore
	settings *PostureSettings

	// serializes calls, their store I/O included; held is read and replaced only under it
	operationLock sync.Mutex
	held          *postureHeld

	stateLock sync.Mutex
	decision  PostureDecision
}

// Restores the posture from store, synchronously, so its decision is in force before the first packet. A store that
// holds nothing is legacy; one that holds something that cannot be read or does not verify is pending, with an alarm.
// Nil settings are the defaults.
func NewPosture(store PostureStore, settings *PostureSettings) (*Posture, PostureDecision) {
	if settings == nil {
		settings = DefaultPostureSettings()
	}
	self := &Posture{store: store, settings: settings}
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	held, alarms := self.load()
	return self, self.publishWithLock(held, alarms, true)
}

// What is in force now. Its Alarms and Changed are the last call's.
func (self *Posture) Decision() PostureDecision {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.decision
}

// legacy -> pending, once the sidecar role has a sidecar_id (§18.6). In pending, a Pending for the same network
// replaces the anchor and ids. Once enforcing, a Pending for the same network and anchor, as after an admin's
// revocation and a new enrollment, replaces the stored id and key and changes no state; any other is ignored and
// alarms, since only the sidecar's own sign-out lowers enforcement.
func (self *Posture) SetPending(pending *bridge.Pending) (PostureDecision, error) {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	return self.setPendingWithLock(pending)
}

// The sidecar role's compiled view (§17.8), vouched for by log: from pending, the state's newest base and every entry
// after it through the state's pin; from enforcing, every entry after the posture's pin through the state's, or none
// for a state at or below it. Versions only rise: a state below the last one is refused. A state's has_document must
// match its verified rows, and only a verified base moves doc to nodoc.
func (self *Posture) SetState(state *bridge.BridgeState, log *PostureLog) (PostureDecision, error) {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	return self.setStateWithLock(state, log)
}

// Projection deltas between states (§8.9), each entry chained from the posture's pin and verified offline: bases by
// §7.9's keyless rule, the six statements this role applies by their signers' keys, every other entry by its chain
// alone. Entries before the first that fails stay applied. In pending no pin exists to chain from, so this takes one
// statement alone, this sidecar's own sign-out, and nothing else.
func (self *Posture) ApplyDeltas(log *PostureLog) (PostureDecision, error) {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	return self.applyDeltasWithLock(log)
}

// The generation of the newest ShareCert kept for a share this host serves, and false for none (§17.9's admit row).
func (self *Posture) ShareCertGeneration(shareId []byte) (uint64, bool) {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	if self.held == nil {
		return 0, false
	}
	for _, shareCert := range self.held.shareCerts {
		if string(shareCert.shareId) == string(shareId) {
			return shareCert.generation, true
		}
	}
	return 0, false
}

// Keeps a ShareCert its caller verified under the pinned ShareKey (§17.9), for a share this host serves, so a
// restart refuses one below it. Generations only rise: a lower one is refused, and an equal one changes nothing.
// Only an enforcing posture keeps them.
func (self *Posture) RaiseShareCert(shareId []byte, generation uint64, signedCert []byte) error {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	return self.raiseShareCertWithLock(shareId, generation, signedCert)
}
