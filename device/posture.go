// The forwarding role's posture (§18.6, owner decision 197, DESIGN-DETAILS 4.2.5): what an app's VPN component
// enforces for one network, one state machine with §17.8's engine (D-SDK-13, D-BRIDGE-18), which device.Bridge embeds
// and turns into enforcement. It persists in the component's own store, sealed (NewSealedPostureStore) and never in an
// app group, and is restored, synchronously, before the first packet.
//
//	legacy     no sidecar role has set up forwarding for the network here: today's behavior, no hook
//	pending    an anchor and no verified state: every Network source is denied loopback, LAN, link-local, overlay and
//	           served-prefix destinations and every exit; maps and hosted addresses refuse
//	enforcing  a verified BridgeState and the verified entries after it; {doc} §17.6's rules, {nodoc} owner decisions
//	           50, 105 and 120's allow-all
//
// legacy -> pending on SetPending. pending -> enforcing on the first state its log verifies. doc -> nodoc only on a
// state whose rows say has_document = false on a verified base above the document_seen_at latch, the newest pin at
// which has_document was true: a base between states saying no document opens nothing until a state judged it. Any ->
// legacy only on this sidecar's own sign-out: a Signed SidecarRevoke of its id, signed by that id under the key its
// Pending carried, which wipes the store (plan-SDK-pending-sidecar-id).
//
// DP1 is the point of all of it: after a device's first verified state, no restart, delay, unsigned input, lower state,
// chain break or rolled-back store lowers enforcement, and what fails to verify leaves the state as it was and alarms.
// A store that exists and does not verify is pending, never legacy, and so is one below the floor (PostureFloor), the
// highest pin the posture committed, kept outside the store.
//
// One judge, two tiers. The component's own compile (the Forwarder, root) is the judge, the rule table of a rows-only
// verifier, and SetState is the one source of what opens: a BridgeState is unsigned, so the log vouches for it
// (posture_verify.go), its newest base checked as bridge.VerifyBaseKeyless checks one (§7.9's keyless rule) and every
// entry after that base chaining to the state's pin. This posture is tier 1: between compiles it applies as an overlay
// of denials the log's SidecarRevoke, MemberRevoke, Suspend, GrantRevoke, BridgeWithdraw and DelegationRevoke entries
// and a newer forwarding Delegation's supersession, each verified by its signer's identity key in the base's rows with
// protocol/bridge's types alone, a covered one on that signature alone, which the next state confirms or reverses
// (owner decisions 185, 187, 189, 192). It lifts nothing: an Unsuspend and every other opening wait for the compile.
//
// A narrowing entry it cannot check (its signer not in the rows, a signature that does not verify, a DelegationRevoke
// of no forwarding Delegation in the state, and every AuthorityProposal, AuthorityCosign, RecoveryRebind, AdminSet,
// BridgeEgress, tick and base of another config head) waits for the compile: Waiting holds it with the time it was
// first seen, and once one has waited NarrowingOverdueTimeout the decision reports Overdue and the posture raises
// PostureAlarmCompileOverdue, again each NarrowingOverdueTimeout while one waits. A waiting entry never changes what is
// enforced: the last compiled state stays in force and the component never goes pending for one, at the accepted cost
// that a revocation the posture cannot check does not apply on a device that cannot compile (QD-621). Verification is
// offline: it reads the anchor, the store and what it is given, never a network, and the clock only for Waiting.
//
// The overlay holds OverlayMaxCount entries, and a device that never compiles can fill it. A denial the posture
// verified and cannot hold then makes it pending, persisted, until a state at or past the newest such denial, rather
// than leave a revocation it could check unapplied: the closed direction, which question
// sdk-m8-17-overlay-bound-without-compiles keeps until the owner answers it (its option 3 keeps the overlay in the
// store instead, as QD-641 directs for bulk state).
//
// Rows reach 4 MiB, so rows stream to the store, hashed as they pass, and only has_document and the config writers'
// keys stay in memory; another signer is found by reading the stored rows again.
//
// A Posture is safe for concurrent use. Each call runs whole before the next, store I/O included, so call it off the
// packet path; Decision only reads what is in force, and the clock.

package device

import (
	"errors"
	"io"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One of §17.8's states. The zero value is pending, so a posture nothing has decided denies.
type PostureState int32

const (
	// An anchor and no verified state, or a store that does not verify: private destinations and exits deny.
	PosturePending PostureState = 0
	// No sidecar role has set up forwarding for the network here, or its own sign-out wiped the posture.
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
	// The store exists and a record could not be read or decoded, or the floor could not be read: pending, never
	// legacy.
	PostureAlarmStoreUnreadable PostureAlarmKind = "store_unreadable"
	// The store read, and what it holds does not verify against the anchor: pending, never legacy.
	PostureAlarmStoreUnverified PostureAlarmKind = "store_unverified"
	// A write to the store failed, so nothing it would have recorded is in force; or the floor could not be raised.
	PostureAlarmStoreFailed PostureAlarmKind = "store_failed"
	// The store holds a pin below the floor, or at it on another chain: a restored copy. Pending until a state brings
	// the pin back to the floor on the floor's chain.
	PostureAlarmStoreRolledBack PostureAlarmKind = "store_rolled_back"
	// A Pending or state for another network or genesis than the anchor.
	PostureAlarmAnchor PostureAlarmKind = "anchor"
	// An entry below the pin.
	PostureAlarmLowerPin PostureAlarmKind = "lower_pin"
	// An entry that does not chain from the pin, or a state off the verified chain.
	PostureAlarmChainBreak PostureAlarmKind = "chain_break"
	// A base that does not verify, or is no config writer's.
	PostureAlarmBaseRefused PostureAlarmKind = "base_refused"
	// A statement this role applies whose signature or signer does not verify; it is not applied and waits.
	PostureAlarmStatementRefused PostureAlarmKind = "statement_refused"
	// A state whose has_document disagrees with the verified rows: an unsigned has_document changes nothing.
	PostureAlarmDocument PostureAlarmKind = "document"
	// An entry or rows past a bound, or that do not decode.
	PostureAlarmMalformed PostureAlarmKind = "malformed"
	// A narrowing entry has waited NarrowingOverdueTimeout for a compile (DESIGN-DETAILS 4.2.5), which reaches the
	// owner as bridge_alarm narrowing_overdue: N is its position and Age how long it has waited. Nothing enforces it.
	PostureAlarmCompileOverdue PostureAlarmKind = "narrowing_overdue"
)

// One refusal or report, at the log position it concerns, 0 for none.
type PostureAlarm struct {
	Kind PostureAlarmKind
	N    uint64
	// For PostureAlarmCompileOverdue, how long the entry at N has waited; 0 otherwise.
	Age time.Duration
	// What failed, in words that carry no key, id or path.
	Reason string
}

// What an overlay entry does to the state in force. Every kind denies, and none opens.
type PostureOverlayKind int32

const (
	// Revokes a sidecar: Id is its sidecar_id.
	PostureOverlaySidecarRevoke PostureOverlayKind = iota + 1
	// Revokes a member and so every device of it: Id is its member_id.
	PostureOverlayMemberRevoke
	// Suspends a subject until a state at or past it: Id is the subject, SuspendId the Suspend's suspend_id. An
	// Unsuspend lifts nothing here; it waits for the compile.
	PostureOverlaySuspend
	// Revokes a grant: Id is its grant_id.
	PostureOverlayGrantRevoke
	// Withdraws a bridge rule, resetting or draining by WithdrawMode: Id is its rule_id.
	PostureOverlayBridgeWithdraw
	// Revokes a forwarding Delegation, denying its forwarding key (DESIGN-DETAILS 4.2.5): Id is its delegation_id.
	PostureOverlayDelegationRevoke
	// A newer forwarding Delegation of a sidecar supersedes its older ones: Id is the sidecar_id, DelegationId the
	// newer Delegation's, and the sidecar's forwarding key under any other delegation_id is denied. The newer key is
	// admitted only by the state that judged it.
	PostureOverlayForwardSupersede
)

// A verified log entry after the state's pin that narrows it (§17.8's forwarding roles), in force until a state at or
// past its position confirms or reverses it.
type PostureOverlayEntry struct {
	Kind PostureOverlayKind
	// The log position of the entry carrying it.
	N  uint64
	Id []byte
	// A Suspend's suspend_id.
	SuspendId    []byte
	WithdrawMode bridge.BridgeWithdrawMode
	// A ForwardSupersede's newer Delegation, whose key it does not deny.
	DelegationId []byte
	// §7.9's presence row covers it, and this role, which parses no KeyRegister, applied it on its identity
	// signature alone: only the next state, which checks the countersignature, makes it final.
	Covered bool
}

// A narrowing entry the posture did not apply as a denial, waiting for a compile to judge it (DESIGN-DETAILS 4.2.5).
// It changes nothing in force.
type PostureWaitingEntry struct {
	// Its log position.
	N uint64
	// The last position it stands for: N, or past WaitingMaxCount a later one whose entries merged into it, so a state
	// clears it only at or past ThroughN.
	ThroughN uint64
	// When the posture first saw it, by PostureSettings.Now, to the millisecond; of a merged run, its oldest.
	FirstSeen time.Time
}

// What the decision reports once the oldest waiting entry has waited NarrowingOverdueTimeout: a report, which nothing
// enforces (QD-621).
type PostureOverdue struct {
	// The oldest waiting entry's position.
	N uint64
	// How long it has waited.
	Age time.Duration
	// When the posture raises PostureAlarmCompileOverdue next, if no state has judged it by then.
	NextAlarmAt time.Time
}

// What a posture has in force, which device.Bridge publishes (BRIDGE-M4-11). Callers must not change what it holds.
type PostureDecision struct {
	State PostureState
	// The network and this device's sidecar_id, from the Pending that anchored the posture; nil before one, as in
	// legacy. A host holds a delegation's target to SidecarId (§17.9's verify row).
	NetworkId []byte
	SidecarId []byte
	// The verified state while enforcing: its rules, names, identities, share keys and listeners. Nil otherwise.
	BridgeState *bridge.BridgeState
	// What verified entries after BridgeState's pin add, oldest first.
	Overlay []PostureOverlayEntry
	// The newest verified pin, nil before the first state.
	Pin *bridge.AuthPin
	// The narrowing entries after BridgeState's pin that wait for a compile, oldest first; nil outside enforcing.
	Waiting []PostureWaitingEntry
	// Set while enforcing once the oldest waiting entry has waited NarrowingOverdueTimeout, at the decision's time.
	Overdue *PostureOverdue
	// The sidecar role, a full reader, found a base that does not compile from its head (SetFork): pending until it
	// says otherwise.
	Fork bool
	// The newest position of a denial the posture verified and could not hold past OverlayMaxCount, 0 for none:
	// pending until a state at or past it (the file's comment).
	OverlayFullThroughN uint64
	// Whether this call took an entry it did not apply as a denial, an opening, a neutral or a waiting one, which only
	// a compile can judge.
	CompileWanted bool
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

// The floor (DESIGN-DETAILS 4.2.5's restart row): the highest pin a posture committed, kept outside its store in the
// platform's key store (4.2.2's fwd.<net8>.floor), so a restored copy of the store reads as rolled back. It is as
// strong as that key store: on Apple a keychain item outside the container, elsewhere a sealed file beside the seeds.
// Its functions run within the posture's call, with no lock of the posture's state held, and must not call the
// posture. Its owner erases it with the keys on the sidecar's own sign-out; one left behind keeps the next load
// pending, which fails closed.
type PostureFloor struct {
	// The floor: n 0 and no chain for none yet. An error, a key store that is not Present among them, leaves the
	// posture pending until a later read succeeds.
	Load func() (n uint64, chain []byte, err error)
	// Raises the floor to (n, chain), A_n, durably, after a commit whose pin rose above it. An error leaves the floor
	// where it was and alarms; the commit stands.
	Commit func(n uint64, chain []byte) error
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
	// The bytes the manifest may take, share certificates, overlay and waiting entries included.
	ManifestMaxByteCount int
	// The bytes the stored BridgeState may take.
	StateMaxByteCount int
	// The overlay entries a posture holds between states, 4,096. Past this a denial it verified and cannot hold makes it
	// pending until a state at or past that denial, which only a compile brings (the file's comment).
	OverlayMaxCount int
	// The share certificates a posture keeps.
	ShareCertMaxCount int
	// How long a narrowing entry the posture cannot apply waits before the decision reports it Overdue and the
	// posture raises PostureAlarmCompileOverdue, and the period at which it raises that again while one waits
	// (DESIGN-DETAILS 4.2.5): 10 min, many times a compile's delay. Nothing enforces it. Non-positive reports nothing.
	NarrowingOverdueTimeout time.Duration
	// The waiting entries a posture keeps apart, 1,024, bounding the manifest on a device that never compiles: past
	// it the newest two merge, waiting from the older's time through the newer's position, so the report only errs
	// early and a state never clears one too soon. Below 1 keeps one.
	WaitingMaxCount int
	// The clock Waiting and Overdue read, and nothing else. Nil is RealClock's.
	Now func() time.Time
	// The floor outside the store. Nil keeps none, as for a store no copy of can be put back.
	Floor *PostureFloor
}

// The defaults: room for §7.9's tails at two fold spans and a Team's 5,000 admissions.
func DefaultPostureSettings() *PostureSettings {
	return &PostureSettings{
		EntryMaxByteCount:       256 * 1024,
		EntriesMaxCount:         16 * 1024,
		RowMaxByteCount:         64 * 1024,
		ReadByteCount:           32 * 1024,
		ManifestMaxByteCount:    1024 * 1024,
		StateMaxByteCount:       8 * 1024 * 1024,
		OverlayMaxCount:         4 * 1024,
		ShareCertMaxCount:       1024,
		NarrowingOverdueTimeout: 10 * time.Minute,
		WaitingMaxCount:         1024,
	}
}

// The time on the settings' clock.
func (self *PostureSettings) now() time.Time {
	if self.Now == nil {
		return RealClock{}.Now()
	}
	return self.Now()
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

	// serializes calls, their store I/O included; held and the floor are read and replaced only under it
	operationLock sync.Mutex
	held          *postureHeld
	// the floor as last read or raised; floorKnown false while Floor.Load fails
	floorKnown bool
	floorN     uint64
	floorChain [postureDigestByteCount]byte

	stateLock sync.Mutex
	decision  PostureDecision
	// the newest point of the overdue alarm's schedule raised since the process started, zero for none
	overdueRaisedAt time.Time
}

// Restores the posture from store, synchronously, so its decision is in force before the first packet. A store that
// holds nothing is legacy; one that holds something that cannot be read or does not verify, or that sits below the
// floor, is pending, with an alarm. Nil settings are the defaults.
func NewPosture(store PostureStore, settings *PostureSettings) (*Posture, PostureDecision) {
	if settings == nil {
		settings = DefaultPostureSettings()
	}
	self := &Posture{store: store, settings: settings}
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	held, alarms := self.load()
	return self, self.publishWithLock(held, alarms, true, false)
}

// What is in force now. Its Alarms, CompileWanted and Changed are the last call's, and its Overdue is now's: when the
// overdue alarm's next point has passed, it raises PostureAlarmCompileOverdue among the Alarms, once a point, and
// once at the first decision after a restart, since what showed the last one went with the process.
func (self *Posture) Decision() PostureDecision {
	now := self.settings.now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.overdueWithLock(now)
}

// legacy -> pending, once forwarding's setup hands over the sidecar's Pending (§18.6). In pending, a Pending for the
// same network replaces the anchor and ids. Once enforcing, a Pending for the same network and anchor, as after an
// admin's revocation and a new enrollment, replaces the stored id and key and changes no state; any other is ignored
// and alarms, since only the sidecar's own sign-out lowers enforcement. Its forward_delegation_id is setup's to keep
// (SDK-M8-16), not the posture's.
func (self *Posture) SetPending(pending *bridge.Pending) (PostureDecision, error) {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	return self.setPendingWithLock(pending)
}

// The compile's view (§17.8, DESIGN-DETAILS 4.2.5), vouched for by log: from pending, the state's newest base and every
// entry after it through the state's pin; from enforcing, every entry after the posture's pin through the state's, or
// none for a state at or below it. A state below the one in force is dropped, which is not an error, since compiles
// finish in any order. A state's has_document must match its verified rows, and only a verified base above the latch
// moves doc to nodoc. A state keeps every overlay and waiting entry above its pin, and below the floor it is refused.
func (self *Posture) SetState(state *bridge.BridgeState, log *PostureLog) (PostureDecision, error) {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	return self.setStateWithLock(state, log)
}

// Projection deltas between states (§8.9), each entry chained from the posture's pin and verified offline: bases by
// §7.9's keyless rule, the statements this role applies as denials by their signers' keys, every other entry by its
// chain alone, those that may narrow joining Waiting. Entries before the first that fails stay applied. In pending no
// pin exists to chain from, so this takes one statement alone, this sidecar's own sign-out, and nothing else.
func (self *Posture) ApplyDeltas(log *PostureLog) (PostureDecision, error) {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	return self.applyDeltasWithLock(log)
}

// The witness hint's fork (DESIGN-DETAILS 4.2.5): the app's sidecar role, a full reader, found a base that does not
// compile from its head. true makes the decision pending, persisted, until a later call with false; the state, the
// overlay and the waiting entries stay beneath it, so false restores what was in force with what arrived meanwhile.
// Legacy refuses it.
func (self *Posture) SetFork(fork bool) (PostureDecision, error) {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	return self.setForkWithLock(fork)
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
