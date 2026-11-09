// §5.4's every-leg types: the Sidecar itself, its events, status, outward actions, the identity
// binding and a member's device list. None names a connect type, so §18.10's sidecar_http leg links
// this file (§4.4). The methods on these types land with their milestones: this file fixes the
// shapes other tracks compile against.

package sidecar

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// One network's sidecar: its own Required client, durable sidecar_id and identity key (D-CORE-4,
// D-CORE-5). Safe for concurrent use.
//
// §5.4's keychain is the instance's, reached through coreSecrets (keys_keychain.go), so the Sidecar
// keeps no root key of its own. NewSidecar (sidecar_new_connect.go on connect legs) sets what is set
// once, and the run loop (sidecar_core.go) alone starts and ends the client generations.
type Sidecar struct {
	host     SidecarHost
	settings *SidecarSettings
	log      Logger
	// The sidecar's client of api, on every leg, holding its jwt and DPoP signer (api_client.go).
	// Set once at construction.
	sidecarApi *SidecarApi
	// Mirrors lifecycle's state for a caller waiting on a change, and is written only with it.
	state          *MonitorValue[SidecarState]
	eventCallbacks *CallbackList[SidecarEventFunction]
	// ServiceToken's cache, under its own lock (api_service_token.go).
	serviceTokens sidecarServiceTokens
	// Running totals for `ur status --stats` (sidecar_stats.go).
	stats sidecarStats
	// Raised for each change the run loop must look at that the instance's state does not show: an
	// enrollment, a generation's end, a component added or removed, a close.
	wakes *MonitorValue[uint64]
	// The number of the generation running, 0 when none: what a caller waits on for a generation to have
	// ended and been joined.
	runningGenerationNumber *MonitorValue[int64]

	// Set once by NewSidecar. instance holds U and this network's keychain, shared with the
	// instance's other Sidecars; leg is what only the leg runs.
	instance *SidecarInstance
	clock    Clock
	leg      sidecarLeg
	ctx      context.Context
	cancel   context.CancelFunc
	// Closed once the run loop has returned, with every generation joined and every component closed.
	done chan struct{}
	// D-TRUST-3's scan of this host's credential stores (identity_host_stores.go), which a test replaces.
	hostStores func() []SidecarHostCredentialStore
	// One enrollment at a time, held across its requests, so never stateLock (identity_enroll.go).
	enrollLock sync.Mutex

	stateLock sync.Mutex
	lifecycle sidecarLifecycle
	// raised and not yet delivered, oldest first
	eventQueue []SidecarEvent
	// a goroutine is delivering eventQueue, which every later event joins
	eventDelivering bool
	// The core's namespace of this network's keychain.ur, which holds the identity key, the ClientKey
	// seed and the newest binding (identity_keys.go). Nil until the sidecar knows its network.
	coreSecrets SidecarSecrets
	// Ids, generation and public keys, never a private key. Nil until the keychain holds an identity.
	identity *SidecarIdentity
	// The network this sidecar is enrolled in: the host store's, or the one Enroll recorded. Nil before.
	networkId *Id
	// The client generation running, which only the run loop starts and ends. Nil when none runs.
	generation *sidecarGeneration
	// The newest generation a confirmed rejection ended. It does not start again: a re-enrollment binds
	// the next one (D-CORE-8).
	endedGeneration int64
	// The instance state the run loop last acted on, so Failed alarms once each time it is entered.
	instanceState SidecarInstanceState
	closed        bool
}

// What an outward action does (I-8), as CanonicalAction.kind carries it (§16.8). Zero is no action,
// and refused, so a value left unset never reads as one.
//
// §5.4 lists these in prose with no numbers, and the numbers here are §5.4's order with §16.7's
// restore appended, as plan-MCP-wire-enum-numbers.md fills them. record.proto's SidecarActionKind
// holds the same values, which record_kind_test.go checks, and they freeze with it at M3.
type SidecarActionKind uint32

const (
	// Refused wherever a kind is read.
	SidecarActionUnspecified SidecarActionKind = 0
	// A tls/ or smtp/ name published to the internet (§13).
	SidecarActionPublish SidecarActionKind = 1
	// A listener on a tls/ or smtp/ name (§9).
	SidecarActionListen SidecarActionKind = 2
	// A port forward (§17).
	SidecarActionForward SidecarActionKind = 3
	// A subnet route or map (§17).
	SidecarActionExpose SidecarActionKind = 4
	// A change to what this sidecar lets out (§17).
	SidecarActionEgressChange SidecarActionKind = 5
	// An invite into the network (§7).
	SidecarActionInvite SidecarActionKind = 6
	// A share of a repo or a grant (§8, §11).
	SidecarActionShare SidecarActionKind = 7
	// A new mail alias (§15.8).
	SidecarActionAliasCreate SidecarActionKind = 8
	// An alias's deletion (§15.8).
	SidecarActionAliasDelete SidecarActionKind = 9
	// A write to an agent-config file in a shared repo (§16.5).
	SidecarActionAgentConfigWrite SidecarActionKind = 10
	// A delete of one (§16.5).
	SidecarActionAgentConfigDelete SidecarActionKind = 11
	// A user DNS record set (§12).
	SidecarActionDnsSet SidecarActionKind = 12
	// A user DNS record deleted (§12).
	SidecarActionDnsDelete SidecarActionKind = 13
	// Mail to a non-member not yet approved, or to any non-member in a tainted run (§15, §16.5).
	SidecarActionMail SidecarActionKind = 14
	// An access request through the team directory (§16.11; CanonicalAction version 3).
	SidecarActionAccessRequest SidecarActionKind = 15
	// A payment.
	SidecarActionPayment SidecarActionKind = 16
	// A run_restore apply, which puts a run's files back (§16.7).
	SidecarActionRestore SidecarActionKind = 17
)

// How much an outward action could cost, the larger of policy's and the daemon's classifier's
// (§16.8). Ordered, because an agent may only raise it. Zero is unset and refused, and the numbers
// are plan-MCP-wire-enum-numbers.md's, as SidecarActionKind's are.
type SidecarRisk uint32

const (
	// Refused wherever a risk is read.
	SidecarRiskUnspecified SidecarRisk = 0
	// An approval on its usual channels.
	SidecarRiskNormal SidecarRisk = 1
	// An approval that also carries the member's SSHSIG (§16.6).
	SidecarRiskHigh SidecarRisk = 2
)

// One outward action on its way through §5.4's gate (I-8).
type SidecarAction struct {
	Kind SidecarActionKind
	// Built by the daemon, never by an agent. payload_sha256 is SHA-256 of these bytes as stored.
	Canonical []byte
	// max(policy, daemon classifier), which an agent may only raise.
	Risk SidecarRisk
	// A decision binds (approval_id, run_id, agent_id) and authorizes at most uses distinct actions,
	// each once (D-MCP-11).
	RunId   *Id
	AgentId *Id
}

// What Authorize answers while an action waits for a person's decision.
type ApprovalPendingError struct {
	// The request the decision will name, which a person sees in `ur approve`.
	ApprovalId Id
}

// Names the request and nothing of the action.
func (self *ApprovalPendingError) Error() string {
	return fmt.Sprintf("approval %s is pending", self.ApprovalId)
}

// What a SidecarEvent reports. Other tracks add their kinds beside the ones here (DNS's dns_alarm,
// bridge's bridge_alarm), so a host passes along a kind it does not know.
type SidecarEventKind string

const (
	// The state or its reason changed.
	SidecarEventState SidecarEventKind = "state"
	// An action or an admission waits for a person's decision (§5.4, §5.6).
	SidecarEventApprovalPending SidecarEventKind = "approval_pending"
	// A leaf or wrapped reader joined a §10 group.
	SidecarEventMemberAdded SidecarEventKind = "member_added"
	// One left.
	SidecarEventMemberRemoved SidecarEventKind = "member_removed"
	// A peer's key changed.
	SidecarEventKeyChanged SidecarEventKind = "key_changed"
	// Something this sidecar relies on refused or failed its checks, and no finer kind says so.
	SidecarEventRefused SidecarEventKind = "refused"
	// An admission under this member that none of its devices signed (§5.6).
	SidecarEventAdmissionAlarm SidecarEventKind = "admission_alarm"
	// A RecoveryRebind this device did not sign, or a binding §7.9's cascade voids (§5.6).
	SidecarEventRecoveryRebind SidecarEventKind = "recovery_rebind"
	// A recovery-signed statement or a restored binding's admission is pending (§5.6).
	SidecarEventRecoveryWindow SidecarEventKind = "recovery_window"
	// A recovery activated too soon for this device to have seen it (§5.6).
	SidecarEventRecoveryUnseen SidecarEventKind = "recovery_unseen"
	// On admin devices, from 90% of config_admissions' cap, with §7.10's cleanup list.
	SidecarEventAdmissionsNearCap SidecarEventKind = "admissions_near_cap"
	// One of §6.4's alarms, named by HeadAlarm.
	SidecarEventHeadAlarm SidecarEventKind = "head_alarm"
	// An index entry disagrees with its document (§11.14).
	SidecarEventIndexMismatch SidecarEventKind = "index_mismatch"
	// An index file failed its format (§11.14).
	SidecarEventIndexMalformed SidecarEventKind = "index_malformed"
	// An indexer's hit that its text disproves, or a local hit it omitted (§11.14).
	SidecarEventSearchAlarm SidecarEventKind = "search_alarm"
	// A drop's state changed (§11.7).
	SidecarEventHistoryDrop SidecarEventKind = "history_drop"
	// An approver's pending directory request (§16.11).
	SidecarEventAccessRequest SidecarEventKind = "access_request"
	// The requester's, with its outcome (§16.11).
	SidecarEventAccessDecided SidecarEventKind = "access_decided"
	// A repo owner's revocation still waiting for the directory's erasure runner past 24 h, then
	// done (§16.11).
	SidecarEventDirectoryErasure SidecarEventKind = "directory_erasure"
	// An erasure this device runs or may finish changed state (§11.12).
	SidecarEventErasure SidecarEventKind = "erasure"
	// An internet send's outcome for a recipient domain changed (§14.5).
	SidecarEventMailSend SidecarEventKind = "mail_send"
	// A store on this host holds a readable network credential (D-TRUST-3; plan-CORE-host-store-refusal #3),
	// raised by an enrolled sidecar at each start and each SyncRefetchInterval. It names no path or value: `ur
	// status` names the store's kind.
	SidecarEventCredentialStore SidecarEventKind = "credential_store"
)

// A drop's state as a device reports it (§11.7).
type SidecarDropState string

const (
	SidecarDropPending   SidecarDropState = "pending"
	SidecarDropCancelled SidecarDropState = "cancelled"
	SidecarDropExecuting SidecarDropState = "executing"
	// A held drop reads done too (owner decision 184).
	SidecarDropDone    SidecarDropState = "done"
	SidecarDropRefused SidecarDropState = "refused"
	// It failed this device's checks (§11.7).
	SidecarDropInvalid SidecarDropState = "invalid"
)

// Why a search_alarm fired (§11.14).
type SidecarSearchAlarm string

const (
	// An opened hit's text disproves it.
	SidecarSearchAlarmMismatch SidecarSearchAlarm = "mismatch"
	// A local confirmed hit that no page of the checked span returned.
	SidecarSearchAlarmOmission SidecarSearchAlarm = "omission"
)

// Which of §6.4's alarms a head_alarm carries.
type SidecarHeadAlarm string

const (
	SidecarHeadAlarmFork SidecarHeadAlarm = "fork"
	// A peer holds proof that its entries are being withheld (§6.4).
	SidecarHeadAlarmWithheld   SidecarHeadAlarm = "withheld"
	SidecarHeadAlarmUnverified SidecarHeadAlarm = "unverified"
	// 24 h without a consistent witness, or 1 h for a revocation this device signed.
	SidecarHeadAlarmUnwitnessed SidecarHeadAlarm = "unwitnessed"
)

// What AddEventCallback, `ur status` and the sdk listener see (§18.5). Each field's comment says
// which kinds fill it. Never log a Path, which is local to this device (I-13).
type SidecarEvent struct {
	Kind SidecarEventKind
	// The client generation it comes from, as §18.5's State block has every event name. A callback
	// of an older generation is dropped (D-SDK-14). Zero is an event no client raised, such as a
	// config alarm, which emitEvent stamps with the current generation.
	Generation int64
	State      SidecarState
	// §18.5's GetStateReason.
	Reason SidecarStateReason
	// Membership kinds: the §10 group.
	GroupId *Id
	// Membership kinds: the leaf or wrapped reader; admission_alarm: the admitted sidecar;
	// recovery_rebind: its signer; recovery_unseen: the recovered device; head_alarm: the peer; index
	// alarms and history_drop: the signer; search_alarm: the indexer.
	SidecarId *Id
	// Index alarms, search_alarm, history_drop, directory_erasure, erasure.
	RepoId *Id
	// Index alarms, history_drop.
	RefId *Id
	// Index alarms: the alarmed path; history_drop: its first listed path, §18.5's Drops listing
	// all.
	Path string
	// history_drop.
	DropId *Id
	// history_drop.
	DropState SidecarDropState
	// history_drop: its window's end (owner decision 183).
	NotBefore time.Time
	// search_alarm.
	SearchAlarm SidecarSearchAlarm
	// access_request, access_decided: the directory request; directory_erasure: its erasure request.
	RequestId *Id
	// access_decided: approved, denied, cancelled or expired; directory_erasure: pending or done.
	Outcome string
	// mail_send: the send, whose outcomes §18.5's GetSendResult reads.
	SendId *Id
	// approval_pending.
	ApprovalId *Id
	// head_alarm.
	HeadAlarm SidecarHeadAlarm
	// head_alarm: this device's pin and the peer's or api's, as §6.5 encodes them (AuthPin, GroupHead,
	// GenHead or RefHead); recovery_rebind at a void: the AuthPins at which keychain.wrap was sealed
	// to the voided binding and re-sealed (§5.9).
	Evidence [2][]byte
	// erasure: its id, state and what is left (§11.12, §11.13's wait).
	Erasure *SidecarErasure
}

// Called for each event, on whatever goroutine raised it. It must not block or call CloseAndWait
// (connect/CODESTYLE.md:171), and it may see two events in the opposite of their order, each naming
// its own State and Generation, so one that needs the state now reads Status.
type SidecarEventFunction func(event SidecarEvent)

// §11.12's erasure as its eraser's device, or a device that may finish it, sees it.
type SidecarErasure struct {
	ErasureId Id
	// fenced: its CUTs committed, its documents masked and unpublishable, its own keys gone with the
	// first ERASE; rewriting; waiting: a 429 for its allowance or turn, or room for its CUT in a ref's
	// full erasure set (§11.12's cut row); done: every key destroyed; stalled: no device that may
	// finish it is running.
	State string
	// Rekey objects not yet re-keyed (§11.13's wait row).
	ObjectsLeft int64
	// Their closure bytes.
	BytesLeft int64
	// The last 429's retry_after_ms. Zero when none waits.
	NextTry time.Time
	// §11.13's bound from BytesLeft, the allowance and the turns. Zero below the limit.
	Finish time.Time
}

// What Status() answers: `ur status`, §18.5's GetState and GetStateReason.
type SidecarStatus struct {
	State  SidecarState
	Reason SidecarStateReason
	// The bound client generation (§5.5).
	Generation int64
	// The newest consistent HeadCheck witness (§6.4). Zero: none yet.
	WitnessedAt time.Time
	// The open UNVERIFIED auth pins (§6.4), as AuthPin bytes. Empty: none.
	Unverified [][]byte
}

// One client generation of a sidecar (§5.5), signed by the ClientKey and the identity key. Its wire
// form is plan-CORE-binding-wire #1's SignedSidecarIdentityBinding (identity_binding.go).
type SidecarIdentityBinding struct {
	NetworkId Id
	SidecarId Id
	ClientId  Id
	// n+1 for every new client: re-enrollment, pairing, fallback (§5.8).
	Generation        int64
	ClientPublicKey   []byte
	IdentityPublicKey []byte
	IssuedAt          time.Time
}

// One of this member's admitted sidecars, as Devices() lists them, the calling sidecar first.
type MemberDevice struct {
	SidecarId Id
	// Its config device name.
	Name string
	// The calling sidecar, which signs out instead.
	This bool
	// A page Worker (§18.8).
	ReadOnly bool
	// A quick burner.
	Ephemeral bool
	// live, pending (suspended while its revocation awaits cosigns), parked, stale (§10.9 removed its
	// leaf as stale from every group this device is a leaf of that seated it, at least one) or
	// revoked.
	State      string
	AdmittedAt time.Time
	// Its newest leaf change in a group this device is a leaf of. Zero: none seen.
	LastChange time.Time
}

// One row of a DeviceRevokePlan.
type DeviceRevokeItem struct {
	// park, void, stands, reseal (§5.9's backup rule) or key (offered for KeyRevoke).
	Effect string
	// What the row names: device, delegation, recovery_binding, key, evs_share, grant, and so on.
	Kind string
	// An Id's 16 bytes, a recovery_binding's 32-byte key hash or a key's key_id (§6.9).
	Id []byte
	// A device's or key's name, or an EvsShare's repo.
	Name string
	// The entry that carries it.
	Position uint64
}

// What PreviewDeviceRevoke shows a person and RevokeDevice re-derives before it signs (§5.6).
type DeviceRevokePlan struct {
	// The first 16 B of SHA-256 over the target and its revocation state, the reason, since_n,
	// Signatures, Presence and the key item ids, never a statement header (§5.6's sign).
	PlanId    Id
	SidecarId Id
	// The target's config device name.
	Name string
	// "lost" or "compromise", SidecarRevoke's reasons (§7.9).
	Reason string
	// Compromise: where P starts (§5.6), with its entry's time.
	SinceN    uint64
	SinceTime time.Time
	Items     []DeviceRevokeItem
	// Counted signatures needed: 1, or k for an AdminSet member's device, this one counting once.
	Signatures int
	// Set from the log, never by the caller: RevokeDevice needs presence (§5.6's approval).
	Presence bool
}

// Every refusal of PreviewDeviceRevoke and RevokeDevice.
type DeviceRevokeError struct {
	// §5.6's REVOKE_ codes.
	Code string
	// REVOKE_PARKS_SELF: the entry that puts this sidecar in P.
	Position uint64
}

// The code, which carries no device name.
func (self *DeviceRevokeError) Error() string {
	return self.Code
}
