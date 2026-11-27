// §5.4's every-leg types: the Sidecar itself, its events, status, outward actions, the identity
// binding and a member's device list. None names a connect type, so §18.10's sidecar_http leg links
// this file (§4.4). The methods on these types land with their milestones: this file fixes the
// shapes other tracks compile against.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
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
	// A member host consumes this network's core rollout across client generations. Guarded by stateLock.
	followCoreGates bool
	// Mirrors lifecycle's state for a caller waiting on a change, and is written only with it.
	state          *MonitorValue[SidecarState]
	eventCallbacks *CallbackList[func(sidecarQueuedEvent)]
	// ServiceToken's cache, under its own lock (api_service_token.go).
	serviceTokens sidecarServiceTokens
	// The network's DnsClient, its label table and its zone watch.
	dns sidecarDns
	// D-TLS-8's CT watch, where the tls component runs one.
	tlsCt sidecarTlsCt
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
	// One agent subkey change at a time, a mint, a renewal or a revocation, so a revocation is never undone by a
	// mint that read the record before it (identity_agent.go). Never held with stateLock.
	agentSubkeyLock sync.Mutex
	// §16's approval ledger and run store, under their own lock (record_ledger.go).
	records sidecarRecords
	// The network's verified config state, which admission, acts and alarms read (identity_authority.go).
	authorities sidecarAuthorities
	// KEYS-M4-01's group view, which §7.10's stale revocations read (identity_act_stale.go).
	staleGroupViews sidecarStaleGroupViews
	// §5.6's alarm watcher on that state's entries (identity_alarms.go).
	alarms sidecarAlarms
	// §7.10's cleanup on admin devices: when its cap was read and the lists a person was shown (identity_cleanup.go).
	cleanups sidecarCleanups
	// §6.4's state Status reads witnessed_at and the UNVERIFIED pins from (sidecar_status.go).
	headCheckStatuses sidecarHeadCheckStatuses
	// The search index's share Status shows, as the last ReadIndexShare left it (sidecar_status_index.go).
	indexShares sidecarIndexShares
	// §16's ledger and spend check behind Authorize (sidecar_gate.go).
	gates sidecarGates
	// A core hint's revocation claim being checked (identity_revoke_self.go).
	revocationClaims sidecarRevocationClaims
	// keychain.wrap's recovery copy and the binding it is sealed to (keys_recovery_seal.go).
	recovery recoverySealer
	// The device revocation plans previewed here, which RevokeDevice signs (identity_revoke_plan.go).
	revokePlans sidecarRevokePlans
	// The k > 1 revocations this device proposed, watched for their completing cosign (identity_revoke_device.go).
	revokeWatches sidecarRevokeWatches
	// A code-only recovery's seams and its one-at-a-time lock (identity_recover.go).
	recoveries sidecarRecoveries
	// §5.9's search state, the index cache and §5.4's search seams (sidecar_search.go), made on first use. Held as any,
	// so this file, which the forwarding leg links, names none of their types: that leg runs no search (§18.10).
	search atomic.Value
	// Forwarding's setup for the app's VPN component, which a host installs (bridge_setup_forward.go). Held as any, as
	// search is: the forwarding leg sets up nothing.
	forwardingSetup atomic.Value
	// The network's config follower, which a host starts (sidecar_config_follower.go). Held as any, as search is: the
	// forwarding-only leg builds none.
	configFollower atomic.Value
	// The enrolled app or browser host owns one GKM and EVS replica for its identity.
	memberReplicaLock sync.Mutex
	memberReplica     interface{ Close() }
	// The network's mail (Sidecar.Mail, mail_client.go). Held as any, as search is: the forwarding leg holds no mail.
	mail atomic.Value
	// What an executed drop reaches beside the mirror and the index cache (state_drop_apply.go). Held as any, as search
	// is: the forwarding leg applies no drop.
	drops atomic.Value
	// An app host's approval parts: the approval log installed in place of the record's, and the phone's part
	// (record_approval_app.go). Held as any, as search is: the forwarding leg decides no approval.
	approvalApps atomic.Value
	// DESIGN-COMPUTE §3.3's components, constructed as the Sidecar starts and closed as its run loop ends
	// (compute_sidecar.go). Held as any, as search is: the forwarding and page Worker legs run no compute.
	compute atomic.Value
	// The compute credentials each area registers for this Sidecar's secret matcher (DESIGN-COMPUTE §2.5,
	// compute_custody.go), made on the first registration. Held as any, as search is: the forwarding leg holds no
	// matcher.
	computeCustody atomic.Value

	stateLock sync.Mutex
	lifecycle sidecarLifecycle
	// raised and not yet delivered, oldest first
	eventQueue []sidecarQueuedEvent
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
// restore appended, as plan-MCP-wire-enum-numbers.md fills them, and then §14.4's TL4 allowance
// (QD-729). record.proto's SidecarActionKind holds the same values, which record_kind_test.go
// checks, and they freeze with it at M3.
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
	// The allowance to send one recipient domain's mail through an MX that cannot be authenticated, §14.4's TL4,
	// which an active URnetwork edge could read (owner decision 38, QD-729).
	SidecarActionMailTlsUnauthenticated SidecarActionKind = 18
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
	// What the action binds on this device alone, built by the daemon as Canonical is: filed as ApprovalRequest's
	// socket_name, local_port, weight and alpn, which approvers render and request_sha256 covers, and no server sees
	// (QD-740, QD-772). A decision spends only on an action whose Detail is its request's. Nil for none.
	Detail *SidecarActionDetail
	// How many distinct actions the agent asks a template's approval to cover (§16.6's multi-use row; QD-1010), filed
	// as ApprovalRequest.uses, which approvers render and sign: 2 or more with a template (Canonical's scope = true, or
	// Template), and 0 or 1, one use, with any other action. Any other pairing is refused (ErrApprovalUses).
	Uses uint32
	// A template Canonical falls inside, of its kind (scope = true), built by the daemon as Canonical is, which the
	// agent asks Uses of in the action's place (owner decision 613: mail_send's uses, NewMailTemplateAction): the gate
	// spends a decision that covers the action as ever, and where none does it files the template's request, not the
	// action's, and answers pending with the template's id, so this action and each later one that falls inside the
	// template spend its uses once a person approves it. Nil for none.
	Template []byte
	// The agent's own words about the action, filed as ApprovalRequest.summary and shown to an approver as
	// untrusted text, never as the action (D-MCP-17). Empty for none.
	Summary string
	// The component's effect, live and set by the caller, which Authorize runs once its use is reserved, or at
	// once under a standing grant (plan-MCP-effect-seam). The gate refuses an action without one.
	Effect SidecarEffect
	// What the effect came to, set by Authorize when it answers nil. A retry of the same action finds the recorded
	// outcome here without the effect running again, unless that outcome is uncertain (AU4).
	Outcome *SidecarOutcome
}

// What an outward action binds on the requesting device beside its CanonicalAction (§16.8's ApprovalRequest fields
// 14 to 17; QD-740, QD-772): a socket_listen's socket name, the local port a socket_listen, tls_publish,
// bridge_forward or bridge_expose points at, a listen's weight and a publish's ALPNs. The kind table says which of
// them a kind takes.
type SidecarActionDetail struct {
	// A listen's name in its one form, which its action's grant_dst names as a server may see it
	// (SocketListenGrantDst); "" for none.
	SocketName string
	// 0 for none.
	LocalPort uint32
	Weight    int32
	Alpn      []string
}

// Whether two details bind the same values, nil binding none.
func (self *SidecarActionDetail) Equal(other *SidecarActionDetail) bool {
	a, b := SidecarActionDetail{}, SidecarActionDetail{}
	if self != nil {
		a = *self
	}
	if other != nil {
		b = *other
	}
	return a.SocketName == b.SocketName && a.LocalPort == b.LocalPort && a.Weight == b.Weight && slices.Equal(a.Alpn, b.Alpn)
}

// A copy, its slices its own; nil for nil.
func (self *SidecarActionDetail) clone() *SidecarActionDetail {
	if self == nil {
		return nil
	}
	return &SidecarActionDetail{SocketName: self.SocketName, LocalPort: self.LocalPort, Weight: self.Weight, Alpn: slices.Clone(self.Alpn)}
}

// One O tool's effect, which §16.6's spend step 5 runs (plan-MCP-effect-seam). A mail body or a file's bytes are not
// in CanonicalAction, so the effect comes in with the action rather than being rebuilt from it.
type SidecarEffect interface {
	// Runs the effect, idempotent per effectKey: a second run under one key finds the first's effect and answers its
	// reference. The key is empty under a standing grant, which keeps no ledger row. An error wrapping
	// ErrSidecarEffectNotDone proves no effect happened; any other error leaves the use uncertain.
	Run(ctx context.Context, effectKey []byte) (effectRef []byte, err error)
}

// What a use's effect came to (§16.6's Outcome).
type SidecarOutcome struct {
	// done, not_done or uncertain.
	State ApprovalOutcomeState
	// The component's reference to what it did, opaque to the gate. Empty unless done.
	EffectRef []byte
	// The reserved use that returned this outcome, supplied in memory by the gate. A component can recover a
	// receipt under this key when an older ledger entry recorded an incomplete reference.
	effectKey []byte
	// The effect's error in this call; nil on a retry that found a recorded outcome. Never stored.
	Err error
}

// A kind's Lookup (§16.6's spend step 5): from the stored action and its effect key alone, so a restart reconciles a
// reserved use with no caller alive, whether the effect happened. done and not_done are the component's proof;
// uncertain, or an error, leaves the use uncertain.
type SidecarEffectLookup func(ctx context.Context, canonical []byte, effectKey []byte) (*SidecarOutcome, error)

// An effect's error proving no effect happened, which records the use's Outcome not_done; the use stays consumed.
// A server gate's refusal proves that only at an action's first presentation (§16.6's spend step 5).
var ErrSidecarEffectNotDone = errors.New("the effect did not happen")

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
	// A recovery-signed statement is pending (§5.6).
	SidecarEventRecoveryWindow SidecarEventKind = "recovery_window"
	// A recovery activated too soon for this device to have seen it (§5.6).
	SidecarEventRecoveryUnseen SidecarEventKind = "recovery_unseen"
	// On admin devices, from 90% of config_admissions' cap, with §7.10's cleanup list.
	SidecarEventAdmissionsNearCap SidecarEventKind = "admissions_near_cap"
	// One of §6.4's alarms or §6.8's rollback, named by HeadAlarm.
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
	// A local git ref the sync engine could not move, its commits kept under the conflict ref Path names
	// (§11.11's restart row; plan-EVS1-evs-events).
	SidecarEventEvsConflict SidecarEventKind = "evs_conflict"
	// An evs read or replay failed a check, named by EvsAlarm (plan-EVS1-evs-events). A head not extending a pin is
	// head_alarm's fork instead.
	SidecarEventEvsAlarm SidecarEventKind = "evs_alarm"
	// A head reader re-pinned past §11.9's catch-up budget: VerifiedSince is the re-pin's time
	// (g0-recheck-0-head-reader-read-paths#3).
	SidecarEventEvsGap SidecarEventKind = "evs_gap"
	// A store on this host holds a readable network credential (D-TRUST-3; plan-CORE-host-store-refusal #3),
	// raised by an enrolled sidecar at each start and each SyncRefetchInterval. It names no path or value: `ur
	// status` names the store's kind.
	SidecarEventCredentialStore SidecarEventKind = "credential_store"
	// The record found what it alarms on, named by RecordAlarm, in the log RepoId, from the writer or signer
	// SidecarId where one is known (plan-RECORD-alarm-kinds). A storage failure is evs_alarm's, and a head not
	// extending a pin head_alarm's.
	SidecarEventRecordAlarm SidecarEventKind = "record_alarm"
	// The bridge found what it alarms on, named by BridgeAlarm (plan-BRIDGE-small-readings #17, DESIGN-DETAILS
	// 12.2.2): the sidecar it concerns in SidecarId where one is named, never a prefix, an address or a name (I-13).
	SidecarEventBridgeAlarm SidecarEventKind = "bridge_alarm"
)

// The zone watch's alarm (D-TRUST-9; DNS-M5-22): a record the device did not request, or resolvers that disagree.
const SidecarEventDnsAlarm SidecarEventKind = "dns_alarm"

// A reader found a receiver or a record it alarms on (reading 8, reading 15; QD-534): SidecarId the receiver or the
// record's signer, RepoId the repo, MailReceiverAlarm why.
const SidecarEventMailReceiverAlarm SidecarEventKind = "mail_receiver_alarm"

// Why a mail_receiver_alarm fired.
type SidecarMailReceiverAlarm string

const (
	// Internet mail a receiver that is none of the network's mail indexers took, under team_mail: indexers.
	SidecarMailReceiverAlarmUndesignated SidecarMailReceiverAlarm = "undesignated"
	// A member scope's deposit from a receiver that is no consented device of the scope's member.
	SidecarMailReceiverAlarmScope SidecarMailReceiverAlarm = "scope"
	// A deposit ingest passed over or wrote as evidence unavailable: a wrong signer, evidence of another message, a
	// depositor with no right there (MailIngestAlarm).
	SidecarMailReceiverAlarmDeposit SidecarMailReceiverAlarm = "deposit"
	// A mailcfg version a reader passed over: a creator that is not the push's signer, a signer that may not change
	// the record (MailConfigAlarm; reading 15).
	SidecarMailReceiverAlarmRecord SidecarMailReceiverAlarm = "record"
)

// Why a dns_alarm fired.
type SidecarDnsAlarm string

const (
	// The two resolvers answered one name and type differently, twice.
	SidecarDnsAlarmSplit SidecarDnsAlarm = "split"
	// The resolvers agree on records this device did not request.
	SidecarDnsAlarmUnrequested SidecarDnsAlarm = "unrequested"
	// The resolvers agree on records GET /dns/zone does not show.
	SidecarDnsAlarmZoneMismatch SidecarDnsAlarm = "zone_mismatch"
)

// The network's DnsClient, which holds the label table it feeds (Sidecar.NetworkLabels), and the zone watch the daemon
// attached (dns_client.go, dns_watch.go), which the legs other than ios_extension build, held through interfaces they
// meet so every leg compiles the Sidecar.
type sidecarDns struct {
	// One opening of the label table at a time, held across its store read, so never stateLock.
	labelsLock sync.Mutex

	stateLock sync.Mutex
	client    sidecarDnsClient
	watch     sidecarZoneWatch
}

// What the Sidecar holds a DnsClient as.
type sidecarDnsClient interface {
	isSidecarDnsClient()
}

// What the Sidecar holds a zone watch as: whether its last pass found a resolver failing.
type sidecarZoneWatch interface {
	Degraded() bool
}

// The attached zone watch's "zone watch degraded", false with none attached.
func (self *sidecarDns) zoneWatchDegraded() bool {
	self.stateLock.Lock()
	watch := self.watch
	self.stateLock.Unlock()
	return watch != nil && watch.Degraded()
}

// D-TLS-8's CT watch found a logged certificate it cannot read back to a device of this network (tls_ct.go).
const SidecarEventCtAlarm SidecarEventKind = "ct_alarm"

// Why a ct_alarm fired.
type SidecarCtAlarm string

const (
	// No row's attestation verifies for the certificate's key and names.
	SidecarCtAlarmUnattested SidecarCtAlarm = "unattested"
	// Every identity that attests it was first pinned under 24 hours before it was issued.
	SidecarCtAlarmRecentIdentity SidecarCtAlarm = "recent_identity"
)

// The CT watch the tls component attached, held through an interface so every leg compiles the Sidecar.
type sidecarTlsCt struct {
	stateLock sync.Mutex
	watch     sidecarCtWatch
}

// What the Sidecar holds a CT watch as: whether its last pass was degraded.
type sidecarCtWatch interface {
	Degraded() bool
}

// The attached CT watch's "CT watch degraded", false with none attached.
func (self *sidecarTlsCt) degraded() bool {
	self.stateLock.Lock()
	watch := self.watch
	self.stateLock.Unlock()
	return watch != nil && watch.Degraded()
}

// Why a bridge_alarm fired: QD-557's five, DESIGN-DETAILS 12.7's three, this build's map_refused and §17.4's
// shared_block.
type SidecarBridgeAlarm string

const (
	// A block that collides with what the host's physical path needs, or a route prefix that collides with the
	// table's own block entries (§17.4).
	SidecarBridgeAlarmBlockConflict SidecarBridgeAlarm = "block_conflict"
	// A share's ShareKey holder left Y's AdminSet or was revoked (§17.9).
	SidecarBridgeAlarmShareHolderRemoved SidecarBridgeAlarm = "share_holder_removed"
	// A client id a host refused names another sidecar or none (§17.9's verify).
	SidecarBridgeAlarmPrincipalMismatch SidecarBridgeAlarm = "principal_mismatch"
	// A ledger file or a sealed body that does not verify: the state in force stands (§17.8).
	SidecarBridgeAlarmStateUnverified SidecarBridgeAlarm = "state_unverified"
	// A head's BridgeBlock a reader refuses: it keeps the previous block (D-BRIDGE-16).
	SidecarBridgeAlarmBlockRefused SidecarBridgeAlarm = "block_refused"
	// The unfolded statements' opened bodies passed BridgeLedgerSettings.UnfoldedBodyMaxByteCount: the state stands.
	SidecarBridgeAlarmLedgerOverBudget SidecarBridgeAlarm = "ledger_over_budget"
	// A share's table hashes to other than its pin, or holds another version (DESIGN-DETAILS 12.2.7).
	SidecarBridgeAlarmShareTableMismatch SidecarBridgeAlarm = "share_table_mismatch"
	// A start's catch-up waited past BridgeComponentSettings.CatchUpAlarmTimeout for the config's follow to reach the
	// posture's pin (DESIGN-DETAILS 12.2.5).
	SidecarBridgeAlarmCatchUpWaiting SidecarBridgeAlarm = "catch_up_waiting"
	// A map onto a block address or one of the daemon's listeners, which the compile voids (§17.6, D-BRIDGE-19).
	SidecarBridgeAlarmMapRefused SidecarBridgeAlarm = "map_refused"
	// Another network this device joined first holds the same block, so the device routes it to that network alone
	// until an admin of either cycles one (§17.4's uniqueness row; BRIDGE-M6-06).
	SidecarBridgeAlarmSharedBlock SidecarBridgeAlarm = "shared_block"
)

// Why a record_alarm fired (plan-RECORD-alarm-kinds): a closed set of 14.
type SidecarRecordAlarm string

const (
	// A writer's chain skips seqs: at once from a writer with no deposit ref on the log, past ChainGapTimeout from one
	// that deposits (RECORD.md section 5.5's chain step).
	SidecarRecordAlarmChainGap SidecarRecordAlarm = "chain_gap"
	// Two entries at one seq of a writer's chain, or a stream wound back below what this device read.
	SidecarRecordAlarmChainFork SidecarRecordAlarm = "chain_fork"
	// An entry that fails a check: RECORD.md section 5.4's steps 1 to 4, section 5.5's steps 1 to 3, 5 and 6.
	SidecarRecordAlarmBadEntry SidecarRecordAlarm = "bad_entry"
	// A receipt-only depositor's entry of another kind (section 5.4's class step).
	SidecarRecordAlarmDepositorKind SidecarRecordAlarm = "depositor_kind"
	// A BASE or ERASE taking an entry before keep_days, or a class 7 entry.
	SidecarRecordAlarmEarlyRemoval SidecarRecordAlarm = "early_removal"
	SidecarRecordAlarmPathRule     SidecarRecordAlarm = "path_rule"
	// A device admitted without the author's consent, which only deposits (§16.8).
	SidecarRecordAlarmParkedWriter SidecarRecordAlarm = "parked_writer"
	// A body past section 6.4's caps.
	SidecarRecordAlarmOverCap SidecarRecordAlarm = "over_cap"
	// §16.11's limits row.
	SidecarRecordAlarmOverLimit SidecarRecordAlarm = "over_limit"
	// plan-RECORD-small-readings#2.
	SidecarRecordAlarmIdReuse SidecarRecordAlarm = "id_reuse"
	// An ERASE, CUT or CLOSURE from another signer, or an erasure_request that fails its check.
	SidecarRecordAlarmBadErasure  SidecarRecordAlarm = "bad_erasure"
	SidecarRecordAlarmBadDecision SidecarRecordAlarm = "bad_decision"
	// RECORD.md section 10.2.
	SidecarRecordAlarmLogCheck SidecarRecordAlarm = "log_check"
	// Shown as a notice.
	SidecarRecordAlarmModeration SidecarRecordAlarm = "moderation"
)

// Why an evs_alarm fired (plan-EVS1-evs-events): a closed set.
type SidecarEvsAlarm string

const (
	// A path's newest version whose content evs does not serve (§11.7, §11.9's collected row).
	SidecarEvsAlarmMissingSegment SidecarEvsAlarm = "missing_segment"
	// A failed entry hash, AEAD, oid or statement.
	SidecarEvsAlarmTamper SidecarEvsAlarm = "tamper"
	// A version off §11.7's rule: a creation not at max(b, m) + 1, a write not at its base + 1.
	SidecarEvsAlarmVersionRule SidecarEvsAlarm = "version_rule"
	// A writer an hour past a path epoch's due_by_ms (§11.6).
	SidecarEvsAlarmEpochOverdue SidecarEvsAlarm = "epoch_overdue"
	// From M6: a stream push off its prefix rule (§16.11), and a change a repo's prefix write rules do not allow its
	// signer (DESIGN-DETAILS 16.2.10), which carries a SidecarEvsAlarmDetail.
	SidecarEvsAlarmPrefixRule SidecarEvsAlarm = "prefix_rule"
)

// What an evs_alarm of reason prefix_rule stands for (DESIGN-DETAILS 16.2.10): a closed set.
type SidecarEvsAlarmDetail string

const (
	// A change of a file-mode ref this device does not follow: its signer's rules do not allow its path.
	SidecarEvsAlarmDetailIgnored SidecarEvsAlarmDetail = "ignored"
	// A git-mode push the mounts refused whole, its ref stopped at the version before (16.2.6).
	SidecarEvsAlarmDetailRefused SidecarEvsAlarmDetail = "refused"
	// A rule set that is void, the set below it staying in force; raised once a set a device, with the row's signer
	// and position in place of a push.
	SidecarEvsAlarmDetailSetVoid SidecarEvsAlarmDetail = "set_void"
	// A rule set of a later release, which this device cannot read: once a set a device, as set_void.
	SidecarEvsAlarmDetailSetNewer SidecarEvsAlarmDetail = "set_newer"
	// More ignored versions over a path than a read walks back under.
	SidecarEvsAlarmDetailDepth SidecarEvsAlarmDetail = "depth"
	// The effective version is gone from evs and this device holds no copy.
	SidecarEvsAlarmDetailUnavailable SidecarEvsAlarmDetail = "unavailable"
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

// Which alarm a head_alarm carries: one of §6.4's four, or §6.8's rollback (owner decision 300).
type SidecarHeadAlarm string

const (
	// Two pins that disagree (§6.4), a head evs serves that does not extend this device's pin among them.
	SidecarHeadAlarmFork SidecarHeadAlarm = "fork"
	// A peer holds proof that its entries are being withheld (§6.4).
	SidecarHeadAlarmWithheld   SidecarHeadAlarm = "withheld"
	SidecarHeadAlarmUnverified SidecarHeadAlarm = "unverified"
	// 24 h without a consistent witness, or 1 h for a revocation this device signed.
	SidecarHeadAlarmUnwitnessed SidecarHeadAlarm = "unwitnessed"
	// A versions page (GET /sidecar/sync/versions) presented a durable topic (team, dns, gkm:<group_id>) below the
	// version this client holds: api lowered a version, where fork is two pins that disagree (§6.8; owner decision 300,
	// QD-928). A resident's or a poll's reset showing one lower raises nothing and sends the client to versions, whose
	// page judges it (QD-1044). SidecarId is nil and Evidence the two TopicVersions as protobuf bytes, the held one
	// first, then the offered one. The push client's Consistent() is false until the topic's owner reconciles it, as
	// for every head alarm.
	SidecarHeadAlarmRollback SidecarHeadAlarm = "rollback"
)

// What AddEventCallback, `ur status` and the sdk listener see (§18.5). Each field's comment says
// which kinds fill it. Never log a Path, which is local to this device (I-13).
type SidecarEvent struct {
	Kind SidecarEventKind
	// The client generation it comes from, as §18.5's State block has every event name. A callback
	// of an older generation is dropped (D-SDK-14). Zero is an event no client raised, such as a
	// config alarm, which emitEvent stamps with the current generation.
	Generation int64
	// state: the state moved to; refused: offline, for a generation whose subprotocol store failed as it started.
	State SidecarState
	// state: §18.5's GetStateReason; refused: subprotocol_store_failed beside that State (§5.9's Failed; owner
	// decision 616).
	Reason SidecarStateReason
	// Membership kinds: the §10 group.
	GroupId *Id
	// Membership kinds: the leaf or wrapped reader; admission_alarm: the admitted sidecar;
	// recovery_rebind: its signer; recovery_unseen: the recovered device; head_alarm: the peer, none for
	// rollback; index alarms and history_drop: the signer; search_alarm: the indexer; evs_alarm: the signer
	// of what failed, where one is known; record_alarm: the writer or signer, where one is known.
	SidecarId *Id
	// Index alarms, search_alarm, history_drop, directory_erasure, erasure, evs_conflict, evs_alarm, evs_gap,
	// record_alarm (the log).
	RepoId *Id
	// Index alarms, history_drop, evs_conflict, evs_alarm, evs_gap.
	RefId *Id
	// Index alarms: the alarmed path; history_drop: its first listed path, §18.5's Drops listing
	// all; evs_conflict: the local conflict ref; evs_alarm: the path, where one is named.
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
	// GenHead or RefHead), or for rollback the TopicVersion held and the one offered, as protobuf bytes;
	// recovery_rebind at a void: the AuthPins at which keychain.wrap was sealed to the voided binding and
	// re-sealed (§5.9); ct_alarm: [0], the leaf's SHA-256.
	Evidence [2][]byte
	// erasure: its id, state and what is left (§11.12, §11.13's wait).
	Erasure *SidecarErasure
	// evs_alarm.
	EvsAlarm SidecarEvsAlarm
	// evs_alarm of reason prefix_rule (DESIGN-DETAILS 16.2.10): what it stands for; the ref version and the push of
	// the first change it names, or for set_void and set_newer the set's log position and no push; and how many
	// changes it stands for, one event a (repo, ref, signer) in AclPrefixSettings.AlarmInterval.
	EvsAlarmDetail SidecarEvsAlarmDetail
	Version        uint64
	PushId         *Id
	Count          int
	// evs_gap: the newest re-pin past the catch-up budget.
	VerifiedSince time.Time
	// record_alarm.
	RecordAlarm SidecarRecordAlarm
	// bridge_alarm.
	BridgeAlarm SidecarBridgeAlarm
	// dns_alarm (D-TRUST-9's zone watch).
	DnsAlarm SidecarDnsAlarm
	// ct_alarm (D-TLS-8's CT watch). SidecarId names the attesting identity of a recent_identity alarm, and
	// Evidence[0] is the leaf's SHA-256: the logged certificate's, or its precertificate's while only that is logged.
	CtAlarm SidecarCtAlarm
	// mail_receiver_alarm (D-MAIL-15, reading 8): SidecarId the receiver or the record's signer, RepoId the repo.
	MailReceiverAlarm SidecarMailReceiverAlarm
	// upgrade_required (DESIGN-COMPUTE §16.6's hold): the authorization features the network turned on that this
	// release lacks, which the update that ends the hold brings.
	AuthFeatures AuthFeature
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
	// The bound client generation (§5.5): Offline and Online name the generation whose client is in that state, and
	// every other state the one the keychain binds.
	Generation int64
	// The newest consistent HeadCheck witness (§6.4). Zero: none yet.
	WitnessedAt time.Time
	// The open UNVERIFIED auth pins (§6.4), as AuthPin bytes. Empty: none.
	Unverified [][]byte
	// "zone watch degraded": a resolver of D-TRUST-9's zone watch failed at its last pass (DnsWatch).
	ZoneWatchDegraded bool
	// "CT watch degraded": D-TLS-8's CT watch could not read a source, the rows or verified config at its last pass.
	CtWatchDegraded bool
	// The search index's share of the network's storage, shown apart from content (D-QUOTA-10), as this device last
	// read it from its repos' index status (Sidecar.ReadIndexShare). nil: none read yet.
	IndexShare *SidecarIndexShare
}

// The search index's files across the repos one read covered (D-QUOTA-10; §11.14's status row). They count toward the
// network's storage like any evs bytes (§20.7's stored row), which is why `ur status` shows them apart from content.
type SidecarIndexShare struct {
	// The repos asked, and of them those whose index this build could not read: an error, or a root in a newer
	// format. A repo of a kind that holds no index (config, mailcfg, secret) counts in neither.
	RepoCount       int64
	UnreadRepoCount int64
	// The index files at each index ref's head and their bytes, pads included, over every root of every repo read.
	// Replaced index versions still in their batch count toward storage for up to 26 h too (owner decision 165),
	// and no head lists them, so this is a floor on the index's stored bytes, never more than them.
	FileCount int64
	ByteCount int64
	// When the read ended, on the Sidecar's clock.
	ReadAt time.Time
}

// The share Status shows, under its own lock: a read's result, replaced whole by the next read.
type sidecarIndexShares struct {
	stateLock sync.Mutex
	share     *SidecarIndexShare
}

// The last share read, a copy sharing nothing; nil before any read.
func (self *sidecarIndexShares) get() *SidecarIndexShare {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.share == nil {
		return nil
	}
	share := *self.share
	return &share
}

// Keeps a copy of share as what Status shows.
func (self *sidecarIndexShares) set(share *SidecarIndexShare) {
	var kept *SidecarIndexShare
	if share != nil {
		copied := *share
		kept = &copied
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.share = kept
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

// One provenance signature by an agent's subkey, with the certificate a reader checks it under: what RECORD.md 5.3's
// AgentSignedBody and §11.6's sealed metadata carry (identity_agent.go's Sidecar.SignProvenance makes it). Here, on
// every leg, since EvsClientArgs names its signer on every leg.
type AgentProvenanceSignature struct {
	AgentId   Id
	KeyId     []byte
	Signature []byte
	Cert      []byte
}
