//go:build !sidecar_http && !ios_extension

// §8.10's contract gate: the verdict CreateContract asks for before it creates a contract that a network with a head
// row is party to (D-ACL-4, D-ACL-5, D-PROTO-18; R-ACL-5, R-ACL-8, R-ACL-9, I-5, I-10, I-12). It answers from memory
// alone: a snapshot of network_acl_head, which says which networks have a config repo and reloads every HeadsInterval
// off the request path, and each such network's verified state in the process's AclGateCache (C-09). A request reads
// one map for the heads and one for the state, intersects the state's bitsets and allocates nothing; only a refusal
// for want of a loaded state takes a lock, to ask the cache for a load. Nothing is checked per packet.
//
// The rule runs on the request's own Companion bit, read before CreateContract settles a same-network companion as
// Network or falls back to a Stream companion, since either rewrites it:
//
//	skip         an end is a platform client (urnetwork-edge) or the control id, or the network the rule reads has
//	             no head row: today's path, untouched, class data (R-ACL-8)
//	Network a→b  both ends in one network with a head row:
//	  hosted     a is §18's hosted device: refused (I-10)
//	  self       a and b act as one subject (D-ACL-3): data, a subject reaching itself
//	  forward    a non-companion with reach(a,b): data
//	  reply      a non-companion with reach(b,a) alone: data once b's origin contract to a stands, which
//	             CreateContract checks with the companion path's bounded origin wait (plan-ACL-network-reply-contracts,
//	             QD-185), else the witness exception or a refusal
//	  companion  reach(b,a): data
//	  witness    otherwise, two admitted sidecars, neither revoked, parked nor suspended: control, with no reach grant;
//	             what rides it is the receivers' to enforce, and providers deny IP on it (D-PROTO-18)
//	  refuse     otherwise
//	Public a→b   a's network has a head row: a non-companion from a declared no-egress client (§20.8), from a sidecar
//	             §8.6 hard-denies or a suspended client, or from a subject in exits or none (§17.8, D-BRIDGE-13) is
//	             refused; anything else is data
//	not loaded   a network with a head row and no verified state refuses, never passes, and asks the cache to load it
//
// reach is AclState.Reach's: an active dial or route grant, sockets expanding to their listeners and ip grants to their
// via subjects, ports left to the endpoints. A client with no acl_enforcing is reached only through a rule whose
// ports_limited is false, and is a source only otherwise (D-ACL-5, owner decision 106). A reply is decided before the
// witness exception, so a reply racing its origin never sticks on a control contract (QD-185).
//
// The caller never records a refusal as a route rejection: a grant can activate at any moment.
//
// Safe for concurrent use. Installing a heads snapshot is the gate's linearization point, between the
// acl_contract.heads barriers. Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret.

package sidecar

import (
	"context"
	"slices"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What C13 seals into StoredContract.contract_class (D-PROTO-18, D-PROTO-19), numbered as connect's ContractClass.
type AclContractClass int32

const (
	// whatever the provide mode allows
	AclContractClassData AclContractClass = 1
	// only §6.4's witnessing and remote search between two admitted sidecars of one network
	AclContractClassControl AclContractClass = 2
)

// What the gate answers one request.
type AclContractOutcome int

const (
	// the rule does not apply: today's path, class data
	AclContractSkip AclContractOutcome = iota + 1
	// created, with the verdict's class
	AclContractAllow
	// a reply: data once the origin stands, else what Origin(false) gives
	AclContractReply
	// refused with ContractError_NoPermission, and never recorded as the route's
	AclContractRefuse
)

// Why the gate answered as it did.
type AclContractReason int

const (
	// skipped: the network the rule reads has no head row
	AclContractReasonNoHead AclContractReason = iota + 1
	// skipped: a platform client or the control id
	AclContractReasonPlatform
	// allowed: both ends act as one subject
	AclContractReasonSelf
	// allowed by reach: a→b, or b→a for a companion
	AclContractReasonReach
	// a reply: reach(b,a) for a non-companion
	AclContractReasonReply
	// allowed as control by the witness exception
	AclContractReasonWitness
	// allowed: a Public contract the egress rules let through
	AclContractReasonPublic
	// refused: no heads snapshot has loaded yet
	AclContractReasonHeadsUnknown
	// refused: a network with a head row and no verified state
	AclContractReasonNotLoaded
	// refused: an end whose subject the facts cannot tell
	AclContractReasonSubjectUnknown
	// refused: a Network contract from a hosted device
	AclContractReasonHosted
	// refused: a Public contract from a declared no-egress client
	AclContractReasonDeclaredNoEgress
	// refused: a Public contract from a subject in exits or none
	AclContractReasonEgress
	// refused: a subject §8.6 hard-denies
	AclContractReasonDenied
	// refused: no reach either way and no witness exception
	AclContractReasonNoReach
)

// A short name for logs and metric labels.
func (self AclContractReason) String() string {
	switch self {
	case AclContractReasonNoHead:
		return "no_head"
	case AclContractReasonPlatform:
		return "platform"
	case AclContractReasonSelf:
		return "self"
	case AclContractReasonReach:
		return "reach"
	case AclContractReasonReply:
		return "reply"
	case AclContractReasonWitness:
		return "witness"
	case AclContractReasonPublic:
		return "public"
	case AclContractReasonHeadsUnknown:
		return "heads_unknown"
	case AclContractReasonNotLoaded:
		return "not_loaded"
	case AclContractReasonSubjectUnknown:
		return "subject_unknown"
	case AclContractReasonHosted:
		return "hosted"
	case AclContractReasonDeclaredNoEgress:
		return "declared_no_egress"
	case AclContractReasonEgress:
		return "egress"
	case AclContractReasonDenied:
		return "denied"
	case AclContractReasonNoReach:
		return "no_reach"
	}
	return "unknown"
}

// One end of a contract as the one query behind CreateContract's relationship loads it (R-ACL-8): the client, its
// network, and the facts of the subject it acts as (D-ACL-3). A value, so a request allocates nothing.
type AclContractEnd struct {
	// Whether the query read this end's facts. False for a client the server does not have, which a network with a
	// head row refuses.
	Known bool
	// The client's network.
	NetworkId Id
	// The client the end acts as: its stored network_client.acl_subject_client_id, else itself when it is top-level
	// or a sidecar's own client. Zero when neither tells it, which the rule refuses.
	SubjectClientId Id
	// The sidecar the subject is bound to (sidecar_identity_binding). Zero for none.
	SidecarId Id
	// The subject's member, network_client_owner.member_id, an app device's owner. Zero for a tagged or legacy client.
	MemberId Id
	// Whether the subject's owner row marks it a sidecar's (strict_exp) or tagged, so that it acts only as its
	// sidecar: with no binding the rule cannot tell what it acts as, and never takes it for an app device.
	SidecarHeld bool
	// Whether the subject's owner row marks it acl_enforcing, checking ports and sockets itself. A client that is no
	// sidecar and has no mark is legacy, reached only through an unrestricted rule (D-ACL-5).
	AclEnforcing bool
	// Whether a hosted proxy device's config names the client, its source client or its subject (§18;
	// proxy_device_config).
	Hosted bool
	// Whether the source declares no egress (§20.8), the mark ProvideRelationshipDetails.DeclaredSourceRefused reads.
	// Unused on a destination.
	DeclaresNoEgress bool
	// Whether the end is a platform client in urnetwork-edge, or the control id, which skip the gate (§8.10).
	Platform bool
	// The subject's identity roles and principal on Embed networks, from the same query
	// (plan-ACL-nonsidecar-subjects).
	Roles     []string
	Principal string
	// A hard deny only the caller sees, an abuse halt (§21) or quota (§20). Zero: none.
	Deny AclReason
}

// The subject the end acts as, false when its facts cannot tell one.
func (self *AclContractEnd) subject() (AclSubject, bool) {
	switch {
	case !self.Known || self.SubjectClientId == (Id{}):
		return AclSubject{}, false
	case self.SidecarId != (Id{}):
		return AclSubject{Kind: AclSubjectSidecar, Id: self.SidecarId, Deny: self.Deny}, true
	case self.SidecarHeld:
		// a sidecar's client before its binding, or a tagged one: never an app device
		return AclSubject{}, false
	}
	return AclSubject{
		Kind:      AclSubjectClient,
		Id:        self.SubjectClientId,
		MemberId:  self.MemberId,
		Roles:     self.Roles,
		Principal: self.Principal,
		Deny:      self.Deny,
	}, true
}

// Whether a reach to the end takes only a rule with ports_limited false: a client that is no sidecar and does not
// enforce (D-ACL-5).
func (self *AclContractEnd) legacy() bool {
	return self.SidecarId == (Id{}) && !self.AclEnforcing
}

// One CreateContract as the gate reads it.
type AclContractRequest struct {
	Source      AclContractEnd
	Destination AclContractEnd
	// The request's own CreateContract.companion, before CreateContract rewrites it (D-ACL-4).
	Companion bool
}

// The gate's answer. A value.
type AclContractVerdict struct {
	Outcome AclContractOutcome
	// What C13 seals: data for a skip, a reach, a reply or a Public contract, control for the witness exception.
	// Zero on a refusal.
	Class  AclContractClass
	Reason AclContractReason
	// The network whose rule decided. Zero for a skip.
	NetworkId Id
	// The reach the rule ran last, naming its rule or why none held (§8.17). Zero when none ran.
	Decision AclDecision
	// a reply's verdict should no origin stand
	noOrigin       AclContractOutcome
	noOriginReason AclContractReason
}

// Whether the contract may go on as the verdict stands: a skip or an allow. A reply first needs Origin.
func (self AclContractVerdict) Allowed() bool {
	return self.Outcome == AclContractSkip || self.Outcome == AclContractAllow
}

// A reply's verdict once CreateContract knows whether b's origin contract to a stands: data when it does, else the
// witness exception's control or a refusal. Any other verdict is itself.
func (self AclContractVerdict) Origin(stands bool) AclContractVerdict {
	if self.Outcome != AclContractReply {
		return self
	}
	if stands {
		self.Outcome, self.Class, self.Reason = AclContractAllow, AclContractClassData, AclContractReasonReply
	} else {
		self.Outcome, self.Reason, self.Class = self.noOrigin, self.noOriginReason, 0
		if self.Outcome == AclContractAllow {
			self.Class = AclContractClassControl
		}
	}
	self.noOrigin, self.noOriginReason = 0, 0
	return self
}

// A skip.
func aclContractSkip(reason AclContractReason) AclContractVerdict {
	return AclContractVerdict{Outcome: AclContractSkip, Class: AclContractClassData, Reason: reason}
}

// An allow.
func aclContractAllow(networkId Id, class AclContractClass, reason AclContractReason, decision AclDecision) AclContractVerdict {
	return AclContractVerdict{Outcome: AclContractAllow, Class: class, Reason: reason, NetworkId: networkId, Decision: decision}
}

// A refusal.
func aclContractRefuse(networkId Id, reason AclContractReason, decision AclDecision) AclContractVerdict {
	return AclContractVerdict{Outcome: AclContractRefuse, Reason: reason, NetworkId: networkId, Decision: decision}
}

// Where the gate reads which networks have a head row: network_acl_head (§8.17; GetNetworkAclHeads).
type AclContractHeadSource interface {
	// Every network with a head row, with its newest verified position n. A network absent has no config repo. Must
	// return its failures, never panic.
	Heads(ctx context.Context) (map[Id]uint64, error)
}

// Where the gate reads each network's verified state: the process's AclGateCache (C-09).
type AclContractStateSource interface {
	// The network's verified state and what the cache says of it, with no lock and no I/O.
	State(networkId Id) (*AclGateSnapshot, AclGateStatus)
	// Asks for a load, without blocking.
	Changed(networkId Id)
}

// The gate's tunables, each with its default here and nowhere else.
type AclContractGateSettings struct {
	// How often the heads snapshot reloads: 5 s, §8.10's heads snapshot. Each load also asks the cache to load the
	// networks whose head is new or moved, up to LoadAskCount, so the gate holds a revocation within about this long
	// even when its {acl_}v event is lost. Non-positive loads once, at construction.
	HeadsInterval time.Duration
	// How long one heads read may run before the gate gives it up and keeps its last snapshot: 4 s, inside one
	// interval. Non-positive is no deadline but the gate's own.
	HeadsTimeout time.Duration
	// The most networks one heads load asks the cache to load, those whose head is new or moved; the rest are asked
	// at the next loads, so a cold start over many networks spreads its loads rather than starting one per network at
	// once (§8.18's fan-out risk): 1,000, each a loader goroutine waiting its turn for one of the cache's
	// LoadConcurrency slots, a few megabytes of stacks at most. A network a contract finds not loaded is asked at once
	// whatever this says. Non-positive asks for none.
	LoadAskCount int
	// Where heads failures are logged, ids only (I-13). Nil is the leg's default.
	Log Logger
	// Called after each heads load on the gate's goroutine, which it must not hold: the snapshot's network count and
	// why the load failed, nil when it read cleanly. What a host counts and a test waits on. Nil calls nothing.
	OnHeads func(networkCount int, err error)
}

// §8.10's values.
func DefaultAclContractGateSettings() *AclContractGateSettings {
	return &AclContractGateSettings{
		HeadsInterval: 5 * time.Second,
		HeadsTimeout:  4 * time.Second,
		LoadAskCount:  1000,
	}
}

// What the gate has decided and loaded since it started, for the host's metrics.
type AclContractGateStats struct {
	SkipCount    uint64
	AllowCount   uint64
	ReplyCount   uint64
	RefusalCount uint64
	// heads loads that read cleanly, and ones that failed with the last snapshot kept
	HeadsLoadCount    uint64
	HeadsFailureCount uint64
}

// §8.10's contract gate. See the file header.
type AclContractGate struct {
	ctx        context.Context
	cancel     context.CancelFunc
	states     AclContractStateSource
	headSource AclContractHeadSource
	clock      Clock
	settings   *AclContractGateSettings
	log        Logger

	// the newest heads snapshot, never changed once stored; nil before the first load reads cleanly
	heads atomic.Pointer[map[Id]uint64]
	// the head position each network's load was last asked at; the heads goroutine's alone
	asked map[Id]uint64

	skipCount         atomic.Uint64
	allowCount        atomic.Uint64
	replyCount        atomic.Uint64
	refusalCount      atomic.Uint64
	headsLoadCount    atomic.Uint64
	headsFailureCount atomic.Uint64
}

// A gate over states and heads, its heads loading on clock until ctx ends or Close: the first load at once, then every
// HeadsInterval. A nil clock is real time.
func NewAclContractGate(ctx context.Context, states AclContractStateSource, heads AclContractHeadSource, clock Clock, settings *AclContractGateSettings) *AclContractGate {
	if settings == nil {
		settings = DefaultAclContractGateSettings()
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &AclContractGate{
		ctx:        cancelCtx,
		cancel:     cancel,
		states:     states,
		headSource: heads,
		clock:      clockOrReal(clock),
		settings:   settings,
		log:        loggerOrDefault(settings.Log),
		asked:      map[Id]uint64{},
	}
	go self.run()
	return self
}

// Stops the heads loads. The last snapshot keeps answering.
func (self *AclContractGate) Close() {
	self.cancel()
}

// Whether a heads snapshot has loaded: until one has, the gate refuses everything it does not skip.
func (self *AclContractGate) Ready() bool {
	return self.heads.Load() != nil
}

// Whether the newest snapshot holds a head row for the network, false before the first.
func (self *AclContractGate) HasHead(networkId Id) bool {
	heads := self.heads.Load()
	if heads == nil {
		return false
	}
	_, found := (*heads)[networkId]
	return found
}

// What the gate has counted.
func (self *AclContractGate) Stats() AclContractGateStats {
	return AclContractGateStats{
		SkipCount:         self.skipCount.Load(),
		AllowCount:        self.allowCount.Load(),
		ReplyCount:        self.replyCount.Load(),
		RefusalCount:      self.refusalCount.Load(),
		HeadsLoadCount:    self.headsLoadCount.Load(),
		HeadsFailureCount: self.headsFailureCount.Load(),
	}
}

// The verdict for one request at now, the server's time. See the file header.
func (self *AclContractGate) Decide(request *AclContractRequest, now time.Time) AclContractVerdict {
	verdict := self.decide(request, now)
	switch verdict.Outcome {
	case AclContractSkip:
		self.skipCount.Add(1)
	case AclContractAllow:
		self.allowCount.Add(1)
	case AclContractReply:
		self.replyCount.Add(1)
	case AclContractRefuse:
		self.refusalCount.Add(1)
	}
	return verdict
}

// Decide's verdict, uncounted.
func (self *AclContractGate) decide(request *AclContractRequest, now time.Time) AclContractVerdict {
	source, destination := &request.Source, &request.Destination
	if source.Platform || destination.Platform {
		return aclContractSkip(AclContractReasonPlatform)
	}
	heads := self.heads.Load()
	if heads == nil {
		// any network might have a head row
		return aclContractRefuse(Id{}, AclContractReasonHeadsUnknown, AclDecision{})
	}
	if !source.Known || source.NetworkId == (Id{}) || !destination.Known {
		// a client the server does not have creates nothing, and its network cannot be told
		return aclContractRefuse(Id{}, AclContractReasonSubjectUnknown, AclDecision{})
	}
	// a Network contract is its network's to judge, and a Public one its source network's egress rules'
	networkId := source.NetworkId
	if _, found := (*heads)[networkId]; !found {
		return aclContractSkip(AclContractReasonNoHead)
	}
	snapshot, status := self.states.State(networkId)
	if status != AclGateLoaded || snapshot == nil || snapshot.Acl == nil {
		self.states.Changed(networkId)
		return aclContractRefuse(networkId, AclContractReasonNotLoaded, AclDecision{})
	}
	nowMs := now.UnixMilli()
	if destination.NetworkId == networkId {
		return snapshot.Acl.contractNetwork(networkId, request, nowMs)
	}
	return snapshot.Acl.contractPublic(networkId, request, nowMs)
}

// The rule for a Network contract, both ends in networkId.
func (self *AclState) contractNetwork(networkId Id, request *AclContractRequest, nowMs int64) AclContractVerdict {
	source, destination := &request.Source, &request.Destination
	if source.Hosted {
		return aclContractRefuse(networkId, AclContractReasonHosted, AclDecision{})
	}
	sourceSubject, sourceKnown := source.subject()
	destinationSubject, destinationKnown := destination.subject()
	if !sourceKnown || !destinationKnown {
		return aclContractRefuse(networkId, AclContractReasonSubjectUnknown, AclDecision{})
	}
	if sourceSubject.Kind == destinationSubject.Kind && sourceSubject.Id == destinationSubject.Id {
		// one subject's clients, such as a sidecar's forwarding client and its own: hard denies still win
		if resolved := self.resolve(&sourceSubject, nowMs); resolved.deny != 0 {
			return aclContractRefuse(networkId, AclContractReasonDenied, aclDeny(resolved.deny))
		}
		return aclContractAllow(networkId, AclContractClassData, AclContractReasonSelf, AclDecision{})
	}
	var decision AclDecision
	if request.Companion {
		// a companion a→b answers b, so b must reach a
		decision = self.contractReach(&destinationSubject, &sourceSubject, source.legacy(), nowMs)
		if decision.Allowed {
			return aclContractAllow(networkId, AclContractClassData, AclContractReasonReach, decision)
		}
	} else {
		decision = self.contractReach(&sourceSubject, &destinationSubject, destination.legacy(), nowMs)
		if decision.Allowed {
			return aclContractAllow(networkId, AclContractClassData, AclContractReasonReach, decision)
		}
		// connect asks for a same-network reply as no companion (QD-185): b's reach to a makes it a reply
		if reverse := self.contractReach(&destinationSubject, &sourceSubject, source.legacy(), nowMs); reverse.Allowed {
			verdict := AclContractVerdict{
				Outcome:        AclContractReply,
				Class:          AclContractClassData,
				Reason:         AclContractReasonReply,
				NetworkId:      networkId,
				Decision:       reverse,
				noOrigin:       AclContractRefuse,
				noOriginReason: AclContractReasonNoReach,
			}
			if self.contractWitnesses(&sourceSubject, &destinationSubject, nowMs) {
				verdict.noOrigin, verdict.noOriginReason = AclContractAllow, AclContractReasonWitness
			}
			return verdict
		}
	}
	if self.contractWitnesses(&sourceSubject, &destinationSubject, nowMs) {
		return aclContractAllow(networkId, AclContractClassControl, AclContractReasonWitness, decision)
	}
	return aclContractRefuse(networkId, AclContractReasonNoReach, decision)
}

// The rule for a Public contract from networkId, whose head row binds its source alone.
func (self *AclState) contractPublic(networkId Id, request *AclContractRequest, nowMs int64) AclContractVerdict {
	source := &request.Source
	if request.Companion {
		// a companion's source answers another's contract, which is no egress of its own
		return aclContractAllow(networkId, AclContractClassData, AclContractReasonPublic, AclDecision{})
	}
	if source.DeclaresNoEgress {
		return aclContractRefuse(networkId, AclContractReasonDeclaredNoEgress, AclDecision{})
	}
	subject, known := source.subject()
	if !known {
		return aclContractRefuse(networkId, AclContractReasonSubjectUnknown, AclDecision{})
	}
	resolved := self.resolve(&subject, nowMs)
	deny := resolved.deny
	if subject.Kind == AclSubjectClient && deny == AclReasonUnadmitted {
		// an app device whose member the log does not hold is named by no row, and keeps the egress it has today
		deny = 0
	}
	if deny != 0 {
		return aclContractRefuse(networkId, AclContractReasonDenied, aclDeny(deny))
	}
	if self.egressRestricted(&resolved) {
		return aclContractRefuse(networkId, AclContractReasonEgress, AclDecision{})
	}
	return aclContractAllow(networkId, AclContractClassData, AclContractReasonPublic, AclDecision{})
}

// reach(source, destination) for the contract rule: Reach's search, holding a legacy destination to rules with
// ports_limited false.
func (self *AclState) contractReach(source *AclSubject, destination *AclSubject, legacyDestination bool, nowMs int64) AclDecision {
	sourceResolved := self.resolve(source, nowMs)
	if sourceResolved.deny != 0 {
		return aclDeny(sourceResolved.deny)
	}
	destinationResolved := self.resolve(destination, nowMs)
	if destinationResolved.deny != 0 {
		return aclDeny(destinationResolved.deny)
	}
	var accept func(rule *aclRule) bool
	if legacyDestination {
		accept = aclRuleUnrestricted
	}
	if rule := self.findSubjectRule(&sourceResolved, &destinationResolved, nowMs, aclReachActions, accept, true); rule != nil {
		return aclAllowRule(rule)
	}
	return aclDeny(AclReasonNoGrant)
}

// Whether a rule reaches a legacy client: one whose ip field names no ports, which only an endpoint could enforce
// (D-ACL-5).
func aclRuleUnrestricted(rule *aclRule) bool {
	return !rule.portsLimited
}

// The witness exception: both are sidecars this state admits, neither revoked, parked, suspended nor past its
// not_after, and neither hard-denied by the caller.
func (self *AclState) contractWitnesses(a *AclSubject, b *AclSubject, nowMs int64) bool {
	if a.Kind != AclSubjectSidecar || b.Kind != AclSubjectSidecar || a.Deny != 0 || b.Deny != 0 {
		return false
	}
	aSidecar, bSidecar := self.sidecarState(a.Id), self.sidecarState(b.Id)
	return aSidecar != nil && bSidecar != nil && aSidecar.hardDeny(nowMs) == 0 && bSidecar.hardDeny(nowMs) == 0
}

// Whether the rows' BridgeRows put the subject in exits or none (§17.8): a row naming its sidecar or client id, or an
// atom it holds. Read from AclRows.bridge's bytes in place, so the check allocates nothing; bytes no verifier folded,
// or a field this build cannot name, read as restricted, the closed direction ParseBridgeRows takes.
func (self *AclState) egressRestricted(resolved *aclResolved) bool {
	data := self.rows.GetBridge()
	for 0 < len(data) {
		number, wireType, n := protowire.ConsumeTag(data)
		if n < 0 || number != 1 || wireType != protowire.BytesType {
			return true
		}
		data = data[n:]
		row, n := protowire.ConsumeBytes(data)
		if n < 0 {
			return true
		}
		data = data[n:]
		subject, mode, ok := aclEgressRow(row)
		if !ok || (mode != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS && mode != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE) {
			return true
		}
		if self.egressNames(resolved, subject) {
			return true
		}
	}
	return false
}

// One BridgeEgressRow's subject and mode, false for bytes CompileBridgeRows never writes.
func aclEgressRow(row []byte) (Id, bridge.BridgeEgressMode, bool) {
	var subject Id
	var mode bridge.BridgeEgressMode
	subjectSet := false
	for 0 < len(row) {
		number, wireType, n := protowire.ConsumeTag(row)
		if n < 0 {
			return Id{}, 0, false
		}
		row = row[n:]
		switch {
		case number == 1 && wireType == protowire.BytesType:
			value, n := protowire.ConsumeBytes(row)
			if n < 0 || len(value) != len(Id{}) {
				return Id{}, 0, false
			}
			subject, subjectSet = Id(value), true
			row = row[n:]
		case number == 2 && wireType == protowire.VarintType:
			value, n := protowire.ConsumeVarint(row)
			if n < 0 {
				return Id{}, 0, false
			}
			mode = bridge.BridgeEgressMode(value)
			row = row[n:]
		default:
			return Id{}, 0, false
		}
	}
	return subject, mode, subjectSet
}

// Whether an egress row's subject, a sidecar_id, a client id or a keyed atom, names the resolved subject.
func (self *AclState) egressNames(resolved *aclResolved, subject Id) bool {
	if resolved.subject.Id == subject {
		return true
	}
	index, found := self.atomIndexes[subject]
	if !found {
		return false
	}
	if resolved.sidecar != nil {
		_, holds := slices.BinarySearch(resolved.sidecar.atoms, index)
		return holds
	}
	return self.holdsAtom(resolved, index)
}

// Loads the heads now and then every HeadsInterval, until the gate closes.
func (self *AclContractGate) run() {
	for {
		self.loadHeads()
		if self.settings.HeadsInterval <= 0 {
			return
		}
		select {
		case <-self.ctx.Done():
			return
		case <-self.clock.After(self.settings.HeadsInterval):
		}
	}
}

// One heads load: the snapshot's install, then a load asked of the cache for each network whose head is new or moved
// since its last ask, at most LoadAskCount of them. A failure keeps the last snapshot.
func (self *AclContractGate) loadHeads() {
	if self.ctx.Err() != nil {
		return
	}
	ctx := self.ctx
	if 0 < self.settings.HeadsTimeout {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(self.ctx, self.settings.HeadsTimeout)
		defer cancel()
	}
	heads, err := self.headSource.Heads(ctx)
	if err != nil {
		self.headsFailureCount.Add(1)
		self.log.Warningf("[acl_contract]heads load failed, the last snapshot keeps serving: %v", err)
		heads = nil
	} else {
		if heads == nil {
			heads = map[Id]uint64{}
		}
		testHookBarrier("acl_contract.heads.before", "")
		self.heads.Store(&heads)
		testHookBarrier("acl_contract.heads", "")
		self.headsLoadCount.Add(1)
		askCount := 0
		for networkId, version := range heads {
			if askedVersion, found := self.asked[networkId]; found && askedVersion == version {
				continue
			}
			if self.settings.LoadAskCount <= askCount {
				break
			}
			self.states.Changed(networkId)
			self.asked[networkId] = version
			askCount += 1
		}
		for networkId := range self.asked {
			if _, found := heads[networkId]; !found {
				delete(self.asked, networkId)
			}
		}
		testHookBarrier("acl_contract.heads.after", "")
	}
	if onHeads := self.settings.OnHeads; onHeads != nil {
		onHeads(len(heads), err)
	}
}
