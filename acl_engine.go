//go:build !ios_extension

// §8.9's client engine: every admitted sidecar evaluates its own rules here, with no always-on compiler (owner
// decision 6). Install swaps one state and its AclLocalPolicy in through an atomic.Pointer, and every check reads
// the installed pair with no lock and no allocation, so a check concurrent with an Install sees the old pair or the
// new one whole. Install refuses a lower pin and a second A_n at one n, keeps what it had, and alarms (I-16).
//
// The checks, each a gate's rows check narrowed by what rows drop on purpose (AclLocalPolicy, §8.10):
//
//	AllowInbound      stream accept (§6) and a listener's check of its dialer: a dial grant reaching this sidecar,
//	                  its ports when the rule limits them, or a socket grant whose exact glob takes the name
//	AllowRoute        a route rule reaching the via whose prefixes take the address and whose ports take the port;
//	                  it serves BRIDGE's compiler and ur bridge's previews, never the device's hook (QD-590)
//	AllowAlias        mail:<alias> for send or listen, which rows carry only as mail_send (D-ACL-12)
//	Check             Sidecar.Authorize's active-grant test through CORE's SidecarGate, and MCP's acl_check
//	VerifyRepoMember  ACL-M2-08's CheckRepoMember at the pin the push or delivery carries (§10.9, FS-104)
//	VerifyHeadSigner  owner decision 7: a reader takes a head only from one of the repo's writers at its pin
//	AllowPrefixWrite  a write's own refusal under the repo's prefix rules, lines 1 to 3 of PrefixVerdict at the
//	                  installed state, whose pin the push then carries, in plaintext, before anything is planned,
//	                  sealed or sent (DESIGN-DETAILS 16.2.7; QD-801): its paths drawn from a sequence until one is
//	                  refused, none drawn for a sidecar a rule with no path names, and the path of no component
//	                  answering whether this device is held
//
// The two Verify checks judge at the pin a push or delivery carries, never the tip, since each late wrap is judged at
// its own pin: a pin above the tip waits (ErrConfigPinAhead), one before what the log retains is unjudged and never
// allowed (ErrConfigPinNotRetained), and one off the chain is invalid and a fork alarm (ErrConfigPinOffChain).
//
// A rule an activated grant gave has no local detail, its own fields being the GrantActivate's: a port-limited one
// opens no port here until the device reads its ports from the grant (sealed_detail, QD-003), the closed direction.
// In-daemon agents share their sidecar's grants (§5.5): the caller narrows, never widens. A client allows
// AclEngineSettings.ClockSkew against the gates' server time (§8.6).
//
// Safe for concurrent use. The root file carries no connect type, and nothing here creates or unwraps a key.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"iter"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Why Install refused.
var (
	// The offered state's pin is below the installed one's (I-16).
	ErrAclEnginePinLower = errors.New("acl engine: a lower pin")
	// The offered state's A_n is not the installed one's at the same n: a fork (I-16).
	ErrAclEngineFork = errors.New("acl engine: a second chain at one position")
)

// What an AclEngine alarms on.
type AclEngineAlarmKind int

const (
	// Install was offered a lower pin
	AclEngineAlarmPinLower AclEngineAlarmKind = iota + 1
	// Install was offered a second A_n at one n
	AclEngineAlarmFork
	// a push or delivery carried a pin off this log's chain
	AclEngineAlarmPinOffChain
)

// One alarm: what the engine held and what it was offered.
type AclEngineAlarm struct {
	Kind      AclEngineAlarmKind
	Installed *bridge.AuthPin
	Offered   *bridge.AuthPin
}

// Where the engine reads the state at a pin a push or delivery carries: TEAM's ConfigLog, through AclEngineStatesOf.
type AclEngineStates interface {
	AclStateAt(pin *bridge.AuthPin) (*AclState, error)
}

// ConfigLog's states as the engine reads them.
type aclConfigLogStates struct {
	log *ConfigLog
}

// The engine's view of a log.
func AclEngineStatesOf(log *ConfigLog) AclEngineStates {
	return &aclConfigLogStates{log: log}
}

// ConfigLog.StateAt's state, its acl part.
func (self *aclConfigLogStates) AclStateAt(pin *bridge.AuthPin) (*AclState, error) {
	state, err := self.log.StateAt(pin)
	if err != nil {
		return nil, err
	}
	return state.Acl()
}

// One installed state and what the checks read beside it.
type aclEngineInstall struct {
	state *AclState
	local *AclLocalPolicy
	// by the state's rule index, the rule's local detail, nil for an activated grant
	localRules []*AclLocalRule
	self       AclSubject
}

// The client engine of one sidecar in one network.
type AclEngine struct {
	settings  *AclEngineSettings
	sidecarId Id
	states    AclEngineStates
	alarm     func(alarm AclEngineAlarm)

	// installs serialize here; checks never take it
	stateLock sync.Mutex
	installed atomic.Pointer[aclEngineInstall]
}

// An engine for the sidecar, with nothing installed: every check refuses until the first Install. states may be nil,
// and then the Verify checks refuse; alarm nil drops alarms.
func NewAclEngine(sidecarId Id, states AclEngineStates, alarm func(alarm AclEngineAlarm), settings *AclEngineSettings) *AclEngine {
	if settings == nil {
		settings = DefaultAclEngineSettings()
	}
	if alarm == nil {
		alarm = func(alarm AclEngineAlarm) {}
	}
	return &AclEngine{settings: settings, sidecarId: sidecarId, states: states, alarm: alarm}
}

// Swaps in a state and its local policy, refusing a lower pin or a second A_n at the installed n, which keeps the
// installed pair and alarms (I-16). local may be nil: the rows' checks then stand alone, every port-limited rule
// opening no port.
func (self *AclEngine) Install(state *AclState, local *AclLocalPolicy) error {
	if state == nil || state.Pin() == nil {
		return fmt.Errorf("%w: no state", ErrAclRowsInvalid)
	}
	next := &aclEngineInstall{state: state, local: local, self: AclSidecarSubject(self.sidecarId)}
	next.localRules = make([]*AclLocalRule, len(state.rules))
	for i := range state.rules {
		next.localRules[i] = local.Rule(state.rules[i].row.GetRuleId())
	}
	var alarm *AclEngineAlarm
	err := func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if current := self.installed.Load(); current != nil {
			installedPin, offeredPin := current.state.Pin(), state.Pin()
			switch {
			case offeredPin.GetVersion() < installedPin.GetVersion():
				alarm = &AclEngineAlarm{Kind: AclEngineAlarmPinLower, Installed: installedPin, Offered: offeredPin}
				return fmt.Errorf("%w: %d below %d", ErrAclEnginePinLower, offeredPin.GetVersion(), installedPin.GetVersion())
			case offeredPin.GetVersion() == installedPin.GetVersion() && !bytes.Equal(offeredPin.GetChain(), installedPin.GetChain()):
				alarm = &AclEngineAlarm{Kind: AclEngineAlarmFork, Installed: installedPin, Offered: offeredPin}
				return fmt.Errorf("%w: %d", ErrAclEngineFork, offeredPin.GetVersion())
			}
		}
		testHookBarrier("acl_engine.install.before", self.sidecarId.String())
		self.installed.Store(next)
		testHookBarrier("acl_engine.install.after", self.sidecarId.String())
		return nil
	}()
	if alarm != nil {
		self.alarm(*alarm)
	}
	return err
}

// The installed state's (n, A_n), nil before the first Install.
func (self *AclEngine) Pin() *bridge.AuthPin {
	if installed := self.installed.Load(); installed != nil {
		return installed.state.Pin()
	}
	return nil
}

// The installed state, nil before the first Install. The caller must not change it.
func (self *AclEngine) State() *AclState {
	if installed := self.installed.Load(); installed != nil {
		return installed.state
	}
	return nil
}

// The check time with the skew allowed, ms since the epoch.
func (self *AclEngine) checkMs(now time.Time) int64 {
	return now.UnixMilli() - max(0, self.settings.ClockSkew.Milliseconds())
}

// Whether a protocol and port pass a rule's local ports: every port for a rule that limits none, none for one whose
// ports the device does not hold.
func aclLocalPortsMatch(rule *aclRule, local *AclLocalRule, ipProtocol uint32, port uint32) bool {
	if !rule.portsLimited {
		return true
	}
	if local == nil {
		return false
	}
	for _, ports := range local.Ports {
		if (ports.Protocol == 0 || ports.Protocol == ipProtocol) && ports.First <= port && port <= ports.Last {
			return true
		}
	}
	return false
}

// One inbound stream or dial as a receiver checks it.
type AclInbound struct {
	Source AclSubject
	// A dial to a socket this sidecar listens on: its canonical name and its token path. Empty for a dial to the
	// sidecar itself.
	SocketName string
	NameToken  []byte
	// The IP protocol number and port, for a dial to the sidecar.
	IpProtocol uint32
	Port       uint32
}

// Whether an inbound stream or dial is allowed (§6, §8.10): to the sidecar, a dial grant reaching it whose ports take
// the port; to one of its sockets, a dial grant on the socket whose exact name or glob, where the device holds it,
// takes the name.
func (self *AclEngine) AllowInbound(inbound *AclInbound, now time.Time) AclDecision {
	installed := self.installed.Load()
	if installed == nil || inbound == nil {
		return aclDeny(AclReasonNoState)
	}
	nowMs := self.checkMs(now)
	state := installed.state
	if inbound.SocketName != "" {
		return state.resourceDecision(inbound.Source, nowMs, protocol.AclAction_ACL_ACTION_DIAL, func(rule *aclRule) bool {
			covered := false
			for i := range rule.sockets {
				covered = covered || rule.sockets[i].covers(inbound.NameToken)
			}
			return covered && aclLocalSocketMatch(installed.localRules[rule.index], inbound.SocketName)
		})
	}
	return state.mayDial(inbound.Source, installed.self, nowMs, func(rule *aclRule) bool {
		return aclLocalPortsMatch(rule, installed.localRules[rule.index], inbound.IpProtocol, inbound.Port)
	})
}

// Whether a rule's exact sockets take a name: any glob of its local detail, segment by segment, a last segment of *
// taking every name below its prefix (acl-policy-small-readings #1), or the rows' token path alone for a rule with
// none, an activated grant's, whose target is one exact path. The name is the listener's own, an application or
// share/ name in §9.4's form, so no glob reaches a namespace a policy must name outright; nothing is copied.
func aclLocalSocketMatch(local *AclLocalRule, name string) bool {
	if local == nil {
		return true
	}
	for _, glob := range local.Sockets {
		if aclPublicSocketCovers(glob, name) {
			return true
		}
	}
	return false
}

// Whether the source may route to the address on the port via a subject: a route rule reaching the via, or
// autogroup:internet for a public address, whose prefixes, where the device holds any, take the address, and whose
// ports take the port.
func (self *AclEngine) AllowRoute(source AclSubject, address netip.Addr, ipProtocol uint32, port uint32, via AclSubject, now time.Time) AclDecision {
	installed := self.installed.Load()
	if installed == nil {
		return aclDeny(AclReasonNoState)
	}
	address = address.Unmap()
	return installed.state.mayRoute(source, address, via, self.checkMs(now), func(rule *aclRule) bool {
		local := installed.localRules[rule.index]
		if !aclLocalPortsMatch(rule, local, ipProtocol, port) {
			return false
		}
		if local == nil || len(local.Cidrs) == 0 {
			// the via's own addresses (§8.4), or autogroup:internet, which mayRoute checks
			return true
		}
		for _, cidr := range local.Cidrs {
			if aclCidrCovers(cidr, address) {
				return true
			}
		}
		return false
	})
}

// Whether the subject may send to or listen on mail:<alias> (§15.10): a send or listen grant whose aliases take it.
// Rows carry no alias, so a rule the device holds no detail of takes none.
func (self *AclEngine) AllowAlias(subject AclSubject, action protocol.AclAction, alias string, now time.Time) AclDecision {
	installed := self.installed.Load()
	if installed == nil {
		return aclDeny(AclReasonNoState)
	}
	if action != protocol.AclAction_ACL_ACTION_SEND && action != protocol.AclAction_ACL_ACTION_LISTEN {
		return aclDeny(AclReasonNoGrant)
	}
	concrete := AclResource{Kind: AclResourceMail, Name: alias}
	return installed.state.resourceDecision(subject, self.checkMs(now), action, func(rule *aclRule) bool {
		local := installed.localRules[rule.index]
		if !rule.mailSend || local == nil {
			return false
		}
		for _, pattern := range local.Aliases {
			if (AclResource{Kind: AclResourceMail, Name: pattern}).covers(concrete) {
				return true
			}
		}
		return false
	})
}

// One Check answer: whether an active grant allows it, the rule or grant id that did, and why not.
type AclCheck struct {
	Allowed bool
	// The rule's id: a document rule's 16 bytes, or an activated grant's grant_id.
	GrantId []byte
	Reason  AclReason
}

// Sidecar.Authorize's active-grant test, through CORE's SidecarGate, and MCP's acl_check: whether the subject holds
// an active grant for action on resource at now, on the installed state. A subject resource is dialed or routed to, a
// socket dialed or listened on by name, a repo read, written, administered or deposited to, a dns host published, an
// alias sent to or listened on; an ip range routed to through any via.
func (self *AclEngine) Check(subject AclSubject, action protocol.AclAction, resource AclResource, now time.Time) AclCheck {
	installed := self.installed.Load()
	if installed == nil {
		return AclCheck{Reason: AclReasonNoState}
	}
	state := installed.state
	nowMs := self.checkMs(now)
	answer := func(decision AclDecision) AclCheck {
		check := AclCheck{Allowed: decision.Allowed, Reason: decision.Reason}
		if decision.Rule != nil {
			check.GrantId = bytes.Clone(decision.Rule.GetRuleId())
		}
		return check
	}
	switch resource.Kind {
	case AclResourceSubject:
		destination, ok := self.checkSubject(state, resource.Subject)
		if !ok {
			return AclCheck{Reason: AclReasonNoGrant}
		}
		if action == protocol.AclAction_ACL_ACTION_DIAL {
			return answer(state.mayDial(subject, destination, nowMs, nil))
		}
		if action == protocol.AclAction_ACL_ACTION_ROUTE {
			return answer(state.mayRoute(subject, netip.Addr{}, destination, nowMs, nil))
		}
	case AclResourceSocket:
		return answer(state.resourceDecision(subject, nowMs, action, func(rule *aclRule) bool {
			local := installed.localRules[rule.index]
			if local == nil {
				return false
			}
			for _, glob := range local.Sockets {
				if glob == resource.Name || (AclResource{Kind: AclResourceSocket, Name: glob}).covers(resource) {
					return true
				}
			}
			for _, publicName := range rule.publicNames {
				if aclPublicSocketCovers(publicName, resource.Name) {
					return true
				}
			}
			return false
		}))
	case AclResourceRepo:
		if resource.RepoId == (Id{}) {
			return AclCheck{Reason: AclReasonNoRepo}
		}
		access := state.EvsAccess(subject, resource.RepoId, AclTokenAudienceEvs, time.UnixMilli(nowMs))
		want := map[protocol.AclAction]AclEvsRights{
			protocol.AclAction_ACL_ACTION_READ: AclEvsRead, protocol.AclAction_ACL_ACTION_WRITE: AclEvsWrite,
			protocol.AclAction_ACL_ACTION_ADMIN: AclEvsAdmin, protocol.AclAction_ACL_ACTION_DEPOSIT: AclEvsDeposit,
		}[action]
		check := answer(access.AclDecision)
		check.Allowed = want != 0 && access.Rights.Has(want)
		if !check.Allowed && check.Reason == AclReasonRule {
			check.Reason = AclReasonNoGrant
		}
		return check
	case AclResourceDns:
		if action == protocol.AclAction_ACL_ACTION_PUBLISH {
			return answer(state.MayPublish(subject, resource.Name, time.UnixMilli(nowMs)))
		}
	case AclResourceMail:
		return answer(self.AllowAlias(subject, action, resource.Name, now))
	case AclResourceIp:
		if action == protocol.AclAction_ACL_ACTION_ROUTE {
			return answer(state.findRouteToPrefix(subject, resource.Cidr, nowMs, installed.localRules))
		}
	}
	return AclCheck{Reason: AclReasonNoGrant}
}

// The subject a destination selector names outright, for Check: a sidecar or a client by id, another network.
func (self *AclEngine) checkSubject(state *AclState, selector AclSelector) (AclSubject, bool) {
	switch selector.Kind {
	case AclSelectorSidecar:
		return AclSidecarSubject(selector.Id), true
	case AclSelectorClient:
		return AclClientSubject(selector.Id, Id{}, nil, ""), true
	}
	return AclSubject{}, false
}

// The first route rule in force whose prefixes hold the whole of cidr, through any via.
func (self *AclState) findRouteToPrefix(subject AclSubject, cidr netip.Prefix, nowMs int64, localRules []*AclLocalRule) AclDecision {
	return self.resourceDecision(subject, nowMs, protocol.AclAction_ACL_ACTION_ROUTE, func(rule *aclRule) bool {
		local := localRules[rule.index]
		if local == nil || !cidr.IsValid() {
			return false
		}
		for _, held := range local.Cidrs {
			if held.Bits() <= cidr.Bits() && held.Contains(cidr.Addr()) {
				return true
			}
		}
		return false
	})
}

// ACL-M2-08's CheckRepoMember at the pin a push or delivery carries (§10.9, FS-104): every Add and wrap judged at its
// own pin. An off-chain pin alarms.
func (self *AclEngine) VerifyRepoMember(repoId Id, member AclRepoMember, pin *bridge.AuthPin, now time.Time) (AclDecision, error) {
	state, err := self.stateAt(pin)
	if err != nil {
		return aclDeny(AclReasonNoState), err
	}
	return state.CheckRepoMember(repoId, member, now), nil
}

// Owner decision 7: whether the sidecar may write the repo's heads at the pin the push carries, so a reader takes a
// head only from one of the repo's writers there. nil when it may.
func (self *AclEngine) VerifyHeadSigner(repoId Id, signerSidecarId Id, pin *bridge.AuthPin, now time.Time) error {
	state, err := self.stateAt(pin)
	if err != nil {
		return err
	}
	access := state.EvsAccess(AclSidecarSubject(signerSidecarId), repoId, AclTokenAudienceEvs, now)
	if !access.Rights.Has(AclEvsWrite) {
		return fmt.Errorf("%w: a head from no writer of the repo at %d (%s)", ErrConfigAuthority, pin.GetVersion(), access.Reason)
	}
	return nil
}

// The state at a pin from the log: the installed one at its own pin, else the log's, which waits above the tip,
// refuses what it does not retain, and alarms on a pin off its chain.
func (self *AclEngine) stateAt(pin *bridge.AuthPin) (*AclState, error) {
	if pin == nil {
		return nil, fmt.Errorf("%w: no pin", ErrConfigPinOffChain)
	}
	if installed := self.installed.Load(); installed != nil {
		installedPin := installed.state.Pin()
		if installedPin.GetVersion() == pin.GetVersion() && bytes.Equal(installedPin.GetChain(), pin.GetChain()) {
			return installed.state, nil
		}
	}
	if self.states == nil {
		return nil, fmt.Errorf("%w: no log to judge the pin at", ErrConfigPinNotRetained)
	}
	state, err := self.states.AclStateAt(pin)
	if errors.Is(err, ErrConfigPinOffChain) {
		self.alarm(AclEngineAlarm{Kind: AclEngineAlarmPinOffChain, Installed: self.Pin(), Offered: pin})
	}
	return state, err
}

// What AllowPrefixWrite asks of one write (DESIGN-DETAILS 16.2.7): the ref it writes, the push's flags where the
// caller knows them, and its paths.
type AclPrefixWrite struct {
	RepoId  Id
	RefKind protocol.EvsRefKind
	RefMode protocol.EvsRefMode
	// The ref's name, which tells ur/index and ur/lfs from the other shared refs.
	RefName []byte
	// The push's flags: one 16.2.4's line 1 leaves outside the rules asks nothing.
	Flags uint32
	// The paths, each its raw names joined by / (§11.6), drawn one at a time (QD-801): the engine stops drawing at the
	// first path it refuses, and draws none where a rule with no path names this sidecar. "" is the path of no
	// component, which asks whether this device is held: allowed where a rule names it for every path, where no set is
	// in force and where the ref is outside the rules, refused with no path to name where it is held. Nil asks about
	// no path.
	Paths iter.Seq[string]
	// The repo's sets this device holds for the installed state's rows (AclPrefixSets): a row with none is pending.
	Sets []*AclPrefixRuleSet
}

// AllowPrefixWrite's answer. AclDecision's Reason is AclReasonPrefixRule either way, or AclReasonNoState and
// AclReasonNoRepo where the engine cannot ask, and its At is the position of the set in force, 0 for none.
type AclPrefixWriteDecision struct {
	AclDecision
	// The line of 16.2.4 that decided.
	Line AclPrefixReason
	// A refusal's EVS_PREFIX_RULE detail: refused, pending or update. The caller adds its own, base or tag (QD-801).
	Detail AclPrefixDetail
	// The first path refused, the caller's own plaintext, which goes into no log (I-13); empty where there is none
	// to name.
	Path string
}

// nil for an allow, else EVS_PREFIX_RULE as an *AclPrefixRuleError, which carries the path and never names it.
func (self AclPrefixWriteDecision) Err() error {
	if self.Allowed {
		return nil
	}
	return &AclPrefixRuleError{Detail: self.Detail, Path: self.Path}
}

// The writer's half of DESIGN-DETAILS 16.2.7: lines 1 to 3 of PrefixVerdict with this sidecar as signer and the
// installed state's pin as the push's, then each path asked by its components in plaintext against the paths of the
// rules that name this sidecar. A device that cannot read the set in force does not write under it: a pending set is
// refused with detail pending and a newer one with update. Called by the planner for every path a file-mode write
// names and by publish for every file a git update changes, before the first round trip, so nothing is planned,
// sealed or sent for a refused path; a push sealed again on another state's pin asks again. A file-mode ref's
// .ur-index/ is outside the rules, as line 4 has it for readers.
func (self *AclEngine) AllowPrefixWrite(write *AclPrefixWrite) AclPrefixWriteDecision {
	refused := func(reason AclReason, line AclPrefixReason, detail AclPrefixDetail, at uint64, path string) AclPrefixWriteDecision {
		return AclPrefixWriteDecision{AclDecision: AclDecision{Reason: reason, At: at}, Line: line, Detail: detail, Path: path}
	}
	allowed := func(line AclPrefixReason, at uint64) AclPrefixWriteDecision {
		return AclPrefixWriteDecision{AclDecision: AclDecision{Allowed: true, Reason: AclReasonPrefixRule, At: at}, Line: line}
	}
	installed := self.installed.Load()
	if installed == nil || write == nil {
		return refused(AclReasonNoState, AclPrefixReasonPending, AclPrefixDetailPending, 0, "")
	}
	state := installed.state
	repo := state.Repo(write.RepoId)
	if repo == nil {
		return refused(AclReasonNoRepo, AclPrefixReasonScope, AclPrefixDetailRefused, 0, "")
	}
	if aclPrefixOutside(repo.GetKind(), write.RefKind, write.RefName, write.Flags) {
		return allowed(AclPrefixReasonScope, 0)
	}
	set, verdict, decided := aclPrefixSetInForce(repo.GetPrefixRules(), write.Sets, state.Pin().GetVersion())
	if decided {
		switch verdict.Outcome {
		case AclPrefixAllowed:
			return allowed(verdict.Reason, 0)
		case AclPrefixUpdate:
			return refused(AclReasonPrefixRule, verdict.Reason, AclPrefixDetailUpdate, verdict.SetAt, "")
		}
		return refused(AclReasonPrefixRule, verdict.Reason, AclPrefixDetailPending, verdict.SetAt, "")
	}
	var row *bridge.SidecarRow
	if sidecar := state.View().Sidecar(self.sidecarId); sidecar != nil {
		row = sidecar.Row
	}
	named := aclPrefixNamedRules(set, row)
	for _, rule := range named {
		if len(rule.GetPath()) == 0 {
			// named for every path: allowed before any path is drawn
			return allowed(AclPrefixReasonUnder, set.At)
		}
	}
	if write.Paths != nil {
		for path := range write.Paths {
			if path == "" {
				// the path of no component: this device is held
				return refused(AclReasonPrefixRule, AclPrefixReasonNotUnder, AclPrefixDetailRefused, set.At, "")
			}
			names := strings.Split(path, "/")
			if write.RefMode == protocol.EvsRefMode_EVS_REF_FILE && names[0] == aclPrefixIndexDirectory {
				continue
			}
			if !aclPrefixRulesCoverNames(named, names) {
				return refused(AclReasonPrefixRule, AclPrefixReasonNotUnder, AclPrefixDetailRefused, set.At, path)
			}
		}
	}
	return allowed(AclPrefixReasonUnder, set.At)
}
