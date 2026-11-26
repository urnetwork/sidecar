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
//	AllowRoute        a route rule reaching the via whose prefixes take the address and whose ports take the port, or
//	                  one that names no prefix whose destinations name the via too, for an address the via's subnet
//	                  routes in force serve (owner decision 575), which InstallRoutes hands in; it serves BRIDGE's
//	                  compiler and ur bridge's previews, never the device's hook (QD-590)
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
// A rule an activated grant gave has no local detail, its own fields being the GrantActivate's: a dial or route grant's
// prefixes and ports ride its sealed detail (owner decisions 220 and 679; QD-003, QD-740, QD-1164). InstallWithGrants
// opens each surviving activated route grant and port-limited dial grant once, under the config keys its opener holds,
// and reads it by the readers the save's ip: tests and the bridge compile read it by (acl_grant_route.go's
// aclReadGrantRoute and its dial counterpart, aclGrantDialPortsOf), so a preview, a dial and acl_check answer what the
// compile serves:
//
//	route    AllowRoute and Check's ip ranges: the detail's prefixes at its ports, none meaning every port, and a
//	         detail naming no prefix routing by its subjects
//	dial     AllowInbound: the ports the detail names at this sidecar, as the host's dial rows serve them
//	         (grantPortRule); a dial grant whose action seals none limits no ports, as its rows say
//	subject  Check's dial or route to a subject, which asks no port or address: a dial grant only to a sidecar its
//	         detail names a port at, and a route grant only through a via it reaches some address through by its
//	         detail, as a document rule is read by its local detail (dialReaches, routeReaches)
//	standing ActiveGrant (acl_grant_file.go): a forward's ask at the ports its own sealed detail names, covered at each
//	         sidecar by a port-limited dial grant whose detail names those ports there
//
// A grant whose detail does not read here, or a route grant whose action seals none, reaches nothing, the closed
// direction. One whose detail waited on a config key generation this device did not hold is read again when the
// keychain takes one (ReadWaitingGrants, which the acl follower calls on the keychain's signal), so it stands from then
// rather than from the next entry or base. In-daemon agents share their sidecar's grants (§5.5): the caller narrows,
// never widens. A client allows AclEngineSettings.ClockSkew against the gates' server time (§8.6).
//
// Safe for concurrent use. The root file carries no connect type; an install and ReadWaitingGrants open grants'
// details, where testHookSecret runs inside OpenConfigBody, and no check creates or unwraps a key but ActiveGrant, a
// gate's standing check on no packet path, which opens a forward's own sealed detail the same way.

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

// One installed state and what the checks read beside it, never changed once stored: ReadWaitingGrants stores another.
type aclEngineInstall struct {
	state *AclState
	local *AclLocalPolicy
	// by the state's rule index, the rule's local detail, nil for an activated grant
	localRules []*AclLocalRule
	// by the state's rule index, an activated route grant's detail as aclReadGrantRoute reads it, nil for every other
	// rule and for a grant whose detail gives nothing here
	grantRoutes []*AclLocalRule
	// by the state's rule index, a port-limited activated dial grant's reading, whose dial ports are empty where its
	// detail gives nothing here; nil for every other rule, a dial grant whose action seals no detail among them
	grantDials []*aclEngineGrantRead
	// the readings the next install may keep, by grant id: those no later opener can change (aclEngineGrantRead.kept)
	grantReads map[string]*aclEngineGrantRead
	// the opener the grants were read through, nil for none, which ReadWaitingGrants asks again
	grants AclGrantDetails
	// how many grants' details wait on a config key generation the opener did not hold
	keyWaitCount int
	self         AclSubject
}

// One activated grant as an install read it: its sealed detail opened once (aclOpenGrantDetail), then read as a route
// and as dial ports by the readers every leg shares, so a grant allowing both is opened once. Never changed once read,
// since later installs share it.
type aclEngineGrantRead struct {
	// why the detail gives nothing here, aclGrantRouteUnreadNone where it opened
	opened aclGrantRouteUnread
	route  aclGrantRoute
	dial   aclGrantDialPorts
}

// Reads one activated grant: grantId its rule's id, portsLimited its rule's ports_limited, grants the opener, nil
// opening none.
func aclEngineReadGrant(grantId []byte, portsLimited bool, grants AclGrantDetails) *aclEngineGrantRead {
	detail, opened := aclOpenGrantDetail(grantId, portsLimited, grants)
	read := &aclEngineGrantRead{opened: opened, route: aclGrantRoute{unread: opened}}
	if detail != nil {
		read.route.local, read.route.unread = aclGrantRouteOfDetail(detail)
		read.dial = aclGrantDialPortsOf(detail)
	}
	return read
}

// Whether a grant's reading stands for every later install of a state holding the grant: its detail opened, or its
// action seals none. A grant id fixes its action's bytes (§8.8's grant_id), so neither changes; every other reading
// is read again, since a later opener may hold the action or the key it lacked.
func (self *aclEngineGrantRead) kept() bool {
	return self.opened == aclGrantRouteUnreadNone || self.opened == aclGrantRouteUnreadUnsealed
}

// Reads each activated route grant and port-limited dial grant of the state through grants, keeping what previous read
// where it stands.
func (self *aclEngineInstall) readGrants(previous *aclEngineInstall, grants AclGrantDetails) {
	rules := self.state.rules
	self.grants = grants
	self.grantRoutes = make([]*AclLocalRule, len(rules))
	self.grantDials = make([]*aclEngineGrantRead, len(rules))
	self.grantReads = map[string]*aclEngineGrantRead{}
	self.keyWaitCount = 0
	for i := range rules {
		rule := &rules[i]
		routes := rule.allows(protocol.AclAction_ACL_ACTION_ROUTE)
		dials := rule.allows(protocol.AclAction_ACL_ACTION_DIAL) && rule.portsLimited
		if len(rule.row.GetSourceRuleId()) == 0 || !(routes || dials) {
			continue
		}
		grantId := rule.row.GetRuleId()
		read, found := self.grantReads[string(grantId)]
		if !found && previous != nil {
			read, found = previous.grantReads[string(grantId)]
		}
		// a kept reading is the rule's own: a read detail beside ports_limited, an unsealed action beside none
		if !found || (read.opened == aclGrantRouteUnreadUnsealed) == rule.portsLimited {
			read = aclEngineReadGrant(grantId, rule.portsLimited, grants)
		}
		if read.kept() {
			self.grantReads[string(grantId)] = read
		}
		if read.opened == aclGrantRouteUnreadGeneration {
			self.keyWaitCount += 1
		}
		if routes {
			self.grantRoutes[i] = read.route.local
		}
		if dials {
			self.grantDials[i] = read
		}
	}
}

// A route rule's prefixes and ports as the route checks read them, whether it limits ports, and whether it reaches
// anything here: a rule of the head's local detail and its ports_limited; an activated grant's sealed detail as
// aclReadGrantRoute reads it, limiting ports only where the detail names some, none meaning every port, and nothing
// for a grant whose detail gives none here (QD-003).
func (self *aclEngineInstall) routeLocal(rule *aclRule) (*AclLocalRule, bool, bool) {
	if len(rule.row.GetSourceRuleId()) == 0 {
		return self.localRules[rule.index], rule.portsLimited, true
	}
	local := self.grantRoutes[rule.index]
	if local == nil {
		return nil, false, false
	}
	return local, 0 < len(local.Ports), true
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
	// the subnet routes in force the bridge compile last answered, nil before the first InstallRoutes
	servedRoutes atomic.Pointer[AclServedRoutes]
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
// opening no port. It opens no activated grant's detail, so an activated route grant or port-limited dial grant
// reaches nothing here unless an earlier install read it: InstallWithGrants with no opener.
func (self *AclEngine) Install(state *AclState, local *AclLocalPolicy) error {
	return self.InstallWithGrants(state, local, nil)
}

// Install, with the opener of the state's activated grants' sealed details, over the ConfigState whose acl part state
// is (newAclStateGrantDetails): each activated route grant and port-limited dial grant is read here, its detail opened
// once for both, never at a check, by the readers the save's tests and the bridge compile read it by
// (aclReadGrantRoute and its dial counterpart), and AllowRoute, AllowInbound and Check count it by its detail. A
// reading that stands is kept for the next install of a state holding the same grant, so an install opens only the
// grants it has not read; one whose action or key was missing is read again, and one whose key generation was missing
// also at ReadWaitingGrants. grants nil opens none.
func (self *AclEngine) InstallWithGrants(state *AclState, local *AclLocalPolicy, grants AclGrantDetails) error {
	if state == nil || state.Pin() == nil {
		return fmt.Errorf("%w: no state", ErrAclRowsInvalid)
	}
	next := &aclEngineInstall{state: state, local: local, self: AclSidecarSubject(self.sidecarId)}
	next.localRules = make([]*AclLocalRule, len(state.rules))
	for i := range state.rules {
		next.localRules[i] = local.Rule(state.rules[i].row.GetRuleId())
	}
	// before the lock, which is never held across the opener's key reads
	next.readGrants(self.installed.Load(), grants)
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

// Reads again, through the opener the installed state was installed with, each activated grant whose sealed detail did
// not read there, and swaps the state in again with what now reads, its pin, local policy and every reading that stood
// unchanged: what the acl follower calls when the keychain takes a generation of the config repo, since a detail sealed
// to a generation this device did not hold opens once the key is held, and the grant then stands at once rather than at
// the next install. Nothing is read where no grant waits on a key. An install landing meanwhile is read again in its
// turn, since it may have read its grants before the key was held, so this goes round again only past a concurrent
// install. Answers whether a grant's detail still waits on a key generation. Never on a check's path.
func (self *AclEngine) ReadWaitingGrants() bool {
	for {
		current := self.installed.Load()
		if current == nil || current.grants == nil || current.keyWaitCount == 0 {
			return false
		}
		next := &aclEngineInstall{state: current.state, local: current.local, localRules: current.localRules, self: current.self}
		// outside the lock, which is never held across the opener's key reads
		next.readGrants(current, current.grants)
		testHookBarrier("acl_engine.read_waiting.before", self.sidecarId.String())
		swapped := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.installed.Load() != current {
				return false
			}
			self.installed.Store(next)
			return true
		}()
		testHookBarrier("acl_engine.read_waiting.after", self.sidecarId.String())
		if swapped {
			return 0 < next.keyWaitCount
		}
	}
}

// Whether the installed state holds an activated grant whose sealed detail waits on a config key generation its opener
// did not hold, which ReadWaitingGrants reads again.
func (self *AclEngine) grantsWaitForKey() bool {
	installed := self.installed.Load()
	return installed != nil && installed.grants != nil && 0 < installed.keyWaitCount
}

// Swaps in the subnet routes in force by advertiser, which AllowRoute and Check's ip ranges read for a route rule that
// names no prefix (owner decision 575): BRIDGE's compile answers them at the state it compiled (BridgeCompiled.
// ServedRoutes), which the component hands on once the device role holds that state, so they are as new as the rows
// the device's hook enforces. Before the first call, and after a nil one, such a rule routes to nothing here, the
// closed direction. No signed statement, so no pin is checked: the routes only narrow which addresses a rule the
// installed state already holds takes.
func (self *AclEngine) InstallRoutes(servedRoutes *AclServedRoutes) {
	testHookBarrier("acl_engine.install_routes.before", self.sidecarId.String())
	self.servedRoutes.Store(servedRoutes)
	testHookBarrier("acl_engine.install_routes.after", self.sidecarId.String())
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
func aclLocalPortsMatch(portsLimited bool, local *AclLocalRule, ipProtocol uint32, port uint32) bool {
	if !portsLimited {
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
// the port, a document rule's from its local detail and a port-limited activated grant's from its sealed detail, the
// ports it names at this sidecar (aclGrantDialPorts, as the host's dial rows serve them); to one of its sockets, a dial
// grant on the socket whose exact name or glob, from the same config head takes the name. A token prefix alone cannot
// verify a private name.
func (self *AclEngine) AllowInbound(inbound *AclInbound, now time.Time) AclDecision {
	installed := self.installed.Load()
	if installed == nil || inbound == nil {
		return aclDeny(AclReasonNoState)
	}
	nowMs := self.checkMs(now)
	state := installed.state
	if inbound.SocketName != "" {
		return state.resourceDecision(inbound.Source, nowMs, protocol.AclAction_ACL_ACTION_DIAL, func(rule *aclRule) bool {
			local := installed.localRules[rule.index]
			for i := range rule.sockets {
				target := &rule.sockets[i]
				if target.covers(inbound.NameToken) && (!target.prefix || local != nil) && aclLocalSocketMatch(local, inbound.SocketName) {
					return true
				}
			}
			return false
		})
	}
	return state.mayDial(inbound.Source, installed.self, nowMs, func(rule *aclRule) bool {
		if read := installed.grantDials[rule.index]; read != nil {
			return read.dial.takes(self.sidecarId, inbound.IpProtocol, inbound.Port)
		}
		return aclLocalPortsMatch(rule.portsLimited, installed.localRules[rule.index], inbound.IpProtocol, inbound.Port)
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

// Whether the source may route to the address on the port via a subject: a route rule whose via subjects hold the via,
// its AclRule.via or, where it names none, the advertisers whose approved routes name it (QD-764), whose ports take the
// port and which takes the address: a public one by its autogroup:internet, through those vias alone, and any by a
// prefix of the device's that holds it. A rule that names no ip: destination and no autogroup:internet takes an address
// only where its subject destinations name the via for the source too and a subnet route in force of the via's serves
// the address (§8.4's readings; owner decision 575), by the routes InstallRoutes last took and by none before it. A
// document rule whose detail the device does not hold takes only a public address by its autogroup:internet, which
// rows carry. An activated route grant is judged by its sealed detail as the compile serves it (routeLocal): its
// prefixes, at its ports, none meaning every port, one naming no prefix by its subjects as above; one whose detail
// does not read here, or whose action seals none, takes nothing (QD-003), the closed direction.
func (self *AclEngine) AllowRoute(source AclSubject, address netip.Addr, ipProtocol uint32, port uint32, via AclSubject, now time.Time) AclDecision {
	installed := self.installed.Load()
	if installed == nil {
		return aclDeny(AclReasonNoState)
	}
	state := installed.state
	nowMs := self.checkMs(now)
	sourceResolved := state.resolve(&source, nowMs)
	if sourceResolved.deny != 0 {
		return aclDeny(sourceResolved.deny)
	}
	viaResolved := state.resolve(&via, nowMs)
	if viaResolved.deny != 0 {
		return aclDeny(viaResolved.deny)
	}
	servedRoutes := self.servedRoutes.Load()
	address = address.Unmap()
	public := aclAddressPublic(address)
	rule := state.findResourceRule(&sourceResolved, nowMs, protocol.AclAction_ACL_ACTION_ROUTE, func(rule *aclRule) bool {
		local, portsLimited, reaches := installed.routeLocal(rule)
		if !reaches || !aclLocalPortsMatch(portsLimited, local, ipProtocol, port) || !state.routeTakes(&sourceResolved, &viaResolved, rule) {
			return false
		}
		if rule.internetTarget && public {
			return true
		}
		if local == nil {
			return false
		}
		if aclRouteBySubject(local, rule.internetTarget) {
			// no prefix of its own: the subnet routes in force of a via its destinations name
			return viaResolved.sidecar != nil && state.targetsSubject(&sourceResolved, &viaResolved, rule) &&
				servedRoutes.serves(viaResolved.sidecar.id, address)
		}
		for _, cidr := range local.Cidrs {
			if aclCidrCovers(cidr, address) {
				return true
			}
		}
		return false
	})
	if rule != nil {
		return aclAllowRule(rule)
	}
	return aclDeny(AclReasonNoGrant)
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
// alias sent to or listened on; an ip range routed to through any via, by a rule's prefixes or, for a rule that names
// none, by the subnet routes in force InstallRoutes last took (findRouteToPrefix), an activated route grant's being
// its sealed detail's, as InstallWithGrants read it. A dial or route to a subject asks no port or address, so it
// counts a rule that reaches the subject at some port, or some address through it, read as AllowInbound and AllowRoute
// read a rule at one, for a document rule and an activated grant alike (dialReaches, routeReaches): a rule limiting
// ports only where this device holds them, a document rule's from its local detail and an activated grant's from its
// sealed detail, and a route rule only by the prefixes, autogroup:internet or routes in force those checks take; so
// acl_check answers what the engine and the compile serve, not the rows alone.
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
			return answer(state.mayDial(subject, destination, nowMs, func(rule *aclRule) bool {
				return installed.dialReaches(rule, destination)
			}))
		}
		if action == protocol.AclAction_ACL_ACTION_ROUTE {
			return answer(installed.routeThrough(subject, destination, nowMs, self.servedRoutes.Load()))
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
			return answer(state.findRouteToPrefix(subject, resource.Cidr, nowMs, installed, self.servedRoutes.Load()))
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

// Whether a dial rule reaches the destination at some port here, as AllowInbound and the host's dial rows read the rule
// at a port (§8.6's ports match; DESIGN-DETAILS 12.2.4's rows): a rule limiting no ports at every port of each
// destination its rows name; a port-limited activated dial grant only at a sidecar its sealed detail names a port at
// (aclGrantDialPorts, as InstallWithGrants read it); and a port-limited document rule only at a sidecar, and only where
// this device holds its ports, its local detail. A client's ports are its own device's to check, and this reader cannot
// tell an enforcing client from a legacy one, which §8.10 reaches only through a rule limiting no ports, so a
// port-limited rule reaches no client here, the closed direction (question
// acl-grant-port-consistency-check-client-ports). Allocates nothing.
func (self *aclEngineInstall) dialReaches(rule *aclRule, destination AclSubject) bool {
	if !rule.portsLimited {
		return true
	}
	if destination.Kind != AclSubjectSidecar {
		return false
	}
	if read := self.grantDials[rule.index]; read != nil {
		return read.dial.reaches(destination.Id)
	}
	local := self.localRules[rule.index]
	return local != nil && 0 < len(local.Ports)
}

// Check's route to a subject: the first route rule in force from the source whose via subjects hold the via
// (routeTakes, as MayRoute reads it) and that reaches some address through it (routeReaches), or why none does.
func (self *aclEngineInstall) routeThrough(source AclSubject, via AclSubject, nowMs int64, servedRoutes *AclServedRoutes) AclDecision {
	state := self.state
	sourceResolved := state.resolve(&source, nowMs)
	if sourceResolved.deny != 0 {
		return aclDeny(sourceResolved.deny)
	}
	viaResolved := state.resolve(&via, nowMs)
	if viaResolved.deny != 0 {
		return aclDeny(viaResolved.deny)
	}
	rule := state.findResourceRule(&sourceResolved, nowMs, protocol.AclAction_ACL_ACTION_ROUTE, func(rule *aclRule) bool {
		return state.routeTakes(&sourceResolved, &viaResolved, rule) && self.routeReaches(&sourceResolved, &viaResolved, rule, servedRoutes)
	})
	if rule != nil {
		return aclAllowRule(rule)
	}
	return aclDeny(AclReasonNoGrant)
}

// Whether a route rule that takes the via reaches some address through it, as AllowRoute reads the rule at one address
// and port, here at any (routeLocal for its prefixes and ports, a document rule's local detail and an activated grant's
// sealed one alike): its ports must open some port, a rule limiting ports only where this device holds them; then its
// autogroup:internet reaches the public addresses, which rows carry; past that the device must hold its detail, whose
// prefixes it reaches, or, where the detail names none, the subnet routes in force of a via its subject destinations
// also name for the source (owner decision 575), by the routes InstallRoutes last took and by none before. A rule whose
// detail the device does not hold reaches only by its autogroup:internet, and an activated grant whose detail does not
// read here, or whose action seals none, reaches nothing (QD-003).
func (self *aclEngineInstall) routeReaches(source *aclResolved, via *aclResolved, rule *aclRule, servedRoutes *AclServedRoutes) bool {
	local, portsLimited, reaches := self.routeLocal(rule)
	if !reaches || (portsLimited && (local == nil || len(local.Ports) == 0)) {
		return false
	}
	if rule.internetTarget {
		return true
	}
	if local == nil {
		return false
	}
	if aclRouteBySubject(local, rule.internetTarget) {
		// no prefix of its own: the subnet routes in force of a via its destinations name
		return via.sidecar != nil && self.state.targetsSubject(source, via, rule) && 0 < len(servedRoutes.Prefixes(via.sidecar.id))
	}
	return true
}

// The first route rule in force that reaches the whole of cidr through some via: one whose prefixes hold it, or one that
// names no ip: destination and no autogroup:internet through an advertiser its via subjects hold for the subject that is
// also among its subject destinations for it, one of whose subnet routes in force holds the whole of cidr (§8.4's
// readings; owner decision 575), by servedRoutes, so by none while it is nil. A rule's prefixes are installed's
// (routeLocal): a document rule's local detail, so one the device does not hold reaches no range, and an activated
// route grant's sealed detail, so one whose detail does not read here reaches none (QD-003). A hard-denied advertiser
// is no via.
func (self *AclState) findRouteToPrefix(subject AclSubject, cidr netip.Prefix, nowMs int64, installed *aclEngineInstall,
	servedRoutes *AclServedRoutes) AclDecision {
	resolved := self.resolve(&subject, nowMs)
	if resolved.deny != 0 {
		return aclDeny(resolved.deny)
	}
	// the advertisers that serve the whole of cidr, as vias at nowMs; each subject stays where its resolution points
	advertisers := servedRoutes.advertisersHolding(cidr)
	viaSubjects := make([]AclSubject, len(advertisers))
	vias := []aclResolved{}
	for i, advertiser := range advertisers {
		viaSubjects[i] = AclSidecarSubject(advertiser)
		if via := self.resolve(&viaSubjects[i], nowMs); via.deny == 0 && via.sidecar != nil {
			vias = append(vias, via)
		}
	}
	rule := self.findResourceRule(&resolved, nowMs, protocol.AclAction_ACL_ACTION_ROUTE, func(rule *aclRule) bool {
		local, _, reaches := installed.routeLocal(rule)
		if !reaches || local == nil || !cidr.IsValid() {
			return false
		}
		if aclRouteBySubject(local, rule.internetTarget) {
			// no prefix of its own: the subnet routes in force of a via its destinations name
			for i := range vias {
				if self.routeTakes(&resolved, &vias[i], rule) && self.targetsSubject(&resolved, &vias[i], rule) {
					return true
				}
			}
			return false
		}
		for _, held := range local.Cidrs {
			if held.Bits() <= cidr.Bits() && held.Contains(cidr.Addr()) {
				return true
			}
		}
		return false
	})
	if rule != nil {
		return aclAllowRule(rule)
	}
	return aclDeny(AclReasonNoGrant)
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
