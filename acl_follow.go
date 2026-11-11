//go:build !ios_extension

// AclFollower (ACL-M2-15): every admitted sidecar follows its config repo and §7's team hints and evaluates its own
// rules, with no always-on compiler (owner decision 6). TEAM-M2-10's ConfigClient is the one follower of the log, so
// this is no second one: on each AddEntryCallback it takes the newest verified state from ConfigClient.State, installs
// its acl part in the sidecar's AclEngine, and acks the position through POST /acl/ack.
//
//	install  the state's AclState and the AclLocalPolicy of the config head its base names; a newer head's local
//	         policy is read and compiled off the callback, and until it lands the rows install beside the last one
//	         compiled, whose detail holds only for rule ids still present, since a rule that changes meaning takes a
//	         new id (plan-ACL-atom-and-rule-ids #3), so a new port-limited rule opens no port meanwhile
//	refuse   §7.9's BASE row owns the rows-hash check: a base whose rows do not compile from its head forks the client,
//	         which raises head_alarm and applies nothing, so nothing reaches here; a state whose acl part does not
//	         build raises refused, and a second A_n at the installed n head_alarm fork, each installing nothing and
//	         keeping the engine's state
//	ack      at most one POST /acl/ack each AckInterval, carrying the newest installed n and its entry's time_ms; the
//	         first install after a quiet interval acks at once, and a failed ack is dropped, never retried, since the
//	         next state carries a newer n
//
// It also serves ur://acl/grants's data (MCP's resource, §16.5): AclGrants, the installed state's rules, members and
// admissions as ids, and GrantsChanged, which moves at each install. Key changes are MLS's SidecarEvents, which the
// resource merges itself.
//
// Applied-time targets are p50 1 s and p99 5 s from the entry (§8.9): the install adds nothing to the client's
// apply, and the ack at most AckInterval. Safe for concurrent use. The root file builds on the sidecar_http page
// Worker's leg too; ios_extension links no AclEngine, its forwarding role compiling in device/.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What AclFollower reads of the log's one follower: TEAM-M2-10's ConfigClient.
type AclFollowerSource interface {
	// The newest verified S(n), nil before the first read.
	State() *ConfigState
	// Calls callback after each applied entry, in log order, on the follower's goroutine; the answer removes it.
	AddEntryCallback(callback SidecarAuthorityEntryFunction) func()
}

// Where acks go: SidecarApi.PostAclAck, or a test's fake. recorded is api's answer, which nothing here acts on.
type AclAckSender interface {
	PostAclAck(ctx context.Context, version uint64, timeMs int64) (recorded bool, err error)
}

// What an AclFollower runs on.
type AclFollowerArgs struct {
	Source AclFollowerSource
	Engine *AclEngine
	// Nil acks nothing.
	Acks AclAckSender
	// Reads the config head a base names, for its AclLocalPolicy. Nil installs none, so every port-limited rule opens
	// no port, the closed direction.
	Heads ConfigHeadReader
	// Raises refused and head_alarm. Nil drops them.
	Emit     SidecarEventFunction
	Settings *AclSettings
}

// What a follower has done since it started.
type AclFollowerStats struct {
	// States installed in the engine.
	InstallCount uint64
	// States refused: an acl part that does not build, or a fork at the installed n. Each raised an event.
	RefusalCount uint64
	// Acks sent, and those that failed and were dropped.
	AckCount        uint64
	AckFailureCount uint64
}

// One position an ack carries.
type aclAckPosition struct {
	version uint64
	timeMs  int64
}

// A config head's local policy, compiled once per head.
type aclFollowerLocal struct {
	headSha256 [sha256.Size]byte
	local      *AclLocalPolicy
}

// One sidecar's acl follower in one network.
type AclFollower struct {
	args     *AclFollowerArgs
	settings *AclSettings
	clock    Clock
	log      Logger

	ctx    context.Context
	cancel context.CancelFunc
	remove func()

	// serializes installs from the client's callback and the head reader, never held across I/O
	applyLock sync.Mutex
	// the newest head's local policy, and the head the reader should read next
	local      atomic.Pointer[aclFollowerLocal]
	wantedHead *MonitorValue[[sha256.Size]byte]

	// the newest installed position, which the ack loop sends and GrantsChanged reports
	installed *MonitorValue[aclAckPosition]
	grants    atomic.Pointer[AclGrants]

	installCount    atomic.Uint64
	refusalCount    atomic.Uint64
	ackCount        atomic.Uint64
	ackFailureCount atomic.Uint64
}

// A follower on args, subscribed to its source and installing at once what the source already holds; its ack loop
// and head reader run until ctx ends or Close.
func NewAclFollower(ctx context.Context, args *AclFollowerArgs) (*AclFollower, error) {
	if args == nil || args.Source == nil || args.Engine == nil {
		return nil, errors.New("acl follower: missing args")
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultAclSettings()
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &AclFollower{
		args:       args,
		settings:   settings,
		clock:      clockOrReal(settings.Clock),
		log:        loggerOrDefault(settings.Log),
		ctx:        cancelCtx,
		cancel:     cancel,
		wantedHead: NewMonitorValue([sha256.Size]byte{}),
		installed:  NewMonitorValue(aclAckPosition{}),
	}
	self.remove = args.Source.AddEntryCallback(func(entry *SidecarAuthorityEntry) {
		self.apply()
	})
	self.apply()
	go self.run()
	if args.Heads != nil {
		go self.readHeads()
	}
	return self, nil
}

// Stops following. Safe to call again.
func (self *AclFollower) Close() {
	self.cancel()
	if self.remove != nil {
		self.remove()
	}
}

// What the follower has counted.
func (self *AclFollower) Stats() AclFollowerStats {
	return AclFollowerStats{
		InstallCount:    self.installCount.Load(),
		RefusalCount:    self.refusalCount.Load(),
		AckCount:        self.ackCount.Load(),
		AckFailureCount: self.ackFailureCount.Load(),
	}
}

// Installs the source's newest state, once per position: its acl part beside the newest compiled local policy, then
// asks for its head's policy when that is another, and marks the position for the ack loop.
func (self *AclFollower) apply() {
	state := self.args.Source.State()
	if state == nil || state.Pin() == nil {
		return
	}
	if base := state.Base(); base != nil && self.args.Heads != nil && len(base.GetConfigHeadSha256()) == sha256.Size {
		self.wantedHead.Set([sha256.Size]byte(base.GetConfigHeadSha256()))
	}
	installed := func() bool {
		self.applyLock.Lock()
		defer self.applyLock.Unlock()
		return self.installWithLock(state)
	}()
	if installed {
		self.installed.Set(aclAckPosition{version: state.Pin().GetVersion(), timeMs: state.TimeMs()})
	}
}

// One state's install, refusing what the file header says. Whether the engine now holds it.
func (self *AclFollower) installWithLock(state *ConfigState) bool {
	pin := state.Pin()
	local := self.newestLocal()
	if current := self.args.Engine.State(); current != nil {
		installedPin := current.Pin()
		sameLocal := local == nil || self.installedLocal() == local
		switch {
		case pin.GetVersion() < installedPin.GetVersion():
			// a read older than what is installed: the source never goes back, so this is a stale read, never a fork
			return false
		case pin.GetVersion() == installedPin.GetVersion() && bytes.Equal(pin.GetChain(), installedPin.GetChain()) && sameLocal:
			return true
		}
	}
	acl, err := state.Acl()
	if err != nil {
		self.refusalCount.Add(1)
		self.log.Errorf("[acl]%s the state at %d does not build, the engine keeps its own: %v", state.NetworkId(), pin.GetVersion(), err)
		self.emit(SidecarEvent{Kind: SidecarEventRefused})
		return false
	}
	if err := self.args.Engine.Install(acl, local); err != nil {
		self.refusalCount.Add(1)
		self.log.Errorf("[acl]%s the engine refused the state at %d: %v", state.NetworkId(), pin.GetVersion(), err)
		if errors.Is(err, ErrAclEngineFork) {
			self.emit(SidecarEvent{Kind: SidecarEventHeadAlarm, HeadAlarm: SidecarHeadAlarmFork,
				Evidence: [2][]byte{configPinBytes(self.args.Engine.Pin()), configPinBytes(pin)}})
		} else {
			self.emit(SidecarEvent{Kind: SidecarEventRefused})
		}
		return false
	}
	self.installCount.Add(1)
	self.grants.Store(newAclGrants(acl))
	return true
}

// The local policy installed with the engine's state, nil for none.
func (self *AclFollower) installedLocal() *AclLocalPolicy {
	if installed := self.args.Engine.installed.Load(); installed != nil {
		return installed.local
	}
	return nil
}

// The newest compiled local policy: the newest base's head's once read, else the last one compiled, nil before any.
func (self *AclFollower) newestLocal() *AclLocalPolicy {
	if local := self.local.Load(); local != nil {
		return local.local
	}
	return nil
}

// Raises an event, when the host takes them.
func (self *AclFollower) emit(event SidecarEvent) {
	if self.args.Emit != nil {
		self.args.Emit(event)
	}
}

// The ack loop: the newest installed position at once, then at most one more each AckInterval, a coalescing emitter
// (connect/CODESTYLE.md): it waits for a change, sends the newest, waits the interval, and only then reads again.
func (self *AclFollower) run() {
	sent := uint64(0)
	for {
		position, changed := self.installed.Get()
		if sent < position.version {
			sent = position.version
			self.ack(position)
			if 0 < self.settings.AckInterval {
				select {
				case <-self.ctx.Done():
					return
				case <-self.clock.After(self.settings.AckInterval):
				}
			}
			continue
		}
		select {
		case <-self.ctx.Done():
			return
		case <-changed:
		}
	}
}

// One ack, dropped on failure.
func (self *AclFollower) ack(position aclAckPosition) {
	if self.args.Acks == nil {
		return
	}
	ctx := self.ctx
	if 0 < self.settings.AckTimeout {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(self.ctx, self.settings.AckTimeout)
		defer cancel()
	}
	if _, err := self.args.Acks.PostAclAck(ctx, position.version, position.timeMs); err != nil {
		self.ackFailureCount.Add(1)
		if self.log.V(1).Enabled() {
			self.log.Infof("[acl]an ack of %d dropped: %v", position.version, err)
		}
		return
	}
	self.ackCount.Add(1)
}

// The head reader: reads each newly wanted config head, compiles its local policy, and installs the source's newest
// state with it. A head that does not read or compile is asked again at the next base.
func (self *AclFollower) readHeads() {
	read := [sha256.Size]byte{}
	for {
		wanted, changed := self.wantedHead.Get()
		if wanted != read && wanted != ([sha256.Size]byte{}) {
			read = wanted
			if local, err := self.compileLocal(wanted); err != nil {
				self.log.Warningf("[acl]a config head's local policy did not compile, ports stay closed for its new rules: %v", err)
			} else {
				self.local.Store(&aclFollowerLocal{headSha256: wanted, local: local})
				self.apply()
			}
			continue
		}
		select {
		case <-self.ctx.Done():
			return
		case <-changed:
		}
	}
}

// The local policy of the config head the source's newest base names, when that base still names headSha256.
func (self *AclFollower) compileLocal(headSha256 [sha256.Size]byte) (*AclLocalPolicy, error) {
	state := self.args.Source.State()
	if state == nil || state.Base() == nil || !bytes.Equal(state.Base().GetConfigHeadSha256(), headSha256[:]) {
		return nil, errors.New("the base moved on before its head was read")
	}
	ctx := self.ctx
	if 0 < self.settings.AckTimeout {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(self.ctx, self.settings.AckTimeout)
		defer cancel()
	}
	head, err := self.args.Heads.ReadConfigHead(ctx, state.Base().GetConfigVersion(), headSha256[:])
	if err != nil {
		return nil, err
	}
	input, err := NewAclCompileInput(head, ConfigCompileRowsOf(state))
	if err != nil {
		return nil, err
	}
	return CompileAclLocal(input)
}

// ur://acl/grants's data: the installed state as ids, nil before the first install. The caller must not change it.
func (self *AclFollower) Grants() *AclGrants {
	return self.grants.Load()
}

// The newest installed position and a channel that closes at the next install: what the resource's
// resources/updated waits on. Read Grants after it fires.
func (self *AclFollower) GrantsChanged() (uint64, chan struct{}) {
	position, changed := self.installed.Get()
	return position.version, changed
}

// One state's rules, members and admissions as ur://acl/grants carries them: ids, actions and expiries, never a
// name, a socket name or a key (§16.6's views).
type AclGrants struct {
	Pin         *bridge.AuthPin
	HasDocument bool
	Rules       []AclGrantsRule
	Requests    []AclGrantsRequest
	Members     []AclGrantsMember
	Sidecars    []AclGrantsSidecar
}

// One rule: a document's, the implicit document's, a kind default's, or an activated grant.
type AclGrantsRule struct {
	RuleId []byte
	// An activated grant's requests rule; nil for a standing rule.
	SourceRuleId []byte
	SrcAtoms     [][]byte
	Actions      []protocol.AclAction
	// Each target as its kind and id: atom, sidecar, client, network, repo or the wildcard repo, socket, public, mail.
	Targets []string
	// ms since the epoch; 0 none.
	ExpiresMs int64
}

// One requests rule.
type AclGrantsRequest struct {
	RuleId        []byte
	SrcAtoms      [][]byte
	ApproverAtoms [][]byte
	Approvers     uint32
	Actions       []protocol.AclAction
	Targets       []string
}

// One member.
type AclGrantsMember struct {
	MemberId Id
	Role     bridge.MemberRole
}

// One admission.
type AclGrantsSidecar struct {
	SidecarId Id
	// Zero for a tagged sidecar.
	MemberId  Id
	TagIds    []Id
	Class     AclSubjectClass
	Revoked   bool
	Suspended bool
	ReadOnly  bool
}

// A target as its kind and id, the text ur://acl/grants carries.
func aclGrantsTarget(target *protocol.AclTarget) string {
	idText := func(kind string, idBytes []byte) string {
		if id, err := IdFromBytes(idBytes); err == nil {
			return kind + ":" + id.String()
		}
		return kind
	}
	switch {
	case len(target.GetAtom()) != 0:
		return idText("atom", target.GetAtom())
	case len(target.GetSidecarId()) != 0:
		return idText("sidecar", target.GetSidecarId())
	case len(target.GetClientId()) != 0:
		return idText("client", target.GetClientId())
	case len(target.GetNetworkId()) != 0:
		return idText("network", target.GetNetworkId())
	case len(target.GetRepoId()) != 0:
		if bytes.Equal(target.GetRepoId(), make([]byte, len(Id{}))) {
			return "repo:*"
		}
		return idText("repo", target.GetRepoId())
	case len(target.GetSocketTokens()) != 0 || target.GetSocketPrefix():
		return "socket"
	case target.GetPublicName() != "":
		return "public:" + target.GetPublicName()
	case target.GetMailSend():
		return "mail"
	}
	return "unknown"
}

// Actions as values.
func aclGrantsActions(values []uint32) []protocol.AclAction {
	actions := make([]protocol.AclAction, 0, len(values))
	for _, value := range values {
		actions = append(actions, protocol.AclAction(value))
	}
	return actions
}

// The grants view of an installed state.
func newAclGrants(state *AclState) *AclGrants {
	rows := state.Rows()
	grants := &AclGrants{Pin: state.Pin(), HasDocument: rows.GetHasDocument()}
	for _, rule := range rows.GetRules() {
		entry := AclGrantsRule{
			RuleId: bytes.Clone(rule.GetRuleId()), SourceRuleId: bytes.Clone(rule.GetSourceRuleId()),
			SrcAtoms: slices.Clone(rule.GetSrcAtoms()), Actions: aclGrantsActions(rule.GetActions()), ExpiresMs: rule.GetExpires(),
		}
		for _, target := range rule.GetTargets() {
			entry.Targets = append(entry.Targets, aclGrantsTarget(target))
		}
		grants.Rules = append(grants.Rules, entry)
	}
	for _, request := range rows.GetRequests() {
		entry := AclGrantsRequest{
			RuleId: bytes.Clone(request.GetRuleId()), SrcAtoms: slices.Clone(request.GetSrcAtoms()),
			ApproverAtoms: slices.Clone(request.GetApproverAtoms()), Approvers: request.GetApprovers(), Actions: aclGrantsActions(request.GetActions()),
		}
		for _, target := range request.GetTargets() {
			entry.Targets = append(entry.Targets, aclGrantsTarget(target))
		}
		grants.Requests = append(grants.Requests, entry)
	}
	memberIds := []Id{}
	for i := range state.sidecars {
		sidecar := &state.sidecars[i]
		grants.Sidecars = append(grants.Sidecars, AclGrantsSidecar{
			SidecarId: sidecar.id, MemberId: sidecar.memberId, TagIds: slices.Clone(sidecar.facts.TagIds), Class: sidecar.class,
			Revoked: sidecar.revoked, Suspended: sidecar.suspended, ReadOnly: sidecar.readOnly,
		})
		if sidecar.memberId != (Id{}) {
			memberIds = append(memberIds, sidecar.memberId)
		}
	}
	slices.SortFunc(memberIds, Id.Cmp)
	for _, memberId := range slices.Compact(memberIds) {
		if member := state.view.Member(memberId); member != nil {
			grants.Members = append(grants.Members, AclGrantsMember{MemberId: memberId, Role: member.GetRole()})
		}
	}
	return grants
}

// POST /acl/ack (§8.9, C11): the projection version this client applied, its entry's time_ms beside it, so api
// measures propagation. Client class on §7.4's strict_exp allowlist, the bearer's own client. Answers whether api
// recorded it.
func (self *SidecarApi) PostAclAck(ctx context.Context, version uint64, timeMs int64) (bool, error) {
	route := "POST /acl/ack"
	if version == 0 || timeMs < 0 {
		return false, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiArgs)
	}
	reply := &sidecarAclAckReply{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     route,
		operation: "acl_ack",
		method:    "POST",
		url:       self.settings.ApiUrl + "/acl/ack",
		bearer:    true,
	}, &sidecarAclAckWire{Version: version, TimeMs: timeMs}, reply)
	if err != nil {
		return false, err
	}
	return reply.Recorded, nil
}

// POST /acl/ack's body (connect/api/bringyour.yml's AclAckArgs).
type sidecarAclAckWire struct {
	Version uint64 `json:"version"`
	TimeMs  int64  `json:"time_ms,omitempty"`
}

// POST /acl/ack's answer (AclAckResult).
type sidecarAclAckReply struct {
	Recorded bool `json:"recorded"`
}
