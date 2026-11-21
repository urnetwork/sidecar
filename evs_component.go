//go:build !sidecar_http && !ios_extension

// The evs SidecarComponent (§5.4): an EvsClient on a Sidecar's client generations. The client itself lives for the
// network, holding its pins and read records across generations; the component follows each generation's env so a
// hint on evs:<repo_id> (§11.10) reaches the client through the generation's own queue, with zero wait on the way in
// (D-CORE-3), and ends with it.
//
// Hints arrive through the generation's Subprotocol.Subscribe on the evs: family (§6.8): a notice carrying an
// EvsHeadChanged goes to ReceiveHint, and a reset's notice to ReceiveResync, each through the generation's queue, and
// the client's subscriptions read what they call for (evs_hint.go). Hints carry no authority either way: every read
// verifies whatever it finds.
//
// The repo's prefix write rules (EVS1-M6-04, EVS1-M6-05): each generation runs the prefix timer, which on a device
// whose composition repairs passes the repair runner and the owed pin pushes every RepairPassInterval; the Sidecar
// files a next rule set through `ur evs rules` (FilePrefixRules), reading the subjects it names against its verified
// state and config head, and sends the filer's pin pushes once its log holds the set. All of it is dark at launch
// (QD-1032): with the client's prefix settings off, the defaults, no timer runs and FilePrefixRules files nothing,
// answering ErrAclPrefixRulesDeferred.
//
// connect legs only: the sidecar_http leg runs no component (§18.10). Safe for concurrent use.

package sidecar

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The evs component.
type EvsComponent struct {
	client *EvsClient

	stateLock sync.Mutex
	// the running generation's env, nil between generations
	env *SidecarEnv
}

// The component of client, which AddComponent or NewSidecar attaches. A client the composition did not enable the
// repo's prefix write rules on is enabled here with the defaults (EVS1-M6-04; DESIGN-DETAILS 16.2.5): a ruled repo is
// read through the judge on every composition that runs evs once the rules run, and the defaults keep them dark
// (QD-1032). A judge a composition installed stays as it was, its settings and repairs with it.
func NewEvsComponent(client *EvsClient) *EvsComponent {
	if client.installedPrefixJudge() == nil {
		client.EnablePrefixRules(nil)
	}
	return &EvsComponent{client: client}
}

// "evs".
func (self *EvsComponent) Name() string {
	return evsComponentName
}

// The component's client.
func (self *EvsComponent) Client() *EvsClient {
	return self.client
}

// Follows one generation: subscribes to its push feed's evs: family, whose hints its queue carries until env.Ctx
// ends. A generation whose dispatcher has no push client yet attaches without hints.
func (self *EvsComponent) Attach(env *SidecarEnv) error {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.env = env
	}()
	remove := func() {}
	if env.Subprotocol != nil {
		if unsubscribe, err := env.Subprotocol.Subscribe(PushTopicEvsPrefix, func(notice PushNotice) {
			switch {
			case notice.Kind == uint32(protocol.MessageType_EVS_HEAD_CHANGED) && 0 < len(notice.Hint):
				self.ReceiveHint(notice.Topic, notice.Version, notice.Hint)
			case notice.Resync:
				self.receiveResync(notice.Topic, notice.Version)
			}
		}); err == nil {
			remove = unsubscribe
		}
	}
	// the subscriptions' rounds, once for the network: a reconnect starts nothing again, and renews nothing
	if err := self.client.StartSubscriptions(); err != nil {
		self.client.log.Warningf("[evs]subscriptions did not start: %v", err)
	}
	go self.runMapper(env.Ctx)
	// the prefix rules' repairs and owed pin pushes, on a device whose composition repairs (DESIGN-DETAILS 16.2.8)
	go self.runPrefixRepair(env.Ctx)
	go func() {
		<-env.Ctx.Done()
		remove()
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.env == env {
			self.env = nil
		}
	}()
	return nil
}

// Ends the component: no generation follows, and the subscriptions' rounds end, their records kept for the next
// start.
func (self *EvsComponent) Close() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.env = nil
	}()
	self.client.Close()
}

// A reset's notice on evs:<repo_id>: handed to the running generation's queue without waiting, as a hint is, false
// when there is none or the topic is not an evs repo's.
func (self *EvsComponent) receiveResync(topic string, version uint64) bool {
	idText, found := strings.CutPrefix(topic, PushTopicEvsPrefix)
	if !found {
		return false
	}
	repoId, err := ParseId(idText)
	if err != nil || repoId.String() != idText {
		return false
	}
	env := func() *SidecarEnv {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.env
	}()
	if env == nil {
		return false
	}
	return env.Enqueue(0, func(ctx context.Context) {
		self.client.ReceiveResync(repoId, version)
	})
}

// A hint on evs:<repo_id>: topic, PushHint.version and its delta. Hands it to the running generation's queue without
// waiting, false when there is none, the topic is not an evs repo's, or the queue is full, in which case it is dropped
// and counted there: a hint is a prompt, and the hourly resync covers a lost one (§11.10's gap row).
func (self *EvsComponent) ReceiveHint(topic string, version uint64, delta []byte) bool {
	idText, found := strings.CutPrefix(topic, PushTopicEvsPrefix)
	if !found {
		return false
	}
	repoId, err := ParseId(idText)
	if err != nil || repoId.String() != idText {
		return false
	}
	env := func() *SidecarEnv {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.env
	}()
	if env == nil {
		return false
	}
	deltaCopy := append([]byte{}, delta...)
	return env.Enqueue(len(deltaCopy), func(ctx context.Context) {
		self.client.ReceiveHint(repoId, version, deltaCopy)
		self.tickMapper(ctx, repoId, deltaCopy)
	})
}

// The mapper's tick on a hint's ref (DESIGN-DETAILS 9.2.7): a ref whose epoch is due maps on this device when it is
// eligible, and anything that waits ticks again on the next hint or the timer (runMapper).
func (self *EvsComponent) tickMapper(ctx context.Context, repoId Id, delta []byte) {
	changed := &protocol.EvsHeadChanged{}
	if err := proto.Unmarshal(delta, changed); err != nil {
		return
	}
	refId, err := IdFromBytes(changed.GetRefId())
	if err != nil {
		return
	}
	self.tickRef(ctx, repoId, refId)
}

// The mapper's loop until ctx ends: a tick of each ref a verified head, a new generation or this device's own
// rotation asks one of (evs_epoch_map.go's wake row), and every MapperSpread a tick of each ref this client pins.
func (self *EvsComponent) runMapper(ctx context.Context) {
	mapper := self.client.mapper()
	timer := self.client.clock.After(self.client.settings.MapperSpread)
	for {
		select {
		case <-ctx.Done():
			return
		case key := <-mapper.wakeups:
			self.tickRef(ctx, key.repoId, key.refId)
		case <-timer:
			timer = self.client.clock.After(self.client.settings.MapperSpread)
			for _, pin := range self.client.pins.loadedPins() {
				self.tickRef(ctx, pin.RepoId, pin.RefId)
			}
		}
	}
}

// One tick of a ref's mapper, what it did not finish logged.
func (self *EvsComponent) tickRef(ctx context.Context, repoId Id, refId Id) {
	if err := self.client.Repo(repoId).TickMapper(ctx, refId); err != nil && self.client.log.V(1).Enabled() {
		self.client.log.Infof("[evs]mapper on repo %s ref %s: %v", repoId, refId, err)
	}
}

// Installs the local application's presence prompt for acts whose verified policy requires it.
func (self *MemberReplica) SetPresenceCheck(check SidecarPresenceCheck) {
	self.presenceLock.Lock()
	defer self.presenceLock.Unlock()
	self.presence = check
}

// A native lifecycle call files the signed act at the installed authority, then waits for the
// following client to observe it before the EVS route or a subsequent create step consumes it.
func (self *MemberReplica) setStatementPoster(args *EvsClientArgs) {
	args.FileStatement = func(ctx context.Context, kind bridge.SignedType, body proto.Message) error {
		client := self.Config()
		if client == nil {
			return ErrEvsNoConfig
		}
		act, err := self.running.newAct(SidecarActConfirmed)
		if err != nil {
			return err
		}
		if err := act.Add(kind, body); err != nil {
			return err
		}
		self.presenceLock.Lock()
		check := self.presence
		self.presenceLock.Unlock()
		pins, err := act.Run(ctx, check)
		if err != nil {
			return err
		}
		if len(pins) == 0 {
			return ErrSidecarActState
		}
		if err := client.CatchUp(ctx); err != nil {
			return err
		}
		_, err = client.WaitFor(ctx, pins[len(pins)-1].GetVersion())
		return err
	}
}

// A native host can file the protected private marker when a repo is created.
func (self *Sidecar) setMemberEvsHooks(args *EvsClientArgs) {
	args.PrivateCreate = self.readyPrivateRepo
}

// What a prefix rule subject's text is read against: the verified state's members and rows, and the names the
// config head's tables give their atoms (AclLocalPolicy.Names), nil where this device opens no head.
func (self *Sidecar) evsPrefixNames() (*ConfigState, *AclLocalPolicy, error) {
	follower := self.ConfigFollower()
	if follower == nil {
		return nil, nil, fmt.Errorf("%w: no config follower stands", ErrEvsNoConfig)
	}
	state := follower.VerifiedState()
	if state == nil {
		return nil, nil, fmt.Errorf("%w: no verified state yet", ErrEvsNoConfig)
	}
	return state, follower.AclLocal(), nil
}

// The atom a subject's text names in a prefix rule, read against this Sidecar's verified state and config head
// (evsPrefixSubjectOf): what `ur evs rules` files a rule for.
func (self *Sidecar) PrefixRuleSubject(text string) (Id, error) {
	state, local, err := self.evsPrefixNames()
	if err != nil {
		return Id{}, err
	}
	return evsPrefixSubjectOf(state, local, text)
}

// A rule's subject as `ur evs rules show` prints it (evsPrefixSubjectText): id:<id> where this Sidecar holds no state.
func (self *Sidecar) PrefixRuleSubjectText(subject Id) string {
	state, local, err := self.evsPrefixNames()
	if err != nil {
		return "id:" + subject.String()
	}
	return evsPrefixSubjectText(state, local, subject)
}

// One `ur evs rules` filing and what followed it (DESIGN-DETAILS 16.2.9).
type EvsPrefixRulesFiling struct {
	// The set's entry, the set as filed, and the standing admins it names in no rule.
	Filed *AclPrefixRulesFiled
	// The repo held no set before: devices older than the release that carries the rules do not follow them, which
	// the command says once (16.2.12).
	FirstSet bool
	// Each shared ref after the filer's pin pushes.
	Refs []*EvsPrefixRef
}

// Files the repo's next prefix rule set as the person confirmed it (origin; never MCP or a hook) through
// AclPrefixRulesFiler, sealed under client's current repo key and built from the sets client holds, then sends the
// filer's pin push to each shared ref of the repo once this device's log holds the set (EvsClient.PinPushRules). A
// pin push that fails stays owed in the journal, and the filing stands: its error is the ref's, not the filing's.
// While client's prefix rules are dark, the launch default, nothing is filed: ErrAclPrefixRulesDeferred (QD-1032).
func (self *Sidecar) FilePrefixRules(ctx context.Context, client *EvsClient, request *AclPrefixRulesRequest, origin SidecarActOrigin) (*EvsPrefixRulesFiling, error) {
	if !client.PrefixRulesEnabled() {
		return nil, ErrAclPrefixRulesDeferred
	}
	follower := self.ConfigFollower()
	if follower == nil || follower.Client() == nil {
		return nil, ErrSidecarActNoAuthority
	}
	judge := client.prefixJudge()
	if judge == nil {
		return nil, &EvsPrefixRuleError{Detail: EvsPrefixDetailPending}
	}
	config := follower.Client()
	firstSet := false
	if state := config.State(); state != nil {
		if repo := state.Repo(request.RepoId); repo != nil {
			firstSet = len(repo.GetPrefixRules()) == 0
		}
	}
	filer := NewAclPrefixRulesFiler(&AclPrefixRulesFilerArgs{
		Sidecar: self,
		Config:  config,
		RepoKey: client.args.Gkm.CurrentRepoKey,
		Sets: func(ctx context.Context, state *ConfigState, repoId Id) ([]*AclPrefixRuleSet, error) {
			return judge.setsOf(ctx, repoId, state)
		},
		Settings: judge.settings,
	})
	filed, err := filer.File(ctx, request, origin, nil)
	if err != nil {
		return nil, err
	}
	filing := &EvsPrefixRulesFiling{Filed: filed, FirstSet: firstSet}
	refs, err := client.PinPushRules(ctx, request.RepoId, filed.Pin.GetVersion())
	if err != nil {
		self.log.Warningf("[evs]the pin pushes after a prefix rule set on repo %s: %v", request.RepoId, err)
	}
	filing.Refs = refs
	return filing, nil
}

// The prefix rules' loop until ctx ends (DESIGN-DETAILS 16.2.8, 16.2.9): every RepairPassInterval, on a device whose
// composition repairs, one pass of the repair runner over each repo whose mirror journalled an ignored event, and the
// pin pushes the journal owes. What a pass leaves waits for the next. None runs while the client's rules are dark
// (QD-1032), since prefixJudge answers no judge.
func (self *EvsComponent) runPrefixRepair(ctx context.Context) {
	judge := self.client.prefixJudge()
	if judge == nil || !judge.args.Repair || judge.settings.RepairPassInterval <= 0 {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-self.client.clock.After(judge.settings.RepairPassInterval):
		}
		self.client.passPrefixRepair(ctx)
	}
}
