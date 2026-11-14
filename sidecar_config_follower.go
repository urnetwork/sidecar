//go:build !ios_extension && !sidecar_http

// A hosted network's config follower (QD-796; TEAM-M2-10, ACL-M2-15, CORE-M2-01): the composition that makes a daemon's
// Sidecar the device's one judge of its network's §7.9 log. Sidecar.FollowConfig adds it as the Sidecar's "config"
// component, and at the first client generation, when the keychain is open and the identity known, it starts:
//
//	anchor   the genesis anchor enrollment recorded (SidecarAnchor), an invite's or a pre-approved key's; a device
//	         whose enrollment brought none trusts the first genesis api serves where its host allows first use, as a
//	         ur device does (§5.6's genesis row), once that genesis verifies and names this network (TrustFirstUse),
//	         and follows nothing where its host does not
//	follow   TEAM-M2-10's ConfigClient on the anchored A_0: GET /network/config/projection through the Sidecar's own
//	         api, the config repo's head reader the host gives, §5.9's authlog/ as its store, the network's key client
//	         and head_alarm through the Sidecar's events; a genesis other than the anchored one, at the read that
//	         serves it, refuses the follower with head_alarm fork
//	stand    once the log holds an entry and is at or past the anchor's head, on its chain where the log still keeps
//	         that position (I-16): the client's authority installed (Sidecar.InstallAuthority), ACL-M2-15's
//	         AclFollower run over the client on an AclEngine of the follower's own, the key client's AuthAdvanced let
//	         through, and only then does Client answer, so nothing on this device judges by a log below what the
//	         credential vouched for
//
// Each client generation hands its team hints to the client and asks it for a follow, since a hint may have gone
// unheard between generations. One follower a Sidecar, and so a network (Sidecar.ConfigFollower): the bridge, the acl
// engine and every other reader of §7.9's log on this device read it here, and the bridge's start gate (QD-669) waits
// on its store. A follower that cannot stand leaves its own network unjudged, nothing admitted there, and the daemon's
// other networks follow on (CORE-M6-01). A refusal lasts the follower's life: a restart anchors again.
//
// What this does not build is the host's to give: the config repo's head reader over evs, which needs a read of a
// file-mode ref at a config version that no EvsClient has yet, and the network's key client. With no head reader every
// base is withheld, so nothing past the genesis installs and nothing is admitted: the closed direction.
//
// Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The follower's component name, which names its keychain namespace and its directory, both unused: the log is kept in
// authlog/.
const sidecarConfigFollowerComponentName = "config"

// §5.9's authlog/: its directory under net/<network_id>/ and its file class.
const (
	sidecarAuthlogDirectoryName = "authlog"
	sidecarAuthlogClass         = "authlog"
)

var (
	// A config follower runs on this Sidecar already: a network has one judge of its log.
	ErrSidecarConfigFollowing = errors.New("a config follower runs for this network already")
	// The follower refused what it was shown and judges nothing: no anchor where first use is not allowed, a genesis
	// other than the anchored one, or a log below or off the anchored head.
	ErrSidecarConfigRefused = errors.New("the network's config follower refused the log")
)

// Where a follower stands, as Status names it.
type SidecarConfigFollowerState string

const (
	// No client generation has attached it yet: no identity, a locked keychain, or no token.
	SidecarConfigFollowerWaiting SidecarConfigFollowerState = "waiting"
	// It reads its anchor, or the first genesis api serves.
	SidecarConfigFollowerAnchoring SidecarConfigFollowerState = "anchoring"
	// Its client follows, and has not reached an entry or the anchored head yet.
	SidecarConfigFollowerCatchingUp SidecarConfigFollowerState = "catching_up"
	// Its client's authority is installed and its acl follower runs.
	SidecarConfigFollowerStanding SidecarConfigFollowerState = "standing"
	// It refused the log, for its life.
	SidecarConfigFollowerRefused SidecarConfigFollowerState = "refused"
	SidecarConfigFollowerClosed  SidecarConfigFollowerState = "closed"
)

// A follower's state and why it is there, ids and positions only (I-13).
type SidecarConfigFollowerStatus struct {
	State  SidecarConfigFollowerState
	Reason string
	// The client's verified pin, nil before its first state.
	Pin *bridge.AuthPin
}

// Tunables of a network's config follower, each with its default in DefaultSidecarConfigFollowerSettings.
type SidecarConfigFollowerSettings struct {
	// The first wait before the follower reads its anchor, or api's genesis for first use, again: 10 s, doubling up to
	// AnchorRetryMaxInterval, 10 min, so a keychain that stays locked or an api that serves no genesis yet is asked a
	// few times an hour. Both must be positive.
	AnchorRetryInterval    time.Duration
	AnchorRetryMaxInterval time.Duration
	// How long one read of api's genesis for first use may take: 60 s, a follow's (ConfigClientSettings.FollowTimeout).
	// Must be positive.
	AnchorReadTimeout time.Duration
	// How long the key client may take to give one of the config repo's generation keys: 10 s. A key it does not give
	// in time reads as one not held. Must be positive.
	RepoKeyTimeout time.Duration
	// Whether a sidecar whose enrollment recorded no anchor trusts the first genesis api serves (§5.6's genesis row): a
	// ur device's, from ur login or ur connect, which shows its SafetyNumber for its admitter to compare. False follows
	// nothing until an anchor is recorded.
	TrustFirstUse bool
	// The client's tunables; nil is DefaultConfigClientSettings. Its log is the Sidecar's where it names none.
	ConfigClient *ConfigClientSettings
	// The acl follower's and its engine's; nil is their defaults, on the Sidecar's clock and log.
	Acl       *AclSettings
	AclEngine *AclEngineSettings
}

// The values in the settings' comments, first use off.
func DefaultSidecarConfigFollowerSettings() *SidecarConfigFollowerSettings {
	return &SidecarConfigFollowerSettings{
		AnchorRetryInterval:    10 * time.Second,
		AnchorRetryMaxInterval: 10 * time.Minute,
		AnchorReadTimeout:      60 * time.Second,
		RepoKeyTimeout:         10 * time.Second,
	}
}

// What a follower runs on beyond its Sidecar.
type SidecarConfigFollowerArgs struct {
	// The config repo's head reader through evs: each base's head is checked by it, and the acl follower's local
	// policy and the bridge's compile read heads through it. Nil holds every base withheld.
	Heads ConfigHeadReader
	// The network's key client: AuthAdvanced after each applied entry once the follower stands, and RepoKey for the
	// config repo's generation keys. Nil for none.
	Gkm GkmClient
	// HeadStopState.ReportFork: a fork of the log stops sealing in shared groups (§6.4). Nil for none.
	ReportFork func(fork HeadFork)
	// Nil is DefaultSidecarConfigFollowerSettings.
	Settings *SidecarConfigFollowerSettings
}

// One network's config follower on its Sidecar (the file's comment).
type SidecarConfigFollower struct {
	sidecar  *Sidecar
	args     *SidecarConfigFollowerArgs
	settings *SidecarConfigFollowerSettings
	clock    Clock
	log      Logger

	ctx    context.Context
	cancel context.CancelFunc
	// the anchoring start, once, at the first generation
	startOnce sync.Once
	closeOnce sync.Once
	// the key client, whose AuthAdvanced is let through once the follower stands; nil with none
	gkm *sidecarConfigFollowerGkm
	// what WaitStanding watches; it moves under stateLock, and never out of refused or closed
	state *MonitorValue[SidecarConfigFollowerState]

	stateLock sync.Mutex
	reason    string
	// why it refused, wrapping ErrSidecarConfigRefused; nil before
	refusal error
	// the network, from the first generation's identity
	networkId *Id
	// from its start; Client answers it only once the follower stands, the hints reach it before
	client          *ConfigClient
	aclEngine       *AclEngine
	aclFollower     *AclFollower
	removeAuthority func()
	// takes the component off the Sidecar
	remove func()
	// one head_alarm for a refused genesis
	genesisRefused bool
}

// Starts the network's config follower on args as the Sidecar's "config" component, which ends with the Sidecar or at
// the answer's Close. One follower a Sidecar: a second is refused while one runs (ErrSidecarConfigFollowing).
func (self *Sidecar) FollowConfig(args *SidecarConfigFollowerArgs) (*SidecarConfigFollower, error) {
	if args == nil {
		args = &SidecarConfigFollowerArgs{}
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultSidecarConfigFollowerSettings()
	}
	if settings.AnchorRetryInterval <= 0 || settings.AnchorRetryMaxInterval < settings.AnchorRetryInterval ||
		settings.AnchorReadTimeout <= 0 || settings.RepoKeyTimeout <= 0 {
		return nil, fmt.Errorf("%w: the follower's anchor intervals and timeouts", errInvalidSettings)
	}
	if self.ctx == nil {
		return nil, ErrSidecarClosed
	}
	ctx, cancel := context.WithCancel(self.ctx)
	follower := &SidecarConfigFollower{
		sidecar:  self,
		args:     args,
		settings: settings,
		clock:    self.clock,
		log:      self.log,
		ctx:      ctx,
		cancel:   cancel,
		state:    NewMonitorValue(SidecarConfigFollowerWaiting),
	}
	if args.Gkm != nil {
		follower.gkm = &sidecarConfigFollowerGkm{GkmClient: args.Gkm}
	}
	previous := self.configFollower.Load()
	if running, _ := previous.(*SidecarConfigFollower); running != nil && !running.isClosed() {
		cancel()
		return nil, ErrSidecarConfigFollowing
	}
	if !self.configFollower.CompareAndSwap(previous, follower) {
		cancel()
		return nil, ErrSidecarConfigFollowing
	}
	remove, err := self.AddComponent(follower)
	if err != nil {
		follower.Close()
		return nil, err
	}
	follower.setRemove(remove)
	return follower, nil
}

// The network's config follower, nil before FollowConfig and once it has closed.
func (self *Sidecar) ConfigFollower() *SidecarConfigFollower {
	follower, _ := self.configFollower.Load().(*SidecarConfigFollower)
	if follower == nil || follower.isClosed() {
		return nil
	}
	return follower
}

// "config".
func (self *SidecarConfigFollower) Name() string {
	return sidecarConfigFollowerComponentName
}

// One client generation: its team hints go to the client until the generation ends, a follow is asked for, and the
// first generation starts the follower on its identity's network. A generation of another network than the first one's
// is refused: a Sidecar's network never changes, and this log judges only its own.
func (self *SidecarConfigFollower) Attach(env *SidecarEnv) error {
	identity := env.Identity
	if identity == nil {
		return fmt.Errorf("%w: a generation with no identity", ErrSidecarNoIdentity)
	}
	networkId, ours := func() (Id, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.networkId == nil {
			id := identity.NetworkId
			self.networkId = &id
		}
		return *self.networkId, *self.networkId == identity.NetworkId
	}()
	if !ours {
		return fmt.Errorf("the config follower of network %s takes no generation of network %s", networkId, identity.NetworkId)
	}
	if env.Subprotocol != nil {
		if unsubscribe, err := env.Subprotocol.Subscribe(PushTopicTeam, self.receiveNotice); err == nil {
			go func() {
				<-env.Ctx.Done()
				unsubscribe()
			}()
		}
	}
	if client := self.followingClient(); client != nil {
		client.requestFollow()
	}
	sidecarId := identity.SidecarId
	self.startOnce.Do(func() {
		go self.run(networkId, sidecarId)
	})
	return nil
}

// Ends the follower for good: the acl follower, the authority it installed and the client stop, and the component
// leaves the Sidecar. The authlog/ store stays for the next start. Safe to call again, from the Sidecar's close too.
func (self *SidecarConfigFollower) Close() {
	self.closeOnce.Do(func() {
		self.cancel()
		var aclFollower *AclFollower
		var removeAuthority func()
		var client *ConfigClient
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			aclFollower, removeAuthority, client = self.aclFollower, self.removeAuthority, self.client
			self.aclFollower, self.removeAuthority = nil, nil
			self.state.Set(SidecarConfigFollowerClosed)
		}()
		if aclFollower != nil {
			aclFollower.Close()
		}
		if removeAuthority != nil {
			removeAuthority()
		}
		if client != nil {
			client.Close()
		}
	})
	remove := func() func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		remove := self.remove
		self.remove = nil
		return remove
	}()
	if remove != nil {
		// the leg calls Close again, which is done
		remove()
	}
}

// Keeps the function that takes the component off the Sidecar, or calls it at once when the follower closed meanwhile.
func (self *SidecarConfigFollower) setRemove(remove func()) {
	closed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.state.Value() == SidecarConfigFollowerClosed {
			return true
		}
		self.remove = remove
		return false
	}()
	if closed {
		remove()
	}
}

// Whether the follower has closed.
func (self *SidecarConfigFollower) isClosed() bool {
	return self.state.Value() == SidecarConfigFollowerClosed
}

// The state, why, and the client's pin.
func (self *SidecarConfigFollower) Status() SidecarConfigFollowerStatus {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	status := SidecarConfigFollowerStatus{State: self.state.Value(), Reason: self.reason}
	if self.client != nil {
		status.Pin = self.client.Pin()
	}
	return status
}

// The client, once the follower stands; nil before, after a refusal and once closed.
func (self *SidecarConfigFollower) Client() *ConfigClient {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.state.Value() != SidecarConfigFollowerStanding {
		return nil
	}
	return self.client
}

// Waits until the follower stands and answers its client, or why it will not: its refusal, wrapping ErrSidecarConfigRefused,
// ErrSidecarClosed once closed, or ctx's error.
func (self *SidecarConfigFollower) WaitStanding(ctx context.Context) (*ConfigClient, error) {
	for {
		state, changed := self.state.Get()
		switch state {
		case SidecarConfigFollowerStanding:
			if client := self.Client(); client != nil {
				return client, nil
			}
		case SidecarConfigFollowerRefused:
			self.stateLock.Lock()
			refusal := self.refusal
			self.stateLock.Unlock()
			return nil, refusal
		case SidecarConfigFollowerClosed:
			return nil, ErrSidecarClosed
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// The config repo's head reader the host gave, nil for none.
func (self *SidecarConfigFollower) Heads() ConfigHeadReader {
	return self.args.Heads
}

// A base's rows as the client keeps them, the current and previous bases', for the log runs a device role verifies,
// and a base's head checked as the client checks one.
func (self *SidecarConfigFollower) Rows() ConfigRowsSource {
	return &sidecarConfigFollowerRows{follower: self}
}

// The config repo's key of generation, from the key client: nil before the follower stands, with no key client, and for
// a generation the client does not give within RepoKeyTimeout, every refusal alike.
func (self *SidecarConfigFollower) RepoKeyAt(generation uint64) *EvsRepoKey {
	client := self.Client()
	if client == nil || self.args.Gkm == nil {
		return nil
	}
	state := client.State()
	if state == nil {
		return nil
	}
	configRepoId, err := IdFromBytes(state.Genesis().GetConfigRepoId())
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(self.ctx, self.settings.RepoKeyTimeout)
	defer cancel()
	key, err := self.args.Gkm.RepoKey(ctx, configRepoId, generation)
	if err != nil {
		if self.log.V(1).Enabled() {
			self.log.Infof("[config]%s the config repo's generation %d is not held: %v", configRepoId, generation, err)
		}
		return nil
	}
	return key
}

// The acl follower's local policy as its engine has it installed, nil before the follower stands or before one
// compiled.
func (self *SidecarConfigFollower) AclLocal() *AclLocalPolicy {
	aclFollower := self.AclFollower()
	if aclFollower == nil {
		return nil
	}
	local, _ := aclFollower.Local()
	return local
}

// The acl follower over the client, nil before the follower stands.
func (self *SidecarConfigFollower) AclFollower() *AclFollower {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.aclFollower
}

// The acl engine the acl follower installs in, nil before the follower stands.
func (self *SidecarConfigFollower) AclEngine() *AclEngine {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.aclEngine
}

// Moves to state for reason, unless the follower refused or closed, which it never leaves. Whether it moved.
func (self *SidecarConfigFollower) moveTo(state SidecarConfigFollowerState, reason string) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	switch self.state.Value() {
	case SidecarConfigFollowerRefused, SidecarConfigFollowerClosed:
		return false
	}
	self.reason = reason
	self.state.Set(state)
	return true
}

// Refuses the log for the follower's life: the client stops, so nothing is applied past what refused, and whatever
// stood comes down, the authority and the acl follower. Never blocks: a read of the client's calls it under the
// client's follow.
func (self *SidecarConfigFollower) refuse(err error) {
	if !errors.Is(err, ErrSidecarConfigRefused) {
		err = fmt.Errorf("%w: %w", ErrSidecarConfigRefused, err)
	}
	var aclFollower *AclFollower
	var removeAuthority func()
	refused := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		switch self.state.Value() {
		case SidecarConfigFollowerRefused, SidecarConfigFollowerClosed:
			return false
		}
		self.reason, self.refusal = err.Error(), err
		self.state.Set(SidecarConfigFollowerRefused)
		aclFollower, removeAuthority = self.aclFollower, self.removeAuthority
		self.aclFollower, self.removeAuthority = nil, nil
		return true
	}()
	if !refused {
		return
	}
	self.log.Errorf("[config]the network's log is refused, and nothing on it is judged: %v", err)
	if aclFollower != nil {
		aclFollower.Close()
	}
	if removeAuthority != nil {
		removeAuthority()
	}
	if client := self.followingClient(); client != nil {
		client.Close()
	}
}

// The client from its start, whatever the follower's state but closed, for the hints.
func (self *SidecarConfigFollower) followingClient() *ConfigClient {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.state.Value() == SidecarConfigFollowerClosed {
		return nil
	}
	return self.client
}

// A team hint from the running generation, to the client.
func (self *SidecarConfigFollower) receiveNotice(notice PushNotice) {
	if client := self.followingClient(); client != nil {
		client.ReceiveNotice(notice)
	}
}

// The start: the anchor, the client on it, the anchored head, then standing. A refusal stops here for the follower's
// life; anything else is asked again until the follower closes.
func (self *SidecarConfigFollower) run(networkId Id, sidecarId Id) {
	anchor, err := self.anchorWithRetry(networkId)
	if err != nil {
		if errors.Is(err, ErrSidecarConfigRefused) {
			self.refuse(err)
		}
		return
	}
	client, err := self.startClient(networkId, [sha256.Size]byte(anchor.GenesisSha256))
	if err != nil {
		if self.ctx.Err() == nil {
			self.refuse(fmt.Errorf("%w: the client did not start: %w", ErrSidecarConfigRefused, err))
		}
		return
	}
	if err := self.awaitAnchoredHead(client, anchor); err != nil {
		if errors.Is(err, ErrSidecarConfigRefused) {
			self.refuse(err)
		}
		return
	}
	self.stand(networkId, sidecarId, client)
}

// The anchor, asked again at a doubling interval while the keychain is locked or api serves no genesis to trust.
func (self *SidecarConfigFollower) anchorWithRetry(networkId Id) (*SidecarAnchor, error) {
	wait := self.settings.AnchorRetryInterval
	for {
		self.moveTo(SidecarConfigFollowerAnchoring, "")
		anchor, err := self.anchor(networkId)
		if err == nil || errors.Is(err, ErrSidecarConfigRefused) {
			return anchor, err
		}
		self.moveTo(SidecarConfigFollowerAnchoring, err.Error())
		if self.log.V(1).Enabled() {
			self.log.Infof("[config]%s no anchor yet, asking again in %s: %v", networkId, wait, err)
		}
		select {
		case <-self.ctx.Done():
			return nil, self.ctx.Err()
		case <-self.clock.After(wait):
		}
		wait = min(2*wait, self.settings.AnchorRetryMaxInterval)
	}
}

// The anchor enrollment recorded, or, where none is and first use is allowed, the first genesis api serves, recorded
// as this sidecar's. ErrSidecarConfigRefused for what can never anchor; any other error is asked again.
func (self *SidecarConfigFollower) anchor(networkId Id) (*SidecarAnchor, error) {
	anchor, err := self.sidecar.Anchor()
	switch {
	case err == nil:
	case errors.Is(err, ErrSidecarStoreAbsent) && self.settings.TrustFirstUse:
		if err := self.trustFirstUse(networkId); err != nil {
			return nil, err
		}
		if anchor, err = self.sidecar.Anchor(); err != nil {
			return nil, err
		}
	case errors.Is(err, ErrSidecarStoreAbsent):
		return nil, fmt.Errorf("%w: enrollment recorded no genesis anchor, and this host trusts no first use", ErrSidecarConfigRefused)
	default:
		return nil, err
	}
	if len(anchor.GenesisSha256) != sha256.Size {
		return nil, fmt.Errorf("%w: %w", ErrSidecarConfigRefused, ErrSidecarAnchorMalformed)
	}
	return anchor, nil
}

// §5.6's first use: the genesis api serves, once it verifies under the key it names and names this network, recorded
// as the anchor. A genesis that does not, or none yet, is asked for again: nothing is trusted from it.
func (self *SidecarConfigFollower) trustFirstUse(networkId Id) error {
	ctx, cancel := context.WithTimeout(self.ctx, self.settings.AnchorReadTimeout)
	defer cancel()
	projection, err := self.sidecar.sidecarApi.ReadConfigProjection(ctx, 0)
	if err != nil {
		return err
	}
	if len(projection.SignedGenesis) == 0 {
		return errors.New("api serves no genesis yet")
	}
	served, err := NewConfigLog(self.logSettings(), projection.SignedGenesis)
	if err != nil {
		self.log.Warningf("[config]%s api serves a genesis that does not verify: %v", networkId, err)
		return err
	}
	if served.State().NetworkId() != networkId {
		self.log.Warningf("[config]%s api serves another network's genesis", networkId)
		return errors.New("api serves another network's genesis")
	}
	genesisChain := bridge.GenesisChain(projection.SignedGenesis)
	if err := self.sidecar.TrustFirstUse(genesisChain[:]); err != nil {
		if errors.Is(err, ErrSidecarAnchorMismatch) {
			return fmt.Errorf("%w: %w", ErrSidecarConfigRefused, err)
		}
		return err
	}
	self.log.Infof("[config]%s anchored on the first genesis api served; the admitter compares the safety number", networkId)
	return nil
}

// The client on the anchored genesis, its store authlog/, its reads checked for the anchored genesis.
func (self *SidecarConfigFollower) startClient(networkId Id, genesisChain [sha256.Size]byte) (*ConfigClient, error) {
	store, err := self.sidecar.LocalStore().Directory(sidecarAuthlogDirectoryName, sidecarAuthlogClass)
	if err != nil {
		return nil, err
	}
	settings := DefaultConfigClientSettings()
	if self.settings.ConfigClient != nil {
		copied := *self.settings.ConfigClient
		settings = &copied
	}
	if settings.Log == nil {
		settings.Log = self.log
	}
	clientArgs := &ConfigClientArgs{
		NetworkId:    networkId,
		GenesisChain: genesisChain,
		Projection:   &sidecarConfigFollowerProjection{follower: self, reader: self.sidecar.sidecarApi, genesisChain: genesisChain},
		Heads:        self.args.Heads,
		Store:        store,
		Emit:         self.sidecar.emitEvent,
		ReportFork:   self.args.ReportFork,
		Clock:        self.clock,
		Settings:     settings,
	}
	if self.gkm != nil {
		clientArgs.Gkm = self.gkm
	}
	client, err := NewConfigClient(self.ctx, clientArgs)
	if err != nil {
		return nil, err
	}
	kept := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		switch self.state.Value() {
		case SidecarConfigFollowerRefused, SidecarConfigFollowerClosed:
			return false
		}
		self.client = client
		self.reason = ""
		self.state.Set(SidecarConfigFollowerCatchingUp)
		return true
	}()
	if !kept {
		client.Close()
		return nil, ErrSidecarClosed
	}
	return client, nil
}

// Waits until the log holds an entry, since no state before one admits anyone, and is at or past the anchor's head,
// then checks it there (I-16): the anchor's own check, and the log's chain at the head's position where it still keeps
// it. ErrSidecarConfigRefused for a fork below the head or another chain at it, with head_alarm fork.
func (self *SidecarConfigFollower) awaitAnchoredHead(client *ConfigClient, anchor *SidecarAnchor) error {
	through := max(anchor.Head.GetVersion(), 1)
	self.moveTo(SidecarConfigFollowerCatchingUp, fmt.Sprintf("following the log to position %d", through))
	state, err := client.WaitFor(self.ctx, through)
	if err != nil {
		fork := &ConfigForkError{}
		if errors.As(err, &fork) {
			return fmt.Errorf("%w: the log forked before position %d: %w", ErrSidecarConfigRefused, through, err)
		}
		return err
	}
	head := anchor.Head
	if head == nil || head.GetVersion() == 0 {
		return nil
	}
	if err := anchor.Check(anchor.GenesisSha256, state.Pin()); err != nil {
		self.alarmAnchoredHead(head, state.Pin())
		return fmt.Errorf("%w: %w", ErrSidecarConfigRefused, err)
	}
	if chain, kept := client.ChainAt(head.GetVersion()); kept && !bytes.Equal(chain, head.GetChain()) {
		self.alarmAnchoredHead(head, &bridge.AuthPin{Version: head.GetVersion(), Chain: chain})
		return fmt.Errorf("%w: %w: another chain at the anchored head %d", ErrSidecarConfigRefused, ErrSidecarAnchorMismatch, head.GetVersion())
	}
	return nil
}

// head_alarm fork: the anchored head beside what the log holds there.
func (self *SidecarConfigFollower) alarmAnchoredHead(head *bridge.AuthPin, held *bridge.AuthPin) {
	self.sidecar.emitEvent(SidecarEvent{Kind: SidecarEventHeadAlarm, HeadAlarm: SidecarHeadAlarmFork,
		Evidence: [2][]byte{configPinBytes(head), configPinBytes(held)}})
}

// A read served a genesis other than the anchored one: head_alarm fork once, with A_0 as anchored and as served, and
// the follower refuses. Called under the client's follow.
func (self *SidecarConfigFollower) refuseGenesis(anchored [sha256.Size]byte, served [sha256.Size]byte) {
	first := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.genesisRefused {
			return false
		}
		self.genesisRefused = true
		return true
	}()
	if !first {
		return
	}
	self.sidecar.emitEvent(SidecarEvent{Kind: SidecarEventHeadAlarm, HeadAlarm: SidecarHeadAlarmFork,
		Evidence: [2][]byte{configPinBytes(&bridge.AuthPin{Chain: anchored[:]}), configPinBytes(&bridge.AuthPin{Chain: served[:]})}})
	self.refuse(fmt.Errorf("%w: %w: api serves another genesis than the anchored one", ErrSidecarConfigRefused, ErrSidecarAnchorMismatch))
}

// Standing: the authority installed, the acl follower started on an engine of its own, the key client let through, and
// only then the state that makes Client answer. A follower that refused or closed meanwhile takes all of it back.
func (self *SidecarConfigFollower) stand(networkId Id, sidecarId Id, client *ConfigClient) {
	aclSettings := DefaultAclSettings()
	if self.settings.Acl != nil {
		copied := *self.settings.Acl
		aclSettings = &copied
	}
	if aclSettings.Clock == nil {
		aclSettings.Clock = self.clock
	}
	if aclSettings.Log == nil {
		aclSettings.Log = self.log
	}
	engine := NewAclEngine(sidecarId, &sidecarConfigFollowerAclStates{client: client}, self.aclAlarm, self.settings.AclEngine)
	testHookBarrier("sidecar_config_follower.stand.before", networkId.String())
	removeAuthority := self.sidecar.InstallAuthority(client.Authority())
	aclFollower, err := NewAclFollower(self.ctx, &AclFollowerArgs{
		Source:   client,
		Engine:   engine,
		Acks:     self.sidecar.sidecarApi,
		Heads:    self.args.Heads,
		Emit:     self.sidecar.emitEvent,
		Settings: aclSettings,
	})
	if err != nil {
		removeAuthority()
		self.refuse(fmt.Errorf("%w: the acl follower did not start: %w", ErrSidecarConfigRefused, err))
		return
	}
	kept := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		switch self.state.Value() {
		case SidecarConfigFollowerRefused, SidecarConfigFollowerClosed:
			return false
		}
		self.aclEngine, self.aclFollower, self.removeAuthority = engine, aclFollower, removeAuthority
		return true
	}()
	if !kept {
		aclFollower.Close()
		removeAuthority()
		return
	}
	if self.gkm != nil {
		self.gkm.standing.Store(true)
		if state := client.State(); state != nil {
			self.gkm.GkmClient.AuthAdvanced(state)
		}
	}
	self.moveTo(SidecarConfigFollowerStanding, "")
	testHookBarrier("sidecar_config_follower.stand.after", networkId.String())
	if self.log.V(1).Enabled() {
		self.log.Infof("[config]%s follows its log at %d", networkId, client.Pin().GetVersion())
	}
}

// The engine's alarms the acl follower does not raise itself: a push or delivery whose pin is off this log's chain, a
// fork about whoever presented it (ACL-M2-09). A lower pin or a second A_n at Install the acl follower raises.
func (self *SidecarConfigFollower) aclAlarm(alarm AclEngineAlarm) {
	if alarm.Kind != AclEngineAlarmPinOffChain {
		return
	}
	self.sidecar.emitEvent(SidecarEvent{Kind: SidecarEventHeadAlarm, HeadAlarm: SidecarHeadAlarmFork,
		Evidence: [2][]byte{configPinBytes(alarm.Installed), configPinBytes(alarm.Offered)}})
}

// The log's own tunables, for checking a genesis offered for first use.
func (self *SidecarConfigFollower) logSettings() *ConfigLogSettings {
	if self.settings.ConfigClient != nil && self.settings.ConfigClient.LogSettings != nil {
		return self.settings.ConfigClient.LogSettings
	}
	settings := DefaultConfigLogSettings()
	settings.Log = self.log
	return settings
}

// The client's projection reader: the Sidecar's api, each page that carries a genesis checked against the anchored one
// first, so api serving another refuses the follower with head_alarm fork, not only fails each follow.
type sidecarConfigFollowerProjection struct {
	follower     *SidecarConfigFollower
	reader       ConfigProjectionReader
	genesisChain [sha256.Size]byte
}

// The Sidecar api's read, its genesis checked first.
func (self *sidecarConfigFollowerProjection) ReadConfigProjection(ctx context.Context, after uint64) (*ConfigProjection, error) {
	projection, err := self.reader.ReadConfigProjection(ctx, after)
	if err == nil && len(projection.SignedGenesis) != 0 {
		if served := bridge.GenesisChain(projection.SignedGenesis); served != self.genesisChain {
			self.follower.refuseGenesis(self.genesisChain, served)
		}
	}
	return projection, err
}

// The key client as the follower hands it to its client: AuthAdvanced reaches it only once the follower stands, so no
// state below the anchored head moves a key flow. Every other call goes through.
type sidecarConfigFollowerGkm struct {
	GkmClient
	standing atomic.Bool
}

// The key client's, once the follower stands; nothing before.
func (self *sidecarConfigFollowerGkm) AuthAdvanced(state GkmAuthView) {
	if self.standing.Load() {
		self.GkmClient.AuthAdvanced(state)
	}
}

// The engine's view of the client: the acl part of the state at a pin a push or delivery carries, judged on the newest
// verified state (ConfigState.StateAt), a pin above it waiting.
type sidecarConfigFollowerAclStates struct {
	client *ConfigClient
}

// The acl part of the state at pin; ErrConfigPinAhead before the client holds a state.
func (self *sidecarConfigFollowerAclStates) AclStateAt(pin *bridge.AuthPin) (*AclState, error) {
	state := self.client.State()
	if state == nil {
		return nil, fmt.Errorf("%w: no state yet", ErrConfigPinAhead)
	}
	at, err := state.StateAt(pin)
	if err != nil {
		return nil, err
	}
	return at.Acl()
}

// The follower's ConfigRowsSource (Rows).
type sidecarConfigFollowerRows struct {
	follower *SidecarConfigFollower
}

// A base's rows as the client keeps them: the current and previous bases'. ErrConfigHeadUnavailable for any other,
// another network's, or before the follower stands.
func (self *sidecarConfigFollowerRows) Rows(networkId Id, rowsSha256 []byte) ([]byte, error) {
	client := self.follower.Client()
	if client == nil || client.NetworkId() != networkId || len(rowsSha256) != sha256.Size {
		return nil, fmt.Errorf("%w: no rows kept for %x", ErrConfigHeadUnavailable, rowsSha256)
	}
	rows, kept := client.keptBaseRows([sha256.Size]byte(rowsSha256))
	if !kept {
		return nil, fmt.Errorf("%w: no rows kept for %x", ErrConfigHeadUnavailable, rowsSha256)
	}
	return rows, nil
}

// A base's head read through the host's head reader, an anchor's under the base's own rows (readConfigHeadForCheck),
// and checked as the client checks one (CheckConfigBase). ErrConfigHeadUnavailable with no head reader.
func (self *sidecarConfigFollowerRows) CheckHead(check *ConfigHeadCheck) (*ConfigHeadFacts, error) {
	heads := self.follower.args.Heads
	if heads == nil {
		return nil, fmt.Errorf("%w: no config head reader", ErrConfigHeadUnavailable)
	}
	ctx, cancel := context.WithTimeout(self.follower.ctx, self.follower.settings.AnchorReadTimeout)
	defer cancel()
	head, err := readConfigHeadForCheck(ctx, heads, check)
	if err != nil {
		return nil, err
	}
	facts, err := CheckConfigBase(head, check, check.CompileRows)
	if errors.Is(err, ErrConfigCompileUnavailable) {
		return nil, fmt.Errorf("%w: %w", ErrConfigHeadUnavailable, err)
	}
	return facts, err
}

// The rows of a base the log keeps, the current and previous bases', read beside the follower as BridgeEntries reads
// entries.
func (self *ConfigClient) keptBaseRows(rowsSha256 [sha256.Size]byte) ([]byte, bool) {
	self.followLock.Lock()
	defer self.followLock.Unlock()
	log := self.configLog.Load()
	if log == nil {
		return nil, false
	}
	rows, kept := log.baseRows[rowsSha256]
	if !kept {
		return nil, false
	}
	return bytes.Clone(rows), true
}
