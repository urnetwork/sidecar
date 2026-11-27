//go:build !sidecar_http && !ios_extension

// The sockets SidecarComponent (§5.4, §9): the registrar (socket_registrar.go) on a Sidecar's client generations, and
// what Sidecar.Listen and Sidecar.Dial run on. The registrar, its set and the listeners live for the network across
// generations, since a Listen outlives a reconnect; each generation it follows lends it the SidecarApi calls on its
// token, its identity key, its push feed's topic sock and its §6 dispatcher, and takes them back when it ends. Each
// live listener takes its stream target on every generation's dispatcher as that generation attaches (socket_listen.go),
// and the dialer opens on the generation attached when it dials (socket_dial.go).
//
// The stock daemon and native SDK use Sidecar.NewSocketComponent. Its application and share names use only the
// network's verified config head's K_sock ring. It follows the standing ACL engine for admissions and revocations,
// builds a tls/ or smtp/ listen's grant and its effect on that engine, and waits for a grant the listen's approval
// activates in its host's config client, the one whose follower installs that engine's states, before the listen
// registers (socket_listen.go), registers the listen kind's Lookup on its host while it lives, and resolves labels
// through the authenticated network APIs. Each prerequisite is required by its consumer. Connect legs only. Safe for
// concurrent use.

package sidecar

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Its keychain namespace and its sealed directory (§5.9).
const socketComponentName = "sockets"

// A network's label (§12.5): ten characters, which keep <label>:<name> within §6's 128 B target.
const socketNetworkLabelByteCount = 10

// What NewSocketComponent takes. Sidecar.SocketComponentArgs fills it for the network a Sidecar is enrolled in.
type SocketComponentArgs struct {
	NetworkId Id
	// SidecarSettings.Sockets.
	Settings *SidecarSocketSettings
	// §9.5's registration format, which the sockets service holds too (socketsservice.SocketsSettings.Format): a
	// listen's default weight and max_streams and the most ALPN ids and protocol bytes it registers. Nil takes
	// DefaultSocketFormatSettings.
	Format *SocketFormatSettings
	// Sidecar.Sign, which claims each registration (§9.5).
	Sign func(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error)
	// nil is real time.
	Clock Clock
	// nil is the default logger.
	Log Logger
}

// What a socket's two ends read of this device's own evaluation of its config (owner decisions 3 and 6, D-SOCK-14):
// the state an AclEngine installed from the verified log. Safe for concurrent use.
type SocketPolicy interface {
	// The authorization log position of the state the checks answer on, 0 before any.
	Position() uint64
	// Waits until the state reaches position or ctx ends, and answers whether it did.
	WaitPosition(ctx context.Context, position uint64) bool
	// A dial on one of this sidecar's sockets (§8.10): admission's step 6 on an application or share/ name.
	AllowInbound(inbound *AclInbound, now time.Time) AclDecision
	// listen on a name for subject: a dialer's check of its listener (owner decision 3), and a listener's own standing
	// on the edge name an edge dials.
	MayListen(subject AclSubject, socket AclSocketName, now time.Time) AclDecision
	// publish on a dns host, which a tls/ edge dial needs at the listener beside listen (§9.10, §13.9).
	MayPublish(subject AclSubject, host string, now time.Time) AclDecision
}

// SocketPolicy over an AclEngine. It holds no follower, so WaitPosition answers at once from the installed state: a
// listener behind a ticket's position answers retry (§9.6's step 6) until the engine's host installs a newer state.
type socketEnginePolicy struct {
	engine *AclEngine
}

// The policy an AclEngine's installed state answers.
func NewSocketEnginePolicy(engine *AclEngine) SocketPolicy {
	return &socketEnginePolicy{engine: engine}
}

// See SocketPolicy.
func (self *socketEnginePolicy) Position() uint64 {
	return self.engine.Pin().GetVersion()
}

// See SocketPolicy. At once, from the installed state.
func (self *socketEnginePolicy) WaitPosition(ctx context.Context, position uint64) bool {
	return position <= self.Position()
}

// See SocketPolicy.
func (self *socketEnginePolicy) AllowInbound(inbound *AclInbound, now time.Time) AclDecision {
	return self.engine.AllowInbound(inbound, now)
}

// See SocketPolicy.
func (self *socketEnginePolicy) MayListen(subject AclSubject, socket AclSocketName, now time.Time) AclDecision {
	return socketInstalledGrants{state: self.engine.State()}.MayListen(subject, socket, now)
}

// See SocketPolicy.
func (self *socketEnginePolicy) MayPublish(subject AclSubject, host string, now time.Time) AclDecision {
	return socketInstalledGrants{state: self.engine.State()}.MayPublish(subject, host, now)
}

// A TLS admission checks both grants on the same installed state, including its signed scope bindings.
type socketPublicGrants interface {
	MayListen(AclSubject, AclSocketName, time.Time) AclDecision
	MayPublish(AclSubject, string, time.Time) AclDecision
}

// Captures the device's installed state once for the listen and publish checks of a single admission.
func socketGrantsAt(policy SocketPolicy) socketPublicGrants {
	if device, ok := policy.(*socketEnginePolicy); ok {
		return socketInstalledGrants{state: device.engine.State()}
	}
	return policy
}

// A snapshot of the grants and team scope bindings installed together on this device.
type socketInstalledGrants struct {
	state *AclState
}

// An unscoped host uses the ordinary grant. A scoped host also requires its signed binding and, for
// a member scope, the named member's consented device. Both facts come from this ACL's own view.
func (self socketInstalledGrants) scope(host string) (AclScope, bool) {
	if self.state == nil {
		return AclScope{}, false
	}
	label, scoped := aclScopeOfHost(host)
	if !scoped {
		return AclScope{}, true
	}
	config, _ := self.state.view.(*ConfigState)
	return config.TeamScope(label)
}

// Checks the listen grant in the scope bound to the socket's public host.
func (self socketInstalledGrants) MayListen(subject AclSubject, socket AclSocketName, now time.Time) AclDecision {
	host, _ := aclSocketHost(socket.PublicName)
	scope, ok := self.scope(host)
	if !ok {
		return aclDeny(AclReasonNoState)
	}
	return self.state.MayListenInScope(subject, socket, scope, now)
}

// Checks the publish grant in the scope bound to the requested host.
func (self socketInstalledGrants) MayPublish(subject AclSubject, host string, now time.Time) AclDecision {
	scope, ok := self.scope(host)
	if !ok {
		return aclDeny(AclReasonNoState)
	}
	return self.state.MayPublishInScope(subject, host, scope, now)
}

// The network's names as sockets need them (§12): its 10-character label, which every stream target names as
// <label>:<name> (plan reading 12, within §6's 128 B), and the resolver a Dial's <net> goes through.
type SocketNetworkLabels struct {
	// The network's 10-character label, never an alias.
	Label string
	// §12's table of the networks this client belongs to. Nil: a Dial that names a <net> is refused.
	Resolver NetworkLabelResolver
	// The user root those labels sit under.
	Root string
}

// One client generation's parts, as the component holds them while it is attached.
type socketGeneration struct {
	ctx         context.Context
	seq         uint64
	subprotocol *Subprotocol
	sidecarApi  *SidecarApi
	identity    *SidecarIdentity
	authorize   func(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error
}

// The sockets component.
type SocketComponent struct {
	// The production host, which supplies authenticated network labels and verified config.
	host          *Sidecar
	configLock    sync.Mutex
	configDone    chan struct{}
	configInstall *aclEngineInstall
	registrar     *socketRegistrar
	networkId     Id
	settings      *SidecarSocketSettings
	format        *SocketFormatSettings
	clock         Clock
	log           Logger
	// removes the listen kind's Lookup the host's gate reconciles a reserved use by; nil without a host
	removeListenLookup func()
	// each tls/ or smtp/ listen's action as its request was filed, kept until its expiry or until the grant its
	// decision activated has ended (socketListenAction)
	listenActions *GrantActionKeeper[socketListenActionKey]

	stateLock sync.Mutex
	// the attached generation, nil between generations
	generation    *socketGeneration
	generationSeq uint64
	policy        SocketPolicy
	labels        *SocketNetworkLabels
	// the live listeners, each taking its target on every generation's dispatcher
	listeners map[*SocketListener]bool
	// the grant filer a tls/ or smtp/ listen's action is built and activated by where the component has no host, which
	// a test sets; nil reads the host's (listenGrants)
	grants *AclGrantFiler
	// the config a grant that filer's use activates is waited on in before the listen registers, beside grants, which a
	// test sets; nil waits on none (listenGrants)
	grantConfig AclGrantConfig
	// the §5.4 action a tls/ or smtp/ listen goes through Authorize as: socketListenAction, which a test replaces
	listenAction func(ctx context.Context, generation *socketGeneration, name string, settings *SocketListenSettings) (*SidecarAction, error)
}

// The args a SocketComponent takes from this Sidecar for the network it is enrolled in: its settings, Sign, the clock
// and the log.
func (self *Sidecar) SocketComponentArgs() (*SocketComponentArgs, error) {
	networkId := self.enrolledNetworkId()
	if networkId == nil {
		return nil, fmt.Errorf("%w: sockets needs an enrolled network", errInvalidSettings)
	}
	return &SocketComponentArgs{
		NetworkId: *networkId,
		Settings:  self.settings.Sockets,
		Sign:      self.Sign,
		Clock:     self.clock,
		Log:       self.log,
	}, nil
}

// Builds a socket component as soon as this Sidecar is enrolled. Its config follower,
// label API and DNS zone supply policy, keys and names until ctx ends or Close.
func (self *Sidecar) NewSocketComponent(ctx context.Context) (*SocketComponent, error) {
	var args *SocketComponentArgs
	for {
		_, changed := self.state.Get()
		var err error
		args, err = self.SocketComponentArgs()
		if err == nil {
			break
		}
		select {
		case <-self.ctx.Done():
			return nil, ErrSidecarClosed
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
	}
	component, err := NewSocketComponent(ctx, args)
	if err != nil {
		return nil, err
	}
	component.host = self
	component.configDone = make(chan struct{})
	// a spent tls/ or smtp/ listen's grant is the grant component's, which a restart reconciles by this Lookup (§16.6)
	component.removeListenLookup = self.RegisterEffectLookup(SidecarActionListen, component.listenLookup)
	go component.followSocketConfig()
	return component, nil
}

// A component whose registrar runs until Close or ctx ends, attached to no generation yet.
func NewSocketComponent(ctx context.Context, args *SocketComponentArgs) (*SocketComponent, error) {
	if args == nil {
		return nil, fmt.Errorf("%w: no socket component args", errInvalidSettings)
	}
	registrar, err := newSocketRegistrar(ctx, &socketRegistrarArgs{
		NetworkId: args.NetworkId,
		Settings:  args.Settings,
		Sign:      args.Sign,
		Clock:     args.Clock,
		Log:       args.Log,
	})
	if err != nil {
		return nil, err
	}
	format := args.Format
	if format == nil {
		format = DefaultSocketFormatSettings()
	}
	component := &SocketComponent{
		registrar:     registrar,
		networkId:     args.NetworkId,
		settings:      registrar.settings,
		format:        format,
		clock:         registrar.clock,
		log:           registrar.log,
		listeners:     map[*SocketListener]bool{},
		listenActions: NewGrantActionKeeper[socketListenActionKey](),
	}
	component.listenAction = component.socketListenAction
	return component, nil
}

// "sockets".
func (self *SocketComponent) Name() string {
	return socketComponentName
}

// Follows one generation: the registrar calls on its token until env.Ctx ends, and its push feed's notices on topic
// sock ask for the set at once. A generation whose dispatcher has no push client yet attaches without hints, and the
// heartbeat carries it. A generation of another network is refused.
func (self *SocketComponent) Attach(env *SidecarEnv) error {
	if env == nil || env.SidecarApi == nil || env.Identity == nil {
		return fmt.Errorf("%w: sockets needs the generation's api and identity", errInvalidSettings)
	}
	if env.Identity.NetworkId != self.registrar.networkId {
		return fmt.Errorf("%w: a generation of another network", errInvalidSettings)
	}
	attachmentSeq := self.registrar.attach(env.Ctx, env.SidecarApi.SocketRegistrations, env.Identity.IdentityPublicKey)
	remove := func() {}
	if env.Subprotocol != nil {
		if unsubscribe, err := env.Subprotocol.Subscribe(PushTopicSock, self.registrar.hint); err == nil {
			remove = unsubscribe
		}
	}
	generation, listeners := func() (*socketGeneration, []*SocketListener) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.generationSeq += 1
		self.generation = &socketGeneration{
			ctx:         env.Ctx,
			seq:         self.generationSeq,
			subprotocol: env.Subprotocol,
			sidecarApi:  env.SidecarApi,
			identity:    env.Identity.clone(),
			authorize:   env.Authorize,
		}
		listeners := make([]*SocketListener, 0, len(self.listeners))
		for listener := range self.listeners {
			listeners = append(listeners, listener)
		}
		return self.generation, listeners
	}()
	// each live listener takes its target on this generation's dispatcher
	for _, listener := range listeners {
		listener.attach(generation)
	}
	go func() {
		<-env.Ctx.Done()
		remove()
		self.registrar.detach(attachmentSeq)
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.generation == generation {
				self.generation = nil
			}
		}()
	}()
	return nil
}

// Whether a listener serves, which keeps the daemon up while one lives (§5.8).
func (self *SocketComponent) Active() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return 0 < len(self.listeners)
}

// One live listen of the component as DESIGN-COMPUTE §26.4's sock row reads it (LSTN-M13-04): its namespace and
// canonical name, which only this device's own person and agents read, and the network's own devices by its listeners
// file, sealed.
type SocketListenName struct {
	Namespace SocketNamespace
	Name      string
}

// The component's live listens, by namespace then name: read only, for the listeners list (LSTN-M13-04).
func (self *SocketComponent) Listens() []SocketListenName {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	names := make([]SocketListenName, 0, len(self.listeners))
	for listener := range self.listeners {
		names = append(names, SocketListenName{Namespace: listener.namespace, Name: listener.name})
	}
	slices.SortFunc(names, func(a SocketListenName, b SocketListenName) int {
		if a.Namespace != b.Namespace {
			return int(a.Namespace) - int(b.Namespace)
		}
		return strings.Compare(a.Name, b.Name)
	})
	return names
}

// Installs this device's own evaluation of its config, which admission's step 6 and a dialer's listen check read.
// nil takes it away, and both refuse again.
func (self *SocketComponent) SetPolicy(policy SocketPolicy) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.policy = policy
}

// Installs the network's labels: its own 10-character label, which every stream target names, and the resolver a
// Dial's <net> goes through. A label that is no 10-character label is refused.
func (self *SocketComponent) SetNetworkLabels(labels *SocketNetworkLabels) error {
	if labels == nil || len(labels.Label) != socketNetworkLabelByteCount || !validSocketLabel(labels.Label) {
		return fmt.Errorf("%w: a network label is 10 characters", errInvalidSettings)
	}
	copied := *labels
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.labels = &copied
	return nil
}

// The attached generation, the policy and the labels, as they stand now.
func (self *SocketComponent) current() (*socketGeneration, SocketPolicy, *SocketNetworkLabels) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.generation, self.policy, self.labels
}

// Ends the registrar, after the Sidecar's last generation, and takes the listen kind's Lookup off the host. Never from
// a registration's callback, which runs on the registrar's own goroutine.
func (self *SocketComponent) Close() {
	self.registrar.close()
	if self.configDone != nil {
		<-self.configDone
	}
	if self.removeListenLookup != nil {
		self.removeListenLookup()
	}
}

// Installs the newest K_sock ring of the network's verified config head (§7.9): blinded names register under it, both
// paths through a rotation's overlap, and the set goes at once. A ring of another network is refused.
func (self *SocketComponent) SetKeyRing(ring *SocketKeyRing) error {
	return self.registrar.setKeyRing(ring)
}

// The newest K_sock ring the registrar holds, nil before one is set.
func (self *SocketComponent) currentKeyRing() *SocketKeyRing {
	self.registrar.stateLock.Lock()
	defer self.registrar.stateLock.Unlock()
	return self.registrar.state.ring
}

// The registrar a listener registers through.
func (self *SocketComponent) socketRegistrar() *socketRegistrar {
	return self.registrar
}

// The Sidecar's sockets component, nil when it runs none.
func (self *Sidecar) socketComponent() *SocketComponent {
	leg, ok := self.leg.(*sidecarConnectLeg)
	if !ok {
		return nil
	}
	for _, component := range leg.componentList() {
		if socketComponent, ok := component.(*SocketComponent); ok {
			return socketComponent
		}
	}
	return nil
}

var _ ApprovalSocketKeys = (*Sidecar)(nil)

// The newest K_sock ring of the network's verified config head that this sidecar's sockets component holds, nil
// without the component or before its host installs one (SetKeyRing). An approver's device reads a listen request's
// application name with it (ApprovalSocketKeys; QD-772), and socket_listen's tool derives the name's grant_dst under
// its current keys (SocketListenGrantDst).
func (self *Sidecar) SocketKeyRing() *SocketKeyRing {
	component := self.socketComponent()
	if component == nil {
		return nil
	}
	if component.host != nil {
		component.refreshSocketConfig()
	}
	return component.currentKeyRing()
}
