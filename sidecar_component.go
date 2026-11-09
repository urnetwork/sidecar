//go:build !sidecar_http

// §5.4's components: evs, sockets, mail, bridge and tls each run on a Sidecar's client generations through one seam.
// A component attaches to each generation with its own SidecarEnv, whose Ctx ends with the generation, whose Secrets
// and Store are its own namespace of the network's keychain and its own sealed directory (§5.9's <component>/), and
// whose queue is its own: complete envelopes a source's worker hands on wait there with zero wait on the way in,
// dropped and counted when full (D-CORE-3). Attach runs outside every lock (connect/CODESTYLE.md:234), on the run
// loop, so it returns promptly and starts its own goroutines on Ctx.
//
// These name connect types, so they are on connect legs only: the sidecar_http leg runs no component (§18.10).

package sidecar

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What a component name may not be: the core's own namespace and class names (§5.9), the index cache's file class and
// directory among them.
var sidecarReservedComponentNames = []string{sidecarCoreSecretsNamespace, keychainRecordsClass, sidecarSubprotocolStoreName,
	SidecarSearchFileClass}

// One of a Sidecar's components (§5.4).
type SidecarComponent interface {
	// "evs", "sockets", "mail", "bridge", "tls": a seal class's form ([a-z0-9-], not starting with -), unique
	// among the Sidecar's components, naming its keychain namespace and its directory.
	Name() string
	// Starts the component's part of one client generation. Called once per generation, outside every lock;
	// returns promptly, and anything it starts ends with env.Ctx. An error detaches the component from this
	// generation only.
	Attach(env *SidecarEnv) error
	// Ends the component for good: at the Sidecar's close, after its last generation, or at its removal.
	Close()
}

// Optional beside SidecarComponent: whether the component keeps its daemon from idling out, as mail, sockets and bridge
// do while they serve (§5.8). The daemon's idle rule asks each component this, never a list of names
// (daemon_idle.go). A component without it keeps nothing up.
type SidecarActiveComponent interface {
	// Whether it serves now. Called from the daemon's idle loop: it must not block.
	Active() bool
}

// Whether any listed component is active.
func (self *sidecarConnectLeg) componentsActive() bool {
	for _, component := range self.componentList() {
		if active, ok := component.(SidecarActiveComponent); ok && active.Active() {
			return true
		}
	}
	return false
}

// One component's view of one client generation (§5.4). Immutable: a new generation brings a new env.
type SidecarEnv struct {
	// Ends with the generation, or when the component is removed.
	Ctx context.Context
	// The generation's Required client (I-3).
	Client *connect.Client
	// connect's api on the generation's token.
	Api *connect.BringYourApi
	// The Sidecar's own api, on the same token, with the ClientKey's proofs.
	SidecarApi *SidecarApi
	// Ids, generation and public keys, never a private key.
	Identity *SidecarIdentity
	// The component's namespace of this network's keychain.ur.
	Secrets SidecarSecrets
	// The component's sealed directory, its files under its own class.
	Store SidecarStore
	// §6's dispatcher on the generation's client: inline, zero-wait handlers, and streams.
	Subprotocol *Subprotocol
	// The outward-action gate (I-8): the Sidecar's Authorize, which refuses every action until §16's track installs
	// its gate (sidecar_gate.go).
	Authorize func(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error
	Log       Logger

	queue *sidecarComponentQueue
}

// Hands run to this component's queue, which byteCount bytes of an envelope stand behind, without waiting: false when
// the queue is full, the item alone is past its byte bound, or the generation has ended, and the caller drops what
// it holds. The queue's worker runs each item in order with a ctx that ends with the generation. A source's dispatch
// worker calls this, so a slow component holds up nothing else (D-CORE-3).
func (self *SidecarEnv) Enqueue(byteCount int, run func(ctx context.Context)) bool {
	if self.queue == nil || run == nil {
		return false
	}
	return self.queue.offer(byteCount, run)
}

// Whether name may name a component.
func checkSidecarComponentName(name string) error {
	if !isSealClass(name) || slices.Contains(sidecarReservedComponentNames, name) {
		return fmt.Errorf("%w: a component name is [a-z0-9-] and not one of the core's", errInvalidSettings)
	}
	return nil
}

// Adds component to the Sidecar, attaching it to the running generation, if any, and to each one after; the answer
// removes it, ending its env's Ctx, waiting for its queue, and calling its Close. A name already taken is refused,
// as is a Sidecar that has closed.
func (self *Sidecar) AddComponent(component SidecarComponent) (func(), error) {
	leg, ok := self.leg.(*sidecarConnectLeg)
	if !ok {
		return nil, fmt.Errorf("%w: this Sidecar runs no components", ErrSidecarClosed)
	}
	if self.isClosed() {
		return nil, ErrSidecarClosed
	}
	if err := leg.addComponent(component); err != nil {
		return nil, err
	}
	self.wake()
	var once sync.Once
	return func() {
		once.Do(func() {
			if !leg.removeComponent(component.Name()) {
				return
			}
			if generation := self.runningGeneration(); generation != nil {
				if connectGeneration, ok := generation.leg.(*sidecarConnectGeneration); ok {
					connectGeneration.detach(component.Name())
				}
			}
			component.Close()
		})
	}, nil
}

// One component attached to one generation.
type sidecarComponentAttachment struct {
	component SidecarComponent
	cancel    context.CancelFunc
	queue     *sidecarComponentQueue
}

// Attaches each listed component the generation does not hold, and detaches each it holds that is no longer listed.
func (self *sidecarConnectGeneration) reconcileComponents() {
	listed := self.leg.componentList()
	attachedNames := func() []string {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		names := []string{}
		for name := range self.attachments {
			names = append(names, name)
		}
		return names
	}()
	for _, name := range attachedNames {
		if !slices.ContainsFunc(listed, func(component SidecarComponent) bool { return component.Name() == name }) {
			self.detach(name)
		}
	}
	for _, component := range listed {
		self.attach(component)
	}
}

// Attaches component, unless it is attached, the generation is closing, or it was removed meanwhile.
func (self *sidecarConnectGeneration) attach(component SidecarComponent) {
	name := component.Name()
	networkId := self.generation.networkId
	store, err := self.leg.sidecar.instance.Store(&networkId).Directory(name, name)
	if err != nil {
		// a name checkSidecarComponentName took is a store name and a class, so this does not happen
		self.leg.sidecar.log.Errorf("[sidecar]component %s has no store: %s", name, err)
		return
	}
	var env *SidecarEnv
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed || self.attachments[name] != nil || !self.leg.listed(name) {
			return
		}
		componentCtx, cancel := context.WithCancel(self.generation.ctx)
		queue := newSidecarComponentQueue(
			componentCtx,
			self.leg.sidecar.settings.ComponentQueueMessageCount,
			int64(self.leg.sidecar.settings.ComponentQueueByteCount),
			self.leg.sidecar.stats.componentQueueCounters(name),
			self.leg.sidecar.log,
		)
		self.attachments[name] = &sidecarComponentAttachment{component: component, cancel: cancel, queue: queue}
		env = &SidecarEnv{
			Ctx:         componentCtx,
			Client:      self.platformClient.Client,
			Api:         self.api,
			SidecarApi:  self.leg.sidecar.sidecarApi,
			Identity:    self.generation.identity.clone(),
			Secrets:     self.leg.sidecar.instance.secrets(networkId, name),
			Store:       store,
			Subprotocol: self.subprotocol,
			Authorize:   self.leg.sidecar.Authorize,
			Log:         self.leg.sidecar.log,
			queue:       queue,
		}
	}()
	if env == nil {
		return
	}
	testHookBarrier("sidecar.attach.before", name)
	err = component.Attach(env)
	testHookBarrier("sidecar.attach.after", name)
	if err != nil {
		self.leg.sidecar.log.Warningf("[sidecar]component %s did not attach: %s", name, err)
		self.detach(name)
	}
}

// Ends a component's part of this generation and waits for its queue's worker.
func (self *sidecarConnectGeneration) detach(name string) {
	var attachment *sidecarComponentAttachment
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		attachment = self.attachments[name]
		delete(self.attachments, name)
	}()
	if attachment == nil {
		return
	}
	attachment.cancel()
	attachment.queue.closeAndWait()
}

// Detaches every component, refusing any later attach.
func (self *sidecarConnectGeneration) detachAll() {
	names := func() []string {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		names := []string{}
		for name := range self.attachments {
			names = append(names, name)
		}
		return names
	}()
	for _, name := range names {
		self.detach(name)
	}
}

// The components, in the order they were added.
func (self *sidecarConnectLeg) componentList() []SidecarComponent {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.components)
}

// Whether a component of name is listed.
func (self *sidecarConnectLeg) listed(name string) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.ContainsFunc(self.components, func(component SidecarComponent) bool {
		return component.Name() == name
	})
}

// Lists component, refusing a nil one, a name taken or invalid, and a leg that has closed.
func (self *sidecarConnectLeg) addComponent(component SidecarComponent) error {
	if component == nil {
		return fmt.Errorf("%w: no component", errInvalidSettings)
	}
	name := component.Name()
	if err := checkSidecarComponentName(name); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return ErrSidecarClosed
	}
	if slices.ContainsFunc(self.components, func(other SidecarComponent) bool { return other.Name() == name }) {
		return fmt.Errorf("%w: a component named %s is there", errInvalidSettings, name)
	}
	self.components = append(self.components, component)
	return nil
}

// Takes the component of name off the list, reporting whether it was there.
func (self *sidecarConnectLeg) removeComponent(name string) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	before := len(self.components)
	self.components = slices.DeleteFunc(self.components, func(component SidecarComponent) bool {
		return component.Name() == name
	})
	return len(self.components) < before
}

// The components that re-register after a restore (§19.10).
func (self *sidecarConnectLeg) restorers() []SidecarRestorer {
	restorers := []SidecarRestorer{}
	for _, component := range self.componentList() {
		if restorer, ok := component.(SidecarRestorer); ok {
			restorers = append(restorers, restorer)
		}
	}
	return restorers
}
