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
// connect legs only: the sidecar_http leg runs no component (§18.10). Safe for concurrent use.

package sidecar

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The evs component.
type EvsComponent struct {
	client *EvsClient

	stateLock sync.Mutex
	// the running generation's env, nil between generations
	env *SidecarEnv
}

// The component of client, which AddComponent or NewSidecar attaches.
func NewEvsComponent(client *EvsClient) *EvsComponent {
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

// The args an EvsClient takes from this Sidecar for the network it is enrolled in: the service url, SidecarApi's
// transport, ServiceToken, Sign, the identity, the evs component's sealed directory, events, the clock, the log,
// settings.Evs, and the team directory's hooks around a create (§16.11's default and private rows, QD-748). gkm, the
// verified config state and the statement poster are the caller's, from KEYS, TEAM and CORE-M2-02 as each lands.
func (self *Sidecar) EvsClientArgs(gkm GkmClient, config EvsConfigFunction, fileStatement EvsFileStatementFunction) (*EvsClientArgs, error) {
	networkId := self.enrolledNetworkId()
	if networkId == nil {
		return nil, fmt.Errorf("%w: evs needs an enrolled network", errInvalidSettings)
	}
	store, err := self.instance.Store(networkId).Directory(evsComponentName, evsComponentName)
	if err != nil {
		return nil, err
	}
	return &EvsClientArgs{
		NetworkId:     *networkId,
		EvsUrl:        self.settings.EvsUrl,
		Transport:     self.sidecarApi.Transport(),
		ServiceToken:  self.ServiceToken,
		Sign:          self.Sign,
		Identity:      self.currentIdentity,
		Gkm:           gkm,
		Store:         store,
		Config:        config,
		FileStatement: fileStatement,
		Emit:          self.emitEvent,
		Clock:         self.clock,
		Log:           self.log,
		Settings:      self.settings.Evs,
		RepoCreated:   self.announceCreatedRepo,
		PrivateCreate: self.readyPrivateRepo,
	}, nil
}
