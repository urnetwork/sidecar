//go:build !sidecar_http

// The evs SidecarComponent (§5.4): an EvsClient on a Sidecar's client generations. The client itself lives for the
// network, holding its pins and read records across generations; the component follows each generation's env so a
// hint on evs:<repo_id> (§11.10) reaches the client through the generation's own queue, with zero wait on the way in
// (D-CORE-3), and ends with it.
//
// Hints arrive through the generation's Subprotocol.Subscribe on the evs: family (§6.8): a notice carrying an
// EvsHeadChanged goes to ReceiveHint, and a resync notice changes nothing here, since every read verifies whatever it
// finds. Hints carry no authority either way.
//
// connect legs only: the sidecar_http leg runs no component (§18.10). Safe for concurrent use.

package sidecar

import (
	"context"
	"fmt"
	"strings"
	"sync"

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
			if notice.Kind == uint32(protocol.MessageType_EVS_HEAD_CHANGED) && 0 < len(notice.Hint) {
				self.ReceiveHint(notice.Topic, notice.Version, notice.Hint)
			}
		}); err == nil {
			remove = unsubscribe
		}
	}
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

// Ends the component: no generation follows.
func (self *EvsComponent) Close() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.env = nil
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
	})
}

// The args an EvsClient takes from this Sidecar for the network it is enrolled in: the service url, SidecarApi's
// transport, ServiceToken, Sign, the identity, the evs component's sealed directory, events, the clock, the log and
// settings.Evs. gkm, the verified config state and the statement poster are the caller's, from KEYS, TEAM and
// CORE-M2-02 as each lands.
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
	}, nil
}
