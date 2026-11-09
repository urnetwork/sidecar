//go:build !sidecar_http

// The evs SidecarComponent (§5.4): an EvsClient on a Sidecar's client generations. The client itself lives for the
// network, holding its pins and read records across generations; the component follows each generation's env so a
// hint on evs:<repo_id> (§11.10) reaches the client through the generation's own queue, with zero wait on the way in
// (D-CORE-3), and ends with it.
//
// Hints arrive by PROTO-M1-06's Subprotocol.Subscribe on the evs: family, which is not on sidecar yet: until it lands
// nothing calls ReceiveHint, so reads find a moved head only by reading, which every read verifies anyway. Hints carry
// no authority either way (§6.8).
//
// connect legs only: the sidecar_http leg runs no component (§18.10). Safe for concurrent use.

package sidecar

import (
	"context"
	"fmt"
	"strings"
	"sync"
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

// Follows one generation: its queue carries hints until env.Ctx ends.
func (self *EvsComponent) Attach(env *SidecarEnv) error {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.env = env
	}()
	go func() {
		<-env.Ctx.Done()
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
	}, nil
}
