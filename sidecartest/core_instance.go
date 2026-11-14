// Several networks' Sidecars on one instance, as ur daemon hosts them (CORE-M6-01): one SidecarInstance in memory, so one
// U opens every network's keychain, and per network a Sidecar of its own, its client generations on the Net's exchange
// and its api the Net's FakeApi, each enrolled from an auth key that api minted and Online. Restart stops every Sidecar
// and the instance and starts them again on the durable state alone, a Sidecar per network sidecar.json records, as the
// daemon does at its start. TestInstanceArgs.Start runs on each Sidecar a start makes, before it enrolls or comes
// Online, as the daemon's composition does with a network's config follower.
//
// The Net does not close an instance: a test closes it before the Net. Safe for concurrent use.

package sidecartest

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/urnetwork/sidecar"
)

// What a TestInstance starts its Sidecars with.
type TestInstanceArgs struct {
	// Each Sidecar's settings, nil for DefaultSidecarSettings; the Net fills what ties them to it.
	Settings func() *sidecar.SidecarSettings
	// Runs on each Sidecar a start makes, the further one an enrollment takes and one per recorded network at a
	// restart, before it enrolls or comes Online. An error ends that start. Nil for none.
	Start func(running *sidecar.Sidecar) error
}

// One instance hosting a Sidecar per network (the file's comment).
type TestInstance struct {
	Name string

	net      *Net
	api      *FakeApi
	args     *TestInstanceArgs
	backend  sidecar.SidecarStoreBackend
	keyStore sidecar.SidecarKeyStore

	stateLock sync.Mutex
	instance  *sidecar.SidecarInstance
	// ends with the running instance, and every Sidecar it started with it
	ctx      context.Context
	cancel   context.CancelFunc
	sidecars map[sidecar.Id]*sidecar.Sidecar
	// every Sidecar the running instance started, an unenrolled one among them, which a stop closes
	running []*sidecar.Sidecar
	// names each Sidecar's clients on the exchange apart
	startCount int
	closed     bool
}

// An instance on its own memory backend and key store, unlocked by the key store, hosting no network yet. args may be
// nil.
func (self *Net) StartInstance(name string, args *TestInstanceArgs) (*TestInstance, error) {
	api, err := self.Api()
	if err != nil {
		return nil, err
	}
	if args == nil {
		args = &TestInstanceArgs{}
	}
	testInstance := &TestInstance{
		Name:     name,
		net:      self,
		api:      api,
		args:     args,
		backend:  sidecar.NewSidecarMemoryBackend(),
		keyStore: sidecar.NewSidecarMemoryKeyStore(),
	}
	if err := testInstance.start(); err != nil {
		return nil, err
	}
	return testInstance, nil
}

// A Sidecar's settings, filled for this Net, with a platform of its own on the exchange.
func (self *TestInstance) newSettings() (*sidecar.SidecarSettings, string) {
	self.stateLock.Lock()
	self.startCount += 1
	name := fmt.Sprintf("%s %d", self.Name, self.startCount)
	self.stateLock.Unlock()
	var settings *sidecar.SidecarSettings
	if self.args.Settings != nil {
		settings = self.args.Settings()
	}
	if settings == nil {
		settings = sidecar.DefaultSidecarSettings()
	}
	self.net.fillTestSidecarSettings(name, settings, self.api, newNetSidecarPlatform(self.net, name, self.api))
	return settings, name
}

// Starts the instance on the durable state, unlocks U through the key store, and starts a Sidecar per recorded network.
func (self *TestInstance) start() error {
	ctx, cancel := context.WithCancel(self.net.ctx)
	instanceSettings, _ := self.newSettings()
	instance, err := sidecar.NewSidecarInstance(ctx, &sidecar.SidecarInstanceArgs{
		Backend:  self.backend,
		KeyStore: self.keyStore,
		Settings: instanceSettings,
	})
	if err != nil {
		cancel()
		return err
	}
	if err := instance.Unlock(nil); err != nil {
		instance.Close()
		cancel()
		return err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.instance = instance
		self.ctx = ctx
		self.cancel = cancel
		self.sidecars = map[sidecar.Id]*sidecar.Sidecar{}
		self.running = nil
	}()
	for _, record := range instance.Networks() {
		networkId := record.NetworkId
		running, err := self.startSidecar(ctx, instance, &networkId)
		if err != nil {
			self.stop()
			return fmt.Errorf("network %s: %w", networkId, err)
		}
		self.stateLock.Lock()
		self.sidecars[networkId] = running
		self.stateLock.Unlock()
	}
	return nil
}

// A Sidecar on the instance's store of networkId, nil for one that enrolls next, with Start run on it.
func (self *TestInstance) startSidecar(ctx context.Context, instance *sidecar.SidecarInstance, networkId *sidecar.Id) (*sidecar.Sidecar, error) {
	settings, _ := self.newSettings()
	host := &testSidecarHost{store: instance.Store(networkId), keyStore: self.keyStore}
	running, err := sidecar.NewSidecar(ctx, host, nil, settings)
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	self.running = append(self.running, running)
	self.stateLock.Unlock()
	if self.args.Start != nil {
		if err := self.args.Start(running); err != nil {
			return nil, err
		}
	}
	return running, nil
}

// Enrolls a further network's Sidecar on the instance from a one-use auth key the api mints for networkId, recording
// anchor as an invite's where it is not nil, and waits for it to be Online.
func (self *TestInstance) AddSidecarIn(networkId sidecar.Id, anchor *sidecar.SidecarEnrollAnchor) (*sidecar.Sidecar, error) {
	ctx, cancel := context.WithTimeout(self.net.ctx, testSidecarOnlineTimeout)
	defer cancel()
	instance, instanceCtx, err := func() (*sidecar.SidecarInstance, context.Context, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed || self.instance == nil {
			return nil, nil, errors.New("the instance is closed")
		}
		if self.sidecars[networkId] != nil {
			return nil, nil, fmt.Errorf("the instance hosts network %s already", networkId)
		}
		return self.instance, self.ctx, nil
	}()
	if err != nil {
		return nil, err
	}
	running, err := self.startSidecar(instanceCtx, instance, nil)
	if err != nil {
		return nil, err
	}
	if err := AwaitSidecarState(ctx, running, sidecar.SidecarStateUnenrolled); err != nil {
		return nil, err
	}
	credential := &sidecar.SidecarEnrollCredential{
		AuthKey: self.api.NewAuthKey(&FakeApiAuthKeyArgs{NetworkId: networkId}),
		Anchor:  anchor,
	}
	if err := running.Enroll(ctx, credential); err != nil {
		return nil, fmt.Errorf("network %s did not enroll: %w", networkId, err)
	}
	if err := AwaitSidecarState(ctx, running, sidecar.SidecarStateOnline); err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.sidecars[networkId] = running
	return running, nil
}

// The Sidecar hosting networkId, nil for none.
func (self *TestInstance) Sidecar(networkId sidecar.Id) *sidecar.Sidecar {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.sidecars[networkId]
}

// The instance, which holds U and every network's keychain.
func (self *TestInstance) Instance() *sidecar.SidecarInstance {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.instance
}

// Stops every Sidecar and the instance, as a killed daemon is, and starts them again on the durable state alone, each
// recorded network's Sidecar through Start. Waits for each to be Online.
func (self *TestInstance) Restart() error {
	self.stop()
	if err := self.start(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(self.net.ctx, testSidecarOnlineTimeout)
	defer cancel()
	self.stateLock.Lock()
	sidecars := []*sidecar.Sidecar{}
	for _, running := range self.sidecars {
		sidecars = append(sidecars, running)
	}
	self.stateLock.Unlock()
	for _, running := range sidecars {
		if err := AwaitSidecarState(ctx, running, sidecar.SidecarStateOnline); err != nil {
			return err
		}
	}
	return nil
}

// Stops every Sidecar and the instance, keeping the durable state.
func (self *TestInstance) stop() {
	running, instance, cancel := func() ([]*sidecar.Sidecar, *sidecar.SidecarInstance, context.CancelFunc) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		running, instance, cancel := self.running, self.instance, self.cancel
		self.running, self.instance, self.ctx, self.cancel = nil, nil, nil, nil
		self.sidecars = map[sidecar.Id]*sidecar.Sidecar{}
		return running, instance, cancel
	}()
	for _, each := range running {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), testSidecarOnlineTimeout)
		each.CloseAndWait(closeCtx)
		closeCancel()
	}
	if instance != nil {
		instance.Close()
	}
	if cancel != nil {
		cancel()
	}
}

// Ends every Sidecar and the instance. Safe to call again.
func (self *TestInstance) Close() {
	self.stateLock.Lock()
	if self.closed {
		self.stateLock.Unlock()
		return
	}
	self.closed = true
	self.stateLock.Unlock()
	self.stop()
}

// Waits until running's state is state, or ctx ends.
func AwaitSidecarState(ctx context.Context, running *sidecar.Sidecar, state sidecar.SidecarState) error {
	changed := make(chan struct{}, 1)
	// subscribed before the read, so a move between them wakes the wait
	remove := running.AddEventCallback(func(event sidecar.SidecarEvent) {
		if event.Kind != sidecar.SidecarEventState {
			return
		}
		select {
		case changed <- struct{}{}:
		default:
		}
	})
	defer remove()
	for {
		status := running.Status()
		if status.State == state {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("a sidecar is %s (%s), not %s: %w", status.State, status.Reason, state, ctx.Err())
		case <-changed:
		}
	}
}
