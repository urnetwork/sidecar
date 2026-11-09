// §22.4's AddSidecar: a running sidecar.Sidecar, NewSidecar's own, on an instance of its own in memory, its client
// generations on the Net's exchange and its api the Net's FakeApi, enrolled from an auth key that api minted and Online,
// which every area's T2 tests start from (CORE-M1-13).
//
// The platform (netSidecarPlatform) stands for connect's PlatformTransport and out-of-band control: it opens each
// generation's Required client on the exchange under the generation's ctx, counts it connected while the platform is
// reachable and the fake api accepts its token, as the platform's auth would, and carries SidecarApi's requests to the
// fake api in process (sidecar.SidecarApiPlatform). A refused token leaves the client unconnected and reports
// AuthorizationClosed, which asks the sidecar's refresher for a refresh, as connect's transport does.
//
// Everything a sidecar logs goes to the Net's capture (CC4), every level up to 1, so §22.7's S1 scan reads it, and the
// fake api hands each token and auth key it mints to the capture as a secret, so a scan looks for them on every leg,
// sidecar_testhooks or not. A test's sidecar sees no credential store of this host's (D-TRUST-3): its host reports
// none, so the build machine's own app state never decides a test.

package sidecartest

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

// How long, in real time, AddSidecar waits for a sidecar to be Online. Every wait is on a monitor; this only stops a
// broken test from hanging, since connect's own timers are real (X9).
const testSidecarOnlineTimeout = 30 * time.Second

// The platform url a test sidecar names: a .example host nothing dials, since its platform is the exchange.
const testSidecarPlatformUrl = "wss://platform.sidecartest.example"

// A test sidecar's host: the instance's store, a memory key store, no token source, and no credential stores.
type testSidecarHost struct {
	store    sidecar.SidecarStore
	keyStore sidecar.SidecarKeyStore

	stateLock sync.Mutex
	stores    []sidecar.SidecarHostCredentialStore
}

func (self *testSidecarHost) Store() sidecar.SidecarStore {
	return self.store
}

func (self *testSidecarHost) KeyStore() sidecar.SidecarKeyStore {
	return self.keyStore
}

func (self *testSidecarHost) TokenSource() sidecar.SidecarTokenSource {
	return nil
}

// What a test set, by default none (sidecar.SidecarHostCredentialScanner).
func (self *testSidecarHost) HostCredentialStores() []sidecar.SidecarHostCredentialStore {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]sidecar.SidecarHostCredentialStore{}, self.stores...)
}

// One client a netSidecarPlatform opened, which counts connected while the platform is reachable and its token is
// accepted.
type netSidecarPlatformClient struct {
	netClient  *NetClient
	authorized bool
	connected  *sidecar.MonitorValue[bool]
}

// The exchange as a sidecar's platform. Safe for concurrent use.
type netSidecarPlatform struct {
	net  *Net
	name string
	api  *FakeApi
	// the newest client opened, nil before one
	newest *sidecar.MonitorValue[*NetClient]

	stateLock sync.Mutex
	reachable bool
	clients   map[*netSidecarPlatformClient]bool
	// the newest client's AuthorizationClosed, nil before one
	authorizationClosed func(cause connect.AuthorizationCloseCause)
}

func newNetSidecarPlatform(net *Net, name string, api *FakeApi) *netSidecarPlatform {
	return &netSidecarPlatform{
		net:       net,
		name:      name,
		api:       api,
		newest:    sidecar.NewMonitorValue[*NetClient](nil),
		reachable: true,
		clients:   map[*netSidecarPlatformClient]bool{},
	}
}

// The fake api's in-process transport, so SidecarApi reaches it with no socket (sidecar.SidecarApiPlatform).
func (self *netSidecarPlatform) ApiTransport() http.RoundTripper {
	return self.api.Transport()
}

// Moves client's connected to what the platform and its token say. Runs under stateLock.
func (self *netSidecarPlatform) updateWithLock(client *netSidecarPlatformClient) {
	client.connected.Set(self.reachable && client.authorized)
}

// Lets the sidecar's clients connect, or cuts them off, as a platform outage would.
func (self *netSidecarPlatform) setReachable(reachable bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.reachable = reachable
	for client := range self.clients {
		self.updateWithLock(client)
	}
}

// Opens one generation's client on the exchange. See sidecar.SidecarPlatform.
func (self *netSidecarPlatform) OpenClient(ctx context.Context, args *sidecar.SidecarPlatformClientArgs) (*sidecar.SidecarPlatformClient, error) {
	clientCtx, cancel := context.WithCancel(ctx)
	netClient := self.net.exchange.addClient(clientCtx, self.name, args.ClientId, args.ClientSettings)
	client := &netSidecarPlatformClient{netClient: netClient, connected: sidecar.NewMonitorValue(false)}
	authorizationClosed := args.PlatformTransportSettings.AuthorizationClosed
	// what the platform's auth does with a token: take it, or refuse it and say so, never in the caller's goroutine
	setAuth := func(auth *connect.ClientAuth) {
		_, clientId, _, minted := self.api.TokenClient(auth.ByJwt)
		accepted := minted && connect.Id(clientId) == args.ClientId && self.api.clientOfToken(auth.ByJwt) != nil
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			client.authorized = accepted
			self.updateWithLock(client)
		}()
		if !accepted && authorizationClosed != nil {
			go authorizationClosed(connect.AuthorizationCloseRejected)
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.clients[client] = true
		self.authorizationClosed = authorizationClosed
	}()
	setAuth(args.Auth)
	self.newest.Set(netClient)
	var closeOnce sync.Once
	return &sidecar.SidecarPlatformClient{
		Client:  netClient.Client,
		SetAuth: setAuth,
		Connected: func() (bool, <-chan struct{}) {
			return client.connected.Get()
		},
		CloseAndWait: func(ctx context.Context) error {
			var err error
			closeOnce.Do(func() {
				func() {
					self.stateLock.Lock()
					defer self.stateLock.Unlock()
					delete(self.clients, client)
				}()
				cancel()
				err = netClient.Client.CloseAndWait(ctx)
			})
			return err
		},
	}, nil
}

// A logger whose lines go to the capture up to verbosity maxLevel, so connect's per-frame tracing stays out of a
// test's memory while every line a host might keep on is scanned.
type testSidecarLogger struct {
	capture  sidecar.Logger
	maxLevel int32
}

func (self *testSidecarLogger) Info(args ...any) {
	self.capture.Info(args...)
}

func (self *testSidecarLogger) Infof(format string, args ...any) {
	self.capture.Infof(format, args...)
}

func (self *testSidecarLogger) Warningf(format string, args ...any) {
	self.capture.Warningf(format, args...)
}

func (self *testSidecarLogger) Errorf(format string, args ...any) {
	self.capture.Errorf(format, args...)
}

func (self *testSidecarLogger) V(level int32) sidecar.Verbose {
	if self.maxLevel < level {
		return sidecar.NewNoopLogger().V(level)
	}
	return self.capture.V(level)
}

// One sidecar on the Net. Its durable state, the memory backend and key store, outlives Restart, as a disk does.
type TestSidecar struct {
	Name     string
	Settings *sidecar.SidecarSettings
	Api      *FakeApi

	net      *Net
	platform *netSidecarPlatform
	backend  sidecar.SidecarStoreBackend
	keyStore sidecar.SidecarKeyStore

	stateLock sync.Mutex
	host      *testSidecarHost
	sidecar   *sidecar.Sidecar
	instance  *sidecar.SidecarInstance
	cancel    context.CancelFunc
	networkId sidecar.Id
	closed    bool
}

// The running Sidecar.
func (self *TestSidecar) Sidecar() *sidecar.Sidecar {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.sidecar
}

// Its instance, which holds U and the network's keychain.
func (self *TestSidecar) Instance() *sidecar.SidecarInstance {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.instance
}

// The network it enrolled in, zero before.
func (self *TestSidecar) NetworkId() sidecar.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.networkId
}

// The newest generation's client on the exchange, nil before one opened.
func (self *TestSidecar) Client() *NetClient {
	return self.platform.newest.Value()
}

// sidecar.json's record of the network it enrolled in, false before.
func (self *TestSidecar) NetworkRecord() (sidecar.SidecarNetworkRecord, bool) {
	networkId := self.NetworkId()
	for _, record := range self.Instance().Networks() {
		if record.NetworkId == networkId {
			return record, true
		}
	}
	return sidecar.SidecarNetworkRecord{}, false
}

// Sets what this host's credential stores hold for D-TRUST-3's check (plan-CORE-host-store-refusal). nil: none.
func (self *TestSidecar) SetHostCredentialStores(stores []sidecar.SidecarHostCredentialStore) {
	self.stateLock.Lock()
	host := self.host
	self.stateLock.Unlock()
	host.stateLock.Lock()
	defer host.stateLock.Unlock()
	host.stores = append([]sidecar.SidecarHostCredentialStore{}, stores...)
}

// Lets the sidecar's clients reach the platform, or cuts them off: Online and Offline follow.
func (self *TestSidecar) SetPlatformReachable(reachable bool) {
	self.platform.setReachable(reachable)
}

// Reports a refused credential on the newest client's connection, as connect's transport does when the platform
// closes it for its authorization (connect.AuthorizationCloseRejected): the sidecar's refresher refreshes at once.
func (self *TestSidecar) CloseAuthorization() {
	self.platform.stateLock.Lock()
	authorizationClosed := self.platform.authorizationClosed
	self.platform.stateLock.Unlock()
	if authorizationClosed != nil {
		authorizationClosed(connect.AuthorizationCloseRejected)
	}
}

// Enrolls in networkId from a one-use auth key the api mints for it, as `ur connect --token` does.
func (self *TestSidecar) Enroll(ctx context.Context, networkId sidecar.Id) error {
	authKey := self.Api.NewAuthKey(&FakeApiAuthKeyArgs{NetworkId: networkId})
	return self.EnrollWith(ctx, &sidecar.SidecarEnrollCredential{AuthKey: authKey})
}

// Enrolls from credential, which Enroll erases.
func (self *TestSidecar) EnrollWith(ctx context.Context, credential *sidecar.SidecarEnrollCredential) error {
	authKey := credential.AuthKey
	networkId := sidecar.Id{}
	if parsed, err := sidecar.ParseAuthKey(authKey); err == nil {
		if keyNetworkId, ok := self.Api.authKeyNetwork(parsed.Bearer()); ok {
			networkId = keyNetworkId
		}
		parsed.Erase()
	}
	if err := self.Sidecar().Enroll(ctx, credential); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networkId = networkId
	return nil
}

// Waits until the sidecar's state is state, or ctx ends.
func (self *TestSidecar) AwaitState(ctx context.Context, state sidecar.SidecarState) error {
	running := self.Sidecar()
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
			return fmt.Errorf("%s is %s (%s), not %s: %w", self.Name, status.State, status.Reason, state, ctx.Err())
		case <-changed:
		}
	}
}

// Waits until the sidecar's state is state and its reason reason, or ctx ends.
func (self *TestSidecar) AwaitStateReason(ctx context.Context, state sidecar.SidecarState, reason sidecar.SidecarStateReason) error {
	running := self.Sidecar()
	changed := make(chan struct{}, 1)
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
		if status.State == state && status.Reason == reason {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s is %s (%s), not %s (%s): %w", self.Name, status.State, status.Reason, state, reason, ctx.Err())
		case <-changed:
		}
	}
}

// Starts the Sidecar and its instance on the durable state, unlocking U through the key store, which makes U on a first
// run (D-CORE-15).
func (self *TestSidecar) start() error {
	ctx, cancel := context.WithCancel(self.net.ctx)
	instance, err := sidecar.NewSidecarInstance(ctx, &sidecar.SidecarInstanceArgs{
		Backend:  self.backend,
		KeyStore: self.keyStore,
		Settings: self.Settings,
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
	var stores []sidecar.SidecarHostCredentialStore
	if self.host != nil {
		stores = self.host.HostCredentialStores()
	}
	host := &testSidecarHost{store: instance.Store(nil), keyStore: self.keyStore, stores: stores}
	running, err := sidecar.NewSidecar(ctx, host, nil, self.Settings)
	if err != nil {
		instance.Close()
		cancel()
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.host = host
	self.sidecar = running
	self.instance = instance
	self.cancel = cancel
	return nil
}

// Stops the Sidecar and its instance and waits for them, keeping the durable state.
func (self *TestSidecar) stop() {
	self.stateLock.Lock()
	running := self.sidecar
	instance := self.instance
	cancel := self.cancel
	self.stateLock.Unlock()
	if running != nil {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), testSidecarOnlineTimeout)
		running.CloseAndWait(closeCtx)
		closeCancel()
	}
	if instance != nil {
		instance.Close()
	}
	if cancel != nil {
		cancel()
	}
}

// Stops the sidecar as a killed daemon is, and starts it again on its durable state alone: the backend and the key
// store.
func (self *TestSidecar) Restart() error {
	self.stop()
	return self.start()
}

// Ends the sidecar, waiting for its generation and components. Safe to call again.
func (self *TestSidecar) Close() {
	self.stateLock.Lock()
	if self.closed {
		self.stateLock.Unlock()
		return
	}
	self.closed = true
	self.stateLock.Unlock()
	self.stop()
}

// The Net's api, which AddSidecar enrolls through, made on first use on the Net's host.
func (self *Net) Api() (*FakeApi, error) {
	self.stateLock.Lock()
	api := self.api
	self.stateLock.Unlock()
	if api != nil {
		return api, nil
	}
	api, err := self.AddApi(nil)
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.api == nil {
		self.api = api
	}
	return self.api, nil
}

// The network AddSidecar enrolls in, made on first use.
func (self *Net) DefaultNetworkId() sidecar.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.defaultNetworkId == (sidecar.Id{}) {
		self.defaultNetworkId = sidecar.NewId()
	}
	return self.defaultNetworkId
}

// Fills settings for a sidecar named name on this Net: the api's urls and .example urls for the services, the Net's
// clock, the capture's logger, a keychain that never auto-locks, connect's client timeouts for a process with no real
// network in it (netClientSettings, made a sidecar's by ApplySidecarClientSettings), and the exchange as platform.
func (self *Net) fillTestSidecarSettings(name string, settings *sidecar.SidecarSettings, api *FakeApi, platform *netSidecarPlatform) {
	settings.ApiUrl = api.Origin()
	settings.AuthUrl = api.AuthOrigin()
	settings.PlatformUrl = testSidecarPlatformUrl
	settings.EvsUrl = api.ServiceOrigin("evs")
	settings.GkmUrl = api.ServiceOrigin("gkm")
	settings.SocketsUrl = api.ServiceOrigin("sockets")
	settings.DnsUrl = api.ServiceOrigin("dns")
	settings.Clock = self.clock
	settings.Log = &testSidecarLogger{capture: self.capture.Logger("sidecar " + name), maxLevel: 1}
	settings.KeychainSettings.AutoLockTimeout = 0
	clientSettings := netClientSettings()
	clientSettings.DefaultTransferOpts = settings.Connect.ClientSettings.DefaultTransferOpts
	sidecar.ApplySidecarClientSettings(clientSettings)
	settings.Connect.ClientSettings = clientSettings
	settings.Connect.Platform = platform
}

// A running sidecar on its own memory instance, Unenrolled, on the Net's api and exchange. settings nil takes
// DefaultSidecarSettings; either way fillTestSidecarSettings sets what ties it to this Net. The Net closes it.
func (self *Net) StartSidecar(name string, settings *sidecar.SidecarSettings) (*TestSidecar, error) {
	api, err := self.Api()
	if err != nil {
		return nil, err
	}
	if settings == nil {
		settings = sidecar.DefaultSidecarSettings()
	}
	platform := newNetSidecarPlatform(self, name, api)
	self.fillTestSidecarSettings(name, settings, api, platform)
	testSidecar := &TestSidecar{
		Name:     name,
		Settings: settings,
		Api:      api,
		net:      self,
		platform: platform,
		backend:  sidecar.NewSidecarMemoryBackend(),
		keyStore: sidecar.NewSidecarMemoryKeyStore(),
	}
	if err := testSidecar.start(); err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.testSidecars = append(self.testSidecars, testSidecar)
	return testSidecar, nil
}

// §22.4's AddSidecar: a sidecar enrolled in the Net's default network and Online. See AddSidecarIn.
func (self *Net) AddSidecar(name string, settings *sidecar.SidecarSettings) (*TestSidecar, error) {
	return self.AddSidecarIn(name, self.DefaultNetworkId(), settings)
}

// A sidecar enrolled in networkId through the Net's api, from a one-use auth key, and Online on the exchange, its
// first client generation bound. Nothing is admitted: a SidecarAdmit is the config repo's (§5.6).
func (self *Net) AddSidecarIn(name string, networkId sidecar.Id, settings *sidecar.SidecarSettings) (*TestSidecar, error) {
	testSidecar, err := self.StartSidecar(name, settings)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(self.ctx, testSidecarOnlineTimeout)
	defer cancel()
	if err := testSidecar.AwaitState(ctx, sidecar.SidecarStateUnenrolled); err != nil {
		return nil, err
	}
	if err := testSidecar.Enroll(ctx, networkId); err != nil {
		return nil, fmt.Errorf("%s did not enroll: %w", name, err)
	}
	if err := testSidecar.AwaitState(ctx, sidecar.SidecarStateOnline); err != nil {
		return nil, err
	}
	return testSidecar, nil
}

// Closes every sidecar the Net started.
func (self *Net) closeTestSidecars() {
	self.stateLock.Lock()
	testSidecars := self.testSidecars
	self.testSidecars = nil
	self.stateLock.Unlock()
	for _, testSidecar := range testSidecars {
		testSidecar.Close()
	}
}

// The network an auth key the api minted enrolls in.
func (self *FakeApi) authKeyNetwork(bearer string) (sidecar.Id, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	authKey := self.core.authKeys[bearer]
	if authKey == nil {
		return sidecar.Id{}, false
	}
	return authKey.networkId, true
}
