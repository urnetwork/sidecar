//go:build !sidecar_http

// NewSidecar on connect legs (§5.4, D-CORE-1, D-CORE-2): a running Sidecar with its components, whose client
// generations are its own Required connect clients (I-3, D-CORE-4), never the sdk device client's (owner decision 4)
// and never Opportunistic. Each generation, modeled on sdk/device_local_provider.go:237-330, is a client on the
// ClientKey seed from the keychain, the out-of-band control and PlatformTransport its SidecarPlatform opens with
// ClientAuth{ByJwt, InstanceId, AppVersion, ClientInfo, StreamLeaseVersion: 1}, AuthorizationClosed wired to the
// refresher, a BringYourApi on the same token, and §6's Subprotocol, which constructing registers on id 21842. It
// provides Network only; Service and FriendsAndFamily are their owners' to add, and Public never (§6).
//
// The persisted connect InstanceId (sidecar.json's network record) keeps the resident across restarts (§5.9). A
// generation's client, transport, dispatcher and components end with its ctx, and its closeAndWait joins them.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"
)

// The network directory and seal class of §6's dispatcher's own state: PROTO-M2-01's generation floors, and the
// first-use pins PROTO-M1-04 kept before them, which the admission check drops.
const sidecarSubprotocolStoreName = "subprotocol"

// How a client generation reaches the platform. Nil in SidecarConnectSettings.Platform is connect's own: an
// ApiOutOfBandControl to ApiUrl and a PlatformTransport to PlatformUrl. sidecartest's Net stands its in-process
// exchange in here, so T2 runs the Sidecar a host runs. Implementations are safe for concurrent use.
type SidecarPlatform interface {
	// A client for one generation, connecting as args.Auth, until ctx ends or the answer's CloseAndWait.
	OpenClient(ctx context.Context, args *SidecarPlatformClientArgs) (*SidecarPlatformClient, error)
}

// What a generation's client is opened with.
type SidecarPlatformClientArgs struct {
	ClientId connect.Id
	// Required, no P2P stream asked for, the generation's ClientKey seed set (ApplySidecarClientSettings). The
	// platform builds the client on exactly these.
	ClientSettings *connect.ClientSettings
	Auth           *connect.ClientAuth
	ClientStrategy *connect.ClientStrategy
	ApiUrl         string
	PlatformUrl    string
	// connect's transport settings with AuthorizationClosed and Log set, a copy the platform may keep.
	PlatformTransportSettings *connect.PlatformTransportSettings
}

// One generation's client and what connects it.
type SidecarPlatformClient struct {
	Client *connect.Client
	// Installs a refreshed token for the transport's later connections and the out-of-band control's requests.
	SetAuth func(auth *connect.ClientAuth)
	// Whether the client is connected now, and a channel that closes at the next change, armed before the read.
	Connected func() (bool, <-chan struct{})
	// Ends the client and what connects it, and joins them, ctx bounding the wait.
	CloseAndWait func(ctx context.Context) error
}

// A SidecarPlatform that also carries SidecarApi's requests, as sidecartest's in-process api answers them: NewSidecar
// sends them through ApiTransport rather than dialing api by the client strategy. ApiTransport answers a transport safe
// for concurrent use, which the Sidecar keeps behind its absolute-url check; nil keeps the strategy's.
type SidecarApiPlatform interface {
	SidecarPlatform
	ApiTransport() http.RoundTripper
}

// connect's own platform.
type connectSidecarPlatform struct{}

// A client on an ApiOutOfBandControl and a PlatformTransport. See SidecarPlatform.
func (self connectSidecarPlatform) OpenClient(ctx context.Context, args *SidecarPlatformClientArgs) (*SidecarPlatformClient, error) {
	oob := connect.NewApiOutOfBandControl(ctx, args.ClientStrategy, args.Auth.ByJwt, args.ApiUrl)
	client := connect.NewClient(ctx, args.ClientId, oob, args.ClientSettings)
	transport := connect.NewPlatformTransport(
		ctx,
		args.ClientStrategy,
		client.RouteManager(),
		args.PlatformUrl,
		args.Auth,
		args.PlatformTransportSettings,
	)
	return &SidecarPlatformClient{
		Client: client,
		SetAuth: func(auth *connect.ClientAuth) {
			transport.SetAuth(auth)
			oob.SetByJwt(auth.ByJwt)
		},
		Connected: func() (bool, <-chan struct{}) {
			// armed first, as ConnectedNotify asks
			notify := transport.ConnectedNotify()
			return transport.IsConnected(), notify
		},
		CloseAndWait: func(ctx context.Context) error {
			return errors.Join(
				transport.CloseAndWait(ctx),
				client.CloseAndWait(ctx),
				oob.CloseAndWait(ctx),
			)
		},
	}, nil
}

// A running Sidecar on settings with components attached (D-CORE-2: there is no Start). host.Store() must be a
// SidecarInstance's, which names the network once it is enrolled; a host TokenSource is refused until CORE-M8-01
// builds the sdk host's child. The Sidecar starts Locked and leaves Locked once the instance opens: a host that has
// not unlocked it calls Unlock. Close or CloseAndWait ends it; the instance stays the host's.
func NewSidecar(ctx context.Context, host SidecarHost, components []SidecarComponent, settings *SidecarSettings) (*Sidecar, error) {
	if err := settings.validate(); err != nil {
		return nil, err
	}
	if host == nil {
		return nil, fmt.Errorf("%w: no host", errInvalidSettings)
	}
	instance, networkId, ok := sidecarInstanceOfStore(host.Store())
	if !ok {
		return nil, fmt.Errorf("%w: the host's store is not a SidecarInstance's", errInvalidSettings)
	}
	if host.TokenSource() != nil {
		return nil, fmt.Errorf("%w: a host TokenSource arrives with the sdk host's child (CORE-M8-01)", errInvalidSettings)
	}
	self := newSidecarBase(host, settings)
	cancelCtx, cancel := context.WithCancel(ctx)
	strategy := connect.NewClientStrategy(cancelCtx, settings.Connect.ClientStrategySettings)
	platform := settings.Connect.Platform
	if platform == nil {
		platform = connectSidecarPlatform{}
	}
	var apiTransport http.RoundTripper
	if apiPlatform, ok := platform.(SidecarApiPlatform); ok {
		apiTransport = apiPlatform.ApiTransport()
	}
	if apiTransport == nil {
		apiTransport = newSidecarApiTransport(cancelCtx, strategy)
	}
	sidecarApi, err := newSidecarApi(settings, apiTransport, self.clock.Now)
	if err != nil {
		cancel()
		strategy.Close()
		return nil, err
	}
	self.sidecarApi = sidecarApi
	leg := &sidecarConnectLeg{
		sidecar:  self,
		strategy: strategy,
		platform: platform,
		budget:   NewSubprotocolBudget(settings.ProtocolSettings, settings.MemoryBudgetByteCount),
		tls:      newTlsDeviceState(settings.Tls),
	}
	for _, component := range components {
		if err := leg.addComponent(component); err != nil {
			cancel()
			strategy.Close()
			return nil, err
		}
	}
	self.start(cancelCtx, cancel, instance, networkId, leg)
	return self, nil
}

// The connect legs' half of a Sidecar: the components, and what every generation's client shares.
type sidecarConnectLeg struct {
	sidecar  *Sidecar
	strategy *connect.ClientStrategy
	platform SidecarPlatform
	// §6's process-wide caps for this Sidecar's dispatchers, inside MemoryBudgetByteCount (§6.6). Several networks
	// in one daemon share one from CORE-M6-01.
	budget *SubprotocolBudget
	// The device key's lock, the certificate source and the self-signed leaves (tls_self_signed.go).
	tls *tlsDeviceState

	stateLock  sync.Mutex
	components []SidecarComponent
	closed     bool
}

// Starts one generation's client: settings from the Sidecar's with the ClientKey seed, the platform's client, a
// BringYourApi and the dispatcher. The watch on the connection and the components start once the run loop has
// published the generation (start), so a removal never misses one. See sidecarLeg.
func (self *sidecarConnectLeg) startGeneration(generation *sidecarGeneration) (sidecarLegGeneration, error) {
	settings := self.sidecar.settings
	clientSettings := *settings.Connect.ClientSettings
	if clientSettings.EncryptionSettings != nil {
		// a copy, since ApplySidecarClientSettings writes through it and the host's settings are its own
		encryptionSettings := *clientSettings.EncryptionSettings
		clientSettings.EncryptionSettings = &encryptionSettings
	}
	ApplySidecarClientSettings(&clientSettings)
	clientSettings.ClientKeySeed = generation.clientKeySeed
	clientSettings.Log = connectLogger(self.sidecar.log)

	clientInfo := connect.UnknownClientInfo()
	clientInfo.AppVersion = settings.AppVersion
	auth := &connect.ClientAuth{
		ByJwt:              generation.byJwt,
		InstanceId:         connect.Id(generation.connectInstanceId),
		AppVersion:         settings.AppVersion,
		ClientInfo:         clientInfo,
		StreamLeaseVersion: 1,
	}
	transportSettings := *settings.Connect.PlatformTransportSettings
	transportSettings.Log = connectLogger(self.sidecar.log)
	transportSettings.AuthorizationClosed = func(cause connect.AuthorizationCloseCause) {
		// nonblocking, as connect requires of it
		generation.authorizationClosed(cause == connect.AuthorizationCloseUnavailable)
	}

	platformClient, err := self.platform.OpenClient(generation.ctx, &SidecarPlatformClientArgs{
		ClientId:                  connect.Id(generation.identity.ClientId),
		ClientSettings:            &clientSettings,
		Auth:                      auth,
		ClientStrategy:            self.strategy,
		ApiUrl:                    settings.ApiUrl,
		PlatformUrl:               settings.PlatformUrl,
		PlatformTransportSettings: &transportSettings,
	})
	clear(clientSettings.ClientKeySeed)
	if err != nil {
		return nil, err
	}
	closePlatform := func() {
		if err := platformClient.CloseAndWait(context.Background()); err != nil {
			self.sidecar.log.Warningf("[sidecar]generation %d's client did not close cleanly: %s", generation.generation, err)
		}
	}
	platformClient.Client.ContractManager().SetProvideModes(map[connectprotocol.ProvideMode]bool{
		connectprotocol.ProvideMode_Network: true,
	})

	api := connect.NewBringYourApi(generation.ctx, self.strategy, settings.ApiUrl)
	api.SetByJwt(generation.byJwt)

	networkId := generation.networkId
	store, err := self.sidecar.instance.Store(&networkId).Directory(sidecarSubprotocolStoreName, sidecarSubprotocolStoreName)
	if err != nil {
		api.Close()
		closePlatform()
		return nil, err
	}
	subprotocol, err := NewSubprotocol(generation.ctx, &SubprotocolEnv{
		Client:   platformClient.Client,
		Store:    store,
		Log:      self.sidecar.log,
		Settings: settings.ProtocolSettings,
		Budget:   self.budget,
		Clock:    self.sidecar.clock,
		// M1's core has no policy; ACL swaps in AclEngine.AllowInbound at M2
		Inbound:   SubprotocolInboundWithoutPolicy,
		NetworkId: generation.networkId,
		Binding:   generation.binding,
		Event:     self.sidecar.emitEvent,
		// M2's admission check: a peer's identity key is its SidecarAdmit's, and until the installed
		// state admits this sidecar it gets no peer (§5.6, §6.4)
		Admissions: sidecarSubprotocolAdmissions{sidecar: self.sidecar},
	})
	if err != nil {
		api.Close()
		closePlatform()
		return nil, err
	}
	// §6.8's push: the resident's frames to the machine, its versions kept beside the pins, and core's
	// notices to the core, every one a bare resync until a body carries more (plan-CORE-core-hint-body)
	pushClientSettings := DefaultPushClientSettings()
	pushClientSettings.SyncRefetchInterval = settings.ProtocolSettings.SyncRefetchInterval
	pushClient, err := NewPushClient(generation.ctx, &PushClientEnv{
		Subprotocol: subprotocol,
		Store:       store,
		Api:         self.sidecar.sidecarApi,
		Settings:    pushClientSettings,
		Clock:       self.sidecar.clock,
		Log:         self.sidecar.log,
		Event:       self.sidecar.emitEvent,
	})
	if err != nil {
		subprotocol.Close()
		api.Close()
		closePlatform()
		return nil, err
	}
	generationNumber := generation.generation
	if _, err := subprotocol.Subscribe(PushTopicCore, func(notice PushNotice) {
		self.sidecar.receiveCoreHint(generationNumber, notice.Hint)
	}); err != nil {
		pushClient.Close()
		subprotocol.Close()
		api.Close()
		closePlatform()
		return nil, err
	}

	connectGeneration := &sidecarConnectGeneration{
		leg:            self,
		generation:     generation,
		platformClient: platformClient,
		api:            api,
		auth:           auth,
		subprotocol:    subprotocol,
		pushClient:     pushClient,
		closePlatform:  closePlatform,
		watchDone:      make(chan struct{}),
		attachments:    map[string]*sidecarComponentAttachment{},
	}
	return connectGeneration, nil
}

// The running generation's dispatcher's counters.
func (self *sidecarConnectLeg) subprotocolStats() SidecarSubprotocolStats {
	generation := self.sidecar.runningGeneration()
	if generation == nil || generation.leg == nil {
		return SidecarSubprotocolStats{}
	}
	return generation.leg.subprotocolStats()
}

// Closes each component once, and the client strategy. The last generation has ended.
func (self *sidecarConnectLeg) close() {
	components := func() []SidecarComponent {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		components := self.components
		self.components = nil
		return components
	}()
	for _, component := range components {
		component.Close()
	}
	self.strategy.Close()
}

// One generation's connect half.
type sidecarConnectGeneration struct {
	leg            *sidecarConnectLeg
	generation     *sidecarGeneration
	platformClient *SidecarPlatformClient
	api            *connect.BringYourApi
	subprotocol    *Subprotocol
	// §6.8's push on subprotocol, which a reconnect resyncs
	pushClient    *PushClient
	closePlatform func()
	watchStarted  atomic.Bool
	watchDone     chan struct{}

	stateLock   sync.Mutex
	auth        *connect.ClientAuth
	attachments map[string]*sidecarComponentAttachment
	closed      bool
}

// Starts the watch on the connection and attaches the components. See sidecarLegGeneration.
func (self *sidecarConnectGeneration) start() {
	self.watchStarted.Store(true)
	go self.watchConnection()
	self.reconcileComponents()
}

// Online and Offline as the client connects and loses its connection, until the generation ends.
func (self *sidecarConnectGeneration) watchConnection() {
	defer close(self.watchDone)
	reported := false
	first := true
	for {
		connected, changed := self.platformClient.Connected()
		if first || connected != reported {
			// a reconnect resyncs every topic: what was hinted while away is gone (§6.8)
			if connected && !first {
				self.pushClient.Resync()
			}
			first = false
			reported = connected
			self.generation.connectionChanged(connected)
		}
		select {
		case <-self.generation.ctx.Done():
			return
		case <-changed:
		}
	}
}

// Installs a refreshed token in connect's three holders: the api, the transport and the out-of-band control (§5.6;
// connect/transfer_oob_control.go:101 keeps its own jwt). SetAuth with a new token ends connect's refusal hold.
func (self *sidecarConnectGeneration) install(byJwt string) {
	auth := func() *connect.ClientAuth {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		next := *self.auth
		next.ByJwt = byJwt
		self.auth = &next
		return &next
	}()
	self.api.SetByJwt(byJwt)
	self.platformClient.SetAuth(auth)
}

// The dispatcher's counters, as they stand.
func (self *sidecarConnectGeneration) subprotocolStats() SidecarSubprotocolStats {
	return self.subprotocol.Stats()
}

// Detaches every component, then closes the dispatcher, the client and its connection, and the api, joining each.
func (self *sidecarConnectGeneration) closeAndWait() {
	self.detachAll()
	if self.watchStarted.Load() {
		<-self.watchDone
	}
	self.pushClient.Close()
	self.subprotocol.Close()
	self.closePlatform()
	self.api.Close()
}
