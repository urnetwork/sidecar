//go:build !sidecar_http && !ios_extension

// EdgeClientPool (§6.10.1, §13.6; TLS-M5-11): the K connect clients an edge process runs in urnetwork-edge, which
// tlsedge, mxedge and smtpedge share. Each is a platform client on the credential its host's ServiceClientSource
// answers for its index: Required and relay-only (ApplySidecarClientSettings; I-3, D-TLS-4), reachable on id 21842
// alone, advertising Service and nothing else, with a Subprotocol in SubprotocolRoleEdge, which runs no Hello and no
// HeadCheck.
//
// The pool lists its clients for Find (Clients, ClientIds) and hands out the one a ticket names (Client), refusing
// an id it does not hold. An edge is ready only while all K are connected (Ready, D-TLS-9), and the pool holds no TLS
// key and no user secret (D-TLS-1): a client's jwt is its only credential, asked of the source again whenever the
// platform closes its authorization, and never logged (I-7). Log lines name a client by its index, never an address
// or an id (I-13).

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"
)

// The pool could not be made, or does not hold what was asked of it.
var (
	ErrEdgeClientPool        = errors.New("the edge client pool cannot be made")
	ErrEdgeClientPoolUnknown = errors.New("the edge client pool holds no such client")
)

// An edge client pool's tunables.
type EdgeClientPoolSettings struct {
	// K, the clients one process runs in urnetwork-edge: 4 (§13.6).
	ClientCount int
	// The pool's share of §5's memory budget, which its K dispatchers share: 192 MiB.
	MemoryBudgetByteCount int64
	// How long a refused or failed credential read waits before the source is asked again: 5 s.
	AuthRetryInterval time.Duration
	// How long Close waits for each client to end: 10 s.
	CloseTimeout time.Duration
	// The version each client reports.
	AppVersion string
	// §6.6's bounds for each dispatcher.
	Protocol *SidecarProtocolSettings
	// connect's own, which the pool copies and holds to Required.
	ClientSettings            *connect.ClientSettings
	ClientStrategySettings    *connect.ClientStrategySettings
	PlatformTransportSettings *connect.PlatformTransportSettings
}

// The defaults, a fresh value each call.
func DefaultEdgeClientPoolSettings() *EdgeClientPoolSettings {
	return &EdgeClientPoolSettings{
		ClientCount:               4,
		MemoryBudgetByteCount:     192 * 1024 * 1024,
		AuthRetryInterval:         5 * time.Second,
		CloseTimeout:              10 * time.Second,
		Protocol:                  DefaultSidecarProtocolSettings(),
		ClientSettings:            connect.DefaultClientSettings(),
		ClientStrategySettings:    connect.DefaultClientStrategySettings(),
		PlatformTransportSettings: connect.DefaultPlatformTransportSettings(),
	}
}

// What NewEdgeClientPool takes.
type EdgeClientPoolArgs struct {
	// Where each client's credential comes from, which only the host holds.
	Source ServiceClientSource
	// How a client reaches the platform. Nil is connect's own.
	Platform SidecarPlatform
	// §8's hook for what a sidecar asks of the engine. Nil refuses every inbound request, so an engine that answers
	// requests, as smtpedge does SmtpProof, passes its own.
	Inbound SubprotocolInboundFunction
	// Nil is DefaultEdgeClientPoolSettings.
	Settings *EdgeClientPoolSettings
	// Nil reads real time.
	Clock Clock
	// Nil logs nothing.
	Log Logger
}

// One of the pool's clients.
type edgePoolClient struct {
	index       int
	clientId    Id
	platform    *SidecarPlatformClient
	subprotocol *Subprotocol
	// a token for each authorization the platform closed, never blocking
	authClosed chan struct{}
}

// K platform clients in urnetwork-edge. Safe for concurrent use.
type EdgeClientPool struct {
	ctx      context.Context
	cancel   context.CancelFunc
	source   ServiceClientSource
	settings *EdgeClientPoolSettings
	clock    Clock
	log      Logger

	// fixed at construction
	clients         []*edgePoolClient
	clientIdClients map[Id]*edgePoolClient

	loopGroup sync.WaitGroup
	closeOnce sync.Once
}

// Refuses every inbound request: the default for an engine that answers none.
func edgeClientPoolRefuseInbound(inbound SubprotocolInbound) bool {
	return false
}

// Opens the K clients, each on the credential source answers for its index, and returns once every one exists; they
// connect on their own, and Ready tells when all have. A source that cannot answer an index, or answers one client
// id twice, fails the pool, and nothing is left running.
func NewEdgeClientPool(ctx context.Context, args *EdgeClientPoolArgs) (*EdgeClientPool, error) {
	if args == nil || args.Source == nil {
		return nil, fmt.Errorf("%w: no client source", ErrEdgeClientPool)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultEdgeClientPoolSettings()
	}
	if settings.ClientCount < 1 || settings.MemoryBudgetByteCount < 1 || settings.AuthRetryInterval <= 0 || settings.CloseTimeout <= 0 ||
		settings.Protocol == nil || settings.ClientSettings == nil || settings.ClientStrategySettings == nil || settings.PlatformTransportSettings == nil {
		return nil, fmt.Errorf("%w: settings", ErrEdgeClientPool)
	}
	platform := args.Platform
	if platform == nil {
		platform = connectSidecarPlatform{}
	}
	inbound := args.Inbound
	if inbound == nil {
		inbound = edgeClientPoolRefuseInbound
	}
	clock := args.Clock
	if clock == nil {
		clock = RealClock{}
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &EdgeClientPool{
		ctx:             cancelCtx,
		cancel:          cancel,
		source:          args.Source,
		settings:        settings,
		clock:           clock,
		log:             log,
		clientIdClients: map[Id]*edgePoolClient{},
	}
	strategy := connect.NewClientStrategy(cancelCtx, settings.ClientStrategySettings)
	budget := NewSubprotocolBudget(settings.Protocol, settings.MemoryBudgetByteCount)
	for index := range settings.ClientCount {
		client, err := self.openClient(index, platform, strategy, budget, inbound)
		if err != nil {
			self.Close()
			return nil, err
		}
		if self.clientIdClients[client.clientId] != nil {
			self.closeClient(client)
			self.Close()
			return nil, fmt.Errorf("%w: the source answered one client id for two indexes", ErrEdgeClientPool)
		}
		self.clients = append(self.clients, client)
		self.clientIdClients[client.clientId] = client
	}
	for _, client := range self.clients {
		self.loopGroup.Add(1)
		go func() {
			defer self.loopGroup.Done()
			self.refreshAuth(client)
		}()
	}
	return self, nil
}

// The auth a client connects with: its jwt, and a stream lease, as a sidecar's generation asks (sidecar_new_connect.go).
func (self *EdgeClientPool) clientAuth(credential *ServiceClientAuth) *connect.ClientAuth {
	clientInfo := connect.UnknownClientInfo()
	clientInfo.AppVersion = self.settings.AppVersion
	return &connect.ClientAuth{
		ByJwt:              credential.ByJwt,
		InstanceId:         connect.NewId(),
		AppVersion:         self.settings.AppVersion,
		ClientInfo:         clientInfo,
		StreamLeaseVersion: 1,
	}
}

// A credential the source answered whole, or an error: a zero client id or an empty field is never a success.
func (self *EdgeClientPool) readCredential(ctx context.Context, index int) (*ServiceClientAuth, error) {
	credential, err := self.source.ServiceClient(ctx, index)
	if err != nil {
		return nil, err
	}
	if credential == nil || credential.ClientId == (connect.Id{}) || credential.ByJwt == "" || credential.ApiUrl == "" || credential.PlatformUrl == "" {
		return nil, fmt.Errorf("%w: the source answered client %d without an id, a jwt or a url", ErrEdgeClientPool, index)
	}
	return credential, nil
}

// One client: Required, relay-only, on id 21842 alone, providing Service, with its edge dispatcher.
func (self *EdgeClientPool) openClient(index int, platform SidecarPlatform, strategy *connect.ClientStrategy, budget *SubprotocolBudget, inbound SubprotocolInboundFunction) (*edgePoolClient, error) {
	credential, err := self.readCredential(self.ctx, index)
	if err != nil {
		return nil, err
	}
	clientSettings := *self.settings.ClientSettings
	if clientSettings.EncryptionSettings != nil {
		// a copy, since ApplySidecarClientSettings writes through it and the host's settings are its own
		encryptionSettings := *clientSettings.EncryptionSettings
		clientSettings.EncryptionSettings = &encryptionSettings
	}
	ApplySidecarClientSettings(&clientSettings)
	clientSettings.Log = connectLogger(self.log)

	client := &edgePoolClient{
		index:      index,
		clientId:   Id(credential.ClientId),
		authClosed: make(chan struct{}, 1),
	}
	transportSettings := *self.settings.PlatformTransportSettings
	transportSettings.Log = connectLogger(self.log)
	transportSettings.AuthorizationClosed = func(cause connect.AuthorizationCloseCause) {
		// nonblocking, as connect requires of it
		select {
		case client.authClosed <- struct{}{}:
		default:
		}
	}
	client.platform, err = platform.OpenClient(self.ctx, &SidecarPlatformClientArgs{
		ClientId:                  credential.ClientId,
		ClientSettings:            &clientSettings,
		Auth:                      self.clientAuth(credential),
		ClientStrategy:            strategy,
		ApiUrl:                    credential.ApiUrl,
		PlatformUrl:               credential.PlatformUrl,
		PlatformTransportSettings: &transportSettings,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: client %d did not open", ErrEdgeClientPool, index)
	}
	// Service and nothing else: no edge provides Network, and none Public (§6.10.1)
	client.platform.Client.ContractManager().SetProvideModes(map[connectprotocol.ProvideMode]bool{
		connectprotocol.ProvideMode_Service: true,
	})
	client.subprotocol, err = NewSubprotocol(self.ctx, &SubprotocolEnv{
		Client:   client.platform.Client,
		Log:      self.log,
		Settings: self.settings.Protocol,
		Budget:   budget,
		Clock:    self.clock,
		Inbound:  inbound,
		Role:     SubprotocolRoleEdge,
	})
	if err != nil {
		self.closeClient(client)
		return nil, err
	}
	return client, nil
}

// Asks the source again each time the platform closes a client's authorization, and installs what it answers for the
// client's later connections. A read that fails is tried again after AuthRetryInterval.
func (self *EdgeClientPool) refreshAuth(client *edgePoolClient) {
	for {
		select {
		case <-self.ctx.Done():
			return
		case <-client.authClosed:
		}
		for {
			credential, err := self.readCredential(self.ctx, client.index)
			if err == nil && Id(credential.ClientId) != client.clientId {
				// a client's id is the same for the process's life (ServiceClientAuth), so another's jwt is never installed
				err = ErrEdgeClientPoolUnknown
			}
			if err == nil {
				client.platform.SetAuth(self.clientAuth(credential))
				break
			}
			self.log.Warningf("[edge]client %d's credential did not refresh", client.index)
			select {
			case <-self.ctx.Done():
				return
			case <-self.clock.After(self.settings.AuthRetryInterval):
			}
		}
	}
}

// Every client, for a Find and for NewSocketEdgeDialer: the same K for the pool's life.
func (self *EdgeClientPool) Clients() []*SocketEdgeClient {
	clients := make([]*SocketEdgeClient, 0, len(self.clients))
	for _, client := range self.clients {
		clients = append(clients, &SocketEdgeClient{ClientId: client.clientId, Subprotocol: client.subprotocol})
	}
	return clients
}

// The K client ids, which every Find sends.
func (self *EdgeClientPool) ClientIds() []Id {
	clientIds := make([]Id, 0, len(self.clients))
	for _, client := range self.clients {
		clientIds = append(clientIds, client.clientId)
	}
	return clientIds
}

// The client a ticket names. An id the pool does not hold is refused: a ticket for another process's client opens
// nothing here.
func (self *EdgeClientPool) Client(clientId Id) (*SocketEdgeClient, error) {
	client := self.clientIdClients[clientId]
	if client == nil {
		return nil, ErrEdgeClientPoolUnknown
	}
	return &SocketEdgeClient{ClientId: client.clientId, Subprotocol: client.subprotocol}, nil
}

// How many clients are connected to the platform now.
func (self *EdgeClientPool) ConnectedCount() int {
	count := 0
	for _, client := range self.clients {
		if connected, _ := client.platform.Connected(); connected {
			count += 1
		}
	}
	return count
}

// Whether all K clients are connected, which an edge's readiness needs (D-TLS-9). False once closed.
func (self *EdgeClientPool) Ready() bool {
	if self.ctx.Err() != nil {
		return false
	}
	return len(self.clients) == self.settings.ClientCount && self.ConnectedCount() == self.settings.ClientCount
}

// Ends one client and its dispatcher, waiting up to CloseTimeout.
func (self *EdgeClientPool) closeClient(client *edgePoolClient) {
	if client.subprotocol != nil {
		client.subprotocol.Close()
	}
	if client.platform != nil {
		closeCtx, cancel := context.WithTimeout(context.Background(), self.settings.CloseTimeout)
		defer cancel()
		if err := client.platform.CloseAndWait(closeCtx); err != nil {
			self.log.Warningf("[edge]client %d did not close cleanly", client.index)
		}
	}
}

// Ends every client and joins the pool's goroutines. Idempotent.
func (self *EdgeClientPool) Close() {
	self.closeOnce.Do(func() {
		self.cancel()
		self.loopGroup.Wait()
		for _, client := range self.clients {
			self.closeClient(client)
		}
	})
}
