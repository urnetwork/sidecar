//go:build !sidecar_http

// NewSidecar on connect legs (§5.4, D-CORE-1, D-CORE-2): a running Sidecar with its components, whose client
// generations are its own Required connect clients (I-3, D-CORE-4), never the sdk device client's (owner decision 4)
// and never Opportunistic. Each generation, modeled on sdk/device_local_provider.go:237-330, is a client on the
// ClientKey seed from the keychain, the out-of-band control and PlatformTransport its SidecarPlatform opens with
// ClientAuth{ByJwt, InstanceId, AppVersion, ClientInfo, StreamLeaseVersion: 1}, AuthorizationClosed wired to the
// refresher, a BringYourApi on the same token, and §6's Subprotocol, which constructing registers on id 21842. It
// provides Network only; Service and FriendsAndFamily are their owners' to add, and Public never (§6).
//
// The persisted connect InstanceId (sidecar.json's network record) keeps the resident across restarts (§5.9), and the
// connect identity the core keeps with the generation (identity_connect.go) keeps the contracts its peers hold: the
// client presents the same ClientKey, sequence certificate and provide keys at every start of the generation, as an
// sdk device does across an app's restarts, so a restart under the kept generation is reached at once rather than
// after each peer's AckTimeout. A generation's client, transport, dispatcher and components end with its ctx, and its
// closeAndWait joins them.

package sidecar

import (
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"
)

// The network directory and seal class of §6's dispatcher's own state: PROTO-M2-01's generation floors, and the
// first-use pins PROTO-M1-04 kept before them, which the admission check drops.
const sidecarSubprotocolStoreName = "subprotocol"

// The connect identity's derivation labels, each a version of its own: a change to one is a new identity for every
// generation's client.
const (
	sidecarConnectIdentityTlsKeyLabel    = "urnetwork-sidecar-v1/connect-identity/sequence-tls-key"
	sidecarConnectIdentityTlsSerialLabel = "urnetwork-sidecar-v1/connect-identity/sequence-tls-serial"
	// followed by the provide mode's number in decimal, one key per mode
	sidecarConnectIdentityProvideLabelPrefix = "urnetwork-sidecar-v1/connect-identity/provide/"
)

// The sequence certificate's fixed template: the name connect's own sequence certificates carry, and RFC 5280
// §4.1.2.5's validity for a certificate with no well-defined expiration, since a peer checks the certificate against a
// contract's commitment to its bytes and never its dates (connect's DefaultSequenceServerTlsConfig). Ed25519 signs
// deterministically, so the certificate's bytes follow from the seed alone, as an edge client's do
// (host_edge_identity.go).
const sidecarConnectIdentityTlsName = "urnetwork-sequence"

// The serial's bytes from the seed, under a leading 0x01 so the serial is positive and 17 bytes, within RFC 5280's 20.
const sidecarConnectIdentityTlsSerialByteCount = 16

// No connect identity came with a generation on a leg that keeps one: its client does not open (identity_connect.go).
var errSidecarNoConnectIdentity = errors.New("the generation has no connect identity")

// The modes a sidecar's client may provide, each of which a peer's contract to it is HMAC'd under: its own Network, and
// on top the Service and FriendsAndFamily its owners hold (Subprotocol.HoldProvideMode), Service while a tls/ or smtp/
// registration or a ur/ stream lives (§6.10.1's C9 items), so an edge's contracts to the client outlive a restart as a
// peer sidecar's do, and FriendsAndFamily while a share it hosts stands. A key for a mode the client does not provide
// verifies nothing and reaches no platform: connect sends and checks only the provided modes' keys.
func sidecarConnectIdentityProvideModes() []connectprotocol.ProvideMode {
	return []connectprotocol.ProvideMode{
		connectprotocol.ProvideMode_Network,
		connectprotocol.ProvideMode_Service,
		connectprotocol.ProvideMode_FriendsAndFamily,
	}
}

// One generation's connect identity, derived from the seed its keychain keeps (identity_connect.go): the sequence
// certificate and its key, which every contract to the client commits to, and a provide secret key for each mode of
// sidecarConnectIdentityProvideModes, which every contract to the client in that mode is HMAC'd with. The same seed
// derives the same bytes, field for field. The client borrows all of it for its life: connect keeps these slices.
type sidecarConnectIdentity struct {
	tlsCertificatePem []byte
	tlsPrivateKeyPem  []byte
	provideSecretKeys map[connectprotocol.ProvideMode][]byte
}

// Derives a generation's connect identity from its seed, each part by HKDF-SHA256 under a label of its own. The seed
// and the certificate's key reach testHookSecret as they are read and derived; the provide keys go to the platform, as
// every client's do, so the privacy harness is not told of them.
func newSidecarConnectIdentity(seed []byte) (*sidecarConnectIdentity, error) {
	if len(seed) != sidecarConnectIdentitySeedByteCount {
		return nil, fmt.Errorf("%w: a seed of %d bytes", errSidecarNoConnectIdentity, len(seed))
	}
	testHookSecret("connect_identity_seed", seed)
	derive := func(label string, byteCount int) ([]byte, error) {
		return hkdf.Key(sha256.New, seed, nil, label, byteCount)
	}
	tlsKeySeed, err := derive(sidecarConnectIdentityTlsKeyLabel, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	testHookSecret("connect_sequence_tls_key", tlsKeySeed)
	tlsKey := ed25519.NewKeyFromSeed(tlsKeySeed)
	clear(tlsKeySeed)
	defer clear(tlsKey)
	serialBytes, err := derive(sidecarConnectIdentityTlsSerialLabel, sidecarConnectIdentityTlsSerialByteCount)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(append([]byte{0x01}, serialBytes...)),
		Subject:      pkix.Name{CommonName: sidecarConnectIdentityTlsName},
		NotBefore:    time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{sidecarConnectIdentityTlsName},
	}
	// Ed25519 ignores the reader, so the certificate's bytes follow from the seed alone
	certificateDer, err := x509.CreateCertificate(rand.Reader, template, template, tlsKey.Public(), tlsKey)
	if err != nil {
		return nil, err
	}
	privateKeyDer, err := x509.MarshalPKCS8PrivateKey(tlsKey)
	if err != nil {
		return nil, err
	}
	tlsPrivateKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDer})
	clear(privateKeyDer)
	provideSecretKeys := map[connectprotocol.ProvideMode][]byte{}
	for _, mode := range sidecarConnectIdentityProvideModes() {
		provideSecretKey, err := derive(sidecarConnectIdentityProvideLabelPrefix+strconv.Itoa(int(mode)), sha256.Size)
		if err != nil {
			return nil, err
		}
		provideSecretKeys[mode] = provideSecretKey
	}
	return &sidecarConnectIdentity{
		tlsCertificatePem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDer}),
		tlsPrivateKeyPem:  tlsPrivateKeyPem,
		provideSecretKeys: provideSecretKeys,
	}, nil
}

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
	// Provide secret keys by mode that the platform loads into the client's contract manager after it builds the
	// client and before anything can reach it (ContractManager.LoadProvideSecretKeys), so a contract a peer holds from
	// an earlier process with the same identity verifies from the first frame (host_edge_identity.go). Borrowed for the
	// client's life. Nil: connect draws each key as its mode is first provided.
	ProvideSecretKeys map[connectprotocol.ProvideMode][]byte
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
	clientSettings := connect.NewOperatorClientSettings(args.ClientSettings, args.ApiUrl, args.ClientStrategy)
	client := connect.NewClient(ctx, args.ClientId, oob, clientSettings)
	if 0 < len(args.ProvideSecretKeys) {
		// before the transport, the client's only way in, exists
		client.ContractManager().LoadProvideSecretKeys(args.ProvideSecretKeys)
	}
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
// SidecarInstance's, which names the network once it is enrolled; a host TokenSource refreshes each generation's
// token once it holds that generation's signer (api_token_source.go). The Sidecar starts Locked and leaves Locked once
// the instance opens: a host that has not unlocked it calls Unlock. Close or CloseAndWait ends it; the instance stays
// the host's.
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

// Yes: each generation's client is a connect client, which presents the connect identity the core keeps for it.
func (self *sidecarConnectLeg) keepsConnectIdentity() bool {
	return true
}

// Starts one generation's client: settings from the Sidecar's with the ClientKey seed and the connect identity the
// generation keeps, the platform's client, a BringYourApi and the dispatcher. The watch on the connection and the
// components start once the run loop has published the generation (start), so a removal never misses one. A
// generation with no kept connect identity opens no client. See sidecarLeg.
func (self *sidecarConnectLeg) startGeneration(generation *sidecarGeneration) (sidecarLegGeneration, error) {
	settings := self.sidecar.settings
	connectIdentity, err := newSidecarConnectIdentity(generation.connectIdentitySeed)
	if err != nil {
		return nil, err
	}
	clientSettings := *settings.Connect.ClientSettings
	if clientSettings.EncryptionSettings != nil {
		// a copy, since ApplySidecarClientSettings writes through it and the host's settings are its own
		encryptionSettings := *clientSettings.EncryptionSettings
		clientSettings.EncryptionSettings = &encryptionSettings
	}
	ApplySidecarClientSettings(&clientSettings)
	clientSettings.ClientKeySeed = generation.clientKeySeed
	// the sequence certificate every contract to the client commits to, the generation's at every start; a
	// ServerTlsConfig in the host's settings still wins over it, as connect has it
	clientSettings.EncryptionSettings.ProvideTlsCertificatePem = connectIdentity.tlsCertificatePem
	clientSettings.EncryptionSettings.ProvideTlsPrivateKeyPem = connectIdentity.tlsPrivateKeyPem
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
		// so a contract a peer holds from an earlier start of this generation verifies from the first frame
		ProvideSecretKeys: connectIdentity.provideSecretKeys,
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
	// a platform that loads no keys as it builds a client gets them here, still before any mode is provided, so no
	// provide frame ever names a key the generation does not keep
	platformClient.Client.ContractManager().LoadProvideSecretKeys(connectIdentity.provideSecretKeys)
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
	// a sealed file of this store that fails decoding is §5.9's Failed, which the core reports as this store's
	// (owner decision 616)
	storeFailed := func(err error) error {
		if errors.Is(err, ErrSidecarStoreFailed) {
			return fmt.Errorf("%w: %w", errSidecarSubprotocolStoreFailed, err)
		}
		return err
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
		return nil, storeFailed(err)
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
		return nil, storeFailed(err)
	}
	if _, err := subprotocol.Subscribe(PushTopicCore, generation.receiveCoreNotice); err != nil {
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
