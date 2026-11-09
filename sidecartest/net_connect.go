// Connect clients in one process (§22.4, Q-TEST-1). Everything here is connect's exported API: a client
// is connect.NewClient with EncryptionModeRequired (D-PROTO-6), a link is a Route, and the exchange is
// a loop reading each client's send route and writing the peer's receive route, conditioned per pair.
//
// The two things a platform gives a client stand in here as a fake contract issuer and a ControlId sink,
// each named in §22.8's cadence rule: every row using them also runs on T3 against server's exchange
// (server/connect/resident.go:902), and a divergence fails, so neither is the last word on connect.
// Every client here runs on both, and fault.Run fails a row that adds one without naming T3. The T3
// run and its comparison are server's, with T3. A Net given NetSettings.Platform opens its clients there
// instead (net_platform.go), which is how T3's Nets run a row's clients on server's exchange.
//
// A connect client keeps real timers of its own, so what happens on a link runs in real time and not on
// the injected clock. A test waits for what it expects on a channel, with no sleep, but a link's timing
// is not a schedule's to set, and barriers hold the protocols built on it instead.

package sidecartest

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
)

// One direction's conditions between two clients (§22.4's SetLink).
type LinkConditions struct {
	// Each frame's chance of being dropped, from 0 to 1.
	LossProbability float64
	// Drops every frame.
	Partition bool
	// The carrier a frame reaches the receiver on, which it reads in connect.Peer. Empty: h1.
	TransportType connect.TransportType
}

type netLinkKey struct {
	source      connect.Id
	destination connect.Id
}

// Routes frames between clients. Safe for concurrent use.
type netExchange struct {
	net    *Net
	ctx    context.Context
	cancel context.CancelFunc

	// NetSettings.Platform's platform, built at its first client (net_platform.go), or what building it failed with
	platformOnce sync.Once
	platform     NetPlatform
	platformErr  error

	stateLock sync.Mutex
	random    *rand.Rand
	clients   map[connect.Id]*NetClient
	// a client was ever added, each of which ran on the platform fakes
	everAdded bool
	links     map[netLinkKey]*LinkConditions
	// the class the issuer seals into a pair's contracts, data where none is set (subprotocol_net.go)
	contractClasses map[netLinkKey]protocol.ContractClass
	// each client's resident, by the client it serves (push_net.go)
	residents map[connect.Id]*NetResident
	// the clients the platform opened, which close ends
	platformClients []*netPlatformClient
	// what a row asked that the platform cannot apply (Net.Unapplied)
	unapplied []string
	// close has begun, so no platform client is taken on
	closed  bool
	workers sync.WaitGroup
}

func newNetExchange(ctx context.Context, net *Net) *netExchange {
	cancelCtx, cancel := context.WithCancel(ctx)
	return &netExchange{
		net:             net,
		ctx:             cancelCtx,
		cancel:          cancel,
		random:          rand.New(rand.NewPCG(uint64(net.settings.LinkSeed), 0x11e7)),
		clients:         map[connect.Id]*NetClient{},
		links:           map[netLinkKey]*LinkConditions{},
		contractClasses: map[netLinkKey]protocol.ContractClass{},
		residents:       map[connect.Id]*NetResident{},
	}
}

func (self *netExchange) close() {
	var clients []*NetClient
	var residents []*NetResident
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		for _, client := range self.clients {
			clients = append(clients, client)
		}
		for _, resident := range self.residents {
			residents = append(residents, resident)
		}
	}()
	// residents first, so no publisher outlives its client or the Redis it reads
	for _, resident := range residents {
		resident.Close()
	}
	for _, client := range clients {
		client.Client.Cancel()
	}
	self.closePlatform()
	self.cancel()
	self.workers.Wait()
}

// A send gateway for every destination but ControlId, or for ControlId alone. No transport connect
// exports makes that split, and without it control frames would loop between peers, so this implements
// connect.Transport, which is all exported methods.
type netSendTransport struct {
	transportId connect.Id
	control     bool
}

func newNetSendTransport(control bool) *netSendTransport {
	return &netSendTransport{transportId: connect.NewId(), control: control}
}

func (self *netSendTransport) TransportId() connect.Id {
	return self.transportId
}

func (self *netSendTransport) Priority() int {
	if self.control {
		return connect.TransportMaxPriority
	}
	return 100
}

func (self *netSendTransport) Weight() float32 {
	return 0
}

func (self *netSendTransport) CanEvalRouteWeight(stats *connect.RouteStats, remainingStats map[connect.Transport]*connect.RouteStats) bool {
	return true
}

func (self *netSendTransport) RouteWeight(stats *connect.RouteStats, remainingStats map[connect.Transport]*connect.RouteStats) float32 {
	return 1.0 / float32(1+len(remainingStats))
}

func (self *netSendTransport) MatchesSend(destination connect.TransferPath) bool {
	return (destination.DestinationId == connect.ControlId) == self.control
}

func (self *netSendTransport) MatchesReceive(destination connect.TransferPath) bool {
	return false
}

func (self *netSendTransport) Downgrade(source connect.TransferPath) {
}

// §22.4's fake contract issuer: what connect's platform control does for CreateContract, signing a
// contract with the destination's provide key from its live client. It runs in this process and
// pre-authorizes nothing else, so a T2 row built on it also names T3 (Q-TEST-1).
type netContractIssuer struct {
	exchange *netExchange
	sourceId connect.Id
	settings *connect.ContractManagerSettings
}

// Takes frames and lends results to callback, as a connect.OutOfBandControl does.
func (self *netContractIssuer) SendControl(frames []*protocol.Frame, callback connect.OobResultFunction) {
	resultFrames := []*protocol.Frame{}
	defer func() {
		for _, frame := range frames {
			connect.MessagePoolReturn(frame.MessageBytes)
		}
		for _, frame := range resultFrames {
			connect.MessagePoolReturn(frame.MessageBytes)
		}
	}()
	for _, frame := range frames {
		message, err := connect.FromFrame(frame)
		if err != nil {
			continue
		}
		createContract, ok := message.(*protocol.CreateContract)
		if !ok {
			continue
		}
		resultFrame, err := self.issue(createContract)
		if err != nil {
			continue
		}
		resultFrames = append(resultFrames, resultFrame)
	}
	if callback != nil {
		connect.HandleError(func() {
			callback(resultFrames, nil)
		})
	}
}

func (self *netContractIssuer) issue(createContract *protocol.CreateContract) (*protocol.Frame, error) {
	destinationId, err := connect.IdFromBytes(createContract.DestinationId)
	if err != nil {
		return nil, err
	}
	destination := self.exchange.client(destinationId)
	if destination == nil {
		return nil, fmt.Errorf("no client %s", destinationId)
	}
	secretKey, ok := destination.Client.ContractManager().GetProvideSecretKey(protocol.ProvideMode_Network)
	if !ok {
		return nil, errors.New("the destination provides nothing")
	}
	storedContractBytes, err := connect.ProtoMarshal(&protocol.StoredContract{
		ContractId:                 connect.NewId().Bytes(),
		TransferByteCount:          createContract.TransferByteCount,
		SourceId:                   self.sourceId.Bytes(),
		DestinationId:              destinationId.Bytes(),
		DestinationClientPublicKey: destination.Client.ClientKeyManager().PublicKey(),
		// C13's class, as the contract gate seals it (§8.10)
		ContractClass: self.exchange.contractClass(self.sourceId, destinationId),
	})
	if err != nil {
		return nil, err
	}
	defer connect.MessagePoolReturn(storedContractBytes)
	return connect.ToFrame(&protocol.CreateContractResult{
		Contract: &protocol.Contract{
			StoredContractBytes: storedContractBytes,
			StoredContractHmac:  connect.SignStoredContract(self.settings, secretKey, storedContractBytes),
			ProvideMode:         protocol.ProvideMode_Network,
		},
	}, connect.DefaultProtocolVersion)
}

// One connect client on the exchange.
type NetClient struct {
	Name     string
	ClientId connect.Id
	Client   *connect.Client

	exchange *netExchange
	// ends when the client leaves the exchange
	ctx context.Context

	stateLock sync.Mutex
	// a receive route per carrier, made when a link first asks for it
	receiveRoutes map[connect.TransportType]connect.Route
}

func (self *netExchange) client(clientId connect.Id) *NetClient {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.clients[clientId]
}

// connect's defaults for a client in this exchange: Required, with timeouts set for a process with no
// real network in it, as connect's own Required tests set them (connect/transfer_encrypt_contract_test.go).
func netClientSettings() *connect.ClientSettings {
	settings := connect.DefaultClientSettingsWithBufferSize(64)
	settings.SendBufferSettings.AckTimeout = 60 * time.Second
	settings.SendBufferSettings.IdleTimeout = 1 * time.Second
	settings.SendBufferSettings.MinResendInterval = 10 * time.Millisecond
	settings.ReceiveBufferSettings.GapTimeout = 60 * time.Second
	settings.ReceiveBufferSettings.IdleTimeout = 60 * time.Second
	settings.ForwardBufferSettings.IdleTimeout = 1 * time.Second
	settings.ContractManagerSettings.LegacyCreateContract = false
	settings.EncryptionSettings.Mode = connect.EncryptionModeRequired
	settings.EncryptionSettings.TlsTimeout = 30 * time.Second
	return settings
}

// OpenClient, for a Net that cannot fail to open one: on the fakes (T2) it never does. On a platform it
// can, and that panics here, so a row that runs on T3 calls OpenClient and returns its error.
func (self *Net) AddClient(name string, settings *connect.ClientSettings) *NetClient {
	client, err := self.OpenClient(name, settings)
	if err != nil {
		panic(fmt.Errorf("client %q: %w", name, err))
	}
	return client
}

// Starts a Required client: on the exchange's fake contract issuer and ControlId sink, or, on a Net given
// NetSettings.Platform, on that platform, under the id it gives. settings nil takes netClientSettings. A
// client whose settings are anything but Required panics, since no sidecar traffic is ever anything else
// (I-3). Only a platform's client can fail to open, with what the platform says.
func (self *Net) OpenClient(name string, settings *connect.ClientSettings) (*NetClient, error) {
	if settings == nil {
		settings = netClientSettings()
	}
	requireRequiredClient(name, settings)
	platform, err := self.exchange.platformOrErr()
	if err != nil {
		return nil, err
	}
	if platform != nil {
		return self.exchange.openPlatformClient(platform, name, settings)
	}
	return self.exchange.addClient(self.exchange.ctx, name, connect.NewId(), settings), nil
}

// Panics unless settings are Required (I-3).
func requireRequiredClient(name string, settings *connect.ClientSettings) {
	if settings.EncryptionSettings == nil || settings.EncryptionSettings.Mode != connect.EncryptionModeRequired {
		panic(fmt.Sprintf("client %q is not Required (I-3)", name))
	}
}

// Starts a Required client of clientId on the exchange, until ctx ends, when it leaves the exchange. A client whose
// settings are anything but Required panics (I-3).
func (self *netExchange) addClient(ctx context.Context, name string, clientId connect.Id, settings *connect.ClientSettings) *NetClient {
	requireRequiredClient(name, settings)
	issuer := &netContractIssuer{exchange: self, sourceId: clientId, settings: connect.DefaultContractManagerSettings()}
	client := connect.NewClient(ctx, clientId, issuer, settings)
	netClient := &NetClient{
		Name:          name,
		ClientId:      clientId,
		Client:        client,
		exchange:      self,
		ctx:           ctx,
		receiveRoutes: map[connect.TransportType]connect.Route{},
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.clients[clientId] = netClient
		self.everAdded = true
	}()

	sendRoute := make(connect.Route)
	client.RouteManager().UpdateTransport(newNetSendTransport(false), []connect.Route{sendRoute})
	controlRoute := make(connect.Route)
	client.RouteManager().UpdateTransport(newNetSendTransport(true), []connect.Route{controlRoute})
	netClient.receiveRoute(connect.TransportTypeH1)
	client.ContractManager().SetProvideModes(map[protocol.ProvideMode]bool{protocol.ProvideMode_Network: true})

	self.workers.Add(3)
	go func() {
		defer self.workers.Done()
		self.pump(ctx, netClient, sendRoute)
	}()
	go func() {
		defer self.workers.Done()
		self.sinkControl(ctx, netClient, controlRoute)
	}()
	go func() {
		defer self.workers.Done()
		select {
		case <-ctx.Done():
		case <-self.ctx.Done():
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.clients[clientId] == netClient {
			delete(self.clients, clientId)
		}
	}()
	return netClient
}

// Why a client may not run on the fake contract issuer and ControlId sink here, empty when it may: what
// NetSettings.RefusePlatformFakes says. A run that added one on such a Net fails (fault.Run).
func (self *Net) RefusesPlatformFakes() string {
	return self.settings.RefusePlatformFakes
}

// Whether a client was added, each of which runs on the fake contract issuer and the ControlId sink, so
// a row that added one names T3 too (Q-TEST-1).
func (self *Net) UsesPlatformFakes() bool {
	exchange := self.exchange
	exchange.stateLock.Lock()
	defer exchange.stateLock.Unlock()
	return exchange.everAdded
}

// The receive route of a carrier, made on first use.
func (self *NetClient) receiveRoute(transportType connect.TransportType) connect.Route {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if route, ok := self.receiveRoutes[transportType]; ok {
		return route
	}
	route := make(connect.Route)
	self.receiveRoutes[transportType] = route
	self.Client.RouteManager().UpdateTransport(connect.NewReceiveGatewayTransportWithType(transportType), []connect.Route{route})
	return route
}

// Reads one client's send route until ctx or the exchange ends, taking each frame's pool buffer: it
// either moves on to the peer's receive route or goes back to the pool here.
func (self *netExchange) pump(ctx context.Context, source *NetClient, route connect.Route) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-self.ctx.Done():
			return
		case frame, ok := <-route:
			if !ok {
				return
			}
			self.forward(source, frame)
		}
	}
}

func (self *netExchange) forward(source *NetClient, frame []byte) {
	filtered := &protocol.FilteredTransferFrame{}
	if err := proto.Unmarshal(frame, filtered); err != nil || filtered.TransferPath == nil {
		connect.MessagePoolReturn(frame)
		return
	}
	destinationId, err := connect.IdFromBytes(filtered.TransferPath.DestinationId)
	if err != nil {
		connect.MessagePoolReturn(frame)
		return
	}
	self.net.capture.AddFrame(source.ClientId, destinationId, frame)

	destination := self.client(destinationId)
	if destination == nil || !self.passes(source.ClientId, destinationId) {
		connect.MessagePoolReturn(frame)
		return
	}
	route := destination.receiveRoute(self.transportType(source.ClientId, destinationId))
	select {
	case route <- frame:
	case <-destination.ctx.Done():
		// a client that left reads nothing more
		connect.MessagePoolReturn(frame)
	case <-self.ctx.Done():
		connect.MessagePoolReturn(frame)
	}
}

func (self *netExchange) transportType(source connect.Id, destination connect.Id) connect.TransportType {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if link, ok := self.links[netLinkKey{source: source, destination: destination}]; ok && link.TransportType != "" {
		return link.TransportType
	}
	return connect.TransportTypeH1
}

func (self *netExchange) passes(source connect.Id, destination connect.Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	link, ok := self.links[netLinkKey{source: source, destination: destination}]
	if !ok {
		return true
	}
	if link.Partition {
		return false
	}
	return link.LossProbability <= self.random.Float64()
}

// §22.4's ControlId sink: frames for the platform end here, kept for a test to read. A client with a
// resident (push_net.go) has its frames carried on to it over h1, as the platform's carriers carry them,
// so the resident's sends are acked; otherwise nothing answers, and a client's control sync retries, as
// it does with a platform that is slow. Runs until ctx or the exchange ends.
func (self *netExchange) sinkControl(ctx context.Context, source *NetClient, route connect.Route) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-self.ctx.Done():
			return
		case frame, ok := <-route:
			if !ok {
				return
			}
			self.net.capture.AddFrame(source.ClientId, connect.ControlId, frame)
			resident := self.resident(source.ClientId)
			if resident == nil || !self.passes(source.ClientId, connect.ControlId) {
				connect.MessagePoolReturn(frame)
				continue
			}
			select {
			case resident.netClient.receiveRoute(connect.TransportTypeH1) <- frame:
			case <-resident.netClient.ctx.Done():
				// a resident that ended reads nothing more
				connect.MessagePoolReturn(frame)
			case <-self.ctx.Done():
				connect.MessagePoolReturn(frame)
			}
		}
	}
}

// Sets the conditions on both directions between two clients. nil lifts them. A Net on a platform
// conditions no link, so conditions there are kept as unapplied (Net.Unapplied), and lifting them is
// nothing to do.
func (self *Net) SetLink(a connect.Id, b connect.Id, link *LinkConditions) {
	exchange := self.exchange
	if self.OnPlatform() {
		if link != nil {
			exchange.refuseOnPlatform(fmt.Sprintf("SetLink %s %s (loss %v, partition %t, carrier %q): the platform's exchange takes no link conditions", a, b, link.LossProbability, link.Partition, link.TransportType))
		}
		return
	}
	exchange.stateLock.Lock()
	defer exchange.stateLock.Unlock()
	for _, key := range []netLinkKey{{source: a, destination: b}, {source: b, destination: a}} {
		if link == nil {
			delete(exchange.links, key)
		} else {
			exchange.links[key] = link
		}
	}
}

// Sends one test message to a peer: Required, so it waits for the peer's session up to settings'
// SendTimeout, and is refused rather than sent in the clear. Returns once the client has taken it. The
// wait is on connect's real timers, so a schedule's actor gives up its baton for it
// (BarrierDriver.Blocking) rather than stalling the others.
func (self *NetClient) SendMessage(destinationId connect.Id, content string) error {
	frame, err := connect.ToFrame(&protocol.SimpleMessage{Content: content}, connect.DefaultProtocolVersion)
	if err != nil {
		return err
	}
	timeout := self.exchange.net.settings.SendTimeout
	var success bool
	self.exchange.net.barriers.Blocking(func() {
		success, err = self.Client.SendWithTimeoutDetailed(frame, destinationId, func(error) {}, timeout)
	})
	if !success || err != nil {
		connect.MessagePoolReturn(frame.MessageBytes)
		return fmt.Errorf("send refused: %v, %w", success, err)
	}
	return nil
}

// A message as a client received it.
type NetMessage struct {
	Source        connect.Id
	Content       string
	TransportType connect.TransportType
}

// Delivers each SimpleMessage to messages with a zero-wait send, as a receive callback must
// (connect/CODESTYLE.md:119), so a full channel drops. Returns the call that stops it.
func (self *NetClient) ReceiveMessages(messages chan<- *NetMessage) (remove func()) {
	return self.Client.AddReceiveCallback(func(source connect.TransferPath, frames []*protocol.Frame, peer connect.Peer) {
		for _, frame := range frames {
			message, err := connect.FromFrame(frame)
			if err != nil {
				continue
			}
			simple, ok := message.(*protocol.SimpleMessage)
			if !ok {
				continue
			}
			select {
			case messages <- &NetMessage{Source: source.SourceId, Content: simple.Content, TransportType: peer.TransportType}:
			default:
			}
		}
	})
}

// Waits for one message on messages, up to settings' SendTimeout in real time. Delivery runs on
// connect's real timers, so a schedule's actor gives up its baton for the wait (BarrierDriver.Blocking),
// as SendMessage does. Answers ctx's error, or one naming the timeout, when none came.
func (self *Net) AwaitMessage(ctx context.Context, messages <-chan *NetMessage) (*NetMessage, error) {
	var message *NetMessage
	var err error
	self.barriers.Blocking(func() {
		select {
		case message = <-messages:
		case <-ctx.Done():
			err = ctx.Err()
		case <-time.After(self.settings.SendTimeout):
			err = fmt.Errorf("no message came within %s", self.settings.SendTimeout)
		}
	})
	return message, err
}

// Whether both ends of a pair hold a sealed session, the state I-3 asks for.
func (self *NetClient) Sealed(peerId connect.Id) bool {
	return slices.ContainsFunc(self.Client.EncryptionSessionManager().PeerEncryptionStates(), func(state *connect.PeerEncryptionState) bool {
		return state.PeerId == peerId && state.Sealed
	})
}

// §22.7's capture: every frame through the exchange, every hooked key, and the fakes' stores.
func (self *Net) Capture() *PrivacyCapture {
	return self.capture
}
