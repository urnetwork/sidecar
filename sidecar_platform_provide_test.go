//go:build !sidecar_http && !ios_extension && !js

// What a platform's client provides from before it can receive (SidecarPlatformClientArgs.ApplyProvide): a readied
// client's provide frame, which goes out once the client's way in exists, names the key the client was given and no key
// drawn in its place; args that name no mode provide none; the edge pool asks its platform for Service from the start
// and a generation for Network, each its dispatcher's own; and on a platform that readies nothing, each opener gives
// its client the keys and the mode once the client is open. On the Net,
// TestEdgeClientPoolRestartedInPlaceTakesItsListenersContractAtOnce holds open the window a client provided that late
// leaves.

package sidecar

import (
	"bytes"
	"context"
	"crypto/rand"
	"maps"
	"sync"
	"testing"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"
)

// The way in a platform transport gives a client once it connects, for what the client sends the platform.
type platformProvideTestControlTransport struct {
	transportId connect.Id
}

func (self *platformProvideTestControlTransport) TransportId() connect.Id {
	return self.transportId
}

func (self *platformProvideTestControlTransport) Priority() int {
	return connect.TransportMaxPriority
}

func (self *platformProvideTestControlTransport) Weight() float32 {
	return 0
}

func (self *platformProvideTestControlTransport) CanEvalRouteWeight(stats *connect.RouteStats, remainingStats map[connect.Transport]*connect.RouteStats) bool {
	return true
}

func (self *platformProvideTestControlTransport) RouteWeight(stats *connect.RouteStats, remainingStats map[connect.Transport]*connect.RouteStats) float32 {
	return 1
}

func (self *platformProvideTestControlTransport) MatchesSend(destination connect.TransferPath) bool {
	return destination.DestinationId == connect.ControlId
}

func (self *platformProvideTestControlTransport) MatchesReceive(destination connect.TransferPath) bool {
	return false
}

func (self *platformProvideTestControlTransport) Downgrade(source connect.TransferPath) {
}

// One provide frame's keys, copied out of the frame.
type platformProvideTestKeys map[connectprotocol.ProvideMode][]byte

// A client as a platform has just built one, before any way in exists: on connect's defaults, held to Required as
// every opener holds them, ended at the test's end.
func platformProvideTestClient(t *testing.T) *connect.Client {
	clientSettings := connect.DefaultClientSettings()
	ApplySidecarClientSettings(clientSettings)
	client := connect.NewClient(t.Context(), connect.NewId(), connect.NewNoContractClientOob(), clientSettings)
	t.Cleanup(client.Cancel)
	return client
}

// A synthetic provide secret key, 32 random bytes.
func platformProvideTestKey(t *testing.T) []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

// A readied client provides its modes under the keys it was given, and its provide frame, held on its control sequence
// until a way in exists, names exactly those keys: the keys went in first, so the frame never names a Service key
// connect drew because the mode came before its key, which the platform would then sign contracts to the client with.
func TestApplyProvideSendsTheGivenKeysOnceTheClientConnects(t *testing.T) {
	client := platformProvideTestClient(t)
	serviceKey := platformProvideTestKey(t)
	args := &SidecarPlatformClientArgs{
		ProvideSecretKeys: map[connectprotocol.ProvideMode][]byte{connectprotocol.ProvideMode_Service: serviceKey},
		ProvideModes:      map[connectprotocol.ProvideMode]bool{connectprotocol.ProvideMode_Service: true},
	}
	args.ApplyProvide(client)
	contractManager := client.ContractManager()
	if modes := contractManager.GetProvideModes(); !maps.Equal(modes, args.ProvideModes) {
		t.Fatalf("the readied client provides %v", modes)
	}
	if key, ok := contractManager.GetProvideSecretKey(connectprotocol.ProvideMode_Service); !ok || !bytes.Equal(key, serviceKey) {
		t.Fatal("the readied client provides Service under another key")
	}

	// the way in comes after, as a platform transport's does: what the client sends the platform from then on, each
	// provide frame's keys copied out before its buffer goes back to the pool
	provides := make(chan platformProvideTestKeys, 16)
	route := make(connect.Route)
	var drained sync.WaitGroup
	drained.Add(1)
	go func() {
		defer drained.Done()
		for {
			select {
			case <-t.Context().Done():
				return
			case message := <-route:
				transferFrame := &connectprotocol.TransferFrame{}
				err := connect.ProtoUnmarshal(message, transferFrame)
				connect.MessagePoolReturn(message)
				if err != nil {
					continue
				}
				for _, frame := range transferFrame.GetPack().GetFrames() {
					if frame.GetMessageType() != connectprotocol.MessageType_TransferProvide {
						continue
					}
					decoded, err := connect.FromFrame(frame)
					provide, ok := decoded.(*connectprotocol.Provide)
					if err != nil || !ok {
						continue
					}
					keys := platformProvideTestKeys{}
					for _, provideKey := range provide.GetKeys() {
						keys[provideKey.GetMode()] = bytes.Clone(provideKey.GetProvideSecretKey())
					}
					select {
					case provides <- keys:
					default:
					}
				}
			}
		}
	}()
	t.Cleanup(drained.Wait)
	client.RouteManager().UpdateTransport(&platformProvideTestControlTransport{transportId: connect.NewId()}, []connect.Route{route})

	select {
	case keys := <-provides:
		if len(keys) != 1 || !bytes.Equal(keys[connectprotocol.ProvideMode_Service], serviceKey) {
			t.Errorf("the first provide frame names %d keys, Service's the given one: %t", len(keys), bytes.Equal(keys[connectprotocol.ProvideMode_Service], serviceKey))
		}
	case <-t.Context().Done():
		t.Fatal("no provide frame reached the platform")
	}
}

// Args that name keys and no mode load the keys and provide nothing: a client whose opener sets its modes later, as
// one whose platform cannot ready it.
func TestApplyProvideWithNoModesProvidesNothing(t *testing.T) {
	client := platformProvideTestClient(t)
	networkKey := platformProvideTestKey(t)
	args := &SidecarPlatformClientArgs{
		ProvideSecretKeys: map[connectprotocol.ProvideMode][]byte{connectprotocol.ProvideMode_Network: networkKey},
	}
	args.ApplyProvide(client)
	contractManager := client.ContractManager()
	if modes := contractManager.GetProvideModes(); len(modes) != 0 {
		t.Errorf("a client given no mode provides %v", modes)
	}
	if !bytes.Equal(contractManager.GetProvideSecretKeys()[connectprotocol.ProvideMode_Network], networkKey) {
		t.Error("the given key was not loaded")
	}
	// nothing at all to apply is nothing done
	(&SidecarPlatformClientArgs{}).ApplyProvide(client)
	if modes := contractManager.GetProvideModes(); len(modes) != 0 {
		t.Errorf("empty args left the client providing %v", modes)
	}
}

// A test platform that readies each client as connect's platform does, before anything can reach it, and records what
// the client provides at that moment, the first at which a contract could reach it.
type edgePoolReadyingTestPlatform struct {
	platform *edgePoolTestPlatform

	stateLock sync.Mutex
	// in open order
	reachableModes       []map[connectprotocol.ProvideMode]bool
	reachableServiceKeys [][]byte
}

func (self *edgePoolReadyingTestPlatform) OpenClient(ctx context.Context, args *SidecarPlatformClientArgs) (*SidecarPlatformClient, error) {
	client, err := self.platform.OpenClient(ctx, args)
	if err != nil {
		return nil, err
	}
	args.ApplyProvide(client.Client)
	// the client is reachable from here on
	contractManager := client.Client.ContractManager()
	modes := contractManager.GetProvideModes()
	serviceKey := bytes.Clone(contractManager.GetProvideSecretKeys()[connectprotocol.ProvideMode_Service])
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.reachableModes = append(self.reachableModes, modes)
	self.reachableServiceKeys = append(self.reachableServiceKeys, serviceKey)
	return client, nil
}

// Each client's opener asks for Service and nothing else, the edge dispatcher's own mode, so a platform that readies
// the client has it providing Service under its slot's key from the moment it can receive, as a restarted edge's first
// contract from a listener needs; and the pool's own steps after the open leave that as it is.
func TestEdgeClientPoolAsksForServiceFromBeforeItsClientCanReceive(t *testing.T) {
	source := newEdgePoolTestIdentitySource(t, 2)
	platform := &edgePoolReadyingTestPlatform{platform: newEdgePoolTestPlatform()}
	pool, err := NewEdgeClientPool(t.Context(), &EdgeClientPoolArgs{Source: source, Platform: platform, Settings: newEdgePoolTestSettings(2)})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	service := map[connectprotocol.ProvideMode]bool{connectprotocol.ProvideMode_Service: true}
	opened := platform.platform.openedArgs()
	clients := pool.Clients()
	if len(opened) != 2 || len(clients) != 2 || len(platform.reachableModes) != 2 {
		t.Fatalf("%d opened, %d listed, %d readied", len(opened), len(clients), len(platform.reachableModes))
	}
	for index, args := range opened {
		serviceKey := edgeIdentityTestDerive(t, bytes.Clone(source.seeds[index])).serviceProvideSecretKey
		if !maps.Equal(args.ProvideModes, service) {
			t.Errorf("client %d's opener asked for %v", index, args.ProvideModes)
		}
		if !maps.Equal(platform.reachableModes[index], service) || !bytes.Equal(platform.reachableServiceKeys[index], serviceKey) {
			t.Errorf("client %d became reachable providing %v, under its slot's Service key: %t", index, platform.reachableModes[index], bytes.Equal(platform.reachableServiceKeys[index], serviceKey))
		}
		contractManager := clients[index].Subprotocol.client.ContractManager()
		key, ok := contractManager.GetProvideSecretKey(connectprotocol.ProvideMode_Service)
		if modes := contractManager.GetProvideModes(); !maps.Equal(modes, service) || !ok || !bytes.Equal(key, serviceKey) {
			t.Errorf("client %d provides %v once the pool is made, under its slot's Service key: %t", index, modes, ok && bytes.Equal(key, serviceKey))
		}
	}
}

// On a platform that readies nothing as it builds a client, the pool gives each client its slot's key and then Service
// once the client is open: late, but the state a readied client starts in.
func TestEdgeClientPoolProvidesServiceOnAPlatformThatReadiesNothing(t *testing.T) {
	source := newEdgePoolTestIdentitySource(t, 2)
	pool, err := NewEdgeClientPool(t.Context(), &EdgeClientPoolArgs{Source: source, Platform: newEdgePoolTestPlatform(), Settings: newEdgePoolTestSettings(2)})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	service := map[connectprotocol.ProvideMode]bool{connectprotocol.ProvideMode_Service: true}
	for index, client := range pool.Clients() {
		serviceKey := edgeIdentityTestDerive(t, bytes.Clone(source.seeds[index])).serviceProvideSecretKey
		contractManager := client.Subprotocol.client.ContractManager()
		key, ok := contractManager.GetProvideSecretKey(connectprotocol.ProvideMode_Service)
		if modes := contractManager.GetProvideModes(); !maps.Equal(modes, service) || !ok || !bytes.Equal(key, serviceKey) {
			t.Errorf("client %d provides %v, under its slot's Service key: %t", index, modes, ok && bytes.Equal(key, serviceKey))
		}
	}
}

// A generation's opener asks for Network from the start, its dispatcher's own mode, beside the keys the generation
// keeps; on a platform that readies nothing, the leg gives the client both once it is open, Network under the kept key.
func TestGenerationAsksItsPlatformForNetworkFromTheStart(t *testing.T) {
	instance, enrollment := newTestEnrolledInstance(t)
	platform := newTestSidecarPlatform()
	component := newTestComponent("provide")
	newTestRunningSidecar(t, instance, &enrollment.networkId, testSidecarSettings(platform), component)
	// a component attaches only once the generation's start, the leg's steps after the open among them, has run
	component.awaitAttached(t, 1)
	client := platform.awaitOpened(t, 1)
	network := map[connectprotocol.ProvideMode]bool{connectprotocol.ProvideMode_Network: true}
	if !maps.Equal(client.args.ProvideModes, network) {
		t.Errorf("the generation's opener asked for %v", client.args.ProvideModes)
	}
	networkKey := client.args.ProvideSecretKeys[connectprotocol.ProvideMode_Network]
	contractManager := client.client.ContractManager()
	key, ok := contractManager.GetProvideSecretKey(connectprotocol.ProvideMode_Network)
	if modes := contractManager.GetProvideModes(); !maps.Equal(modes, network) || len(networkKey) == 0 || !ok || !bytes.Equal(key, networkKey) {
		t.Errorf("the generation's client provides %v, under its kept Network key: %t", modes, ok && bytes.Equal(key, networkKey))
	}
}
