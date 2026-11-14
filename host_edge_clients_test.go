//go:build !sidecar_http && !ios_extension

// EdgeClientPool on a platform a test answers: K clients opened Required, relay-only, on id 21842 alone and providing
// Service only, each with an edge dispatcher; ready only while all K are connected; a client the pool does not hold
// refused; a source that fails, answers part of a credential or repeats a client id failing the pool; and a closed
// authorization asking the source again for the same client.

package sidecar

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"
)

// A source of synthetic credentials: client ids fixed per index, and a jwt that names how often the index was asked.
type edgePoolTestSource struct {
	stateLock sync.Mutex
	clientIds []connect.Id
	asked     map[int]int
	// answered for an index when set
	errs map[int]error
	// credentials answered whole unless an index is listed
	partial map[int]bool
	// signalled at each ask
	askedSignal chan int
}

func newEdgePoolTestSource(count int) *edgePoolTestSource {
	source := &edgePoolTestSource{asked: map[int]int{}, errs: map[int]error{}, partial: map[int]bool{}, askedSignal: make(chan int, 64)}
	for range count {
		source.clientIds = append(source.clientIds, connect.NewId())
	}
	return source
}

func (self *edgePoolTestSource) ServiceClient(ctx context.Context, clientIndex int) (*ServiceClientAuth, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.asked[clientIndex] += 1
	select {
	case self.askedSignal <- clientIndex:
	default:
	}
	if err := self.errs[clientIndex]; err != nil {
		return nil, err
	}
	credential := &ServiceClientAuth{
		ClientId:    self.clientIds[clientIndex],
		ByJwt:       "synthetic-jwt-" + string(rune('a'+clientIndex)) + "-" + string(rune('0'+self.asked[clientIndex])),
		ApiUrl:      "https://api.sidecar.example",
		PlatformUrl: "wss://connect.sidecar.example",
	}
	if self.partial[clientIndex] {
		credential.ByJwt = ""
	}
	return credential, nil
}

func (self *edgePoolTestSource) askedCount(clientIndex int) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.asked[clientIndex]
}

// A platform that builds each client on exactly the settings it was given, with no transport: a test says which are
// connected, and reads what was opened, installed and closed.
type edgePoolTestPlatform struct {
	stateLock sync.Mutex
	opened    []*SidecarPlatformClientArgs
	connected map[connect.Id]bool
	auths     map[connect.Id][]string
	closed    map[connect.Id]bool
	// signalled at each SetAuth
	authSignal chan connect.Id
	failIndex  int
}

func newEdgePoolTestPlatform() *edgePoolTestPlatform {
	return &edgePoolTestPlatform{connected: map[connect.Id]bool{}, auths: map[connect.Id][]string{}, closed: map[connect.Id]bool{}, authSignal: make(chan connect.Id, 64), failIndex: -1}
}

func (self *edgePoolTestPlatform) OpenClient(ctx context.Context, args *SidecarPlatformClientArgs) (*SidecarPlatformClient, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if len(self.opened) == self.failIndex {
		return nil, errors.New("synthetic open failure")
	}
	self.opened = append(self.opened, args)
	client := connect.NewClient(ctx, args.ClientId, connect.NewNoContractClientOob(), args.ClientSettings)
	clientId := args.ClientId
	return &SidecarPlatformClient{
		Client: client,
		SetAuth: func(auth *connect.ClientAuth) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.auths[clientId] = append(self.auths[clientId], auth.ByJwt)
			self.authSignal <- clientId
		},
		Connected: func() (bool, <-chan struct{}) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.connected[clientId], nil
		},
		CloseAndWait: func(ctx context.Context) error {
			client.Cancel()
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.closed[clientId] = true
			return nil
		},
	}, nil
}

func (self *edgePoolTestPlatform) setConnected(clientId connect.Id, connected bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.connected[clientId] = connected
}

func (self *edgePoolTestPlatform) openedArgs() []*SidecarPlatformClientArgs {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.opened)
}

func (self *edgePoolTestPlatform) closedCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.closed)
}

func newEdgePoolTestSettings(count int) *EdgeClientPoolSettings {
	settings := DefaultEdgeClientPoolSettings()
	settings.ClientCount = count
	settings.AppVersion = "0.0.0-test"
	return settings
}

func TestDefaultEdgeClientPoolSettings(t *testing.T) {
	settings := DefaultEdgeClientPoolSettings()
	if settings.ClientCount != 4 || settings.MemoryBudgetByteCount != 192*1024*1024 || settings.AuthRetryInterval.Seconds() != 5 || settings.CloseTimeout.Seconds() != 10 {
		t.Errorf("settings %+v", settings)
	}
	if settings.Protocol == nil || settings.ClientSettings == nil || settings.ClientStrategySettings == nil || settings.PlatformTransportSettings == nil {
		t.Errorf("a part is missing: %+v", settings)
	}
	if DefaultEdgeClientPoolSettings() == settings {
		t.Error("the defaults are shared")
	}
}

// Each of the K clients is Required and relay-only, takes Service sources on id 21842 alone, provides Service and
// nothing else, and has a dispatcher in the edge's role.
func TestEdgeClientPoolOpensRequiredRelayOnlyServiceClients(t *testing.T) {
	source := newEdgePoolTestSource(3)
	platform := newEdgePoolTestPlatform()
	pool, err := NewEdgeClientPool(t.Context(), &EdgeClientPoolArgs{Source: source, Platform: platform, Settings: newEdgePoolTestSettings(3)})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	opened := platform.openedArgs()
	if len(opened) != 3 {
		t.Fatalf("%d clients opened", len(opened))
	}
	for index, args := range opened {
		if args.ClientId != source.clientIds[index] {
			t.Errorf("client %d's id", index)
		}
		clientSettings := args.ClientSettings
		if clientSettings.EncryptionSettings == nil || clientSettings.EncryptionSettings.Mode != connect.EncryptionModeRequired {
			t.Errorf("client %d is not Required", index)
		}
		if clientSettings.DefaultTransferOpts.ForceStream {
			t.Errorf("client %d asks for a P2P stream", index)
		}
		if !slices.Equal(clientSettings.ServiceSubprotocolIds, []connect.SubprotocolId{SubprotocolId}) {
			t.Errorf("client %d's service ids %v", index, clientSettings.ServiceSubprotocolIds)
		}
		if args.Auth.ByJwt == "" || args.Auth.StreamLeaseVersion != 1 || args.Auth.AppVersion != "0.0.0-test" {
			t.Errorf("client %d's auth", index)
		}
		if args.ApiUrl != "https://api.sidecar.example" || args.PlatformUrl != "wss://connect.sidecar.example" || args.PlatformTransportSettings.AuthorizationClosed == nil {
			t.Errorf("client %d's urls or transport settings", index)
		}
	}
	clients := pool.Clients()
	if len(clients) != 3 || len(pool.ClientIds()) != 3 {
		t.Fatalf("%d clients listed", len(clients))
	}
	for index, client := range clients {
		if client.ClientId != Id(source.clientIds[index]) || pool.ClientIds()[index] != client.ClientId {
			t.Errorf("client %d listed out of order", index)
		}
		if client.Subprotocol == nil || client.Subprotocol.role != SubprotocolRoleEdge {
			t.Errorf("client %d's dispatcher is not an edge's", index)
		}
		provideModes := client.Subprotocol.client.ContractManager().GetProvideModes()
		if len(provideModes) != 1 || !provideModes[connectprotocol.ProvideMode_Service] {
			t.Errorf("client %d provides %v", index, provideModes)
		}
	}
}

func TestEdgeClientPoolIsReadyOnlyWhileAllAreConnected(t *testing.T) {
	source := newEdgePoolTestSource(2)
	platform := newEdgePoolTestPlatform()
	pool, err := NewEdgeClientPool(t.Context(), &EdgeClientPoolArgs{Source: source, Platform: platform, Settings: newEdgePoolTestSettings(2)})
	if err != nil {
		t.Fatal(err)
	}
	if pool.Ready() || pool.ConnectedCount() != 0 {
		t.Error("ready with no client connected")
	}
	platform.setConnected(source.clientIds[0], true)
	if pool.Ready() || pool.ConnectedCount() != 1 {
		t.Error("ready with one of two connected")
	}
	platform.setConnected(source.clientIds[1], true)
	if !pool.Ready() {
		t.Error("not ready with both connected")
	}
	platform.setConnected(source.clientIds[0], false)
	if pool.Ready() {
		t.Error("ready after one dropped")
	}
	platform.setConnected(source.clientIds[0], true)
	pool.Close()
	pool.Close()
	if pool.Ready() || platform.closedCount() != 2 {
		t.Errorf("after Close: ready %t, %d closed", pool.Ready(), platform.closedCount())
	}
}

func TestEdgeClientPoolRefusesAClientItDoesNotHold(t *testing.T) {
	source := newEdgePoolTestSource(2)
	pool, err := NewEdgeClientPool(t.Context(), &EdgeClientPoolArgs{Source: source, Platform: newEdgePoolTestPlatform(), Settings: newEdgePoolTestSettings(2)})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	held, err := pool.Client(Id(source.clientIds[1]))
	if err != nil || held.ClientId != Id(source.clientIds[1]) || held.Subprotocol == nil {
		t.Errorf("a held client: %+v, %v", held, err)
	}
	if _, err := pool.Client(Id(connect.NewId())); !errors.Is(err, ErrEdgeClientPoolUnknown) {
		t.Errorf("another process's client: %v", err)
	}
	if _, err := pool.Client(Id{}); !errors.Is(err, ErrEdgeClientPoolUnknown) {
		t.Errorf("the zero id: %v", err)
	}
}

func TestNewEdgeClientPoolFailsClosed(t *testing.T) {
	if _, err := NewEdgeClientPool(t.Context(), nil); !errors.Is(err, ErrEdgeClientPool) {
		t.Errorf("no args: %v", err)
	}
	if _, err := NewEdgeClientPool(t.Context(), &EdgeClientPoolArgs{Platform: newEdgePoolTestPlatform()}); !errors.Is(err, ErrEdgeClientPool) {
		t.Errorf("no source: %v", err)
	}
	zero := newEdgePoolTestSettings(0)
	if _, err := NewEdgeClientPool(t.Context(), &EdgeClientPoolArgs{Source: newEdgePoolTestSource(1), Platform: newEdgePoolTestPlatform(), Settings: zero}); !errors.Is(err, ErrEdgeClientPool) {
		t.Errorf("no clients: %v", err)
	}
	// the source fails the second index: the first client is closed, and no pool is left
	failing := newEdgePoolTestSource(2)
	failing.errs[1] = errors.New("synthetic source failure")
	platform := newEdgePoolTestPlatform()
	if _, err := NewEdgeClientPool(t.Context(), &EdgeClientPoolArgs{Source: failing, Platform: platform, Settings: newEdgePoolTestSettings(2)}); err == nil {
		t.Error("a failing source made a pool")
	}
	if platform.closedCount() != 1 {
		t.Errorf("%d clients closed after a failed start", platform.closedCount())
	}
	// part of a credential is never a success
	partial := newEdgePoolTestSource(1)
	partial.partial[0] = true
	if _, err := NewEdgeClientPool(t.Context(), &EdgeClientPoolArgs{Source: partial, Platform: newEdgePoolTestPlatform(), Settings: newEdgePoolTestSettings(1)}); !errors.Is(err, ErrEdgeClientPool) {
		t.Errorf("a credential with no jwt: %v", err)
	}
	// one client id for two indexes would tie two dispatchers to one client
	repeated := newEdgePoolTestSource(2)
	repeated.clientIds[1] = repeated.clientIds[0]
	platform = newEdgePoolTestPlatform()
	if _, err := NewEdgeClientPool(t.Context(), &EdgeClientPoolArgs{Source: repeated, Platform: platform, Settings: newEdgePoolTestSettings(2)}); !errors.Is(err, ErrEdgeClientPool) {
		t.Errorf("a repeated client id: %v", err)
	}
	// the platform refuses the second open
	refusing := newEdgePoolTestPlatform()
	refusing.failIndex = 1
	if _, err := NewEdgeClientPool(t.Context(), &EdgeClientPoolArgs{Source: newEdgePoolTestSource(2), Platform: refusing, Settings: newEdgePoolTestSettings(2)}); !errors.Is(err, ErrEdgeClientPool) {
		t.Errorf("a refused open: %v", err)
	}
	if refusing.closedCount() != 1 {
		t.Errorf("%d clients closed after a refused open", refusing.closedCount())
	}
}

// The platform closing a client's authorization has the pool ask the source again for that index, and install the
// newer jwt on that client alone.
func TestEdgeClientPoolAsksTheSourceAgainWhenAuthorizationCloses(t *testing.T) {
	source := newEdgePoolTestSource(2)
	platform := newEdgePoolTestPlatform()
	pool, err := NewEdgeClientPool(t.Context(), &EdgeClientPoolArgs{Source: source, Platform: platform, Settings: newEdgePoolTestSettings(2)})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	opened := platform.openedArgs()
	opened[1].PlatformTransportSettings.AuthorizationClosed(connect.AuthorizationCloseUnavailable)
	select {
	case clientId := <-platform.authSignal:
		if clientId != source.clientIds[1] {
			t.Errorf("another client's auth was installed")
		}
	case <-t.Context().Done():
		t.Fatal("no auth installed")
	}
	if source.askedCount(1) != 2 || source.askedCount(0) != 1 {
		t.Errorf("asked %d and %d times", source.askedCount(0), source.askedCount(1))
	}
	platform.stateLock.Lock()
	installed := slices.Clone(platform.auths[source.clientIds[1]])
	platform.stateLock.Unlock()
	if len(installed) != 1 || installed[0] != "synthetic-jwt-b-2" {
		t.Errorf("installed %v", installed)
	}
}
