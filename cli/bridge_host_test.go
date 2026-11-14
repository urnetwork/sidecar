// The CLI's BridgeHost (bridge_host.go): a link's window client is minted through the Sidecar's api, the generator's
// ClientCredentials, as a child of the sidecar's client, and never on connect's plain path, which a strict_exp bearer's
// mint would fail; a build with no client generation, or for a share, is refused; a mint whose answer does not mark
// admin_refused and strict_exp is refused; and the sink adapter reads the device role's decision.

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
)

// Credentials that record each mint and refuse it.
type testUrBridgeCredentials struct {
	stateLock sync.Mutex
	mints     []*connect.AuthNetworkClientArgs
}

var errTestUrBridgeMint = errors.New("the test's credentials refuse every mint")

func (self *testUrBridgeCredentials) AuthNetworkClient(ctx context.Context, args *connect.AuthNetworkClientArgs) (*connect.AuthNetworkClientResult, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.mints = append(self.mints, args)
	return nil, errTestUrBridgeMint
}

func (self *testUrBridgeCredentials) RemoveNetworkClient(ctx context.Context, args *connect.RemoveNetworkClientArgs) (*connect.RemoveNetworkClientResult, error) {
	return &connect.RemoveNetworkClientResult{}, nil
}

// §7.4's trap: a link's mint goes through ClientCredentials as a child of the sidecar's client, and the plain path's
// POST /network/auth-client is never sent.
func TestBridgeHostMintsThroughTheSidecarsApi(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var plainLock sync.Mutex
	plainMints := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/network/auth-client" {
			plainLock.Lock()
			plainMints += 1
			plainLock.Unlock()
		}
		writer.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	credentials := &testUrBridgeCredentials{}
	sourceClientId := connect.NewId()
	generation := &urBridgeGeneration{
		credentials:    credentials,
		sourceClientId: sourceClientId,
		strategy:       connect.NewClientStrategy(ctx, connect.DefaultClientStrategySettings()),
		apiUrl:         server.URL,
		platformUrl:    server.URL,
	}
	generator, ok := urBridgeApiGenerator(ctx, generation, connect.NewId()).(*connect.ApiMultiClientGenerator)
	if !ok {
		t.Fatal("the link's generator is not connect's")
	}
	if _, err := generator.NewClientArgs(); !errors.Is(err, errTestUrBridgeMint) {
		t.Fatalf("a mint: %v", err)
	}
	credentials.stateLock.Lock()
	mints := credentials.mints
	credentials.stateLock.Unlock()
	if len(mints) != 1 || mints[0].SourceClientId == nil || *mints[0].SourceClientId != sourceClientId {
		t.Fatalf("mints through the credentials: %v", mints)
	}
	plainLock.Lock()
	defer plainLock.Unlock()
	if plainMints != 0 {
		t.Fatalf("%d mints on the plain path", plainMints)
	}
}

// A build with no client generation, and a share link before shares, are refused and build nothing.
func TestBridgeHostRefusesWhatItCannotBuild(t *testing.T) {
	host := newUrBridgeHost(context.Background(), nil)
	sign := func(windowClientId connect.Id, windowClientPublicKey []byte, notAfter time.Time) ([]byte, error) {
		return nil, errors.New("never signed")
	}
	if client, err := host.NewBridgeLink(context.Background(), connect.NewId(), connect.NewId(), nil, sign); !errors.Is(err, errUrBridgeHostRefused) || client != nil {
		t.Errorf("no generation: %v", err)
	}
	host.setGeneration(&urBridgeGeneration{credentials: &testUrBridgeCredentials{}})
	shareAliases := []netip.Prefix{netip.MustParsePrefix("100.80.200.0/24")}
	if client, err := host.NewBridgeLink(context.Background(), connect.NewId(), connect.NewId(), shareAliases, sign); !errors.Is(err, errUrBridgeHostRefused) || client != nil {
		t.Errorf("a share link: %v", err)
	}
	if err := device.CheckBridgeLinkMultiClientSettings(device.BridgeLinkMultiClientSettings(host.settings), host.settings.LinkAllowDirect); err != nil {
		t.Errorf("the links' settings: %v", err)
	}
}

// The sink adapter reads a fresh device role as legacy with no pins, and after its anchor as pending.
func TestBridgeSinkReadsTheDeviceRolesDecision(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store, err := device.NewFilePostureStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	deviceBridge, err := device.NewBridge(ctx, store, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer deviceBridge.Close()
	sink := &urBridgeSink{bridge: deviceBridge}
	if decision := sink.Decision(); decision.State != sidecar.BridgeSinkLegacy || decision.Pin != nil || decision.StatePin != nil {
		t.Fatalf("a fresh role: %+v", decision)
	}
	if sink.EgressHook() != deviceBridge.EgressHook() {
		t.Error("the adapter hands another hook")
	}
}
