// The generator wrapper (bridge_link_generator.go) on real connect clients: the out-of-band control here is the
// platform, which sees each contract request and answers it. A window client is signed for before the window gets it,
// so its first contract request carries the delegation; a sign that fails retires the client with its args, once, and
// no contract is asked for; a contract whose stored key is not the one the target's binding names is refused and marks
// the link down (FS-38's sender row); a token with no exp gets no delegation; and a context no link's build made
// refuses every client.

package device_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/sidecartest"
)

// An unsigned token naming clientId, expiring at expireTime, or never with a zero one, as the platform's child token
// reads to ParseByJwtUnverified. Nothing verifies it here.
func generatorTestToken(t *testing.T, clientId connect.Id, expireTime time.Time) string {
	t.Helper()
	claims := map[string]any{"client_id": clientId.String()}
	if !expireTime.IsZero() {
		claims["exp"] = expireTime.Unix()
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	return encode([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + encode(claimsBytes) + "." + encode([]byte("unsigned"))
}

// The platform's side of a window client's out-of-band control: every contract request, with its answer to come.
type generatorTestControl struct {
	stateLock sync.Mutex
	requests  []*protocol.CreateContract
	callbacks []connect.OobResultFunction
	answered  []bool
}

// connect.OutOfBandControl: keeps each contract request and its callback, and answers every other control at once.
func (self *generatorTestControl) SendControl(frames []*protocol.Frame, callback connect.OobResultFunction) {
	var request *protocol.CreateContract
	for _, frame := range frames {
		message, err := connect.FromFrame(frame)
		connect.MessagePoolReturn(frame.MessageBytes)
		if create, ok := message.(*protocol.CreateContract); err == nil && ok {
			request = create
		}
	}
	if request == nil {
		callback(nil, nil)
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.requests = append(self.requests, request)
	self.callbacks = append(self.callbacks, callback)
	self.answered = append(self.answered, false)
}

// Answers request index with frames, outside the lock, as the platform's reply would arrive.
func (self *generatorTestControl) answer(index int, frames []*protocol.Frame, err error) {
	callback := func() connect.OobResultFunction {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.answered[index] = true
		return self.callbacks[index]
	}()
	callback(frames, err)
}

// Fails every request not yet answered, so a client closing waits on none.
func (self *generatorTestControl) failPending() {
	pending := func() []int {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		indexes := []int{}
		for index, answered := range self.answered {
			if !answered {
				indexes = append(indexes, index)
			}
		}
		return indexes
	}()
	for _, index := range pending {
		self.answer(index, nil, errors.New("the test ended"))
	}
}

// The contract requests so far.
func (self *generatorTestControl) taken() []*protocol.CreateContract {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*protocol.CreateContract(nil), self.requests...)
}

// The host's own generator: real clients on the test's control, tokens expiring at expireTime, and a count of each
// retirement.
type generatorTestInner struct {
	t          *testing.T
	control    *generatorTestControl
	expireTime time.Time

	stateLock       sync.Mutex
	clients         []*connect.Client
	removedArgs     int
	removedWithArgs int
}

func (self *generatorTestInner) NextDestinations(count int, excludeDestinations []connect.MultiHopId, rankMode string) (map[connect.MultiHopId]connect.DestinationStats, error) {
	return map[connect.MultiHopId]connect.DestinationStats{}, nil
}

func (self *generatorTestInner) NewClientArgs() (*connect.MultiClientGeneratorClientArgs, error) {
	clientId := connect.NewId()
	return &connect.MultiClientGeneratorClientArgs{
		ClientId:   clientId,
		ClientAuth: &connect.ClientAuth{ByJwt: generatorTestToken(self.t, clientId, self.expireTime)},
	}, nil
}

func (self *generatorTestInner) RemoveClientArgs(args *connect.MultiClientGeneratorClientArgs) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.removedArgs += 1
}

func (self *generatorTestInner) RemoveClientWithArgs(client *connect.Client, args *connect.MultiClientGeneratorClientArgs) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.removedWithArgs += 1
}

func (self *generatorTestInner) NewClientSettings() *connect.ClientSettings {
	settings := connect.DefaultClientSettings()
	settings.Log = connect.NewNoopLogger()
	settings.EncryptionSettings.Mode = connect.EncryptionModeOff
	settings.ControlPingTimeout = 0
	return settings
}

func (self *generatorTestInner) NewClient(ctx context.Context, args *connect.MultiClientGeneratorClientArgs, clientSettings *connect.ClientSettings) (*connect.Client, error) {
	client := connect.NewClient(ctx, args.ClientId, self.control, clientSettings)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.clients = append(self.clients, client)
	return client, nil
}

func (self *generatorTestInner) FixedDestinationSize() (int, bool) {
	return 1, true
}

// How many args and clients with their args the host's generator retired.
func (self *generatorTestInner) retired() (removedArgs int, removedWithArgs int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.removedArgs, self.removedWithArgs
}

// Joins every client the generator built.
func (self *generatorTestInner) close(t *testing.T) {
	self.stateLock.Lock()
	clients := append([]*connect.Client(nil), self.clients...)
	self.stateLock.Unlock()
	self.control.failPending()
	for _, client := range clients {
		client.Cancel()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := client.CloseAndWait(ctx); err != nil {
			t.Error(err)
		}
		cancel()
	}
}

// A host as the sdk's and the CLI's are, past the multi client: it wraps its generator for the link and builds one
// window client through it, as the link's window would, handing the args back on a failure as the window does.
type generatorTestHost struct {
	inner *generatorTestInner

	stateLock sync.Mutex
	window    *connect.Client
	newErr    error
}

func (self *generatorTestHost) NewBridgeLink(ctx context.Context, target connect.Id, subject connect.Id, shareAliases []netip.Prefix,
	sign func(windowClientId connect.Id, windowClientPublicKey []byte, notAfter time.Time) ([]byte, error),
) (connect.UserNatClient, error) {
	generator := device.NewBridgeLinkGenerator(ctx, self.inner, sign)
	args, err := generator.NewClientArgs()
	if err != nil {
		return nil, err
	}
	window, err := generator.NewClient(ctx, args, generator.NewClientSettings())
	self.stateLock.Lock()
	self.window = window
	self.newErr = err
	self.stateLock.Unlock()
	if err != nil {
		generator.RemoveClientArgs(args)
	}
	return &sidecartest.FakeBridgeLink{Target: target}, nil
}

// The window client the link's build made, and the error its NewClient returned.
func (self *generatorTestHost) built() (*connect.Client, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.window, self.newErr
}

// A link manager on the generator host, signing for tokens that expire at expireTime.
func newGeneratorTest(t *testing.T, expireTime time.Time) (*linkTest, *generatorTestHost) {
	t.Helper()
	inner := &generatorTestInner{t: t, control: &generatorTestControl{}, expireTime: expireTime}
	host := &generatorTestHost{inner: inner}
	test := &linkTest{
		t:        t,
		clock:    sidecartest.NewFakeClock(time.UnixMilli(linkTestTimeMs)),
		downs:    make(chan device.BridgeLinkId, 256),
		changes:  make(chan struct{}, 1),
		bindings: map[connect.Id][]byte{},
	}
	settings := device.DefaultBridgeSettings()
	settings.Clock = test.clock
	settings.LinkSign = test.sign
	settings.LinkTargetKey = test.targetKey
	test.manager = device.NewBridgeLinkManager(context.Background(), host, settings)
	t.Cleanup(func() {
		test.manager.Close()
		inner.close(t)
	})
	test.passes = test.manager.WatchForTest()
	test.manager.AddDownCallback(func(link device.BridgeLinkId) {
		test.downs <- link
	})
	test.manager.SetIdentity(linkTestNetworkId, linkTestSidecarId)
	return test, host
}

// Builds the target's link, and returns its id with the window client the build made.
func (self *linkTest) buildWindow(host *generatorTestHost, seed byte) (device.BridgeLinkId, *connect.Client, error) {
	self.t.Helper()
	link := self.link(seed)
	self.manager.RouteForTest(link)
	self.await("the build", func() bool { return self.manager.LinkBuiltForTest(link) })
	window, err := host.built()
	return link, window, err
}

// A window client is signed for before the window gets it: its first contract request carries the delegation as the
// sidecar role signed it, naming the window client, its key and its token's exp.
func TestBridgeLinkGeneratorSignsBeforeAnyContract(t *testing.T) {
	expireTime := time.UnixMilli(linkTestTimeMs).Add(7 * 24 * time.Hour)
	test, host := newGeneratorTest(t, expireTime)
	_, window, err := test.buildWindow(host, 4)
	if err != nil || window == nil {
		t.Fatalf("no window client: %v", err)
	}
	signed := test.signedDelegations()
	if len(signed) != 1 {
		t.Fatalf("%d delegations signed, want 1", len(signed))
	}
	delegation := signed[0]
	if !bytes.Equal(delegation.GetWindowClientId(), window.ClientId().Bytes()) ||
		!bytes.Equal(delegation.GetWindowClientPublicKey(), window.ClientKeyManager().PublicKey()) ||
		delegation.GetNotAfterMs() != expireTime.UnixMilli() {
		t.Fatalf("delegation %v for window client %v", delegation, window.ClientId())
	}
	target := linkTestTarget(4)
	window.ContractManager().CreateContract(connect.ContractKey{Destination: connect.DestinationId(target.ClientId)}, 0, 0)
	requests := host.inner.control.taken()
	if len(requests) != 1 {
		t.Fatalf("%d contract requests, want 1", len(requests))
	}
	if want := append([]byte("signed delegation of "), window.ClientId().Bytes()...); !bytes.Equal(requests[0].WindowDelegation, want) {
		t.Fatalf("the request carried %q", requests[0].WindowDelegation)
	}
}

// A sign the sidecar role refuses retires the window client with its args, and the args the window hands back are not
// retired again; no contract is asked for, and the link has a window client never.
func TestBridgeLinkGeneratorSignErrorRetiresTheClient(t *testing.T) {
	test, host := newGeneratorTest(t, time.UnixMilli(linkTestTimeMs).Add(7*24*time.Hour))
	test.setSignErr(errors.New("refused"))
	_, window, err := test.buildWindow(host, 4)
	if window != nil || !errors.Is(err, device.ErrBridgeLinkRefused) {
		t.Fatalf("window %v, error %v", window, err)
	}
	removedArgs, removedWithArgs := host.inner.retired()
	if removedWithArgs != 1 || removedArgs != 0 {
		t.Fatalf("retired %d args and %d clients with their args, want 0 and 1", removedArgs, removedWithArgs)
	}
	if requests := host.inner.control.taken(); len(requests) != 0 {
		t.Fatalf("%d contract requests from a refused window client", len(requests))
	}
}

// A token with no exp bounds nothing, so its window client gets no delegation and no contract.
func TestBridgeLinkGeneratorRefusesATokenWithNoExp(t *testing.T) {
	test, host := newGeneratorTest(t, time.Time{})
	_, window, err := test.buildWindow(host, 4)
	if window != nil || !errors.Is(err, device.ErrBridgeLinkRefused) {
		t.Fatalf("window %v, error %v", window, err)
	}
	if signed := test.signedDelegations(); len(signed) != 0 {
		t.Fatalf("%d delegations signed for a token with no exp", len(signed))
	}
}

// FS-38's sender row: a contract whose stored key is not the key the target's verified binding names is refused, and
// the link is marked down; a contract with the target's key is taken.
func TestBridgeLinkGeneratorRefusesASubstitutedTargetKey(t *testing.T) {
	test, host := newGeneratorTest(t, time.UnixMilli(linkTestTimeMs).Add(7*24*time.Hour))
	link, window, err := test.buildWindow(host, 4)
	if err != nil {
		t.Fatal(err)
	}
	target := linkTestTarget(4)
	contractKey := connect.ContractKey{Destination: connect.DestinationId(target.ClientId)}
	answer := func(index int, storedKey []byte) {
		storedBytes, err := proto.Marshal(&protocol.StoredContract{
			ContractId:                 connect.NewId().Bytes(),
			TransferByteCount:          1024 * 1024,
			SourceId:                   window.ClientId().Bytes(),
			DestinationId:              target.ClientId.Bytes(),
			DestinationClientPublicKey: storedKey,
		})
		if err != nil {
			t.Fatal(err)
		}
		resultBytes, err := proto.Marshal(&protocol.CreateContractResult{Contract: &protocol.Contract{
			StoredContractBytes: storedBytes,
			ProvideMode:         protocol.ProvideMode_Network,
		}})
		if err != nil {
			t.Fatal(err)
		}
		host.inner.control.answer(index, []*protocol.Frame{{MessageType: protocol.MessageType_TransferCreateContractResult, MessageBytes: resultBytes}}, nil)
	}

	substitutedKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	window.ContractManager().CreateContract(contractKey, 0, 0)
	answer(0, substitutedKey)
	if down := test.awaitDown(); down != link {
		t.Fatalf("link %d down, want %d", down, link)
	}
	if contract := window.ContractManager().TakeContract(context.Background(), contractKey, 0); contract != nil {
		t.Fatal("a contract to a substituted key was taken")
	}

	window.ContractManager().CreateContract(contractKey, 1, 0)
	answer(1, linkTestClientKey(4).Public().(ed25519.PublicKey))
	if contract := window.ContractManager().TakeContract(context.Background(), contractKey, 0); contract == nil {
		t.Fatal("a contract to the target's own key was refused")
	}
}

// A generator made from a context no link's build handed its host refuses every client, before the host's
// generator builds one.
func TestBridgeLinkGeneratorWithoutALinkRefuses(t *testing.T) {
	inner := &generatorTestInner{t: t, control: &generatorTestControl{}, expireTime: time.UnixMilli(linkTestTimeMs).Add(time.Hour)}
	signCount := 0
	generator := device.NewBridgeLinkGenerator(context.Background(), inner,
		func(windowClientId connect.Id, windowClientPublicKey []byte, notAfter time.Time) ([]byte, error) {
			signCount += 1
			return []byte("signed"), nil
		})
	args, err := generator.NewClientArgs()
	if err != nil {
		t.Fatal(err)
	}
	client, err := generator.NewClient(context.Background(), args, generator.NewClientSettings())
	if client != nil || !errors.Is(err, device.ErrBridgeLinkRefused) || signCount != 0 {
		t.Fatalf("client %v, error %v, %d signs", client, err, signCount)
	}
	inner.stateLock.Lock()
	defer inner.stateLock.Unlock()
	if len(inner.clients) != 0 {
		t.Fatalf("the host's generator built %d clients", len(inner.clients))
	}
}
