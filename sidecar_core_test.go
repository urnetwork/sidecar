//go:build !sidecar_http && !js

package sidecar

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// How long a test waits for the run loop before it calls the test broken. Every wait is on a monitor or a channel;
// this only stops a broken test from hanging.
const sidecarTestTimeout = 30 * time.Second

// A host whose store is the instance's.
type testSidecarHost struct {
	store SidecarStore
}

func (self *testSidecarHost) Store() SidecarStore {
	return self.store
}

func (self *testSidecarHost) KeyStore() SidecarKeyStore {
	return nil
}

func (self *testSidecarHost) TokenSource() SidecarTokenSource {
	return nil
}

// One client a testSidecarPlatform opened.
type testPlatformClient struct {
	args   *SidecarPlatformClientArgs
	client *connect.Client
	closed chan struct{}

	stateLock sync.Mutex
	auths     []*connect.ClientAuth
}

// The auths SetAuth installed.
func (self *testPlatformClient) installedAuths() []*connect.ClientAuth {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*connect.ClientAuth{}, self.auths...)
}

// A platform with no network: each client is a real Required connect client on an out-of-band control that makes
// no contract, connected exactly when the test says.
type testSidecarPlatform struct {
	connected *MonitorValue[bool]
	opened    *MonitorValue[int]

	stateLock sync.Mutex
	clients   []*testPlatformClient
}

func newTestSidecarPlatform() *testSidecarPlatform {
	return &testSidecarPlatform{connected: NewMonitorValue(false), opened: NewMonitorValue(0)}
}

func (self *testSidecarPlatform) OpenClient(ctx context.Context, args *SidecarPlatformClientArgs) (*SidecarPlatformClient, error) {
	client := connect.NewClient(ctx, args.ClientId, connect.NewNoContractClientOob(), args.ClientSettings)
	opened := &testPlatformClient{args: args, client: client, closed: make(chan struct{})}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.clients = append(self.clients, opened)
	}()
	self.opened.Update(func(count int) int { return count + 1 })
	var closeOnce sync.Once
	return &SidecarPlatformClient{
		Client: client,
		SetAuth: func(auth *connect.ClientAuth) {
			opened.stateLock.Lock()
			defer opened.stateLock.Unlock()
			opened.auths = append(opened.auths, auth)
		},
		Connected: func() (bool, <-chan struct{}) {
			connected, changed := self.connected.Get()
			return connected, changed
		},
		CloseAndWait: func(ctx context.Context) error {
			err := client.CloseAndWait(ctx)
			closeOnce.Do(func() { close(opened.closed) })
			return err
		},
	}, nil
}

// The clients opened so far, oldest first.
func (self *testSidecarPlatform) openedClients() []*testPlatformClient {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*testPlatformClient{}, self.clients...)
}

// Waits until count clients have been opened, and answers the newest.
func (self *testSidecarPlatform) awaitOpened(t *testing.T, count int) *testPlatformClient {
	t.Helper()
	deadline := time.After(sidecarTestTimeout)
	for {
		opened, changed := self.opened.Get()
		if count <= opened {
			clients := self.openedClients()
			return clients[count-1]
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("%d clients opened, want %d", opened, count)
		}
	}
}

// A component that records each env it is given, and its close.
type testComponent struct {
	name     string
	onAttach func(env *SidecarEnv) error
	attached *MonitorValue[int]
	closes   atomic.Int32

	stateLock sync.Mutex
	envs      []*SidecarEnv
}

func newTestComponent(name string) *testComponent {
	return &testComponent{name: name, attached: NewMonitorValue(0)}
}

func (self *testComponent) Name() string {
	return self.name
}

func (self *testComponent) Attach(env *SidecarEnv) error {
	var err error
	if self.onAttach != nil {
		err = self.onAttach(env)
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.envs = append(self.envs, env)
	}()
	self.attached.Update(func(count int) int { return count + 1 })
	return err
}

func (self *testComponent) Close() {
	self.closes.Add(1)
}

// Waits until the component has been attached count times, and answers the newest env.
func (self *testComponent) awaitAttached(t *testing.T, count int) *SidecarEnv {
	t.Helper()
	deadline := time.After(sidecarTestTimeout)
	for {
		attached, changed := self.attached.Get()
		if count <= attached {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.envs[count-1]
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("attached %d times, want %d", attached, count)
		}
	}
}

// One network's enrollment, written straight into an instance's keychain and sidecar.json, as CORE-M1-09 leaves it.
type testEnrollment struct {
	networkId Id
	sidecarId Id
	clientId  Id
	keys      *sidecarIdentityKeys
	byJwt     string
	secrets   SidecarSecrets
}

// An open instance holding an enrollment of generation 1, on a memory backend and a key store holding W.
func newTestEnrolledInstance(t *testing.T) (*SidecarInstance, *testEnrollment) {
	t.Helper()
	instance := newInstanceOn(t, NewSidecarMemoryBackend(), newFakeKeyStore())
	if err := instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	enrollment := &testEnrollment{networkId: NewId(), sidecarId: NewId()}
	if _, err := instance.createKeychain(enrollment.networkId); err != nil {
		t.Fatal(err)
	}
	enrollment.secrets = instance.secrets(enrollment.networkId, sidecarCoreSecretsNamespace)
	keys, err := newSidecarIdentityKeys(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enrollment.keys = keys
	enrollment.bind(t, 1, keys)
	if err := instance.RecordNetwork(SidecarNetworkRecord{
		NetworkId:         enrollment.networkId,
		ClientId:          enrollment.clientId,
		SidecarId:         enrollment.sidecarId,
		ConnectInstanceId: NewId(),
	}); err != nil {
		t.Fatal(err)
	}
	return instance, enrollment
}

// Persists generation's binding of keys with a new client id and token, as an enrollment does.
func (self *testEnrollment) bind(t *testing.T, generation int64, keys *sidecarIdentityKeys) {
	t.Helper()
	self.clientId = NewId()
	signedBinding, err := NewSidecarIdentityBinding(&SidecarIdentityBinding{
		NetworkId:  self.networkId,
		SidecarId:  self.sidecarId,
		ClientId:   self.clientId,
		Generation: generation,
		IssuedAt:   time.Now(),
	}, keys.identitySeed, keys.clientKeySeed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistSidecarIdentity(self.secrets, keys, signedBinding); err != nil {
		t.Fatal(err)
	}
	// a token of this client that refreshes days from now, so no refresh runs in a test
	self.byJwt = testClientTokenOf(self.networkId, self.clientId)
	if err := persistSidecarByJwt(self.secrets, self.byJwt); err != nil {
		t.Fatal(err)
	}
}

// A client token of networkId's clientId, issued now for 7 days, with its own jti.
func testClientTokenOf(networkId Id, clientId Id) string {
	now := time.Now()
	return testClientJwt(fmt.Sprintf(`{"jti":%q,"iat":%d,"exp":%d,"network_id":%q,"client_id":%q,"device_id":%q}`,
		NewId().String(), now.Unix(), now.Add(7*24*time.Hour).Unix(), networkId, clientId, NewId()))
}

// Settings for a test Sidecar on platform.
func testSidecarSettings(platform SidecarPlatform) *SidecarSettings {
	settings := cheapKeychainSettings()
	settings.Connect.Platform = platform
	return settings
}

// A running Sidecar of the enrollment's network, closed at the test's end.
func newTestRunningSidecar(t *testing.T, instance *SidecarInstance, networkId *Id, settings *SidecarSettings, components ...SidecarComponent) *Sidecar {
	t.Helper()
	sidecar, err := NewSidecar(context.Background(), &testSidecarHost{store: instance.Store(networkId)}, components, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), sidecarTestTimeout)
		defer cancel()
		if err := sidecar.CloseAndWait(ctx); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return sidecar
}

// Waits until the sidecar's status satisfies want, re-reading at each event.
func awaitSidecarStatus(t *testing.T, sidecar *Sidecar, want func(status SidecarStatus) bool) SidecarStatus {
	t.Helper()
	events := NewMonitorValue(0)
	remove := sidecar.AddEventCallback(func(event SidecarEvent) {
		events.Update(func(count int) int { return count + 1 })
	})
	defer remove()
	deadline := time.After(sidecarTestTimeout)
	for {
		_, changed := events.Get()
		status := sidecar.Status()
		if want(status) {
			return status
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("status stayed %+v", status)
		}
	}
}

// A predicate on state and generation.
func atStatus(state SidecarState, generation int64) func(status SidecarStatus) bool {
	return func(status SidecarStatus) bool {
		return status.State == state && status.Generation == generation
	}
}

// An enrolled Sidecar starts its own Required client on the keychain's ClientKey and token, offline until the
// platform connects it, and Online after.
func TestNewSidecarRunsTheEnrolledGeneration(t *testing.T) {
	instance, enrollment := newTestEnrolledInstance(t)
	platform := newTestSidecarPlatform()
	sidecar := newTestRunningSidecar(t, instance, &enrollment.networkId, testSidecarSettings(platform))

	awaitSidecarStatus(t, sidecar, atStatus(SidecarStateOffline, 1))
	opened := platform.awaitOpened(t, 1)
	if opened.args.ClientId != connect.Id(enrollment.clientId) {
		t.Errorf("the client is %s, not the enrolled one", opened.args.ClientId)
	}
	if opened.args.ClientSettings.EncryptionSettings.Mode != connect.EncryptionModeRequired {
		t.Error("the client is not Required (I-3)")
	}
	if opened.args.ClientSettings.DefaultTransferOpts.ForceStream {
		t.Error("the client asks for P2P streams")
	}
	if opened.args.Auth.ByJwt != enrollment.byJwt || opened.args.Auth.StreamLeaseVersion != 1 {
		t.Errorf("auth %+v", opened.args.Auth)
	}
	if !bytes.Equal(opened.client.ClientKeyManager().PublicKey(), enrollment.keys.clientPublicKey()) {
		t.Error("the client's key is not the keychain's ClientKey")
	}
	if !opened.client.EncryptionSessionManager().RequireEncryption() {
		t.Error("the client does not require encryption")
	}

	platform.connected.Set(true)
	awaitSidecarStatus(t, sidecar, atStatus(SidecarStateOnline, 1))
	platform.connected.Set(false)
	awaitSidecarStatus(t, sidecar, atStatus(SidecarStateOffline, 1))
}

// A Sidecar with no enrollment stays Unenrolled and opens no client.
func TestUnenrolledSidecarOpensNoClient(t *testing.T) {
	instance := newInstanceOn(t, NewSidecarMemoryBackend(), newFakeKeyStore())
	if err := instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	platform := newTestSidecarPlatform()
	sidecar := newTestRunningSidecar(t, instance, nil, testSidecarSettings(platform))
	awaitSidecarStatus(t, sidecar, atStatus(SidecarStateUnenrolled, 0))
	if len(platform.openedClients()) != 0 {
		t.Error("an unenrolled sidecar opened a client")
	}
}

// Attach runs outside stateLock: a component taking it in Attach, as one reading Status does, finds it free.
func TestAttachOutsideStateLock(t *testing.T) {
	instance, enrollment := newTestEnrolledInstance(t)
	platform := newTestSidecarPlatform()
	var sidecar *Sidecar
	component := newTestComponent("evs")
	statusRead := make(chan SidecarStatus, 1)
	component.onAttach = func(env *SidecarEnv) error {
		// Status takes stateLock, which no one holds across a call out, so this returns; under the lock it never
		// would, and awaitAttached would fail
		statusRead <- sidecar.Status()
		return nil
	}
	settings := testSidecarSettings(platform)
	built, err := NewSidecar(context.Background(), &testSidecarHost{store: instance.Store(&enrollment.networkId)}, nil, settings)
	if err != nil {
		t.Fatal(err)
	}
	sidecar = built
	defer sidecar.CloseAndWait(context.Background())
	if _, err := sidecar.AddComponent(component); err != nil {
		t.Fatal(err)
	}
	env := component.awaitAttached(t, 1)
	if status := <-statusRead; status.Generation != 1 {
		t.Errorf("Attach read status %+v", status)
	}
	if env.Identity.SidecarId != enrollment.sidecarId || env.Identity.Generation != 1 {
		t.Errorf("identity %+v", env.Identity)
	}
	if env.Client != platform.awaitOpened(t, 1).client || env.Subprotocol == nil || env.SidecarApi != sidecar.sidecarApi {
		t.Error("the env is not the generation's")
	}
	// the component's own namespace and directory, which the core's do not share
	if err := env.Secrets.Put("record", []byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	if _, err := enrollment.secrets.Get("record"); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Errorf("a component's secret shows in the core's namespace: %v", err)
	}
	writer, err := env.Store.Create("state")
	if err != nil {
		t.Fatal(err)
	}
	writer.Write([]byte("synthetic"))
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	// every outward action is refused until the gate lands
	if err := env.Authorize(context.Background(), &SidecarAction{Kind: SidecarActionPublish}, nil); err == nil {
		t.Error("the env's gate allowed an action")
	}
}

// A component's queue, reached through its env, drops and counts at its bound without waiting, and the counts reach
// Stats under the component's name alone.
func TestComponentQueueDropsAndCountsInStats(t *testing.T) {
	instance, enrollment := newTestEnrolledInstance(t)
	platform := newTestSidecarPlatform()
	settings := testSidecarSettings(platform)
	settings.ComponentQueueMessageCount = 2
	component := newTestComponent("sockets")
	sidecar := newTestRunningSidecar(t, instance, &enrollment.networkId, settings, component)
	env := component.awaitAttached(t, 1)

	held := make(chan struct{})
	release := make(chan struct{})
	if !env.Enqueue(8, func(ctx context.Context) {
		close(held)
		<-release
	}) {
		t.Fatal("the first item was refused")
	}
	<-held
	ran := make(chan int, 4)
	for i := 0; i < 2; i += 1 {
		if !env.Enqueue(8, func(ctx context.Context) { ran <- i }) {
			t.Fatalf("item %d refused under the bound", i)
		}
	}
	if env.Enqueue(8, func(ctx context.Context) { ran <- 99 }) {
		t.Fatal("an item past the bound was taken")
	}
	close(release)
	for i := 0; i < 2; i += 1 {
		if got := <-ran; got != i {
			t.Fatalf("ran %d, want %d", got, i)
		}
	}
	stats := sidecar.Stats()
	if len(stats.Components) != 1 || stats.Components[0].Name != "sockets" || stats.Components[0].DroppedCount != 1 ||
		stats.Components[0].QueuedCount != 3 {
		t.Errorf("stats %+v", stats.Components)
	}
	if stats.GenerationCount != 1 {
		t.Errorf("generations %d", stats.GenerationCount)
	}
}

// A new generation in the keychain, as a re-enrollment writes, ends the old client and every env on it, and runs a
// new client under the same sidecar_id. The old generation's reports are dropped from then on (D-SDK-14).
func TestNewGenerationReplacesClient(t *testing.T) {
	instance, enrollment := newTestEnrolledInstance(t)
	platform := newTestSidecarPlatform()
	component := newTestComponent("mail")
	sidecar := newTestRunningSidecar(t, instance, &enrollment.networkId, testSidecarSettings(platform), component)
	platform.connected.Set(true)
	awaitSidecarStatus(t, sidecar, atStatus(SidecarStateOnline, 1))
	firstClient := platform.awaitOpened(t, 1)
	firstEnv := component.awaitAttached(t, 1)

	keys, err := enrollment.keys.withNewClientKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enrollment.bind(t, 2, keys)
	sidecar.wake()

	secondClient := platform.awaitOpened(t, 2)
	secondEnv := component.awaitAttached(t, 2)
	awaitSidecarStatus(t, sidecar, atStatus(SidecarStateOnline, 2))
	select {
	case <-firstClient.closed:
	default:
		t.Error("the old client is still open")
	}
	if firstEnv.Ctx.Err() == nil {
		t.Error("the old generation's env is still live")
	}
	if secondClient.args.ClientId != connect.Id(enrollment.clientId) ||
		!bytes.Equal(secondClient.client.ClientKeyManager().PublicKey(), keys.clientPublicKey()) {
		t.Error("the new client is not the new generation's")
	}
	if secondEnv.Identity.SidecarId != enrollment.sidecarId || secondEnv.Identity.Generation != 2 {
		t.Errorf("identity %+v", secondEnv.Identity)
	}
	if component.closes.Load() != 0 {
		t.Error("a new generation closed the component, which only detaches")
	}
}

// Once generation 2 runs, generation 1's refusal and events go nowhere.
func TestOldGenerationEventsDropped(t *testing.T) {
	instance, enrollment := newTestEnrolledInstance(t)
	platform := newTestSidecarPlatform()
	sidecar := newTestRunningSidecar(t, instance, &enrollment.networkId, testSidecarSettings(platform))
	awaitSidecarStatus(t, sidecar, atStatus(SidecarStateOffline, 1))
	keys, err := enrollment.keys.withNewClientKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enrollment.bind(t, 2, keys)
	sidecar.wake()
	platform.awaitOpened(t, 2)
	platform.connected.Set(true)
	awaitSidecarStatus(t, sidecar, atStatus(SidecarStateOnline, 2))

	seen := make(chan SidecarEvent, 8)
	remove := sidecar.AddEventCallback(func(event SidecarEvent) {
		seen <- event
	})
	defer remove()
	sidecar.tokenRefused(1, SidecarReasonRefused)
	sidecar.emitEvent(SidecarEvent{Kind: SidecarEventKeyChanged, Generation: 1})
	sidecar.emitEvent(SidecarEvent{Kind: SidecarEventMemberAdded, Generation: 2})
	if event := <-seen; event.Kind != SidecarEventMemberAdded {
		t.Errorf("an older generation's %s event was delivered", event.Kind)
	}
	if status := sidecar.Status(); status.State != SidecarStateOnline || status.Generation != 2 {
		t.Errorf("an older generation's refusal moved the sidecar: %+v", status)
	}
}

// A refused generation ends with its client, the sidecar keeps its identity Unenrolled, and nothing starts that
// generation again (D-CORE-8).
func TestRefusedGenerationEndsAndStaysEnded(t *testing.T) {
	instance, enrollment := newTestEnrolledInstance(t)
	platform := newTestSidecarPlatform()
	sidecar := newTestRunningSidecar(t, instance, &enrollment.networkId, testSidecarSettings(platform))
	platform.connected.Set(true)
	awaitSidecarStatus(t, sidecar, atStatus(SidecarStateOnline, 1))
	client := platform.awaitOpened(t, 1)

	generation := sidecar.runningGeneration()
	generation.tokenManager.Load().end(SidecarReasonRefused)
	status := awaitSidecarStatus(t, sidecar, atStatus(SidecarStateUnenrolled, 1))
	if status.Reason != SidecarReasonRefused {
		t.Errorf("reason %q", status.Reason)
	}
	<-client.closed
	sidecar.wake()
	sidecar.wake()
	// a lock and an unlock wake the loop too, and still start nothing
	instance.Lock()
	awaitSidecarStatus(t, sidecar, atStatus(SidecarStateLocked, 1))
	if err := sidecar.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	awaitSidecarStatus(t, sidecar, atStatus(SidecarStateUnenrolled, 1))
	if opened := len(platform.openedClients()); opened != 1 {
		t.Errorf("%d clients opened after a refusal", opened)
	}
	if identity := sidecar.currentIdentity(); identity == nil || identity.SidecarId != enrollment.sidecarId {
		t.Error("the refusal lost the identity")
	}
}

// A store that locks takes the sidecar to Locked and tears its client down, keeping its identity (§5.9).
func TestLockedStoreEntersLocked(t *testing.T) {
	instance, enrollment := newTestEnrolledInstance(t)
	platform := newTestSidecarPlatform()
	component := newTestComponent("tls")
	sidecar := newTestRunningSidecar(t, instance, &enrollment.networkId, testSidecarSettings(platform), component)
	platform.connected.Set(true)
	awaitSidecarStatus(t, sidecar, atStatus(SidecarStateOnline, 1))
	client := platform.awaitOpened(t, 1)
	env := component.awaitAttached(t, 1)

	instance.Lock()
	awaitSidecarStatus(t, sidecar, atStatus(SidecarStateLocked, 1))
	<-client.closed
	if env.Ctx.Err() == nil {
		t.Error("the env outlived the lock")
	}
	if identity := sidecar.currentIdentity(); identity == nil || identity.SidecarId != enrollment.sidecarId {
		t.Error("the lock dropped the identity")
	}
	if sidecar.sidecarApi.currentByJwt() != "" {
		t.Error("the token stayed in memory past the lock")
	}
	if _, err := sidecar.Sign(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_SIDECAR_ADMIT, []byte("x"), nil); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Errorf("sign while locked: %v", err)
	}
}

// Unlock(nil) opens U by the key store's wrap, and the same identity's generation runs again.
func TestUnlockNilReopens(t *testing.T) {
	instance, enrollment := newTestEnrolledInstance(t)
	platform := newTestSidecarPlatform()
	sidecar := newTestRunningSidecar(t, instance, &enrollment.networkId, testSidecarSettings(platform))
	platform.connected.Set(true)
	awaitSidecarStatus(t, sidecar, atStatus(SidecarStateOnline, 1))
	instance.Lock()
	awaitSidecarStatus(t, sidecar, atStatus(SidecarStateLocked, 1))

	if err := sidecar.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	awaitSidecarStatus(t, sidecar, atStatus(SidecarStateOnline, 1))
	reopened := platform.awaitOpened(t, 2)
	if reopened.args.ClientId != connect.Id(enrollment.clientId) || reopened.args.Auth.ByJwt != enrollment.byJwt {
		t.Error("the reopened client is not the same generation's")
	}
	if identity := sidecar.currentIdentity(); identity.SidecarId != enrollment.sidecarId {
		t.Error("the identity changed across the lock")
	}
}

// A keychain that cannot open because its wrap is gone is a loss: Unenrolled(keystore_lost), creating nothing.
func TestLostKeychainIsUnenrolledKeystoreLost(t *testing.T) {
	instance, enrollment := newTestEnrolledInstance(t)
	instance.Lock()
	if err := instance.backend.Remove(keychainWrapPath(enrollment.networkId)); err != nil {
		t.Fatal(err)
	}
	if err := instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	platform := newTestSidecarPlatform()
	sidecar := newTestRunningSidecar(t, instance, &enrollment.networkId, testSidecarSettings(platform))
	status := awaitSidecarStatus(t, sidecar, func(status SidecarStatus) bool {
		return status.State == SidecarStateUnenrolled && status.Reason == SidecarReasonKeystoreLost
	})
	if status.Generation != 0 {
		t.Errorf("generation %d", status.Generation)
	}
	if len(platform.openedClients()) != 0 {
		t.Error("a lost keychain opened a client")
	}
}

// Every goroutine the Sidecar started has returned when CloseAndWait does: the run loop, the refresher, the watch on
// the connection, the queues and the dispatcher, with each component closed once.
func TestCloseAndWaitJoins(t *testing.T) {
	instance, enrollment := newTestEnrolledInstance(t)
	platform := newTestSidecarPlatform()
	component := newTestComponent("bridge")
	sidecar, err := NewSidecar(context.Background(), &testSidecarHost{store: instance.Store(&enrollment.networkId)}, []SidecarComponent{component}, testSidecarSettings(platform))
	if err != nil {
		t.Fatal(err)
	}
	platform.connected.Set(true)
	awaitSidecarStatus(t, sidecar, atStatus(SidecarStateOnline, 1))
	env := component.awaitAttached(t, 1)
	env.Enqueue(1, func(ctx context.Context) {
		<-ctx.Done()
	})
	client := platform.awaitOpened(t, 1)

	ctx, cancel := context.WithTimeout(context.Background(), sidecarTestTimeout)
	defer cancel()
	if err := sidecar.CloseAndWait(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.closed:
	default:
		t.Error("the client was not closed")
	}
	if component.closes.Load() != 1 {
		t.Errorf("the component closed %d times", component.closes.Load())
	}
	stacks := make([]byte, 4*1024*1024)
	stacks = stacks[:runtime.Stack(stacks, true)]
	for _, function := range []string{
		"sidecar.(*Sidecar).run(",
		"sidecar.(*sidecarTokenManager).run(",
		"sidecar.(*sidecarConnectGeneration).watchConnection(",
		"sidecar.(*sidecarComponentQueue).run(",
		"sidecar.(*Subprotocol).runSender(",
	} {
		if strings.Contains(string(stacks), function) {
			t.Errorf("%s outlived CloseAndWait", function)
		}
	}
	if _, err := sidecar.AddComponent(newTestComponent("evs")); !errors.Is(err, ErrSidecarClosed) {
		t.Errorf("a closed sidecar took a component: %v", err)
	}
}

// Removing a component ends its env and closes it; the rest stay attached.
func TestRemovedComponentDetachesAndCloses(t *testing.T) {
	instance, enrollment := newTestEnrolledInstance(t)
	platform := newTestSidecarPlatform()
	sidecar := newTestRunningSidecar(t, instance, &enrollment.networkId, testSidecarSettings(platform))
	kept := newTestComponent("evs")
	removed := newTestComponent("sockets")
	if _, err := sidecar.AddComponent(kept); err != nil {
		t.Fatal(err)
	}
	remove, err := sidecar.AddComponent(removed)
	if err != nil {
		t.Fatal(err)
	}
	keptEnv := kept.awaitAttached(t, 1)
	removedEnv := removed.awaitAttached(t, 1)
	remove()
	remove()
	if removedEnv.Ctx.Err() == nil || removed.closes.Load() != 1 {
		t.Error("the removed component is still attached or was not closed once")
	}
	if keptEnv.Ctx.Err() != nil || kept.closes.Load() != 0 {
		t.Error("removing one component touched another")
	}
	if removedEnv.Enqueue(1, func(ctx context.Context) {}) {
		t.Error("a removed component's queue took an item")
	}
}

// Names are unique, a seal class's form, and none of the core's.
func TestComponentNamesAreChecked(t *testing.T) {
	instance, enrollment := newTestEnrolledInstance(t)
	sidecar := newTestRunningSidecar(t, instance, &enrollment.networkId, testSidecarSettings(newTestSidecarPlatform()))
	if _, err := sidecar.AddComponent(newTestComponent("evs")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"evs", "core", "keychain", "subprotocol", "", "Evs", "-x", "a/b"} {
		if _, err := sidecar.AddComponent(newTestComponent(name)); err == nil {
			t.Errorf("component %q was taken", name)
		}
	}
}

// A host whose store is no instance's, or that brings its own TokenSource before CORE-M8-01, is refused.
func TestNewSidecarRefusesWhatItCannotRun(t *testing.T) {
	settings := testSidecarSettings(newTestSidecarPlatform())
	if _, err := NewSidecar(context.Background(), &testSidecarHost{store: refusingTestStore{}}, nil, settings); err == nil {
		t.Error("a store that is no instance's was taken")
	}
	if _, err := NewSidecar(context.Background(), nil, nil, settings); err == nil {
		t.Error("no host was taken")
	}
	settings.ApiUrl = ""
	instance := newInstanceOn(t, NewSidecarMemoryBackend(), newFakeKeyStore())
	if _, err := NewSidecar(context.Background(), &testSidecarHost{store: instance.Store(nil)}, nil, settings); !errors.Is(err, errInvalidSettings) {
		t.Errorf("settings validate refuses were taken: %v", err)
	}
}

// A core hint is a bare resync at M1: counted, and it moves nothing, Revoked least of all (§5.6).
func TestCoreHintIsABareResync(t *testing.T) {
	instance, enrollment := newTestEnrolledInstance(t)
	platform := newTestSidecarPlatform()
	sidecar := newTestRunningSidecar(t, instance, &enrollment.networkId, testSidecarSettings(platform))
	platform.connected.Set(true)
	awaitSidecarStatus(t, sidecar, atStatus(SidecarStateOnline, 1))
	sidecar.receiveCoreHint(1, []byte{0x08, 0x01})
	sidecar.receiveCoreHint(0, []byte{0x08, 0x01})
	if status := sidecar.Status(); status.State != SidecarStateOnline {
		t.Errorf("a core hint moved the sidecar to %s", status.State)
	}
	if sidecar.Stats().CoreHintCount != 1 {
		t.Errorf("core hints %d, want 1: an older generation's counts nothing", sidecar.Stats().CoreHintCount)
	}
}

// A store that is not a SidecarInstance's.
type refusingTestStore struct {
	SidecarStore
}

// A token of another client beside the identity, which an enrollment a kill cut short can leave, starts nothing.
func TestTokenOfAnotherClientStartsNothing(t *testing.T) {
	instance, enrollment := newTestEnrolledInstance(t)
	if err := persistSidecarByJwt(enrollment.secrets, testClientTokenOf(enrollment.networkId, NewId())); err != nil {
		t.Fatal(err)
	}
	platform := newTestSidecarPlatform()
	sidecar := newTestRunningSidecar(t, instance, &enrollment.networkId, testSidecarSettings(platform))
	awaitSidecarStatus(t, sidecar, atStatus(SidecarStateUnenrolled, 1))
	if len(platform.openedClients()) != 0 {
		t.Error("a token of another client started a generation")
	}
}
