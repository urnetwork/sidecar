//go:build !js && !ios && !android && !sdk_mobile_bind && !windows && !sidecar_http && !ios_extension

// Sidecar.Listen's tls/ and smtp/ listens wait for a fresh grant to reach this device's engine before they register
// (socket_listen.go's gate paragraph, acl_grant_keep.go's landed row; §9.9, §16.6's grant row, I-8), at §16.6's real
// gate on the listen gate world's sidecar, config log and ACL engine, with the config the component waits in held
// where a test holds it, and a sockets service that judges each outward entry on the verified state this device's
// engine installed from the same log, denying one whose grant that state does not hold yet, as the service refuses a
// registration its view does not bear out:
//
//   - ur socket listen's tls/ listen through a real daemon's socket.listen: the approved call's use waits while the
//     GrantActivate is in the log and not in the engine, no page sent, and once the engine holds the grant the same
//     call registers on it, the service taking its first registration, its reply carrying the grant's end, with one
//     request filed and one statement posted;
//   - a mail receiver's smtp/25/mx the same: its first listen after the member's decision holds the registration;
//   - the wait's own timeout (ListenGrantLandTimeout), on a config whose follow never reaches the receipt, ends the
//     listen unavailable, its error naming the grant and no socket, nothing registered; once the engine holds the
//     grant the listen asked again passes on it as standing and registers, keeping the grant's end, with no second
//     GrantActivate; and with no config to wait on at all an approved listen ends naming its grant too;
//   - awaitGrant answers at once for a grant the engine holds, waiting on nothing, and names the grant where a follow
//     reaches the receipt without the engine holding it and where its filer has no engine;
//   - the stock component waits in its host's standing follower's config client, the follower whose engine its
//     filer builds on, and in none while that follower does not stand or follows another network.
//
// Synthetic values only.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The sockets service judging each outward entry of a page as its registration step 5 does
// (socketsservice/registrations.go): MayListen for the caller's sidecar on the name, here on the verified state the
// world's engine installed from its log, so an entry whose grant that state does not hold yet is denied. Each judged
// entry is kept, in order.
type testListenAwaitService struct {
	*testListenService
	world *testListenGateWorld

	stateLock sync.Mutex
	verdicts  []testListenAwaitVerdict
}

// One outward entry as the service judged it.
type testListenAwaitVerdict struct {
	name   string
	status SocketRegistrationStatus
}

// The scripted service's answer, each outward entry's status judged on the world's engine.
func (self *testListenAwaitService) registrations(ctx context.Context, args *SocketRegistrationsArgs) (*SocketRegistrationsResult, error) {
	result, err := self.testListenService.registrations(ctx, args)
	if err != nil {
		return nil, err
	}
	state := self.world.engine.State()
	now := self.world.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for i, registration := range args.Registrations {
		if registration.Name == "" {
			// a blinded name, which no test here registers
			continue
		}
		status := SocketRegistrationStatusDenied
		if state != nil && state.MayListen(AclSidecarSubject(self.world.hostId), AclSocketName{PublicName: registration.Name}, now).Allowed {
			status = SocketRegistrationStatusOk
		}
		result.Statuses[i] = status
		self.verdicts = append(self.verdicts, testListenAwaitVerdict{name: registration.Name, status: status})
	}
	return result, nil
}

// The statuses the service answered for name, in order.
func (self *testListenAwaitService) judged(name string) []SocketRegistrationStatus {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	statuses := []SocketRegistrationStatus{}
	for _, verdict := range self.verdicts {
		if verdict.name == name {
			statuses = append(statuses, verdict.status)
		}
	}
	return statuses
}

// Fails unless the service judged name and took every registration of it, the first included.
func (self *testListenAwaitService) expectTaken(t *testing.T, name string) {
	t.Helper()
	if judged := self.judged(name); len(judged) == 0 || slices.Contains(judged, SocketRegistrationStatusDenied) {
		t.Errorf("the service's verdicts on %s: %v", name, judged)
	}
}

// Fails if the service was sent name at all.
func (self *testListenAwaitService) expectUnsent(t *testing.T, name string, what string) {
	t.Helper()
	if judged := self.judged(name); len(judged) != 0 {
		t.Errorf("%s registered: %v", what, judged)
	}
}

// A listen gate world on settings whose registrar pages the judging service.
func newTestListenAwaitWorld(t *testing.T, settings *SidecarSocketSettings) (*testListenGateWorld, *testListenAwaitService) {
	t.Helper()
	world := newTestListenGateWorldWith(t, settings)
	service := &testListenAwaitService{testListenService: world.service, world: world}
	// the same identity key, so the registrar keeps its set and pages this service from now on
	world.component.registrar.attach(t.Context(), service.registrations, world.generation.identity.IdentityPublicKey)
	return world, service
}

// The world's component waiting for a fresh grant in config, nil for none.
func (self *testListenGateWorld) waitIn(config AclGrantConfig) {
	self.component.stateLock.Lock()
	defer self.component.stateLock.Unlock()
	self.component.grantConfig = config
}

// A config whose follow never reaches the position asked: each WaitFor ends with its waiter's context, here the
// listen's own wait's timeout, counted with whether that context carried a deadline.
type testListenStuckConfig struct {
	stateLock sync.Mutex
	waits     int
	deadlines int
}

// See AclGrantConfig.
func (self *testListenStuckConfig) WaitFor(ctx context.Context, n uint64) (*ConfigState, error) {
	_, deadline := ctx.Deadline()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.waits += 1
		if deadline {
			self.deadlines += 1
		}
	}()
	<-ctx.Done()
	return nil, ctx.Err()
}

// How many waits there were, and how many carried a deadline.
func (self *testListenStuckConfig) counts() (int, int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.waits, self.deadlines
}

// A config whose follow answers every position at once and installs nothing, so the engine keeps the state it holds.
type testListenIdleConfig struct{}

// See AclGrantConfig.
func (self testListenIdleConfig) WaitFor(ctx context.Context, n uint64) (*ConfigState, error) {
	return nil, nil
}

// Whether err is an unconfirmed grant's naming grantId.
func testListenNamesGrant(err error, grantId []byte) bool {
	var unconfirmed *AclGrantUnconfirmedError
	return errors.Is(err, ErrAclGrantUnconfirmed) && errors.As(err, &unconfirmed) && bytes.Equal(unconfirmed.GrantId, grantId)
}

// The daemon's backend for the world's network: its listens are the world's component's, as the stock backend's are
// its Sidecar's (sidecarSocketBackend), and the rest the in-memory network's.
type testListenAwaitBackend struct {
	*testSocketBackend
	world *testListenGateWorld
}

// See daemonSocketBackend: the world's component's listen.
func (self *testListenAwaitBackend) listen(ctx context.Context, address *SocketAddress, settings *SocketListenSettings, share bool) (daemonSocketListener, error) {
	listener, err := self.world.component.listen(ctx, address, settings, share)
	if err != nil {
		return nil, err
	}
	return listener, nil
}

// A real daemon hosting the world's network, its sockets on the world's component, and a control session to it.
func newTestListenAwaitDaemon(t *testing.T, world *testListenGateWorld) *DaemonClient {
	t.Helper()
	started := startTestDaemon(t, func(settings *DaemonSettings) {
		settings.Clock = newTestArmedClock()
	})
	if err := started.daemon.AddSidecar(world.net.networkId, &Sidecar{}); err != nil {
		t.Fatal(err)
	}
	backend := &testListenAwaitBackend{testSocketBackend: newTestSocketBackend(newTestSocketNet()), world: world}
	sockets := started.daemon.Sockets()
	sockets.backends = func(networkId Id) (daemonSocketBackend, error) {
		if networkId != world.net.networkId {
			return nil, &DaemonNetworkError{Reason: "unknown"}
		}
		return backend, nil
	}
	for _, method := range sockets.Methods() {
		if err := started.daemon.RegisterMethod(method); err != nil {
			t.Fatal(err)
		}
	}
	return dialTestDaemon(t, started, DaemonModeControl)
}

// ur socket listen's tls/ listen under a requests rule through a real daemon's socket.listen: the call before the
// member's decision answers the approval it waits on; the approved call's use waits while its GrantActivate is in the
// log and not in this device's engine, sending no page; and once the engine holds the grant the same call registers,
// the service taking its first registration, and replies with the grant's end, one request filed and one statement
// posted.
func TestDaemonSocketListenRegistersAFreshGrantOnItsFirstAsk(t *testing.T) {
	world, service := newTestListenAwaitWorld(t, DefaultSidecarSocketSettings())
	world.requests("tls/443/blog")
	control := newTestListenAwaitDaemon(t, world)
	_, port := startTestEchoTarget(t)
	params := &DaemonSocketListenParams{Address: "tls/443/blog", Target: strconv.Itoa(port)}

	pending := &DaemonSocketListenReply{}
	if err := control.Call(context.Background(), DaemonMethodSocketListen, params, false, pending); err != nil || pending.ApprovalId == nil {
		t.Fatalf("the listen before the decision: %+v, %v", pending, err)
	}
	request := world.pendingRequest(&ApprovalPendingError{ApprovalId: *pending.ApprovalId})
	world.approve(request)
	grantId := AclGrantId(request.ApprovalId(), request.Action.PayloadSha256())

	world.config.hold(true)
	type answer struct {
		reply *DaemonSocketListenReply
		err   error
	}
	answered := make(chan answer, 1)
	go func() {
		reply := &DaemonSocketListenReply{}
		err := control.Call(context.Background(), DaemonMethodSocketListen, params, false, reply)
		answered <- answer{reply: reply, err: err}
	}()
	var position uint64
	select {
	case position = <-world.config.waiting:
	case got := <-answered:
		t.Fatalf("the approved listen answered without waiting for its grant: %+v, %v", got.reply, got.err)
	}
	// the GrantActivate is in the log at the receipt's position and not in the engine: nothing is registered yet
	if logPin := world.net.log.State().Pin().GetVersion(); position == 0 || logPin < position {
		t.Fatalf("the listen waits for position %d with the log at %d", position, logPin)
	}
	if world.engine.State().grantRule(grantId[:]) != nil {
		t.Fatal("the engine held the grant before the wait answered")
	}
	service.expectUnsent(t, "tls/443/blog", "the listen before its grant reached the engine")
	world.config.release <- nil
	got := <-answered
	world.config.hold(false)
	if got.err != nil || got.reply.Status == nil || got.reply.ApprovalId != nil {
		t.Fatalf("the approved listen once its grant reached the engine: %+v, %v", got.reply, got.err)
	}
	if got.reply.Status.Name != "tls/443/blog" || got.reply.Status.GrantExpiresMs != request.Action.Action.GetExpiresMillis() {
		t.Errorf("the listen's status: %+v", got.reply.Status)
	}
	service.expectTaken(t, "tls/443/blog")
	if spent, _ := world.lastAsked(); spent.Outcome == nil || spent.Outcome.State != ApprovalOutcomeDone || !bytes.Equal(spent.Outcome.EffectRef, grantId[:]) {
		t.Errorf("the approved listen's use: %+v", spent.Outcome)
	}
	if types := world.api.postedTypes(t); world.approvals.filedCount() != 1 || !slices.Equal(types, []bridge.SignedType{bridge.SignedType_SIGNED_GRANT_ACTIVATE}) {
		t.Errorf("%d requests filed, posted %v", world.approvals.filedCount(), types)
	}
}

// A mail receiver's smtp/25/mx under a requests rule giving 7 days: its listen before the member's decision shows the
// approval it waits on; its first listen after the decision waits while the GrantActivate is not in the engine,
// sending no page, and once the engine holds the grant holds the registration, the service taking its first
// registration, with one request filed and one statement posted.
func TestMailReceiverRegistersAFreshGrantOnItsFirstListen(t *testing.T) {
	gate, service := newTestListenAwaitWorld(t, DefaultSidecarSocketSettings())
	gate.requestsWithin("smtp/25/mx", testListenExpiresRuleMax, 0)
	world := newMailReceiverTestWorld(t, nil)
	receiver := world.newReceiver(func(args *MailReceiverArgs) {
		args.Listen = func(ctx context.Context, address string, settings *SocketListenSettings) (MailReceiverListener, error) {
			listener, err := gate.listen(address, settings)
			if err != nil {
				return nil, err
			}
			return listener, nil
		}
	})
	_, err := receiver.listen(world.ctx)
	request := gate.pendingRequest(err)
	if status := receiver.Status(); status.ApprovalId == nil || *status.ApprovalId != request.ApprovalId() {
		t.Errorf("the receiver's status before the decision: %+v", status)
	}
	gate.approve(request)
	grantId := AclGrantId(request.ApprovalId(), request.Action.PayloadSha256())

	gate.config.hold(true)
	type answer struct {
		listener MailReceiverListener
		err      error
	}
	answered := make(chan answer, 1)
	go func() {
		listener, err := receiver.listen(world.ctx)
		answered <- answer{listener: listener, err: err}
	}()
	select {
	case <-gate.config.waiting:
	case got := <-answered:
		t.Fatalf("the receiver's approved listen answered without waiting for its grant: %v", got.err)
	}
	if gate.engine.State().grantRule(grantId[:]) != nil {
		t.Fatal("the engine held the grant before the wait answered")
	}
	service.expectUnsent(t, "smtp/25/mx", "the receiver before its grant reached the engine")
	gate.config.release <- nil
	got := <-answered
	gate.config.hold(false)
	if got.err != nil || got.listener == nil {
		t.Fatalf("the receiver's first listen after the decision: %v", got.err)
	}
	defer got.listener.Close()
	service.expectTaken(t, "smtp/25/mx")
	if status := receiver.Status(); status.ApprovalId != nil || status.Problem != "" {
		t.Errorf("the receiver's status once it listens: %+v", status)
	}
	if gate.approvals.filedCount() != 1 || gate.api.postCount() != 1 {
		t.Errorf("%d requests filed, %d statements posted", gate.approvals.filedCount(), gate.api.postCount())
	}
}

// The approved tls/ listen's wait, on a config whose follow never reaches the receipt, ends at its own timeout,
// ListenGrantLandTimeout: the listen answers unavailable, its error naming the grant and why the wait ended and no
// socket, nothing registered and the use uncertain after one GrantActivate. Once the engine holds the grant, the same
// listen asked again passes on it as standing and registers, keeping the grant's end, with no second GrantActivate
// and nothing more filed.
func TestSocketListenGrantWaitTimeoutEndsTheListenNamingTheGrant(t *testing.T) {
	settings := DefaultSidecarSocketSettings()
	settings.ListenGrantLandTimeout = time.Millisecond
	world, service := newTestListenAwaitWorld(t, settings)
	world.requests("tls/443/blog")
	_, err := world.listen("tls/443/blog", nil)
	request := world.pendingRequest(err)
	world.approve(request)
	grantId := AclGrantId(request.ApprovalId(), request.Action.PayloadSha256())

	stuck := &testListenStuckConfig{}
	world.waitIn(stuck)
	listener, err := world.listen("tls/443/blog", nil)
	if err == nil {
		listener.Close()
		t.Fatal("the listen registered on a grant its wait never saw reach the engine")
	}
	if !errors.Is(err, ErrSocketUnavailable) || !testListenNamesGrant(err, grantId[:]) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the listen whose wait timed out: %v", err)
	}
	if text := err.Error(); !strings.Contains(text, hex.EncodeToString(grantId[:])) || strings.Contains(text, "blog") {
		t.Errorf("the listen's error, which names its grant and no socket: %q", text)
	}
	if waits, deadlines := stuck.counts(); waits != 1 || deadlines != 1 {
		t.Errorf("the config was waited on %d times, %d with a deadline", waits, deadlines)
	}
	if spent, _ := world.lastAsked(); spent.Outcome == nil || spent.Outcome.State != ApprovalOutcomeUncertain {
		t.Errorf("the use: %+v", spent.Outcome)
	}
	service.expectUnsent(t, "tls/443/blog", "a listen whose grant is not in the engine")
	if types := world.api.postedTypes(t); !slices.Equal(types, []bridge.SignedType{bridge.SignedType_SIGNED_GRANT_ACTIVATE}) {
		t.Fatalf("the spend posted %v", types)
	}

	// the engine catches up: asked again, the listen passes on its grant as standing and registers, keeping its end
	world.install()
	listener, err = world.listen("tls/443/blog", nil)
	if err != nil {
		t.Fatalf("the listen asked again once the engine holds its grant: %v", err)
	}
	defer listener.Close()
	if again, _ := world.lastAsked(); again.Outcome == nil || again.Outcome.State != ApprovalOutcomeDone {
		t.Errorf("the listen asked again: %+v", again.Outcome)
	}
	if got, want := listener.GrantExpires(), time.UnixMilli(request.Action.Action.GetExpiresMillis()).UTC(); !got.Equal(want) {
		t.Errorf("the listen asked again ends %v, not its grant's %v", got, want)
	}
	service.expectTaken(t, "tls/443/blog")
	if world.api.postCount() != 1 || world.approvals.filedCount() != 1 {
		t.Errorf("%d statements posted, %d requests filed", world.api.postCount(), world.approvals.filedCount())
	}
}

// With no config to wait on, an approved smtp/25/mx listen's use is uncertain as its GrantActivate's post answers: the
// listen answers unavailable naming its grant, and nothing registers.
func TestSocketListenWithNoConfigEndsNamingTheGrant(t *testing.T) {
	world, service := newTestListenAwaitWorld(t, DefaultSidecarSocketSettings())
	world.waitIn(nil)
	world.requests("smtp/25/mx")
	_, err := world.listen("smtp/25/mx", nil)
	request := world.pendingRequest(err)
	world.approve(request)
	grantId := AclGrantId(request.ApprovalId(), request.Action.PayloadSha256())
	if listener, err := world.listen("smtp/25/mx", nil); err == nil {
		listener.Close()
		t.Fatal("the listen registered with no config to wait on for its grant")
	} else if !errors.Is(err, ErrSocketUnavailable) || !testListenNamesGrant(err, grantId[:]) {
		t.Errorf("the listen with no config: %v", err)
	}
	service.expectUnsent(t, "smtp/25/mx", "a listen with no config to wait on")
	if world.api.postCount() != 1 {
		t.Errorf("%d statements posted", world.api.postCount())
	}
}

// awaitGrant, the one wait the publish and both listens take, answers at once for a grant the engine holds in force,
// waiting on nothing; a follow that reaches the receipt with the engine still not holding the grant, and a filer with
// no engine to hold it, answer unconfirmed, naming the grant.
func TestAclGrantAwaitNamesTheGrantItWaitedFor(t *testing.T) {
	world := newTestListenGateWorld(t)
	world.requests("tls/443/blog")
	_, err := world.listen("tls/443/blog", nil)
	request := world.pendingRequest(err)
	world.approve(request)
	listener, err := world.listen("tls/443/blog", nil)
	if err != nil {
		t.Fatalf("the approved listen: %v", err)
	}
	listener.Close()
	grants := NewAclGrantFiler(world.sidecar, world.engine)
	grantId := AclGrantId(request.ApprovalId(), request.Action.PayloadSha256())
	receipt := world.net.log.State().Pin()

	stuck := &testListenStuckConfig{}
	if err := grants.awaitGrant(t.Context(), stuck, time.Hour, receipt, grantId[:]); err != nil {
		t.Errorf("a grant the engine holds: %v", err)
	}
	if waits, _ := stuck.counts(); waits != 0 {
		t.Errorf("a grant the engine holds was waited on %d times", waits)
	}
	other := bytes.Repeat([]byte{0x5a}, len(grantId))
	if err := grants.awaitGrant(t.Context(), testListenIdleConfig{}, time.Hour, receipt, other); !testListenNamesGrant(err, other) ||
		!strings.Contains(err.Error(), "not in force") {
		t.Errorf("a follow that reached the receipt without the grant: %v", err)
	}
	if err := NewAclGrantFiler(world.sidecar, nil).awaitGrant(t.Context(), stuck, time.Hour, receipt, other); !testListenNamesGrant(err, other) {
		t.Errorf("a filer with no engine: %v", err)
	}
}

// The stock component waits for a fresh grant in its host's standing follower's config client, the follower whose
// engine its grant filer builds on, and in none while that follower follows another network or does not stand.
func TestSocketComponentWaitsInItsHostsConfigClient(t *testing.T) {
	world := newTestBridgeFileWorld(t, false)
	running := world.sidecar
	networkId := world.net.networkId
	running.networkId = &networkId
	client := &ConfigClient{args: &ConfigClientArgs{NetworkId: networkId}}
	client.configLog.Store(world.net.log)
	follower := &SidecarConfigFollower{client: client, state: NewMonitorValue(SidecarConfigFollowerStanding), aclEngine: world.engine}
	running.configFollower.Store(follower)
	component, err := running.NewSocketComponent(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer component.Close()
	if grants, config := component.listenGrants(); grants == nil || grants.engine != world.engine || config != AclGrantConfig(client) {
		t.Errorf("the stock component's grant filer %+v and config %v", grants, config)
	}

	// a standing follower of another network lends neither
	other := &ConfigClient{args: &ConfigClientArgs{NetworkId: testConfigId("another network")}}
	running.configFollower.Store(&SidecarConfigFollower{client: other, state: NewMonitorValue(SidecarConfigFollowerStanding), aclEngine: world.engine})
	if grants, config := component.listenGrants(); grants != nil || config != nil {
		t.Errorf("a follower of another network lent a grant filer %+v and config %v", grants, config)
	}

	// a follower that no longer stands lends neither
	running.configFollower.Store(follower)
	follower.state.Set(SidecarConfigFollowerAnchoring)
	if grants, config := component.listenGrants(); grants != nil || config != nil {
		t.Errorf("a follower that does not stand lent a grant filer %+v and config %v", grants, config)
	}
}
