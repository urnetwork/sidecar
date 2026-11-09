//go:build !sidecar_http && !js

// §6's dispatcher: construction on a sidecar's Required client and nothing else, the inline order's
// version, identity and hook steps, dispatch by type, the answers it gives itself, and Close. Frames
// enter where connect hands them over, the registered handler, on a real Required client whose C15 key
// and send are the fixture's: a test frame's key is named by its Peer's Principal, which nothing here
// reads otherwise, and every send is recorded. The guard's table is rpc_guard_test.go's and overload
// rpc_overload_test.go's.

package sidecar

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/protocol"
)

// Types from the unreleased experimental services (§6.11), so a test's function stands for no real one.
const (
	testHeldMessageType   = protocol.MessageType(0x8001)
	testFreeMessageType   = protocol.MessageType(0x8002)
	testMarkerMessageType = protocol.MessageType(0x8003)
)

// How long a test waits for something it expects before it fails, so a broken dispatcher fails with a
// message instead of hanging. No outcome depends on it.
const testSubprotocolAwaitTimeout = 30 * time.Second

// Waits for one value, failing the test after testSubprotocolAwaitTimeout.
func testAwait[T any](t testing.TB, values <-chan T, what string) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(testSubprotocolAwaitTimeout):
		t.Fatalf("no %s", what)
		var zero T
		return zero
	}
}

// What Clock adds to the reassembly tests' clock: a call once a wait fires. The dispatcher schedules
// none, so this completes the interface and no test here reaches it.
func (self *testEnvelopeClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	fire := self.After(timeout)
	stopped := make(chan struct{})
	var done atomic.Bool
	go func() {
		select {
		case <-fire:
			if done.CompareAndSwap(false, true) {
				function()
			}
		case <-stopped:
		}
	}()
	return func() bool {
		if done.CompareAndSwap(false, true) {
			close(stopped)
			return true
		}
		return false
	}
}

// A store nothing in the dispatcher opens: PROTO-M1-04's pins are its first reader.
type testUnusedStore struct{}

var errTestUnusedStore = errors.New("store not used by the dispatcher")

// Refuses.
func (self testUnusedStore) Open(name string) (io.ReadCloser, error) {
	return nil, errTestUnusedStore
}

// Refuses.
func (self testUnusedStore) Create(name string) (SidecarStoreWriter, error) {
	return nil, errTestUnusedStore
}

// Refuses.
func (self testUnusedStore) Remove(name string) error {
	return errTestUnusedStore
}

// Refuses.
func (self testUnusedStore) List(prefix string) ([]SidecarStoreEntry, error) {
	return nil, errTestUnusedStore
}

// Refuses.
func (self testUnusedStore) Directory(name string, class string) (SidecarStore, error) {
	return nil, errTestUnusedStore
}

// The C15 key a test names: SHA-256 of its name, the size of an Ed25519 key.
func testClientKey(name string) [ed25519.PublicKeySize]byte {
	return sha256.Sum256([]byte(name))
}

// The fixture's C15 reader: the key the Peer's Principal names, and none for an empty one.
func testClientPublicKeyOf(peer connect.Peer) ([ed25519.PublicKeySize]byte, bool) {
	if peer.Principal == "" {
		return [ed25519.PublicKeySize]byte{}, false
	}
	return testClientKey(peer.Principal), true
}

// A same-network peer on h1 whose frames carry the C15 key keyName names. Its TransferKey sets every
// field, so a reply that drops or keeps one shows.
func testNetworkPeer(keyName string) connect.Peer {
	return connect.Peer{
		ProvideMode:   connectprotocol.ProvideMode_Network,
		TransportType: connect.TransportTypeH1,
		Principal:     keyName,
		TransferKey: connect.TransferKey{
			ForceStream:         true,
			CompanionContract:   true,
			EncryptionRole:      connectprotocol.SequenceRole_SequenceRoleServer,
			EncryptionCompanion: true,
			LogicalLane:         3,
		},
	}
}

var testRequestIds atomic.Uint64

// A request envelope of messageType carrying body, with a fresh request_id.
func testRequest(messageType protocol.MessageType, body []byte) *protocol.Envelope {
	return &protocol.Envelope{
		Version:   WireVersionMajor,
		Type:      uint32(messageType),
		RequestId: testRequestIds.Add(1),
		TimeoutMs: 15000,
		Body:      body,
	}
}

// A response to requestId.
func testResponse(messageType protocol.MessageType, requestId uint64, flags uint32) *protocol.Envelope {
	return &protocol.Envelope{
		Version:   WireVersionMajor,
		Type:      uint32(messageType),
		RequestId: requestId,
		Flags:     EnvelopeFlagResponse | flags,
	}
}

// One envelope the dispatcher handed connect.
type testSentEnvelope struct {
	destinationId connect.Id
	envelope      *protocol.Envelope
	ack           connect.AckFunction
	timeout       time.Duration
	opts          []any
}

// The send option a sent envelope carried.
func (self *testSentEnvelope) transferKey(t testing.TB) connect.TransferKey {
	t.Helper()
	for _, opt := range self.opts {
		if transferKey, ok := opt.(connect.TransferKey); ok {
			return transferKey
		}
	}
	t.Fatalf("no TransferKey in %v", self.opts)
	return connect.TransferKey{}
}

// The Error a sent refusal carries.
func (self *testSentEnvelope) errorCode(t testing.TB) protocol.ErrorCode {
	t.Helper()
	if self.envelope.Type != uint32(protocol.MessageType_ERROR) || self.envelope.Flags != EnvelopeFlagResponse|EnvelopeFlagError {
		t.Fatalf("not a refusal: type %d flags %d", self.envelope.Type, self.envelope.Flags)
	}
	refusal := &protocol.Error{}
	if err := proto.Unmarshal(self.envelope.Body, refusal); err != nil {
		t.Fatal(err)
	}
	code, ok := readErrorCode(refusal.Code)
	if !ok {
		t.Fatalf("code %d is no sender's", refusal.Code)
	}
	return code
}

// A dispatcher on a Required client, its C15 key and its sends the fixture's, on a clock the test moves.
type testSubprotocol struct {
	subprotocol *Subprotocol
	client      *connect.Client
	clock       *testEnvelopeClock
	settings    *SidecarProtocolSettings
	budget      *SubprotocolBudget
	sent        chan *testSentEnvelope
	// connect's count of pool ownership violations when the fixture was built
	violationCount uint64

	stateLock sync.Mutex
	// while set, a send waits for it to close
	sendGate chan struct{}
	// what a send answers
	sendRefused bool
}

// A running fixture, closed with the test. adjust may change the env before construction.
func newTestSubprotocol(t testing.TB, adjust func(env *SubprotocolEnv)) *testSubprotocol {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	client := newTestRequiredClient(t, ctx)
	settings := DefaultSidecarProtocolSettings()
	fixture := &testSubprotocol{
		client:         client,
		clock:          newTestEnvelopeClock(),
		settings:       settings,
		budget:         NewSubprotocolBudget(settings, 128*1024*1024),
		sent:           make(chan *testSentEnvelope, 1024),
		violationCount: connect.MessagePoolViolationCount(),
	}
	env := &SubprotocolEnv{
		Client:   client,
		Store:    testUnusedStore{},
		Log:      NewNoopLogger(),
		Settings: settings,
		Budget:   fixture.budget,
		Clock:    fixture.clock,
		Inbound:  SubprotocolInboundWithoutPolicy,
	}
	if adjust != nil {
		adjust(env)
	}
	subprotocol, err := newSubprotocol(ctx, env, &subprotocolSeams{clientPublicKeyOf: testClientPublicKeyOf, send: fixture.send})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(subprotocol.Close)
	fixture.subprotocol = subprotocol
	return fixture
}

// A connect client a sidecar would run, Required through ApplySidecarClientSettings, with no route, so
// nothing it would send leaves the process. Cancelled with the test.
func newTestRequiredClient(t testing.TB, ctx context.Context) *connect.Client {
	t.Helper()
	clientSettings := connect.DefaultClientSettings()
	ApplySidecarClientSettings(clientSettings)
	client := connect.NewClient(ctx, connect.NewId(), connect.NewNoContractClientOob(), clientSettings)
	t.Cleanup(client.Cancel)
	return client
}

// The fixture's send: records a copy, then waits at the gate if one is set.
func (self *testSubprotocol) send(destinationId connect.Id, envelope *protocol.Envelope, ack connect.AckFunction, timeout time.Duration, opts ...any) (bool, error) {
	var gate chan struct{}
	refused := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		gate = self.sendGate
		refused = self.sendRefused
	}()
	self.sent <- &testSentEnvelope{
		destinationId: destinationId,
		envelope:      proto.Clone(envelope).(*protocol.Envelope),
		ack:           ack,
		timeout:       timeout,
		opts:          slices.Clone(opts),
	}
	if gate != nil {
		<-gate
	}
	return !refused, nil
}

// Hands envelope to the inline handler as connect would from sourceId.
func (self *testSubprotocol) receive(sourceId connect.Id, envelope *protocol.Envelope, peer connect.Peer) {
	self.subprotocol.receive(connect.SourceId(sourceId), envelope, peer)
}

// Opens the gate to sourceId under the key keyName names, as PROTO-M1-04's Hello will.
func (self *testSubprotocol) verify(sourceId connect.Id, keyName string) {
	self.subprotocol.markPeerVerified(sourceId, testClientKey(keyName))
}

// The next envelope sent, failing the test if none comes.
func (self *testSubprotocol) nextSent(t testing.TB) *testSentEnvelope {
	t.Helper()
	return testAwait(t, self.sent, "send")
}

// Registers a dispatch that hands each message's request_id and body on, failing the test if it cannot.
func (self *testSubprotocol) collect(t testing.TB, messageType protocol.MessageType) chan *subprotocolMessage {
	t.Helper()
	messages := make(chan *subprotocolMessage, 256)
	remove, err := self.subprotocol.setMessageTypeDispatch(messageType, func(ctx context.Context, message *subprotocolMessage) {
		messages <- testCopyMessage(message)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remove)
	return messages
}

// A copy that outlives the dispatch call, as a function that keeps a message must make.
func testCopyMessage(message *subprotocolMessage) *subprotocolMessage {
	copied := *message
	copied.envelope = proto.Clone(message.envelope).(*protocol.Envelope)
	return &copied
}

// Sends a marker of markerType from sourceId and waits until its worker dispatches it to markers, by
// which point everything that source queued before it has been processed, since a worker drains in
// order.
func (self *testSubprotocol) drain(
	t testing.TB,
	sourceId connect.Id,
	peer connect.Peer,
	markerType protocol.MessageType,
	markers chan *subprotocolMessage,
) {
	t.Helper()
	marker := testRequest(markerType, nil)
	self.receive(sourceId, marker, peer)
	for {
		message := testAwait(t, markers, "marker")
		if message.envelope.RequestId == marker.RequestId {
			return
		}
	}
}

// Closes the dispatcher, which joins every worker, and reconciles its pool buffers both ways: every one
// it retained came back through its release, so none leaked, and connect saw no buffer returned that
// nobody held. The process-wide outstanding count cannot say this, since the fixture's live client keeps
// frames of its own.
func (self *testSubprotocol) closeBalanced(t testing.TB) {
	t.Helper()
	self.subprotocol.Close()
	if held := self.subprotocol.stats.heldBufferCount.Load(); held != 0 {
		t.Errorf("%d pool buffers held after Close", held)
	}
	if violationCount := connect.MessagePoolViolationCount(); violationCount != self.violationCount {
		t.Errorf("%d pool ownership violations", violationCount-self.violationCount)
	}
}

// X10, I-3: a client that is anything but Required carries no sidecar traffic, and refusing it
// registers nothing, so the client stays as it was.
func TestNewSubprotocolRefusesAClientThatIsNotRequired(t *testing.T) {
	for _, mode := range []connect.EncryptionMode{connect.EncryptionModeOff, connect.EncryptionModeOpportunistic} {
		ctx, cancel := context.WithCancel(context.Background())
		clientSettings := connect.DefaultClientSettings()
		clientSettings.EncryptionSettings.Mode = mode
		client := connect.NewClient(ctx, connect.NewId(), connect.NewNoContractClientOob(), clientSettings)
		settings := DefaultSidecarProtocolSettings()
		_, err := NewSubprotocol(ctx, &SubprotocolEnv{
			Client:   client,
			Store:    testUnusedStore{},
			Log:      NewNoopLogger(),
			Settings: settings,
			Budget:   NewSubprotocolBudget(settings, 128*1024*1024),
			Inbound:  SubprotocolInboundWithoutPolicy,
		})
		if !errors.Is(err, errSubprotocolNotRequired) {
			t.Errorf("mode %v: err %v", mode, err)
		}
		unregister, err := connect.RegisterSubprotocol(client, SubprotocolId, envelopeCodec{}, func(connect.TransferPath, *protocol.Envelope, connect.Peer) {})
		if err != nil {
			t.Errorf("mode %v: the refusal left a registration: %v", mode, err)
		} else {
			unregister()
		}
		client.Cancel()
		cancel()
	}
}

// Every required field is required, and §8's hook above all is never read as allow when missing.
func TestNewSubprotocolRefusesAnIncompleteEnv(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := newTestRequiredClient(t, ctx)
	cases := []struct {
		name   string
		adjust func(env *SubprotocolEnv)
		want   error
	}{
		{name: "no client", adjust: func(env *SubprotocolEnv) { env.Client = nil }, want: errSubprotocolEnv},
		{name: "no store", adjust: func(env *SubprotocolEnv) { env.Store = nil }, want: errSubprotocolEnv},
		{name: "no settings", adjust: func(env *SubprotocolEnv) { env.Settings = nil }, want: errSubprotocolEnv},
		{name: "no budget", adjust: func(env *SubprotocolEnv) { env.Budget = nil }, want: errSubprotocolEnv},
		{name: "no inbound", adjust: func(env *SubprotocolEnv) { env.Inbound = nil }, want: errSubprotocolEnv},
		{name: "no queue", adjust: func(env *SubprotocolEnv) { env.Settings.PeerQueueMessageCount = 0 }, want: errInvalidSettings},
		{name: "no hello cache", adjust: func(env *SubprotocolEnv) { env.Settings.HelloCacheTimeout = 0 }, want: errInvalidSettings},
		{name: "call past 55 s", adjust: func(env *SubprotocolEnv) { env.Settings.DefaultCallTimeout = 56 * time.Second }, want: errInvalidSettings},
	}
	for _, c := range cases {
		settings := DefaultSidecarProtocolSettings()
		env := &SubprotocolEnv{
			Client:   client,
			Store:    testUnusedStore{},
			Log:      NewNoopLogger(),
			Settings: settings,
			Budget:   NewSubprotocolBudget(settings, 128*1024*1024),
			Inbound:  SubprotocolInboundWithoutPolicy,
		}
		c.adjust(env)
		subprotocol, err := NewSubprotocol(ctx, env)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err %v", c.name, err)
		}
		if subprotocol != nil {
			subprotocol.Close()
		}
	}
	var nilEnv *SubprotocolEnv
	if _, err := NewSubprotocol(ctx, nilEnv); !errors.Is(err, errSubprotocolEnv) {
		t.Errorf("nil env: err %v", err)
	}
}

// Constructing registers id 21842, so a second dispatcher on one client is connect's error and leaves
// the first in place, and Close unregisters, so the id is free again.
func TestNewSubprotocolRegistersAndCloseUnregisters(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := newTestRequiredClient(t, ctx)
	settings := DefaultSidecarProtocolSettings()
	env := &SubprotocolEnv{
		Client:   client,
		Store:    testUnusedStore{},
		Log:      NewNoopLogger(),
		Settings: settings,
		Budget:   NewSubprotocolBudget(settings, 128*1024*1024),
		Inbound:  SubprotocolInboundWithoutPolicy,
	}
	first, err := NewSubprotocol(ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := NewSubprotocol(ctx, env); err == nil {
		second.Close()
		t.Fatal("a second dispatcher registered on one client")
	}
	if _, err := connect.RegisterSubprotocol(client, SubprotocolId, envelopeCodec{}, func(connect.TransferPath, *protocol.Envelope, connect.Peer) {}); err == nil {
		t.Fatal("id 21842 was free with a dispatcher on it")
	}

	first.Close()
	first.Close()
	unregister, err := connect.RegisterSubprotocol(client, SubprotocolId, envelopeCodec{}, func(connect.TransferPath, *protocol.Envelope, connect.Peer) {})
	if err != nil {
		t.Fatalf("Close left id 21842 registered: %v", err)
	}
	unregister()
	third, err := NewSubprotocol(ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	third.Close()
}

// The real send path is connect's: §6.5's limit holds through envelopeCodec, and ControlId, which
// refuses sends (§6.6), is refused before anything is queued.
func TestSendGoesThroughConnect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := newTestRequiredClient(t, ctx)
	settings := DefaultSidecarProtocolSettings()
	subprotocol, err := NewSubprotocol(ctx, &SubprotocolEnv{
		Client:   client,
		Store:    testUnusedStore{},
		Log:      NewNoopLogger(),
		Settings: settings,
		Budget:   NewSubprotocolBudget(settings, 128*1024*1024),
		Inbound:  SubprotocolInboundWithoutPolicy,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer subprotocol.Close()

	tooLarge := testRequest(testFreeMessageType, testEnvelopeBody(MaxEnvelopeBodyByteCount+1))
	if err := subprotocol.sendEnvelope(connect.NewId(), tooLarge, 0); !errors.Is(err, errEnvelopeTooLarge) {
		t.Errorf("too large: err %v", err)
	}
	if err := subprotocol.sendEnvelope(connect.ControlId, testRequest(testFreeMessageType, nil), 0); err == nil {
		t.Error("a send to ControlId was taken")
	}
	if stats := client.SubprotocolStats(); stats.Sent != 0 {
		t.Errorf("stats %+v", stats)
	}
}

// D-PROTO-6, D-PROTO-10, D-PROTO-13: whatever connect's settings were, a sidecar's client is Required,
// exposes C15's key and asks for no stream, and connect's defaults are filled in where there were none.
func TestApplySidecarClientSettings(t *testing.T) {
	clientSettings := connect.DefaultClientSettings()
	clientSettings.EncryptionSettings.Mode = connect.EncryptionModeOpportunistic
	clientSettings.EncryptionSettings.ExposeVerifiedPeerClientKey = false
	clientSettings.DefaultTransferOpts.ForceStream = true
	bare := connect.DefaultClientSettings()
	bare.EncryptionSettings = nil
	for _, settings := range []*connect.ClientSettings{clientSettings, bare} {
		ApplySidecarClientSettings(settings)
		if settings.EncryptionSettings.Mode != connect.EncryptionModeRequired {
			t.Errorf("mode %v", settings.EncryptionSettings.Mode)
		}
		if !settings.EncryptionSettings.ExposeVerifiedPeerClientKey {
			t.Error("C15's key not exposed")
		}
		if settings.DefaultTransferOpts.ForceStream {
			t.Error("ForceStream stayed on")
		}
	}
}

// The rpc_ files that build on every leg, and who needs them there. Each names no connect package.
var rpcEveryLegFiles = map[string]string{
	// ACL's every-leg engine fills the hook
	"rpc_inbound.go": "ACL's engine",
	// HeadCheck's sources, reconcile engine and relay, which HeadStopState runs and TEAM-M2-10's
	// every-leg ConfigClient reaches (PROTO-M2-04)
	"rpc_headcheck_sources.go": "TEAM's ConfigClient",
	"rpc_headcheck_state.go":   "TEAM's ConfigClient",
	"rpc_headcheck_relay.go":   "TEAM's ConfigClient",
	// HeadStopState, which TEAM-M2-10's ConfigClient reports forks to
	"rpc_headcheck_stop.go":    "TEAM's ConfigClient",
	"rpc_headcheck_witness.go": "TEAM's ConfigClient",
	"rpc_headcheck_revoker.go": "TEAM's ConfigClient",
}

// §4.4: every rpc_ file but those of rpcEveryLegFiles is off the sidecar_http leg, and those, which
// every-leg code reaches, name no connect package.
func TestRpcFilesKeepToTheirLegs(t *testing.T) {
	buildContext := sidecarHttpBuildContext()
	fileSet := token.NewFileSet()
	rpcFileCount := 0
	for _, goFile := range rootGoFiles(t) {
		if !strings.HasPrefix(goFile, "rpc_") || strings.HasSuffix(goFile, "_test.go") {
			continue
		}
		rpcFileCount += 1
		matched, err := buildContext.MatchFile(".", goFile)
		if err != nil {
			t.Fatal(err)
		}
		needer, everyLeg := rpcEveryLegFiles[goFile]
		if !everyLeg {
			if matched {
				t.Errorf("%s builds on the sidecar_http leg", goFile)
			}
			continue
		}
		if !matched {
			t.Errorf("%s is off the sidecar_http leg, where %s needs it", goFile, needer)
		}
		file, err := parser.ParseFile(fileSet, goFile, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			if namesConnect(strings.Trim(spec.Path.Value, `"`)) {
				t.Errorf("%s imports %s", goFile, spec.Path.Value)
			}
		}
	}
	if rpcFileCount < 5 {
		t.Errorf("%d rpc_ files", rpcFileCount)
	}
}

// Step 2 (§6.4): another major is answered VERSION, before the identity gate, so an unverified peer
// learns the range is wrong rather than that it is unknown; the answer goes to the source on its own
// session as a non-companion contract that asks for no stream.
func TestOtherVersionAnsweredVersion(t *testing.T) {
	fixture := newTestSubprotocol(t, nil)
	sourceId := connect.NewId()
	peer := testNetworkPeer("a")
	for _, version := range []uint32{0, 2, 0xFFFFFFFF} {
		request := testRequest(protocol.MessageType_PING, nil)
		request.Version = version
		fixture.receive(sourceId, request, peer)
		sent := fixture.nextSent(t)
		if code := sent.errorCode(t); code != protocol.ErrorCode_ERR_VERSION {
			t.Errorf("version %d: code %v", version, code)
		}
		if sent.destinationId != sourceId || sent.envelope.RequestId != request.RequestId || sent.envelope.Version != WireVersionMajor {
			t.Errorf("version %d: to %s id %d version %d", version, sent.destinationId, sent.envelope.RequestId, sent.envelope.Version)
		}
		if sent.timeout != 0 {
			t.Errorf("version %d: the shared sender waited %v", version, sent.timeout)
		}
		want := peer.TransferKey
		want.CompanionContract = false
		want.ForceStream = false
		if transferKey := sent.transferKey(t); transferKey != want {
			t.Errorf("version %d: reply key %+v, want %+v", version, transferKey, want)
		}
	}
	if count := fixture.subprotocol.stats.versionRefusedCount.Load(); count != 3 {
		t.Errorf("counted %d", count)
	}
	fixture.closeBalanced(t)
}

// A response, a NO_REPLY envelope and anything from ControlId are never answered, whatever is wrong
// with them: answering a response could loop, and ControlId takes no sends.
func TestOtherVersionNotAnsweredWhereNothingIsAsked(t *testing.T) {
	fixture := newTestSubprotocol(t, nil)
	sourceId := connect.NewId()
	response := testResponse(protocol.MessageType_PONG, 7, 0)
	noReply := testRequest(protocol.MessageType_CANCEL, nil)
	noReply.Flags = EnvelopeFlagNoReply
	push := testRequest(protocol.MessageType_PUSH_HINT, []byte{1})
	for _, envelope := range []*protocol.Envelope{response, noReply, push} {
		envelope.Version = 2
	}
	fixture.receive(sourceId, response, testNetworkPeer("a"))
	fixture.receive(sourceId, noReply, testNetworkPeer("a"))
	fixture.receive(connect.ControlId, push, connect.Peer{TransportType: connect.TransportTypeH1})
	stats := &fixture.subprotocol.stats
	if stats.versionRefusedCount.Load() != 3 || stats.replyQueuedCount.Load() != 0 || stats.replyDroppedCount.Load() != 0 {
		t.Errorf("refused %d, queued %d replies", stats.versionRefusedCount.Load(), stats.replyQueuedCount.Load())
	}
	fixture.closeBalanced(t)
}

// Step 5 (D-PROTO-13): with no verified Hello, every request but Hello is refused UNAUTHENTICATED and
// reaches nothing, and every response but the Hello exchange's is dropped. Hello itself passes the gate
// to its check, which refuses one that does not decode, so nothing opens the gate.
func TestNothingBeforeAVerifiedHello(t *testing.T) {
	fixture := newTestSubprotocol(t, nil)
	sourceId := connect.NewId()
	peer := testNetworkPeer("a")
	held := fixture.collect(t, testHeldMessageType)
	for _, messageType := range []protocol.MessageType{
		protocol.MessageType_PING,
		protocol.MessageType_HEAD_CHECK,
		protocol.MessageType_STREAM_OPEN,
		protocol.MessageType_SEARCH,
		testHeldMessageType,
	} {
		request := testRequest(messageType, []byte{1, 2, 3})
		fixture.receive(sourceId, request, peer)
		sent := fixture.nextSent(t)
		if code := sent.errorCode(t); code != protocol.ErrorCode_ERR_UNAUTHENTICATED || sent.envelope.RequestId != request.RequestId {
			t.Errorf("%v: code %v id %d", messageType, code, sent.envelope.RequestId)
		}
	}
	fixture.receive(sourceId, testResponse(protocol.MessageType_PONG, 1, 0), peer)

	hello := testRequest(protocol.MessageType_HELLO, []byte{1})
	fixture.receive(sourceId, hello, peer)
	sent := fixture.nextSent(t)
	if code := sent.errorCode(t); code != protocol.ErrorCode_ERR_INVALID_ARGUMENT || sent.envelope.RequestId != hello.RequestId {
		t.Errorf("hello: code %v", code)
	}
	if fixture.subprotocol.peerVerified(sourceId) {
		t.Errorf("a malformed Hello opened the gate")
	}
	fixture.closeBalanced(t)
	if len(held) != 0 {
		t.Error("an unverified peer's request was dispatched")
	}
	if count := fixture.subprotocol.stats.identityRefusedCount.Load(); count != 6 {
		t.Errorf("refused %d", count)
	}
}

// The Hello exchange passes the closed gate whole: a Hello to its check, which answers it, and a
// HelloResult or an Error to the response dispatch, which drops one that echoes no request this side
// sent; a HelloResult that is no response is refused at the gate.
func TestHelloExchangePassesTheClosedGate(t *testing.T) {
	fixture := newTestSubprotocol(t, nil)
	sourceId := connect.NewId()
	peer := testNetworkPeer("a")

	hello := testRequest(protocol.MessageType_HELLO, []byte{1})
	fixture.receive(sourceId, hello, peer)
	if sent := fixture.nextSent(t); sent.envelope.RequestId != hello.RequestId || sent.errorCode(t) != protocol.ErrorCode_ERR_INVALID_ARGUMENT {
		t.Errorf("hello answered %d", sent.envelope.RequestId)
	}
	unrouted := fixture.subprotocol.stats.unroutedCount.Load()
	fixture.receive(sourceId, testResponse(protocol.MessageType_HELLO_RESULT, 11, 0), peer)
	fixture.receive(sourceId, testResponse(protocol.MessageType_ERROR, 12, EnvelopeFlagError), peer)
	// a HelloResult that is no response is no part of the exchange
	notResponse := testRequest(protocol.MessageType_HELLO_RESULT, nil)
	fixture.receive(sourceId, notResponse, peer)
	if code := fixture.nextSent(t).errorCode(t); code != protocol.ErrorCode_ERR_UNAUTHENTICATED {
		t.Errorf("code %v", code)
	}
	// a second Hello rides the same worker behind the two responses, so its answer means both were
	// dispatched
	second := testRequest(protocol.MessageType_HELLO, []byte{1})
	fixture.receive(sourceId, second, peer)
	if sent := fixture.nextSent(t); sent.envelope.RequestId != second.RequestId {
		t.Errorf("answer to %d", sent.envelope.RequestId)
	}
	fixture.closeBalanced(t)
	if count := fixture.subprotocol.stats.unroutedCount.Load() - unrouted; count != 2 {
		t.Errorf("%d responses reached the response dispatch and were dropped, want 2", count)
	}
	if count := fixture.subprotocol.stats.identityRefusedCount.Load(); count != 1 {
		t.Errorf("refused %d at the gate", count)
	}
}

// An open gate admits the frames of the session it opened under, and closes for good on another key,
// stays closed for a frame with no key without forgetting the peer, and ends at HelloCacheTimeout
// (plan-PROTO-small-readings.md's reading 1).
func TestIdentityGateFollowsTheVerifiedKey(t *testing.T) {
	fixture := newTestSubprotocol(t, nil)
	sourceId := connect.NewId()
	ping := func(keyName string) protocol.ErrorCode {
		request := testRequest(protocol.MessageType_PING, nil)
		fixture.receive(sourceId, request, testNetworkPeer(keyName))
		sent := fixture.nextSent(t)
		if sent.envelope.RequestId != request.RequestId {
			t.Fatalf("answer to %d, want %d", sent.envelope.RequestId, request.RequestId)
		}
		if sent.envelope.Type == uint32(protocol.MessageType_PONG) {
			return protocol.ErrorCode_ERR_OK
		}
		return sent.errorCode(t)
	}

	fixture.verify(sourceId, "a")
	if !fixture.subprotocol.peerVerified(sourceId) {
		t.Errorf("verified, and the gate reads closed")
	}
	if code := ping("a"); code != protocol.ErrorCode_ERR_OK {
		t.Errorf("verified key: %v", code)
	}
	if code := ping(""); code != protocol.ErrorCode_ERR_UNAUTHENTICATED {
		t.Errorf("no key: %v", code)
	}
	if code := ping("a"); code != protocol.ErrorCode_ERR_OK {
		t.Errorf("a frame with no key forgot the peer: %v", code)
	}
	if code := ping("b"); code != protocol.ErrorCode_ERR_UNAUTHENTICATED {
		t.Errorf("re-keyed: %v", code)
	}
	if code := ping("a"); code != protocol.ErrorCode_ERR_UNAUTHENTICATED {
		t.Errorf("a re-keyed session left the gate open: %v", code)
	}

	fixture.verify(sourceId, "c")
	fixture.clock.Advance(fixture.settings.HelloCacheTimeout - time.Nanosecond)
	if code := ping("c"); code != protocol.ErrorCode_ERR_OK {
		t.Errorf("before the cache ends: %v", code)
	}
	fixture.clock.Advance(time.Nanosecond)
	if fixture.subprotocol.peerVerified(sourceId) {
		t.Errorf("expired, and the gate reads open")
	}
	if code := ping("c"); code != protocol.ErrorCode_ERR_UNAUTHENTICATED {
		t.Errorf("after the cache ends: %v", code)
	}

	fixture.verify(sourceId, "d")
	fixture.subprotocol.forgetPeer(sourceId)
	if code := ping("d"); code != protocol.ErrorCode_ERR_UNAUTHENTICATED {
		t.Errorf("forgotten: %v", code)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := fixture.subprotocol.ensurePeerVerified(cancelled, sourceId); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: err %v", err)
	}
	fixture.closeBalanced(t)
}

// Step 7: §8's hook is asked about each envelope that passed the gate, told its source, type, stream
// and direction, and a refusal answers PERMISSION_DENIED. It is never asked about what an earlier step
// refused, nor about ControlId's hints.
func TestInboundHookDecidesLast(t *testing.T) {
	var stateLock sync.Mutex
	asked := []SubprotocolInbound{}
	admit := false
	fixture := newTestSubprotocol(t, func(env *SubprotocolEnv) {
		env.Inbound = func(inbound SubprotocolInbound) bool {
			stateLock.Lock()
			defer stateLock.Unlock()
			asked = append(asked, inbound)
			return admit
		}
	})
	sourceId := connect.NewId()
	unverifiedId := connect.NewId()
	fixture.verify(sourceId, "a")
	pushes := fixture.collect(t, protocol.MessageType_PUSH_HINT)

	request := testRequest(testHeldMessageType, []byte{1})
	request.StreamId = 5
	fixture.receive(sourceId, request, testNetworkPeer("a"))
	if code := fixture.nextSent(t).errorCode(t); code != protocol.ErrorCode_ERR_PERMISSION_DENIED {
		t.Errorf("code %v", code)
	}
	fixture.receive(sourceId, testResponse(testHeldMessageType, 3, 0), testNetworkPeer("a"))
	fixture.receive(unverifiedId, testRequest(testHeldMessageType, nil), testNetworkPeer("a"))
	if code := fixture.nextSent(t).errorCode(t); code != protocol.ErrorCode_ERR_UNAUTHENTICATED {
		t.Errorf("unverified: code %v", code)
	}
	fixture.receive(connect.ControlId, testRequest(protocol.MessageType_PUSH_HINT, []byte{1}), connect.Peer{TransportType: connect.TransportTypeH1})
	testAwait(t, pushes, "push")

	stateLock.Lock()
	defer stateLock.Unlock()
	want := []SubprotocolInbound{
		{SourceId: Id(sourceId), MessageType: testHeldMessageType, StreamId: 5},
		{SourceId: Id(sourceId), MessageType: testHeldMessageType, Response: true},
	}
	if !slices.Equal(asked, want) {
		t.Errorf("asked %+v, want %+v", asked, want)
	}
	if count := fixture.subprotocol.stats.inboundRefusedCount.Load(); count != 2 {
		t.Errorf("refused %d", count)
	}
}

// §6.4: a request of a type nothing registered is answered UNIMPLEMENTED; a NO_REPLY envelope or a
// response nothing takes is counted and left; a Ping gets a Pong with its request_id and no body, and a
// Ping that carries one is refused.
func TestDispatchAnswersWhatNothingTakes(t *testing.T) {
	fixture := newTestSubprotocol(t, nil)
	sourceId := connect.NewId()
	peer := testNetworkPeer("a")
	fixture.verify(sourceId, "a")
	markers := fixture.collect(t, testMarkerMessageType)

	unknown := testRequest(protocol.MessageType(0x8F01), []byte{1})
	fixture.receive(sourceId, unknown, peer)
	if sent := fixture.nextSent(t); sent.errorCode(t) != protocol.ErrorCode_ERR_UNIMPLEMENTED || sent.envelope.RequestId != unknown.RequestId {
		t.Errorf("unknown: %+v", sent.envelope)
	}
	ping := testRequest(protocol.MessageType_PING, nil)
	fixture.receive(sourceId, ping, peer)
	pong := fixture.nextSent(t)
	if pong.envelope.Type != uint32(protocol.MessageType_PONG) || pong.envelope.Flags != EnvelopeFlagResponse ||
		pong.envelope.RequestId != ping.RequestId || len(pong.envelope.Body) != 0 || pong.envelope.Version != WireVersionMajor {
		t.Errorf("pong %+v", pong.envelope)
	}
	withBody := testRequest(protocol.MessageType_PING, []byte{1})
	fixture.receive(sourceId, withBody, peer)
	if code := fixture.nextSent(t).errorCode(t); code != protocol.ErrorCode_ERR_INVALID_ARGUMENT {
		t.Errorf("ping with a body: %v", code)
	}

	noReply := testRequest(protocol.MessageType(0x8F02), []byte{1})
	noReply.Flags = EnvelopeFlagNoReply
	pingNoReply := testRequest(protocol.MessageType_PING, nil)
	pingNoReply.Flags = EnvelopeFlagNoReply
	fixture.receive(sourceId, noReply, peer)
	fixture.receive(sourceId, pingNoReply, peer)
	fixture.receive(sourceId, testResponse(protocol.MessageType_PONG, 9, 0), peer)
	fixture.drain(t, sourceId, peer, testMarkerMessageType, markers)
	stats := &fixture.subprotocol.stats
	if stats.unroutedCount.Load() != 3 || stats.unimplementedCount.Load() != 1 {
		t.Errorf("unrouted %d, unimplemented %d", stats.unroutedCount.Load(), stats.unimplementedCount.Load())
	}
	if len(fixture.sent) != 0 {
		t.Errorf("%d sends for what asked nothing", len(fixture.sent))
	}
	fixture.closeBalanced(t)
}

// One function per type, none for Ping, which is answered here; remove frees the type, and a removal
// that is no longer the registration's own leaves a later one alone.
func TestDispatchRegistration(t *testing.T) {
	fixture := newTestSubprotocol(t, nil)
	function := func(ctx context.Context, message *subprotocolMessage) {}
	remove, err := fixture.subprotocol.setMessageTypeDispatch(testHeldMessageType, function)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.subprotocol.setMessageTypeDispatch(testHeldMessageType, function); !errors.Is(err, errSubprotocolDispatchTaken) {
		t.Errorf("second: err %v", err)
	}
	if _, err := fixture.subprotocol.setMessageTypeDispatch(protocol.MessageType_PING, function); !errors.Is(err, errSubprotocolDispatchTaken) {
		t.Errorf("ping: err %v", err)
	}
	if _, err := fixture.subprotocol.setMessageTypeDispatch(testFreeMessageType, nil); !errors.Is(err, errSubprotocolDispatchTaken) {
		t.Errorf("nil: err %v", err)
	}
	remove()
	again, err := fixture.subprotocol.setMessageTypeDispatch(testHeldMessageType, function)
	if err != nil {
		t.Fatal(err)
	}
	remove()
	if _, err := fixture.subprotocol.setMessageTypeDispatch(testHeldMessageType, function); !errors.Is(err, errSubprotocolDispatchTaken) {
		t.Errorf("a stale remove freed a later registration: err %v", err)
	}
	again()

	// the dispatcher's own: every response, Hello and Cancel
	if _, err := fixture.subprotocol.setResponseDispatch(function); !errors.Is(err, errSubprotocolDispatchTaken) {
		t.Errorf("a second response dispatch: err %v", err)
	}
	for _, messageType := range []protocol.MessageType{protocol.MessageType_HELLO, protocol.MessageType_CANCEL} {
		if _, err := fixture.subprotocol.setMessageTypeDispatch(messageType, function); !errors.Is(err, errSubprotocolDispatchTaken) {
			t.Errorf("%v: err %v", messageType, err)
		}
	}
}

// A chunked request reaches its function once, whole, from its source's worker; a first chunk over the
// reassembly cap is answered RESOURCE_EXHAUSTED and its later chunks drop; every chunk's pool buffer
// goes back.
func TestChunkedRequestsReassembleBeforeDispatch(t *testing.T) {
	fixture := newTestSubprotocol(t, nil)
	sourceId := connect.NewId()
	peer := testNetworkPeer("a")
	fixture.verify(sourceId, "a")
	held := fixture.collect(t, testHeldMessageType)

	body := testEnvelopeBody(3*MaxEnvelopeBodyByteCount + 7)
	header := testRequest(testHeldMessageType, nil)
	for _, envelope := range testChunks(t, header, body) {
		fixture.receive(sourceId, envelope, peer)
	}
	message := testAwait(t, held, "reassembled request")
	if message.envelope.RequestId != header.RequestId || message.envelope.Chunk != nil || !slices.Equal(message.envelope.Body, body) {
		t.Errorf("request %d, %d B", message.envelope.RequestId, len(message.envelope.Body))
	}

	overCap := testRequest(testHeldMessageType, nil)
	chunks := testChunks(t, overCap, testEnvelopeBody(int(fixture.settings.ReassemblyMaxBodyByteCount)+1))
	for _, envelope := range chunks[:3] {
		fixture.receive(sourceId, envelope, peer)
	}
	sent := fixture.nextSent(t)
	if code := sent.errorCode(t); code != protocol.ErrorCode_ERR_RESOURCE_EXHAUSTED || sent.envelope.RequestId != overCap.RequestId {
		t.Errorf("over the cap: code %v id %d", code, sent.envelope.RequestId)
	}
	fixture.closeBalanced(t)
	if len(held) != 0 || len(fixture.sent) != 0 {
		t.Errorf("%d dispatched, %d sent after the refusal", len(held), len(fixture.sent))
	}
}

// A function that panics loses its own message and nothing more: the worker goes on to the next.
func TestDispatchPanicStaysWithItsMessage(t *testing.T) {
	fixture := newTestSubprotocol(t, nil)
	sourceId := connect.NewId()
	peer := testNetworkPeer("a")
	fixture.verify(sourceId, "a")
	markers := fixture.collect(t, testMarkerMessageType)
	remove, err := fixture.subprotocol.setMessageTypeDispatch(testHeldMessageType, func(ctx context.Context, message *subprotocolMessage) {
		panic("a component's bug")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	fixture.receive(sourceId, testRequest(testHeldMessageType, []byte{1}), peer)
	fixture.drain(t, sourceId, peer, testMarkerMessageType, markers)
	if count := fixture.subprotocol.stats.panicCount.Load(); count != 1 {
		t.Errorf("panics %d", count)
	}
	fixture.closeBalanced(t)
}

// The sender serves every peer, so it never waits on one: while connect holds its send, refusals
// fill the reply queue, the next is dropped and counted, and the inline handler still returns at once.
// A send connect refuses is counted too.
func TestReplyQueueDropsWhenFull(t *testing.T) {
	fixture := newTestSubprotocol(t, nil)
	gate := make(chan struct{})
	func() {
		fixture.stateLock.Lock()
		defer fixture.stateLock.Unlock()
		fixture.sendGate = gate
	}()
	sourceId := connect.NewId()
	peer := testNetworkPeer("a")

	fixture.receive(sourceId, testRequest(protocol.MessageType_PING, nil), peer)
	fixture.nextSent(t)
	for range fixture.settings.PeerQueueMessageCount {
		fixture.receive(sourceId, testRequest(protocol.MessageType_PING, nil), peer)
	}
	returned := make(chan struct{})
	go func() {
		fixture.receive(sourceId, testRequest(protocol.MessageType_PING, nil), peer)
		close(returned)
	}()
	testAwait(t, returned, "return from the inline handler")
	stats := &fixture.subprotocol.stats
	if dropped := stats.replyDroppedCount.Load(); dropped != 1 {
		t.Errorf("dropped %d", dropped)
	}

	func() {
		fixture.stateLock.Lock()
		defer fixture.stateLock.Unlock()
		fixture.sendGate = nil
		fixture.sendRefused = true
	}()
	close(gate)
	for range fixture.settings.PeerQueueMessageCount {
		fixture.nextSent(t)
	}
	fixture.closeBalanced(t)
	if sent, failed := stats.replySentCount.Load(), stats.replyFailedCount.Load(); sent+failed != uint64(fixture.settings.PeerQueueMessageCount)+1 || failed == 0 {
		t.Errorf("sent %d, failed %d", sent, failed)
	}
}

// Close joins a worker held in its function, which sees its ctx end, gives back every queued buffer
// without running it, and drops what arrives after it.
func TestCloseJoinsWithWorkQueued(t *testing.T) {
	fixture := newTestSubprotocol(t, nil)
	sourceId := connect.NewId()
	peer := testNetworkPeer("a")
	fixture.verify(sourceId, "a")
	entered := make(chan struct{}, 1)
	returned := make(chan struct{})
	var returnOnce sync.Once
	remove, err := fixture.subprotocol.setMessageTypeDispatch(testHeldMessageType, func(ctx context.Context, message *subprotocolMessage) {
		entered <- struct{}{}
		<-ctx.Done()
		returnOnce.Do(func() { close(returned) })
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remove()

	fixture.receive(sourceId, testRequest(testHeldMessageType, []byte{1}), peer)
	testAwait(t, entered, "dispatch")
	for range 3 {
		fixture.receive(sourceId, testRequest(testHeldMessageType, []byte{2}), peer)
	}
	stats := &fixture.subprotocol.stats
	if held := stats.heldBufferCount.Load(); held != 4 {
		t.Errorf("%d buffers held", held)
	}
	fixture.closeBalanced(t)
	select {
	case <-returned:
	default:
		t.Fatal("Close returned before the function it waits for")
	}
	if dispatched := stats.dispatchedCount.Load(); dispatched != 1 {
		t.Errorf("%d dispatched after Close began", dispatched)
	}

	fixture.receive(sourceId, testRequest(testHeldMessageType, []byte{3}), peer)
	if stats.closedDroppedCount.Load() != 1 || stats.heldBufferCount.Load() != 0 {
		t.Errorf("after Close: dropped %d, held %d", stats.closedDroppedCount.Load(), stats.heldBufferCount.Load())
	}
}
