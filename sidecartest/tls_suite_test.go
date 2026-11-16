// §22.5's §13 row across components (TLS-M5-25; S5, FS-34's edge half, §13.9's kill switch, §13.5's route probe) on
// T2's fakes, in one process: the socket suite's world, the sockets engine on the production gate over a network's real
// authorization log (socket_suite_test.go), with tls/'s ValidateListen registered over a fake listen facts source; and
// in front of it tlsedge, on the Net's host, serving loopback 443 behind its PROXY listener, its label map a
// FakeTlsEdgeStore holding the network's label, every Find it makes going through the sockets engine's own route as an
// urnetwork-edge platform client. Each component's own rows stay in its task (namespace_tls_test.go's refusal table,
// tlsedge's alert table, the front's FS-34 and audiences); what is here is what only the composition shows:
//
//   - S5's registration half: the publish grant §8's evaluator gives a member device for tls/443/blog, under each §13.7
//     audience, admits the registration; at Community a grant of 8 days is refused and one of 7 passes, the 8-day grant
//     ending a lease it held at the next heartbeat once the log moves; an unverified network publishes nothing; a
//     device with no certificate row, or the system publish without a receiver's grant, registers nothing.
//   - Passthrough (X1, R-TLS-4): a visitor completes TLS with the device's key, on the chain certs ordered from Pebble
//     for the network's set, while what tlsedge handled of the connection is the hello and records whose page bodies it
//     never holds, both directions spliced byte for byte; the listener receives the TlsEdgeOpen and ticket the edge's
//     Find gave, naming the visitor, the server name, the ticket's expiry and one of the edge's K clients.
//   - The kill switch (§13.9): a host killed through network_tls_suspension and {tes_}, with the trigger's key event on
//     the host's one subscriber, refuses new visitors with unrecognized_name and no Find and resets an open splice
//     with RST_REVOKED within 5 s of the fake clock, and the engine's own Find answers denied; a lift lets visitors in
//     again.
//   - The route probe (§13.4): a hello offering ur-route-probe gets unrecognized_name with no Find, no ticket and no
//     record.
//
// Where the composition stops: the edge's stream to the listener is an in-memory pair, and the listener's end is a
// TLS server on the device's key and chain, not §13.7's front over a SocketListener. sidecartest has no edge-role
// connect client on its exchange yet, so no test here runs SocketEdgeDialer's open, §9.6's admission or the front
// (FS-34's front half is TestTlsFrontZeroBytesBeforeAuthentication's). Nothing sleeps: loads, kills and connection
// ends are awaited by the engines' own counts, time is the Net's FakeClock, and a real timer is only a guard that
// fails a hung test.

package sidecartest_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/certsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/socketsservice"
	"github.com/urnetwork/sidecar/tlsedgeservice"
)

// The production gate with an urnetwork-edge caller's tls/ dial and publish answered as §8.10 has an edge Find stand:
// a visitor's Find runs as autogroup:public and passes where a sidecar of the network holds a publish grant for the
// name's host, whatever its audience, which only the listener's front enforces (§13.7). SocketProjectionGate refuses
// every edge tls/ Find until SOCK-M5-07's gate takes ACL-M5-01's view (sock-m5-07's report), so this stands in for
// that wiring; every other answer, the listener check Find makes of each picked listener under its own sidecar
// included, is the production gate's on the network's real log.
type tlsSuiteEdgeGate struct {
	*socketsservice.SocketProjectionGate
	edgeNetworkId connect.Id
	// the network's sidecars a publish grant is looked for under, read once the world has them
	publishers func() []connect.Id
	clock      sidecar.Clock
}

var _ socketsservice.SocketGateFollower = (*tlsSuiteEdgeGate)(nil)

func (self *tlsSuiteEdgeGate) View(networkId connect.Id) (socketsservice.SocketGateView, error) {
	view, err := self.SocketProjectionGate.View(networkId)
	if err != nil {
		return nil, err
	}
	return &tlsSuiteEdgeView{SocketGateView: view, gate: self}, nil
}

func (self *tlsSuiteEdgeGate) MayDial(ctx context.Context, request *socketsservice.SocketGateRequest) (*socketsservice.SocketGateVerdict, error) {
	view, err := self.View(request.NetworkId)
	if err != nil {
		return nil, err
	}
	return view.MayDial(request, self.clock.Now()), nil
}

func (self *tlsSuiteEdgeGate) MayPublish(ctx context.Context, request *socketsservice.SocketGateRequest) (*socketsservice.SocketGateVerdict, error) {
	view, err := self.View(request.NetworkId)
	if err != nil {
		return nil, err
	}
	return view.MayPublish(request, self.clock.Now()), nil
}

// One network's state with the edge's tls/ answers above.
type tlsSuiteEdgeView struct {
	socketsservice.SocketGateView
	gate *tlsSuiteEdgeGate
}

// Whether request is an urnetwork-edge caller's on a tls/ name.
func (self *tlsSuiteEdgeView) edgeTls(request *socketsservice.SocketGateRequest) bool {
	return request.CallerNetworkId == self.gate.edgeNetworkId && strings.HasPrefix(request.Name, "tls/")
}

// The first publish grant a sidecar of the network holds for the name's host, as the production view judges it under
// that sidecar, or a refusal.
func (self *tlsSuiteEdgeView) edgeVerdict(request *socketsservice.SocketGateRequest, now time.Time) *socketsservice.SocketGateVerdict {
	for _, sidecarId := range self.gate.publishers() {
		publisher := *request
		publisher.CallerNetworkId = request.NetworkId
		publisher.SidecarId = &sidecarId
		if verdict := self.SocketGateView.MayPublish(&publisher, now); verdict != nil && verdict.Allowed {
			return verdict
		}
	}
	return &socketsservice.SocketGateVerdict{}
}

func (self *tlsSuiteEdgeView) MayDial(request *socketsservice.SocketGateRequest, now time.Time) *socketsservice.SocketGateVerdict {
	if self.edgeTls(request) {
		return self.edgeVerdict(request, now)
	}
	return self.SocketGateView.MayDial(request, now)
}

func (self *tlsSuiteEdgeView) MayPublish(request *socketsservice.SocketGateRequest, now time.Time) *socketsservice.SocketGateVerdict {
	if self.edgeTls(request) {
		return self.edgeVerdict(request, now)
	}
	return self.SocketGateView.MayPublish(request, now)
}

// The socket suite's world with tls/ open over facts the test sets.
type tlsSuiteWorld struct {
	*socketSuiteWorld
	hooks *socketsservice.TlsNamespaceHooks

	stateLock sync.Mutex
	facts     *socketsservice.TlsListenFacts
}

// A world whose network is verified, at Community, and whose listener holds the network's pair until a day from now.
func newTlsSuiteWorld(t *testing.T) *tlsSuiteWorld {
	t.Helper()
	world := &tlsSuiteWorld{socketSuiteWorld: newSocketSuiteWorldGated(t, nil, func(world *socketSuiteWorld, production *socketsservice.SocketProjectionGate) socketsservice.SocketGate {
		return &tlsSuiteEdgeGate{
			SocketProjectionGate: production,
			edgeNetworkId:        world.edgeNetworkId,
			publishers: func() []connect.Id {
				return []connect.Id{connect.Id(world.listener.device.SidecarId), connect.Id(world.dialer.device.SidecarId)}
			},
			clock: world.net.Clock(),
		}
	})}
	world.facts = &socketsservice.TlsListenFacts{
		Verified: true,
		Standing: sidecar.AbuseStandingStandard,
		Tier:     "free",
		Certs: []*socketsservice.TlsListenCert{
			{SidecarId: connect.Id(world.listener.device.SidecarId), NotAfter: world.net.Clock().Now().Add(24 * time.Hour), NetworkPair: true},
		},
	}
	source := socketsservice.TlsListenFactsFunc(func(ctx context.Context, networkId connect.Id) (*socketsservice.TlsListenFacts, error) {
		if networkId != world.networkId {
			return nil, fmt.Errorf("no such network")
		}
		return world.currentFacts(), nil
	})
	hooks, err := socketsservice.NewTlsNamespaceHooks(world.ctx, source, world.net.Clock(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hooks.Close)
	world.hooks = hooks
	if err := world.engine.RegisterNamespace(sidecar.SocketNamespaceTls, hooks); err != nil {
		t.Fatal(err)
	}
	world.loadFacts()
	return world
}

// The facts the source answers now.
func (self *tlsSuiteWorld) currentFacts() *socketsservice.TlsListenFacts {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.facts
}

// Has the source answer change's copy of the facts from now on, and the hooks read them.
func (self *tlsSuiteWorld) setFacts(change func(facts *socketsservice.TlsListenFacts)) {
	self.t.Helper()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		facts := *self.facts
		change(&facts)
		self.facts = &facts
	}()
	self.loadFacts()
}

// Has the hooks read the facts as they now stand.
func (self *tlsSuiteWorld) loadFacts() {
	self.t.Helper()
	if err := self.hooks.LoadFacts(self.ctx, self.networkId); err != nil {
		self.t.Fatal(err)
	}
}

// Saves a policy giving members publish and listen on the tls/443 names of hosts under audience, expiring at
// expires, and has the gate load it.
func (self *tlsSuiteWorld) savePublish(audience string, expires time.Time, hosts ...string) {
	self.t.Helper()
	if len(hosts) == 0 {
		hosts = []string{"blog"}
	}
	grants := []string{`{ "src": ["autogroup:member"], "dst": ["sock:app/*"], "allow": ["listen", "dial"] }`}
	for _, host := range hosts {
		grants = append(grants, fmt.Sprintf(`{ "src": ["autogroup:member"], "dst": ["dns:%s", "sock:tls/443/%s"], "allow": ["publish", "listen"], "audience": %q, "expires": %q }`,
			host, host, audience, expires.UTC().Format(time.RFC3339)))
	}
	self.admission.SaveAclPolicy([]byte(`{"grants": [`+strings.Join(grants, ",\n")+`]}`), sidecartest.AclSaveMembers{})
	count, _ := self.gate.Loads()
	self.engine.ProjectionChanged(self.networkId)
	self.awaitLoadsPast(count)
}

// caller's registration of an edge name, http, with a claim its identity key signs.
func (self *tlsSuiteWorld) edgeRegistration(caller *socketSuiteSidecar, name string) *sidecar.SocketRegistration {
	self.t.Helper()
	listenId := connect.NewId()
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.SocketRegistrationClaim{
		NetworkId: self.networkId.Bytes(),
		Name:      name,
		ListenId:  listenId.Bytes(),
		Protocol:  "tls",
		AppMode:   "http",
	})
	if err != nil {
		self.t.Fatal(err)
	}
	signed := &bridge.Signed{
		Body:      body,
		Signature: ed25519.Sign(caller.device.Key, bridge.SignedBytes(sidecar.SocketRegistrationPurpose, bridge.SignedType_SIGNED_SOCKET_REGISTRATION, body)),
		Type:      uint32(bridge.SignedType_SIGNED_SOCKET_REGISTRATION),
	}
	claim, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil {
		self.t.Fatal(err)
	}
	return &sidecar.SocketRegistration{
		Name:       name,
		ListenId:   &listenId,
		Protocol:   "tls",
		AppMode:    "http",
		Alpn:       []string{"h2", "http/1.1"},
		Weight:     100,
		MaxStreams: 256,
		Serving:    true,
		Claim:      claim,
	}
}

// The one entry's status on a whole-set page.
func (self *tlsSuiteWorld) status(caller *socketSuiteSidecar, setVersion uint64, registration *sidecar.SocketRegistration) sidecar.SocketRegistrationStatus {
	self.t.Helper()
	code, result := self.register(caller, setVersion, nil, nil, []*sidecar.SocketRegistration{registration})
	if code != http.StatusOK || result.Error != nil {
		self.t.Fatalf("the page answered %d, %+v", code, result.Error)
	}
	return result.Statuses[0]
}

// S5 on the log: each §13.7 audience's grant admits a member device's tls/443/blog; at Community a 7-day grant passes
// and an 8-day one is refused, ending the lease at the next heartbeat once the log carries it.
func TestTlsSuiteAdmitsEachAudienceAndHoldsCommunityToSevenDays(t *testing.T) {
	world := newTlsSuiteWorld(t)
	now := world.net.Clock().Now()
	setVersion := uint64(0)
	for _, audience := range []string{"members", "members-device", "link", "public"} {
		world.savePublish(audience, now.Add(7*24*time.Hour))
		setVersion += 1
		if status := world.status(world.listener, setVersion, world.edgeRegistration(world.listener, "tls/443/blog")); status != sidecar.SocketRegistrationStatusOk {
			t.Fatalf("a %s grant of 7 days answered %s", audience, status)
		}
	}
	registration := world.edgeRegistration(world.listener, "tls/443/blog")
	setVersion += 1
	if status := world.status(world.listener, setVersion, registration); status != sidecar.SocketRegistrationStatusOk {
		t.Fatalf("the lease answered %s", status)
	}
	world.savePublish("public", now.Add(8*24*time.Hour))
	setVersion += 1
	if status := world.status(world.listener, setVersion, registration); status != sidecar.SocketRegistrationStatusRevoked {
		t.Fatalf("an 8-day grant at Community answered %s", status)
	}
	// at Pro the same grant passes
	world.setFacts(func(facts *socketsservice.TlsListenFacts) { facts.Tier = "pro" })
	setVersion += 1
	if status := world.status(world.listener, setVersion, world.edgeRegistration(world.listener, "tls/443/blog")); status != sidecar.SocketRegistrationStatusOk {
		t.Fatalf("an 8-day grant at Pro answered %s", status)
	}
}

// An unverified network publishes nothing, a device holding no certificate row registers nothing, and a host the policy
// gives no publish grant is refused, all on the log's own grants.
func TestTlsSuiteRefusesWhatTheGrantsOrFactsDoNotAllow(t *testing.T) {
	world := newTlsSuiteWorld(t)
	world.savePublish("public", world.net.Clock().Now().Add(24*time.Hour))
	if status := world.status(world.dialer, 1, world.edgeRegistration(world.dialer, "tls/443/blog")); status != sidecar.SocketRegistrationStatusDenied {
		t.Fatalf("a device with no certificate row answered %s", status)
	}
	if status := world.status(world.listener, 1, world.edgeRegistration(world.listener, "tls/443/shop")); status != sidecar.SocketRegistrationStatusDenied {
		t.Fatalf("a host with no publish grant answered %s", status)
	}
	if status := world.status(world.listener, 2, world.edgeRegistration(world.listener, "tls/443/blog")); status != sidecar.SocketRegistrationStatusOk {
		t.Fatalf("the granted host answered %s", status)
	}
	world.setFacts(func(facts *socketsservice.TlsListenFacts) { facts.Verified = false })
	if status := world.status(world.listener, 3, world.edgeRegistration(world.listener, "tls/443/blog")); status == sidecar.SocketRegistrationStatusOk {
		t.Fatal("an unverified network's publish was admitted")
	}
	// the system publish needs a receiver's smtp/25/mx grant, which no member holds here
	world.setFacts(func(facts *socketsservice.TlsListenFacts) {
		facts.Verified = true
		facts.MailNetwork = true
	})
	if status := world.status(world.listener, 4, world.edgeRegistration(world.listener, sidecar.SocketSystemPublishName)); status != sidecar.SocketRegistrationStatusDenied {
		t.Fatalf("the system publish with no receiver's grant answered %s", status)
	}
}

// The registered domain the edge's names sit under: a .example name, which no real root is.
const tlsSuiteRoot = "ur.example"

// How long, in real time, one step through loopback or an engine's goroutines may take before the test fails: a
// failure's bound, never a wait a test relies on.
const tlsSuiteGuard = 30 * time.Second

// The visitor every PROXY header here names, from RFC 5737's documentation range, and the lb address it came in on.
var (
	tlsSuiteVisitor = netip.MustParseAddrPort("198.51.100.23:40123")
	tlsSuiteLb      = netip.MustParseAddr("192.0.2.10")
)

// One direction of an edge stream: bytes written wait until they are read, and an end is either a close, which reads
// as EOF once drained, or a failure, which every later call returns.
type tlsSuiteHalf struct {
	stateLock sync.Mutex
	changed   *sync.Cond
	buffer    bytes.Buffer
	closed    bool
	err       error
}

func newTlsSuiteHalf() *tlsSuiteHalf {
	half := &tlsSuiteHalf{}
	half.changed = sync.NewCond(&half.stateLock)
	return half
}

func (self *tlsSuiteHalf) write(b []byte) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.err != nil {
		return 0, self.err
	}
	if self.closed {
		return 0, net.ErrClosed
	}
	self.buffer.Write(b)
	self.changed.Broadcast()
	return len(b), nil
}

func (self *tlsSuiteHalf) read(b []byte) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for {
		if self.err != nil {
			return 0, self.err
		}
		if 0 < self.buffer.Len() {
			return self.buffer.Read(b)
		}
		if self.closed {
			return 0, io.EOF
		}
		self.changed.Wait()
	}
}

func (self *tlsSuiteHalf) closeWrite() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.closed = true
	self.changed.Broadcast()
}

func (self *tlsSuiteHalf) fail(err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.err == nil {
		self.err = err
	}
	self.changed.Broadcast()
}

// The stream one edge dial opened: tlsedge holds the edge's end as a TlsEdgeStream, and the listener's end is a
// net.Conn the test's listener serves. Every byte the edge put into it or took out of it is kept, in order, which is
// all tlsedge handled of the visitor's connection past the PROXY header.
type tlsSuiteStream struct {
	toListener   *tlsSuiteHalf
	fromListener *tlsSuiteHalf
	// what the open carried: the verified ticket and the TlsEdgeOpen the edge built for it
	ticket   *protocol.SocketTicket
	metadata []byte
	// the edge's Reset code, sent once
	resetCodes chan protocol.StreamResetCode
	resetOnce  sync.Once

	stateLock sync.Mutex
	edgeWrote bytes.Buffer
	edgeRead  bytes.Buffer
}

func newTlsSuiteStream(ticket *protocol.SocketTicket, metadata []byte) *tlsSuiteStream {
	return &tlsSuiteStream{
		toListener:   newTlsSuiteHalf(),
		fromListener: newTlsSuiteHalf(),
		ticket:       ticket,
		metadata:     metadata,
		resetCodes:   make(chan protocol.StreamResetCode, 1),
	}
}

// What the edge wrote into the stream and read from it so far.
func (self *tlsSuiteStream) edgeBytes() ([]byte, []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return bytes.Clone(self.edgeWrote.Bytes()), bytes.Clone(self.edgeRead.Bytes())
}

// The edge's open as the listener received it.
func (self *tlsSuiteStream) open(t *testing.T) *protocol.TlsEdgeOpen {
	t.Helper()
	open := &protocol.TlsEdgeOpen{}
	if err := proto.Unmarshal(self.metadata, open); err != nil {
		t.Fatal(err)
	}
	return open
}

// Waits for the edge's Reset and answers its code.
func (self *tlsSuiteStream) awaitReset(t *testing.T) protocol.StreamResetCode {
	t.Helper()
	select {
	case code := <-self.resetCodes:
		return code
	case <-time.After(tlsSuiteGuard):
		t.Fatal("the edge never reset its stream")
	}
	return protocol.StreamResetCode_RST_UNSPECIFIED
}

// tlsedge's end.
type tlsSuiteEdgeEnd struct {
	stream *tlsSuiteStream
}

var _ tlsedgeservice.TlsEdgeStream = (*tlsSuiteEdgeEnd)(nil)

func (self *tlsSuiteEdgeEnd) Read(b []byte) (int, error) {
	n, err := self.stream.fromListener.read(b)
	self.stream.stateLock.Lock()
	self.stream.edgeRead.Write(b[:n])
	self.stream.stateLock.Unlock()
	return n, err
}

func (self *tlsSuiteEdgeEnd) Write(b []byte) (int, error) {
	n, err := self.stream.toListener.write(b)
	if err == nil {
		self.stream.stateLock.Lock()
		self.stream.edgeWrote.Write(b[:n])
		self.stream.stateLock.Unlock()
	}
	return n, err
}

func (self *tlsSuiteEdgeEnd) CloseWrite() error {
	self.stream.toListener.closeWrite()
	return nil
}

func (self *tlsSuiteEdgeEnd) Close() error {
	self.stream.toListener.closeWrite()
	self.stream.fromListener.fail(net.ErrClosed)
	return nil
}

func (self *tlsSuiteEdgeEnd) Reset(code protocol.StreamResetCode) error {
	self.stream.resetOnce.Do(func() {
		self.stream.resetCodes <- code
	})
	err := &sidecar.SocketCodeError{Err: sidecar.ErrSocketReset, ResetCode: code}
	self.stream.toListener.fail(err)
	self.stream.fromListener.fail(err)
	return nil
}

func (self *tlsSuiteEdgeEnd) SetReadDeadline(t time.Time) error  { return nil }
func (self *tlsSuiteEdgeEnd) SetWriteDeadline(t time.Time) error { return nil }

// The listener's end, as a net.Conn a TLS server runs on. Its Close ends its own direction alone: what the edge still
// sends after it is taken and never read, as a stream's StreamClose leaves the peer's bytes to be discarded.
type tlsSuiteListenerEnd struct {
	stream *tlsSuiteStream
}

func (self *tlsSuiteListenerEnd) Read(b []byte) (int, error) { return self.stream.toListener.read(b) }
func (self *tlsSuiteListenerEnd) Write(b []byte) (int, error) {
	return self.stream.fromListener.write(b)
}

func (self *tlsSuiteListenerEnd) Close() error {
	self.stream.fromListener.closeWrite()
	return nil
}

func (self *tlsSuiteListenerEnd) LocalAddr() net.Addr                { return tlsSuiteStreamAddr{} }
func (self *tlsSuiteListenerEnd) RemoteAddr() net.Addr               { return tlsSuiteStreamAddr{} }
func (self *tlsSuiteListenerEnd) SetDeadline(t time.Time) error      { return nil }
func (self *tlsSuiteListenerEnd) SetReadDeadline(t time.Time) error  { return nil }
func (self *tlsSuiteListenerEnd) SetWriteDeadline(t time.Time) error { return nil }

// A stream's address, which names nothing.
type tlsSuiteStreamAddr struct{}

func (tlsSuiteStreamAddr) Network() string { return "ur" }
func (tlsSuiteStreamAddr) String() string  { return "stream" }

// The error a Find's refusal is, as SocketEdgeDialer maps it (socket_errors.go): a code a Find never answers reads as
// denied.
func tlsSuiteFindError(refusal *sidecar.SocketError) error {
	switch refusal.Code {
	case sidecar.SocketErrorCodeNoListener:
		return &sidecar.SocketCodeError{Err: sidecar.ErrSocketNoListener}
	case sidecar.SocketErrorCodeBusy:
		return &sidecar.SocketCodeError{Err: sidecar.ErrSocketBusy}
	case sidecar.SocketErrorCodeQuota:
		return &sidecar.SocketCodeError{Err: sidecar.ErrSocketQuota}
	case sidecar.SocketErrorCodeUnavailable:
		return &sidecar.SocketCodeError{Err: sidecar.ErrSocketUnavailable}
	}
	return &sidecar.SocketCodeError{Err: sidecar.ErrSocketDenied}
}

// tlsedge's dialer in the suite: Find through the sockets engine's own route as the edge's first urnetwork-edge
// platform client, sending the K client ids, then the ticket checked as SocketEdgeDialer checks it (its signature, a
// client this edge holds, the network and the name) and a stream to its listener. The stream is the in-memory pair
// above, standing for SocketEdgeDialer's open over connect.
type tlsSuiteDialer struct {
	world     *tlsSuiteWorld
	clientIds []sidecar.Id
	token     string
	// Dial calls: every Find tlsedge asked for
	dials  atomic.Int64
	opened chan *tlsSuiteStream
}

var _ tlsedgeservice.TlsEdgeDialer = (*tlsSuiteDialer)(nil)

func (self *tlsSuiteDialer) ClientIds() []sidecar.Id {
	return slices.Clone(self.clientIds)
}

// One edge Find of name in networkId offering alpnIds, through the engine's route: its answer, or an error for a call
// that did not answer.
func (self *tlsSuiteDialer) find(ctx context.Context, networkId sidecar.Id, name string, alpnIds []string) (*sidecar.SocketFindResult, error) {
	findNetworkId := connect.Id(networkId)
	clientIds := []*connect.Id{}
	for _, clientId := range self.clientIds {
		id := connect.Id(clientId)
		clientIds = append(clientIds, &id)
	}
	body, err := json.Marshal(&sidecar.SocketFindArgs{
		Name:      name,
		NetworkId: &findNetworkId,
		Protocol:  "tls",
		Alpn:      alpnIds,
		ClientIds: clientIds,
	})
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://sockets.sidecartest.example/socket/find", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+self.token)
	response, err := self.world.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Find answered %d", response.StatusCode)
	}
	result := &sidecar.SocketFindResult{}
	if err := json.NewDecoder(response.Body).Decode(result); err != nil {
		return nil, err
	}
	return result, nil
}

func (self *tlsSuiteDialer) Dial(ctx context.Context, request *tlsedgeservice.TlsEdgeDialRequest) (tlsedgeservice.TlsEdgeStream, error) {
	self.dials.Add(1)
	unavailable := &sidecar.SocketCodeError{Err: sidecar.ErrSocketUnavailable}
	result, err := self.find(ctx, request.Target.NetworkId, request.Target.Name, request.AlpnIds)
	if err != nil {
		return nil, unavailable
	}
	if result.Error != nil {
		return nil, tlsSuiteFindError(result.Error)
	}
	if result.Primary == nil {
		return nil, unavailable
	}
	ticket, err := sidecar.VerifySocketTicket(result.Primary.Ticket, self.world.ticketKeys.VerifyKeys(), uint64(self.world.net.Clock().Now().UnixMilli()))
	if err != nil {
		return nil, unavailable
	}
	dialerClientId, err := sidecar.IdFromBytes(ticket.GetDialerClientId())
	if err != nil || !slices.Contains(self.clientIds, dialerClientId) || !bytes.Equal(ticket.GetNetworkId(), request.Target.NetworkId.Bytes()) ||
		ticket.GetName() != request.Target.Name {
		return nil, unavailable
	}
	metadata, err := request.Metadata(ticket.GetGrantExpireTimeMillis())
	if err != nil {
		return nil, unavailable
	}
	stream := newTlsSuiteStream(ticket, metadata)
	// the hello rides the open, before the accept, as early_data and StreamData do
	end := &tlsSuiteEdgeEnd{stream: stream}
	if _, err := end.Write(request.HelloBytes); err != nil {
		return nil, unavailable
	}
	self.opened <- stream
	return end, nil
}

// Waits for the next stream the edge opened.
func (self *tlsSuiteDialer) awaitOpened(t *testing.T) *tlsSuiteStream {
	t.Helper()
	select {
	case stream := <-self.opened:
		return stream
	case <-time.After(tlsSuiteGuard):
		t.Fatal("the edge opened no stream")
	}
	return nil
}

// A listener reporting port 443, the port tlsedge serves, whatever loopback port it took.
type tlsSuitePortListener struct {
	net.Listener
}

func (self *tlsSuitePortListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
}

// tlsedge's side of one visitor connection, its PROXY header off: what tlsedge read from the visitor and wrote to it.
type tlsSuiteVisitorConn struct {
	*tlsedgeservice.ProxyHeaderConn

	stateLock sync.Mutex
	read      bytes.Buffer
	wrote     bytes.Buffer
}

func (self *tlsSuiteVisitorConn) Read(b []byte) (int, error) {
	n, err := self.ProxyHeaderConn.Read(b)
	self.stateLock.Lock()
	self.read.Write(b[:n])
	self.stateLock.Unlock()
	return n, err
}

func (self *tlsSuiteVisitorConn) Write(b []byte) (int, error) {
	n, err := self.ProxyHeaderConn.Write(b)
	self.stateLock.Lock()
	self.wrote.Write(b[:n])
	self.stateLock.Unlock()
	return n, err
}

// What tlsedge read from the visitor and wrote to it so far.
func (self *tlsSuiteVisitorConn) bytes() ([]byte, []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return bytes.Clone(self.read.Bytes()), bytes.Clone(self.wrote.Bytes())
}

// tlsedge's listener: the host's PROXY listener, each connection it gives kept as tlsedge's side of a visitor.
type tlsSuiteRecordingListener struct {
	net.Listener
	accepted chan *tlsSuiteVisitorConn
}

func (self *tlsSuiteRecordingListener) Accept() (net.Conn, error) {
	conn, err := self.Listener.Accept()
	if err != nil {
		return nil, err
	}
	proxied, ok := conn.(*tlsedgeservice.ProxyHeaderConn)
	if !ok {
		conn.Close()
		return nil, errors.New("a connection without its PROXY header")
	}
	visitorConn := &tlsSuiteVisitorConn{ProxyHeaderConn: proxied}
	select {
	case self.accepted <- visitorConn:
	default:
	}
	return visitorConn, nil
}

// The world with tlsedge in front of its sockets engine.
type tlsSuiteEdge struct {
	*tlsSuiteWorld
	store    *sidecartest.FakeTlsEdgeStore
	service  *tlsedgeservice.TlsEdgeService
	dialer   *tlsSuiteDialer
	label    string
	address  string
	accepted chan *tlsSuiteVisitorConn
}

// The engine's process name on the Net.
const tlsSuiteEdgeEngine = "tlsedge"

// A world whose network publishes tls/443/blog to the public for a day, its listener's lease registered, and tlsedge
// ready in front of it: the network's label in the map, a balance and Community's caps for meter tls, the tlsedge gate
// open to it, and the {tes_*}n family on the host's one subscriber, handing each event to both engines as
// server/cli/tlsedge and server/cli/sockets each do.
func newTlsSuiteEdge(t *testing.T) *tlsSuiteEdge {
	t.Helper()
	world := newTlsSuiteWorld(t)
	edge := &tlsSuiteEdge{
		tlsSuiteWorld: world,
		store:         sidecartest.NewFakeTlsEdgeStore(nil),
		accepted:      make(chan *tlsSuiteVisitorConn, 64),
	}
	label, err := edge.store.AddLabel(tlsSuiteRoot, sidecar.Id(world.networkId))
	if err != nil {
		t.Fatal(err)
	}
	edge.label = label
	fakes := world.net.Fakes()
	fakes.Quota.SetLimits(world.networkId, &sidecar.QuotaLimits{Tier: "free", Limits: map[string]int64{
		"tls_endpoint_concurrent":        256,
		"tls_endpoint_new_per_s":         50,
		"tls_endpoint_mbit_per_s":        20,
		"tls_visitor_concurrent":         64,
		"tls_visitor_new_per_s":          20,
		"tls_visitor_aggregate_multiple": 4,
	}})
	fakes.Quota.SetBalance(world.networkId, 1<<30)
	fakes.Gates.OpenService(sidecar.ServiceGateTlsedge, world.networkId)

	settings := tlsedgeservice.DefaultTlsEdgeSettings()
	settings.Root = tlsSuiteRoot
	settings.Blocks = 1
	now := world.net.Clock().Now()
	edge.dialer = &tlsSuiteDialer{world: world, opened: make(chan *tlsSuiteStream, 64)}
	for range settings.Clients {
		edge.dialer.clientIds = append(edge.dialer.clientIds, sidecar.NewId())
	}
	edge.dialer.token = fakes.Authenticator.Issue(&sidecar.Principal{
		NetworkId: world.edgeNetworkId,
		ClientId:  connect.Id(edge.dialer.clientIds[0]),
		Audience:  socketsservice.SocketsAudience,
		IssuedAt:  now,
		ExpiresAt: now.Add(48 * time.Hour),
	})
	engine, err := world.net.AddEngine(tlsSuiteEdgeEngine, func(ctx context.Context, host *sidecar.ServiceHost) (sidecar.Engine, error) {
		return tlsedgeservice.NewTlsEdgeService(ctx, host, edge.store, edge.dialer, settings)
	})
	if err != nil {
		t.Fatal(err)
	}
	edge.service = engine.(*tlsedgeservice.TlsEdgeService)
	t.Cleanup(edge.service.Close)
	remove, err := fakes.Redis.AddKeyEventCallback(sidecar.TlsKillTriggerKeyPattern, func(event sidecar.RedisKeyEvent) {
		if event.Resync {
			edge.service.KillsResync()
			world.engine.KillsResync()
			return
		}
		if networkId, ok := sidecar.ParseTlsKillTriggerKey(event.Key); ok {
			edge.service.KillChanged(networkId)
			world.engine.KillChanged(connect.Id(networkId))
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remove)
	tlsSuiteAwait(t, "tlsedge's first label map", edge.service.NameLoads, 0)
	tlsSuiteAwait(t, "tlsedge's first kill reload", edge.service.KillLoads, 0)
	if !edge.service.Ready() {
		t.Fatal("tlsedge is not ready")
	}

	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxySettings := tlsedgeservice.DefaultProxyHeaderSettings()
	proxySettings.Clock = world.net.Clock()
	proxyListener, err := tlsedgeservice.NewProxyHeaderListener(world.ctx, &tlsSuitePortListener{Listener: inner}, proxySettings)
	if err != nil {
		inner.Close()
		t.Fatal(err)
	}
	edge.address = inner.Addr().String()
	served := make(chan error, 1)
	go func() {
		served <- edge.service.Serve(&tlsSuiteRecordingListener{Listener: proxyListener, accepted: edge.accepted})
	}()
	t.Cleanup(func() {
		proxyListener.Close()
		<-served
	})

	world.savePublish("public", now.Add(24*time.Hour))
	if status := world.status(world.listener, 1, world.edgeRegistration(world.listener, "tls/443/blog")); status != sidecar.SocketRegistrationStatusOk {
		t.Fatalf("the listener's tls/443/blog answered %s", status)
	}
	return edge
}

// The name a visitor reaches host of the network by.
func (self *tlsSuiteEdge) serverName(host string) string {
	return host + "." + self.label + "." + tlsSuiteRoot
}

// A visitor's TCP connection to tlsedge, its PROXY v1 header naming tlsSuiteVisitor, as the lb's stream server sends.
func (self *tlsSuiteEdge) dialVisitor() net.Conn {
	self.t.Helper()
	conn, err := net.Dial("tcp", self.address)
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(tlsSuiteGuard))
	header := fmt.Sprintf("PROXY TCP4 %s %s %d 443\r\n", tlsSuiteVisitor.Addr(), tlsSuiteLb, tlsSuiteVisitor.Port())
	if _, err := io.WriteString(conn, header); err != nil {
		self.t.Fatal(err)
	}
	return conn
}

// Waits for tlsedge's side of the next visitor connection.
func (self *tlsSuiteEdge) awaitAccepted() *tlsSuiteVisitorConn {
	self.t.Helper()
	select {
	case visitorConn := <-self.accepted:
		return visitorConn
	case <-time.After(tlsSuiteGuard):
		self.t.Fatal("tlsedge accepted no connection")
	}
	return nil
}

// Runs a visitor's handshake for serverName offering alpnIds and trusting roots on its own goroutine, answering its
// connection or the error it ended with.
func (self *tlsSuiteEdge) handshake(serverName string, alpnIds []string, roots *x509.CertPool) chan *tlsSuiteHandshake {
	conn := self.dialVisitor()
	done := make(chan *tlsSuiteHandshake, 1)
	go func() {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: serverName, NextProtos: alpnIds, RootCAs: roots, MinVersion: tls.VersionTLS12})
		err := tlsConn.Handshake()
		done <- &tlsSuiteHandshake{conn: tlsConn, err: err}
	}()
	return done
}

// How a visitor's handshake ended.
type tlsSuiteHandshake struct {
	conn *tls.Conn
	err  error
}

// Waits for a handshake's end.
func (self *tlsSuiteEdge) awaitHandshake(done chan *tlsSuiteHandshake) *tlsSuiteHandshake {
	self.t.Helper()
	select {
	case handshake := <-done:
		return handshake
	case <-time.After(tlsSuiteGuard):
		self.t.Fatal("a visitor's handshake never ended")
	}
	return nil
}

// Waits until tlsedge has run count connections to their end.
func (self *tlsSuiteEdge) awaitEnded(count uint64) {
	self.t.Helper()
	tlsSuiteAwait(self.t, "a connection's end", self.service.ConnectionEnds, count-1)
}

// Kills host of the network until until, zero for until its case lifts it, as POST /tls/suspend's model call does
// (model.SetTlsSuspension): network_tls_suspension's row, then the {tes_} field and its trigger's INCR, whose key
// event reaches both engines through the host's subscriber. Returns once both have taken it in.
func (self *tlsSuiteEdge) kill(host string, until time.Time) {
	self.t.Helper()
	self.store.SetSuspension(&sidecar.TlsSuspendArgs{NetworkId: sidecar.Id(self.networkId), Host: host, Reason: "case", Until: until})
	value, err := json.Marshal(&sidecar.TlsKillEntry{Host: host, Reason: "case", Until: until})
	if err != nil {
		self.t.Fatal(err)
	}
	self.writeKill("tls/443/"+host, true, func(ctx context.Context, redis sidecar.Redis, key string) error {
		return redis.HashSet(ctx, key, map[string][]byte{host: value})
	})
}

// Lifts host's kill: the row, then the field and its trigger.
func (self *tlsSuiteEdge) lift(host string) {
	self.t.Helper()
	self.store.LiftSuspension(sidecar.Id(self.networkId), host)
	self.writeKill("tls/443/"+host, false, func(ctx context.Context, redis sidecar.Redis, key string) error {
		return redis.HashDelete(ctx, key, []string{host})
	})
}

// Writes the network's {tes_} hash with write, INCRs its trigger, and waits until tlsedge's kill set has changed and
// the engine's kills reader has read the hash since the event reached it, which its answer to an edge Find of name,
// denied or not as killed says, shows.
func (self *tlsSuiteEdge) writeKill(name string, killed bool, write func(ctx context.Context, redis sidecar.Redis, key string) error) {
	self.t.Helper()
	redis := self.net.Fakes().Redis
	edgeChanges, _ := self.service.KillChanges()
	engineReads, _ := self.engine.KillReads()
	if err := write(self.ctx, redis, sidecar.TlsKillKey(sidecar.Id(self.networkId))); err != nil {
		self.t.Fatal(err)
	}
	if _, err := redis.Increment(self.ctx, sidecar.TlsKillTriggerKey(sidecar.Id(self.networkId)), 0); err != nil {
		self.t.Fatal(err)
	}
	if err := redis.AwaitKeyEvents(self.ctx); err != nil {
		self.t.Fatal(err)
	}
	tlsSuiteAwait(self.t, "tlsedge's kill change", self.service.KillChanges, edgeChanges)
	// the event came after engineReads was read: the round that reads the hash ends past it, the first to end unless
	// one was under way when it was read, and then the second
	for past := engineReads; ; past += 1 {
		tlsSuiteAwait(self.t, "the engine's kill read", self.engine.KillReads, past)
		if code, _ := self.edgeFind(name); (code == sidecar.SocketErrorCodeDenied) == killed {
			return
		}
		if engineReads < past {
			self.t.Fatalf("the engine's Find of %s answers as before two kill reads after the event", name)
		}
	}
}

// Waits until counts rises past past, failing the test after tlsSuiteGuard of real time.
func tlsSuiteAwait[T int | uint64](t *testing.T, what string, counts func() (T, chan struct{}), past T) {
	t.Helper()
	guard := time.After(tlsSuiteGuard)
	for {
		count, changed := counts()
		if past < count {
			return
		}
		select {
		case <-changed:
		case <-guard:
			t.Fatalf("%s never came", what)
		}
	}
}

// One edge Find of name, as tlsedge's dialer sends it: the refusal's code, or "" with the primary ticket verified.
func (self *tlsSuiteEdge) edgeFind(name string) (sidecar.SocketErrorCode, *protocol.SocketTicket) {
	self.t.Helper()
	result, err := self.dialer.find(self.ctx, sidecar.Id(self.networkId), name, []string{"h2", "http/1.1"})
	if err != nil {
		self.t.Fatal(err)
	}
	if result.Error != nil {
		return result.Error.Code, nil
	}
	ticket, err := sidecar.VerifySocketTicket(result.Primary.Ticket, self.ticketKeys.VerifyKeys(), uint64(self.net.Clock().Now().UnixMilli()))
	if err != nil {
		self.t.Fatalf("an edge Find's ticket: %v", err)
	}
	return "", ticket
}

// certs on Pebble (§22.9's ACME rows on T2), as taskworker runs certs: the engine on a store and a host of its own,
// its clock at the wall's time, since Pebble's certificates are valid from it.
type tlsSuiteCerts struct {
	t       *testing.T
	ctx     context.Context
	pebble  *sidecartest.Pebble
	store   *sidecartest.FakeCertsStore
	service *certsservice.CertsService
}

// How long one order may take against Pebble before the test fails.
const tlsSuiteAcmeTimeout = 2 * time.Minute

func newTlsSuiteCerts(t *testing.T) *tlsSuiteCerts {
	t.Helper()
	pebble := sidecartest.StartPebble(t, nil)
	settings := certsservice.DefaultCertsSettings()
	settings.RootDomain = tlsSuiteRoot
	settings.Cas[certsservice.CertsCaLetsEncrypt].DirectoryUrl = pebble.DirectoryUrl
	settings.Cas[certsservice.CertsCaLetsEncrypt].Profile = sidecartest.PebbleProfileTlsServer
	settings.AcmePollInterval = 50 * time.Millisecond
	settings.AcmeOrderTimeout = tlsSuiteAcmeTimeout
	ctx, cancel := context.WithTimeout(context.Background(), tlsSuiteAcmeTimeout)
	t.Cleanup(cancel)
	clock := sidecartest.NewFakeClock(time.Now().UTC().Truncate(time.Microsecond))
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	sidecartest.RegisterCertsBudgetTwins(host.Redis)
	store := sidecartest.NewFakeCertsStore(host.Redis.Faults())
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	accountKeyDer, err := x509.MarshalPKCS8PrivateKey(accountKey)
	if err != nil {
		t.Fatal(err)
	}
	accountFile := "ca: " + string(certsservice.CertsCaLetsEncrypt) + "\n" +
		"key_create_time: " + time.Now().UTC().Format(time.RFC3339) + "\n" +
		"private_key: |\n"
	for _, line := range strings.Split(strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: accountKeyDer}))), "\n") {
		accountFile += "  " + line + "\n"
	}
	accounts, err := certsservice.NewCertsAccountSet([][]byte{[]byte(accountFile)})
	if err != nil {
		t.Fatal(err)
	}
	acme, err := certsservice.NewCertsAcme(settings, &certsservice.CertsAcmeDeps{
		Accounts:   accounts,
		Dns:        pebble.Dns,
		Clock:      sidecar.RealClock{},
		HttpClient: pebble.HttpClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := certsservice.NewCertsService(ctx, host.ServiceHost(), store, nil, acme, settings)
	if err != nil {
		t.Fatal(err)
	}
	return &tlsSuiteCerts{t: t, ctx: ctx, pebble: pebble, store: store, service: service}
}

// A device's key for the network's set: its own P-256 key, which never leaves it, and the chain certs ordered from
// Pebble for it, as POST /tls/cert-order takes the CSR and the identity key's attestation.
type tlsSuiteDeviceCertificate struct {
	certId      sidecar.Id
	key         *ecdsa.PrivateKey
	chain       [][]byte
	certificate *tls.Certificate
}

// Orders device's certificate for identifierSet on a new key of its own and runs certs' order chain until Pebble has
// issued it.
func (self *tlsSuiteCerts) issue(device *sidecartest.AdmissionDevice, networkId sidecar.Id, clientId sidecar.Id, identifierSet []string) *tlsSuiteDeviceCertificate {
	self.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		self.t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: identifierSet}, key)
	if err != nil {
		self.t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		self.t.Fatal(err)
	}
	spkiSha256 := sha256.Sum256(spki)
	setSha256, err := sidecar.TlsIdentifierSetHash(identifierSet)
	if err != nil {
		self.t.Fatal(err)
	}
	attestation, err := sidecar.SignTlsKeyAttestation(&protocol.TlsKeyAttestation{
		NetworkId:           networkId.Bytes(),
		SidecarId:           device.SidecarId.Bytes(),
		SpkiSha256:          spkiSha256[:],
		IdentifierSetSha256: setSha256[:],
		IssueTimeMillis:     uint64(time.Now().UnixMilli()),
	}, func(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
		return &bridge.Signed{
			Body:      body,
			SignerId:  device.SidecarId.Bytes(),
			Signature: ed25519.Sign(device.Key, bridge.SignedBytes(purpose, signedType, body)),
			Type:      uint32(signedType),
		}, nil
	})
	if err != nil {
		self.t.Fatal(err)
	}
	result, err := self.service.Accept(self.ctx, &certsservice.CertsOrderRequest{
		NetworkId:         networkId,
		ClientId:          clientId,
		SidecarId:         device.SidecarId,
		IdentifierSet:     identifierSet,
		IdentityPublicKey: device.PublicKey(),
		Granted:           true,
		Args:              &sidecar.TlsCertOrderArgs{Csr: csr, Attestation: attestation},
	})
	if err != nil {
		self.t.Fatal(err)
	}
	orders, err := self.service.RunOrders(self.ctx, sidecar.Id{})
	if err != nil || !slices.Contains(orders.Issued, result.CertId) {
		self.t.Fatalf("certs' orders %+v, %v", orders, err)
	}
	row, err := self.store.GetCert(self.ctx, result.CertId)
	if err != nil || row.State != sidecar.TlsCertStateIssued || len(row.Chain) == 0 {
		self.t.Fatalf("the issued row %+v, %v", row, err)
	}
	return &tlsSuiteDeviceCertificate{
		certId:      result.CertId,
		key:         key,
		chain:       row.Chain,
		certificate: &tls.Certificate{Certificate: row.Chain, PrivateKey: key},
	}
}

// What a visitor sends and the listener answers: an HTTP/1.1 request carrying body, and a page carrying page.
func tlsSuiteRequest(serverName string, body string) string {
	return "POST /form HTTP/1.1\r\nHost: " + serverName + "\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
}

func tlsSuitePage(page string) string {
	return "HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(page)) + "\r\nConnection: close\r\n\r\n" + page
}

// Serves one visitor on stream's listener end as the device does: TLS on its own key and chain, then one request
// read and one page written, the request's body handed back on the channel answered.
func tlsSuiteServeDevice(stream *tlsSuiteStream, certificate *tls.Certificate, page string) chan string {
	bodies := make(chan string, 1)
	go func() {
		defer close(bodies)
		conn := tls.Server(&tlsSuiteListenerEnd{stream: stream}, &tls.Config{
			Certificates: []tls.Certificate{*certificate},
			NextProtos:   []string{"http/1.1"},
			MinVersion:   tls.VersionTLS12,
		})
		defer conn.Close()
		request, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return
		}
		if _, err := io.WriteString(conn, tlsSuitePage(page)); err != nil {
			return
		}
		bodies <- string(body)
	}()
	return bodies
}

// Passthrough (X1, R-TLS-4; §22.7's "tlsedge and mxedge splices are byte-identical"): the visitor completes TLS on
// the device's own key, under the chain Pebble issued for the network's set, through tlsedge and the engine's Find;
// tlsedge's side holds the hello and records but neither the request's body nor the page, and what it read from each
// side it wrote to the other, byte for byte. The listener's open names the visitor, the server name, the ticket's
// expiry and a ticket from one of the edge's own clients to this listener.
func TestTlsSuitePassthroughCompletesTlsOnTheDeviceKey(t *testing.T) {
	edge := newTlsSuiteEdge(t)
	certs := newTlsSuiteCerts(t)
	identifierSet, err := sidecar.TlsIdentifierSet(tlsSuiteRoot, edge.label, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	device := certs.issue(edge.listener.device, sidecar.Id(edge.networkId), sidecar.Id(edge.listener.clientId), identifierSet)
	leaf, err := x509.ParseCertificate(device.chain[0])
	if err != nil {
		t.Fatal(err)
	}
	if !device.key.PublicKey.Equal(leaf.PublicKey) {
		t.Fatal("the issued chain is not on the device's key")
	}

	serverName := edge.serverName("blog")
	done := edge.handshake(serverName, []string{"http/1.1"}, certs.pebble.Roots)
	stream := edge.dialer.awaitOpened(t)
	visitorConn := edge.awaitAccepted()
	requestBody := "a form the visitor posts to the device alone"
	page := "a page only the device and the visitor read"
	bodies := tlsSuiteServeDevice(stream, device.certificate, page)
	handshake := edge.awaitHandshake(done)
	if handshake.err != nil {
		t.Fatalf("the visitor's handshake: %v", handshake.err)
	}
	state := handshake.conn.ConnectionState()
	if !state.PeerCertificates[0].PublicKey.(*ecdsa.PublicKey).Equal(&device.key.PublicKey) {
		t.Fatal("the visitor's TLS ended on another key than the device's")
	}
	if _, err := io.WriteString(handshake.conn, tlsSuiteRequest(serverName, requestBody)); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(handshake.conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	read, err := io.ReadAll(response.Body)
	if err != nil || string(read) != page {
		t.Fatalf("the visitor read %q, %v", read, err)
	}
	if body := <-bodies; body != requestBody {
		t.Fatalf("the device read %q", body)
	}
	handshake.conn.Close()
	edge.awaitEnded(1)

	// what tlsedge handled: the hello, then records it never opened
	visitorRead, visitorWrote := visitorConn.bytes()
	streamWrote, streamRead := stream.edgeBytes()
	if !bytes.Equal(visitorRead, streamWrote) {
		t.Fatalf("tlsedge read %d bytes from the visitor and wrote %d to the listener", len(visitorRead), len(streamWrote))
	}
	if !bytes.Equal(streamRead, visitorWrote) {
		t.Fatalf("tlsedge read %d bytes from the listener and wrote %d to the visitor", len(streamRead), len(visitorWrote))
	}
	if len(visitorRead) == 0 || visitorRead[0] != 0x16 || !bytes.Contains(visitorRead, []byte(serverName)) {
		t.Fatal("what tlsedge read does not open with the visitor's hello")
	}
	for _, plain := range []string{requestBody, page, "POST /form", "HTTP/1.1 200 OK"} {
		for _, seen := range [][]byte{visitorRead, visitorWrote} {
			if bytes.Contains(seen, []byte(plain)) {
				t.Fatalf("tlsedge's side of the connection holds %q", plain)
			}
		}
	}

	// the open and ticket the listener got
	open := stream.open(t)
	visitorIp, ok := netip.AddrFromSlice(open.GetClientIp())
	if !ok || visitorIp != tlsSuiteVisitor.Addr() || open.GetClientPort() != uint32(tlsSuiteVisitor.Port()) {
		t.Fatalf("the open names the visitor %v:%d", visitorIp, open.GetClientPort())
	}
	if open.GetServerName() != serverName || open.GetExpireTimeMillis() != stream.ticket.GetGrantExpireTimeMillis() || len(open.GetConnectionId()) != 16 {
		t.Fatalf("the open %+v under a ticket whose grant ends at %d", open, stream.ticket.GetGrantExpireTimeMillis())
	}
	if !bytes.Equal(stream.ticket.GetListenerClientId(), edge.listener.clientId.Bytes()) || stream.ticket.GetName() != "tls/443/blog" {
		t.Fatal("the ticket names another listener or name")
	}
}

// §13.9's kill switch through both engines: a kill of blog, written as POST /tls/suspend writes it, resets the open
// splice with RST_REVOKED and refuses the next visitor with unrecognized_name and no Find, with no more than 5 s of
// the clock gone, and the engine's own Find of the name answers denied; the lift lets the next visitor through to the
// listener again.
func TestTlsSuiteKillSwitchEndsNewAndOpenConnectionsWithinFiveSeconds(t *testing.T) {
	edge := newTlsSuiteEdge(t)
	serverName := edge.serverName("blog")
	done := edge.handshake(serverName, []string{"http/1.1"}, nil)
	open := edge.dialer.awaitOpened(t)
	visitorConn := edge.awaitAccepted()

	killedAt := edge.net.Clock().Now()
	edge.kill("blog", time.Time{})
	if code := open.awaitReset(t); code != protocol.StreamResetCode_RST_REVOKED {
		t.Fatalf("the open splice reset with %s", code)
	}
	if handshake := edge.awaitHandshake(done); handshake.err == nil {
		t.Fatal("a visitor's handshake completed through a killed splice")
	}
	edge.awaitEnded(1)
	if visitorRead, _ := visitorConn.bytes(); !bytes.Contains(visitorRead, []byte(serverName)) {
		t.Fatal("the killed splice never carried the visitor's hello")
	}
	dials := edge.dialer.dials.Load()
	refused := edge.awaitHandshake(edge.handshake(serverName, []string{"http/1.1"}, nil))
	if refused.err == nil || !strings.Contains(refused.err.Error(), "unrecognized name") {
		t.Fatalf("a visitor of a killed host: %v", refused.err)
	}
	if edge.dialer.dials.Load() != dials {
		t.Fatal("tlsedge sent a killed host's visitor to Find")
	}
	if code, _ := edge.edgeFind("tls/443/blog"); code != sidecar.SocketErrorCodeDenied {
		t.Fatalf("the engine's Find of a killed host answered %q", code)
	}
	if elapsed := edge.net.Clock().Now().Sub(killedAt); 5*time.Second < elapsed {
		t.Fatalf("the kill took %v of the clock", elapsed)
	}

	// the lift: the next visitor reaches the listener
	edge.lift("blog")
	if code, _ := edge.edgeFind("tls/443/blog"); code != "" {
		t.Fatalf("the engine's Find of a lifted host answered %q", code)
	}
	edge.handshake(serverName, []string{"http/1.1"}, nil)
	if stream := edge.dialer.awaitOpened(t); stream.ticket.GetName() != "tls/443/blog" {
		t.Fatal("a lifted host's visitor reached another name")
	}
}

// §13.4's route probe through the composed path: a hello offering ur-route-probe, for a published host, gets
// unrecognized_name at once, with no Find, no ticket signed and no record, while a hello without it reaches the
// listener.
func TestTlsSuiteRouteProbeMakesNoFind(t *testing.T) {
	edge := newTlsSuiteEdge(t)
	metrics := edge.net.Fakes().Metrics
	signed := metrics.Value("urnetwork_sockets_find_total", "ok")
	probe := edge.awaitHandshake(edge.handshake(edge.serverName("blog"), []string{"ur-route-probe", "http/1.1"}, nil))
	if probe.err == nil || !strings.Contains(probe.err.Error(), "unrecognized name") {
		t.Fatalf("a route probe: %v", probe.err)
	}
	edge.awaitEnded(1)
	if dials := edge.dialer.dials.Load(); dials != 0 {
		t.Fatalf("a route probe made %d Finds", dials)
	}
	if metrics.Value("urnetwork_sockets_find_total", "ok") != signed {
		t.Fatal("a route probe's hello had a ticket signed")
	}
	edge.service.Close()
	if records := edge.store.Records(); len(records) != 0 {
		t.Fatalf("a route probe left %d records", len(records))
	}
}

// The twin of the probe: the same hello without ur-route-probe reaches the listener through one Find.
func TestTlsSuiteHelloWithoutTheProbeReachesTheListener(t *testing.T) {
	edge := newTlsSuiteEdge(t)
	edge.handshake(edge.serverName("blog"), []string{"http/1.1"}, nil)
	stream := edge.dialer.awaitOpened(t)
	if dials := edge.dialer.dials.Load(); dials != 1 {
		t.Fatalf("one visitor made %d Finds", dials)
	}
	if open := stream.open(t); open.GetServerName() != edge.serverName("blog") || !slices.Equal(open.GetAlpn(), []string{"http/1.1"}) {
		t.Fatalf("the listener's open %+v", open)
	}
}
