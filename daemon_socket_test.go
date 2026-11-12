//go:build !js && !ios && !android && !sdk_mobile_bind && !windows && !sidecar_http && !ios_extension

// The daemon's sockets (SOCK-M5-14) through a real daemon and its control and socket sessions, on an in-memory socket
// network that stands for each Sidecar's sockets component: a listen forward splices to its local target and serving
// follows the target; a dial forward and the socket mode reach a listener through the network; the socket mode carries
// an ssh-like exchange with each half closed alone; ur socket ls shows unsealed names and drops seals that do not
// open; a pending approval names its id; drain drains; a forward keeps the daemon up.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// An in-memory network of sockets: each name's listener takes the dials made to it, over pipes, and each listener-side
// conn keeps the sidecar that dialed it, as admission's verified Hello does.
type testSocketNet struct {
	stateLock sync.Mutex
	listeners map[string]*testSocketListener
	sidecars  map[*SocketConn]Id
}

func newTestSocketNet() *testSocketNet {
	return &testSocketNet{listeners: map[string]*testSocketListener{}, sidecars: map[*SocketConn]Id{}}
}

// The sidecar that dialed a listener-side conn, as socketConnDialerSidecarId reads a Hello.
func (self *testSocketNet) dialerSidecarId(conn *SocketConn) (Id, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	sidecarId, ok := self.sidecars[conn]
	return sidecarId, ok
}

// One listener on the network: its accepted conns, and what the daemon set on it.
type testSocketListener struct {
	net      *testSocketNet
	name     string
	accepted chan *SocketConn
	closed   chan struct{}
	once     sync.Once
	serving  chan bool
	drains   chan struct{}
}

func (self *testSocketListener) AcceptSocket(ctx context.Context) (*SocketConn, error) {
	select {
	case conn := <-self.accepted:
		return conn, nil
	case <-self.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (self *testSocketListener) SetServing(serving bool) {
	self.serving <- serving
}

func (self *testSocketListener) Drain(ctx context.Context) error {
	self.drains <- struct{}{}
	return self.Close()
}

func (self *testSocketListener) Close() error {
	self.once.Do(func() {
		close(self.closed)
		self.net.stateLock.Lock()
		defer self.net.stateLock.Unlock()
		if self.net.listeners[self.name] == self {
			delete(self.net.listeners, self.name)
		}
	})
	return nil
}

func (self *testSocketListener) inflightCount() int {
	return 0
}

// Hands conn to the listener's accept, false once it closed.
func (self *testSocketListener) deliver(conn *SocketConn) bool {
	select {
	case self.accepted <- conn:
		return true
	case <-self.closed:
		return false
	}
}

// A network's backend for one hosted network: listens and dials on the network, and what a listing pages.
type testSocketBackend struct {
	net           *testSocketNet
	settingsValue *SidecarSocketSettings
	ring          *SocketKeyRing
	labelValue    string
	sidecar       *Id
	store         SidecarStore

	stateLock sync.Mutex
	pages     map[string]*SocketListResult
	listenErr error
	dialErr   error
	// each dial's name and the listener sidecar it held to
	dialed []testSocketDialed
}

type testSocketDialed struct {
	name              string
	listenerSidecarId *Id
}

func newTestSocketBackend(network *testSocketNet) *testSocketBackend {
	sidecarId := testSocketId("daemon sidecar")
	return &testSocketBackend{
		net:           network,
		settingsValue: DefaultSidecarSocketSettings(),
		labelValue:    "abcdefghij",
		sidecar:       &sidecarId,
		pages:         map[string]*SocketListResult{},
	}
}

func (self *testSocketBackend) listen(ctx context.Context, address *SocketAddress, settings *SocketListenSettings, share bool) (daemonSocketListener, error) {
	self.stateLock.Lock()
	listenErr := self.listenErr
	self.stateLock.Unlock()
	if listenErr != nil {
		return nil, listenErr
	}
	_, namespace, err := ParseSocketName(address.Name)
	if err != nil || (namespace == SocketNamespaceShare) != share {
		return nil, &SocketCodeError{Err: ErrSocketDenied}
	}
	return self.net.listen(address.Name)
}

// A listener on name, refused when one holds it, as an exclusive group refuses a second.
func (self *testSocketNet) listen(name string) (*testSocketListener, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.listeners[name] != nil {
		return nil, errSocketNameTaken
	}
	listener := &testSocketListener{
		net:      self,
		name:     name,
		accepted: make(chan *SocketConn),
		closed:   make(chan struct{}),
		serving:  make(chan bool, 16),
		drains:   make(chan struct{}, 4),
	}
	self.listeners[name] = listener
	return listener, nil
}

// A dial of name: a pipe whose far end name's listener accepts.
func (self *testSocketNet) dial(name string) (*SocketConn, error) {
	return self.dialAs(name, testSocketId("a dialer"))
}

// A dial of name by sidecarId's sidecar.
func (self *testSocketNet) dialAs(name string, sidecarId Id) (*SocketConn, error) {
	conn, _, err := self.dialServed(name, sidecarId)
	return conn, err
}

// dialAs's dial, with a channel closed once the listener's side closes its conn: what a server does last, past
// whatever it does after the dialer's half has ended, so a test waits on it to read that work's result.
func (self *testSocketNet) dialServed(name string, sidecarId Id) (*SocketConn, <-chan struct{}, error) {
	self.stateLock.Lock()
	listener := self.listeners[name]
	self.stateLock.Unlock()
	if listener == nil {
		return nil, nil, &SocketCodeError{Err: ErrSocketNoListener}
	}
	dialerEnd, listenerEnd := newSocketStreamPipe(64 * 1024)
	served := &testSocketServedStream{socketStream: listenerEnd, served: make(chan struct{})}
	listenerConn := newSocketConn(served, &SocketAddr{}, &SocketAddr{}, nil, nil)
	self.stateLock.Lock()
	self.sidecars[listenerConn] = sidecarId
	self.stateLock.Unlock()
	if !listener.deliver(listenerConn) {
		return nil, nil, &SocketCodeError{Err: ErrSocketNoListener}
	}
	return newSocketConn(dialerEnd, &SocketAddr{}, &SocketAddr{}, nil, nil), served.served, nil
}

// A listener's end of a test dial that closes served at its first Close.
type testSocketServedStream struct {
	socketStream
	once   sync.Once
	served chan struct{}
}

func (self *testSocketServedStream) Close() error {
	defer self.once.Do(func() { close(self.served) })
	return self.socketStream.Close()
}

// Whether a listener holds name now.
func (self *testSocketNet) listening(name string) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.listeners[name] != nil
}

func (self *testSocketBackend) dial(ctx context.Context, address *SocketAddress, listenerSidecarId *Id) (*SocketConn, error) {
	self.stateLock.Lock()
	self.dialed = append(self.dialed, testSocketDialed{name: address.Name, listenerSidecarId: listenerSidecarId})
	dialErr := self.dialErr
	self.stateLock.Unlock()
	if dialErr != nil {
		return nil, dialErr
	}
	return self.net.dialAs(address.Name, *self.sidecar)
}

func (self *testSocketBackend) listPage(ctx context.Context, cursor string) (*SocketListResult, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	page := self.pages[cursor]
	if page == nil {
		return nil, &SocketCodeError{Err: ErrSocketUnavailable}
	}
	return page, nil
}

func (self *testSocketBackend) keyRing() *SocketKeyRing {
	return self.ring
}

func (self *testSocketBackend) label() string {
	return self.labelValue
}

func (self *testSocketBackend) sidecarId() *Id {
	return self.sidecar
}

func (self *testSocketBackend) localStore() SidecarStore {
	if self.store == nil {
		return &sealedStore{}
	}
	return self.store
}

func (self *testSocketBackend) settings() *SidecarSocketSettings {
	return self.settingsValue
}

// The names dialed so far.
func (self *testSocketBackend) dialedNames() []testSocketDialed {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]testSocketDialed{}, self.dialed...)
}

// A daemon hosting one network on the in-memory socket network, its socket methods registered, on an armed clock.
type testDaemonSockets struct {
	started *testDaemon
	clock   *testArmedClock
	net     *testSocketNet
	backend *testSocketBackend
	control *DaemonClient
}

func newTestDaemonSockets(t *testing.T) *testDaemonSockets {
	t.Helper()
	clock := newTestArmedClock()
	started := startTestDaemon(t, func(settings *DaemonSettings) {
		settings.Clock = clock
	})
	network := newTestSocketNet()
	backend := newTestSocketBackend(network)
	if err := started.daemon.AddSidecar(testRegistrarNetworkId, &Sidecar{}); err != nil {
		t.Fatal(err)
	}
	sockets := started.daemon.Sockets()
	sockets.backends = func(networkId Id) (daemonSocketBackend, error) {
		if networkId != testRegistrarNetworkId {
			return nil, &DaemonNetworkError{Reason: "unknown"}
		}
		return backend, nil
	}
	for _, method := range sockets.Methods() {
		if err := started.daemon.RegisterMethod(method); err != nil {
			t.Fatal(err)
		}
	}
	return &testDaemonSockets{started: started, clock: clock, net: network, backend: backend, control: dialTestDaemon(t, started, DaemonModeControl)}
}

// A control call, failing the test on its error.
func (self *testDaemonSockets) call(t *testing.T, method string, params any, result any) {
	t.Helper()
	if err := self.control.Call(context.Background(), method, params, false, result); err != nil {
		t.Fatalf("%s: %v", method, err)
	}
}

// A socket session dialing address, past its status line, or the status line's error.
func (self *testDaemonSockets) session(t *testing.T, address string, sidecarId *Id) (*DaemonClient, error) {
	t.Helper()
	client, err := DialDaemon(context.Background(), self.started.socketPath, &DaemonHello{
		Mode: DaemonModeSocket, Version: testDaemonVersion, Socket: address, SocketSidecarId: sidecarId,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client, ReadDaemonSocketSessionAnswer(client.Stream(), 16*1024)
}

// A TCP server on 127.0.0.1 that echoes each conn until its FIN, then closes it.
func startTestEchoTarget(t *testing.T) (net.Listener, int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return listener, listener.Addr().(*net.TCPAddr).Port
}

// A port on 127.0.0.1 that nothing listens on now.
func testRefusingPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}

// The listener the network holds on name, waiting until a listen makes one.
func (self *testDaemonSockets) listenerOn(t *testing.T, name string) *testSocketListener {
	t.Helper()
	self.net.stateLock.Lock()
	defer self.net.stateLock.Unlock()
	listener := self.net.listeners[name]
	if listener == nil {
		t.Fatalf("no listener on %s", name)
	}
	return listener
}

// Writes text and reads the same bytes back.
func testSocketRoundTrip(t *testing.T, stream io.ReadWriter, text string) {
	t.Helper()
	if _, err := stream.Write([]byte(text)); err != nil {
		t.Fatal(err)
	}
	back := make([]byte, len(text))
	if _, err := io.ReadFull(stream, back); err != nil || string(back) != text {
		t.Fatalf("read back %q, %v", back, err)
	}
}

// A listen forward splices each admitted conn to its target, and a socket session reaches it through the network,
// each half's FIN arriving as io.EOF.
func TestSocketListenForwardsToTarget(t *testing.T) {
	fixture := newTestDaemonSockets(t)
	_, port := startTestEchoTarget(t)
	reply := &DaemonSocketListenReply{}
	fixture.call(t, DaemonMethodSocketListen, &DaemonSocketListenParams{Address: "DB/Primary", Target: strconv.Itoa(port)}, reply)
	if reply.Status == nil || reply.Status.Name != "db/primary" || reply.Status.Target != "127.0.0.1:"+strconv.Itoa(port) ||
		!reply.Status.Serving || reply.Status.Kind != DaemonSocketKindListen || reply.ApprovalId != nil {
		t.Fatalf("reply %+v", reply.Status)
	}
	client, err := fixture.session(t, "db/primary", nil)
	if err != nil {
		t.Fatal(err)
	}
	stream := client.Stream()
	testSocketRoundTrip(t, stream, "through the daemon and back")
	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	// the target saw the FIN, closed, and its FIN came back through the forward
	if rest, err := io.ReadAll(stream); err != nil || len(rest) != 0 {
		t.Fatalf("after the FIN: %q, %v", rest, err)
	}

	local := &DaemonSocketLocalReply{}
	fixture.call(t, DaemonMethodSocketLocal, nil, local)
	if len(local.Sockets) != 1 || local.Sockets[0].Name != "db/primary" || local.Sockets[0].NetworkId != testRegistrarNetworkId {
		t.Errorf("local %+v", local.Sockets)
	}
	second := &DaemonSocketListenReply{}
	err = fixture.control.Call(context.Background(), DaemonMethodSocketListen, &DaemonSocketListenParams{Address: "db/primary", Target: strconv.Itoa(port)}, false, second)
	if err == nil || !strings.Contains(err.Error(), ErrDaemonSocketListening.Error()) {
		t.Errorf("a second listen on the name: %v", err)
	}
}

// serving follows the local target: a target that refuses at the listen turns serving off, a conn admitted meanwhile is
// reset, and once the target answers a probe serving turns on again.
func TestSocketServingFollowsTarget(t *testing.T) {
	fixture := newTestDaemonSockets(t)
	port := testRefusingPort(t)
	reply := &DaemonSocketListenReply{}
	fixture.call(t, DaemonMethodSocketListen, &DaemonSocketListenParams{Address: "db/primary", Target: "127.0.0.1:" + strconv.Itoa(port)}, reply)
	if reply.Status == nil || reply.Status.Serving {
		t.Fatalf("a refusing target's status %+v", reply.Status)
	}
	listener := fixture.listenerOn(t, "db/primary")
	if serving := testSocketAwait(t, listener.serving, "serving set"); serving {
		t.Fatal("serving stayed on")
	}
	fixture.clock.awaitArmed(t, fixture.backend.settingsValue.Forward.TargetProbeInterval)

	// a ticket issued before the service saw serving off still arrives, and the refusing target resets it
	conn, err := fixture.net.dial("db/primary")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, ErrSocketReset) {
		t.Errorf("a conn to a refusing target: %v", err)
	}

	target, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Skipf("the port was taken meanwhile: %v", err)
	}
	defer target.Close()
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	fixture.clock.advance(fixture.backend.settingsValue.Forward.TargetProbeInterval)
	if serving := testSocketAwait(t, listener.serving, "serving set again"); !serving {
		t.Fatal("serving stayed off once the target answered")
	}
	local := &DaemonSocketLocalReply{}
	fixture.call(t, DaemonMethodSocketLocal, nil, local)
	if len(local.Sockets) != 1 || !local.Sockets[0].Serving {
		t.Errorf("local %+v", local.Sockets)
	}
}

// A dial forward listens on a local port with no TLS-only rule, shows in ur status's listeners, and splices each local
// conn to a fresh dial through the network to the listen forward and its target.
func TestSocketDialForwardReachesListener(t *testing.T) {
	fixture := newTestDaemonSockets(t)
	_, port := startTestEchoTarget(t)
	fixture.call(t, DaemonMethodSocketListen, &DaemonSocketListenParams{Address: "db/primary", Target: strconv.Itoa(port)}, &DaemonSocketListenReply{})
	status := &DaemonSocketStatus{}
	fixture.call(t, DaemonMethodSocketDial, &DaemonSocketDialParams{Address: "db/primary", Listen: "127.0.0.1:0"}, status)
	if status.Kind != DaemonSocketKindDial || len(status.LocalAddresses) != 1 || status.LanExposed {
		t.Fatalf("status %+v", status)
	}
	listeners := fixture.started.daemon.LocalListeners()
	if len(listeners) != 1 || listeners[0].Service != DaemonLocalForward || listeners[0].LanExposed {
		t.Errorf("ur status's listeners %+v", listeners)
	}
	local, err := net.Dial("tcp", status.LocalAddresses[0])
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	testSocketRoundTrip(t, local, "a local conn through the dial forward")
	local.(*net.TCPConn).CloseWrite()
	if rest, err := io.ReadAll(local); err != nil || len(rest) != 0 {
		t.Fatalf("after the FIN: %q, %v", rest, err)
	}
	if dialed := fixture.backend.dialedNames(); len(dialed) != 1 || dialed[0].name != "db/primary" || dialed[0].listenerSidecarId != nil {
		t.Errorf("dialed %+v", dialed)
	}

	// a drain stops taking local conns and the forward goes once its conns are done
	listener := fixture.listenerOn(t, "db/primary")
	drained := &DaemonSocketDrainReply{}
	fixture.call(t, DaemonMethodSocketDrain, &DaemonSocketDrainParams{Address: "db/primary"}, drained)
	if drained.DrainedCount != 2 {
		t.Errorf("drained %d", drained.DrainedCount)
	}
	testSocketAwait(t, listener.drains, "the listen forward's drain")
	if _, err := net.Dial("tcp", status.LocalAddresses[0]); err == nil {
		t.Error("the drained dial forward still takes conns")
	}
}

// The socket mode carries an ssh-like exchange: banners each way, binary packets, then the client's FIN reaching the
// listener as io.EOF while the listener's last packet still reaches the client, then its FIN.
func TestSocketSessionRelaysSshExchange(t *testing.T) {
	fixture := newTestDaemonSockets(t)
	remote, err := fixture.net.listen("ssh/host")
	if err != nil {
		t.Fatal(err)
	}
	packets := [][]byte{bytes.Repeat([]byte{0x00, 0xff, 0x0a}, 300), {0x0d, 0x0a, 0x00}, bytes.Repeat([]byte("synthetic"), 7000)}
	serverDone := make(chan error, 1)
	go func() {
		conn, err := remote.AcceptSocket(context.Background())
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		banner := make([]byte, len("SSH-2.0-synthetic_client\r\n"))
		if _, err := io.ReadFull(conn, banner); err != nil || string(banner) != "SSH-2.0-synthetic_client\r\n" {
			serverDone <- errors.New("the client's banner")
			return
		}
		conn.Write([]byte("SSH-2.0-synthetic_server\r\n"))
		for _, packet := range packets {
			echo := make([]byte, len(packet))
			if _, err := io.ReadFull(conn, echo); err != nil || !bytes.Equal(echo, packet) {
				serverDone <- errors.New("a packet")
				return
			}
			conn.Write(echo)
		}
		if rest, err := io.ReadAll(conn); err != nil || len(rest) != 0 {
			serverDone <- errors.New("no FIN from the client")
			return
		}
		conn.Write([]byte("last words"))
		serverDone <- nil
	}()

	client, err := fixture.session(t, "ssh/host", nil)
	if err != nil {
		t.Fatal(err)
	}
	stream := client.Stream()
	stream.Write([]byte("SSH-2.0-synthetic_client\r\n"))
	banner := make([]byte, len("SSH-2.0-synthetic_server\r\n"))
	if _, err := io.ReadFull(stream, banner); err != nil || string(banner) != "SSH-2.0-synthetic_server\r\n" {
		t.Fatalf("the server's banner %q, %v", banner, err)
	}
	for _, packet := range packets {
		testSocketRoundTrip(t, stream, string(packet))
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if rest, err := io.ReadAll(stream); err != nil || string(rest) != "last words" {
		t.Fatalf("after the client's FIN: %q, %v", rest, err)
	}
	if err := testSocketAwait(t, serverDone, "the server's end"); err != nil {
		t.Fatal(err)
	}
}

// A refused dial is the session's status line, §9.9's error with its wait, and nothing past it.
func TestSocketSessionRefusalNamesItsCode(t *testing.T) {
	fixture := newTestDaemonSockets(t)
	if _, err := fixture.session(t, "db/primary", nil); !errors.Is(err, ErrSocketNoListener) {
		t.Errorf("no listener: %v", err)
	}
	fixture.backend.stateLock.Lock()
	fixture.backend.dialErr = &SocketCodeError{Err: ErrSocketBusy, RetryAfter: 1500 * time.Millisecond}
	fixture.backend.stateLock.Unlock()
	_, err := fixture.session(t, "db/primary", nil)
	var codeErr *SocketCodeError
	if !errors.Is(err, ErrSocketBusy) || !errors.As(err, &codeErr) || codeErr.RetryAfter != 1500*time.Millisecond {
		t.Errorf("busy: %v", err)
	}
	if _, err := fixture.session(t, "othernetwk:db/primary", nil); err == nil || errors.Is(err, ErrSocketBusy) {
		t.Errorf("a network not hosted: %v", err)
	}
}

// A share/ session holds the dial to the link's sidecar, and the hello refuses a share/ address without one.
func TestSocketSessionHoldsShareDialToSidecar(t *testing.T) {
	fixture := newTestDaemonSockets(t)
	remote, err := fixture.net.listen("share/abcdefghijklmnopqrstuvwxyz")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		if conn, err := remote.AcceptSocket(context.Background()); err == nil {
			conn.Close()
		}
	}()
	sharer := testSocketId("sharer")
	if _, err := fixture.session(t, "share/abcdefghijklmnopqrstuvwxyz", &sharer); err != nil {
		t.Fatal(err)
	}
	dialed := fixture.backend.dialedNames()
	if len(dialed) != 1 || dialed[0].listenerSidecarId == nil || *dialed[0].listenerSidecarId != sharer {
		t.Errorf("dialed %+v", dialed)
	}
	_, err = DialDaemon(context.Background(), fixture.started.socketPath, &DaemonHello{
		Mode: DaemonModeSocket, Version: testDaemonVersion, Socket: "share/abcdefghijklmnopqrstuvwxyz",
	})
	var refusal *DaemonHelloRefusal
	if !errors.As(err, &refusal) || refusal.Code != DaemonHelloErrorMalformed {
		t.Errorf("a share/ session with no sidecar: %v", err)
	}
}

// ur socket ls: edge names as they are, blinded ones as their seals open here, a name on two pages once, and a seal
// under another key, one moved to another token and one cut short dropped and counted, never shown.
func TestSocketListUnsealsAndDropsMismatchedSeals(t *testing.T) {
	fixture := newTestDaemonSockets(t)
	ring := newTestSocketRing(t, "current", "", 0)
	other := newTestSocketRing(t, "another key", "", 0)
	fixture.backend.ring = ring
	sealed := func(keys *SocketKeys, name string) *SocketListName {
		token, err := keys.TokenPath(name)
		if err != nil {
			t.Fatal(err)
		}
		seal, err := keys.Seal(name)
		if err != nil {
			t.Fatal(err)
		}
		return &SocketListName{NameToken: token, SealedName: seal}
	}
	moved := sealed(ring.Current(), "db/primary")
	moved.NameToken = sealed(ring.Current(), "web/front").NameToken
	short := sealed(ring.Current(), "db/replica")
	short.SealedName = short.SealedName[:100]
	fixture.backend.pages[""] = &SocketListResult{
		Names: []*SocketListName{
			{Name: "tls/443/blog"},
			sealed(ring.Current(), "db/primary"),
			sealed(other.Current(), "db/secret"),
			moved,
			short,
		},
		NextCursor: "page-2",
	}
	fixture.backend.pages["page-2"] = &SocketListResult{Names: []*SocketListName{sealed(ring.Current(), "web/front"), sealed(ring.Current(), "db/primary")}}
	_, port := startTestEchoTarget(t)
	fixture.call(t, DaemonMethodSocketListen, &DaemonSocketListenParams{Address: "web/front", Target: strconv.Itoa(port)}, &DaemonSocketListenReply{})

	reply := &DaemonSocketListReply{}
	fixture.call(t, DaemonMethodSocketList, &DaemonSocketListParams{}, reply)
	names := []string{}
	for _, name := range reply.Names {
		names = append(names, name.Name)
		if name.Local != (name.Name == "web/front") {
			t.Errorf("%s local %v", name.Name, name.Local)
		}
	}
	if strings.Join(names, " ") != "db/primary tls/443/blog web/front" || reply.DroppedCount != 3 || !reply.Complete || reply.Error != nil {
		t.Errorf("listing %q, dropped %d, complete %v, %+v", names, reply.DroppedCount, reply.Complete, reply.Error)
	}

	// with no ring installed every seal is dropped, and a refused page stops the listing short
	fixture.backend.ring = nil
	fixture.backend.pages["page-2"] = &SocketListResult{Names: []*SocketListName{}, Error: &SocketError{Code: SocketErrorCodeUnavailable, RetryAfterMs: 20}}
	short2 := &DaemonSocketListReply{}
	fixture.call(t, DaemonMethodSocketList, &DaemonSocketListParams{}, short2)
	if len(short2.Names) != 1 || short2.Names[0].Name != "tls/443/blog" || short2.DroppedCount != 4 || short2.Complete ||
		short2.Error == nil || short2.Error.Code != SocketErrorCodeUnavailable {
		t.Errorf("a short listing %+v", short2)
	}
}

// An outward listen whose gate waits on a person answers the approval's id and holds nothing.
func TestSocketListenPendingApprovalNamesIt(t *testing.T) {
	fixture := newTestDaemonSockets(t)
	approvalId := testSocketId("approval")
	fixture.backend.listenErr = &ApprovalPendingError{ApprovalId: approvalId}
	reply := &DaemonSocketListenReply{}
	fixture.call(t, DaemonMethodSocketListen, &DaemonSocketListenParams{Address: "tls/443/blog", Target: "8443"}, reply)
	if reply.ApprovalId == nil || *reply.ApprovalId != approvalId || reply.Status != nil {
		t.Fatalf("reply %+v", reply)
	}
	local := &DaemonSocketLocalReply{}
	fixture.call(t, DaemonMethodSocketLocal, nil, local)
	if len(local.Sockets) != 0 {
		t.Errorf("a pending listen is held: %+v", local.Sockets)
	}
}

// A forward keeps the daemon up, and an unlisten lets it go; a drain of an address with no forward is refused.
func TestSocketForwardKeepsDaemonUp(t *testing.T) {
	fixture := newTestDaemonSockets(t)
	if fixture.started.daemon.busy() {
		t.Fatal("busy with nothing held")
	}
	_, port := startTestEchoTarget(t)
	fixture.call(t, DaemonMethodSocketListen, &DaemonSocketListenParams{Address: "db/primary", Target: strconv.Itoa(port)}, &DaemonSocketListenReply{})
	if !fixture.started.daemon.busy() {
		t.Error("a listen forward does not keep the daemon up")
	}
	sockets := fixture.started.daemon.Sockets()
	if status, ok := sockets.Status(testRegistrarNetworkId, "db/primary"); !ok || status.Name != "db/primary" {
		t.Errorf("status %+v %v", status, ok)
	}
	if !sockets.Unlisten(testRegistrarNetworkId, "db/primary") || sockets.Unlisten(testRegistrarNetworkId, "db/primary") {
		t.Error("unlisten")
	}
	if fixture.started.daemon.busy() {
		t.Error("busy after the unlisten")
	}
	err := fixture.control.Call(context.Background(), DaemonMethodSocketDrain, &DaemonSocketDrainParams{Address: "db/primary"}, false, &DaemonSocketDrainReply{})
	if err == nil || !strings.Contains(err.Error(), ErrDaemonSocketNone.Error()) {
		t.Errorf("a drain with nothing held: %v", err)
	}
}

// [<ip>:]<port>'s grammar.
func TestSocketTargetGrammar(t *testing.T) {
	cases := []struct {
		text string
		host string
		port int
		ok   bool
	}{
		{text: "8080", port: 8080, ok: true},
		{text: "0", port: 0, ok: true},
		{text: "127.0.0.1:22", host: "127.0.0.1", port: 22, ok: true},
		{text: "[::1]:22", host: "::1", port: 22, ok: true},
		{text: "[::ffff:192.0.2.1]:22", host: "192.0.2.1", port: 22, ok: true},
		{text: "65536"},
		{text: "+22"},
		{text: "-1"},
		{text: ""},
		{text: "host.example:22"},
		{text: "::1:22"},
		{text: "[fe80::1%en0]:22"},
		{text: "127.0.0.1:"},
	}
	for _, c := range cases {
		host, port, err := parseDaemonSocketHostPort(c.text)
		if (err == nil) != c.ok || (c.ok && (host != c.host || port != c.port)) {
			t.Errorf("%q: %q %d %v", c.text, host, port, err)
		}
	}
}
