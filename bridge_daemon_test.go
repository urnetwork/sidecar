//go:build !js && !ios && !android && !sdk_mobile_bind && !windows && !sidecar_http && !ios_extension

// The daemon's bridge methods and forwards (BRIDGE-M4-20) over a fake backend: its filings are recorded, its
// userspace stack is a dial of a loopback echo server, the fake link, and its grant is what the test sets.

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A backend a test drives.
type testDaemonBridgeBackend struct {
	sidecarId Id
	target    Id
	// where DialForward connects in place of the overlay address: the fake link's far end, by network
	echo map[string]string

	stateLock sync.Mutex
	// what Forward answers next: an approval to wait on, else a filing of grantId
	pending   *Id
	grantId   []byte
	live      bool
	expiresAt time.Time
	// what was asked
	forwards []*BridgeForwardRequest
	origins  []*BridgeFileOrigin
	routes   []*BridgeRouteRequest
	maps     []*BridgeMapRequest
	closed   [][]byte
	egress   []*BridgeEgressRequest
	blocks   []*BridgeBlockRequest
	dialed   []netip.AddrPort
}

var _ DaemonBridgeBackend = (*testDaemonBridgeBackend)(nil)

func (self *testDaemonBridgeBackend) SidecarId() Id {
	return self.sidecarId
}

func (self *testDaemonBridgeBackend) List(ctx context.Context) (*DaemonBridgeList, error) {
	return &DaemonBridgeList{State: "enforcing_document", Block: "100.80.0.0/16", Addresses: []string{"100.80.3.9"}, PinnedCount: 2, UnpinnedCount: 1, Waits: map[string]int{"seal": 1}}, nil
}

func (self *testDaemonBridgeBackend) ResolveSidecar(ctx context.Context, name string) (Id, error) {
	if name != "peer" {
		return Id{}, errors.New("no such sidecar")
	}
	return self.target, nil
}

func (self *testDaemonBridgeBackend) Expose(ctx context.Context, origin *BridgeFileOrigin, request *BridgeRouteRequest) (*BridgeFiling, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.routes = append(self.routes, request)
	return &BridgeFiling{RuleId: []byte{1, 2}}, nil
}

func (self *testDaemonBridgeBackend) ExposeMap(ctx context.Context, origin *BridgeFileOrigin, request *BridgeMapRequest) (*BridgeFiling, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.maps = append(self.maps, request)
	return &BridgeFiling{RuleId: []byte{3, 4}, Address: netip.MustParseAddr("100.80.3.9"), AddressFiled: true}, nil
}

func (self *testDaemonBridgeBackend) Forward(ctx context.Context, origin *BridgeFileOrigin, request *BridgeForwardRequest) (*BridgeFiling, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.forwards = append(self.forwards, request)
	self.origins = append(self.origins, origin)
	if self.pending != nil {
		return nil, &ApprovalPendingError{ApprovalId: *self.pending}
	}
	return &BridgeFiling{GrantId: self.grantId}, nil
}

func (self *testDaemonBridgeBackend) Close(ctx context.Context, origin *BridgeFileOrigin, id []byte, reset bool) (*BridgeFiling, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.closed = append(self.closed, id)
	if bytes.Equal(id, self.grantId) {
		self.live = false
	}
	return &BridgeFiling{GrantId: id}, nil
}

func (self *testDaemonBridgeBackend) SetEgress(ctx context.Context, origin *BridgeFileOrigin, request *BridgeEgressRequest) (*BridgeFiling, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.egress = append(self.egress, request)
	return &BridgeFiling{}, nil
}

func (self *testDaemonBridgeBackend) SetBlock(ctx context.Context, origin *BridgeFileOrigin, request *BridgeBlockRequest) (*bridge.BridgeBlock, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.blocks = append(self.blocks, request)
	return &bridge.BridgeBlock{
		Ipv4Prefix:     &bridge.BridgeIpv4Prefix{Address: 100<<24 | 90<<16, Length: 16},
		PreviousPrefix: &bridge.BridgeIpv4Prefix{Address: 100<<24 | 80<<16, Length: 16},
	}, nil
}

func (self *testDaemonBridgeBackend) ForwardRoute(ctx context.Context, request *BridgeForwardRequest, grantId []byte) (*DaemonBridgeForwardRoute, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return &DaemonBridgeForwardRoute{Address: netip.MustParseAddr("100.80.4.10"), Live: self.live, ExpiresAt: self.expiresAt}, nil
}

func (self *testDaemonBridgeBackend) DialForward(ctx context.Context, network string, address netip.AddrPort) (net.Conn, error) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.dialed = append(self.dialed, address)
	}()
	dialer := &net.Dialer{}
	return dialer.DialContext(ctx, network, self.echo[network])
}

func (self *testDaemonBridgeBackend) set(update func()) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	update()
}

// The fake link's far end: a loopback TCP server and a UDP one, each answering what it reads, until the test ends.
func newTestDaemonBridgeEcho(t *testing.T) map[string]string {
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
	packets, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { packets.Close() })
	go func() {
		buffer := make([]byte, 2048)
		for {
			count, source, err := packets.ReadFrom(buffer)
			if err != nil {
				return
			}
			packets.WriteTo(buffer[:count], source)
		}
	}()
	return map[string]string{"tcp": listener.Addr().String(), "udp": packets.LocalAddr().String()}
}

// The daemon's bridges over a fake backend, a test daemon's local listeners and a clock the test moves.
type testDaemonBridges struct {
	daemon    *Daemon
	bridges   *DaemonBridges
	backend   *testDaemonBridgeBackend
	clock     *testEnvelopeClock
	networkId Id
}

func newTestDaemonBridges(t *testing.T) *testDaemonBridges {
	t.Helper()
	daemon := newDispatchTestDaemon(t)
	clock := newTestEnvelopeClock()
	clock.firesWaits = true
	backend := &testDaemonBridgeBackend{
		sidecarId: NewId(),
		target:    NewId(),
		echo:      newTestDaemonBridgeEcho(t),
		grantId:   []byte{9, 9, 9, 9},
		live:      true,
	}
	bridges, err := NewDaemonBridges(context.Background(), &DaemonBridgesArgs{
		Backend: func(ctx context.Context, networkId Id, running *Sidecar) (DaemonBridgeBackend, error) {
			return backend, nil
		},
		Listen: daemon.LocalListen,
		Clock:  clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bridges.Close)
	return &testDaemonBridges{daemon: daemon, bridges: bridges, backend: backend, clock: clock, networkId: NewId()}
}

// A forward to the peer's port 5000 on a loopback listener, by a confirmed call.
func (self *testDaemonBridges) forward(t *testing.T, protocol string, listen []string) *DaemonBridgeForwardStatus {
	t.Helper()
	reply, err := self.bridges.Forward(context.Background(), self.networkId, nil, &BridgeFileOrigin{Act: SidecarActConfirmed},
		&DaemonBridgeForwardParams{Target: "peer", Port: 5000, Protocol: protocol, Listen: listen})
	if err != nil {
		t.Fatal(err)
	}
	if reply.Forward == nil || reply.ApprovalPendingId != nil {
		t.Fatalf("no forward: %+v", reply)
	}
	return reply.Forward
}

// The default binds every interface and is listed LAN-exposed, in the forward's status and in what ur status prints;
// --listen narrows it to the address named, which is then not exposed (owner decision 84, D-BRIDGE-10).
func TestBridgeForwardBindsAllInterfacesUnlessListenNarrowsIt(t *testing.T) {
	world := newTestDaemonBridges(t)
	wide := world.forward(t, "tcp", nil)
	if !wide.LanExposed || len(wide.LocalAddresses) == 0 || wide.LocalPort == 0 {
		t.Fatalf("the default bind: %+v", wide)
	}
	unspecified := 0
	for _, address := range wide.LocalAddresses {
		bound, err := netip.ParseAddrPort(address)
		if err != nil {
			t.Fatal(err)
		}
		if bound.Addr().IsUnspecified() {
			unspecified += 1
		}
	}
	if unspecified != len(wide.LocalAddresses) {
		t.Fatalf("the default bind is every interface: %v", wide.LocalAddresses)
	}
	narrow := world.forward(t, "tcp", []string{"127.0.0.1"})
	if narrow.LanExposed || len(narrow.LocalAddresses) != 1 || !strings.HasPrefix(narrow.LocalAddresses[0], "127.0.0.1:") {
		t.Fatalf("the narrowed bind: %+v", narrow)
	}
	exposed := 0
	listeners := world.daemon.LocalListeners()
	for _, listener := range listeners {
		if listener.Service != DaemonLocalForward {
			t.Fatalf("a forward's listener is the forward service: %+v", listener)
		}
		if listener.LanExposed {
			exposed += 1
		}
	}
	if len(listeners) != 2 || exposed != 1 {
		t.Fatalf("ur status lists both forwards, one LAN-exposed: %+v", listeners)
	}
	wideUdp := world.forward(t, "udp", nil)
	narrowUdp := world.forward(t, "udp", []string{"127.0.0.1"})
	if !wideUdp.LanExposed || narrowUdp.LanExposed || len(narrowUdp.LocalAddresses) != 1 {
		t.Fatalf("udp binds alike: %+v and %+v", wideUdp, narrowUdp)
	}
	if got := world.bridges.Forwards(world.networkId); len(got) != 4 {
		t.Fatalf("%d forwards listed", len(got))
	}
	if got := world.bridges.Forwards(NewId()); len(got) != 0 {
		t.Fatalf("another network lists %d forwards", len(got))
	}
}

// A TCP forward and a UDP one each carry bytes to the target's port over the fake link and back, dialing the
// target's overlay address at the port asked.
func TestBridgeForwardRoundTripsTcpAndUdp(t *testing.T) {
	world := newTestDaemonBridges(t)
	for _, protocol := range []string{"tcp", "udp"} {
		status := world.forward(t, protocol, []string{"127.0.0.1"})
		conn, err := net.Dial(protocol, status.LocalAddresses[0])
		if err != nil {
			t.Fatal(err)
		}
		message := []byte("over the bridge by " + protocol)
		if _, err := conn.Write(message); err != nil {
			t.Fatal(err)
		}
		answer := make([]byte, len(message))
		if _, err := io.ReadFull(conn, answer); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(answer, message) {
			t.Fatalf("%s answered %q", protocol, answer)
		}
		conn.Close()
		if got, err := world.bridges.ForwardStatus(status.ForwardId); err != nil || got.Protocol != protocol || got.Target != world.backend.target {
			t.Fatalf("the forward's status: %+v, %v", got, err)
		}
	}
	world.backend.set(func() {
		want := netip.MustParseAddrPort("100.80.4.10:5000")
		if len(world.backend.dialed) != 2 || world.backend.dialed[0] != want || world.backend.dialed[1] != want {
			t.Fatalf("dialed %v", world.backend.dialed)
		}
		if len(world.backend.forwards) != 2 || world.backend.forwards[0].Protocol != bridgeProtocolTcp || world.backend.forwards[1].Protocol != bridgeProtocolUdp {
			t.Fatalf("filed %+v", world.backend.forwards)
		}
		if world.backend.forwards[0].Target != world.backend.target || world.backend.forwards[0].Port != 5000 {
			t.Fatalf("filed %+v", world.backend.forwards[0])
		}
	})
}

// A connection through a forward, with one round trip done.
func testDaemonBridgeConn(t *testing.T, status *DaemonBridgeForwardStatus) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", status.LocalAddresses[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if _, err := conn.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	return conn
}

// A forward stops at its grant's expiry on the clock: the connection it carries is reset, the listener is gone and
// the daemon lists it no more. A minute before, it still serves.
func TestBridgeForwardStopsAtItsGrantsExpiry(t *testing.T) {
	world := newTestDaemonBridges(t)
	world.backend.set(func() { world.backend.expiresAt = world.clock.Now().Add(time.Hour) })
	status := world.forward(t, "tcp", []string{"127.0.0.1"})
	if status.ExpiresMs != world.clock.Now().Add(time.Hour).UnixMilli() {
		t.Fatalf("expires %d", status.ExpiresMs)
	}
	world.clock.Advance(59 * time.Minute)
	conn := testDaemonBridgeConn(t, status)
	if len(world.bridges.Forwards(world.networkId)) != 1 {
		t.Fatal("the forward ended before its grant")
	}
	world.clock.Advance(time.Minute)
	// the reset arrives once the forward has closed
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("the connection outlived the grant")
	}
	if len(world.bridges.Forwards(world.networkId)) != 0 || world.bridges.Active() {
		t.Fatal("the forward outlived its grant")
	}
	if late, err := net.Dial("tcp", status.LocalAddresses[0]); err == nil {
		late.Close()
		t.Fatal("the listener outlived the grant")
	}
	if len(world.daemon.LocalListeners()) != 0 {
		t.Fatal("ur status still lists the listener")
	}
	// a grant already past its expiry binds nothing
	world.backend.set(func() { world.backend.expiresAt = world.clock.Now() })
	if _, err := world.bridges.Forward(context.Background(), world.networkId, nil, &BridgeFileOrigin{Act: SidecarActConfirmed},
		&DaemonBridgeForwardParams{Target: "peer", Port: 5000}); !errors.Is(err, ErrDaemonBridgeGrantEnded) {
		t.Fatalf("an expired grant: %v", err)
	}
}

// A GrantRevoke closes the forward's listener: the reread the config's move asks for finds the grant not active.
// bridge.close of the grant's id files the revocation and ends the forwards it admitted; a forward under another
// reread that still finds its grant stays.
func TestBridgeForwardClosesWhenItsGrantIsRevoked(t *testing.T) {
	world := newTestDaemonBridges(t)
	status := world.forward(t, "tcp", []string{"127.0.0.1"})
	conn := testDaemonBridgeConn(t, status)
	world.bridges.GrantsChanged(world.networkId)
	if len(world.bridges.Forwards(world.networkId)) != 1 {
		t.Fatal("a reread that finds the grant closed the forward")
	}
	world.bridges.GrantsChanged(NewId())
	reply, err := world.bridges.CloseId(context.Background(), world.networkId, nil, &BridgeFileOrigin{Act: SidecarActConfirmed},
		&DaemonBridgeCloseParams{Id: "09090909"})
	if err != nil || reply.GrantId != "09090909" || reply.ForwardClosed {
		t.Fatalf("the revocation: %+v, %v", reply, err)
	}
	if len(world.bridges.Forwards(world.networkId)) != 0 {
		t.Fatal("the forward outlived its grant's revocation")
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("the connection outlived the revocation")
	}
	if late, err := net.Dial("tcp", status.LocalAddresses[0]); err == nil {
		late.Close()
		t.Fatal("the listener outlived the revocation")
	}
	// a grant not active binds nothing
	if _, err := world.bridges.Forward(context.Background(), world.networkId, nil, &BridgeFileOrigin{Act: SidecarActConfirmed},
		&DaemonBridgeForwardParams{Target: "peer", Port: 5000}); !errors.Is(err, ErrDaemonBridgeGrantEnded) {
		t.Fatalf("a revoked grant: %v", err)
	}
}

// bridge.close of a forward's own id ends that forward and files nothing: its grant stays.
func TestBridgeCloseEndsAForwardByItsId(t *testing.T) {
	world := newTestDaemonBridges(t)
	first := world.forward(t, "tcp", []string{"127.0.0.1"})
	second := world.forward(t, "tcp", []string{"127.0.0.1"})
	reply, err := world.bridges.CloseId(context.Background(), world.networkId, nil, &BridgeFileOrigin{Act: SidecarActUnconfirmed}, &DaemonBridgeCloseParams{Id: first.ForwardId})
	if err != nil || !reply.ForwardClosed {
		t.Fatalf("%+v, %v", reply, err)
	}
	left := world.bridges.Forwards(world.networkId)
	if len(left) != 1 || left[0].ForwardId != second.ForwardId {
		t.Fatalf("left %+v", left)
	}
	world.backend.set(func() {
		if len(world.backend.closed) != 0 {
			t.Fatal("closing a forward filed a revocation")
		}
	})
	if _, err := world.bridges.CloseId(context.Background(), world.networkId, nil, &BridgeFileOrigin{Act: SidecarActUnconfirmed}, &DaemonBridgeCloseParams{Id: "not hex"}); !errors.Is(err, ErrDaemonBridgeParams) {
		t.Fatalf("a malformed id: %v", err)
	}
	if _, err := world.bridges.ForwardStatus(first.ForwardId); !errors.Is(err, ErrDaemonBridgeNoForward) {
		t.Fatalf("the closed forward's status: %v", err)
	}
}

// A forward whose grant waits for a person's decision answers the approval's id and binds nothing; asked again once
// the decision landed, it binds (§16.6).
func TestBridgeForwardWaitsForADecisionThenProceeds(t *testing.T) {
	world := newTestDaemonBridges(t)
	approvalId := NewId()
	world.backend.set(func() { world.backend.pending = &approvalId })
	params := &DaemonBridgeForwardParams{Target: "peer", Port: 5000, Listen: []string{"127.0.0.1"}}
	reply, err := world.bridges.Forward(context.Background(), world.networkId, nil, &BridgeFileOrigin{Act: SidecarActMcp}, params)
	if err != nil || reply.ApprovalPendingId == nil || *reply.ApprovalPendingId != approvalId || reply.Forward != nil {
		t.Fatalf("a pending grant: %+v, %v", reply, err)
	}
	if world.bridges.Active() || len(world.daemon.LocalListeners()) != 0 {
		t.Fatal("a forward bound before its grant was decided")
	}
	world.backend.set(func() { world.backend.pending = nil })
	reply, err = world.bridges.Forward(context.Background(), world.networkId, nil, &BridgeFileOrigin{Act: SidecarActMcp}, params)
	if err != nil || reply.ApprovalPendingId != nil || reply.Forward == nil || reply.GrantId != "09090909" {
		t.Fatalf("after the decision: %+v, %v", reply, err)
	}
	world.backend.set(func() {
		if len(world.backend.origins) != 2 || world.backend.origins[1].Act != SidecarActMcp {
			t.Fatalf("the origin: %+v", world.backend.origins)
		}
	})
}

// The daemon holds ForwardMaxCount forwards and refuses the next, naming the limit; a call it cannot take is refused
// before anything is filed.
func TestBridgeForwardRefusesPastItsLimitAndMalformedCalls(t *testing.T) {
	world := newTestDaemonBridges(t)
	world.bridges.settings = DefaultDaemonBridgeSettings()
	world.bridges.settings.ForwardMaxCount = 1
	world.forward(t, "tcp", []string{"127.0.0.1"})
	origin := &BridgeFileOrigin{Act: SidecarActConfirmed}
	if _, err := world.bridges.Forward(context.Background(), world.networkId, nil, origin, &DaemonBridgeForwardParams{Target: "peer", Port: 5000}); !errors.Is(err, ErrDaemonBridgeForwardLimit) {
		t.Fatalf("past the limit: %v", err)
	}
	world.bridges.settings.ForwardMaxCount = 8
	filed := 0
	world.backend.set(func() { filed = len(world.backend.forwards) })
	for name, params := range map[string]*DaemonBridgeForwardParams{
		"no port":         {Target: "peer"},
		"a port past 16b": {Target: "peer", Port: 65536},
		"no target":       {Port: 5000},
		"a protocol":      {Target: "peer", Port: 5000, Protocol: "icmp"},
		"a listen name":   {Target: "peer", Port: 5000, Listen: []string{"localhost"}},
	} {
		if _, err := world.bridges.Forward(context.Background(), world.networkId, nil, origin, params); !errors.Is(err, ErrDaemonBridgeParams) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := world.bridges.Forward(context.Background(), world.networkId, nil, origin, &DaemonBridgeForwardParams{Target: "stranger", Port: 5000}); err == nil {
		t.Fatal("an unknown target forwarded")
	}
	world.backend.set(func() {
		if len(world.backend.forwards) != filed {
			t.Fatal("a refused call filed a grant")
		}
	})
}

// bridge.egress and bridge.block run only for a person's confirmed control call: the daemon refuses them from mcp and
// hook and from control with no confirmation, before any handler, and the methods refuse any other origin again.
func TestBridgeEgressAndBlockTakeAPersonsConfirmation(t *testing.T) {
	world := newTestDaemonBridges(t)
	confirmNames := []string{}
	for _, method := range world.bridges.Methods() {
		if method.Confirm {
			confirmNames = append(confirmNames, method.Name)
		}
		if !method.Network {
			t.Fatalf("%s acts on no network", method.Name)
		}
		if err := world.daemon.RegisterMethod(method); err != nil {
			t.Fatal(err)
		}
	}
	if fmt.Sprint(confirmNames) != fmt.Sprint([]string{DaemonMethodBridgeEgress, DaemonMethodBridgeBlock}) {
		t.Fatalf("the Confirm methods: %v", confirmNames)
	}
	for _, name := range confirmNames {
		for _, attempt := range []struct {
			mode      string
			confirmed bool
		}{{mode: DaemonModeMcp, confirmed: true}, {mode: DaemonModeHook, confirmed: true}, {mode: DaemonModeMcp, confirmed: false}, {mode: DaemonModeControl, confirmed: false}} {
			line := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"ur_confirmed":%t,"params":{"mode":"none","block":"cycle"}}`, name, attempt.confirmed)
			response := dispatchTest(world.daemon, attempt.mode, line)
			if response.Error == nil || response.Error.Code != DaemonRpcConfirmationRequired {
				t.Fatalf("%s from %s, confirmed %t: %+v", name, attempt.mode, attempt.confirmed, response.Error)
			}
		}
	}
	for _, act := range []SidecarActOrigin{SidecarActMcp, SidecarActHook, SidecarActUnconfirmed} {
		origin := &BridgeFileOrigin{Act: act}
		if _, err := world.bridges.Egress(context.Background(), world.networkId, nil, origin, &DaemonBridgeEgressParams{Mode: "none"}); !errors.Is(err, ErrBridgeFileRefused) {
			t.Fatalf("egress as %d: %v", act, err)
		}
		if _, err := world.bridges.Block(context.Background(), world.networkId, nil, origin, &DaemonBridgeBlockParams{Block: "cycle"}); !errors.Is(err, ErrBridgeFileRefused) {
			t.Fatalf("block as %d: %v", act, err)
		}
	}
	world.backend.set(func() {
		if len(world.backend.egress) != 0 || len(world.backend.blocks) != 0 {
			t.Fatal("an unconfirmed call reached the filer")
		}
	})
}

// A confirmed bridge.egress files each of §17.11's forms for this subject, and bridge.block cycle or a /16.
func TestBridgeEgressAndBlockFileEachForm(t *testing.T) {
	world := newTestDaemonBridges(t)
	origin := &BridgeFileOrigin{Act: SidecarActConfirmed}
	tagId := NewId()
	for _, params := range []*DaemonBridgeEgressParams{{Mode: "auto"}, {Mode: "none"}, {Mode: "tag:" + tagId.String()}, {Exits: []string{"peer"}}} {
		if _, err := world.bridges.Egress(context.Background(), world.networkId, nil, origin, params); err != nil {
			t.Fatal(err)
		}
	}
	for name, params := range map[string]*DaemonBridgeEgressParams{
		"no mode":          {},
		"an unknown mode":  {Mode: "fastest"},
		"a mode and exits": {Mode: "auto", Exits: []string{"peer"}},
		"a malformed tag":  {Mode: "tag:x"},
	} {
		if _, err := world.bridges.Egress(context.Background(), world.networkId, nil, origin, params); !errors.Is(err, ErrDaemonBridgeParams) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	reply, err := world.bridges.Block(context.Background(), world.networkId, nil, origin, &DaemonBridgeBlockParams{Block: "cycle"})
	if err != nil || reply.Block != "100.90.0.0/16" || reply.PreviousBlock != "100.80.0.0/16" {
		t.Fatalf("cycle: %+v, %v", reply, err)
	}
	if _, err := world.bridges.Block(context.Background(), world.networkId, nil, origin, &DaemonBridgeBlockParams{Block: "10.20.0.0/16"}); err != nil {
		t.Fatal(err)
	}
	if _, err := world.bridges.Block(context.Background(), world.networkId, nil, origin, &DaemonBridgeBlockParams{Block: "fd00::/16"}); !errors.Is(err, ErrDaemonBridgeParams) {
		t.Fatalf("an ipv6 block: %v", err)
	}
	world.backend.set(func() {
		egress := world.backend.egress
		if len(egress) != 4 {
			t.Fatalf("%d egress filings", len(egress))
		}
		for _, request := range egress {
			if request.Subject != world.backend.sidecarId {
				t.Fatal("an egress spec for another subject")
			}
		}
		if egress[0].Mode != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO || egress[1].Mode != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE {
			t.Fatalf("auto and none: %+v", egress[:2])
		}
		if egress[2].Mode != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS || egress[2].ExitTagId != tagId || len(egress[2].ExitSidecarIds) != 0 {
			t.Fatalf("a tag: %+v", egress[2])
		}
		if egress[3].Mode != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS || len(egress[3].ExitSidecarIds) != 1 || egress[3].ExitSidecarIds[0] != world.backend.target {
			t.Fatalf("exits: %+v", egress[3])
		}
		blocks := world.backend.blocks
		if len(blocks) != 2 || !blocks[0].Cycle || blocks[1].Cycle || blocks[1].Prefix != netip.MustParsePrefix("10.20.0.0/16") {
			t.Fatalf("blocks: %+v", blocks)
		}
	})
}

// bridge.expose files a route of subnets or an exit, or a map of a port, and refuses a call that mixes them.
func TestBridgeExposeFilesARouteOrAMap(t *testing.T) {
	world := newTestDaemonBridges(t)
	origin := &BridgeFileOrigin{Act: SidecarActUnconfirmed}
	reply, err := world.bridges.Expose(context.Background(), world.networkId, nil, origin, &DaemonBridgeExposeParams{Prefixes: []string{"10.1.2.3/24", "192.168.0.0/16"}})
	if err != nil || reply.RuleId != "0102" {
		t.Fatalf("a route: %+v, %v", reply, err)
	}
	if _, err := world.bridges.Expose(context.Background(), world.networkId, nil, origin, &DaemonBridgeExposeParams{Exit: true}); err != nil {
		t.Fatal(err)
	}
	reply, err = world.bridges.Expose(context.Background(), world.networkId, nil, origin, &DaemonBridgeExposeParams{Port: 5432, Target: "10.0.0.7", TargetPort: 15432})
	if err != nil || reply.RuleId != "0304" || reply.Address != "100.80.3.9" || !reply.AddressFiled {
		t.Fatalf("a map: %+v, %v", reply, err)
	}
	if _, err := world.bridges.Expose(context.Background(), world.networkId, nil, origin, &DaemonBridgeExposeParams{Port: 53, Protocol: "udp"}); err != nil {
		t.Fatal(err)
	}
	for name, params := range map[string]*DaemonBridgeExposeParams{
		"nothing":             {},
		"a port and subnets":  {Port: 80, Prefixes: []string{"10.0.0.0/8"}},
		"an exit and subnets": {Exit: true, Prefixes: []string{"10.0.0.0/8"}},
		"an ipv6 subnet":      {Prefixes: []string{"fd00::/8"}},
		"a route's target":    {Prefixes: []string{"10.0.0.0/8"}, Target: "10.0.0.1"},
		"a map's name":        {Port: 80, Target: "localhost"},
		"a map's protocol":    {Port: 80, Protocol: "sctp"},
	} {
		if _, err := world.bridges.Expose(context.Background(), world.networkId, nil, origin, params); !errors.Is(err, ErrDaemonBridgeParams) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	world.backend.set(func() {
		routes, maps := world.backend.routes, world.backend.maps
		if len(routes) != 2 || len(routes[0].Prefixes) != 2 || routes[0].Prefixes[0] != netip.MustParsePrefix("10.1.2.0/24") || routes[0].Exit || !routes[1].Exit {
			t.Fatalf("routes: %+v", routes)
		}
		if len(maps) != 2 || maps[0].Protocol != bridgeProtocolTcp || maps[0].FirstPort != 5432 || maps[0].Target != netip.MustParseAddr("10.0.0.7") || maps[0].TargetPort != 15432 {
			t.Fatalf("maps: %+v", maps)
		}
		if maps[1].Protocol != bridgeProtocolUdp || maps[1].Target.IsValid() {
			t.Fatalf("a udp map: %+v", maps[1])
		}
	})
}

// A network with no backend answers that no bridge runs for it, on every method.
func TestBridgeMethodsRefuseANetworkWithNoBackend(t *testing.T) {
	bridges, err := NewDaemonBridges(context.Background(), &DaemonBridgesArgs{
		Backend: func(ctx context.Context, networkId Id, running *Sidecar) (DaemonBridgeBackend, error) {
			return nil, nil
		},
		Listen: DaemonLocalListen,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bridges.Close()
	origin := &BridgeFileOrigin{Act: SidecarActConfirmed}
	networkId := NewId()
	ctx := context.Background()
	_, statusErr := bridges.Status(ctx, networkId, nil)
	_, exposeErr := bridges.Expose(ctx, networkId, nil, origin, &DaemonBridgeExposeParams{Exit: true})
	_, forwardErr := bridges.Forward(ctx, networkId, nil, origin, &DaemonBridgeForwardParams{Target: "peer", Port: 1})
	_, closeErr := bridges.CloseId(ctx, networkId, nil, origin, &DaemonBridgeCloseParams{Id: "0a"})
	_, egressErr := bridges.Egress(ctx, networkId, nil, origin, &DaemonBridgeEgressParams{Mode: "none"})
	_, blockErr := bridges.Block(ctx, networkId, nil, origin, &DaemonBridgeBlockParams{Block: "cycle"})
	for name, err := range map[string]error{"status": statusErr, "expose": exposeErr, "forward": forwardErr, "close": closeErr, "egress": egressErr, "block": blockErr} {
		if !errors.Is(err, ErrDaemonBridgeUnwired) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := NewDaemonBridges(ctx, &DaemonBridgesArgs{}); err == nil {
		t.Fatal("bridges with no backend")
	}
}

// Whether a reply type can carry key bytes: any []byte, at any depth.
func testDaemonBridgeHoldsBytes(valueType reflect.Type, seen map[reflect.Type]bool) bool {
	if seen[valueType] {
		return false
	}
	seen[valueType] = true
	switch valueType.Kind() {
	case reflect.Pointer, reflect.Map:
		return testDaemonBridgeHoldsBytes(valueType.Elem(), seen)
	case reflect.Slice:
		return valueType.Elem().Kind() == reflect.Uint8 || testDaemonBridgeHoldsBytes(valueType.Elem(), seen)
	case reflect.Struct:
		for i := range valueType.NumField() {
			if testDaemonBridgeHoldsBytes(valueType.Field(i).Type, seen) {
				return true
			}
		}
	}
	return false
}

// The bridge's replies hold no secret (I-13, TestRepliesHoldNoSecret's rule): each passes the daemon's reply walk, the
// status matches the listing the backend gave, and no reply type has a field that could carry key bytes, ids being
// hex text or an Id.
func TestBridgeRepliesHoldNoSecret(t *testing.T) {
	world := newTestDaemonBridges(t)
	forward := world.forward(t, "tcp", []string{"127.0.0.1"})
	status, err := world.bridges.Status(context.Background(), world.networkId, nil)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := world.backend.List(context.Background())
	if !reflect.DeepEqual(status.List, want) || len(status.Forwards) != 1 || status.Forwards[0].ForwardId != forward.ForwardId {
		t.Fatalf("the status: %+v", status)
	}
	approvalId := NewId()
	replies := map[string]any{
		"status": status,
		"filing": &DaemonBridgeFilingReply{ApprovalPendingId: &approvalId, RuleId: "0102", GrantId: "0304", ApprovalId: &approvalId, Address: "100.80.3.9", Forward: forward, Block: "100.90.0.0/16"},
	}
	for name, reply := range replies {
		reply := reply
		if err := world.daemon.RegisterMethod(&DaemonMethod{Name: "synthetic.bridge." + name, Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
			return reply, nil
		}}); err != nil {
			t.Fatal(err)
		}
		response := dispatchTest(world.daemon, DaemonModeMcp, fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"synthetic.bridge.%s"}`, name))
		if response.Error != nil || len(response.Result) == 0 {
			t.Fatalf("%s did not pass the reply walk: %+v", name, response.Error)
		}
		encoded, err := json.Marshal(reply)
		if err != nil || !json.Valid(response.Result) || len(encoded) == 0 {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for _, reply := range []any{DaemonBridgeStatusReply{}, DaemonBridgeFilingReply{}, DaemonBridgeForwardStatus{}, DaemonBridgeList{}} {
		if testDaemonBridgeHoldsBytes(reflect.TypeOf(reply), map[reflect.Type]bool{}) {
			t.Fatalf("%T can carry key bytes", reply)
		}
	}
}
