//go:build !sidecar_http && !ios_extension

// BRIDGE-M6-08's schedules on T2 (fs_bridge_m6.go): FS-38's share rows, under every rule §22.8 gives the case;
// server/controller/connect_bridge_m6_test.go runs the same builders on T3. Beside them, the schedules' actors as a
// failing seed's trace must write them, a failed exchange's report of where its packet stopped, and the host's daemon
// listener kept off its upstream's ports, which rule 0 would otherwise refuse.

package fault

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/sidecartest"
)

func TestFs38Share(t *testing.T) {
	RunRow(t, "FS-38", "shares", nil)
}

// A failing seed of either schedule leaves its trace (§22.8's explorer row), one event a line with its actor as one
// field, so no actor of theirs may hold a space: "Y's ungranted reader" did, and the seed that failed in its step left
// no trace to replay.
func TestFs38ShareActorsFitATrace(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	for _, builder := range []Builder{Fs38ShareRefusals, Fs38ShareSigner} {
		expectActorsFitATrace(t, "FS-38's shares", builder(net))
	}
}

// The share world FS-38's first step builds, failing t if it does not, which t's cleanup closes. bridgeSettings, when
// set, are the Net's (sidecartest.SetNetBridgeSettings), as server's T3 test sets them.
func fs38ShareWorldForTest(t *testing.T, settings *Fs38ShareSettings, bridgeSettings *sidecartest.BridgeNetSettings) *fsShareWorld {
	t.Helper()
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	if bridgeSettings != nil {
		sidecartest.SetNetBridgeSettings(net, bridgeSettings)
		t.Cleanup(func() { sidecartest.SetNetBridgeSettings(net, nil) })
	}
	world := &fsShareWorld{}
	err := fsShareSetup(world, settings).Action(t.Context(), net)
	if world.share != nil {
		t.Cleanup(world.share.Close)
	}
	if err != nil {
		t.Fatalf("the share's world: %v", err)
	}
	return world
}

// The share world waits less than a run's barrier wait, so a wait that fails names itself and what the world saw of
// its flow before the run's own bound fails the step: the share refusals' datagram that never came back said only
// "waited 10s for actor operator to end", from under a world wait of 30 s.
func TestFs38ShareWaitsWithinARunsBound(t *testing.T) {
	settings := DefaultFs38ShareSettings()
	if await := sidecartest.DefaultBarrierDriverSettings().AwaitTimeout; await <= settings.WaitTimeout {
		t.Fatalf("FS-38's share world waits %s, not within a run's barrier wait of %s", settings.WaitTimeout, await)
	}
	world := fs38ShareWorldForTest(t, settings, nil)
	if wait := world.share.X.Settings().WaitTimeout; wait != settings.WaitTimeout {
		t.Fatalf("the share's world waits %s, not FS-38's %s", wait, settings.WaitTimeout)
	}
}

// A datagram the host's NAT holds at its dial goes unanswered, and what the world saw says where it stopped: the host
// mapped the flow and the NAT's dial waits at the gate unconnected, with nothing at the upstream. Once the gate opens,
// the same datagram is answered.
func TestFs38ShareHeldDatagramSaysWhereItStopped(t *testing.T) {
	world := fs38ShareWorldForTest(t, DefaultFs38ShareSettings(), nil)
	err := fsTeamCatch(func() error {
		share := world.share
		window := fsShareWindow(world, "fs38 share held", func() []byte { return share.CurrentCert(7) }, 7)
		defer window.Close()
		flows := &fsShareFlows{world: world, window: window}
		payload := []byte("fs38 share held")
		dialCount := len(share.Host.Dials())
		share.Host.HoldDials()
		defer share.Host.OpenDials()
		udp, err := window.SendUdp(flows.udpAddress(), payload)
		if err != nil {
			return err
		}
		defer udp.Close()
		share.Host.WaitHeldDials(1)
		seen := flows.seenOf(connect.IpProtocolUdp, flows.udpAddress(), payload, dialCount)
		for _, want := range []string{
			"the window's link refused 0 packets",
			"the host decided map to 127.0.0.1:",
			"the NAT's udp dial held=true connected=false wrote 0 bytes",
			"the upstream took the payload: false",
		} {
			if !strings.Contains(seen, want) {
				return fmt.Errorf("what the world saw of the held datagram, %q, does not say %q", seen, want)
			}
		}
		share.Host.OpenDials()
		if err := udp.SetReadDeadline(time.Now().Add(share.X.Settings().WaitTimeout)); err != nil {
			return err
		}
		answer := make([]byte, len(payload)+1)
		n, err := udp.Read(answer)
		if err != nil || !bytes.Equal(answer[:n], payload) {
			return fmt.Errorf("the datagram once its dial went on: %q, %v", answer[:n], err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A datagram the window's own client policy drops never leaves the window, and what the world saw says so: its link
// refused one packet, and the host decided no flow for it.
func TestFs38ShareRefusedDatagramSaysTheWindowLostIt(t *testing.T) {
	world := fs38ShareWorldForTest(t, DefaultFs38ShareSettings(), nil)
	err := fsTeamCatch(func() error {
		share := world.share
		window := fsShareWindow(world, "fs38 share refused", func() []byte { return share.CurrentCert(7) }, 7)
		defer window.Close()
		flows := &fsShareFlows{world: world, window: window}
		// a privileged port, which the window's public relationship to the alias drops (connect's CFAA rule)
		dropped := netip.AddrPortFrom(share.Alias(), sidecartest.DefaultBridgeShareNetSettings().UnprivilegedPortFirst-1)
		payload := []byte("fs38 share refused")
		refused, err := window.SendUdp(dropped, payload)
		if err != nil {
			return err
		}
		defer refused.Close()
		// the link takes the stack's packets in order, so once the host decides a datagram sent after it, the link has
		// answered the dropped one
		passed, err := window.SendUdp(flows.udpAddress(), []byte("fs38 share passed"))
		if err != nil {
			return err
		}
		defer passed.Close()
		share.Host.WaitDecision(window.Client.ClientId, connect.IpProtocolUdp)
		seen := flows.seenOf(connect.IpProtocolUdp, dropped, payload, len(share.Host.Dials()))
		for _, want := range []string{
			"the window's link refused 1 packets",
			"the host decided no udp flow of it to " + dropped.String(),
		} {
			if !strings.Contains(seen, want) {
				return fmt.Errorf("what the world saw of the dropped datagram, %q, does not say %q", seen, want)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// An offer of a daemon listener that holds no socket and says it listens at address, as the kernel, which numbers TCP
// and UDP ports apart, may hand a TCP listener the number it gave a UDP one: an offer on that number whatever the
// kernel holds free. Its taker closes it.
type fs38ShareOfferedListener struct {
	address   *net.TCPAddr
	closeOnce sync.Once
	closed    chan struct{}
}

func newFs38ShareOfferedListener(port uint16) *fs38ShareOfferedListener {
	return &fs38ShareOfferedListener{
		address: net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)),
		closed:  make(chan struct{}),
	}
}

func (self *fs38ShareOfferedListener) Accept() (net.Conn, error) {
	<-self.closed
	return nil, net.ErrClosed
}

func (self *fs38ShareOfferedListener) Close() error {
	self.closeOnce.Do(func() {
		close(self.closed)
	})
	return nil
}

func (self *fs38ShareOfferedListener) Addr() net.Addr {
	return self.address
}

// Whether its taker closed it.
func (self *fs38ShareOfferedListener) isClosed() bool {
	select {
	case <-self.closed:
		return true
	default:
		return false
	}
}

// Tip-check's red at 54e31119: the kernel gave the share host's daemon listener the number it had given the upstream's
// UDP listener, and rule 0, which refuses a daemon listener's port whatever a flow's protocol, denied readerY's
// datagram, which went unanswered. A host whose first daemon offer takes that number refuses it and listens on
// another, and the twin's honest reader's connection, datagram and echo all open, as expectOpen asks of readerY.
func TestFs38ShareDaemonListensOnNoPortOfTheUpstreams(t *testing.T) {
	var offers []net.Listener
	bridgeSettings := sidecartest.DefaultBridgeNetSettings()
	bridgeSettings.ListenDaemon = func(upstream *sidecartest.BridgeNetUpstream) (net.Listener, error) {
		if len(offers) == 0 {
			offers = append(offers, newFs38ShareOfferedListener(upstream.UdpPort()))
			return offers[0], nil
		}
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err == nil {
			offers = append(offers, listener)
		}
		return listener, err
	}
	world := fs38ShareWorldForTest(t, DefaultFs38ShareSettings(), bridgeSettings)
	share := world.share
	firstClosed := 0 < len(offers) && offers[0].(*fs38ShareOfferedListener).isClosed()
	if len(offers) != 2 || !firstClosed || share.Host.Daemon != offers[1] {
		t.Fatalf("the host's daemon took %d offers, its first on the upstream's datagram port closed: %v", len(offers), firstClosed)
	}
	daemonPort := share.Host.Daemon.Addr().(*net.TCPAddr).Port
	if daemonPort == int(share.Host.Upstream.UdpPort()) || daemonPort == int(share.Host.Upstream.TcpPort()) {
		t.Fatalf("the host's daemon listens on %d, a port of its upstream's", daemonPort)
	}
	err := fsTeamCatch(func() error {
		window := share.OpenReaderWindow("fs38 share daemon clear", share.AcceptingSidecarId, func() []byte { return share.CurrentCert(7) }, 7)
		defer window.Close()
		return (&fsShareFlows{world: world, window: window}).expectOpen("fs38 share daemon clear")
	})
	if err != nil {
		t.Fatal(err)
	}
}

// What readerY's datagram met at 54e31119, on a world as every one is now built: a datagram through the share to the
// port of the host's daemon listener, a TCP listener's, sealed and carrying the share's principal, is denied at rule 0
// all the same, and what the world saw of it names the daemon's address, so a datagram denied there says so rather
// than reads as lost.
func TestFs38ShareDatagramToTheDaemonsPortIsDenied(t *testing.T) {
	world := fs38ShareWorldForTest(t, DefaultFs38ShareSettings(), nil)
	err := fsTeamCatch(func() error {
		share := world.share
		window := share.OpenReaderWindow("fs38 share daemon port", share.AcceptingSidecarId, func() []byte { return share.CurrentCert(7) }, 7)
		defer window.Close()
		flows := &fsShareFlows{world: world, window: window}
		daemon := share.Host.Daemon.Addr().(*net.TCPAddr)
		to := netip.AddrPortFrom(share.Alias(), uint16(daemon.Port))
		payload := []byte("fs38 share daemon port")
		dialCount := len(share.Host.Dials())
		udp, err := window.SendUdp(to, payload)
		if err != nil {
			return err
		}
		defer udp.Close()
		ofDatagram := func(decision *sidecartest.BridgeNetDecision) bool {
			return decision.Protocol == connect.IpProtocolUdp && decision.To == to
		}
		decisions := share.Host.WaitDecisions(window.Client.ClientId, func(decisions []*sidecartest.BridgeNetDecision) bool {
			return slices.ContainsFunc(decisions, ofDatagram)
		})
		decision := decisions[slices.IndexFunc(decisions, ofDatagram)]
		if decision.Opens() || !decision.Sealed || decision.Principal == nil || decision.Principal.ShareId != connect.Id(share.ShareId) {
			return fmt.Errorf("the datagram to the daemon's port was decided %s, sealed=%v, principal %+v", decision.Verdict, decision.Sealed, decision.Principal)
		}
		if len(share.Host.Dials()) != dialCount {
			return fmt.Errorf("the NAT dialed for the datagram to the daemon's port")
		}
		seen := flows.seenOf(connect.IpProtocolUdp, to, payload, dialCount)
		for _, want := range []string{
			"the window's link refused 0 packets",
			"the host decided deny at generation ",
			"the flow sealed=true with a principal of share " + connect.Id(share.ShareId).String(),
			"the host's daemon listening at " + daemon.String(),
		} {
			if !strings.Contains(seen, want) {
				return fmt.Errorf("what the world saw of the datagram to the daemon's port, %q, does not say %q", seen, want)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
