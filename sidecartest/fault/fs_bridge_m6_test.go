//go:build !sidecar_http && !ios_extension

// BRIDGE-M6-08's schedules on T2 (fs_bridge_m6.go): FS-38's share rows, under every rule §22.8 gives the case;
// server/controller/connect_bridge_m6_test.go runs the same builders on T3. Beside them, the schedules' actors as a
// failing seed's trace must write them, and a failed exchange's report of where its packet stopped.

package fault

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"
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

// The share world FS-38's first step builds, failing t if it does not, which t's cleanup closes.
func fs38ShareWorldForTest(t *testing.T, settings *Fs38ShareSettings) *fsShareWorld {
	t.Helper()
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
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
	world := fs38ShareWorldForTest(t, settings)
	if wait := world.share.X.Settings().WaitTimeout; wait != settings.WaitTimeout {
		t.Fatalf("the share's world waits %s, not FS-38's %s", wait, settings.WaitTimeout)
	}
}

// A datagram the host's NAT holds at its dial goes unanswered, and what the world saw says where it stopped: the host
// mapped the flow and the NAT's dial waits at the gate unconnected, with nothing at the upstream. Once the gate opens,
// the same datagram is answered.
func TestFs38ShareHeldDatagramSaysWhereItStopped(t *testing.T) {
	world := fs38ShareWorldForTest(t, DefaultFs38ShareSettings())
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
	world := fs38ShareWorldForTest(t, DefaultFs38ShareSettings())
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
