// The LAN splice to mxedge (SMTP-M9-14, D-SMTP-13) at T2 with a stub router: an MX on a router interface goes
// by the host LAN with a PROXY v1 line naming the sending address and the dialed interface, the receiver behind
// the router gets the send's TLS as any MX does, and an MX elsewhere never goes by the LAN.

package smtpedgeservice_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// mxedge's router on the LAN: it reads the PROXY line, keeps it, then hands the connection to the receiver.
type stubRouter struct {
	receiver *sidecartest.ScriptedMx
	served   sync.WaitGroup

	stateLock sync.Mutex
	lines     []string
}

func (self *stubRouter) dial(lan netip.AddrPort) func(ctx context.Context, address netip.AddrPort) (net.Conn, error) {
	return func(ctx context.Context, address netip.AddrPort) (net.Conn, error) {
		if address != lan {
			return nil, errors.New("not the router's LAN listener")
		}
		client, server := sidecartest.NewMxPipe(&net.TCPAddr{IP: net.IPv4(10, 0, 0, 10), Port: 40001}, net.TCPAddrFromAddrPort(lan))
		self.served.Add(1)
		go func() {
			defer self.served.Done()
			// the line octet by octet, so nothing past it is taken from the receiver
			line := []byte{}
			octet := make([]byte, 1)
			for len(line) == 0 || line[len(line)-1] != '\n' {
				if _, err := server.Read(octet); err != nil {
					server.Close()
					return
				}
				line = append(line, octet[0])
			}
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				self.lines = append(self.lines, string(line))
			}()
			self.receiver.ServeMx(server)
		}()
		return client, nil
	}
}

func (self *stubRouter) proxyLines() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.lines)
}

func TestLanSpliceReachesARouterInterfaceByTheLan(t *testing.T) {
	routerAddress := netip.MustParseAddr("203.0.113.25")
	lan := netip.MustParseAddrPort("10.0.0.25:2525")
	receiver, err := sidecartest.NewScriptedMx("mx.n9.root.example", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	router := &stubRouter{receiver: receiver}
	w := newEdgeWorld(t, func(world *edgeWorld) {
		world.settings.RouterInterfaces = []netip.Addr{routerAddress}
		world.settings.RouterLanAddress = lan
		world.mustWorld(world.world.SetMx("n9.root.example", &sidecar.SmtpMxHost{Preference: 10, Host: "mx.n9.root.example"}))
		// the world dials no MX there: a hairpin to an lb address fails
		world.mustWorld(world.world.AddMx("mx.n9.root.example", routerAddress, nil))
		world.lanDial = router.dial(lan)
		world.recipientDomain = "n9.root.example"
	})
	w.verifier.SetScript(&sidecartest.FakeSmtpProofScript{HoldAfterClientRecords: 3, MailForwardedAtClientRecord: 5})
	splice := w.splice(sidecartest.NewFakeSmtpProver(nil), testSpliceMessage("x"), nil)
	router.served.Wait()
	if splice.err != nil || splice.proofResult == nil || !splice.proofResult.Accepted {
		t.Fatalf("the send: %+v, %v", splice.proofResult, splice.err)
	}
	if lines := router.proxyLines(); !slices.Equal(lines, []string{"PROXY TCP4 192.0.2.10 203.0.113.25 40001 25\r\n"}) {
		t.Fatalf("PROXY lines %q", lines)
	}
	// the router's sender path: the banner, EHLO with the PTR name, STARTTLS, then the transaction in TLS
	if accepted := receiver.Accepted(); len(accepted) < 2 || accepted[0] != "EHLO "+testHeloName || accepted[1] != "STARTTLS" {
		t.Fatalf("the receiver accepted %q", accepted)
	}
	if transactions := receiver.Transactions(); len(transactions) != 1 {
		t.Fatalf("%d transactions at the receiver", len(transactions))
	}
	if slices.Contains(w.world.Dials(), routerAddress) {
		t.Fatal("the edge dialed the router interface directly")
	}

	// an MX elsewhere never goes by the LAN
	w.recipientDomain = ""
	other := w.splice(sidecartest.NewFakeSmtpProver(nil), testSpliceMessage("y"), nil)
	if other.err != nil || !other.proofResult.Accepted {
		t.Fatalf("the other send: %+v, %v", other.proofResult, other.err)
	}
	if lines := router.proxyLines(); len(lines) != 1 {
		t.Fatalf("%d LAN dials", len(lines))
	}
}

// With no LAN listener named, an MX on a router interface is not reached at all: TRY_LATER, and never a
// direct dial.
func TestLanSpliceWithNoListenerReachesNothing(t *testing.T) {
	routerAddress := netip.MustParseAddr("203.0.113.25")
	w := newEdgeWorld(t, func(world *edgeWorld) {
		world.settings.RouterInterfaces = []netip.Addr{routerAddress}
		world.mustWorld(world.world.SetMx("n9.root.example", &sidecar.SmtpMxHost{Preference: 10, Host: "mx.n9.root.example"}))
		world.mustWorld(world.world.AddMx("mx.n9.root.example", routerAddress, nil))
		world.recipientDomain = "n9.root.example"
	})
	w.expect(w.preamble(), protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER)
	if slices.Contains(w.world.Dials(), routerAddress) {
		t.Fatal("the edge dialed the router interface directly")
	}
}
