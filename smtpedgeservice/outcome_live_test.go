// SmtpOutcome's window from a connection's registration (QD-1112): the driver sends its outcome at its own close,
// which this edge may see end only after its QUIT, 221 and close round trip with the MX, so the dialer's outcome is
// taken while the connection is live, once, with the connection's network for the hard-bounce rule, and the end keeps
// it taken. A connection held live by the session's hold, as TestConnectionStopsReadingWhileTheSessionHolds holds
// one, and ended by an oversized part naming it, shows each step without a timer.

package smtpedgeservice_test

import (
	"net"
	"net/netip"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The dialer's outcome is taken while its connection is live and its hard bounces reach the halt rule; a stranger's
// is refused, a second is a repeat, and after the connection's end the same outcome is still a repeat.
func TestOutcomeIsTakenFromTheDialerWhileItsConnectionIsLive(t *testing.T) {
	w := newEdgeWorld(t, func(world *edgeWorld) {
		world.settings.ConnectionHeldMaxByteCount = 2048
		world.mustWorld(world.world.SetMx("quiet.example", &sidecar.SmtpMxHost{Preference: 10, Host: "mx.quiet.example"}))
		world.mustWorld(world.world.AddMx("mx.quiet.example", netip.MustParseAddr("192.0.2.26"), silentMx{}))
	})
	// the first record passes and every later one waits for a part that never comes, so the connection stays live
	w.verifier.SetScript(&sidecartest.FakeSmtpProofScript{HoldAfterClientRecords: 1})
	sidecarEnd, edgeEnd := sidecartest.NewMxPipe(&net.TCPAddr{}, &net.TCPAddr{})
	defer sidecarEnd.Close()
	served := make(chan struct{})
	go func() {
		defer close(served)
		w.service.ServeTestStream(w.networkId, w.clientId, w.sidecarId, edgeEnd)
	}()
	preamble := w.preamble()
	preamble.RecipientDomain = "quiet.example"
	if err := sidecar.WriteSmtpPreamble(sidecarEnd, preamble, nil); err != nil {
		t.Fatal(err)
	}
	result, err := sidecar.ReadSmtpPreambleResult(sidecarEnd, nil)
	if err != nil || result.GetCode() != uint32(protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK) {
		t.Fatalf("result %v, %v", result, err)
	}
	sendId := result.GetSendId()
	// one record passes and the held ones reach the bound, so the reader waits: the connection is registered and live
	for range 4 {
		if _, err := sidecarEnd.Write(append([]byte{23, 3, 3, 4, 0}, make([]byte, 1024)...)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.service.AwaitHeldWaits(w.ctx, 1); err != nil {
		t.Fatal(err)
	}
	if count := w.service.LiveConnectionCount(); count != 1 {
		t.Fatalf("%d live connections", count)
	}

	outcome, err := proto.Marshal(&protocol.SmtpOutcome{SendId: sendId, TlsLevel: 1, Mode: 1, HardBounceCount: 3})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.service.AcceptOutcome(sidecar.NewId(), outcome); err == nil {
		t.Fatal("a stranger's outcome was taken")
	}
	if err := w.service.AcceptOutcome(w.clientId, outcome); err != nil {
		t.Fatalf("the dialer's outcome while its connection is live: %v", err)
	}
	// its hard bounces went to the halt rule, under the connection's network
	if err := w.service.AwaitHaltWork(w.ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := w.service.AcceptOutcome(w.clientId, outcome); err == nil {
		t.Fatal("a second outcome while live was taken")
	}

	// a part past ProofMaxByteCount naming the send ends its connection (proof_rpc.go), and the end keeps the outcome
	oversized, err := proto.Marshal(&protocol.SmtpProof{SendId: sendId, Proof: make([]byte, w.settings.ProofMaxByteCount+1)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.service.HandleProofForTest(w.ctx, w.clientId, oversized); err != nil {
		t.Fatal(err)
	}
	<-served
	if count := w.service.LiveConnectionCount(); count != 0 {
		t.Fatalf("%d live connections after the end", count)
	}
	if err := w.service.AcceptOutcome(w.clientId, outcome); err == nil {
		t.Fatal("the end forgot the outcome its live connection took")
	}
	for _, c := range []struct {
		labels []string
		want   float64
	}{
		{labels: []string{"taken", "tl1", "bdat"}, want: 1},
		{labels: []string{"not_dialer", "unknown", "unknown"}, want: 1},
		{labels: []string{"repeated", "unknown", "unknown"}, want: 2},
		{labels: []string{"unknown_send", "unknown", "unknown"}, want: 0},
	} {
		if value := w.host.Metrics.Value("urnetwork_smtpedge_outcomes_total", c.labels...); value != c.want {
			t.Errorf("%v: %v, want %v", c.labels, value, c.want)
		}
	}
	w.world.Wait()
}
