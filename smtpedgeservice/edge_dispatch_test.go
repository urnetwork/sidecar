// SMTP-M9-13's engine on real dispatchers (owner decision 624, QD-1089): the functions Serve registers on a platform
// client's dispatcher (registerHandlers) take a sidecar's calls marked for the edge and its SendEdge NO_REPLY envelope
// over sidecartest's Net, on connect's Required sessions and Service contracts both ways. The sidecar's own SmtpSender
// sends over a real §6 stream the engine serves; its parts and SHTS reach SMTP_PROOF's and SMTP_HANDSHAKE's handlers as
// calls with no Hello, and its SmtpOutcome reaches AcceptOutcome by SendEdge: taken from the dialer once, refused from
// another sidecar and a second time. The root's TestSmtpConnectionSendsOverARealEdgeStream runs the daemon's own
// stream and channel; this runs the engine's own functions.
//
// The sidecar's stream sends its outcome right at its own close, as the driver does, with nothing to order it after
// the engine's end of the connection: the engine takes it from a live connection's dialer too (QD-1112), so it is
// taken whichever end sees the stream end first.
//
// Every wait is on what the run delivers, bounded by the world's context so a broken run fails rather than hangs.

package smtpedgeservice_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

// Sidecars and smtpedge's platform client on one Net.
type testEngineEdgeNet struct {
	sidecars []*sidecartest.SubprotocolSidecar
	// smtpedge's platform client and its dispatcher, in the edge's role
	edgeClientId connect.Id
	edge         *sidecar.Subprotocol
}

// The Net with a sidecar of each name, enrolled and admitted, and smtpedge's platform client as EdgeClientPool makes
// one: Required, reachable from a Service source on 21842 alone, providing Service and nothing else. Each pair's
// contracts are Service both ways, CreateContract's decision for a ur/ pair, and each sidecar holds Service, as its
// ur/ dial does while the stream lives (QD-849), so the edge's answers reach it.
func newTestEngineEdgeNet(t *testing.T, names ...string) *testEngineEdgeNet {
	t.Helper()
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	sidecars, _, err := net.AddSubprotocolSidecars(names...)
	if err != nil {
		t.Fatal(err)
	}
	args, err := net.EdgeClientPoolArgs(sidecar.NewId())
	if err != nil {
		t.Fatal(err)
	}
	args.Settings = sidecar.DefaultEdgeClientPoolSettings()
	args.Settings.ClientCount = 1
	args.Inbound = smtpedgeservice.Inbound
	pool, err := sidecar.NewEdgeClientPool(t.Context(), args)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	edgeClient := pool.Clients()[0]
	edgeClientId := connect.Id(edgeClient.ClientId)
	for _, sidecarOnNet := range sidecars {
		net.SetContractProvideMode(sidecarOnNet.ClientId(), edgeClientId, connectprotocol.ProvideMode_Service)
		net.SetContractProvideMode(edgeClientId, sidecarOnNet.ClientId(), connectprotocol.ProvideMode_Service)
		release, err := sidecarOnNet.Subprotocol().HoldProvideMode(connectprotocol.ProvideMode_Service)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(release)
	}
	return &testEngineEdgeNet{sidecars: sidecars, edgeClientId: edgeClientId, edge: edgeClient.Subprotocol}
}

// A sender's opens and SMTP methods are accepted only by the serving edge. Both roles keep unrecognized
// operations closed and route continuations using the stream ID.
func TestEdgeInboundRoles(t *testing.T) {
	for _, test := range []struct {
		messageType protocol.MessageType
		streamId    uint64
		response    bool
		dial        bool
		smtp        bool
	}{
		{messageType: protocol.MessageType_STREAM_OPEN, streamId: 1, smtp: true},
		{messageType: protocol.MessageType_STREAM_OPEN},
		{messageType: protocol.MessageType_STREAM_ACCEPT, streamId: 1, dial: true, smtp: true},
		{messageType: protocol.MessageType_STREAM_REJECT, streamId: 1, dial: true, smtp: true},
		{messageType: protocol.MessageType_STREAM_DATA, streamId: 1, dial: true, smtp: true},
		{messageType: protocol.MessageType_STREAM_WINDOW, streamId: 1, dial: true, smtp: true},
		{messageType: protocol.MessageType_STREAM_CLOSE, streamId: 1, dial: true, smtp: true},
		{messageType: protocol.MessageType_STREAM_RESET, streamId: 1, dial: true, smtp: true},
		{messageType: protocol.MessageType_STREAM_DATA},
		{messageType: protocol.MessageType_PING, dial: true, smtp: true},
		{messageType: protocol.MessageType_PONG, response: true, dial: true, smtp: true},
		{messageType: protocol.MessageType_SMTP_HANDSHAKE, smtp: true},
		{messageType: protocol.MessageType_SMTP_PROOF, smtp: true},
		{messageType: protocol.MessageType_SMTP_OUTCOME, smtp: true},
		{messageType: protocol.MessageType_CANCEL, smtp: true},
		{messageType: protocol.MessageType_SMTP_PROOF, response: true},
		{messageType: protocol.MessageType_SMTP_PROOF, streamId: 1},
		{messageType: protocol.MessageType_SEARCH},
		{messageType: protocol.MessageType_HELLO},
	} {
		inbound := sidecar.SubprotocolInbound{MessageType: test.messageType, StreamId: test.streamId, Response: test.response}
		if sidecar.EdgeDialInbound(inbound) != test.dial || smtpedgeservice.Inbound(inbound) != test.smtp {
			t.Errorf("unexpected inbound policy for %+v", inbound)
		}
	}
}

// A sender's channel as a daemon's: each part and the SHTS a call marked for the edge, answered by its result's code.
type testDispatchProofChannel struct {
	subprotocol *sidecar.Subprotocol
	edgeId      sidecar.Id
	sendId      []byte
}

func (self *testDispatchProofChannel) DiscloseShts(ctx context.Context, shts []byte) error {
	body, err := proto.Marshal(&protocol.SmtpHandshake{SendId: self.sendId, Shts: shts})
	if err != nil {
		return err
	}
	answer, err := self.subprotocol.Call(ctx, self.edgeId, protocol.MessageType_SMTP_HANDSHAKE, body, &sidecar.CallOptions{Edge: true})
	if err != nil {
		return err
	}
	result := &protocol.SmtpHandshakeResult{}
	if err := proto.Unmarshal(answer, result); err != nil || result.GetCode() != uint32(protocol.SmtpHandshakeCode_SMTP_HANDSHAKE_OK) {
		return errors.New("the handshake was refused")
	}
	return nil
}

func (self *testDispatchProofChannel) SubmitPart(ctx context.Context, part *sidecar.SmtpProofPart) error {
	body, err := proto.Marshal(&protocol.SmtpProof{
		SendId:            self.sendId,
		Index:             part.Index,
		Mode:              part.Mode,
		FirstRecord:       part.FirstRecord,
		LastRecord:        part.LastRecord,
		Proof:             part.Proof,
		Last:              part.Last,
		ServerRecordCount: part.ServerRecordCount,
		Records:           part.Records,
		KeyCommitment:     part.KeyCommitment,
		ReplyCount:        part.ReplyCount,
		HeaderRecordCount: part.HeaderRecordCount,
		Carry:             part.Carry,
	})
	if err != nil {
		return err
	}
	answer, err := self.subprotocol.Call(ctx, self.edgeId, protocol.MessageType_SMTP_PROOF, body, &sidecar.CallOptions{Edge: true})
	if err != nil {
		return err
	}
	result := &protocol.SmtpProofResult{}
	if err := proto.Unmarshal(answer, result); err != nil || result.GetCode() != uint32(protocol.SmtpProofCode_SMTP_PROOF_OK) {
		return errors.New("a part was refused")
	}
	return nil
}

// The sidecar's end of one stream the engine serves.
type testDispatchStream struct {
	*sidecar.SubprotocolStream
	subprotocol *sidecar.Subprotocol
	edgeId      sidecar.Id
	dialer      *testDispatchDialer
}

func (self *testDispatchStream) ProofChannel(sendId []byte) sidecar.SmtpProofChannel {
	return &testDispatchProofChannel{subprotocol: self.subprotocol, edgeId: self.edgeId, sendId: bytes.Clone(sendId)}
}

// SendEdge at once, as the daemon's stream sends it, kept for the test.
func (self *testDispatchStream) SendOutcome(ctx context.Context, outcome *protocol.SmtpOutcome) error {
	func() {
		self.dialer.stateLock.Lock()
		defer self.dialer.stateLock.Unlock()
		self.dialer.outcomes = append(self.dialer.outcomes, proto.CloneOf(outcome))
	}()
	body, err := proto.Marshal(outcome)
	if err != nil {
		return err
	}
	return self.subprotocol.SendEdge(ctx, self.edgeId, protocol.MessageType_SMTP_OUTCOME, body)
}

func (self *testDispatchStream) Abort() error {
	return self.SubprotocolStream.Reset(protocol.StreamResetCode_RST_CANCELLED)
}

// A sidecar.SmtpEdgeDialer opening each stream to the edge's dispatcher on the Net, as a ur/ dial does past its ticket.
type testDispatchDialer struct {
	subprotocol *sidecar.Subprotocol
	edgeId      sidecar.Id

	stateLock sync.Mutex
	// every outcome a stream sent, in order
	outcomes []*protocol.SmtpOutcome
}

// Every outcome sent so far.
func (self *testDispatchDialer) sentOutcomes() []*protocol.SmtpOutcome {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*protocol.SmtpOutcome(nil), self.outcomes...)
}

func (self *testDispatchDialer) DialSmtpEdge(ctx context.Context) (sidecar.SmtpEdgeStream, error) {
	stream, err := self.subprotocol.OpenStream(ctx, self.edgeId, &sidecar.StreamOpenRequest{Target: smtpedgeservice.SmtpEdgeSocketName, Edge: true})
	if err != nil {
		return nil, err
	}
	return &testDispatchStream{SubprotocolStream: stream, subprotocol: self.subprotocol, edgeId: self.edgeId, dialer: self}, nil
}

// Waits until source's earlier envelopes to the edge have been dispatched there: a call marked for the edge, which
// the source's worker at the edge takes after them, in order, answered INVALID as a handshake naming no live send.
func testEdgeDispatchBarrier(t *testing.T, ctx context.Context, source *sidecar.Subprotocol, edgeId sidecar.Id) {
	t.Helper()
	body, err := proto.Marshal(&protocol.SmtpHandshake{SendId: bytes.Repeat([]byte{0xb0}, smtpedgeservice.SmtpSendIdByteCount)})
	if err != nil {
		t.Fatal(err)
	}
	answer, err := source.Call(ctx, edgeId, protocol.MessageType_SMTP_HANDSHAKE, body, &sidecar.CallOptions{Edge: true})
	result := &protocol.SmtpHandshakeResult{}
	if err != nil || proto.Unmarshal(answer, result) != nil || result.GetCode() != uint32(protocol.SmtpHandshakeCode_SMTP_HANDSHAKE_INVALID) {
		t.Fatalf("the barrier's call: %v, %v", result, err)
	}
}

// The sidecar's own SmtpSender through the engine over the Net: sent at TL4 by the message's allowance, every part
// and the SHTS through the engine's handlers as calls with no Hello, and the SmtpOutcome by SendEdge to AcceptOutcome,
// taken from the dialer once; the same outcome from another sidecar, and from the dialer again, is refused.
func TestSmtpSenderOverRealDispatchersReachesAcceptOutcome(t *testing.T) {
	edgeNet := newTestEngineEdgeNet(t, "laptop", "desk")
	laptop, desk := edgeNet.sidecars[0].Subprotocol(), edgeNet.sidecars[1].Subprotocol()
	edgeId := sidecar.Id(edgeNet.edgeClientId)
	w := newTestEngineWorld(t, func(world *edgeWorld) {
		world.verifier = sidecartest.NewFakeSmtpProofVerifier(&sidecartest.FakeSmtpProofScript{HoldAfterClientRecords: 3, MailForwardedAtClientRecord: 5})
	})
	remove, err := w.service.RegisterHandlersForTest(edgeNet.edge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remove)
	dialer := &testDispatchDialer{subprotocol: laptop, edgeId: edgeId}
	// the engine serves each stream the edge's listener accepts, its dialer the stream's source as a ticket would name
	// it; closing the edge's dispatcher ends every stream, so a run that failed half way leaves no serve waiting
	var serving sync.WaitGroup
	t.Cleanup(func() {
		edgeNet.edge.Close()
		serving.Wait()
	})
	removeListen, err := edgeNet.edge.Listen(smtpedgeservice.SmtpEdgeSocketName, func(ctx context.Context, incoming *sidecar.StreamIncoming) error {
		serving.Add(1)
		go func() {
			defer serving.Done()
			w.service.ServeTestStream(w.networkId, incoming.SourceId, w.sidecarId, incoming.Stream)
		}()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(removeListen)

	sender, prover, senderLog := newTestEngineSender(t, w, dialer)
	result, err := sender.Send(w.ctx, testEngineMessage(w, 0x51))
	if err != nil {
		t.Fatal(err)
	}
	outcome := result.Domains[0]
	if outcome.Outcome != sidecar.SmtpOutcomeSent || outcome.TlsLevel != sidecar.SmtpTlsLevelUnauthenticated {
		t.Fatalf("outcome %+v; the sender logged %q; the prover saw %+v", outcome, senderLog.Lines(), prover.Sends())
	}
	if transactions := w.mx.Transactions(); len(transactions) != 1 {
		t.Fatalf("transactions %+v", transactions)
	}
	// every part reached the engine's session through its SMTP_PROOF handler
	sessions := w.verifier.Sessions()
	if len(sessions) != 1 || !sessions[0].MailForwarded() {
		t.Fatalf("%d sessions", len(sessions))
	}
	partCount := 0
	for _, call := range sessions[0].Calls() {
		if call.Method == "VerifyPart" && call.Err == nil {
			partCount += 1
		}
	}
	if partCount == 0 {
		t.Error("no part reached the session")
	}

	// the sender's outcome went by SendEdge at its close, and AcceptOutcome took it, live or ended
	sentOutcomes := dialer.sentOutcomes()
	if len(sentOutcomes) != 1 || len(sentOutcomes[0].GetSendId()) != smtpedgeservice.SmtpSendIdByteCount {
		t.Fatalf("outcomes sent %v", sentOutcomes)
	}
	testEdgeDispatchBarrier(t, w.ctx, laptop, edgeId)
	mode := "bdat"
	if outcome.Mode == sidecar.SmtpModeData {
		mode = "data"
	}
	if value := w.host.Metrics.Value("urnetwork_smtpedge_outcomes_total", "taken", "tl4", mode); value != 1 {
		t.Fatalf("%v outcomes taken; %q", value, w.host.Metrics.Dump())
	}

	// the same report from another sidecar, then from the dialer again: refused, each counted
	again, err := proto.Marshal(sentOutcomes[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := desk.SendEdge(w.ctx, edgeId, protocol.MessageType_SMTP_OUTCOME, again); err != nil {
		t.Fatal(err)
	}
	testEdgeDispatchBarrier(t, w.ctx, desk, edgeId)
	if err := laptop.SendEdge(w.ctx, edgeId, protocol.MessageType_SMTP_OUTCOME, again); err != nil {
		t.Fatal(err)
	}
	testEdgeDispatchBarrier(t, w.ctx, laptop, edgeId)
	for _, why := range []string{"not_dialer", "repeated"} {
		if value := w.host.Metrics.Value("urnetwork_smtpedge_outcomes_total", why, "unknown", "unknown"); value != 1 {
			t.Errorf("%v outcomes refused as %s", value, why)
		}
	}
	if value := w.host.Metrics.Value("urnetwork_smtpedge_outcomes_total", "taken", "tl4", mode); value != 1 {
		t.Errorf("%v outcomes taken", value)
	}
	// no Hello, HeadCheck or SEARCH ever reached the edge, which would have dropped it at its guard
	if dropped := edgeNet.edge.Stats().ProvideModeDroppedCount; dropped != 0 {
		t.Errorf("the edge's guard dropped %d frames", dropped)
	}
}
