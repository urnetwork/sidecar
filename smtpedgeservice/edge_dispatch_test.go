// SMTP-M9-13's engine on real dispatchers (owner decision 624, QD-1089): the functions Serve registers on a platform
// client's dispatcher (registerHandlers) take a sidecar's calls marked for the edge and its SendEdge NO_REPLY envelope
// over sidecartest's Net, on connect's Required sessions and Service contracts both ways. The sidecar's own SmtpSender
// sends over a real §6 stream the engine serves; its parts and SHTS reach SMTP_PROOF's and SMTP_HANDSHAKE's handlers as
// calls with no Hello, and its SmtpOutcome reaches AcceptOutcome by SendEdge: taken from the dialer once, refused from
// another sidecar and a second time. The root's TestSmtpConnectionSendsOverARealEdgeStream runs the daemon's own
// stream and channel; this runs the engine's own functions.
//
// The engine takes an outcome only once it has ended the connection (§14.14's window, outcome.go), and the driver
// sends it right after its own close, so here the sidecar's stream sends it once the engine's serve of that stream has
// returned: which end's view of the stream's end governs is question smtp-edge-outcome-before-the-edge-ends.
//
// Every wait is on what the run delivers, bounded by the world's context so a broken run fails rather than hangs.

package smtpedgeservice_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

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
	// the timeouts are the Net's own clients', for a process with no real network in it
	edgeSettings := connect.DefaultClientSettingsWithBufferSize(64)
	edgeSettings.SendBufferSettings.AckTimeout = 60 * time.Second
	edgeSettings.SendBufferSettings.IdleTimeout = 1 * time.Second
	edgeSettings.SendBufferSettings.MinResendInterval = 10 * time.Millisecond
	edgeSettings.ReceiveBufferSettings.GapTimeout = 60 * time.Second
	edgeSettings.ReceiveBufferSettings.IdleTimeout = 60 * time.Second
	edgeSettings.ForwardBufferSettings.IdleTimeout = 1 * time.Second
	edgeSettings.ContractManagerSettings.LegacyCreateContract = false
	edgeSettings.EncryptionSettings.TlsTimeout = 30 * time.Second
	sidecar.ApplySidecarClientSettings(edgeSettings)
	edgeClient := net.AddClient("smtpedge", edgeSettings)
	edgeClient.Client.ContractManager().SetProvideModes(map[connectprotocol.ProvideMode]bool{connectprotocol.ProvideMode_Service: true})
	protocolSettings := sidecar.DefaultSidecarProtocolSettings()
	edge, err := sidecar.NewSubprotocol(t.Context(), &sidecar.SubprotocolEnv{
		Client:   edgeClient.Client,
		Log:      sidecar.NewNoopLogger(),
		Settings: protocolSettings,
		Budget:   sidecar.NewSubprotocolBudget(protocolSettings, 64*1024*1024),
		Inbound:  sidecar.SubprotocolInboundWithoutPolicy,
		Role:     sidecar.SubprotocolRoleEdge,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(edge.Close)
	for _, sidecarOnNet := range sidecars {
		net.SetContractProvideMode(sidecarOnNet.ClientId(), edgeClient.ClientId, connectprotocol.ProvideMode_Service)
		net.SetContractProvideMode(edgeClient.ClientId, sidecarOnNet.ClientId(), connectprotocol.ProvideMode_Service)
		release, err := sidecarOnNet.Subprotocol().HoldProvideMode(connectprotocol.ProvideMode_Service)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(release)
	}
	return &testEngineEdgeNet{sidecars: sidecars, edgeClientId: edgeClient.ClientId, edge: edge}
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
	// closed once the engine's serve of this stream has returned, its connection ended
	served <-chan struct{}
}

func (self *testDispatchStream) ProofChannel(sendId []byte) sidecar.SmtpProofChannel {
	return &testDispatchProofChannel{subprotocol: self.subprotocol, edgeId: self.edgeId, sendId: bytes.Clone(sendId)}
}

// SendEdge, once the engine has ended the connection: see the file header.
func (self *testDispatchStream) SendOutcome(ctx context.Context, outcome *protocol.SmtpOutcome) error {
	select {
	case <-self.served:
	case <-ctx.Done():
		return ctx.Err()
	}
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
	// what closes once the engine's serve of each stream returns, by stream id; one sidecar dials, so ids do not collide
	streamIdServed map[uint64]chan struct{}
}

func (self *testDispatchDialer) servedOf(streamId uint64) chan struct{} {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.streamIdServed == nil {
		self.streamIdServed = map[uint64]chan struct{}{}
	}
	served := self.streamIdServed[streamId]
	if served == nil {
		served = make(chan struct{})
		self.streamIdServed[streamId] = served
	}
	return served
}

func (self *testDispatchDialer) DialSmtpEdge(ctx context.Context) (sidecar.SmtpEdgeStream, error) {
	stream, err := self.subprotocol.OpenStream(ctx, self.edgeId, &sidecar.StreamOpenRequest{Target: smtpedgeservice.SmtpEdgeSocketName, Edge: true})
	if err != nil {
		return nil, err
	}
	return &testDispatchStream{SubprotocolStream: stream, subprotocol: self.subprotocol, edgeId: self.edgeId, served: self.servedOf(stream.StreamId())}, nil
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
		served := dialer.servedOf(incoming.Stream.StreamId())
		serving.Add(1)
		go func() {
			defer serving.Done()
			defer close(served)
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

	// the sender's outcome went by SendEdge once the engine ended the connection, and AcceptOutcome took it
	testEdgeDispatchBarrier(t, w.ctx, laptop, edgeId)
	mode := "bdat"
	if outcome.Mode == sidecar.SmtpModeData {
		mode = "data"
	}
	if value := w.host.Metrics.Value("urnetwork_smtpedge_outcomes_total", "taken", "tl4", mode); value != 1 {
		t.Fatalf("%v outcomes taken; %q", value, w.host.Metrics.Dump())
	}

	// the same report from another sidecar, then from the dialer again: refused, each counted
	sends := w.loggedSends()
	if len(sends) != 1 {
		t.Fatalf("%d sends logged", len(sends))
	}
	again, err := proto.Marshal(&protocol.SmtpOutcome{SendId: sends[0].SendId, TlsLevel: uint32(sidecar.SmtpTlsLevelUnauthenticated), Mode: uint32(outcome.Mode)})
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
