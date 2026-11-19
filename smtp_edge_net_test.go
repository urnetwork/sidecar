//go:build !sidecar_http && !js && !ios_extension

// SMTP-M9-07's connection driver over a real ur/smtpedge stream on sidecartest's Net (owner decision 624, QD-1089): a
// Sidecar's dispatcher dials the edge's platform client by §9's ticket path (PlatformDialOn), the daemon's own stream
// carries the preamble and the TLS, the parts and the SHTS go as calls marked for the edge to the handlers on the
// edge's dispatcher, and the outcome as SendEdge's NO_REPLY envelope to its HandleNoReply function, all over connect's
// Required sessions and Service contracts both ways. Behind the edge's dispatcher StubSmtpEdge serves the stream and
// checks the parts, so what this adds to TestSmtpConnectionSendsThroughTheStub is §6 between the two ends: before
// owner decision 624 every part's call ran a Hello the edge drops and failed at its deadline, so nothing past the
// handshake reached the MX, and the outcome had no way to go. The engine's own functions on a real dispatcher are
// smtpedgeservice's TestSmtpSenderOverRealDispatchersReachesAcceptOutcome.
//
// Every wait is on what the run delivers, bounded only so a broken run fails rather than hangs.

package sidecar_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A sidecar and smtpedge's platform client on one Net, the sidecar's ur/ dial reaching the edge's listener.
type testSmtpEdgeNet struct {
	net    *sidecartest.Net
	laptop *sidecartest.SubprotocolSidecar
	// smtpedge's platform client and its dispatcher, in the edge's role
	edgeClientId connect.Id
	edge         *sidecar.Subprotocol
	dial         *sidecar.PlatformDialOn
}

// The Net, with a sidecar enrolled and admitted, and smtpedge's platform client as EdgeClientPool makes one: Required,
// reachable from a Service source on 21842 alone, providing Service and nothing else. The pair's contracts are
// Service both ways, CreateContract's decision for a ur/ pair, and the ur/ dial's Finds answer one ticket naming
// the edge's client as listener, signed with the service's key.
func newTestSmtpEdgeNet(t *testing.T) *testSmtpEdgeNet {
	t.Helper()
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	sidecars, _, err := net.AddSubprotocolSidecars("laptop")
	if err != nil {
		t.Fatal(err)
	}
	laptop := sidecars[0]
	laptopClientId := laptop.ClientId()

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
	net.SetContractProvideMode(laptopClientId, edgeClient.ClientId, connectprotocol.ProvideMode_Service)
	net.SetContractProvideMode(edgeClient.ClientId, laptopClientId, connectprotocol.ProvideMode_Service)

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	urnetworkEdge := sidecar.NewId()
	find := func(ctx context.Context, args *sidecar.SocketFindArgs) (*sidecar.SocketFindResult, error) {
		nowMillis := uint64(time.Now().UnixMilli())
		signedTicket, err := sidecar.SignSocketTicket("net", privateKey, &protocol.SocketTicket{
			TicketId:         sidecar.NewId().Bytes(),
			NetworkId:        urnetworkEdge.Bytes(),
			Name:             sidecar.SmtpEdgeAddress,
			ListenerClientId: edgeClient.ClientId.Bytes(),
			ListenId:         sidecar.NewId().Bytes(),
			DialerClientId:   laptopClientId.Bytes(),
			DialerNetworkId:  laptop.NetworkId().Bytes(),
			IssueTimeMillis:  nowMillis,
			ExpireTimeMillis: nowMillis + 30_000,
		})
		if err != nil {
			return nil, err
		}
		ticketBytes, err := proto.Marshal(signedTicket)
		if err != nil {
			return nil, err
		}
		return &sidecar.SocketFindResult{Primary: &sidecar.SocketFindTicket{Ticket: ticketBytes}}, nil
	}
	dial := sidecar.NewPlatformDialOn(laptop.Subprotocol(), laptop.NetworkId(), sidecar.Id(laptopClientId), urnetworkEdge, []*sidecar.SocketTicketKey{{
		KeyId:            "net",
		PublicKey:        publicKey,
		ExpireTimeMillis: uint64(time.Now().Add(24 * time.Hour).UnixMilli()),
	}}, find)
	return &testSmtpEdgeNet{net: net, laptop: laptop, edgeClientId: edgeClient.ClientId, edge: edge, dial: dial}
}

// A dialer set once the world that holds it exists, since the world's sender takes its dialer when it is built and
// the Net's edge serves with the world's stub.
type testLateSmtpEdgeDialer struct {
	stateLock sync.Mutex
	dialer    sidecar.SmtpEdgeDialer
}

func (self *testLateSmtpEdgeDialer) set(dialer sidecar.SmtpEdgeDialer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.dialer = dialer
}

func (self *testLateSmtpEdgeDialer) DialSmtpEdge(ctx context.Context) (sidecar.SmtpEdgeStream, error) {
	self.stateLock.Lock()
	dialer := self.dialer
	self.stateLock.Unlock()
	return dialer.DialSmtpEdge(ctx)
}

// One call or NO_REPLY envelope the edge's dispatcher handed a function.
type testEdgeArrival struct {
	sourceId    sidecar.Id
	messageType protocol.MessageType
	outcome     *protocol.SmtpOutcome
}

// A send over a real stream: the stream opens on its ticket, the preamble is answered OK, the SHTS and every part
// reach the edge's handlers as calls from the sidecar's client with no Hello, the MX takes the one transaction, and
// the SmtpOutcome reaches the edge's NO_REPLY function from the same client, naming the send at its level and mode.
func TestSmtpConnectionSendsOverARealEdgeStream(t *testing.T) {
	late := &testLateSmtpEdgeDialer{}
	world := newTestSenderWorld(t, &testSenderOptions{dialer: func(stub *sidecartest.StubSmtpEdgeDialer) sidecar.SmtpEdgeDialer {
		return late
	}})
	edgeNet := newTestSmtpEdgeNet(t)
	late.set(sidecar.NewSmtpEdgeDialerOn(edgeNet.dial, edgeNet.laptop.Subprotocol(), world.settings))

	// the edge: StubSmtpEdge serves each stream its listener accepts, and its handlers answer the parts and the SHTS.
	// Closing the edge's dispatcher ends every stream, so a run that failed half way leaves no Serve waiting.
	var serving sync.WaitGroup
	t.Cleanup(func() {
		edgeNet.edge.Close()
		serving.Wait()
	})
	removeListen, err := edgeNet.edge.Listen(sidecar.SmtpEdgeAddress, func(ctx context.Context, incoming *sidecar.StreamIncoming) error {
		serving.Add(1)
		go func() {
			defer serving.Done()
			world.edge.Serve(context.Background(), incoming.Stream)
		}()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(removeListen)
	arrivals := make(chan *testEdgeArrival, 64)
	removeProof, err := edgeNet.edge.Handle(protocol.MessageType_SMTP_PROOF, func(ctx context.Context, request *sidecar.SubprotocolRequest) ([]byte, error) {
		arrivals <- &testEdgeArrival{sourceId: request.SourceId, messageType: request.MessageType}
		proof := &protocol.SmtpProof{}
		if err := proto.Unmarshal(request.Body, proof); err != nil {
			return nil, &sidecar.SubprotocolError{Code: protocol.ErrorCode_ERR_INVALID_ARGUMENT}
		}
		return proto.Marshal(world.edge.SubmitProof(ctx, proof))
	}, &sidecar.HandleOptions{Mutating: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(removeProof)
	removeHandshake, err := edgeNet.edge.Handle(protocol.MessageType_SMTP_HANDSHAKE, func(ctx context.Context, request *sidecar.SubprotocolRequest) ([]byte, error) {
		arrivals <- &testEdgeArrival{sourceId: request.SourceId, messageType: request.MessageType}
		handshake := &protocol.SmtpHandshake{}
		if err := proto.Unmarshal(request.Body, handshake); err != nil {
			return nil, &sidecar.SubprotocolError{Code: protocol.ErrorCode_ERR_INVALID_ARGUMENT}
		}
		return proto.Marshal(world.edge.Handshake(ctx, handshake))
	}, &sidecar.HandleOptions{Mutating: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(removeHandshake)
	outcomes := make(chan *testEdgeArrival, 4)
	removeOutcome, err := edgeNet.edge.HandleNoReply(protocol.MessageType_SMTP_OUTCOME, func(ctx context.Context, message *sidecar.SubprotocolNoReply) {
		outcome := &protocol.SmtpOutcome{}
		if err := proto.Unmarshal(message.Body, outcome); err != nil {
			outcome = nil
		}
		outcomes <- &testEdgeArrival{sourceId: message.SourceId, messageType: message.MessageType, outcome: outcome}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(removeOutcome)

	ctx, cancel := context.WithTimeout(t.Context(), testPlatformDialNetTimeout)
	defer cancel()
	message := world.message([]string{"bob@" + testTlsDomain}, nil, "A body line.\r\n")
	result := world.sender.RunConnectionForTest(ctx, world.connectionArgs(message, sidecartest.FakeSmtpProverKeySet()))
	if result.Err != nil || result.Proof == nil || !result.Proof.Accepted {
		t.Fatalf("not sent: %+v %v", result.Proof, result.Err)
	}
	if result.PreambleCode != protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK || result.TlsLevel != sidecar.SmtpTlsLevelIndependentMx || result.EdgeResetCount != 0 {
		t.Errorf("code %s, level %d, resets %d", result.PreambleCode, result.TlsLevel, result.EdgeResetCount)
	}
	transactions := world.mx.Transactions()
	if len(transactions) != 1 || transactions[0].Sender != "<"+testSenderAddress+">" {
		t.Fatalf("transactions %+v", transactions)
	}

	// past the handshake: the SHTS and the parts each came as a call from the sidecar's own client
	laptopClientId := sidecar.Id(edgeNet.laptop.ClientId())
	handshakeCount, proofCount := 0, 0
	for len(arrivals) != 0 {
		arrival := <-arrivals
		if arrival.sourceId != laptopClientId {
			t.Errorf("a %v call from %s", arrival.messageType, arrival.sourceId)
		}
		switch arrival.messageType {
		case protocol.MessageType_SMTP_HANDSHAKE:
			handshakeCount += 1
		case protocol.MessageType_SMTP_PROOF:
			proofCount += 1
		}
	}
	if handshakeCount != 1 || proofCount == 0 {
		t.Errorf("%d handshakes and %d parts reached the edge's handlers", handshakeCount, proofCount)
	}

	// and the outcome, by SendEdge, reached the NO_REPLY function, not the stub's own path
	if !result.OutcomeSent {
		t.Error("the outcome did not go")
	}
	arrival := testPlatformDialNetAwait(t, outcomes, "the edge's SmtpOutcome")
	if arrival.sourceId != laptopClientId || arrival.outcome == nil || string(arrival.outcome.GetSendId()) != string(result.SendId) ||
		arrival.outcome.GetTlsLevel() != uint32(sidecar.SmtpTlsLevelIndependentMx) || arrival.outcome.GetMode() != uint32(sidecar.SmtpModeBdat) ||
		len(arrival.outcome.GetReplyCodes()) == 0 {
		t.Errorf("the outcome from %s: %v", arrival.sourceId, arrival.outcome)
	}
	if stubOutcomes := world.edge.Outcomes(); len(stubOutcomes) != 0 {
		t.Errorf("the stub's own path took %d outcomes", len(stubOutcomes))
	}
	// no Hello, HeadCheck or SEARCH ever reached the edge, which would have dropped it at its guard
	if dropped := edgeNet.edge.Stats().ProvideModeDroppedCount; dropped != 0 {
		t.Errorf("the edge's guard dropped %d frames", dropped)
	}
}
