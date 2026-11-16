//go:build !sidecar_http && !js

// QD-849's ur/ stream on T2: a real Sidecar on sidecartest's Net dials ur/smtpedge at an edge's dispatcher on a
// platform client of its own, over connect's Required sessions and the Net's contract issuer, which signs each
// contract with the destination client's live provide key for the pair's mode, as CreateContract does, and refuses a
// destination that does not provide it. The pair's mode is Service both ways, CreateContract's decision for a ur/ pair
// (QD-728). So the edge's replies reach the sidecar only on contracts under its Service key, which the sidecar's
// client verifies as connect does, and the stream completes only because the dial holds Service for it: with no hold
// the issuer signs nothing to the sidecar, and not even the Required session's handshake, whose answers are the
// edge's too, completes. The twin that opens with no hold, the hold's sharing and its refusals are
// socket_dial_service_test.go's, on the pipe seam and on dispatchers with the issuer modelled.

package sidecar_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// How long the test waits, in real time, for what it expects: only a broken run's bound.
const testPlatformDialNetTimeout = 45 * time.Second

func testPlatformDialNetAwait[T any](t *testing.T, values <-chan T, what string) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(testPlatformDialNetTimeout):
		t.Fatalf("no %s", what)
		var zero T
		return zero
	}
}

// A sidecar with no tls/ or smtp/ registration dials ur/smtpedge on the Net: the stream opens, carries bytes both ways
// and closes, every frame of the edge's on a contract the issuer signed with the sidecar's Service key, held from the
// open until the edge's close has arrived, and the sidecar's own Network stays through it.
func TestPlatformDialStreamCompletesUnderServiceContractsOnTheNet(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	sidecars, _, err := net.AddSubprotocolSidecars("laptop")
	if err != nil {
		t.Fatal(err)
	}
	laptop := sidecars[0]
	laptopClientId := laptop.ClientId()
	laptopManager := laptop.Client().Client.ContractManager()

	// smtpedge's platform client, as EdgeClientPool makes one: Required, reachable from a Service source on 21842
	// alone (ApplySidecarClientSettings), providing Service and nothing else, on a dispatcher in the edge's role.
	// The timeouts are the Net's own clients', for a process with no real network in it.
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
	incomings := make(chan *sidecar.StreamIncoming, 4)
	if _, err := edge.Listen("ur/smtpedge", func(ctx context.Context, incoming *sidecar.StreamIncoming) error {
		incomings <- incoming
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	net.SetContractProvideMode(laptopClientId, edgeClient.ClientId, connectprotocol.ProvideMode_Service)
	net.SetContractProvideMode(edgeClient.ClientId, laptopClientId, connectprotocol.ProvideMode_Service)

	// the sockets service's part: one ticket for the edge's listener, signed with its key
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
			Name:             "ur/smtpedge",
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

	// no tls/ or smtp/ registration: the sidecar provides no Service, and the issuer would sign nothing to it
	if _, ok := laptopManager.GetProvideSecretKey(connectprotocol.ProvideMode_Service); ok {
		t.Fatal("a sidecar with no registration provides Service")
	}

	ctx, cancel := context.WithTimeout(t.Context(), testPlatformDialNetTimeout)
	defer cancel()
	conn, err := dial.Dial(ctx, "ur/smtpedge")
	if err != nil {
		t.Fatal(err)
	}
	incoming := testPlatformDialNetAwait(t, incomings, "the edge's accept")
	if !incoming.Edge || incoming.SourceId != sidecar.Id(laptopClientId) {
		t.Errorf("the edge's incoming %+v", incoming)
	}
	if _, ok := laptopManager.GetProvideSecretKey(connectprotocol.ProvideMode_Service); !ok {
		t.Error("the open stream holds no Service")
	}
	canary := net.Capture().Canary("smtp preamble")
	if _, err := conn.Write(canary); err != nil {
		t.Fatal(err)
	}
	preamble := make([]byte, len(canary))
	if _, err := io.ReadFull(incoming.Stream, preamble); err != nil || string(preamble) != string(canary) {
		t.Fatalf("the edge read %x, %v", preamble, err)
	}
	if _, err := incoming.Stream.Write([]byte("smtp outcome")); err != nil {
		t.Fatal(err)
	}
	outcome := make([]byte, 12)
	if _, err := io.ReadFull(conn, outcome); err != nil || string(outcome) != "smtp outcome" {
		t.Fatalf("the sidecar read %q, %v", outcome, err)
	}

	// the sidecar closes first: the edge's close still arrives, under the key the stream holds until then
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := incoming.Stream.Close(); err != nil {
		t.Fatal(err)
	}
	testPlatformDialNetAwait(t, dial.Released, "the ended stream's release")
	if _, ok := laptopManager.GetProvideSecretKey(connectprotocol.ProvideMode_Service); ok {
		t.Error("the ended stream left Service provided")
	}
	if modes := laptopManager.GetProvideModes(); !modes[connectprotocol.ProvideMode_Network] {
		t.Errorf("the sidecar's own Network went with the hold: %v", modes)
	}
	for _, finding := range net.Capture().Scan() {
		t.Errorf("finding: %+v", finding)
	}
}
