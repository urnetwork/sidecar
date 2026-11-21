//go:build !sidecar_http && !js

// The sockets component on a generation: its registrar calls POST /socket/registrations through the generation's
// SidecarApi, a SocketHint from the resident's push on topic sock asks for the set at once and hands a forced drain to
// the entry it names, and a generation of another network or with no api is refused.

package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// A sockets service behind the scripted transport: each page it gets is reported, and every entry is taken.
func newTestSocketsTransport(pages chan<- *SocketRegistrationsArgs) *scriptedApiTransport {
	return &scriptedApiTransport{
		answer: func(request *http.Request, body []byte) (*http.Response, error) {
			args := &SocketRegistrationsArgs{}
			if err := json.Unmarshal(body, args); err != nil {
				return syntheticResponse(request, 400, "{}", nil), nil
			}
			pages <- args
			statuses := make([]string, len(args.Registrations))
			for i := range statuses {
				statuses[i] = `"ok"`
			}
			answer := `{"statuses":[` + strings.Join(statuses, ",") + `],"set_version":1,"server_time":1}`
			return syntheticResponse(request, 200, answer, nil), nil
		},
	}
}

func TestSocketComponentFollowsAGeneration(t *testing.T) {
	pages := make(chan *SocketRegistrationsArgs, 64)
	api, _ := newTestSocketsApi(t, newTestSocketsTransport(pages))
	fixture := newTestSubprotocol(t, nil)
	fetches := make(chan struct{}, 16)
	pushClient, err := newPushClient(t.Context(), &PushClientEnv{
		Subprotocol: fixture.subprotocol,
		Store:       newTestPushStore(),
		Clock:       newTestEnvelopeClock(),
		Log:         NewNoopLogger(),
	}, func(ctx context.Context, cursor []byte) (*protocol.PollResponse, error) {
		fetches <- struct{}{}
		return &protocol.PollResponse{Reset_: &protocol.PushReset{Epoch: 1, Complete: true}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pushClient.Close()
	testSocketAwait(t, fetches, "the push's first resync")

	signer := newTestSocketSigner("a")
	component, err := NewSocketComponent(t.Context(), &SocketComponentArgs{
		NetworkId: testRegistrarNetworkId,
		Settings:  DefaultSidecarSocketSettings(),
		Sign:      signer.sign,
		Clock:     newTestSocketClock(),
		Log:       NewNoopLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer component.Close()
	if component.Name() != "sockets" {
		t.Errorf("name %q", component.Name())
	}
	drained := make(chan struct{}, 4)
	args := testSocketArgs("tls/443/blog")
	args.DrainHinted = func() {
		drained <- struct{}{}
	}
	registration, err := component.socketRegistrar().add(args)
	if err != nil {
		t.Fatal(err)
	}

	identity := &SidecarIdentity{NetworkId: testRegistrarNetworkId, IdentityPublicKey: signer.publicKey()}
	if err := component.Attach(&SidecarEnv{Ctx: t.Context(), SidecarApi: api, Identity: &SidecarIdentity{NetworkId: testSocketId("other network")}}); err == nil {
		t.Errorf("a generation of another network attached")
	}
	if err := component.Attach(&SidecarEnv{Ctx: t.Context(), Identity: identity}); err == nil {
		t.Errorf("a generation with no api attached")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	err = component.Attach(&SidecarEnv{Ctx: ctx, SidecarApi: api, Identity: identity, Subprotocol: fixture.subprotocol, Log: NewNoopLogger()})
	if err != nil {
		t.Fatal(err)
	}
	first := testSocketAwait(t, pages, "the first page")
	if len(first.Registrations) != 1 || first.Registrations[0].Name != "tls/443/blog" {
		t.Fatalf("first page %+v", first)
	}
	if status, err := registration.verdict(t.Context()); err != nil || status != SocketRegistrationStatusOk {
		t.Fatalf("verdict %q, %v", status, err)
	}

	listenId := testSocketId("listen tls/443/blog")
	hint, err := proto.Marshal(&protocol.SocketHint{Kind: protocol.SocketHintKind_SOCKET_HINT_DRAIN, ListenId: listenId.Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	fixture.receive(connect.ControlId, testPushFrame(t, protocol.MessageType_PUSH_HINT, &protocol.PushHint{
		Seq: 1, Topic: PushTopicSock, Version: 5, Kind: uint32(protocol.MessageType_SOCKET_HINT), Hint: hint,
	}), connect.Peer{TransportType: connect.TransportTypeH1})
	testSocketAwait(t, drained, "the forced drain")
	hinted := testSocketAwait(t, pages, "the hint's page")
	if len(hinted.Registrations) != 1 || hinted.SetVersion <= first.SetVersion {
		t.Errorf("the hint's page %+v", hinted)
	}
	admission := component.socketRegistrar().admission()
	if !admission.known {
		t.Errorf("no admission state after an answer")
	}
}

// A sidecar that only dials learns platform ticket keys from the service. A
// restart rebases an old set version, and an idle dialer refreshes rotated keys.
func TestSocketComponentDialsPlatformWithoutListeners(t *testing.T) {
	world := newTestServiceDial(t)
	clock := newTestSocketClock()
	edge := connect.Id(testSocketId("platform network"))
	settings := DefaultSidecarSocketSettings()
	device := newTestSocketSigner("dial-only")
	identity := &SidecarIdentity{
		NetworkId: testRegistrarNetworkId, ClientId: Id(world.sidecar.clientId), IdentityPublicKey: device.publicKey(),
	}
	var pages, finds, keyVersion atomic.Int32
	keyVersion.Store(1)
	var rebase atomic.Bool
	rebase.Store(true)
	api, _ := newTestSocketsApi(t, &scriptedApiTransport{answer: func(request *http.Request, body []byte) (*http.Response, error) {
		keyId := fmt.Sprintf("service-%d", keyVersion.Load())
		key := newTestSocketSigner(keyId)
		now := clock.Now()
		var answer any
		switch request.URL.Path {
		case "/socket/registrations":
			var args SocketRegistrationsArgs
			if err := json.Unmarshal(body, &args); err != nil || len(args.Registrations) != 0 {
				return nil, fmt.Errorf("expected an empty listener set")
			}
			pages.Add(1)
			result := &SocketRegistrationsResult{Statuses: []SocketRegistrationStatus{}, SetVersion: args.SetVersion}
			if rebase.Swap(false) {
				result.Error = &SocketError{Code: SocketErrorCodeStale}
				result.SetVersion += 100
			} else {
				result.ServerTimeMillis = uint64(now.UnixMilli())
				result.UrnetworkEdge = &edge
				result.TicketKeys = []*SocketTicketKey{{
					KeyId: keyId, PublicKey: key.publicKey(), ExpireTimeMillis: uint64(now.Add(settings.HeartbeatInterval).UnixMilli()),
				}}
			}
			answer = result
		case "/socket/find":
			var args SocketFindArgs
			if err := json.Unmarshal(body, &args); err != nil || args.NetworkId == nil || *args.NetworkId != edge || args.Name != "ur/smtpedge" {
				return nil, fmt.Errorf("the lookup did not use the service's edge network")
			}
			ticket := &protocol.SocketTicket{
				TicketId:  testSocketId(fmt.Sprintf("ticket-%d", finds.Add(1))).Bytes(),
				NetworkId: edge.Bytes(), Name: args.Name, ListenerClientId: world.edge.clientId.Bytes(),
				ListenId: testSocketId("smtpedge listener").Bytes(), DialerClientId: identity.ClientId.Bytes(),
				DialerNetworkId: identity.NetworkId.Bytes(), IssueTimeMillis: uint64(now.UnixMilli()),
				ExpireTimeMillis: uint64(now.Add(time.Minute).UnixMilli()),
			}
			signed, err := SignSocketTicket(keyId, key.privateKey, ticket)
			if err != nil {
				return nil, err
			}
			wire, err := proto.Marshal(signed)
			if err != nil {
				return nil, err
			}
			answer = &SocketFindResult{Primary: &SocketFindTicket{Ticket: wire}}
		default:
			return nil, fmt.Errorf("unexpected path %s", request.URL.Path)
		}
		wire, err := json.Marshal(answer)
		return syntheticResponse(request, 200, string(wire), nil), err
	}})
	start := func() *SocketComponent {
		t.Helper()
		component, err := NewSocketComponent(t.Context(), &SocketComponentArgs{
			NetworkId: testRegistrarNetworkId, Settings: settings, Sign: device.sign, Clock: clock, Log: NewNoopLogger(),
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)
		if err := component.Attach(&SidecarEnv{Ctx: ctx, SidecarApi: api, Identity: identity, Subprotocol: world.sidecar.subprotocol}); err != nil {
			component.Close()
			t.Fatal(err)
		}
		t.Cleanup(component.Close)
		return component
	}
	dial := func(component *SocketComponent, wantPages, wantFinds int32) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		conn, err := component.dial(ctx, &SocketAddress{Name: "ur/smtpedge"}, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		incoming := testAwait(t, world.incomings, "smtpedge's incoming stream")
		world.exchange(t, conn, incoming.Stream)
		conn.Close()
		incoming.Stream.Close()
		if pages.Load() != wantPages || finds.Load() != wantFinds {
			t.Fatalf("dial sent %d registration pages and %d finds", pages.Load(), finds.Load())
		}
	}
	first := start()
	dial(first, 2, 1)
	dial(first, 2, 2)
	// Find can start signing with an overlapping new key before the cached metadata ages out.
	keyVersion.Store(2)
	dial(first, 3, 3)
	clock.advance(settings.HeartbeatInterval)
	keyVersion.Store(3)
	dial(first, 4, 4)
	first.Close()
	rebase.Store(true)
	dial(start(), 6, 5)
}
