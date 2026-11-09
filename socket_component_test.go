//go:build !sidecar_http && !js

// The sockets component on a generation: its registrar calls POST /socket/registrations through the generation's
// SidecarApi, a SocketHint from the resident's push on topic sock asks for the set at once and hands a forced drain to
// the entry it names, and a generation of another network or with no api is refused.

package sidecar

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

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
	api := newTestSidecarApi(t, newTestSocketsTransport(pages))
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
