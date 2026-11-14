//go:build !sidecar_http && !ios_extension && !js

// The tls component on a generation: its manager reads GET /tls/certs through the generation's SidecarApi, a TlsHint
// from the resident's push on topic tls reads again, and a generation of another network or with no api is refused.
// And §13.15's four routes as SidecarApi sends them: the order routes under the service token, never the client's.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

func TestTlsComponentFollowsAGeneration(t *testing.T) {
	fixture := newTlsCertFixture(t)
	fixture.manager.Close()
	reads := make(chan *http.Request, 64)
	transport := &scriptedApiTransport{
		answer: func(request *http.Request, body []byte) (*http.Response, error) {
			if request.Method != "GET" || request.URL.Path != "/tls/certs" {
				return syntheticResponse(request, 404, "{}", nil), nil
			}
			reads <- request
			return syntheticResponse(request, 200, `{"certs":[]}`, nil), nil
		},
	}
	api := newTestSidecarApi(t, transport)
	subprotocolFixture := newTestSubprotocol(t, nil)
	fetches := make(chan struct{}, 16)
	pushClient, err := newPushClient(t.Context(), &PushClientEnv{
		Subprotocol: subprotocolFixture.subprotocol,
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

	var source TlsCertificateSource
	component, err := NewTlsComponent(t.Context(), &TlsComponentArgs{
		Manager: &TlsCertManagerArgs{
			NetworkId: fixture.networkId,
			SidecarId: fixture.sidecarId,
			Settings:  fixture.settings,
			Keys:      fixture.keys,
			Sign:      testTlsSign(fixture.identity, fixture.sidecarId[:]),
			ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
				return "synthetic-service-token", nil
			},
			Names: fixture.names,
			Store: fixture.store,
			Clock: fixture.clock,
			Log:   NewNoopLogger(),
		},
		SetSource: func(installed TlsCertificateSource) error {
			source = installed
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if component.Name() != "tls" || component.Name() != tlsSecretsNamespace {
		t.Errorf("name %q", component.Name())
	}
	// the manager answers TlsDeviceCertificate from the moment the component exists
	if source != TlsCertificateSource(component.CertManager()) {
		t.Errorf("the manager is not installed as the certificate source")
	}

	identity := &SidecarIdentity{NetworkId: fixture.networkId, SidecarId: fixture.sidecarId}
	if err := component.Attach(&SidecarEnv{Ctx: t.Context(), SidecarApi: api, Identity: &SidecarIdentity{NetworkId: tlsCertTestId("other network")}}); err == nil {
		t.Errorf("a generation of another network attached")
	}
	if err := component.Attach(&SidecarEnv{Ctx: t.Context(), Identity: identity}); err == nil {
		t.Errorf("a generation with no api attached")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	err = component.Attach(&SidecarEnv{Ctx: ctx, SidecarApi: api, Identity: identity, Subprotocol: subprotocolFixture.subprotocol, Log: NewNoopLogger()})
	if err != nil {
		t.Fatal(err)
	}
	// the attachment's own pass reads the rows, with the client's token
	first := testSocketAwait(t, reads, "the attachment's read")
	if authorization := first.Header.Get("Authorization"); authorization != "Bearer "+testByJwt {
		t.Errorf("GET /tls/certs was not sent under the client token")
	}
	fixture.clock.awaitTimer(t, fixture.settings.CertHintMinInterval)
	fixture.clock.advance(fixture.settings.CertHintMinInterval)
	fixture.clock.awaitTimer(t, fixture.settings.CertResyncInterval)

	// a hint on topic tls reads them again at once
	certId := NewId()
	hint, err := proto.Marshal(&protocol.TlsHint{Kind: protocol.TlsHintKind_TLS_HINT_ISSUED, CertId: certId.Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	subprotocolFixture.receive(connect.ControlId, testPushFrame(t, protocol.MessageType_PUSH_HINT, &protocol.PushHint{
		Seq: 1, Topic: PushTopicTls, Version: 5, Kind: uint32(protocol.MessageType_TLS_HINT), Hint: hint,
	}), connect.Peer{TransportType: connect.TransportTypeH1})
	testSocketAwait(t, reads, "the hint's read")

	// the generation's end takes its api back: the next pass is offline
	fixture.clock.awaitTimer(t, fixture.settings.CertHintMinInterval)
	cancel()
	ended := func() chan struct{} {
		component.stateLock.Lock()
		defer component.stateLock.Unlock()
		return component.generationEnded
	}()
	<-ended
	if err := component.CertManager().Sync(t.Context()); !errors.Is(err, ErrTlsCertsOffline) {
		t.Errorf("a pass after the generation ended: %v", err)
	}
	component.Close()
	if source != nil {
		t.Errorf("a closed component is still the certificate source")
	}
}

func TestSidecarWithNoTlsComponentRefuses(t *testing.T) {
	sidecar := newTestSidecar(t)
	if _, err := sidecar.EnsureTlsCertificate(t.Context()); !errors.Is(err, ErrTlsComponentAbsent) {
		t.Errorf("ensure: %v", err)
	}
	if certificates := sidecar.TlsCertificates(); len(certificates) != 0 {
		t.Errorf("certificates %v", certificates)
	}
	if _, err := sidecar.TlsSignLabelReclaim(t.Context(), "abcdefghij.sidecar.example", NewId()); !errors.Is(err, ErrTlsComponentAbsent) {
		t.Errorf("reclaim: %v", err)
	}
	if _, err := NewTlsComponent(t.Context(), nil); !errors.Is(err, errInvalidSettings) {
		t.Errorf("a component with no args: %v", err)
	}
}

func TestSidecarApiTlsRoutes(t *testing.T) {
	const serviceToken = "synthetic-certs-service-token"
	certId := NewId()
	transport := &scriptedApiTransport{
		answer: func(request *http.Request, body []byte) (*http.Response, error) {
			switch request.Method + " " + request.URL.Path {
			case "POST /tls/cert-order":
				return syntheticResponse(request, 200, `{"cert_id":"`+certId.String()+`","state":"queued","retry_after_ms":250}`, nil), nil
			case "GET /tls/cert-order/" + certId.String():
				return syntheticResponse(request, 200, `{"state":"ordering","retry_after_ms":500}`, nil), nil
			case "GET /tls/certs":
				return syntheticResponse(request, 200, `{"certs":[{"cert_id":"`+certId.String()+`","state":"custom_issued"}]}`, nil), nil
			case "POST /tls/cert-revoke":
				return syntheticResponse(request, 200, `{}`, nil), nil
			}
			return syntheticResponse(request, 404, `{}`, nil), nil
		},
	}
	api := newTestSidecarApi(t, transport)
	settings := validSidecarSettings()

	order, err := api.TlsCertOrder(t.Context(), serviceToken, &TlsCertOrderArgs{Csr: []byte("csr"), Attestation: []byte("attestation"), Replaces: "aki.serial"})
	if err != nil || order.CertId != certId || order.State != TlsCertStateQueued || order.RetryAfterMs != 250 {
		t.Fatalf("order %+v, %v", order, err)
	}
	status, err := api.TlsCertOrderStatus(t.Context(), serviceToken, certId)
	if err != nil || status.State != TlsCertStateOrdering || status.RetryAfterMs != 500 {
		t.Fatalf("status %+v, %v", status, err)
	}
	certs, err := api.TlsCerts(t.Context())
	if err != nil || len(certs.Certs) != 1 || certs.Certs[0].State != TlsCertStateCustomIssued {
		t.Fatalf("certs %+v, %v", certs, err)
	}
	if err := api.TlsCertRevoke(t.Context(), &TlsCertRevokeArgs{CertId: certId, KeyCompromise: true}); err != nil {
		t.Fatal(err)
	}

	transport.stateLock.Lock()
	requests := transport.requests
	bodies := transport.bodies
	transport.stateLock.Unlock()
	if len(requests) != 4 {
		t.Fatalf("%d requests", len(requests))
	}
	// the order routes carry the service token and never the client's; the other two the client's
	wantBearers := []string{serviceToken, serviceToken, testByJwt, testByJwt}
	for index, request := range requests {
		if authorization := request.Header.Get("Authorization"); authorization != "Bearer "+wantBearers[index] {
			t.Errorf("request %d (%s %s) carries another token", index, request.Method, request.URL.Path)
		}
		if request.URL.Scheme+"://"+request.URL.Host != settings.ApiUrl {
			t.Errorf("request %d went to another origin", index)
		}
	}
	sent := &TlsCertOrderArgs{}
	if err := json.Unmarshal(bodies[0], sent); err != nil || string(sent.Csr) != "csr" || string(sent.Attestation) != "attestation" || sent.Replaces != "aki.serial" {
		t.Errorf("the order's body %s", bodies[0])
	}
	revoked := &TlsCertRevokeArgs{}
	if err := json.Unmarshal(bodies[3], revoked); err != nil || revoked.CertId != certId || !revoked.KeyCompromise {
		t.Errorf("the revocation's body %s", bodies[3])
	}

	// refused before sending: no token, no CSR, no id
	for _, refuse := range []func() error{
		func() error {
			_, err := api.TlsCertOrder(t.Context(), "", &TlsCertOrderArgs{Csr: []byte("csr"), Attestation: []byte("attestation")})
			return err
		},
		func() error {
			_, err := api.TlsCertOrder(t.Context(), serviceToken, &TlsCertOrderArgs{Attestation: []byte("attestation")})
			return err
		},
		func() error {
			_, err := api.TlsCertOrderStatus(t.Context(), serviceToken, Id{})
			return err
		},
		func() error {
			return api.TlsCertRevoke(t.Context(), &TlsCertRevokeArgs{})
		},
	} {
		if err := refuse(); !errors.Is(err, ErrSidecarApiArgs) {
			t.Errorf("a call that cannot be one: %v", err)
		}
	}
	// a refusal is the route's error, with its status
	missing, err := api.TlsCertOrderStatus(t.Context(), serviceToken, NewId())
	if apiErr := asSidecarApiError(t, err); missing != nil || apiErr.Status != 404 || apiErr.Route != tlsCertOrderStatusRoute {
		t.Errorf("a missing order: %v", err)
	}
}

func TestSidecarApiTlsRoutesRefuseAnAnswerThatIsNotTheRoutes(t *testing.T) {
	transport := &scriptedApiTransport{
		answer: func(request *http.Request, body []byte) (*http.Response, error) {
			switch request.Method + " " + request.URL.Path {
			case "POST /tls/cert-order":
				return syntheticResponse(request, 200, `{"state":"queued"}`, nil), nil
			case "GET /tls/certs":
				return syntheticResponse(request, 200, `{"certs":[{"state":"issued"}]}`, nil), nil
			}
			return syntheticResponse(request, 200, `{}`, nil), nil
		},
	}
	api := newTestSidecarApi(t, transport)
	if _, err := api.TlsCertOrder(t.Context(), "token", &TlsCertOrderArgs{Csr: []byte("csr"), Attestation: []byte("attestation")}); !errors.Is(err, ErrSidecarApiReply) {
		t.Errorf("an order's answer with no row: %v", err)
	}
	if _, err := api.TlsCertOrderStatus(t.Context(), "token", NewId()); !errors.Is(err, ErrSidecarApiReply) {
		t.Errorf("a status with no state: %v", err)
	}
	if _, err := api.TlsCerts(t.Context()); !errors.Is(err, ErrSidecarApiReply) {
		t.Errorf("a row with no id: %v", err)
	}
}
