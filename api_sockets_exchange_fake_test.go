//go:build !sidecar_http && !js

// QD-1029 end to end on T2: the sidecar's own route code, SidecarApi.SocketList, exchanges its client token at
// sidecartest's fake api for a service token of audience sockets and presents it to a sockets engine whose host
// authenticates service tokens as server's block does (the fake api's authenticator, which takes only the tokens the
// fake's exchange issued, for the audience each names): the engine admits the call, and refuses the client token
// itself and an evs token presented in its place, each 401. Fake clock throughout.

package sidecar_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/socketsservice"
)

// A transport that hands every request for host to handler and every other to next.
type socketsExchangeRouteTransport struct {
	host    string
	handler http.Handler
	next    http.RoundTripper
}

func (self *socketsExchangeRouteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Host != self.host {
		return self.next.RoundTrip(request)
	}
	recorder := httptest.NewRecorder()
	self.handler.ServeHTTP(recorder, request)
	response := recorder.Result()
	response.Request = request
	return response, nil
}

// One GET /socket/list at handler with bearer as its Authorization, its status.
func socketsExchangeListStatus(t *testing.T, handler http.Handler, url string, bearer string) int {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, url+"/socket/list", nil)
	request.Header.Set("Authorization", "Bearer "+bearer)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder.Code
}

func TestSocketCallsExchangeForASocketsToken(t *testing.T) {
	var engine *socketsservice.SocketsService
	var socketsUrl string
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		engine.Handler().ServeHTTP(writer, request)
	})
	world := newExchangeFakeWorldWith(t, 0, func(transport http.RoundTripper) http.RoundTripper {
		return &socketsExchangeRouteTransport{host: "sockets.sidecartest.example", handler: handler, next: transport}
	})
	socketsUrl = world.settings.SocketsUrl

	ctx, cancel := context.WithCancel(world.ctx)
	t.Cleanup(cancel)
	host := sidecartest.NewFakeHost(ctx, world.clock, nil, nil, nil)
	if err := host.Gates.Set("sidecar:\n  sockets: {enabled: true, percent: 100}\n"); err != nil {
		t.Fatal(err)
	}
	serviceHost := host.ServiceHost()
	// server's block verifies service tokens of the exchange's issuer: here the fake api's
	serviceHost.Authenticator = world.api.Authenticator()
	store := sidecartest.NewFakeSocketStore(world.clock, nil, nil)
	// GET /socket/list asks the gate nothing (socketsservice/list.go)
	var err error
	engine, err = socketsservice.NewSocketsService(ctx, serviceHost, store, socketsservice.ClosedSocketGate{}, socketsservice.DefaultSocketsSettings())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)

	result, err := world.client.SocketList(world.ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Error != nil || result.Names == nil {
		t.Fatalf("the sidecar's call: %+v", result.Error)
	}

	// the client token itself, and an evs token, are no sockets tokens
	clientToken := world.api.ClientToken(sidecar.NewId(), world.clientId, world.sidecarId)
	if status := socketsExchangeListStatus(t, handler, socketsUrl, clientToken); status != http.StatusUnauthorized {
		t.Errorf("the client token answered %d", status)
	}
	evsToken, err := world.client.ExchangeToken(world.ctx, world.settings.EvsUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	if status := socketsExchangeListStatus(t, handler, socketsUrl, evsToken.AccessToken); status != http.StatusUnauthorized {
		t.Errorf("an evs token answered %d", status)
	}
	socketsToken, err := world.client.ExchangeToken(world.ctx, socketsUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	if status := socketsExchangeListStatus(t, handler, socketsUrl, socketsToken.AccessToken); status != http.StatusOK {
		t.Errorf("a sockets token answered %d", status)
	}
}
