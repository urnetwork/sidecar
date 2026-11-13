//go:build !sidecar_http && !js

// A sidecar whose clock is 10 min off against T2's fake api (sidecartest.FakeApi), which holds a DPoP proof's iat
// within §7.4's 60 s of its own clock and each jti once (QD-757): SidecarApi's real requests at the three routes that
// carry a proof, GET /auth/refresh, POST /oauth/token and POST /network/auth-client, each refused once on the device's
// own clock and taken on the api's, and a proof replayed still refused. Fake clock throughout.

package sidecar_test

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

// One request as it went out, and the status it was answered with.
type recordedApiRequest struct {
	method string
	url    string
	header http.Header
	body   []byte
	status int
}

// Records each request through transport.
type recordingApiTransport struct {
	transport http.RoundTripper

	stateLock sync.Mutex
	requests  []*recordedApiRequest
}

func (self *recordingApiTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	recorded := &recordedApiRequest{method: request.Method, url: request.URL.String(), header: request.Header.Clone()}
	if request.Body != nil {
		body, err := io.ReadAll(request.Body)
		request.Body.Close()
		if err != nil {
			return nil, err
		}
		recorded.body = body
		request.Body = io.NopCloser(bytes.NewReader(body))
	}
	response, err := self.transport.RoundTrip(request)
	if err == nil {
		recorded.status = response.StatusCode
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.requests = append(self.requests, recorded)
	return response, err
}

// The requests recorded since the last take.
func (self *recordingApiTransport) take() []*recordedApiRequest {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	requests := self.requests
	self.requests = nil
	return requests
}

// Sends recorded again, byte for byte, and answers its status.
func (self *recordingApiTransport) replay(t *testing.T, recorded *recordedApiRequest) int {
	t.Helper()
	request, err := http.NewRequest(recorded.method, recorded.url, bytes.NewReader(recorded.body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header = recorded.header.Clone()
	response, err := self.transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	return response.StatusCode
}

// A world whose client's clock runs deviceOffset from the api's, its requests recorded.
func newSkewedExchangeFakeWorld(t *testing.T, deviceOffset time.Duration) (*exchangeFakeWorld, *recordingApiTransport) {
	t.Helper()
	recorder := &recordingApiTransport{}
	world := newExchangeFakeWorldWith(t, deviceOffset, func(transport http.RoundTripper) http.RoundTripper {
		recorder.transport = transport
		return recorder
	})
	return world, recorder
}

// The statuses of requests, in order.
func recordedStatuses(requests []*recordedApiRequest) []int {
	statuses := []int{}
	for _, request := range requests {
		statuses = append(statuses, request.status)
	}
	return statuses
}

// A client 10 min fast or slow exchanges at POST /oauth/token under the api's 60 s window: its first proof, on its
// own clock, is refused, the refusal gives the api's clock, and the second is taken. The next exchange is one
// request. The taken proof sent again is refused: its jti is spent.
func TestSkewedSidecarApiExchangesWithTheFakeApi(t *testing.T) {
	for _, deviceOffset := range []time.Duration{10 * time.Minute, -10 * time.Minute} {
		world, recorder := newSkewedExchangeFakeWorld(t, deviceOffset)
		serviceToken, err := world.client.ExchangeToken(world.ctx, world.settings.EvsUrl, nil)
		if err != nil {
			t.Errorf("device %s: %v", deviceOffset, err)
			continue
		}
		principal, err := world.api.Authenticator().Authenticate(world.ctx, "evs", serviceToken.AccessToken)
		if err != nil || principal.ClientId != connect.Id(world.clientId) {
			t.Errorf("device %s: the token: %v", deviceOffset, err)
		}
		requests := recorder.take()
		if statuses := recordedStatuses(requests); len(statuses) != 2 || statuses[0] != http.StatusBadRequest || statuses[1] != http.StatusOK {
			t.Errorf("device %s: answers %v", deviceOffset, statuses)
			continue
		}
		if requests[0].header.Get("DPoP") == requests[1].header.Get("DPoP") {
			t.Errorf("device %s: the second request carried the first's proof", deviceOffset)
		}
		if status := recorder.replay(t, requests[1]); status != http.StatusBadRequest {
			t.Errorf("device %s: the taken proof replayed answered %d", deviceOffset, status)
		}

		world.clock.Advance(time.Minute)
		if _, err := world.client.ExchangeToken(world.ctx, world.settings.GkmUrl, nil); err != nil {
			t.Errorf("device %s: the next exchange: %v", deviceOffset, err)
		}
		if statuses := recordedStatuses(recorder.take()); len(statuses) != 1 || statuses[0] != http.StatusOK {
			t.Errorf("device %s: the next exchange's answers %v", deviceOffset, statuses)
		}
	}
}

// The same client mints a child at POST /network/auth-client, whose proof the strict_exp gate checks: refused once,
// 403, then taken, and the taken request sent again is refused 403 and mints nothing.
func TestSkewedSidecarApiMintsAChildWithTheFakeApi(t *testing.T) {
	for _, deviceOffset := range []time.Duration{10 * time.Minute, -10 * time.Minute} {
		world, recorder := newSkewedExchangeFakeWorld(t, deviceOffset)
		sourceClientId := world.clientId
		minted, err := world.client.AuthClient(world.ctx, &sidecar.SidecarAuthClientArgs{SourceClientId: &sourceClientId, DeviceSpec: "synthetic"})
		if err != nil {
			t.Errorf("device %s: %v", deviceOffset, err)
			continue
		}
		if _, clientId, _, ok := world.api.TokenClient(minted.ByClientJwt); !ok || clientId != minted.ClientId || !minted.StrictExp {
			t.Errorf("device %s: the child's token names %s (%v), strict_exp %v", deviceOffset, clientId, ok, minted.StrictExp)
		}
		requests := recorder.take()
		if statuses := recordedStatuses(requests); len(statuses) != 2 || statuses[0] != http.StatusForbidden || statuses[1] != http.StatusOK {
			t.Errorf("device %s: answers %v", deviceOffset, statuses)
			continue
		}
		if status := recorder.replay(t, requests[1]); status != http.StatusForbidden {
			t.Errorf("device %s: the taken proof replayed answered %d", deviceOffset, status)
		}
		if count := world.api.RouteCount("POST /network/auth-client"); count != 3 {
			t.Errorf("device %s: %d requests reached the route", deviceOffset, count)
		}
	}
}

// And renews at GET /auth/refresh: refused once at the proof gate, 403, then past it. This world's client has posted
// no binding, so what lies past the gate is the 200 that asks it to re-register, restore_required, which no request
// with a refused proof reaches; a bound sidecar's whole renewal runs in sidecartest/fault's skew row.
func TestSkewedSidecarApiRefreshPassesTheProofGateOfTheFakeApi(t *testing.T) {
	for _, deviceOffset := range []time.Duration{10 * time.Minute, -10 * time.Minute} {
		world, recorder := newSkewedExchangeFakeWorld(t, deviceOffset)
		_, err := world.client.Refresh(world.ctx)
		apiErr := &sidecar.SidecarApiError{}
		if !errors.As(err, &apiErr) || apiErr.Status != http.StatusOK || apiErr.Code != sidecar.SidecarApiCodeRestoreRequired {
			t.Errorf("device %s: %v", deviceOffset, err)
		}
		requests := recorder.take()
		if statuses := recordedStatuses(requests); len(statuses) != 2 || statuses[0] != http.StatusForbidden || statuses[1] != http.StatusOK {
			t.Errorf("device %s: answers %v", deviceOffset, statuses)
			continue
		}
		if status := recorder.replay(t, requests[1]); status != http.StatusForbidden {
			t.Errorf("device %s: the taken proof replayed answered %d", deviceOffset, status)
		}
	}
}

// The window stands: a proof signed 10 min off is refused wherever the client cannot read the api's clock, as behind
// a transport that strips Date, and nothing is sent twice on a guess.
func TestSkewedSidecarApiWithNoDateStaysRefused(t *testing.T) {
	for _, deviceOffset := range []time.Duration{10 * time.Minute, -10 * time.Minute} {
		recorder := &recordingApiTransport{}
		world := newExchangeFakeWorldWith(t, deviceOffset, func(transport http.RoundTripper) http.RoundTripper {
			recorder.transport = dateStrippingTransport{transport: transport}
			return recorder
		})
		if _, err := world.client.ExchangeToken(world.ctx, world.settings.EvsUrl, nil); exchangeRefusalCode(err) != "invalid_dpop_proof" {
			t.Errorf("device %s: %v", deviceOffset, err)
		}
		if statuses := recordedStatuses(recorder.take()); len(statuses) != 1 {
			t.Errorf("device %s: answers %v", deviceOffset, statuses)
		}
	}
}

// Drops Date from every answer, as a page Worker's fetch does for an origin that does not expose it.
type dateStrippingTransport struct {
	transport http.RoundTripper
}

func (self dateStrippingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := self.transport.RoundTrip(request)
	if err == nil {
		response.Header.Del("Date")
	}
	return response, err
}
