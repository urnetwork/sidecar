//go:build sidecar_http

package sidecar

// CORE-M4-01 on the sidecar_http leg, the page Worker's: NewSidecar with no components runs a generation that is §6.8's
// long-poll, carrying core; the keychain opens from the host's key store; the refresher sends its DPoP proof; and a poll
// a 401 ends asks for a refresh and polls again on the new token. Run under Node by sidecartest/legs, or by hand with
// go_js_wasm_exec. api is a RoundTripper in the test, since net/http has no socket here.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// How long a test waits for what it expects: only a broken run's bound.
const httpSidecarTestTimeout = 30 * time.Second

// api as the page Worker's tests script it: polls answer from a queue and otherwise hold until their request ends, as
// api's 25 s hold does; refresh answers the next token; every request's bearer and proof are kept.
type httpTestApi struct {
	networkId Id
	clientId  Id
	deviceId  string
	// polls answer these, in order: a PollResponse, or an int status
	pollAnswers chan any

	stateLock sync.Mutex
	// each request's path and bearer, in order
	requests []httpTestRequest
	// the token refresh answers next, empty for a 401
	refreshByJwt string
	refreshCount int
	changes      *MonitorValue[int]
}

// One request api saw.
type httpTestRequest struct {
	path   string
	bearer string
	dpop   string
}

func newHttpTestApi(networkId Id, clientId Id) *httpTestApi {
	return &httpTestApi{
		networkId:   networkId,
		clientId:    clientId,
		deviceId:    NewId().String(),
		pollAnswers: make(chan any, 16),
		changes:     NewMonitorValue(0),
	}
}

// A client token of the api's client, issued at iat for lifetime, with its own jti.
func (self *httpTestApi) token(iat time.Time, lifetime time.Duration) string {
	return testClientJwt(fmt.Sprintf(`{"jti":%q,"iat":%d,"exp":%d,"network_id":%q,"client_id":%q,"device_id":%q}`,
		NewId().String(), iat.Unix(), iat.Add(lifetime).Unix(), self.networkId, self.clientId, self.deviceId))
}

func (self *httpTestApi) record(request *http.Request) {
	self.stateLock.Lock()
	self.requests = append(self.requests, httpTestRequest{
		path:   request.URL.Path,
		bearer: strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer "),
		dpop:   request.Header.Get("DPoP"),
	})
	self.stateLock.Unlock()
	self.changes.Update(func(count int) int { return count + 1 })
}

// The requests so far.
func (self *httpTestApi) requestsSoFar() []httpTestRequest {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]httpTestRequest{}, self.requests...)
}

// Waits until the requests satisfy want.
func (self *httpTestApi) await(t *testing.T, want func(requests []httpTestRequest) bool) []httpTestRequest {
	t.Helper()
	deadline := time.After(httpSidecarTestTimeout)
	for {
		_, changed := self.changes.Get()
		requests := self.requestsSoFar()
		if want(requests) {
			return requests
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("api saw only %+v", requests)
		}
	}
}

func (self *httpTestApi) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Body != nil {
		request.Body.Close()
	}
	self.record(request)
	respond := func(status int, contentType string, body []byte) *http.Response {
		return &http.Response{
			StatusCode: status,
			Header:     http.Header{"Content-Type": {contentType}},
			Body:       io.NopCloser(bytes.NewReader(body)),
			Request:    request,
		}
	}
	respondPoll := func(response *protocol.PollResponse) (*http.Response, error) {
		body, err := proto.Marshal(response)
		if err != nil {
			return nil, err
		}
		return respond(http.StatusOK, "application/octet-stream", body), nil
	}
	switch request.URL.Path {
	case "/sidecar/sync/poll":
		select {
		case answer := <-self.pollAnswers:
			switch answer := answer.(type) {
			case *protocol.PollResponse:
				return respondPoll(answer)
			case int:
				body, _ := json.Marshal(map[string]any{"error": "refused", "code": "unauthorized"})
				return respond(answer, "application/json", body), nil
			}
			return nil, errors.New("a poll answer of no known kind")
		case <-request.Context().Done():
			return nil, request.Context().Err()
		}
	case "/sidecar/sync/versions":
		return respondPoll(&protocol.PollResponse{Reset_: &protocol.PushReset{Epoch: 1, Complete: true}})
	case "/auth/refresh":
		self.stateLock.Lock()
		byJwt := self.refreshByJwt
		self.refreshCount += 1
		self.stateLock.Unlock()
		if byJwt == "" {
			body, _ := json.Marshal(map[string]any{"error": "refused", "code": "unauthorized"})
			return respond(http.StatusUnauthorized, "application/json", body), nil
		}
		body, _ := json.Marshal(map[string]any{"by_jwt": byJwt})
		return respond(http.StatusOK, "application/json", body), nil
	}
	body, _ := json.Marshal(map[string]any{"error": "no such route", "code": "not_found"})
	return respond(http.StatusNotFound, "application/json", body), nil
}

// A host whose store is the instance's and that gives no token source, as the page Worker's does.
type httpTestHost struct {
	store       SidecarStore
	keyStore    SidecarKeyStore
	tokenSource SidecarTokenSource
}

func (self *httpTestHost) Store() SidecarStore                                { return self.store }
func (self *httpTestHost) KeyStore() SidecarKeyStore                          { return self.keyStore }
func (self *httpTestHost) TokenSource() SidecarTokenSource                    { return self.tokenSource }
func (self *httpTestHost) HostCredentialStores() []SidecarHostCredentialStore { return nil }

// An instance on the memory backend, opened from a key store as the page Worker's WebCrypto key opens it, holding an
// enrollment of generation 1 whose token api issued at iat for lifetime.
func newHttpTestEnrollment(t *testing.T, iat time.Time, lifetime time.Duration) (*SidecarInstance, *fakeKeyStore, *httpTestApi) {
	t.Helper()
	keyStore := newFakeKeyStore()
	instance := newInstanceOn(t, NewSidecarMemoryBackend(), keyStore)
	if err := instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	networkId := NewId()
	sidecarId := NewId()
	clientId := NewId()
	if _, err := instance.createKeychain(networkId); err != nil {
		t.Fatal(err)
	}
	secrets := instance.secrets(networkId, sidecarCoreSecretsNamespace)
	keys, err := newSidecarIdentityKeys(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signedBinding, err := NewSidecarIdentityBinding(&SidecarIdentityBinding{
		NetworkId:  networkId,
		SidecarId:  sidecarId,
		ClientId:   clientId,
		Generation: 1,
		IssuedAt:   iat,
	}, keys.identitySeed, keys.clientKeySeed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistSidecarIdentity(secrets, keys, signedBinding); err != nil {
		t.Fatal(err)
	}
	api := newHttpTestApi(networkId, clientId)
	if err := persistSidecarByJwt(secrets, api.token(iat, lifetime)); err != nil {
		t.Fatal(err)
	}
	if err := instance.RecordNetwork(SidecarNetworkRecord{
		NetworkId:         networkId,
		ClientId:          clientId,
		SidecarId:         sidecarId,
		ConnectInstanceId: NewId(),
	}); err != nil {
		t.Fatal(err)
	}
	return instance, keyStore, api
}

// The page Worker's Sidecar on api, closed at the test's end.
func newHttpTestSidecar(t *testing.T, instance *SidecarInstance, keyStore SidecarKeyStore, api *httpTestApi) *Sidecar {
	t.Helper()
	networkId := api.networkId
	sidecar, err := newHttpSidecar(context.Background(), &httpTestHost{store: instance.Store(&networkId), keyStore: keyStore}, cheapKeychainSettings(), api)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), httpSidecarTestTimeout)
		defer cancel()
		if err := sidecar.CloseAndWait(ctx); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return sidecar
}

// Waits until the sidecar's status satisfies want, re-reading at each event.
func awaitHttpSidecarStatus(t *testing.T, sidecar *Sidecar, want func(status SidecarStatus) bool) SidecarStatus {
	t.Helper()
	events := NewMonitorValue(0)
	remove := sidecar.AddEventCallback(func(event SidecarEvent) {
		events.Update(func(count int) int { return count + 1 })
	})
	defer remove()
	deadline := time.After(httpSidecarTestTimeout)
	for {
		_, changed := events.Get()
		status := sidecar.Status()
		if want(status) {
			return status
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("status stayed %+v", status)
		}
	}
}

// A poll answering a complete reset that names core, and a core hint of kind resync after it.
func httpTestCorePoll(t *testing.T) *protocol.PollResponse {
	t.Helper()
	hint, err := proto.Marshal(&protocol.CoreHint{Kind: protocol.CoreHintKind_CORE_HINT_KIND_RESYNC})
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.PollResponse{
		Cursor: []byte("cursor-1"),
		Reset_: &protocol.PushReset{Epoch: 1, Complete: true, Versions: []*protocol.TopicVersion{{Topic: PushTopicCore, Version: 1}}},
		Hints:  []*protocol.PushHint{{Seq: 1, Topic: PushTopicCore, Version: 2, Kind: 0x1A01, Hint: hint}},
	}
}

// The page Worker's NewSidecar takes no component and no host token source.
func TestHttpSidecarRefusesATokenSource(t *testing.T) {
	instance, keyStore, api := newHttpTestEnrollment(t, time.Now(), 7*24*time.Hour)
	networkId := api.networkId
	host := &httpTestHost{store: instance.Store(&networkId), keyStore: keyStore, tokenSource: &testHttpTokenSource{}}
	if _, err := newHttpSidecar(context.Background(), host, cheapKeychainSettings(), api); !errors.Is(err, errInvalidSettings) {
		t.Errorf("err %v", err)
	}
}

// A token source a host might wrongly bring.
type testHttpTokenSource struct{}

func (self *testHttpTokenSource) ByJwt() (string, error) {
	return "", errors.New("none")
}

func (self *testHttpTokenSource) AddByJwtCallback(callback func(byJwt string)) func() {
	return func() {}
}

// The keychain opens from the host's key store, the generation is the long-poll, Online once a poll answers, and core
// rides it: the hint reaches the core, which counts it.
func TestHttpSidecarCarriesCoreOnTheLongPoll(t *testing.T) {
	instance, keyStore, api := newHttpTestEnrollment(t, time.Now(), 7*24*time.Hour)
	instance.Lock()
	sidecar := newHttpTestSidecar(t, instance, keyStore, api)
	awaitHttpSidecarStatus(t, sidecar, func(status SidecarStatus) bool { return status.State == SidecarStateLocked })
	if err := sidecar.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	awaitHttpSidecarStatus(t, sidecar, func(status SidecarStatus) bool {
		return status.State == SidecarStateOffline && status.Generation == 1
	})
	// the poll, beside the versions refetch a client with no versions starts with (§6.8)
	api.await(t, func(requests []httpTestRequest) bool {
		for _, request := range requests {
			if request.path == "/sidecar/sync/poll" {
				return true
			}
		}
		return false
	})
	api.pollAnswers <- httpTestCorePoll(t)
	awaitHttpSidecarStatus(t, sidecar, func(status SidecarStatus) bool {
		return status.State == SidecarStateOnline && status.Generation == 1
	})
	// the poll loop applies a reply, its notices delivered, before it polls again
	api.await(t, func(requests []httpTestRequest) bool {
		polls := 0
		for _, request := range requests {
			if request.path == "/sidecar/sync/poll" {
				polls += 1
			}
		}
		return 2 <= polls
	})
	if sidecar.Stats().CoreHintCount == 0 {
		t.Error("the core hint never reached the core")
	}
}

// A token due for refresh is refreshed with the ClientKey's DPoP proof, and the polls after carry the new token.
func TestHttpSidecarRefreshesWithDpop(t *testing.T) {
	now := time.Now()
	// past the 0.5 point of its life, so the refresher's first look finds it due
	instance, keyStore, api := newHttpTestEnrollment(t, now.Add(-6*24*time.Hour), 7*24*time.Hour)
	next := api.token(now, 7*24*time.Hour)
	api.stateLock.Lock()
	api.refreshByJwt = next
	api.stateLock.Unlock()
	newHttpTestSidecar(t, instance, keyStore, api)

	// The refresher and the poll loop start together, so the first poll may leave on the old token before the refresh
	// lands, and a long poll holds until it is answered. Each such poll is answered once, so the loop polls again on
	// the token then in force.
	answeredPolls := 0
	requests := api.await(t, func(requests []httpTestRequest) bool {
		oldPolls := 0
		for _, request := range requests {
			if request.path == "/sidecar/sync/poll" {
				if request.bearer == next {
					return true
				}
				oldPolls += 1
			}
		}
		for ; answeredPolls < oldPolls; answeredPolls += 1 {
			api.pollAnswers <- httpTestCorePoll(t)
		}
		return false
	})
	refreshed := false
	for _, request := range requests {
		if request.path == "/auth/refresh" {
			refreshed = true
			if request.dpop == "" {
				t.Error("the refresh carries no DPoP proof")
			}
			if request.bearer == next {
				t.Error("the refresh presents the new token")
			}
		}
	}
	if !refreshed {
		t.Error("no refresh")
	}
}

// A poll answering 401 is the token refused: the generation asks for a refresh, and polls again on the new token.
func TestHttpPollRefusedRefreshesAndPollsAgain(t *testing.T) {
	now := time.Now()
	instance, keyStore, api := newHttpTestEnrollment(t, now, 7*24*time.Hour)
	next := api.token(now, 7*24*time.Hour)
	api.stateLock.Lock()
	api.refreshByJwt = next
	api.stateLock.Unlock()
	api.pollAnswers <- http.StatusUnauthorized
	sidecar := newHttpTestSidecar(t, instance, keyStore, api)

	api.await(t, func(requests []httpTestRequest) bool {
		for _, request := range requests {
			if request.path == "/sidecar/sync/poll" && request.bearer == next {
				return true
			}
		}
		return false
	})
	api.pollAnswers <- httpTestCorePoll(t)
	awaitHttpSidecarStatus(t, sidecar, func(status SidecarStatus) bool {
		return status.State == SidecarStateOnline && status.Generation == 1
	})
}

// A 401 whose refresh is refused too ends the generation as D-CORE-8 says: Unenrolled(refused), the identity kept.
func TestHttpPollRefusedAndRefreshRefusedEndsTheGeneration(t *testing.T) {
	instance, keyStore, api := newHttpTestEnrollment(t, time.Now(), 7*24*time.Hour)
	api.pollAnswers <- http.StatusUnauthorized
	sidecar := newHttpTestSidecar(t, instance, keyStore, api)

	status := awaitHttpSidecarStatus(t, sidecar, func(status SidecarStatus) bool { return status.State == SidecarStateUnenrolled })
	if status.Reason != SidecarReasonRefused {
		t.Errorf("reason %q", status.Reason)
	}
	if sidecar.Identity() == nil {
		t.Error("the identity went with the refused client")
	}
}
