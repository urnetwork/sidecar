//go:build !ios_extension

// The authenticated core read, including a previous read finishing after its invalidation, on both client legs.
package sidecar

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
)

// A generation can accept an explicitly empty list. A missing gate list or an incomplete core response is unknown.
func TestSyncCoreRequiresTheCompleteNetworkGateReply(t *testing.T) {
	for _, body := range []string{
		`{"version":"8","gates":null,"min_secure_version":0,"revoked":false}`,
		`{"version":"8","min_secure_version":0,"revoked":false}`,
		`{"version":"08","gates":["format2"],"min_secure_version":0,"revoked":false}`,
		`{"version":"8","gates":["format2"]}`,
	} {
		api := newTestSidecarApi(t, &scriptedApiTransport{answer: func(request *http.Request, _ []byte) (*http.Response, error) {
			return syntheticResponse(request, http.StatusOK, body, nil), nil
		}})
		if core, err := api.SyncCore(t.Context()); core != nil || !errors.Is(err, ErrSidecarSyncReply) {
			t.Fatalf("incomplete core: %+v, %v", core, err)
		}
	}
}

// A newer hint invalidates immediately, a version older than that hint waits for a retry, and the current
// generation's positive and negative answers both expire. A replacement credential cannot reuse either one.
func TestCoreRolloutInvalidatesInFlightExpiredAndReplacedAnswers(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	clock := newTokenTestClock()
	settings := validSidecarSettings()
	identity := &SidecarIdentity{NetworkId: NewId(), SidecarId: NewId(), ClientId: NewId(), Generation: 1}
	token := func(networkId Id) string {
		return testClientJwt(fmt.Sprintf(`{"network_id":%q,"client_id":%q,"exp":%d}`, networkId, identity.ClientId, clock.Now().Add(3*settings.ProtocolSettings.SyncRefetchInterval).Unix()))
	}
	bearer := token(identity.NetworkId)
	requests := make(chan *http.Request)
	replies := make(chan string)
	transport := &scriptedApiTransport{answer: func(request *http.Request, _ []byte) (*http.Response, error) {
		select {
		case requests <- request:
		case <-request.Context().Done():
			return nil, request.Context().Err()
		}
		select {
		case body := <-replies:
			return syntheticResponse(request, http.StatusOK, body, nil), nil
		case <-request.Context().Done():
			return nil, request.Context().Err()
		}
	}}
	api, err := newSidecarApi(settings, transport, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	api.SetByJwt(bearer)
	generation := &sidecarGeneration{
		ctx: ctx, networkId: identity.NetworkId, identity: identity, generation: identity.Generation,
		sidecar: &Sidecar{sidecarApi: api, settings: settings, clock: clock},
		core:    sidecarCoreSync{requests: NewMonitorValue(sidecarCoreRequest{online: true, revision: 1})},
	}
	generation.startCoreSyncWithLock()
	defer func() { cancel(); <-generation.core.done }()
	waitRequest := func() {
		t.Helper()
		select {
		case request := <-requests:
			if request.Method != http.MethodGet || request.URL.Path != "/sidecar/sync/core" ||
				request.Header.Get("Authorization") != "Bearer "+bearer {
				t.Fatal("core did not use the enrolled client's authenticated route")
			}
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		}
	}
	reply := func(version uint64, gates string) {
		replies <- fmt.Sprintf(`{"version":"%d","gates":%s,"min_secure_version":0,"revoked":false}`, version, gates)
	}
	waitRequest()
	generation.refreshCore(20)
	reply(10, `["format2"]`)
	waitRequest()
	if generation.currentCore() != nil {
		t.Fatal("a positive response arriving after a newer hint opened the gate")
	}
	reply(19, `["format2"]`)
	backoff := clock.awaitArmed(t, 4)
	if backoff != DefaultPushClientSettings().RetryMinInterval || generation.currentCore() != nil {
		t.Fatal("a response below the requested version opened the gate")
	}
	clock.Advance(backoff)
	waitRequest()
	reply(20, `["format2"]`)
	interval := clock.awaitArmed(t, 6)
	if interval != settings.ProtocolSettings.SyncRefetchInterval || !EvsFormat2AdmittedBy(generation.currentCore()) {
		t.Fatal("a current authenticated response did not open the network")
	}
	clock.Advance(interval)
	waitRequest()
	if generation.currentCore() != nil {
		t.Fatal("the old gate outlived its hourly refetch")
	}
	reply(20, `[]`)
	clock.awaitArmed(t, 8)
	if core := generation.currentCore(); core == nil || EvsFormat2AdmittedBy(core) {
		t.Fatal("the explicit closed rollout became unknown")
	}
	api.SetByJwt(token(NewId()))
	if generation.currentCore() != nil {
		t.Fatal("replacement credentials inherited the previous gate")
	}
	generation.refreshCore(0)
	clock.awaitArmed(t, 10)
	if transport.requestCount() != 4 || generation.currentCore() != nil {
		t.Fatal("a core request used a different network's credential")
	}
}
