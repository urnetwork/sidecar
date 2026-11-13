// CORE-M1-13's T2 schedules: a real Sidecar enrolled through the fake api to Online, refreshing on the Net's clock
// across 21 days, a refused refresh then `ur login` under the same sidecar_id, restore_required through a re-bind, an
// ended session, a lost refresh answer, and enrollment's fail-closed refusals; then the routes alone, held to
// plan-CORE-binding-wire's rules and §7.4's proof, which server's real routes answer alike on T3
// (server/api/sidecar_identity_route_db_test.go). §22.7's S1 scan closes each schedule: no token or auth key in a log,
// the environment or a frame.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// How long a schedule waits, in real time, for what it expects. Every wait is on a monitor or an event; this only
// stops a broken test from hanging.
const coreScheduleTimeout = 30 * time.Second

// A context that a broken schedule's waits end with.
func coreScheduleContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(t.Context(), coreScheduleTimeout)
	t.Cleanup(cancel)
	return ctx
}

// A sidecar enrolled in the Net's default network and Online.
func addCoreSidecar(t *testing.T, net *Net, name string) *TestSidecar {
	t.Helper()
	testSidecar, err := net.AddSidecar(name, nil)
	if err != nil {
		t.Fatal(err)
	}
	return testSidecar
}

// The record of the network the sidecar enrolled in.
func coreNetworkRecord(t *testing.T, testSidecar *TestSidecar) sidecar.SidecarNetworkRecord {
	t.Helper()
	record, ok := testSidecar.NetworkRecord()
	if !ok {
		t.Fatalf("%s has no network record", testSidecar.Name)
	}
	return record
}

// Waits until the refresher has set its timer for the newest token's refresh, a pending timer in the token's window
// (RefreshWindowStart to RefreshWindowEnd of its lifetime), then moves the clock to it. Waiting first matters: a timer
// is set relative to the clock it is set on, so a move between the refresher's reading of the clock and its timer would
// push the timer past the move. Answers the token's iat.
func advancePastRefreshPoint(t *testing.T, net *Net, testSidecar *TestSidecar, clientId sidecar.Id) time.Time {
	t.Helper()
	issuedAt, expireTime, ok := testSidecar.Api.NewestClientToken(clientId)
	if !ok {
		t.Fatal("the client has no token")
	}
	settings := testSidecar.Settings.TokenRefreshSettings
	lifetime := float64(expireTime.Sub(issuedAt))
	windowStart := issuedAt.Add(time.Duration(settings.RefreshWindowStart*lifetime) - time.Second)
	windowEnd := issuedAt.Add(time.Duration(settings.RefreshWindowEnd*lifetime) + time.Second)
	deadline := time.After(coreScheduleTimeout)
	for {
		pending, added := net.Clock().WatchTimers()
		for _, at := range pending {
			if !at.Before(windowStart) && !at.After(windowEnd) {
				net.Clock().AdvanceTo(at)
				return issuedAt
			}
		}
		select {
		case <-added:
		case <-deadline:
			t.Fatalf("no refresh timer between %s and %s: %v", windowStart, windowEnd, pending)
		}
	}
}

// Waits until the api has minted the client count tokens in all.
func awaitClientTokenCount(t *testing.T, api *FakeApi, clientId sidecar.Id, count int) {
	t.Helper()
	deadline := time.After(coreScheduleTimeout)
	for {
		// subscribed before the read, so a mint between them wakes the wait
		_, minted := api.Mints()
		if count <= api.ClientTokenCount(clientId) {
			return
		}
		select {
		case <-minted:
		case <-deadline:
			t.Fatalf("the api minted %d tokens for the client, want %d", api.ClientTokenCount(clientId), count)
		}
	}
}

// §22.7's S1 on what the schedule captured: no token, auth key or hooked key in any log, the environment or a frame,
// and the logs were there to read.
func requireS1Clean(t *testing.T, net *Net) {
	t.Helper()
	capture := net.Capture()
	if capture.ItemCount(PrivacyClassLog) == 0 {
		t.Error("the capture holds no log line, so a clean scan proves nothing there")
	}
	if findings := capture.Scan(); len(findings) != 0 {
		t.Errorf("S1: %v", findings)
	}
}

// Enrollment end to end: the auth key's bearer, a bound first generation, the binding's sidecar at api, and Online.
func TestSidecarEnrollsToOnline(t *testing.T) {
	net := newTestNet(t)
	laptop := addCoreSidecar(t, net, "laptop")
	api := laptop.Api
	record := coreNetworkRecord(t, laptop)

	status := laptop.Sidecar().Status()
	if status.State != sidecar.SidecarStateOnline || status.Generation != 1 {
		t.Fatalf("status %+v", status)
	}
	if record.NetworkId != net.DefaultNetworkId() {
		t.Errorf("enrolled in %s, not the default network", record.NetworkId)
	}
	identityStatus, newest, ok := api.SidecarIdentity(record.SidecarId)
	if !ok || identityStatus != fakeApiIdentityActive || newest != 1 {
		t.Errorf("api holds %q at generation %d (%v)", identityStatus, newest, ok)
	}
	if api.RouteCount("POST /network/enroll") != 1 || api.RouteCount("POST /sidecar/bind") != 1 {
		t.Errorf("enroll %d, bind %d", api.RouteCount("POST /network/enroll"), api.RouteCount("POST /sidecar/bind"))
	}
	if laptop.Client() == nil || laptop.Client().ClientId.String() != record.ClientId.String() {
		t.Errorf("the generation's client is not the enrolled one")
	}
	requireS1Clean(t, net)
}

// D-CORE-8 on the Net's clock: a 7-day token refreshes by its ClientKey's proof in its window, each time, for 21 days,
// the generation and Online kept and no token ever expiring.
func TestSidecarRefreshesAcross21Days(t *testing.T) {
	net := newTestNet(t)
	laptop := addCoreSidecar(t, net, "laptop")
	api := laptop.Api
	record := coreNetworkRecord(t, laptop)

	start := net.Clock().Now()
	refreshCount := 0
	for net.Clock().Now().Before(start.Add(21 * 24 * time.Hour)) {
		count := api.ClientTokenCount(record.ClientId)
		advancePastRefreshPoint(t, net, laptop, record.ClientId)
		awaitClientTokenCount(t, api, record.ClientId, count+1)
		refreshCount += 1
		if status := laptop.Sidecar().Status(); status.State != sidecar.SidecarStateOnline || status.Generation != 1 {
			t.Fatalf("after %d refreshes: %+v", refreshCount, status)
		}
	}
	// 21 days of 7-day tokens refreshed at most half way through each
	if refreshCount < 6 {
		t.Errorf("%d refreshes in 21 days", refreshCount)
	}
	if _, expireTime, _ := api.NewestClientToken(record.ClientId); !net.Clock().Now().Before(expireTime) {
		t.Error("the newest token has expired")
	}
	if api.RouteCount("POST /network/enroll") != 1 {
		t.Error("a refresh re-enrolled")
	}
	requireS1Clean(t, net)
}

// A refused refresh ends the generation as refused, the identity kept (D-CORE-8); `ur login`'s enrollment then binds
// generation 2 under the same sidecar_id, removing the old client with its own token.
func TestRefusedRefreshThenLoginKeepsTheSidecarId(t *testing.T) {
	net := newTestNet(t)
	ctx := coreScheduleContext(t)
	laptop := addCoreSidecar(t, net, "laptop")
	api := laptop.Api
	first := coreNetworkRecord(t, laptop)

	api.RefuseRefresh(first.ClientId)
	advancePastRefreshPoint(t, net, laptop, first.ClientId)
	if err := laptop.AwaitStateReason(ctx, sidecar.SidecarStateUnenrolled, sidecar.SidecarReasonRefused); err != nil {
		t.Fatal(err)
	}

	if err := laptop.Enroll(ctx, first.NetworkId); err != nil {
		t.Fatal(err)
	}
	if err := laptop.AwaitState(ctx, sidecar.SidecarStateOnline); err != nil {
		t.Fatal(err)
	}
	second := coreNetworkRecord(t, laptop)
	if second.SidecarId != first.SidecarId || second.ClientId == first.ClientId {
		t.Fatalf("first %+v, second %+v", first, second)
	}
	if generation := laptop.Sidecar().Status().Generation; generation != 2 {
		t.Errorf("generation %d", generation)
	}
	if identityStatus, newest, _ := api.SidecarIdentity(first.SidecarId); identityStatus != fakeApiIdentityActive || newest != 2 {
		t.Errorf("api holds %q at generation %d", identityStatus, newest)
	}
	if !api.ClientRemoved(first.ClientId) || api.ClientRemoved(second.ClientId) {
		t.Errorf("removed: first %v, second %v", api.ClientRemoved(first.ClientId), api.ClientRemoved(second.ClientId))
	}
	requireS1Clean(t, net)
}

// A session api ended answers 401 session_revoked, which §18.5 maps to session_ended, never Revoked.
func TestEndedSessionUnenrollsAsSessionEnded(t *testing.T) {
	net := newTestNet(t)
	ctx := coreScheduleContext(t)
	laptop := addCoreSidecar(t, net, "laptop")
	record := coreNetworkRecord(t, laptop)

	laptop.Api.EndSession(record.ClientId)
	advancePastRefreshPoint(t, net, laptop, record.ClientId)
	if err := laptop.AwaitStateReason(ctx, sidecar.SidecarStateUnenrolled, sidecar.SidecarReasonSessionEnded); err != nil {
		t.Fatal(err)
	}
	requireS1Clean(t, net)
}

// After a Postgres restore that lost the identity tables, refresh answers restore_required, which is no refusal: the
// sidecar posts its newest binding again and refreshes, Online and at generation 1 throughout (§5.6, §19.10).
func TestRestoreRequiredRebindsAndRefreshes(t *testing.T) {
	net := newTestNet(t)
	laptop := addCoreSidecar(t, net, "laptop")
	api := laptop.Api
	record := coreNetworkRecord(t, laptop)

	api.ForgetSidecarIdentities(record.NetworkId)
	if _, _, ok := api.SidecarIdentity(record.SidecarId); ok {
		t.Fatal("the restore kept the identity")
	}
	count := api.ClientTokenCount(record.ClientId)
	advancePastRefreshPoint(t, net, laptop, record.ClientId)
	awaitClientTokenCount(t, api, record.ClientId, count+1)

	if identityStatus, newest, ok := api.SidecarIdentity(record.SidecarId); !ok || identityStatus != fakeApiIdentityActive || newest != 1 {
		t.Errorf("api holds %q at generation %d (%v)", identityStatus, newest, ok)
	}
	if api.RouteCount("POST /sidecar/bind") != 2 || api.RouteCount("GET /auth/refresh") < 2 {
		t.Errorf("bind %d, refresh %d", api.RouteCount("POST /sidecar/bind"), api.RouteCount("GET /auth/refresh"))
	}
	if status := laptop.Sidecar().Status(); status.State != sidecar.SidecarStateOnline || status.Generation != 1 {
		t.Errorf("status %+v", status)
	}
	requireS1Clean(t, net)
}

// A refresh whose answer is lost keeps the token it had, and the next request for a refresh, connect's report of a
// refused credential, refreshes again with a fresh proof.
func TestLostRefreshAnswerRetries(t *testing.T) {
	net := newTestNet(t)
	laptop := addCoreSidecar(t, net, "laptop")
	api := laptop.Api
	record := coreNetworkRecord(t, laptop)

	fired, err := net.Faults().Add(&FaultPlan{Op: FaultOpHttp, KeyPrefix: "/auth/refresh", Result: ApplyThenDrop})
	if err != nil {
		t.Fatal(err)
	}
	count := api.ClientTokenCount(record.ClientId)
	advancePastRefreshPoint(t, net, laptop, record.ClientId)
	select {
	case <-fired:
	case <-time.After(coreScheduleTimeout):
		t.Fatal("no refresh was sent")
	}
	awaitClientTokenCount(t, api, record.ClientId, count+1)

	laptop.CloseAuthorization()
	awaitClientTokenCount(t, api, record.ClientId, count+2)
	if status := laptop.Sidecar().Status(); status.State != sidecar.SidecarStateOnline || status.Generation != 1 {
		t.Errorf("status %+v", status)
	}
	requireS1Clean(t, net)
}

// A platform outage drops the sidecar to Offline and its end brings it back Online, the generation kept.
func TestPlatformOutageIsOfflineNotUnenrolled(t *testing.T) {
	net := newTestNet(t)
	ctx := coreScheduleContext(t)
	laptop := addCoreSidecar(t, net, "laptop")

	laptop.SetPlatformReachable(false)
	if err := laptop.AwaitState(ctx, sidecar.SidecarStateOffline); err != nil {
		t.Fatal(err)
	}
	laptop.SetPlatformReachable(true)
	if err := laptop.AwaitState(ctx, sidecar.SidecarStateOnline); err != nil {
		t.Fatal(err)
	}
	if generation := laptop.Sidecar().Status().Generation; generation != 1 {
		t.Errorf("generation %d", generation)
	}
}

// D-CORE-7 and D-TRUST-3 fail closed: a network outside preview_networks, a tagged key before base 1, a readable
// network credential on this host, and a reply without admin_refused each leave nothing on disk and the sidecar
// Unenrolled; the unmarked client is removed.
func TestEnrollmentFailsClosed(t *testing.T) {
	net := newTestNet(t)
	ctx := coreScheduleContext(t)
	laptop, err := net.StartSidecar("laptop", nil)
	if err != nil {
		t.Fatal(err)
	}
	api := laptop.Api
	networkId := net.DefaultNetworkId()
	if err := laptop.AwaitState(ctx, sidecar.SidecarStateUnenrolled); err != nil {
		t.Fatal(err)
	}
	nothingKept := func(name string) {
		t.Helper()
		if records := laptop.Instance().Networks(); len(records) != 0 {
			t.Errorf("%s: kept %+v", name, records)
		}
		if state := laptop.Sidecar().Status().State; state != sidecar.SidecarStateUnenrolled {
			t.Errorf("%s: %s", name, state)
		}
	}

	api.SetPreviewNetworks([]sidecar.Id{sidecar.NewId()})
	enrollErr := &sidecar.SidecarEnrollError{}
	if err := laptop.Enroll(ctx, networkId); !errors.As(err, &enrollErr) || enrollErr.Reason != sidecar.SidecarEnrollPreview {
		t.Errorf("outside preview: %v", err)
	}
	nothingKept("outside preview")
	api.SetPreviewNetworks(nil)

	taggedKey := api.NewAuthKey(&FakeApiAuthKeyArgs{NetworkId: networkId, Tagged: true})
	if err := laptop.EnrollWith(ctx, &sidecar.SidecarEnrollCredential{AuthKey: taggedKey}); !errors.As(err, &enrollErr) || enrollErr.Reason != sidecar.SidecarEnrollNoGenesis {
		t.Errorf("tagged before base 1: %v", err)
	}
	nothingKept("tagged before base 1")

	laptop.SetHostCredentialStores([]sidecar.SidecarHostCredentialStore{{Kind: "app"}})
	if err := laptop.Restart(); err != nil {
		t.Fatal(err)
	}
	if err := laptop.AwaitState(ctx, sidecar.SidecarStateUnenrolled); err != nil {
		t.Fatal(err)
	}
	if err := laptop.Enroll(ctx, networkId); !errors.Is(err, sidecar.ErrSidecarHostCredentialStore) {
		t.Errorf("beside a host credential: %v", err)
	}
	nothingKept("beside a host credential")
	laptop.SetHostCredentialStores(nil)
	if err := laptop.Restart(); err != nil {
		t.Fatal(err)
	}
	if err := laptop.AwaitState(ctx, sidecar.SidecarStateUnenrolled); err != nil {
		t.Fatal(err)
	}

	api.SetEnrollDropsMarks(true)
	removesBefore := api.RouteCount("POST /network/remove-client")
	if err := laptop.Enroll(ctx, networkId); !errors.Is(err, sidecar.ErrSidecarEnrollNotAdminRefused) {
		t.Errorf("no admin_refused: %v", err)
	}
	nothingKept("no admin_refused")
	if api.RouteCount("POST /network/remove-client") != removesBefore+1 {
		t.Error("the unmarked client was not removed")
	}
	api.SetEnrollDropsMarks(false)

	if err := laptop.Enroll(ctx, networkId); err != nil {
		t.Fatal(err)
	}
	if err := laptop.AwaitState(ctx, sidecar.SidecarStateOnline); err != nil {
		t.Fatal(err)
	}
	requireS1Clean(t, net)
}

// One client of a fake api with its own ClientKey and identity key, enrolled and unbound.
type coreRouteClient struct {
	t           *testing.T
	world       *fakeApiTestWorld
	networkId   sidecar.Id
	clientId    sidecar.Id
	sidecarId   sidecar.Id
	token       string
	clientKey   ed25519.PrivateKey
	identityKey ed25519.PrivateKey
	jtiCount    int
}

// Enrolls a client of networkId on the world's api through POST /network/enroll.
func newCoreRouteClient(t *testing.T, world *fakeApiTestWorld, networkId sidecar.Id) *coreRouteClient {
	t.Helper()
	_, clientKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, identityKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authKey := world.api.NewAuthKey(&FakeApiAuthKeyArgs{NetworkId: networkId})
	result := &fakeApiEnrollResult{}
	status, refusal, err := world.call(http.MethodPost, "/network/enroll", "", &fakeApiEnrollArgs{
		AuthKey:         authKey,
		ClientPublicKey: clientKey.Public().(ed25519.PublicKey),
		DeviceSpec:      "ur",
		AdminRefused:    true,
		StrictExp:       true,
	}, result)
	if err != nil || status != http.StatusOK || !result.AdminRefused {
		t.Fatalf("enroll: %d %v %v", status, refusal, err)
	}
	return &coreRouteClient{
		t:           t,
		world:       world,
		networkId:   networkId,
		clientId:    result.ClientId,
		sidecarId:   sidecar.NewId(),
		token:       result.ByClientJwt,
		clientKey:   clientKey,
		identityKey: identityKey,
	}
}

// The client's binding of generation, by its keys.
func (self *coreRouteClient) binding(generation int64) []byte {
	self.t.Helper()
	signed, err := sidecar.NewSidecarIdentityBinding(&sidecar.SidecarIdentityBinding{
		NetworkId:  self.networkId,
		SidecarId:  self.sidecarId,
		ClientId:   self.clientId,
		Generation: generation,
		IssuedAt:   self.world.clock.Now(),
	}, self.identityKey.Seed(), self.clientKey.Seed())
	if err != nil {
		self.t.Fatal(err)
	}
	return signed
}

// POST /sidecar/bind of binding: its status, code and generation.
func (self *coreRouteClient) bind(binding []byte) (int, string, int64) {
	self.t.Helper()
	result := &fakeApiBindResult{}
	status, refusal, err := self.world.call(http.MethodPost, "/sidecar/bind", self.token, &fakeApiBindArgs{Binding: binding}, result)
	if err != nil {
		self.t.Fatal(err)
	}
	code, _ := refusal["code"].(string)
	return status, code, result.Generation
}

// A fresh proof of method on path by key over the client's token.
func (self *coreRouteClient) proof(key ed25519.PrivateKey, method string, path string) string {
	self.jtiCount += 1
	return fakeApiTestProof(key, method, self.world.api.Origin()+path, self.token, fmt.Sprintf("core-jti-%d", self.jtiCount), self.world.clock.Now().Unix())
}

// GET /auth/refresh with proof: its status, its error code and the new token.
func (self *coreRouteClient) refresh(proof string) (int, string, string) {
	self.t.Helper()
	request, err := http.NewRequestWithContext(self.world.ctx, http.MethodGet, self.world.api.Origin()+"/auth/refresh", nil)
	if err != nil {
		self.t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+self.token)
	if proof != "" {
		request.Header.Set("DPoP", proof)
	}
	response, err := self.world.api.Transport().RoundTrip(request)
	if err != nil {
		self.t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		self.t.Fatal(err)
	}
	// a refused proof answers in plain text, as server's gate does
	result := map[string]any{}
	json.Unmarshal(body, &result)
	code, _ := result["code"].(string)
	if refusal, ok := result["error"].(map[string]any); ok {
		code, _ = refusal["code"].(string)
	}
	byJwt, _ := result["by_jwt"].(string)
	return response.StatusCode, code, byJwt
}

// plan-CORE-binding-wire's rules on the fake's bind: generation 1 first, a byte-identical retry answering its
// generation, other bytes for a bound client client_bound, another client's binding binding_invalid, a ClientKey other
// than the enrolled one binding_invalid, a generation that skips generation_conflict, and a revoked identity
// sidecar_revoked.
func TestFakeApiBindFollowsTheBindingRules(t *testing.T) {
	world := newFakeApiTestWorld(t)
	networkId := sidecar.NewId()
	laptop := newCoreRouteClient(t, world, networkId)

	// a re-registration after a restore, server's seam admitting it until TEAM-M2-16's projection check
	restored := newCoreRouteClient(t, world, networkId)
	if status, code, generation := restored.bind(restored.binding(3)); status != http.StatusOK || generation != 3 {
		t.Errorf("a re-registration at generation 3: %d %s %d", status, code, generation)
	}
	first := laptop.binding(1)
	if status, code, generation := laptop.bind(first); status != http.StatusOK || generation != 1 {
		t.Fatalf("generation 1: %d %s %d", status, code, generation)
	}
	if status, _, generation := laptop.bind(first); status != http.StatusOK || generation != 1 {
		t.Errorf("a retry: %d %d", status, generation)
	}
	world.clock.Advance(time.Second)
	if status, code, _ := laptop.bind(laptop.binding(1)); status != http.StatusConflict || code != fakeApiCodeClientBound {
		t.Errorf("other bytes: %d %s", status, code)
	}

	phone := newCoreRouteClient(t, world, networkId)
	phone.sidecarId = laptop.sidecarId
	phone.identityKey = laptop.identityKey
	other := phone.binding(2)
	phone.token = laptop.token
	if status, code, _ := phone.bind(other); status != http.StatusBadRequest || code != fakeApiCodeBindingInvalid {
		t.Errorf("another client's binding: %d %s", status, code)
	}
	phone.token = newCoreRouteClient(t, world, networkId).token
	if status, code, _ := phone.bind(other); status != http.StatusBadRequest || code != fakeApiCodeBindingInvalid {
		t.Errorf("a binding for a client the token does not name: %d %s", status, code)
	}

	tablet := newCoreRouteClient(t, world, networkId)
	tablet.sidecarId = laptop.sidecarId
	tablet.identityKey = laptop.identityKey
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enrolledKey := tablet.clientKey
	tablet.clientKey = otherKey
	if status, code, _ := tablet.bind(tablet.binding(2)); status != http.StatusBadRequest || code != fakeApiCodeBindingInvalid {
		t.Errorf("a ClientKey other than the enrolled one: %d %s", status, code)
	}
	tablet.clientKey = enrolledKey
	if status, code, _ := tablet.bind(tablet.binding(3)); status != http.StatusConflict || code != fakeApiCodeGenerationConflict {
		t.Errorf("a skipped generation: %d %s", status, code)
	}
	world.api.RevokeSidecarIdentity(laptop.sidecarId)
	if status, code, _ := tablet.bind(tablet.binding(2)); status != http.StatusForbidden || code != fakeApiCodeSidecarRevoked {
		t.Errorf("a revoked identity: %d %s", status, code)
	}
}

// §7.4's proof on the fake's refresh: none, a replayed jti, a proof by a key that is not the newest bound one, and one
// past the iat window are server's 403 proof refusal, in plain text; the bound key's fresh proof renews, the same
// client and device.
func TestFakeApiRefreshNeedsTheBoundKeysProof(t *testing.T) {
	world := newFakeApiTestWorld(t)
	laptop := newCoreRouteClient(t, world, sidecar.NewId())
	if status, _, _ := laptop.bind(laptop.binding(1)); status != http.StatusOK {
		t.Fatal(status)
	}

	if status, _, _ := laptop.refresh(""); status != http.StatusForbidden {
		t.Errorf("no proof: %d", status)
	}
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if status, _, _ := laptop.refresh(laptop.proof(otherKey, http.MethodGet, "/auth/refresh")); status != http.StatusForbidden {
		t.Errorf("another key: %d", status)
	}
	stale := laptop.proof(laptop.clientKey, http.MethodGet, "/auth/refresh")
	world.clock.Advance(2 * time.Minute)
	if status, _, _ := laptop.refresh(stale); status != http.StatusForbidden {
		t.Errorf("past the iat window: %d", status)
	}
	good := laptop.proof(laptop.clientKey, http.MethodGet, "/auth/refresh")
	status, code, refreshed := laptop.refresh(good)
	if status != http.StatusOK || refreshed == "" {
		t.Fatalf("a good proof: %d %s", status, code)
	}
	if networkId, clientId, sidecarId, ok := world.api.TokenClient(refreshed); !ok || networkId != laptop.networkId || clientId != laptop.clientId || sidecarId != laptop.sidecarId {
		t.Errorf("the renewal names %s %s %s", networkId, clientId, sidecarId)
	}
	if status, _, _ := laptop.refresh(good); status != http.StatusForbidden {
		t.Errorf("a replayed jti: %d", status)
	}
}

// server's refresh answers restore_required, never a refusal, to a strict_exp client with no binding, and a removed
// client's token is refused everywhere.
func TestFakeApiRefreshAnswersRestoreRequiredUnbound(t *testing.T) {
	world := newFakeApiTestWorld(t)
	laptop := newCoreRouteClient(t, world, sidecar.NewId())

	// the enrolled key proves before any bind (plan-TEAM-enroll-client-key)
	status, code, _ := laptop.refresh(laptop.proof(laptop.clientKey, http.MethodGet, "/auth/refresh"))
	if status != http.StatusOK || code != fakeApiCodeRestoreRequired {
		t.Errorf("unbound: %d %s", status, code)
	}
	world.api.RemoveClient(laptop.clientId)
	if status, _, _ := laptop.refresh(laptop.proof(laptop.clientKey, http.MethodGet, "/auth/refresh")); status != http.StatusUnauthorized {
		t.Errorf("removed: %d", status)
	}
}

// The lookups: a sidecar of the caller's network with its bindings newest first, a page below a generation, the
// sidecar a client binds, and 404 for a sidecar of another network or a client with no binding.
func TestFakeApiIdentityLookups(t *testing.T) {
	world := newFakeApiTestWorld(t)
	networkId := sidecar.NewId()
	laptop := newCoreRouteClient(t, world, networkId)
	if status, _, _ := laptop.bind(laptop.binding(1)); status != http.StatusOK {
		t.Fatal(status)
	}
	again := newCoreRouteClient(t, world, networkId)
	again.sidecarId = laptop.sidecarId
	again.identityKey = laptop.identityKey
	if status, _, _ := again.bind(again.binding(2)); status != http.StatusOK {
		t.Fatal(status)
	}

	result := &fakeApiIdentityResult{}
	status, refusal, err := world.call(http.MethodGet, "/sidecar/identity/"+laptop.sidecarId.String(), laptop.token, nil, result)
	if err != nil || status != http.StatusOK || len(result.Bindings) != 2 || result.Status != fakeApiIdentityActive {
		t.Fatalf("by sidecar: %d %v %v %+v", status, refusal, err, result)
	}
	newest, err := sidecar.VerifySidecarIdentityBinding(result.Binding)
	if err != nil || newest.Generation != 2 {
		t.Errorf("the current binding: %v %+v", err, newest)
	}
	below := &fakeApiIdentityResult{}
	world.call(http.MethodGet, "/sidecar/identity/"+laptop.sidecarId.String()+"?before_generation=2", laptop.token, nil, below)
	if len(below.Bindings) != 1 {
		t.Errorf("below generation 2: %d bindings", len(below.Bindings))
	}
	byClient := &fakeApiIdentityResult{}
	status, _, _ = world.call(http.MethodGet, "/sidecar/identity?client_id="+laptop.clientId.String(), again.token, nil, byClient)
	if status != http.StatusOK || byClient.SidecarId != laptop.sidecarId {
		t.Errorf("by client: %d %+v", status, byClient)
	}
	if binding, err := sidecar.VerifySidecarIdentityBinding(byClient.Binding); err != nil || binding.Generation != 1 {
		t.Errorf("the client's binding: %v", err)
	}

	stranger := newCoreRouteClient(t, world, sidecar.NewId())
	if status, _, _ := world.call(http.MethodGet, "/sidecar/identity/"+laptop.sidecarId.String(), stranger.token, nil, nil); status != http.StatusNotFound {
		t.Errorf("another network's sidecar: %d", status)
	}
	if status, _, _ := world.call(http.MethodGet, "/sidecar/identity?client_id="+stranger.clientId.String(), laptop.token, nil, nil); status != http.StatusNotFound {
		t.Errorf("an unbound client: %d", status)
	}
}

// §7.8's enroll refuses a bearer holding #, a urn_ key, a spent or unknown key, and a tagged key before base 1; and
// D-TRUST-3's preview gate refuses strict_exp outside preview_networks.
func TestFakeApiEnrollRefusals(t *testing.T) {
	world := newFakeApiTestWorld(t)
	networkId := sidecar.NewId()
	_, clientKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enroll := func(authKey string) (int, string) {
		t.Helper()
		status, refusal, err := world.call(http.MethodPost, "/network/enroll", "", &fakeApiEnrollArgs{
			AuthKey:         authKey,
			ClientPublicKey: clientKey.Public().(ed25519.PublicKey),
			DeviceSpec:      "ur",
			AdminRefused:    true,
			StrictExp:       true,
		}, &fakeApiEnrollResult{})
		if err != nil {
			t.Fatal(err)
		}
		code, _ := refusal["code"].(string)
		return status, code
	}
	authKey := world.api.NewAuthKey(&FakeApiAuthKeyArgs{NetworkId: networkId})
	if status, _ := enroll(authKey + "#bundle"); status != http.StatusBadRequest {
		t.Errorf("a bundle: %d", status)
	}
	if status, _ := enroll("urn_synthetic"); status != http.StatusBadRequest {
		t.Errorf("an api key: %d", status)
	}
	world.api.SetPreviewNetworks([]sidecar.Id{sidecar.NewId()})
	if status, code := enroll(authKey); status != http.StatusForbidden || code != fakeApiCodeNotPreview {
		t.Errorf("outside preview: %d %s", status, code)
	}
	world.api.SetPreviewNetworks(nil)
	if status, _ := enroll(authKey); status != http.StatusOK {
		t.Errorf("the key: %d", status)
	}
	if status, code := enroll(authKey); status != http.StatusUnauthorized || code != fakeApiCodeAuthKey {
		t.Errorf("a spent key: %d %s", status, code)
	}
	tagged := world.api.NewAuthKey(&FakeApiAuthKeyArgs{NetworkId: networkId, Tagged: true})
	if status, code := enroll(tagged); status != http.StatusForbidden || code != fakeApiCodeNoGenesis {
		t.Errorf("tagged before base 1: %d %s", status, code)
	}
	expired := world.api.NewAuthKey(&FakeApiAuthKeyArgs{NetworkId: networkId, Timeout: time.Minute})
	world.clock.Advance(2 * time.Minute)
	if status, code := enroll(expired); status != http.StatusUnauthorized || code != fakeApiCodeAuthKey {
		t.Errorf("an expired key: %d %s", status, code)
	}
}

// POST /network/auth-client with a fresh proof by key over the client's token: the answer, or its refusal's message.
func (self *coreRouteClient) authClient(key ed25519.PrivateKey, args *fakeApiAuthClientArgs) (*fakeApiAuthClientResult, string) {
	self.t.Helper()
	encoded, err := json.Marshal(args)
	if err != nil {
		self.t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(self.world.ctx, http.MethodPost, self.world.api.Origin()+"/network/auth-client", bytes.NewReader(encoded))
	if err != nil {
		self.t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+self.token)
	request.Header.Set("DPoP", self.proof(key, http.MethodPost, "/network/auth-client"))
	response, err := self.world.api.Transport().RoundTrip(request)
	if err != nil {
		self.t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK {
		self.t.Fatalf("auth-client: %d %s %v", response.StatusCode, body, err)
	}
	result := &fakeApiAuthClientResult{}
	if err := json.Unmarshal(body, result); err != nil {
		self.t.Fatal(err)
	}
	if result.Error != nil {
		return nil, result.Error.Message
	}
	return result, ""
}

// §7.4's forwarding client on the fake's mint, as server's checkForwardOnlyMint answers it: a bound sidecar client
// mints F under its key, the answer confirming forward_only with both other marks; a repeat for that key reissues the
// same F and another key mints another; F's own proofs pass under its key, and its children inherit the mark and take
// no key; an unbound source, a missing or short key, and a key with no forward_only are refused.
func TestFakeApiMintsForwardingClients(t *testing.T) {
	world := newFakeApiTestWorld(t)
	networkId := sidecar.NewId()
	source := newCoreRouteClient(t, world, networkId)
	forwardPublic, forwardKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mint := func(client *coreRouteClient, key ed25519.PrivateKey, forwardOnly bool, clientPublicKey []byte) (*fakeApiAuthClientResult, string) {
		t.Helper()
		sourceClientId := client.clientId
		return client.authClient(key, &fakeApiAuthClientArgs{
			SourceClientId: &sourceClientId, Description: "forwarding", DeviceSpec: "sidecar forwarding", DeclaresNoEgress: true,
			AdminRefused: true, StrictExp: true, ForwardOnly: forwardOnly, ClientPublicKey: clientPublicKey,
		})
	}
	if _, refusal := mint(source, source.clientKey, true, forwardPublic); refusal != fakeApiForwardOnlyUnboundMessage {
		t.Errorf("an unbound source: %q", refusal)
	}
	if status, code, _ := source.bind(source.binding(1)); status != http.StatusOK {
		t.Fatalf("the bind: %d %s", status, code)
	}
	first, refusal := mint(source, source.clientKey, true, forwardPublic)
	if refusal != "" || first.ClientId == nil || !first.ForwardOnly || !first.AdminRefused || !first.StrictExp || *first.ClientId == source.clientId {
		t.Fatalf("F's mint: %+v %q", first, refusal)
	}
	again, refusal := mint(source, source.clientKey, true, forwardPublic)
	if refusal != "" || *again.ClientId != *first.ClientId || again.ByClientJwt == first.ByClientJwt || !again.ForwardOnly {
		t.Errorf("a repeat for the same key: %+v %q", again, refusal)
	}
	if other, refusal := mint(source, source.clientKey, true, otherPublic); refusal != "" || *other.ClientId == *first.ClientId {
		t.Errorf("another key: %+v %q", other, refusal)
	}
	for name, refused := range map[string]struct {
		forwardOnly     bool
		clientPublicKey []byte
		want            string
	}{
		"no key":                  {forwardOnly: true, want: fakeApiForwardOnlyKeyMessage},
		"a short key":             {forwardOnly: true, clientPublicKey: forwardPublic[:31], want: fakeApiForwardOnlyKeyMessage},
		"a key with no mark":      {clientPublicKey: forwardPublic, want: fakeApiClientPublicKeyMarkMessage},
		"a key for a plain child": {clientPublicKey: otherPublic, want: fakeApiClientPublicKeyMarkMessage},
	} {
		if _, refusal := mint(source, source.clientKey, refused.forwardOnly, refused.clientPublicKey); refusal != refused.want {
			t.Errorf("%s: %q", name, refusal)
		}
	}

	forwarding := &coreRouteClient{t: t, world: world, networkId: networkId, clientId: *first.ClientId, token: again.ByClientJwt, clientKey: forwardKey}
	window, refusal := mint(forwarding, forwardKey, true, nil)
	if refusal != "" || !window.ForwardOnly || *window.ClientId == *first.ClientId {
		t.Fatalf("F's window client: %+v %q", window, refusal)
	}
	if plain, refusal := mint(forwarding, forwardKey, false, nil); refusal != "" || !plain.ForwardOnly {
		t.Errorf("F's plain child: %+v %q", plain, refusal)
	}
	if _, refusal := mint(forwarding, forwardKey, true, otherPublic); refusal != fakeApiClientPublicKeyMarkMessage {
		t.Errorf("F's child with a key: %q", refusal)
	}
}
