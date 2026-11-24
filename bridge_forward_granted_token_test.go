// The forwarding client's gkm reads riding out api's gate lag on F's grant (QD-1230; §8.9's targets; owner decision
// 726): a Forwarder over a real ForwardingClient, whose token exchange and gkm a fake api behind the client's transport
// answers. The exchange grants F the config's r once api's gate holds S's forwarding Delegation, at a time a test sets
// on the client's own clock, and refuses invalid_scope before, as server/oauth's grantForwardOnly does; gkm answers
// from the Forwarder world's gkm (bridge_forward_follow_test.go) under a token the exchange minted. Only F's gkm reads
// wait on the client's clock, so a test moves it past each wait they arm while the Forwarder's compile runs.

package sidecar

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One exchange the fake api took: when on the client's clock, the scope asked, whether F's token and a proof were
// presented, and whether it granted any scope.
type testForwardingGrantExchange struct {
	at        time.Time
	scope     string
	presented bool
	granted   bool
}

// One request the fake gkm took: when on the client's clock, its route's path, and whether its bearer was a token the
// exchange minted.
type testForwardingGrantGkmRequest struct {
	at     time.Time
	path   string
	minted bool
}

// api's token exchange and gkm behind the forwarding client's transport (the file's comment). Safe for concurrent use.
type testForwardingGrantApi struct {
	clock        *gkmTestClock
	byJwt        string
	configRepoId Id
	gkm          *testForwarderGkm

	stateLock sync.Mutex
	// from when api's gate holds S's forwarding Delegation, so the exchange grants F the config's r; zero for never
	grantAt      time.Time
	mintedTokens map[string]bool
	exchanges    []*testForwardingGrantExchange
	gkmRequests  []*testForwardingGrantGkmRequest
}

// The fake api over the Forwarder world's gkm and config repo, granting nothing until a test says.
func newTestForwardingGrantApi(world *testForwarderWorld) *testForwardingGrantApi {
	return &testForwardingGrantApi{
		clock:        newGkmTestClock(),
		byJwt:        "synthetic-forwarding-client-jwt",
		configRepoId: world.net.configRepoId(),
		gkm:          world.gkm,
		mintedTokens: map[string]bool{},
	}
}

// api's gate holds the forwarding Delegation from lag on, on the client's clock.
func (self *testForwardingGrantApi) grantAfter(lag time.Duration) {
	at := self.clock.Now().Add(lag)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.grantAt = at
}

// The config's r, the one scope a forward_only client is granted.
func (self *testForwardingGrantApi) configScope() string {
	return GkmRepoScope{RepoId: self.configRepoId, Role: GkmScopeRoleRead}.scope()
}

// F's client over this api, on its clock, as the VPN component builds it, with gkmSettings as its settings' gkm
// settings, nil for the defaults.
func (self *testForwardingGrantApi) client(t *testing.T, gkmSettings *GkmSettings) *ForwardingClient {
	t.Helper()
	settings := validSidecarSettings()
	if gkmSettings != nil {
		settings.Gkm = gkmSettings
	}
	client, err := NewForwardingClient(&ForwardingClientArgs{
		Settings:      settings,
		Transport:     self,
		ByJwt:         self.byJwt,
		ClientKeySeed: gkmTestBytes("forwarding grant client key", ed25519.SeedSize),
		Clock:         self.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func (self *testForwardingGrantApi) RoundTrip(request *http.Request) (*http.Response, error) {
	body := []byte{}
	if request.Body != nil {
		var err error
		body, err = io.ReadAll(request.Body)
		request.Body.Close()
		if err != nil {
			return nil, err
		}
	}
	switch {
	case request.Method == http.MethodPost && request.URL.Host == "auth.example" && request.URL.Path == "/oauth/token":
		return self.exchange(request, body), nil
	case request.Method == http.MethodGet && request.URL.Host == "gkm.example":
		return self.serveGkm(request), nil
	}
	return syntheticResponse(request, http.StatusNotFound, `{"error":"not_found"}`, nil), nil
}

// POST /oauth/token at gkm, as server/oauth's grantForwardOnly answers F with its proof: of the scopes asked, the
// config's r alone, once api's gate holds the Delegation, the token naming what it granted; invalid_scope where it
// grants none.
func (self *testForwardingGrantApi) exchange(request *http.Request, body []byte) *http.Response {
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return syntheticResponse(request, http.StatusBadRequest, `{"error":"invalid_request"}`, nil)
	}
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	record := &testForwardingGrantExchange{
		at:        now,
		scope:     form.Get("scope"),
		presented: form.Get("subject_token") == self.byJwt && request.Header.Get("DPoP") != "",
	}
	self.exchanges = append(self.exchanges, record)
	granted := []string{}
	if record.presented && form.Get("resource") == "https://gkm.example" && !self.grantAt.IsZero() && !now.Before(self.grantAt) {
		for _, scope := range strings.Fields(record.scope) {
			if scope == self.configScope() {
				granted = append(granted, scope)
			}
		}
	}
	record.granted = 0 < len(granted)
	if !record.granted {
		return syntheticResponse(request, http.StatusBadRequest, `{"error":"invalid_scope"}`, nil)
	}
	token := fmt.Sprintf("synthetic-forwarding-gkm-token-%d", len(self.exchanges))
	self.mintedTokens[token] = true
	return syntheticResponse(request, http.StatusOK, fmt.Sprintf(
		`{"access_token":%q,"issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":900,"scope":%q}`,
		token, strings.Join(granted, " "),
	), nil)
}

// gkm's three reads the Forwarder makes, from the world's gkm, under a token the exchange minted; 401 for any other.
func (self *testForwardingGrantApi) serveGkm(request *http.Request) *http.Response {
	token := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
	record := &testForwardingGrantGkmRequest{at: self.clock.Now(), path: request.URL.Path}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		record.minted = self.mintedTokens[token]
		self.gkmRequests = append(self.gkmRequests, record)
	}()
	if !record.minted {
		return syntheticResponse(request, http.StatusUnauthorized, "", nil)
	}
	answer := func(reply proto.Message, err error) *http.Response {
		if err != nil {
			return syntheticResponse(request, http.StatusInternalServerError, "", nil)
		}
		replyBytes, err := proto.Marshal(reply)
		if err != nil {
			return syntheticResponse(request, http.StatusInternalServerError, "", nil)
		}
		return syntheticResponse(request, http.StatusOK, string(replyBytes), http.Header{"Content-Type": {gkmHttpContentType}})
	}
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/gkm/"), "/")
	idOf := func(text string) (Id, bool) {
		idBytes, err := hex.DecodeString(text)
		if err != nil {
			return Id{}, false
		}
		id, err := IdFromBytes(idBytes)
		return id, err == nil
	}
	query := request.URL.Query()
	ctx := request.Context()
	switch {
	case len(parts) == 3 && parts[0] == "repos" && parts[2] == "forms":
		if repoId, ok := idOf(parts[1]); ok && repoId == self.configRepoId {
			return answer(self.gkm.Forms(ctx, repoId))
		}
	case len(parts) == 3 && parts[0] == "groups" && parts[2] == "gen":
		groupId, ok := idOf(parts[1])
		since, err := strconv.ParseUint(query.Get("since"), 10, 64)
		if ok && err == nil {
			return answer(self.gkm.Generations(ctx, self.configRepoId, groupId, since))
		}
	case len(parts) == 4 && parts[0] == "groups" && parts[2] == "wraps":
		groupId, ok := idOf(parts[1])
		generation, err := strconv.ParseUint(parts[3], 10, 64)
		want, wantErr := hex.DecodeString(query.Get("want"))
		if ok && err == nil && wantErr == nil {
			return answer(self.gkm.Wraps(ctx, self.configRepoId, groupId, generation, &GkmWrapsQuery{Recipient: query.Get("recipient"), Want: want}))
		}
	}
	return syntheticResponse(request, http.StatusForbidden, "", nil)
}

// What the api took, in order.
func (self *testForwardingGrantApi) taken() ([]*testForwardingGrantExchange, []*testForwardingGrantGkmRequest) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.exchanges), slices.Clone(self.gkmRequests)
}

// Runs settle on the test's goroutine while another moves the client's clock past each wait F's reads arm, and
// answers those waits in order. A wait still armed when settle returns is answered too, unmoved.
func (self *testForwardingGrantApi) pump(settle func()) []time.Duration {
	stop := make(chan struct{})
	pumped := make(chan []time.Duration, 1)
	go func() {
		waits := []time.Duration{}
		for {
			select {
			case wait := <-self.clock.armed:
				waits = append(waits, wait)
				self.clock.Advance(wait)
			case <-stop:
				for {
					select {
					case wait := <-self.clock.armed:
						waits = append(waits, wait)
					default:
						pumped <- waits
						return
					}
				}
			}
		}
	}()
	settle()
	close(stop)
	return <-pumped
}

// The exchanges' times after start, as offsets.
func testForwardingGrantOffsets(exchanges []*testForwardingGrantExchange, start time.Time) []time.Duration {
	offsets := []time.Duration{}
	for _, exchange := range exchanges {
		offsets = append(offsets, exchange.at.Sub(start))
	}
	return offsets
}

// Whether the newest compile waited for a generation's key.
func testForwardingGrantWaitsFor(status ForwarderStatus, generation uint64) bool {
	return slices.ContainsFunc(status.Waits, func(wait BridgeCompileWait) bool {
		return wait.Kind == BridgeCompileWaitGeneration && wait.Generation == generation
	})
}

// A forwarding role whose grant reaches api's gate late: the Forwarder's first compile judges a state holding S's
// forwarding Delegation, while api's gate takes it 2.5 s later. The compile's first read of gkm, the config's
// GroupForms, is refused invalid_scope at 0, 1 and 2 s and granted at 3 s, asked again ReadRetryWait apart within
// ExchangeScopeWaitTimeout of its first refusal; its generations and the DelegationWrap are granted at once after it,
// each asking the config's r alone with F's token and proof, and the compile opens generation 1 by the wrap and links
// the peer whose address is sealed to it, all inside the window. The code before ended the read at the exchange's first
// refusal, since F's reads presented the config's r as a scope no verified state backs, so the compile opened nothing
// and left the peer unlinked until its retry CompileRetryInterval later.
func TestAForwardingRoleWhoseGrantReachesApisGateLateReadsGkmWithinTheWindow(t *testing.T) {
	world := newTestForwarderWorld(t)
	world.rotate(world.recipient())
	world.bind(world.peer)
	api := newTestForwardingGrantApi(world)
	start := api.clock.Now()
	api.grantAfter(2500 * time.Millisecond)
	world.forwardGkm = api.client(t, nil).Gkm()

	forwarder := world.forwarderIn(context.Background())
	waits := api.pump(func() { world.settle(forwarder) })

	targets, inForce := forwarder.LinkTargets()
	status := forwarder.Status()
	if !inForce || !slices.Equal(targets, []Id{world.peer.sidecarId}) || status.GenerationCount != 1 || status.CompileErrorCount != 0 {
		t.Fatalf("links %v in force %t, status %+v", targets, inForce, status)
	}
	if key := forwarder.RepoKeyAt(1); key == nil || key.RepoId() != world.net.configRepoId() {
		t.Fatalf("generation 1's key: %v", key)
	}
	if !slices.Equal(waits, gkmGrantLagRepeat(time.Second, 3)) {
		t.Errorf("F's reads waited %v", waits)
	}
	exchanges, requests := api.taken()
	if len(exchanges) < 4 {
		t.Fatalf("%d exchanges", len(exchanges))
	}
	window := DefaultGkmSettings().ExchangeScopeWaitTimeout
	for index, exchange := range exchanges {
		offset := exchange.at.Sub(start)
		if exchange.scope != api.configScope() || !exchange.presented {
			t.Errorf("exchange %d asked %q, presenting F's token and proof %t", index, exchange.scope, exchange.presented)
		}
		switch {
		case index < 3 && (exchange.granted || offset != time.Duration(index)*time.Second):
			t.Errorf("exchange %d at +%s granted %t, want refused at +%ds", index, offset, exchange.granted, index)
		case 3 <= index && (!exchange.granted || offset != 3*time.Second):
			t.Errorf("exchange %d at +%s granted %t, want granted at +3s", index, offset, exchange.granted)
		}
	}
	if last := exchanges[2].at.Sub(exchanges[0].at); window <= last {
		t.Errorf("the last refusal came %s after the first, past the %s window", last, window)
	}
	paths := []string{}
	for _, request := range requests {
		paths = append(paths, request.path)
		if !request.minted || request.at.Sub(start) != 3*time.Second {
			t.Errorf("gkm took %s at +%s under a minted token %t", request.path, request.at.Sub(start), request.minted)
		}
	}
	groupPath := "/gkm/groups/" + gkmUrlId(world.groupId)
	wantPaths := []string{"/gkm/repos/" + gkmUrlId(world.net.configRepoId()) + "/forms", groupPath + "/gen", groupPath + "/wraps/1"}
	if !slices.Equal(paths, wantPaths) {
		t.Errorf("gkm took %v, want %v", paths, wantPaths)
	}
}

// A grant api's gate does not hold within the window: the GroupForms read is refused invalid_scope at 0 to 5 s, six
// asks ReadRetryWait apart, the last at the window's end, and then ends with that refusal, nothing having reached gkm;
// the compile hands its state with generation 1 waiting and the peer sealed to it unlinked, QD-1230's cost. A window
// of 2.5 s set in the client's own settings asks at 0, 1, 2 and 2.5 s, its last wait the half second left. The peer's
// binding is had only later, so no fetch after the compile wants another at once, which would ride out a window of
// its own. Once the gate holds the Delegation, the compile's retry CompileRetryInterval on is granted at its first ask
// and opens it, with no wait.
func TestAForwardingRoleEndsAGrantApisGateNeverHoldsAfterTheWindow(t *testing.T) {
	for _, c := range []struct {
		window  time.Duration
		offsets []time.Duration
		waits   []time.Duration
	}{
		{offsets: []time.Duration{0, time.Second, 2 * time.Second, 3 * time.Second, 4 * time.Second, 5 * time.Second}, waits: gkmGrantLagRepeat(time.Second, 5)},
		{window: 2500 * time.Millisecond, offsets: []time.Duration{0, time.Second, 2 * time.Second, 2500 * time.Millisecond}, waits: []time.Duration{time.Second, time.Second, 500 * time.Millisecond}},
	} {
		world := newTestForwarderWorld(t)
		world.rotate(world.recipient())
		api := newTestForwardingGrantApi(world)
		start := api.clock.Now()
		var gkmSettings *GkmSettings
		if c.window != 0 {
			gkmSettings = DefaultGkmSettings()
			gkmSettings.ExchangeScopeWaitTimeout = c.window
		}
		world.forwardGkm = api.client(t, gkmSettings).Gkm()

		forwarder := world.forwarderIn(context.Background())
		waits := api.pump(func() { world.settle(forwarder) })

		if !slices.Equal(waits, c.waits) {
			t.Errorf("window %s: F's read waited %v, want %v", c.window, waits, c.waits)
		}
		exchanges, requests := api.taken()
		if offsets := testForwardingGrantOffsets(exchanges, start); !slices.Equal(offsets, c.offsets) {
			t.Errorf("window %s: the exchange was asked at %v, want %v", c.window, offsets, c.offsets)
		}
		if slices.ContainsFunc(exchanges, func(exchange *testForwardingGrantExchange) bool { return exchange.granted }) || len(requests) != 0 {
			t.Errorf("window %s: a grant the gate never held reached gkm %d times", c.window, len(requests))
		}
		targets, _ := forwarder.LinkTargets()
		status := forwarder.Status()
		if status.GenerationCount != 0 || !testForwardingGrantWaitsFor(status, 1) || slices.Contains(targets, world.peer.sidecarId) || status.CompileCount != 1 {
			t.Fatalf("window %s: with no grant, links %v, status %+v", c.window, targets, status)
		}

		world.bind(world.peer)
		api.grantAfter(0)
		asked := len(exchanges)
		waits = api.pump(func() { world.advance(forwarder, world.settings.CompileRetryTimeout(0)) })
		if len(waits) != 0 {
			t.Errorf("window %s: the retry waited %v", c.window, waits)
		}
		exchanges, requests = api.taken()
		for _, exchange := range exchanges[asked:] {
			if !exchange.granted {
				t.Errorf("window %s: an exchange after the gate held the grant was refused at +%s", c.window, exchange.at.Sub(start))
			}
		}
		targets, inForce := forwarder.LinkTargets()
		status = forwarder.Status()
		if !inForce || !slices.Equal(targets, []Id{world.peer.sidecarId}) || status.GenerationCount != 1 || testForwardingGrantWaitsFor(status, 1) || len(requests) != 3 {
			t.Errorf("window %s: the retry's links %v in force %t, status %+v, %d requests at gkm", c.window, targets, inForce, status, len(requests))
		}
	}
}

// F's gkm client reads the scopes the exchange granted beside each token, as a member's does through
// Sidecar.GrantedServiceToken (QD-1230): a request of the config's r and another repo's, which the exchange grants
// the first of, answers that one alone with its token, where a client on ServiceToken alone read both as granted. A
// request the exchange grants nothing of is its invalid_scope, read as gkm's client reads it.
func TestTheForwardingClientReadsTheScopesItsExchangeGranted(t *testing.T) {
	world := newTestForwarderWorld(t)
	api := newTestForwardingGrantApi(world)
	client := api.client(t, nil)
	other := GkmRepoScope{RepoId: testConfigId("another repo"), Role: GkmScopeRoleRead}.scope()
	ctx := context.Background()

	_, _, err := client.gkm.api.serviceToken(ctx, "https://gkm.example", []string{api.configScope(), other})
	if refusal := sidecarServiceTokenRefusalOf(err); !refusal.scopeRefused || !refusal.final {
		t.Errorf("before the gate holds the grant: %v", err)
	}
	api.grantAfter(0)
	token, granted, err := client.gkm.api.serviceToken(ctx, "https://gkm.example", []string{api.configScope(), other})
	if err != nil || !slices.Equal(granted, []string{api.configScope()}) {
		t.Fatalf("a partial grant read as %v: %v", granted, err)
	}
	api.stateLock.Lock()
	minted := api.mintedTokens[token]
	api.stateLock.Unlock()
	if !minted {
		t.Error("the token answered is not the one the exchange minted")
	}
}

// A state that gives F nothing is never ridden out: with S's forwarding Delegation revoked in the state the Forwarder
// judges, and api's gate refusing F too, the GroupForms read asks the exchange once and ends at its invalid_scope with
// no wait, nothing reaching gkm, as every read did before QD-1230.
func TestAForwardingRoleWhoseStateGivesFNothingRidesNothingOut(t *testing.T) {
	world := newTestForwarderWorld(t)
	world.rotate(world.recipient())
	world.net.mustPost(world.net.owner, bridge.SignedType_SIGNED_DELEGATION_REVOKE, world.net.delegationRevoke(world.delegationId, 0))
	world.publish()
	api := newTestForwardingGrantApi(world)
	world.forwardGkm = api.client(t, nil).Gkm()

	forwarder := world.forwarderIn(context.Background())
	waits := api.pump(func() { world.settle(forwarder) })

	exchanges, requests := api.taken()
	if len(waits) != 0 || len(exchanges) != 1 || exchanges[0].granted || len(requests) != 0 {
		t.Errorf("a state giving F nothing: waits %v, %d exchanges, %d requests at gkm", waits, len(exchanges), len(requests))
	}
	if status := forwarder.Status(); status.GenerationCount != 0 || len(status.ForwardDelegationId) != 0 {
		t.Errorf("status %+v", status)
	}
}

// The scope F's reads present as a verified state's is the one §7.8's exchange grants a forward_only client of the
// sidecar at the same state (AclExchangeScopes, which the extension's leg does not link): the config's r while the
// sidecar's forwarding Delegation is live, a newer one superseding the first included, and nothing before any, once
// the live one is revoked, for another sidecar with none, for no state and for no sidecar. A read of a state that gives
// nothing presents the config's r as no verified state's, so its first failure to get a token ends it.
func TestTheForwardingClientsVerifiedScopeIsTheExchangesGrant(t *testing.T) {
	net := newTestConfigNet(t)
	_, laptop := net.consentedMember("forwarding scope")
	configRepoId := Id(net.log.State().Genesis().GetConfigRepoId())
	configR := GkmRepoScope{RepoId: configRepoId, Role: GkmScopeRoleRead}.scope()
	api, err := NewGkmApi(&GkmApiArgs{
		GkmUrl:    "https://gkm.example",
		Transport: &gkmTestTransport{},
		GrantedServiceToken: func(ctx context.Context, resource string, scopes []string) (string, []string, error) {
			return "", nil, errors.New("no exchange in this test")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	clientGkm := &forwardingClientGkm{api: api}
	given := func() bool {
		callScopes, err := api.scopesFor(&configRepoId, GkmScopeRoleRead)
		if err != nil {
			t.Fatal(err)
		}
		return callScopes.stateGives && !callScopes.unverified && slices.Equal(callScopes.scopes, []string{configR})
	}
	check := func(name string, sidecarId Id, want bool) {
		t.Helper()
		state := net.log.State()
		now := time.UnixMilli(state.TimeMs())
		grant, err := AclExchangeScopes(state, &AclExchangeRequest{
			SidecarId: sidecarId, Audience: AclTokenAudienceGkm, Scopes: []string{configR}, ForwardOnly: true, Now: now,
		})
		if err != nil {
			t.Fatal(err)
		}
		clientGkm.judgedState(state, sidecarId, now)
		if got, granted := given(), slices.Equal(grant.Scopes, []string{configR}); got != want || granted != want {
			t.Errorf("%s: F's reads backed %t and the exchange granting %t, want %t", name, got, granted, want)
		}
	}
	check("before any forwarding Delegation", laptop.sidecarId, false)
	net.forward(laptop, "first")
	check("while it lives", laptop.sidecarId, true)
	check("another sidecar with none", net.owner.sidecarId, false)
	second := net.forward(laptop, "second")
	check("a newer one superseding it", laptop.sidecarId, true)
	clientGkm.judgedState(nil, laptop.sidecarId, time.UnixMilli(net.timeMs))
	if given() {
		t.Error("no state backs F's reads")
	}
	clientGkm.judgedState(net.log.State(), Id{}, time.UnixMilli(net.timeMs))
	if given() {
		t.Error("no sidecar backs F's reads")
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_DELEGATION_REVOKE, net.delegationRevoke(second.id, 0))
	check("once the live one is revoked", laptop.sidecarId, false)
}
