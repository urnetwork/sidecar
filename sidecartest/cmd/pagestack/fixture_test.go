// The fixture network through pagestack's own listener and proxy (SDK-M4-09; §22.9's Browsers row, "a vault record
// opens with C4 absent"): a device of the vault's owner, admitted after start, reaches gkm and evs by HTTPS alone,
// through the proxy a browser takes and trusting only the stack's certificate, takes its key from gkm's routes and opens
// the record; and evs and gkm honor nothing the fixture's state does not hold.

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"testing"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A stack on listeners of t's own, closed at t's end. Nothing it serves here reads the key origin or the pages.
func testPagestack(t *testing.T) *pagestack {
	t.Helper()
	settings := defaultPagestackSettings()
	settings.keyOrigin, settings.pages = t.TempDir(), t.TempDir()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	stack, err := newPagestack(t.Context(), settings, listener, proxyListener)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stack.close() })
	return stack
}

// The URLs a browser's transport took, recorded.
type testPagestackTrace struct {
	transport http.RoundTripper
	stateLock sync.Mutex
	urls      []*url.URL
}

func (self *testPagestackTrace) RoundTrip(request *http.Request) (*http.Response, error) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.urls = append(self.urls, request.URL)
	}()
	return self.transport.RoundTrip(request)
}

func (self *testPagestackTrace) hosts() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	hosts := []string{}
	for _, requestUrl := range self.urls {
		if !slices.Contains(hosts, requestUrl.Host) {
			hosts = append(hosts, requestUrl.Host)
		}
	}
	slices.Sort(hosts)
	return hosts
}

func (self *testPagestackTrace) schemes() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	schemes := []string{}
	for _, requestUrl := range self.urls {
		if !slices.Contains(schemes, requestUrl.Scheme) {
			schemes = append(schemes, requestUrl.Scheme)
		}
	}
	return schemes
}

// A transport as a browser's: every request by CONNECT through the stack's proxy, TLS trusting the stack's certificate
// alone.
func testPagestackTransport(t *testing.T, stack *pagestack) *testPagestackTrace {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(stack.certificate.Leaf)
	transport := &http.Transport{
		Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: stack.proxyListener.Addr().String()}),
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &testPagestackTrace{transport: transport}
}

func TestVaultRecordOpensOverHttpsAlone(t *testing.T) {
	stack := testPagestack(t)
	ctx := t.Context()
	trace := testPagestackTransport(t, stack)
	device, err := stack.fixture.admit(ctx, "laptop", trace, stack.origin("evs"), stack.origin("gkm"))
	if err != nil {
		t.Fatal(err)
	}
	content := &bytes.Buffer{}
	info, err := device.evs.Repo(stack.fixture.vaultRepoId).ReadHead(ctx, &sidecar.EvsReadArgs{Path: pagestackRecordPath}, content)
	if err != nil {
		t.Fatalf("the record: %v", err)
	}
	if content.String() != pagestackRecordContent || info.SignerSidecarId != stack.fixture.writer.signer.SidecarId {
		t.Errorf("the record: %q, signed by %s", content.String(), info.SignerSidecarId)
	}
	// the generation the rotation made down to the record's, each from gkm over the proxy
	if key, err := device.gkm.CurrentRepoKey(ctx, stack.fixture.vaultRepoId); err != nil || key.Generation() < 2 {
		t.Errorf("the newest key held: %v", err)
	}
	if hosts := trace.hosts(); !slices.Equal(hosts, []string{"evs.sidecartest.example:" + portOf(stack), "gkm.sidecartest.example:" + portOf(stack)}) {
		t.Errorf("the device reached %v", hosts)
	}
	if schemes := trace.schemes(); !slices.Equal(schemes, []string{"https"}) {
		t.Errorf("the device's schemes: %v", schemes)
	}
}

// The TLS port, as text.
func portOf(stack *pagestack) string {
	return stack.proxy.port
}

func TestFixtureIdsAnswerAtTheHarnessAddressAlone(t *testing.T) {
	stack := testPagestack(t)
	pool := x509.NewCertPool()
	pool.AddCert(stack.certificate.Leaf)
	direct := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	defer direct.CloseIdleConnections()
	response, err := direct.Get("https://127.0.0.1:" + portOf(stack) + "/fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	view := &pagestackFixtureView{}
	if err := json.NewDecoder(response.Body).Decode(view); err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("%d, %v", response.StatusCode, err)
	}
	if view.NetworkId != stack.fixture.networkId.String() || view.VaultRepoId != stack.fixture.vaultRepoId.String() ||
		view.MemberId != stack.fixture.memberId.String() || view.RecordPath != pagestackRecordPath {
		t.Errorf("the fixture's ids: %+v", view)
	}
	// no browser reaches the harness's address: the proxy tunnels only fixture names
	browser := &http.Client{Transport: testPagestackTransport(t, stack)}
	if _, err := browser.Get("https://127.0.0.1:" + portOf(stack) + "/fixture.json"); err == nil {
		t.Errorf("the harness's address was proxied")
	}
}

// One request with bearer, if any, through the browser-like transport, answering its status.
func testPagestackStatus(t *testing.T, client *http.Client, method string, requestUrl string, bearer string) int {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, requestUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	return response.StatusCode
}

func TestServicesHonorNothingTheFixtureDoesNotHold(t *testing.T) {
	stack := testPagestack(t)
	fixture := stack.fixture
	client := &http.Client{Transport: testPagestackTransport(t, stack)}
	readScopes := []string{"repo:" + fixture.vaultRepoId.String() + ":r"}
	// a device the state never admitted, a writer's sidecar with a client not its own, and a writer's token of another
	// network
	stranger, err := fixture.newDevice("stranger")
	if err != nil {
		t.Fatal(err)
	}
	unbound := *fixture.writer
	unbound.clientId = sidecar.NewId()
	otherNetwork := func(audience string) string {
		now := fixture.world.Clock().Now()
		sidecarId := connect.Id(fixture.writer.signer.SidecarId)
		return fixture.world.Fakes().Authenticator.Issue(&sidecar.Principal{
			NetworkId: connect.NewId(), ClientId: connect.Id(fixture.writer.clientId), SidecarId: &sidecarId,
			Audience: audience, Scopes: readScopes, IssuedAt: now, ExpiresAt: now.Add(stack.settings.serviceTokenLifetime),
		})
	}
	routes := []struct {
		url      string
		audience string
	}{
		{url: stack.origin("evs") + "/evs/v1/repos/" + sidecar.EvsKeyId(fixture.vaultRepoId), audience: evsservice.EvsAudience},
		{url: stack.origin("gkm") + "/gkm/groups/" + sidecar.EvsKeyId(fixture.vaultGroupId) + "/gen", audience: gkmservice.GkmAudience},
	}
	for _, route := range routes {
		cases := map[string]struct {
			bearer string
			want   int
		}{
			"the writer's own":         {bearer: fixture.token(fixture.writer, route.audience, readScopes), want: http.StatusOK},
			"no token":                 {want: http.StatusUnauthorized},
			"another audience's":       {bearer: fixture.token(fixture.writer, "dns", readScopes), want: http.StatusUnauthorized},
			"another network's":        {bearer: otherNetwork(route.audience), want: http.StatusServiceUnavailable},
			"a sidecar never admitted": {bearer: fixture.token(stranger, route.audience, readScopes), want: http.StatusForbidden},
			"no scope on the vault":    {bearer: fixture.token(fixture.writer, route.audience, nil), want: http.StatusForbidden},
		}
		// evs alone matches the token's client to the sidecar's binding (§11.8's authorization row)
		if route.audience == evsservice.EvsAudience {
			cases["a client not the sidecar's"] = struct {
				bearer string
				want   int
			}{bearer: fixture.token(&unbound, route.audience, readScopes), want: http.StatusForbidden}
		}
		for name, c := range cases {
			if status := testPagestackStatus(t, client, http.MethodGet, route.url, c.bearer); status != c.want {
				t.Errorf("%s, %s: %d, want %d", route.url, name, status, c.want)
			}
		}
	}
}

func TestFixtureStateRefusesWhatItDoesNotHold(t *testing.T) {
	stack := testPagestack(t)
	fixture := stack.fixture
	now := fixture.world.Clock().Now()
	view := fixture.log.Tip()
	writerId := fixture.writer.signer.SidecarId
	for _, c := range []struct {
		right sidecar.AclEvsRights
		want  bool
	}{
		{right: sidecar.AclEvsRead, want: true},
		{right: sidecar.AclEvsWrite, want: true},
		{right: sidecar.AclEvsAdmin, want: true},
		{right: sidecar.AclEvsRead | sidecar.AclEvsWrite, want: true},
		// no fixture device deposits, and a read receipt's deposit is RECORD-M3-12's binding
		{right: sidecar.AclEvsDeposit, want: false},
		{right: sidecar.AclEvsRead | sidecar.AclEvsDeposit, want: false},
		{right: 0, want: false},
	} {
		if got := pagestackHonors(view, fixture.vaultRepoId, writerId, c.right, now); got != c.want {
			t.Errorf("right %d: %t", c.right, got)
		}
	}
	if pagestackHonors(view, sidecar.NewId(), writerId, sidecar.AclEvsRead, now) {
		t.Errorf("a repo the state does not hold was honored")
	}
	if pagestackHonors(view, fixture.vaultRepoId, sidecar.NewId(), sidecar.AclEvsRead, now) {
		t.Errorf("a sidecar the state does not hold was honored")
	}
	// a principal of another network reads as a network whose state is not loaded, whatever it asks
	evsState := &pagestackEvsAuthState{fixture: fixture}
	gkmState := &pagestackGkmAuthState{fixture: fixture}
	sidecarId := connect.Id(writerId)
	other := &sidecar.Principal{NetworkId: connect.NewId(), ClientId: connect.Id(fixture.writer.clientId), SidecarId: &sidecarId}
	if evsState.MatchBinding(other) != evsservice.EvsAuthUnknown || evsState.HonorScope(other, fixture.vaultRepoId, sidecar.AclEvsRead, now) != evsservice.EvsAuthUnknown {
		t.Errorf("evs answered another network")
	}
	if _, answer := evsState.Repo(other, fixture.vaultRepoId); answer != evsservice.EvsAuthUnknown {
		t.Errorf("evs answered another network's repo: %d", answer)
	}
	if _, answer := (&pagestackGateViews{fixture: fixture}).View(sidecar.NewId()); answer != evsservice.EvsAuthUnknown {
		t.Errorf("evs's gate views answered another network: %d", answer)
	}
	if _, answer := gkmState.Sidecar(other, writerId); answer != gkmservice.GkmAuthUnknown {
		t.Errorf("gkm answered another network's sidecar: %d", answer)
	}
	if gkmState.CheckPin(other, view.Pin()) != gkmservice.GkmAuthUnknown {
		t.Errorf("gkm judged another network's pin")
	}
	own := &sidecar.Principal{NetworkId: connect.Id(fixture.networkId), ClientId: connect.Id(fixture.writer.clientId), SidecarId: &sidecarId}
	if gkmState.CheckPin(own, view.Pin()) != gkmservice.GkmAuthAllowed {
		t.Errorf("the tip's own pin was not on its chain")
	}
	forked := &bridge.AuthPin{Version: view.Pin().GetVersion(), Chain: bytes.Repeat([]byte{7}, len(view.Pin().GetChain()))}
	if gkmState.CheckPin(own, forked) != gkmservice.GkmAuthDenied {
		t.Errorf("a pin off the tip's chain was not denied")
	}
	ahead := &bridge.AuthPin{Version: view.Pin().GetVersion() + 1, Chain: view.Pin().GetChain()}
	if gkmState.CheckPin(own, ahead) != gkmservice.GkmAuthUnknown {
		t.Errorf("a pin past the tip was judged")
	}
	if _, answer := gkmState.DelegationKey(own, bytes.Repeat([]byte{1}, 16)); answer != gkmservice.GkmAuthDenied {
		t.Errorf("a Delegation the fixture does not hold: %d", answer)
	}
	if _, answer := evsState.Repo(own, sidecar.NewId()); answer != evsservice.EvsAuthDenied {
		t.Errorf("a repo the fixture does not hold: %d", answer)
	}
	facts, answer := evsState.Repo(own, fixture.vaultRepoId)
	if answer != evsservice.EvsAuthAllowed || facts.Kind != protocol.RepoKind_REPO_KIND_VAULT || facts.OwnerMemberId != fixture.memberId ||
		facts.NetworkId != fixture.networkId {
		t.Errorf("the vault's facts: %+v, %d", facts, answer)
	}
}
