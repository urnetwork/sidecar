// tls/'s ValidateListen at T2 (TLS-M5-22, §22.5's §13 row): each row of §13.9's refusal table with its positive twin
// on a fake facts source and a fake view, a URnetwork-run client refused, an unknown fact refused, the time box's
// edges (a Community 8-day grant refused and a 7-day one passing, a probation 25 h grant refused), the facts read off
// the path and kept through a failed read, and the hooks composed into the engine's registration path.

package socketsservice_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/socketsservice"
)

// A facts source a test fills, network by network, that counts its reads and fails while err is set.
type testTlsFactsSource struct {
	stateLock       sync.Mutex
	networkIdFacts  map[connect.Id]*socketsservice.TlsListenFacts
	err             error
	readCount       int
	networkIdsAsked []connect.Id
}

func newTestTlsFactsSource() *testTlsFactsSource {
	return &testTlsFactsSource{networkIdFacts: map[connect.Id]*socketsservice.TlsListenFacts{}}
}

// See socketsservice.TlsListenFactsSource.
func (self *testTlsFactsSource) ListenFacts(ctx context.Context, networkId connect.Id) (*socketsservice.TlsListenFacts, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.readCount += 1
	self.networkIdsAsked = append(self.networkIdsAsked, networkId)
	if self.err != nil {
		return nil, self.err
	}
	facts, found := self.networkIdFacts[networkId]
	if !found {
		return nil, errors.New("no such network")
	}
	return facts, nil
}

// Sets the network's facts, which the next read answers.
func (self *testTlsFactsSource) set(networkId connect.Id, facts *socketsservice.TlsListenFacts) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networkIdFacts[networkId] = facts
}

// Makes every read fail with err, or succeed again with nil.
func (self *testTlsFactsSource) setErr(err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.err = err
}

// Reads so far.
func (self *testTlsFactsSource) reads() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.readCount
}

// A view that answers PublishGrant with the grant a test sets, and records the app mode it was asked for. Its other
// answers refuse, since the hook asks nothing else.
type testTlsView struct {
	grant         *sidecar.AclPublishGrant
	askedAppModes []string
	askedNames    []string
}

var _ socketsservice.SocketGateView = (*testTlsView)(nil)

func (self *testTlsView) Position() uint64 {
	return 1
}

func (self *testTlsView) MayListen(request *socketsservice.SocketGateRequest, now time.Time) *socketsservice.SocketGateVerdict {
	return &socketsservice.SocketGateVerdict{}
}

func (self *testTlsView) MayDial(request *socketsservice.SocketGateRequest, now time.Time) *socketsservice.SocketGateVerdict {
	return &socketsservice.SocketGateVerdict{}
}

func (self *testTlsView) MayPublish(request *socketsservice.SocketGateRequest, now time.Time) *socketsservice.SocketGateVerdict {
	return &socketsservice.SocketGateVerdict{}
}

func (self *testTlsView) PublishGrant(request *socketsservice.SocketGateRequest, appMode string, now time.Time) *sidecar.AclPublishGrant {
	self.askedAppModes = append(self.askedAppModes, appMode)
	self.askedNames = append(self.askedNames, request.Name)
	return self.grant
}

func (self *testTlsView) IdentityKey(sidecarId connect.Id) ([]byte, bool) {
	return nil, false
}

// One entry's world: a verified Pro network whose sidecar holds the network's pair until a day from now and a
// members http publish grant for tls/443/blog expiring in an hour. Each case changes one thing.
type testTlsListenScene struct {
	t         *testing.T
	ctx       context.Context
	clock     *sidecartest.FakeClock
	source    *testTlsFactsSource
	hooks     *socketsservice.TlsNamespaceHooks
	networkId connect.Id
	clientId  connect.Id
	sidecarId connect.Id
	facts     *socketsservice.TlsListenFacts
	view      *testTlsView
	check     *socketsservice.SocketListenCheck
}

func newTestTlsListenScene(t *testing.T, mutate func(settings *socketsservice.TlsNamespaceSettings)) *testTlsListenScene {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := socketsservice.DefaultTlsNamespaceSettings()
	if mutate != nil {
		mutate(settings)
	}
	source := newTestTlsFactsSource()
	hooks, err := socketsservice.NewTlsNamespaceHooks(ctx, source, clock, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hooks.Close)
	scene := &testTlsListenScene{
		t:         t,
		ctx:       ctx,
		clock:     clock,
		source:    source,
		hooks:     hooks,
		networkId: testSocketId(),
		clientId:  testSocketId(),
		sidecarId: testSocketId(),
	}
	now := clock.Now()
	scene.facts = &socketsservice.TlsListenFacts{
		Verified: true,
		Standing: sidecar.AbuseStandingStandard,
		Tier:     "pro",
		Certs: []*socketsservice.TlsListenCert{
			{SidecarId: scene.sidecarId, NotAfter: now.Add(24 * time.Hour), NetworkPair: true},
		},
	}
	scene.view = &testTlsView{
		grant: &sidecar.AclPublishGrant{
			GrantIds:  [][]byte{[]byte("grant")},
			Audience:  protocol.AclAudience_ACL_AUDIENCE_MEMBERS,
			AppMode:   protocol.AclAppMode_ACL_APP_MODE_HTTP,
			ExpiresMs: now.Add(time.Hour).UnixMilli(),
		},
	}
	listenId := testSocketId()
	sidecarId := scene.sidecarId
	scene.check = &socketsservice.SocketListenCheck{
		NetworkId:        scene.networkId,
		ListenerClientId: scene.clientId,
		SidecarId:        &sidecarId,
		Name:             "tls/443/blog",
		Namespace:        sidecar.SocketNamespaceTls,
		Registration: &sidecar.SocketRegistration{
			Name:       "tls/443/blog",
			ListenId:   &listenId,
			Protocol:   "tls",
			AppMode:    "http",
			Weight:     100,
			MaxStreams: 256,
			Serving:    true,
		},
		Listen: &socketsservice.SocketGateVerdict{Allowed: true, GrantId: []byte("listen"), PolicyVersion: 1},
		View:   scene.view,
	}
	return scene
}

// Sets the scene's name on the check and its registration.
func (self *testTlsListenScene) setName(name string) {
	self.check.Name = name
	self.check.Registration.Name = name
}

// Hands the source the scene's facts and has the hooks read them now.
func (self *testTlsListenScene) load() {
	self.t.Helper()
	self.source.set(self.networkId, self.facts)
	if err := self.hooks.LoadFacts(self.ctx, self.networkId); err != nil {
		self.t.Fatal(err)
	}
}

// The hooks' answer on the scene's check, its facts read first.
func (self *testTlsListenScene) validate() error {
	self.t.Helper()
	self.load()
	return self.hooks.ValidateListen(self.ctx, self.check)
}

// Waits until the hooks have finished count reads in all.
func (self *testTlsListenScene) awaitLoads(count uint64) {
	self.t.Helper()
	for {
		loaded, changed := self.hooks.Loads()
		if count <= loaded {
			return
		}
		select {
		case <-changed:
		case <-self.ctx.Done():
			self.t.Fatalf("%d reads of %d", loaded, count)
		}
	}
}

// One row of the table: what it changes, and whether the entry then passes.
type testTlsListenCase struct {
	name   string
	mutate func(scene *testTlsListenScene)
	allow  bool
}

// Runs each case on a fresh scene, the error a refusal for a refused case and nil for a passing one.
func testTlsListenCases(t *testing.T, cases []testTlsListenCase) {
	t.Helper()
	for _, c := range cases {
		scene := newTestTlsListenScene(t, nil)
		c.mutate(scene)
		err := scene.validate()
		switch {
		case c.allow && err != nil:
			t.Errorf("%s: refused with %v", c.name, err)
		case !c.allow && !errors.Is(err, socketsservice.ErrSocketListenRefused):
			t.Errorf("%s: answered %v, not a refusal", c.name, err)
		}
	}
}

// A brand's own domains from the screen's list, so no real hostname is written here.
func testTlsBrandDomains(t *testing.T, brand string) []string {
	t.Helper()
	for _, screenBrand := range sidecar.ScreenBrands() {
		if screenBrand.Brand == brand && 0 < len(screenBrand.Domains) {
			return screenBrand.Domains
		}
	}
	t.Fatalf("no brand %q with a domain", brand)
	return nil
}

// The scene as built passes, the view asked for the registration's own name and mode.
func TestTlsListenPassesAPublishedHostWithACertificate(t *testing.T) {
	scene := newTestTlsListenScene(t, nil)
	if err := scene.validate(); err != nil {
		t.Fatalf("refused: %v", err)
	}
	if !slices.Equal(scene.view.askedAppModes, []string{"http"}) || !slices.Equal(scene.view.askedNames, []string{"tls/443/blog"}) {
		t.Fatalf("the view was asked %v for %v", scene.view.askedNames, scene.view.askedAppModes)
	}
}

// The shape row: a non-tls/ entry, a name that is not canonical, and an app mode tls/ does not take.
func TestTlsListenRefusesAMalformedEntry(t *testing.T) {
	testTlsListenCases(t, []testTlsListenCase{
		{name: "smtp/ namespace", mutate: func(scene *testTlsListenScene) {
			scene.check.Namespace = sidecar.SocketNamespaceSmtp
		}},
		{name: "no registration", mutate: func(scene *testTlsListenScene) {
			scene.check.Registration = nil
		}},
		{name: "upper case", mutate: func(scene *testTlsListenScene) {
			scene.check.Name = "tls/443/Blog"
		}},
		{name: "a fourth segment", mutate: func(scene *testTlsListenScene) {
			scene.check.Name = "tls/443/blog/x"
		}},
		{name: "app mode ws", mutate: func(scene *testTlsListenScene) {
			scene.check.Registration.AppMode = "ws"
		}},
		{name: "twin", mutate: func(scene *testTlsListenScene) {}, allow: true},
	})
}

// The client row (D-TLS-1): an entry with no sidecar, which platform clients and hosted devices never hold, and a
// sidecar bound to a hosted device, refused; the scene's own sidecar passes.
func TestTlsListenRefusesAUrnetworkRunClient(t *testing.T) {
	testTlsListenCases(t, []testTlsListenCase{
		{name: "no sidecar", mutate: func(scene *testTlsListenScene) {
			scene.check.SidecarId = nil
		}},
		{name: "the zero sidecar", mutate: func(scene *testTlsListenScene) {
			zero := connect.Id{}
			scene.check.SidecarId = &zero
		}},
		{name: "a hosted device's sidecar", mutate: func(scene *testTlsListenScene) {
			scene.facts.HostedSidecarIds = []connect.Id{scene.sidecarId}
		}},
		{name: "another sidecar hosted", mutate: func(scene *testTlsListenScene) {
			scene.facts.HostedSidecarIds = []connect.Id{testSocketId()}
		}, allow: true},
	})
}

// The port row: a port the settings do not list is refused, each of the four passing by default.
func TestTlsListenRefusesAPortTlsedgeDoesNotServe(t *testing.T) {
	for _, port := range []string{"443", "8443", "8883", "5671"} {
		scene := newTestTlsListenScene(t, nil)
		scene.setName("tls/" + port + "/blog")
		if err := scene.validate(); err != nil {
			t.Errorf("port %s refused: %v", port, err)
		}
	}
	scene := newTestTlsListenScene(t, func(settings *socketsservice.TlsNamespaceSettings) {
		settings.Ports = []string{"443"}
	})
	scene.setName("tls/8443/blog")
	if err := scene.validate(); !errors.Is(err, socketsservice.ErrSocketListenRefused) {
		t.Fatalf("an unlisted port answered %v", err)
	}
	if settings := socketsservice.DefaultTlsNamespaceSettings(); settings.Validate() != nil {
		t.Fatal("the defaults do not validate")
	}
	bad := socketsservice.DefaultTlsNamespaceSettings()
	bad.Ports = []string{"8080"}
	if err := bad.Validate(); !errors.Is(err, socketsservice.ErrSocketsSettingsRefused) {
		t.Fatalf("a port no tls/ name takes validated: %v", err)
	}
}

// The host row: mta-sts on any port (the system publish waits for TLS-M8-02), a scope host (TLS-M6-03), and the
// hosts §13.5 maps to no listener of the network's, which ScreenHost denies whatever the facts: §12.7's system hosts
// and a word-number label. The apex and an ordinary host pass.
func TestTlsListenRefusesAHostNoListenerTakes(t *testing.T) {
	cases := []testTlsListenCase{}
	for _, name := range []string{"tls/443/mta-sts", "tls/8443/mta-sts", "tls/443/blog.team", "tls/443/mx", "tls/443/b",
		"tls/443/mail", "tls/443/apple-1234"} {
		cases = append(cases, testTlsListenCase{name: name, mutate: func(scene *testTlsListenScene) {
			scene.setName(name)
		}})
	}
	for _, name := range []string{"tls/443/@", "tls/443/www", "tls/443/api"} {
		cases = append(cases, testTlsListenCase{name: name, mutate: func(scene *testTlsListenScene) {
			scene.setName(name)
		}, allow: true})
	}
	testTlsListenCases(t, cases)
}

// The screen row (QD-188, QD-807): a brand the network has not verified is denied and one it has passes; a brand with
// a keyword goes to review, refused until a reviewer allows that host for the network; on probation the review is a
// denial.
func TestTlsListenScreensTheHost(t *testing.T) {
	testTlsListenCases(t, []testTlsListenCase{
		{name: "an unverified brand", mutate: func(scene *testTlsListenScene) {
			scene.setName("tls/443/apple")
		}},
		{name: "a verified brand", mutate: func(scene *testTlsListenScene) {
			scene.setName("tls/443/apple")
			scene.facts.VerifiedDomains = testTlsBrandDomains(t, "apple")
		}, allow: true},
		{name: "a brand with a keyword", mutate: func(scene *testTlsListenScene) {
			scene.setName("tls/443/apple-login")
		}},
		{name: "a brand with a keyword a reviewer allowed", mutate: func(scene *testTlsListenScene) {
			scene.setName("tls/443/apple-login")
			scene.facts.ScreenAllowedHosts = []string{"apple-login"}
		}, allow: true},
		{name: "another host allowed", mutate: func(scene *testTlsListenScene) {
			scene.setName("tls/443/apple-login")
			scene.facts.ScreenAllowedHosts = []string{"apple-support"}
		}},
		{name: "a scope label as a host", mutate: func(scene *testTlsListenScene) {
			scene.setName("tls/443/team")
			scene.facts.ScopeLabels = []string{"team"}
		}},
	})
}

// The grant row: no grant; a mode other than the registration's, each way; raw under members or members-device; a raw
// link with no pin or a short one. Their twins: raw public, raw link with its 32-byte pin, http under each audience.
func TestTlsListenRefusesAGrantOfAnotherShape(t *testing.T) {
	raw := func(scene *testTlsListenScene, audience protocol.AclAudience, pin []byte) {
		scene.check.Registration.AppMode = "raw"
		scene.view.grant.AppMode = protocol.AclAppMode_ACL_APP_MODE_RAW
		scene.view.grant.Audience = audience
		scene.view.grant.LinkSpkiSha256 = pin
	}
	pin := bytes.Repeat([]byte{7}, sha256.Size)
	cases := []testTlsListenCase{
		{name: "no grant", mutate: func(scene *testTlsListenScene) {
			scene.view.grant = nil
		}},
		{name: "http registration on a raw grant", mutate: func(scene *testTlsListenScene) {
			scene.view.grant.AppMode = protocol.AclAppMode_ACL_APP_MODE_RAW
			scene.view.grant.Audience = protocol.AclAudience_ACL_AUDIENCE_PUBLIC
		}},
		{name: "raw registration on an http grant", mutate: func(scene *testTlsListenScene) {
			scene.check.Registration.AppMode = "raw"
		}},
		{name: "raw members", mutate: func(scene *testTlsListenScene) {
			raw(scene, protocol.AclAudience_ACL_AUDIENCE_MEMBERS, nil)
		}},
		{name: "raw members-device", mutate: func(scene *testTlsListenScene) {
			raw(scene, protocol.AclAudience_ACL_AUDIENCE_MEMBERS_DEVICE, nil)
		}},
		{name: "raw unspecified, read as members", mutate: func(scene *testTlsListenScene) {
			raw(scene, protocol.AclAudience_ACL_AUDIENCE_UNSPECIFIED, nil)
		}},
		{name: "raw link with no pin", mutate: func(scene *testTlsListenScene) {
			raw(scene, protocol.AclAudience_ACL_AUDIENCE_LINK, nil)
		}},
		{name: "raw link with a short pin", mutate: func(scene *testTlsListenScene) {
			raw(scene, protocol.AclAudience_ACL_AUDIENCE_LINK, pin[:31])
		}},
		{name: "raw public", mutate: func(scene *testTlsListenScene) {
			raw(scene, protocol.AclAudience_ACL_AUDIENCE_PUBLIC, nil)
		}, allow: true},
		{name: "raw link with its pin", mutate: func(scene *testTlsListenScene) {
			raw(scene, protocol.AclAudience_ACL_AUDIENCE_LINK, pin)
		}, allow: true},
		{name: "http on an unspecified mode, read as http", mutate: func(scene *testTlsListenScene) {
			scene.view.grant.AppMode = protocol.AclAppMode_ACL_APP_MODE_UNSPECIFIED
		}, allow: true},
	}
	for _, audience := range []protocol.AclAudience{protocol.AclAudience_ACL_AUDIENCE_MEMBERS,
		protocol.AclAudience_ACL_AUDIENCE_MEMBERS_DEVICE, protocol.AclAudience_ACL_AUDIENCE_LINK,
		protocol.AclAudience_ACL_AUDIENCE_PUBLIC} {
		cases = append(cases, testTlsListenCase{name: "http " + audience.String(), mutate: func(scene *testTlsListenScene) {
			scene.view.grant.Audience = audience
		}, allow: true})
	}
	testTlsListenCases(t, cases)
}

// The network row (QD-107): an unverified network is refused, and a suspended one, or one in a standing or tier this
// build does not read, publishes nothing.
func TestTlsListenRefusesAnUnverifiedOrSuspendedNetwork(t *testing.T) {
	testTlsListenCases(t, []testTlsListenCase{
		{name: "unverified", mutate: func(scene *testTlsListenScene) {
			scene.facts.Verified = false
		}},
		{name: "suspended", mutate: func(scene *testTlsListenScene) {
			scene.facts.Standing = sidecar.AbuseStandingSuspended
		}},
		{name: "an unknown standing", mutate: func(scene *testTlsListenScene) {
			scene.facts.Standing = sidecar.AbuseStanding("frozen")
		}},
		{name: "no standing", mutate: func(scene *testTlsListenScene) {
			scene.facts.Standing = ""
		}},
		{name: "an unknown tier", mutate: func(scene *testTlsListenScene) {
			scene.facts.Tier = "enterprise"
		}},
		{name: "trusted", mutate: func(scene *testTlsListenScene) {
			scene.facts.Standing = sidecar.AbuseStandingTrusted
		}, allow: true},
	})
}

// The time box (QD-107): at Community a grant of 8 days, or none, is refused and one of 7 days passes; on probation
// or restricted 25 h is refused and 24 h passes, at any tier; Pro and Team hold standing names; a Community network
// whose tier fell keeps a standing grant until §20.7's 14 days end.
func TestTlsListenHoldsThePublishTimeBox(t *testing.T) {
	expiring := func(lifetime time.Duration) func(scene *testTlsListenScene) {
		return func(scene *testTlsListenScene) {
			scene.view.grant.ExpiresMs = scene.clock.Now().Add(lifetime).UnixMilli()
		}
	}
	standing := func(scene *testTlsListenScene) {
		scene.view.grant.ExpiresMs = 0
	}
	community := func(scene *testTlsListenScene) {
		scene.facts.Tier = "free"
	}
	probation := func(scene *testTlsListenScene) {
		scene.facts.Standing = sidecar.AbuseStandingProbation
	}
	restricted := func(scene *testTlsListenScene) {
		scene.facts.Standing = sidecar.AbuseStandingRestricted
	}
	both := func(mutates ...func(scene *testTlsListenScene)) func(scene *testTlsListenScene) {
		return func(scene *testTlsListenScene) {
			for _, mutate := range mutates {
				mutate(scene)
			}
		}
	}
	testTlsListenCases(t, []testTlsListenCase{
		{name: "Community 8 days", mutate: both(community, expiring(8*24*time.Hour))},
		{name: "Community 7 days and a minute", mutate: both(community, expiring(7*24*time.Hour+time.Minute))},
		{name: "Community 7 days", mutate: both(community, expiring(7*24*time.Hour)), allow: true},
		{name: "Community standing", mutate: both(community, standing)},
		{name: "probation 25 h", mutate: both(probation, expiring(25*time.Hour))},
		{name: "probation 24 h", mutate: both(probation, expiring(24*time.Hour)), allow: true},
		{name: "probation standing at Pro", mutate: both(probation, standing)},
		{name: "probation 25 h at Team", mutate: func(scene *testTlsListenScene) {
			probation(scene)
			scene.facts.Tier = "team"
			expiring(25 * time.Hour)(scene)
		}},
		{name: "restricted 25 h", mutate: both(restricted, expiring(25*time.Hour))},
		{name: "restricted 24 h", mutate: both(restricted, expiring(24*time.Hour)), allow: true},
		{name: "Pro standing", mutate: standing, allow: true},
		{name: "Team standing", mutate: func(scene *testTlsListenScene) {
			scene.facts.Tier = "team"
			standing(scene)
		}, allow: true},
		{name: "Community standing within the downgrade's 14 days", mutate: func(scene *testTlsListenScene) {
			community(scene)
			standing(scene)
			scene.facts.StandingGrantsEndTime = scene.clock.Now().Add(time.Hour)
		}, allow: true},
		{name: "Community standing past the downgrade's 14 days", mutate: func(scene *testTlsListenScene) {
			community(scene)
			standing(scene)
			scene.facts.StandingGrantsEndTime = scene.clock.Now()
		}},
	})
}

// The cert row: no row, another sidecar's, one past not_after, and one naming only a scope's pair are refused; the
// apex rides the network's pair; an acme-tls/1-only registration, a TLS-ALPN-01 responder before its first order,
// needs none, while acme-tls/1 among other ids does.
func TestTlsListenRefusesAListenerWithNoCertificate(t *testing.T) {
	testTlsListenCases(t, []testTlsListenCase{
		{name: "no certificate", mutate: func(scene *testTlsListenScene) {
			scene.facts.Certs = nil
		}},
		{name: "another sidecar's", mutate: func(scene *testTlsListenScene) {
			scene.facts.Certs[0].SidecarId = testSocketId()
		}},
		{name: "expired", mutate: func(scene *testTlsListenScene) {
			scene.facts.Certs[0].NotAfter = scene.clock.Now()
		}},
		{name: "a scope's pair alone", mutate: func(scene *testTlsListenScene) {
			scene.facts.Certs[0].NetworkPair = false
			scene.facts.Certs[0].ScopePairs = []string{"team"}
		}},
		{name: "an expired one beside a live one", mutate: func(scene *testTlsListenScene) {
			scene.facts.Certs = append([]*socketsservice.TlsListenCert{
				{SidecarId: scene.sidecarId, NotAfter: scene.clock.Now().Add(-time.Hour), NetworkPair: true},
			}, scene.facts.Certs...)
		}, allow: true},
		{name: "the apex", mutate: func(scene *testTlsListenScene) {
			scene.setName("tls/443/@")
		}, allow: true},
		{name: "acme-tls/1 alone with no certificate", mutate: func(scene *testTlsListenScene) {
			scene.facts.Certs = nil
			scene.check.Registration.Alpn = []string{"acme-tls/1"}
		}, allow: true},
		{name: "acme-tls/1 and h2 with no certificate", mutate: func(scene *testTlsListenScene) {
			scene.facts.Certs = nil
			scene.check.Registration.Alpn = []string{"acme-tls/1", "h2"}
		}},
	})
}

// An unknown fact refuses, never passes: an entry before the network's facts load answers undecided and asks a
// worker for a read, a read that fails leaves it undecided, and once a read lands it is judged.
func TestTlsListenAnswersUndecidedUntilItsFactsLoad(t *testing.T) {
	scene := newTestTlsListenScene(t, nil)
	scene.source.setErr(errors.New("api down"))
	if err := scene.hooks.ValidateListen(scene.ctx, scene.check); !errors.Is(err, socketsservice.ErrSocketListenUnavailable) {
		t.Fatalf("with no facts answered %v", err)
	}
	scene.awaitLoads(1)
	if err := scene.hooks.ValidateListen(scene.ctx, scene.check); !errors.Is(err, socketsservice.ErrSocketListenUnavailable) {
		t.Fatalf("after a failed read answered %v", err)
	}
	if reads := scene.source.reads(); reads != 1 {
		t.Fatalf("%d reads within the retry interval", reads)
	}
	// the retry interval passes and the source answers: the next entry asks again, and is judged once the read lands
	scene.source.setErr(nil)
	scene.source.set(scene.networkId, scene.facts)
	scene.clock.Advance(socketsservice.DefaultTlsNamespaceSettings().FactsRetryInterval)
	if err := scene.hooks.ValidateListen(scene.ctx, scene.check); !errors.Is(err, socketsservice.ErrSocketListenUnavailable) {
		t.Fatalf("before the second read answered %v", err)
	}
	scene.awaitLoads(2)
	if err := scene.hooks.ValidateListen(scene.ctx, scene.check); err != nil {
		t.Fatalf("once loaded refused: %v", err)
	}
	// a refusal the check can make before the facts is a refusal, never undecided
	other := newTestTlsListenScene(t, nil)
	other.view.grant = nil
	if err := other.hooks.ValidateListen(other.ctx, other.check); !errors.Is(err, socketsservice.ErrSocketListenRefused) {
		t.Fatalf("a refused entry with no facts answered %v", err)
	}
}

// Facts are read again once FactsRefreshInterval old, the old facts serving until the read lands, and a failed
// refresh keeps the last facts serving (plan-SOCK-gate-data).
func TestTlsListenRefreshesItsFactsOffThePath(t *testing.T) {
	scene := newTestTlsListenScene(t, nil)
	if err := scene.validate(); err != nil {
		t.Fatal(err)
	}
	settings := socketsservice.DefaultTlsNamespaceSettings()
	// within the interval no read is asked for
	scene.clock.Advance(settings.FactsRefreshInterval - time.Second)
	if err := scene.hooks.ValidateListen(scene.ctx, scene.check); err != nil {
		t.Fatal(err)
	}
	if reads := scene.source.reads(); reads != 1 {
		t.Fatalf("%d reads within the interval", reads)
	}
	// the network is no longer verified: the old facts serve until the read lands, then the entry is refused
	scene.source.set(scene.networkId, &socketsservice.TlsListenFacts{
		Verified: false,
		Standing: sidecar.AbuseStandingStandard,
		Tier:     "pro",
		Certs:    scene.facts.Certs,
	})
	scene.clock.Advance(time.Second)
	if err := scene.hooks.ValidateListen(scene.ctx, scene.check); err != nil {
		t.Fatalf("the old facts did not serve: %v", err)
	}
	scene.awaitLoads(2)
	if err := scene.hooks.ValidateListen(scene.ctx, scene.check); !errors.Is(err, socketsservice.ErrSocketListenRefused) {
		t.Fatalf("the new facts answered %v", err)
	}
	// a failed refresh keeps them
	scene.source.setErr(errors.New("api down"))
	scene.clock.Advance(settings.FactsRefreshInterval)
	if err := scene.hooks.ValidateListen(scene.ctx, scene.check); !errors.Is(err, socketsservice.ErrSocketListenRefused) {
		t.Fatalf("before the failed read answered %v", err)
	}
	scene.awaitLoads(3)
	if err := scene.hooks.ValidateListen(scene.ctx, scene.check); !errors.Is(err, socketsservice.ErrSocketListenRefused) {
		t.Fatalf("a failed read dropped the facts: %v", err)
	}
}

// The hooks hold at most FactsMaxNetworkCount networks, the one read longest ago going first.
func TestTlsListenBoundsTheNetworksItHolds(t *testing.T) {
	scene := newTestTlsListenScene(t, func(settings *socketsservice.TlsNamespaceSettings) {
		settings.FactsMaxNetworkCount = 2
	})
	networkIds := []connect.Id{testSocketId(), testSocketId(), testSocketId()}
	for _, networkId := range networkIds {
		scene.source.set(networkId, scene.facts)
		if err := scene.hooks.LoadFacts(scene.ctx, networkId); err != nil {
			t.Fatal(err)
		}
		scene.clock.Advance(time.Second)
	}
	readsBefore := scene.source.reads()
	// the first network went: its entry is undecided again and asks for a read
	scene.check.NetworkId = networkIds[0]
	if err := scene.hooks.ValidateListen(scene.ctx, scene.check); !errors.Is(err, socketsservice.ErrSocketListenUnavailable) {
		t.Fatalf("an evicted network answered %v", err)
	}
	scene.awaitLoads(uint64(readsBefore) + 1)
	scene.check.NetworkId = networkIds[2]
	if err := scene.hooks.ValidateListen(scene.ctx, scene.check); err != nil {
		t.Fatalf("a held network refused: %v", err)
	}
}

// A host gives tls/ no hooks without a source, and refuses settings that cannot serve.
func TestTlsListenOpensOnlyWithASource(t *testing.T) {
	ctx := context.Background()
	if _, err := socketsservice.NewTlsNamespaceHooks(ctx, nil, nil, nil); err == nil {
		t.Fatal("hooks with no source")
	}
	settings := socketsservice.DefaultTlsNamespaceSettings()
	settings.FactsRefreshInterval = 0
	if _, err := socketsservice.NewTlsNamespaceHooks(ctx, newTestTlsFactsSource(), nil, settings); !errors.Is(err, socketsservice.ErrSocketsSettingsRefused) {
		t.Fatalf("a zero refresh interval answered %v", err)
	}
}

// Composed into the engine's registration path on the fake gate: the page's view answers the publish grant, an entry
// before its network's facts load makes the page unavailable, once loaded the entry is ok, and when the certificate
// row ends the next heartbeat after a refresh ends the lease as revoked. A raw link entry rides its pinned grant.
func TestTlsListenComposesIntoTheRegistrationPath(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	listener := testSocketEnrolledListener(world, process)
	source := newTestTlsFactsSource()
	hooks, err := socketsservice.NewTlsNamespaceHooks(world.ctx, source, world.clock, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hooks.Close)
	if err := process.service.RegisterNamespace(sidecar.SocketNamespaceTls, hooks); err != nil {
		t.Fatal(err)
	}
	now := world.clock.Now()
	pin := bytes.Repeat([]byte{9}, sha256.Size)
	process.gate.AllowListen(listener.networkId, listener.sidecarId, []byte("tls/443/blog"), testSocketGrant("blog"))
	process.gate.AllowPublish(listener.networkId, []byte("tls/443/blog"), sidecartest.FakeSocketGrant{
		GrantId:      []byte("blog-publish"),
		ExpireMillis: uint64(now.Add(time.Hour).UnixMilli()),
	})
	process.gate.AllowListen(listener.networkId, listener.sidecarId, []byte("tls/8883/mqtt"), testSocketGrant("mqtt"))
	process.gate.AllowPublish(listener.networkId, []byte("tls/8883/mqtt"), sidecartest.FakeSocketGrant{
		GrantId:        []byte("mqtt-publish"),
		ExpireMillis:   uint64(now.Add(time.Hour).UnixMilli()),
		Audience:       protocol.AclAudience_ACL_AUDIENCE_LINK,
		AppMode:        protocol.AclAppMode_ACL_APP_MODE_RAW,
		LinkSpkiSha256: pin,
	})
	process.gate.Load(listener.networkId)
	facts := &socketsservice.TlsListenFacts{
		Verified: true,
		Standing: sidecar.AbuseStandingStandard,
		Tier:     "pro",
		Certs: []*socketsservice.TlsListenCert{
			{SidecarId: listener.sidecarId, NotAfter: now.Add(24 * time.Hour), NetworkPair: true},
		},
	}
	source.set(listener.networkId, facts)
	blog := listener.edgeRegistration(t, "tls/443/blog", "tls", "http")
	mqtt := listener.edgeRegistration(t, "tls/8883/mqtt", "tls", "raw")
	args := &sidecar.SocketRegistrationsArgs{SetVersion: 1, Registrations: testSocketSortRegistrations([]*sidecar.SocketRegistration{blog, mqtt})}
	code, result := process.register(listener.token, args)
	if code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeUnavailable {
		t.Fatalf("before the facts loaded answered %d, %+v", code, result)
	}
	for {
		loaded, changed := hooks.Loads()
		if 1 <= loaded {
			break
		}
		select {
		case <-changed:
		case <-world.ctx.Done():
			t.Fatal("no read")
		}
	}
	args.SetVersion = 2
	code, result = process.register(listener.token, args)
	if code != http.StatusOK || result.Error != nil {
		t.Fatalf("once loaded answered %d, %+v", code, result)
	}
	for index, status := range result.Statuses {
		if status != sidecar.SocketRegistrationStatusOk {
			t.Fatalf("entry %d answered %s", index, status)
		}
	}
	// the certificate row ends: once the facts are read again, the next heartbeat revokes both leases
	source.set(listener.networkId, &socketsservice.TlsListenFacts{
		Verified: true,
		Standing: sidecar.AbuseStandingStandard,
		Tier:     "pro",
	})
	if err := hooks.LoadFacts(world.ctx, listener.networkId); err != nil {
		t.Fatal(err)
	}
	args.SetVersion = 3
	code, result = process.register(listener.token, args)
	if code != http.StatusOK || result.Error != nil {
		t.Fatalf("after the row ended answered %d, %+v", code, result)
	}
	for index, status := range result.Statuses {
		if status != sidecar.SocketRegistrationStatusRevoked {
			t.Fatalf("entry %d answered %s", index, status)
		}
	}
}

// The production gate's view answers the publish grant by §8's agreement rule on the verified log: a member device's
// grant for the host bound to its name, with the audience the policy gives, for the mode it gives and no other, and
// nothing for another host, another sidecar or a request naming none.
func TestTlsListenReadsThePublishGrantFromTheProjection(t *testing.T) {
	log := newTestGateLog(t)
	network := log.newNetwork()
	network.admission.SaveAclPolicy([]byte(`{
		"grants": [
			{ "src": ["autogroup:member"], "dst": ["dns:blog", "sock:tls/443/blog"], "allow": ["publish", "listen"], "audience": "public" },
		],
	}`), sidecartest.AclSaveMembers{})
	world := newTestSocketWorldOn(t, log.net.Clock())
	process := log.newProcess(world, nil)
	listener := network.sidecarOf(world, network.listener)
	view := process.awaitLoaded(network.networkId)
	now := world.clock.Now()
	request := &socketsservice.SocketGateRequest{NetworkId: network.networkId, SidecarId: &listener.sidecarId, Name: "tls/443/blog"}
	grant := view.PublishGrant(request, "http", now)
	if grant == nil || grant.Audience != protocol.AclAudience_ACL_AUDIENCE_PUBLIC || grant.AppMode != protocol.AclAppMode_ACL_APP_MODE_HTTP || len(grant.GrantIds) == 0 {
		t.Fatalf("the member's grant is %+v", grant)
	}
	if view.PublishGrant(request, "raw", now) != nil {
		t.Fatal("an http grant answered a raw registration")
	}
	if view.PublishGrant(request, "ws", now) != nil {
		t.Fatal("a mode tls/ does not take has a grant")
	}
	shop := &socketsservice.SocketGateRequest{NetworkId: network.networkId, SidecarId: &listener.sidecarId, Name: "tls/443/shop"}
	if view.PublishGrant(shop, "http", now) != nil {
		t.Fatal("a host the policy does not name has a grant")
	}
	stranger := testSocketId()
	if view.PublishGrant(&socketsservice.SocketGateRequest{NetworkId: network.networkId, SidecarId: &stranger, Name: "tls/443/blog"}, "http", now) != nil {
		t.Fatal("a sidecar outside the grant has one")
	}
	if view.PublishGrant(&socketsservice.SocketGateRequest{NetworkId: network.networkId, Name: "tls/443/blog"}, "http", now) != nil {
		t.Fatal("a request naming no sidecar has a grant")
	}
	platform, err := process.projection.View(world.edgeNetworkId)
	if err != nil || platform.PublishGrant(request, "http", now) != nil {
		t.Fatalf("the platform network answered %v", err)
	}
}

// A receiver's entry for §13.9's system publish: tls/443/mta-sts, http, its listen verdict the receiver's smtp/25/mx
// grant, in a verified mail network whose receiver holds the network's pair.
func (self *testTlsListenScene) systemPublish() {
	self.setName("tls/443/mta-sts")
	self.facts.MailNetwork = true
	self.view.grant = nil
	self.check.Listen = &socketsservice.SocketGateVerdict{Allowed: true, GrantId: []byte("receiver-smtp-listen"), PolicyVersion: 1}
}

// The system publish's lines (TLS-M8-02, §22.5's row): a receiver passes with no tls/ grant, no expiry and no screen;
// a non-receiver, an unverified network, a network with no mail_network row, a receiver with no certificate for the
// network's pair, a hosted or suspended one, and raw are refused; mta-sts on another port takes no such path.
func TestTlsListenAdmitsTheSystemPublishOnlyForAReceiver(t *testing.T) {
	testTlsListenCases(t, []testTlsListenCase{
		{name: "a receiver", mutate: func(scene *testTlsListenScene) {
			scene.systemPublish()
		}, allow: true},
		{name: "a receiver at Community on probation, standing", mutate: func(scene *testTlsListenScene) {
			scene.systemPublish()
			scene.facts.Tier = "free"
			scene.facts.Standing = sidecar.AbuseStandingProbation
		}, allow: true},
		{name: "a non-receiver", mutate: func(scene *testTlsListenScene) {
			scene.systemPublish()
			scene.check.Listen = &socketsservice.SocketGateVerdict{}
		}},
		{name: "no listen verdict", mutate: func(scene *testTlsListenScene) {
			scene.systemPublish()
			scene.check.Listen = nil
		}},
		{name: "a non-receiver holding a tls/ publish grant", mutate: func(scene *testTlsListenScene) {
			scene.systemPublish()
			scene.check.Listen = &socketsservice.SocketGateVerdict{}
			scene.view.grant = &sidecar.AclPublishGrant{
				GrantIds: [][]byte{[]byte("grant")},
				Audience: protocol.AclAudience_ACL_AUDIENCE_PUBLIC,
				AppMode:  protocol.AclAppMode_ACL_APP_MODE_HTTP,
			}
		}},
		{name: "an unverified network", mutate: func(scene *testTlsListenScene) {
			scene.systemPublish()
			scene.facts.Verified = false
		}},
		{name: "no mail_network row", mutate: func(scene *testTlsListenScene) {
			scene.systemPublish()
			scene.facts.MailNetwork = false
		}},
		{name: "no certificate", mutate: func(scene *testTlsListenScene) {
			scene.systemPublish()
			scene.facts.Certs = nil
		}},
		{name: "a scope's pair alone", mutate: func(scene *testTlsListenScene) {
			scene.systemPublish()
			scene.facts.Certs[0].NetworkPair = false
			scene.facts.Certs[0].ScopePairs = []string{"team"}
		}},
		{name: "a hosted receiver", mutate: func(scene *testTlsListenScene) {
			scene.systemPublish()
			scene.facts.HostedSidecarIds = []connect.Id{scene.sidecarId}
		}},
		{name: "a suspended network", mutate: func(scene *testTlsListenScene) {
			scene.systemPublish()
			scene.facts.Standing = sidecar.AbuseStandingSuspended
		}},
		{name: "raw", mutate: func(scene *testTlsListenScene) {
			scene.systemPublish()
			scene.check.Registration.AppMode = "raw"
		}},
		{name: "mta-sts on 8443", mutate: func(scene *testTlsListenScene) {
			scene.systemPublish()
			scene.setName("tls/8443/mta-sts")
		}},
		{name: "another host on the receiver's listen alone", mutate: func(scene *testTlsListenScene) {
			scene.systemPublish()
			scene.setName("tls/443/policy")
		}},
	})
	// the system publish asks no publish grant of the view
	scene := newTestTlsListenScene(t, nil)
	scene.systemPublish()
	if err := scene.validate(); err != nil {
		t.Fatalf("a receiver refused: %v", err)
	}
	if len(scene.view.askedNames) != 0 {
		t.Fatalf("the system publish asked the view for %v", scene.view.askedNames)
	}
	// and with no facts it is undecided, never passed
	undecided := newTestTlsListenScene(t, nil)
	undecided.systemPublish()
	if err := undecided.hooks.ValidateListen(undecided.ctx, undecided.check); !errors.Is(err, socketsservice.ErrSocketListenUnavailable) {
		t.Fatalf("with no facts answered %v", err)
	}
}

// Composed into the registration path: a receiver's system publish registers on its smtp/25/mx listen grant alone
// with no tls/ grant in the network, and when that grant is revoked the next heartbeat ends the lease as revoked; a
// non-receiver is denied.
func TestTlsListenSystemPublishComposesIntoTheRegistrationPath(t *testing.T) {
	world := newTestSocketWorld(t)
	networkId := testSocketId()
	source := newTestTlsFactsSource()
	process := world.newProcess(nil)
	hooks, err := socketsservice.NewTlsNamespaceHooks(world.ctx, source, world.clock, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hooks.Close)
	if err := process.service.RegisterNamespace(sidecar.SocketNamespaceTls, hooks); err != nil {
		t.Fatal(err)
	}
	receiver := world.newSidecar(networkId)
	outsider := world.newSidecar(networkId)
	process.gate.SetIdentityKey(networkId, receiver.sidecarId, receiver.publicKey())
	process.gate.SetIdentityKey(networkId, outsider.sidecarId, outsider.publicKey())
	process.gate.AllowListen(networkId, receiver.sidecarId, []byte(sidecar.SocketSystemPublishListenName), testSocketGrant("smtp-listen"))
	process.gate.Load(networkId)
	source.set(networkId, &socketsservice.TlsListenFacts{
		Verified:    true,
		Standing:    sidecar.AbuseStandingStandard,
		Tier:        "free",
		MailNetwork: true,
		Certs: []*socketsservice.TlsListenCert{
			{SidecarId: receiver.sidecarId, NotAfter: world.clock.Now().Add(24 * time.Hour), NetworkPair: true},
			{SidecarId: outsider.sidecarId, NotAfter: world.clock.Now().Add(24 * time.Hour), NetworkPair: true},
		},
	})
	if err := hooks.LoadFacts(world.ctx, networkId); err != nil {
		t.Fatal(err)
	}
	register := func(listener *testSocketSidecar, setVersion uint64) sidecar.SocketRegistrationStatus {
		t.Helper()
		code, result := process.register(listener.token, &sidecar.SocketRegistrationsArgs{
			SetVersion:    setVersion,
			Registrations: []*sidecar.SocketRegistration{testSocketSystemPublishRegistration(t, listener, "http")},
		})
		if code != http.StatusOK || result.Error != nil {
			t.Fatalf("the page answered %d, %+v", code, result)
		}
		return result.Statuses[0]
	}
	if status := register(receiver, 1); status != sidecar.SocketRegistrationStatusOk {
		t.Fatalf("the receiver's system publish answered %s", status)
	}
	if status := register(outsider, 1); status != sidecar.SocketRegistrationStatusDenied {
		t.Fatalf("a non-receiver's system publish answered %s", status)
	}
	process.gate.RevokeListen(networkId, receiver.sidecarId, []byte(sidecar.SocketSystemPublishListenName))
	process.gate.Load(networkId)
	if status := register(receiver, 2); status != sidecar.SocketRegistrationStatusRevoked {
		t.Fatalf("after the receiver's grant was revoked the entry answered %s", status)
	}
}
