//go:build !sidecar_http && !ios_extension && !js

// A tls/ or smtp/ listen asks its grant's lifetime (owner decision 687; QD-1172): SocketListenSettings.Expires, filed
// as an absolute expiry that MatchAclRequest holds to the requests rule's maxExpiry, 0 taking its expiresDefault, and
// the mail receiver asks its own MailReceiverSettings.ListenExpires, 7 days by default. At §16.6's real gate, over the
// bridge file world's config log and ACL engine (socket_listen_gate_test.go's world), under a requests rule that gives
// at most 7 days, as the implicit document's tls/ and smtp/ rule does:
//
//   - a listen asking 3 days files a request for 3 days from now, which it presents again a minute later, and the
//     member's decision activates a grant the log holds for those 3 days and no longer;
//   - one asking 30 days is held to the maximum: refused before the gate, its error saying the rule's maxExpiry and
//     what that is, filing and registering nothing; one asking exactly 7 days is filed; a standing grant passes the 30
//     days' listen; and a refusal where no requests rule takes the listen at all claims no maxExpiry;
//   - one asking nothing takes the rule's expiresDefault;
//   - a listen's action is kept per lifetime asked, so asking a longer one files its own request rather than
//     presenting the shorter one's, and asking the first again finds the first;
//   - an expiry is refused negative, on a name whose listen asks no grant and on the system publish;
//   - the receiver asks its setting, 7 days by default, a setting it is given and 0 as given, refuses a negative one,
//     and through the gate its request asks 7 days and the member's decision activates a 7-day grant.
//
// Synthetic values only.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The longest the test's requests rule gives, as the implicit document's tls/ and smtp/ rule does (§13.9).
const testListenExpiresRuleMax = 7 * 24 * time.Hour

// A requests rule by which members ask listen on name, the requester's own member approving, giving a grant of at most
// maxExpiry and by default defaultExpiry, 0 for the format's 1 h; installed, and its id.
func (self *testListenGateWorld) requestsWithin(name string, maxExpiry time.Duration, defaultExpiry time.Duration) []byte {
	self.t.Helper()
	ruleId := testConfigId("listen expires requests " + name).Bytes()
	self.net.withAclRows(func(rows *protocol.AclRows) {
		rows.Requests = append(rows.Requests, &protocol.AclRequestRule{
			RuleId:               ruleId,
			SrcAtoms:             [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()},
			Targets:              []*protocol.AclTarget{{PublicName: name}},
			Actions:              []uint32{uint32(protocol.AclAction_ACL_ACTION_LISTEN)},
			ApproverAtoms:        [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF).Bytes()},
			MaxExpirySeconds:     int64(maxExpiry / time.Second),
			DefaultExpirySeconds: int64(defaultExpiry / time.Second),
		})
	})
	self.install()
	return ruleId
}

// The grant the world's log holds for this sidecar's listen on name at now, failing the test where it holds none from
// request's approval.
func (self *testListenGateWorld) activatedListenGrant(name string, request *StoredApprovalRequest, now time.Time) *protocol.AclRule {
	self.t.Helper()
	acl, err := self.net.log.State().Acl()
	if err != nil {
		self.t.Fatal(err)
	}
	grantId := AclGrantId(request.ApprovalId(), sha256.Sum256(request.Action.Bytes))
	decision := acl.MayListen(AclSidecarSubject(self.hostId), AclSocketName{PublicName: name}, now)
	if !decision.Allowed || !bytes.Equal(decision.Rule.GetRuleId(), grantId[:]) {
		self.t.Fatalf("the log's grant for %s: %+v", name, decision)
	}
	return decision.Rule
}

// Whether the world's log lets this sidecar listen on name at now.
func (self *testListenGateWorld) mayListen(name string, now time.Time) bool {
	self.t.Helper()
	acl, err := self.net.log.State().Acl()
	if err != nil {
		self.t.Fatal(err)
	}
	return acl.MayListen(AclSidecarSubject(self.hostId), AclSocketName{PublicName: name}, now).Allowed
}

// A listen asking 3 days under a rule giving at most 7 files its request for 3 days from now, which it presents again
// a minute on rather than a later one, and the member's decision activates a grant the log holds for exactly those 3
// days: allowed a millisecond before their end and not at it.
func TestSocketListenAsksItsExpiresUnderARequestsRule(t *testing.T) {
	world := newTestListenGateWorld(t)
	ruleId := world.requestsWithin("tls/443/blog", testListenExpiresRuleMax, 0)
	settings := &SocketListenSettings{Expires: 3 * 24 * time.Hour}
	asked := world.clock.Now()
	end := asked.Add(3 * 24 * time.Hour)
	_, err := world.listen("tls/443/blog", settings)
	request := world.pendingRequest(err)
	if action := request.Action.Action; !bytes.Equal(action.GetRuleId(), ruleId) || action.GetExpiresMillis() != end.UnixMilli() {
		t.Fatalf("the request's action: %+v", action)
	}
	world.expectNoPage("a pending listen")

	world.advance(time.Minute)
	_, err = world.listen("tls/443/blog", settings)
	if again := world.pendingRequest(err); again.ApprovalId() != request.ApprovalId() {
		t.Fatalf("the listen asked again filed %s beside %s", again.ApprovalId(), request.ApprovalId())
	}

	world.approve(request)
	listener, err := world.listen("tls/443/blog", settings)
	if err != nil {
		t.Fatalf("the approved listen: %v", err)
	}
	defer listener.Close()
	testSocketAwait(t, world.service.pages, "the page")
	if grant := world.activatedListenGrant("tls/443/blog", request, world.clock.Now()); grant.GetExpires() != end.UnixMilli() {
		t.Errorf("the grant ends at %d, not 3 days after it was asked, %d", grant.GetExpires(), end.UnixMilli())
	}
	if !world.mayListen("tls/443/blog", end.Add(-time.Millisecond)) || world.mayListen("tls/443/blog", end) {
		t.Error("the grant does not end at its 3 days")
	}
	if world.approvals.filedCount() != 1 {
		t.Errorf("%d requests filed", world.approvals.filedCount())
	}
}

// A listen asking 30 days under a rule giving at most 7 is held to that maximum: MatchAclRequest takes no grant past
// it, so the listen is refused before the gate, its error saying so and naming the 7 days, with nothing filed, posted
// or registered. Exactly 7 days is taken and filed, a standing grant passes the 30 days' listen with nothing more
// filed, and a listen no requests rule takes is refused with no word of a maxExpiry.
func TestSocketListenPastTheRulesMaxExpiryIsRefused(t *testing.T) {
	world := newTestListenGateWorld(t)
	world.requestsWithin("tls/443/blog", testListenExpiresRuleMax, 0)
	month := &SocketListenSettings{Expires: 30 * 24 * time.Hour}
	_, err := world.listen("tls/443/blog", month)
	if !errors.Is(err, ErrSocketDenied) || !strings.Contains(err.Error(), "maxExpiry") ||
		!strings.Contains(err.Error(), testListenExpiresRuleMax.String()) {
		t.Fatalf("a listen asking past the rule's maxExpiry: %v", err)
	}
	var codeErr *SocketCodeError
	if !errors.As(err, &codeErr) || codeErr.Err != ErrSocketDenied {
		t.Errorf("the refusal carries no denied code: %v", err)
	}
	if world.askedCount() != 0 || world.approvals.filedCount() != 0 || world.api.postCount() != 0 {
		t.Errorf("a refused listen asked the gate %d times, filed %d requests and posted %d statements", world.askedCount(), world.approvals.filedCount(), world.api.postCount())
	}
	world.expectNoPage("a listen past the maximum")

	// a listen no requests rule takes is refused bare, whatever it asks
	if _, err := world.listen("smtp/25/mx", month); !errors.Is(err, ErrSocketDenied) || strings.Contains(err.Error(), "maxExpiry") {
		t.Errorf("a listen no requests rule takes: %v", err)
	}

	// the maximum itself is taken
	_, err = world.listen("tls/443/blog", &SocketListenSettings{Expires: testListenExpiresRuleMax})
	request := world.pendingRequest(err)
	if request.Action.Action.GetExpiresMillis() != world.clock.Now().Add(testListenExpiresRuleMax).UnixMilli() {
		t.Errorf("the maximum's request: %+v", request.Action.Action)
	}

	// a standing grant asks no expiry, so it passes the listen whatever it asks
	world.standing("tls/443/blog")
	listener, err := world.listen("tls/443/blog", month)
	if err != nil {
		t.Fatalf("a listen under a standing grant asking 30 days: %v", err)
	}
	defer listener.Close()
	action, _ := world.lastAsked()
	if action.Outcome == nil || action.Outcome.State != ApprovalOutcomeDone || len(action.Outcome.EffectRef) != 0 {
		t.Errorf("the standing listen's outcome: %+v", action.Outcome)
	}
	if world.approvals.filedCount() != 1 || world.api.postCount() != 0 {
		t.Errorf("the standing listen filed %d requests and posted %d statements", world.approvals.filedCount(), world.api.postCount())
	}
}

// A listen asking nothing takes the rule's expiresDefault: 2 h where the rule says so.
func TestSocketListenWithNoExpiresTakesTheRulesDefault(t *testing.T) {
	world := newTestListenGateWorld(t)
	world.requestsWithin("smtp/25/mx", testListenExpiresRuleMax, 2*time.Hour)
	for _, settings := range []*SocketListenSettings{nil, {Expires: 0}} {
		_, err := world.listen("smtp/25/mx", settings)
		request := world.pendingRequest(err)
		if request.Action.Action.GetExpiresMillis() != world.clock.Now().Add(2*time.Hour).UnixMilli() {
			t.Errorf("settings %+v: the request's action %+v", settings, request.Action.Action)
		}
	}
	if world.approvals.filedCount() != 1 {
		t.Errorf("no settings and Expires 0 filed %d requests", world.approvals.filedCount())
	}
}

// A listen's action is kept per lifetime asked: a listen asking 3 days after one asking 1 day on the same name and
// weight files its own request for 3 days, where a keeper by name and weight alone would present the 1 day's, whose
// expiry is no later; asking the 1 day again a minute on finds the first request.
func TestSocketListenKeepsAnActionPerLifetimeAsked(t *testing.T) {
	world := newTestListenGateWorld(t)
	world.requestsWithin("tls/443/blog", testListenExpiresRuleMax, 0)
	day := &SocketListenSettings{Expires: 24 * time.Hour}
	_, err := world.listen("tls/443/blog", day)
	first := world.pendingRequest(err)

	world.advance(time.Minute)
	_, err = world.listen("tls/443/blog", &SocketListenSettings{Expires: 3 * 24 * time.Hour})
	longer := world.pendingRequest(err)
	if longer.ApprovalId() == first.ApprovalId() {
		t.Fatal("a listen asking 3 days presented the request filed for 1 day")
	}
	if longer.Action.Action.GetExpiresMillis() != world.clock.Now().Add(3*24*time.Hour).UnixMilli() {
		t.Errorf("the 3 days' request: %+v", longer.Action.Action)
	}

	world.advance(time.Minute)
	_, err = world.listen("tls/443/blog", day)
	if again := world.pendingRequest(err); again.ApprovalId() != first.ApprovalId() {
		t.Errorf("the 1 day asked again filed %s beside %s", again.ApprovalId(), first.ApprovalId())
	}
	if world.approvals.filedCount() != 2 {
		t.Errorf("%d requests filed", world.approvals.filedCount())
	}
}

// An expiry is refused negative, on a name whose listen asks no grant, an application or share/ name, and on the
// system publish, which asks none of its own; tls/ and smtp/ take one.
func TestSocketListenRefusesAnExpiryNoGrantBears(t *testing.T) {
	format := DefaultSocketFormatSettings()
	sockets := DefaultSidecarSocketSettings()
	for _, c := range []struct {
		name      string
		namespace SocketNamespace
		expires   time.Duration
		valid     bool
	}{
		{name: "tls/443/blog", namespace: SocketNamespaceTls, expires: time.Hour, valid: true},
		{name: "smtp/25/mx", namespace: SocketNamespaceSmtp, expires: testListenExpiresRuleMax, valid: true},
		{name: "tls/443/blog", namespace: SocketNamespaceTls, expires: -time.Hour},
		{name: "smtp/25/mx", namespace: SocketNamespaceSmtp, expires: -time.Millisecond},
		{name: "db/primary", namespace: SocketNamespaceApplication, expires: time.Hour},
		{name: "share/abcdefghijklmnopqrstuvwxyz", namespace: SocketNamespaceShare, expires: time.Hour},
		{name: "db/primary", namespace: SocketNamespaceApplication, valid: true},
	} {
		_, err := socketListenArgs(format, sockets, c.name, c.namespace, &SocketListenSettings{Expires: c.expires})
		if c.valid != (err == nil) || (err != nil && !errors.Is(err, errSocketRegistrationInvalid)) {
			t.Errorf("%s asking %v: %v", c.name, c.expires, err)
		}
	}

	fixture := newTestListenFixture(t)
	fixture.policy.set(func(policy *testSocketPolicy) {
		policy.listenNames = map[string]bool{SocketSystemPublishListenName: true}
	})
	if _, err := fixture.component.listenSystemPublish(t.Context(), &SocketListenSettings{Expires: time.Hour}); !errors.Is(err, errSocketRegistrationInvalid) {
		t.Errorf("the system publish asking an expiry: %v", err)
	}
	select {
	case page := <-fixture.service.pages:
		t.Errorf("a refused system publish registered %+v", page.Registrations)
	default:
	}
}

// The receiver's listen asks its ListenExpires, 7 days by default, a setting it is given and 0 as given; a negative one
// is refused when the receiver is made.
func TestMailReceiverAsksItsListenExpires(t *testing.T) {
	if DefaultMailReceiverSettings().ListenExpires != testListenExpiresRuleMax {
		t.Fatalf("the default ListenExpires is %v", DefaultMailReceiverSettings().ListenExpires)
	}
	for _, c := range []struct {
		settings *MailReceiverSettings
		want     time.Duration
	}{
		{want: testListenExpiresRuleMax},
		{settings: &MailReceiverSettings{ListenExpires: 2 * 24 * time.Hour}, want: 2 * 24 * time.Hour},
		{settings: &MailReceiverSettings{ListenExpires: 0}, want: 0},
	} {
		world := newMailReceiverTestWorld(t, nil)
		var stateLock sync.Mutex
		askedExpires := []time.Duration{}
		receiver := world.newReceiver(func(args *MailReceiverArgs) {
			if c.settings != nil {
				settings := DefaultMailReceiverSettings()
				settings.ListenExpires = c.settings.ListenExpires
				args.Settings = settings
			}
			listen := args.Listen
			args.Listen = func(ctx context.Context, address string, settings *SocketListenSettings) (MailReceiverListener, error) {
				func() {
					stateLock.Lock()
					defer stateLock.Unlock()
					askedExpires = append(askedExpires, settings.Expires)
				}()
				return listen(ctx, address, settings)
			}
		})
		if _, err := receiver.listen(world.ctx); err != nil {
			t.Fatal(err)
		}
		stateLock.Lock()
		if len(askedExpires) != 1 || askedExpires[0] != c.want {
			t.Errorf("settings %+v: the listen asked %v", c.settings, askedExpires)
		}
		stateLock.Unlock()
	}

	settings := DefaultMailReceiverSettings()
	settings.ListenExpires = -time.Hour
	world := newMailReceiverTestWorld(t, nil)
	if _, err := NewMailReceiver(&MailReceiverArgs{
		Host: "mx", Listen: func(ctx context.Context, address string, settings *SocketListenSettings) (MailReceiverListener, error) {
			return nil, errors.New("not asked")
		},
		Keys: world.keys, Publisher: world.publisher, Names: func(ctx context.Context) ([]string, error) { return nil, nil },
		Settings: settings,
	}); !errors.Is(err, ErrMailReceiverInvalid) {
		t.Errorf("a negative ListenExpires: %v", err)
	}
}

// The receiver's listen through the gate, under a requests rule giving at most 7 days as the implicit document's does:
// its request asks 7 days from now, the receiver shows the approval it waits on, and once the member decides, its
// listen asked again activates a grant the log holds for those 7 days, so a person approves it once a week.
func TestMailReceiverListenAsksItsLifetimeAtTheGate(t *testing.T) {
	gate := newTestListenGateWorld(t)
	gate.requestsWithin("smtp/25/mx", testListenExpiresRuleMax, 0)
	world := newMailReceiverTestWorld(t, nil)
	receiver := world.newReceiver(func(args *MailReceiverArgs) {
		args.Listen = func(ctx context.Context, address string, settings *SocketListenSettings) (MailReceiverListener, error) {
			listener, err := gate.listen(address, settings)
			if err != nil {
				return nil, err
			}
			return listener, nil
		}
	})
	asked := gate.clock.Now()
	end := asked.Add(testListenExpiresRuleMax)
	_, err := receiver.listen(world.ctx)
	request := gate.pendingRequest(err)
	if request.Action.Action.GetExpiresMillis() != end.UnixMilli() || !bytes.Equal(request.Action.Action.GetSubject(), gate.hostId.Bytes()) {
		t.Fatalf("the receiver's request: %+v", request.Action.Action)
	}
	if status := receiver.Status(); status.ApprovalId == nil || *status.ApprovalId != request.ApprovalId() {
		t.Errorf("the receiver's status: %+v", status)
	}

	gate.approve(request)
	listener, err := receiver.listen(world.ctx)
	if err != nil {
		t.Fatalf("the receiver's approved listen: %v", err)
	}
	defer listener.Close()
	testSocketAwait(t, gate.service.pages, "the receiver's page")
	if grant := gate.activatedListenGrant("smtp/25/mx", request, gate.clock.Now()); grant.GetExpires() != end.UnixMilli() {
		t.Errorf("the receiver's grant ends at %d, not 7 days after it was asked, %d", grant.GetExpires(), end.UnixMilli())
	}
	if gate.approvals.filedCount() != 1 {
		t.Errorf("%d requests filed", gate.approvals.filedCount())
	}
}
