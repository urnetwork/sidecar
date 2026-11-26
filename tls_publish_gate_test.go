//go:build !sidecar_http && !ios_extension && !js

// §13.10's publish at §16.6's real gate (tls_publish.go's step 2 and 3; §16.6's grant row, I-8, AU4): on the listen
// gate world's sidecar, config log and ACL engine, the publish's grant built and confirmed by the production pieces
// (AclGrantFiler, and sidecarTlsPublishBackend's grant effect with its awaitGrant over a config the test holds), and
// behind the publish the world's own tls/ listen, which asks its own grant at the same gate. The names, the
// certificate and the probe's target are scripted.
//
//   - a publish under a requests rule waits for a person, and asked again later presents the action its request was
//     filed with, though the rule's expiry moved on with the clock, so the member's decision is what the publish asked
//     again spends: one GrantActivate, the result naming its grant and the request's expiry;
//   - that publish's use is done only once the engine holds the grant: the listen behind it does not run while its
//     GrantActivate has not reached the engine, and runs on the grant once it has, passing the gate on it with no
//     decision of the publish's, filing nothing and posting nothing more;
//   - a grant the engine does not hold within the wait answers unavailable and listens on nothing, and the same publish
//     asked again once the engine holds it completes, naming that grant, with no second GrantActivate;
//   - a publish no requests rule takes passes on a standing grant that gives its audience, filing and posting nothing,
//     its result naming no grant and no expiry, and a publish to another audience than the standing grant gives is
//     refused, filing nothing.
//
// Synthetic values only.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The world's verified config as a publish's awaitGrant waits on it: at a position the log holds, the log's state is
// installed in the world's engine, as the follower installs it before the position shows (acl_follow.go). Held, it
// first tells the test it waits and takes its answer from release.
type tlsPublishGateConfig struct {
	world   *testListenGateWorld
	hold    bool
	waiting chan uint64
	release chan error
}

func (self *tlsPublishGateConfig) WaitFor(ctx context.Context, n uint64) (*ConfigState, error) {
	if self.hold {
		select {
		case self.waiting <- n:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		select {
		case err := <-self.release:
			if err != nil {
				return nil, err
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	state := self.world.net.log.State()
	if state.Pin().GetVersion() < n {
		return nil, fmt.Errorf("the log holds %d, not %d", state.Pin().GetVersion(), n)
	}
	acl, err := state.Acl()
	if err != nil {
		return nil, err
	}
	if err := self.world.engine.Install(acl, nil); err != nil {
		return nil, err
	}
	return state, nil
}

// One listen the publish ran: its settings, whether the engine let the host listen on the name as it began, and its
// answer.
type tlsPublishGateServe struct {
	settings  *SocketListenSettings
	engineHad bool
	err       error
}

// What a publish runs on at the real gate (the file header).
type tlsPublishGateBackend struct {
	world     *testListenGateWorld
	grants    *AclGrantFiler
	sidecar   *sidecarTlsPublishBackend
	directory string

	stateLock sync.Mutex
	served    []*tlsPublishGateServe
}

func (self *tlsPublishGateBackend) identity() (Id, Id, error) {
	return self.world.net.networkId, self.world.hostId, nil
}

func (self *tlsPublishGateBackend) names(ctx context.Context) (*TlsCertNames, error) {
	return &TlsCertNames{Root: tlsCertTestRoot, Label: tlsCertTestLabel}, nil
}

func (self *tlsPublishGateBackend) clientNames() ([]string, error) {
	return []string{}, nil
}

func (self *tlsPublishGateBackend) grantAction(ctx context.Context, base *protocol.CanonicalAction, request *AclGrantRequest, now time.Time) (*StoredCanonicalAction, error) {
	return self.grants.Action(ctx, base, request, now)
}

// The production grant effect, confirming its grant in the engine (AclGrantFiler.awaitGrant).
func (self *tlsPublishGateBackend) grantEffect(action *StoredCanonicalAction) SidecarEffect {
	return self.sidecar.grantEffect(action)
}

func (self *tlsPublishGateBackend) standingGrant(action *StoredCanonicalAction, now time.Time) bool {
	return self.world.engine.ActiveGrant(action, self.world.hostId, now)
}

func (self *tlsPublishGateBackend) priorGrant(action *StoredCanonicalAction, detail *SidecarActionDetail, runId *Id, agentId *Id, now time.Time) ([]byte, bool) {
	return self.sidecar.priorGrant(action, detail, runId, agentId, now)
}

func (self *tlsPublishGateBackend) authorize(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error {
	return self.world.sidecar.Authorize(ctx, action, decision)
}

func (self *tlsPublishGateBackend) ensureCertificate(ctx context.Context) error {
	return nil
}

func (self *tlsPublishGateBackend) daemonPorts() []int {
	return nil
}

func (self *tlsPublishGateBackend) recordProbeRefusal(refusal TlsProbeRefusal) {
}

// The world's own tls/ listen on the name, at the same gate, as Sidecar.Listen runs it.
func (self *tlsPublishGateBackend) serve(ctx context.Context, target *TlsFrontTarget, settings *SocketListenSettings) (tlsPublishEndpoint, error) {
	engineHad := false
	if state := self.world.engine.State(); state != nil {
		engineHad = state.MayListen(AclSidecarSubject(self.world.hostId), AclSocketName{PublicName: target.Name}, self.world.clock.Now()).Allowed
	}
	parsed, err := ParseSocketAddress(target.Name)
	if err != nil {
		return nil, err
	}
	listener, err := self.world.component.listen(ctx, parsed, settings, false)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.served = append(self.served, &tlsPublishGateServe{settings: settings, engineHad: engineHad, err: err})
	}()
	if err != nil {
		return nil, err
	}
	return listener, nil
}

func (self *tlsPublishGateBackend) revokeGrant(ctx context.Context, grantId []byte, origin SidecarActOrigin) error {
	return self.grants.Revoke(ctx, grantId, origin, nil)
}

func (self *tlsPublishGateBackend) clientCertificateDirectory() (string, error) {
	return self.directory, nil
}

func (self *tlsPublishGateBackend) now() time.Time {
	return self.world.clock.Now()
}

// The listens run so far.
func (self *tlsPublishGateBackend) serves() []*tlsPublishGateServe {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.served)
}

// A publisher on the listen gate world's real gate (the file header), its config, and a local service to publish.
func newTlsPublishGateTest(t *testing.T) (*testListenGateWorld, *tlsPublisher, *tlsPublishGateBackend, *tlsPublishGateConfig, string) {
	t.Helper()
	world := newTestListenGateWorld(t)
	grants := NewAclGrantFiler(world.sidecar, world.engine)
	// the daemon registers the publish kind's Lookup beside its tls component (cli's daemon_desktop_tls.go)
	t.Cleanup(world.sidecar.RegisterEffectLookup(SidecarActionPublish, grants.Lookup))
	config := &tlsPublishGateConfig{world: world, waiting: make(chan uint64, 1), release: make(chan error, 1)}
	backend := &tlsPublishGateBackend{
		world: world, grants: grants, directory: t.TempDir(),
		sidecar: &sidecarTlsPublishBackend{sidecar: world.sidecar, args: &TlsPublishArgs{Grants: grants, Config: config}},
	}
	target := newTlsProbeTestTarget(t, "<html><head><title>A blog</title></head></html>")
	return world, newTlsPublisher(backend, nil), backend, config, target
}

// A requests rule by which members ask to publish host on 443, which the requester's own member approves; its id.
func (self *testListenGateWorld) publishRequests(host string) []byte {
	self.t.Helper()
	ruleId := testConfigId("publish gate requests " + host).Bytes()
	self.net.withAclRows(func(rows *protocol.AclRows) {
		rows.Requests = append(rows.Requests, &protocol.AclRequestRule{
			RuleId:        ruleId,
			SrcAtoms:      [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()},
			Targets:       []*protocol.AclTarget{{PublicName: host}, {PublicName: "tls/443/" + host}},
			Actions:       []uint32{uint32(protocol.AclAction_ACL_ACTION_PUBLISH), uint32(protocol.AclAction_ACL_ACTION_LISTEN)},
			ApproverAtoms: [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF).Bytes()},
		})
	})
	self.install()
	return ruleId
}

// A document rule letting members publish host on 443 to audience over http, a standing name, installed.
func (self *testListenGateWorld) publishStanding(host string, audience protocol.AclAudience) {
	self.t.Helper()
	self.net.withAclRows(func(rows *protocol.AclRows) {
		rows.Rules = append(rows.Rules, &protocol.AclRule{
			RuleId:   testConfigId("publish gate standing " + host).Bytes(),
			SrcAtoms: [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()},
			Targets:  []*protocol.AclTarget{{PublicName: host}, {PublicName: "tls/443/" + host}},
			Actions:  []uint32{uint32(protocol.AclAction_ACL_ACTION_PUBLISH), uint32(protocol.AclAction_ACL_ACTION_LISTEN)},
			Audience: audience,
		})
	})
	self.install()
}

// The member's approval of request from its consented laptop, one use, as a caller holding it hands it in.
func (self *testListenGateWorld) decision(request *StoredApprovalRequest) *bridge.Signed {
	self.t.Helper()
	requestSha256 := request.Sha256()
	payloadSha256 := request.Action.PayloadSha256()
	return testSpendSignedBy(self.t, self.laptop.sidecarId, self.laptop.key, &protocol.ApprovalDecision{
		ApprovalId:         request.Request.GetApprovalId(),
		RequestSha256:      requestSha256[:],
		PayloadSha256:      payloadSha256[:],
		Decision:           uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE),
		Uses:               1,
		NotAfterMillis:     request.Request.GetNotAfterMillis(),
		ApproverMemberId:   self.member.Bytes(),
		Channel:            uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE),
		RequesterSidecarId: request.Request.GetRequesterSidecarId(),
		AuthPin:            self.net.log.State().Pin(),
		Version:            1,
	})
}

// A publish under a requests rule waits, asked again presents its request's action, and spends the member's decision,
// handed in with it, into one GrantActivate; the listen behind it runs on the grant, which the engine holds by then,
// with no decision of the publish's, filing nothing and posting nothing more.
func TestTlsPublishAskedAgainAfterApprovalSpendsIt(t *testing.T) {
	world, publisher, backend, _, target := newTlsPublishGateTest(t)
	ruleId := world.publishRequests("blog")
	settings := &TlsPublishSettings{Host: "blog", Target: target}
	_, err := publisher.publish(t.Context(), settings)
	request := world.pendingRequest(err)
	action := request.Action.Action
	if action.GetKind() != uint32(SidecarActionPublish) || !bytes.Equal(action.GetRuleId(), ruleId) || action.GetHost() != "blog" ||
		action.GetExpiresMillis() != world.clock.Now().Add(time.Duration(aclRequestDefaultExpiryMs)*time.Millisecond).UnixMilli() {
		t.Fatalf("the request's action: %+v", action)
	}

	// asked again a minute on, the publish presents the action its request was filed with, filing nothing more
	world.advance(time.Minute)
	_, err = publisher.publish(t.Context(), settings)
	if again := world.pendingRequest(err); again.ApprovalId() != request.ApprovalId() {
		t.Fatalf("the publish asked again filed %s beside %s", again.ApprovalId(), request.ApprovalId())
	}
	if world.approvals.filedCount() != 1 || world.api.postCount() != 0 || len(backend.serves()) != 0 {
		t.Fatalf("%d requests filed, %d statements posted, %d listens before the decision", world.approvals.filedCount(), world.api.postCount(), len(backend.serves()))
	}

	settings.Decision = world.decision(request)
	result, err := publisher.publish(t.Context(), settings)
	if err != nil {
		t.Fatalf("the approved publish: %v (the log's last verdict %+v)", err, world.net.verdicts[world.net.n])
	}
	grantId := AclGrantId(request.ApprovalId(), request.Action.PayloadSha256())
	if !bytes.Equal(result.GrantId, grantId[:]) || !result.Expires.Equal(time.UnixMilli(action.GetExpiresMillis()).UTC()) {
		t.Errorf("the result: grant %x, expires %s", result.GrantId, result.Expires)
	}
	if types := world.api.postedTypes(t); !slices.Equal(types, []bridge.SignedType{bridge.SignedType_SIGNED_GRANT_ACTIVATE}) {
		t.Errorf("the publish and its listen posted %v", types)
	}
	serves := backend.serves()
	if len(serves) != 1 || serves[0].err != nil || !serves[0].engineHad || serves[0].settings.Decision != nil {
		t.Fatalf("the listen behind the publish: %+v", serves)
	}
	if world.approvals.filedCount() != 1 {
		t.Errorf("the listen filed a request of its own: %d filed", world.approvals.filedCount())
	}
	page := testSocketAwait(t, world.service.pages, "the publish's page")
	if registration := page.Registrations[0]; registration.Name != "tls/443/blog" || registration.Protocol != "tls" {
		t.Errorf("the registration %+v", registration)
	}
}

// The listen behind an approved publish waits for the grant: while its GrantActivate has not reached the engine the
// publish's use is not done and nothing listens; once the engine holds it, the listen runs on it.
func TestTlsPublishListenWaitsForItsGrant(t *testing.T) {
	world, publisher, backend, config, target := newTlsPublishGateTest(t)
	world.publishRequests("blog")
	settings := &TlsPublishSettings{Host: "blog", Target: target}
	_, err := publisher.publish(t.Context(), settings)
	request := world.pendingRequest(err)
	world.approve(request)
	grantId := AclGrantId(request.ApprovalId(), request.Action.PayloadSha256())

	config.hold = true
	type answer struct {
		result *TlsPublishResult
		err    error
	}
	answered := make(chan answer, 1)
	go func() {
		result, err := publisher.publish(context.Background(), settings)
		answered <- answer{result: result, err: err}
	}()
	position := <-config.waiting
	// the GrantActivate is in the log at the receipt's position, and not yet in the engine: nothing listens
	if logPin := world.net.log.State().Pin().GetVersion(); position == 0 || logPin < position {
		t.Fatalf("the publish waits for position %d with the log at %d", position, logPin)
	}
	if state := world.engine.State(); state.grantRule(grantId[:]) != nil {
		t.Fatal("the engine held the grant before the wait answered")
	}
	if serves := backend.serves(); len(serves) != 0 {
		t.Fatalf("%d listens ran before the grant reached the engine", len(serves))
	}
	select {
	case got := <-answered:
		t.Fatalf("the publish answered before the grant reached the engine: %v", got.err)
	default:
	}
	config.release <- nil
	got := <-answered
	if got.err != nil || !bytes.Equal(got.result.GrantId, grantId[:]) {
		t.Fatalf("the publish once its grant was in the engine: %+v, %v", got.result, got.err)
	}
	if serves := backend.serves(); len(serves) != 1 || serves[0].err != nil || !serves[0].engineHad {
		t.Fatalf("the listen behind the publish: %+v", serves)
	}
	if world.api.postCount() != 1 || world.approvals.filedCount() != 1 {
		t.Errorf("%d statements posted, %d requests filed", world.api.postCount(), world.approvals.filedCount())
	}
}

// A grant the engine does not hold within the wait answers unavailable and listens on nothing; the same publish asked
// again once the engine holds it completes on that grant, naming it, with no second GrantActivate.
func TestTlsPublishGrantNotInTheEngineAnswersUnavailable(t *testing.T) {
	world, publisher, backend, config, target := newTlsPublishGateTest(t)
	world.publishRequests("blog")
	settings := &TlsPublishSettings{Host: "blog", Target: target}
	_, err := publisher.publish(t.Context(), settings)
	request := world.pendingRequest(err)
	world.approve(request)
	grantId := AclGrantId(request.ApprovalId(), request.Action.PayloadSha256())

	config.hold = true
	config.release <- context.DeadlineExceeded
	if _, err := publisher.publish(t.Context(), settings); !errors.Is(err, ErrTlsPublishUnavailable) {
		t.Fatalf("a grant not in the engine: %v", err)
	}
	<-config.waiting
	if serves := backend.serves(); len(serves) != 0 || len(publisher.list()) != 0 {
		t.Fatalf("a publish whose grant is not in the engine listened: %+v", serves)
	}
	if types := world.api.postedTypes(t); !slices.Equal(types, []bridge.SignedType{bridge.SignedType_SIGNED_GRANT_ACTIVATE}) {
		t.Fatalf("the spend posted %v", types)
	}

	// the engine catches up, and the same publish asked again completes, the gate passing it on the grant it activated
	config.hold = false
	world.install()
	result, err := publisher.publish(t.Context(), settings)
	if err != nil || !bytes.Equal(result.GrantId, grantId[:]) {
		t.Fatalf("the publish asked again: %+v, %v", result, err)
	}
	if world.api.postCount() != 1 || world.approvals.filedCount() != 1 {
		t.Errorf("%d statements posted, %d requests filed", world.api.postCount(), world.approvals.filedCount())
	}
	if serves := backend.serves(); len(serves) != 1 || serves[0].err != nil {
		t.Errorf("the listen behind the publish: %+v", serves)
	}
	// its end revokes the grant it names
	if err := publisher.unpublish(t.Context(), "blog", 443, SidecarActConfirmed); err != nil {
		t.Fatal(err)
	}
	if types := world.api.postedTypes(t); !slices.Equal(types, []bridge.SignedType{bridge.SignedType_SIGNED_GRANT_ACTIVATE, bridge.SignedType_SIGNED_GRANT_REVOKE}) {
		t.Errorf("the publish's end posted %v", types)
	}
}

// A publish no requests rule takes passes on a standing grant that gives its audience, filing and posting nothing, its
// result naming no grant and no expiry, and its listen running on the same standing grant; a publish to another
// audience than the standing grant gives is refused, filing nothing.
func TestTlsPublishStandingWithNoRequestsRulePasses(t *testing.T) {
	world, publisher, backend, _, target := newTlsPublishGateTest(t)
	world.publishStanding("blog", protocol.AclAudience_ACL_AUDIENCE_UNSPECIFIED)
	result, err := publisher.publish(t.Context(), &TlsPublishSettings{Host: "blog", Target: target})
	if err != nil {
		t.Fatalf("a standing publish with no requests rule: %v", err)
	}
	if len(result.GrantId) != 0 || !result.Expires.IsZero() || result.Audience != TlsPublishAudienceMembers {
		t.Errorf("the standing publish's result: %+v", result)
	}
	if world.approvals.filedCount() != 0 || world.api.postCount() != 0 {
		t.Errorf("a standing publish filed %d requests and posted %d statements", world.approvals.filedCount(), world.api.postCount())
	}
	if serves := backend.serves(); len(serves) != 1 || serves[0].err != nil {
		t.Fatalf("the listen behind the standing publish: %+v", serves)
	}
	testSocketAwait(t, world.service.pages, "the standing publish's page")

	// its end revokes nothing, the standing grant being the config's, and a public publish of the name, which the
	// standing grant does not give, is refused with nothing filed
	if err := publisher.unpublish(t.Context(), "blog", 443, SidecarActConfirmed); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.publish(t.Context(), &TlsPublishSettings{Host: "blog", Target: target, Audience: TlsPublishAudiencePublic}); !errors.Is(err, ErrAclGrantFile) {
		t.Errorf("a publish to another audience than the standing grant gives: %v", err)
	}
	if world.approvals.filedCount() != 0 || world.api.postCount() != 0 || len(backend.serves()) != 1 {
		t.Errorf("the refused publish filed %d requests, posted %d statements, listened %d times", world.approvals.filedCount(), world.api.postCount(), len(backend.serves()))
	}
}
