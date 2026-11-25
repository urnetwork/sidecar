//go:build !js && !ios && !android && !sdk_mobile_bind && !windows && !sidecar_http && !ios_extension

// Three follow-ups to the kept grant actions of listens, publishes and forwards (acl_grant_keep.go), each at §16.6's
// real gate on the bridge file world's sidecar, config log and ACL engine:
//
//   - Sidecar.Listen's tls/ listen keeps its action in a GrantActionKeeper with the ended check: asked again once the
//     grant its decision activated has been revoked, it files a new request, where the kept action's spent decision
//     answered done from its record and the listen registered on a grant that no longer stands; while the grant stands
//     the kept action is presented and passes on it, filing nothing.
//   - A forward asking an end, as bridge_forward's expires reaches the filer, is kept by that end: asked again a minute
//     on, the same end, written in another zone, presents the action its request was filed with and spends the
//     member's decision into one GrantActivate ending at that end; a lifetime and an end together and an end not ahead
//     are refused before anything is filed, and the daemon's bridge.forward hands its expires_ms to the filer as the
//     end, refusing one beside a lifetime and one below zero.
//   - MCP's socket_listen (SocketListenGrantAction): an approved listen's use is done only once the engine holds the
//     grant it activated, its config waited on up to the GrantActivate's receipt; a grant the engine does not hold
//     within the wait leaves the use uncertain, and the listen asked again once it does passes the gate under that
//     grant, its effect naming it, with no second GrantActivate; and with no config to wait on the use is uncertain.
//
// Synthetic values only.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// action's outcome, nil for no action, for a failure to print.
func testKeptOutcome(action *SidecarAction) *SidecarOutcome {
	if action == nil {
		return nil
	}
	return action.Outcome
}

// A tls/ listen under a requests rule spends the member's decision into its grant; asked again while the grant stands
// it presents its request's action and passes on the grant, filing nothing; once the grant is revoked, the same
// listen asked again before its kept action expires asks afresh: a new request for a fresh action, nothing registered.
// The new decision then spends into a grant of its own, on which the listen registers.
func TestSocketListenAsksAfreshOnceItsGrantIsRevoked(t *testing.T) {
	world := newTestListenGateWorld(t)
	world.requests("tls/443/blog")
	settings := &SocketListenSettings{Weight: 250}
	_, err := world.listen("tls/443/blog", settings)
	request := world.pendingRequest(err)
	world.approve(request)
	listener, err := world.listen("tls/443/blog", settings)
	if err != nil {
		t.Fatalf("the approved listen: %v", err)
	}
	listener.Close()
	grantId := AclGrantId(request.ApprovalId(), request.Action.PayloadSha256())
	world.install()

	// the grant stands: the kept action is presented and passes on it
	world.advance(time.Minute)
	listener, err = world.listen("tls/443/blog", settings)
	if err != nil {
		t.Fatalf("the listen asked again on its standing grant: %v", err)
	}
	listener.Close()
	if _, stored := world.lastAsked(); !bytes.Equal(stored.Bytes, request.Action.Bytes) {
		t.Error("the listen asked again while its grant stands presented another action than its request's")
	}
	if world.approvals.filedCount() != 1 || world.api.postCount() != 1 {
		t.Fatalf("%d requests filed, %d statements posted", world.approvals.filedCount(), world.api.postCount())
	}

	// revoked, within the kept action's expiry: the listen asks afresh rather than present the spent action
	if err := NewAclGrantFiler(world.sidecar, world.engine).Revoke(t.Context(), grantId[:], SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	world.install()
	world.advance(time.Minute)
	if expiresMs := request.Action.Action.GetExpiresMillis(); expiresMs <= world.clock.Now().UnixMilli() {
		t.Fatalf("the kept action expired at %d, before the test asked again at %d", expiresMs, world.clock.Now().UnixMilli())
	}
	listener, err = world.listen("tls/443/blog", settings)
	if err == nil {
		listener.Close()
		t.Fatal("the listen registered on the spent decision of a revoked grant")
	}
	afresh := world.pendingRequest(err)
	if afresh.ApprovalId() == request.ApprovalId() || bytes.Equal(afresh.Action.Bytes, request.Action.Bytes) {
		t.Fatalf("the listen after its grant's revocation presented its spent action: approval %s", afresh.ApprovalId())
	}
	if _, stored := world.lastAsked(); !bytes.Equal(stored.Bytes, afresh.Action.Bytes) {
		t.Error("the gate saw another action than the new request's")
	}

	// the new decision spends into its own grant, which the listen registers on
	world.approve(afresh)
	listener, err = world.listen("tls/443/blog", settings)
	if err != nil {
		t.Fatalf("the listen on the new decision: %v", err)
	}
	defer listener.Close()
	spent, _ := world.lastAsked()
	newGrantId := AclGrantId(afresh.ApprovalId(), afresh.Action.PayloadSha256())
	if spent.Outcome == nil || spent.Outcome.State != ApprovalOutcomeDone || !bytes.Equal(spent.Outcome.EffectRef, newGrantId[:]) {
		t.Errorf("the new decision's use: %+v", spent.Outcome)
	}
	want := []bridge.SignedType{bridge.SignedType_SIGNED_GRANT_ACTIVATE, bridge.SignedType_SIGNED_GRANT_REVOKE, bridge.SignedType_SIGNED_GRANT_ACTIVATE}
	if types := world.api.postedTypes(t); !slices.Equal(types, want) {
		t.Errorf("posted %v", types)
	}
}

// A forward asking an end waits for a person; asked again a minute on with the same end, written in another zone, it
// presents the action its request was filed with, whose expiry is that end, so the member's decision is what the
// forward asked again spends, into one GrantActivate ending at the end asked. A lifetime and an end together, and an
// end not ahead, are refused before anything is filed.
func TestBridgeForwardAskedAgainWithTheSameEndSpendsItsApproval(t *testing.T) {
	world := newTestBridgeEffectWorld(t)
	world.net.log.settings.AclSpendCheck = NewSpendCheck(nil)
	ctx := t.Context()
	origin := world.mcp()
	// an end with part of a ms, which the grant rounds up so it never ends before the time asked
	end := world.clock.Now().Add(90*time.Minute + 250*time.Microsecond).UTC()
	endMs := end.Truncate(time.Millisecond).Add(time.Millisecond).UnixMilli()
	request := &BridgeForwardRequest{Target: world.laptop.sidecarId, Port: 22, LocalPort: 2222, ExpiresAt: end}
	pending := func(request *BridgeForwardRequest) Id {
		t.Helper()
		_, err := world.filer.Forward(ctx, origin, request)
		var waiting *ApprovalPendingError
		if !errors.As(err, &waiting) {
			t.Fatalf("waiting for a forward approval: %v", err)
		}
		return waiting.ApprovalId
	}
	approvalId := pending(request)
	entry, err := world.ledgerRows.State(approvalId)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := ParseStoredApprovalRequest(entry.Request)
	if err != nil {
		t.Fatal(err)
	}
	if expiresMs := approved.Action.Action.GetExpiresMillis(); expiresMs != endMs {
		t.Fatalf("the request asks an end of %d ms, not %d", expiresMs, endMs)
	}

	// a minute on, the same end, written in another zone, finds the same request
	world.clock.advance(time.Minute)
	world.net.tickAt(world.clock.Now().UnixMilli())
	sameEnd := *request
	sameEnd.ExpiresAt = end.In(time.FixedZone("a synthetic zone", 5*60*60))
	if again := pending(&sameEnd); again != approvalId {
		t.Fatalf("the forward asked again with the same end filed %s beside %s", again, approvalId)
	}
	if posted := world.api.postCount(); posted != 0 {
		t.Fatalf("the pending forward posted %d statements", posted)
	}

	world.approve(approved)
	world.clock.advance(30 * time.Second)
	world.net.tickAt(world.clock.Now().UnixMilli())
	world.install()
	filed, err := world.filer.Forward(ctx, origin, request)
	wantGrant := AclGrantId(approvalId, approved.Action.PayloadSha256())
	if err != nil || filed.ApprovalId != approvalId || !bytes.Equal(filed.GrantId, wantGrant[:]) {
		t.Fatalf("the approved forward: %+v, %v", filed, err)
	}
	if types := world.api.postedTypes(t); !slices.Equal(types, []bridge.SignedType{bridge.SignedType_SIGNED_GRANT_ACTIVATE}) {
		t.Fatalf("the spend posted %v", types)
	}
	acl, err := world.net.log.State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	if rule := acl.grantRule(wantGrant[:]); rule == nil || rule.expiresMs != endMs {
		t.Errorf("the log's grant: %+v, its end %d ms", rule, endMs)
	}

	// refused before anything is filed
	filedCount := world.approvals.filedCount()
	both := *request
	both.Lifetime = time.Hour
	past := *request
	past.ExpiresAt = world.clock.Now()
	for name, refused := range map[string]*BridgeForwardRequest{"a lifetime and an end": &both, "an end not ahead": &past} {
		if _, err := world.filer.Forward(ctx, origin, refused); !errors.Is(err, ErrBridgeFileRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if world.approvals.filedCount() != filedCount || world.api.postCount() != 1 {
		t.Errorf("a refused forward filed %d requests and posted %d statements", world.approvals.filedCount()-filedCount, world.api.postCount()-1)
	}
}

// The daemon's bridge.forward hands expires_ms to the filer as the end itself, as bridge_forward sends it, so a call
// made again with the same params asks the same end; a lifetime asks a lifetime; and an end beside a lifetime, or one
// below zero, is refused before anything is filed.
func TestDaemonBridgeForwardHandsItsEndToTheFiler(t *testing.T) {
	world := newTestDaemonBridges(t)
	approvalId := NewId()
	world.backend.set(func() { world.backend.pending = &approvalId })
	origin := &BridgeFileOrigin{Act: SidecarActMcp}
	endMs := world.clock.Now().Add(90 * time.Minute).UnixMilli()
	params := &DaemonBridgeForwardParams{Target: "peer", Port: 5000, LocalPort: 15000, Listen: []string{"127.0.0.1"}, ExpiresMs: endMs}
	for range 2 {
		if reply, err := world.bridges.Forward(t.Context(), world.networkId, nil, origin, params); err != nil || reply.ApprovalPendingId == nil {
			t.Fatalf("a forward asking an end: %+v, %v", reply, err)
		}
		world.clock.Advance(time.Minute)
	}
	lifetime := &DaemonBridgeForwardParams{Target: "peer", Port: 5000, LocalPort: 15000, Listen: []string{"127.0.0.1"}, LifetimeSeconds: 900}
	if _, err := world.bridges.Forward(t.Context(), world.networkId, nil, origin, lifetime); err != nil {
		t.Fatal(err)
	}
	for name, refused := range map[string]*DaemonBridgeForwardParams{
		"an end and a lifetime": {Target: "peer", Port: 5000, ExpiresMs: endMs, LifetimeSeconds: 900},
		"an end below zero":     {Target: "peer", Port: 5000, ExpiresMs: -1},
	} {
		if _, err := world.bridges.Forward(t.Context(), world.networkId, nil, origin, refused); !errors.Is(err, ErrDaemonBridgeParams) {
			t.Errorf("%s: %v", name, err)
		}
	}
	world.backend.set(func() {
		forwards := world.backend.forwards
		if len(forwards) != 3 {
			t.Fatalf("%d forwards reached the filer", len(forwards))
		}
		for _, forward := range forwards[:2] {
			if forward.ExpiresAt.UnixMilli() != endMs || forward.Lifetime != 0 {
				t.Errorf("a forward asking an end reached the filer as %s and a lifetime of %s", forward.ExpiresAt, forward.Lifetime)
			}
		}
		if forward := forwards[2]; !forward.ExpiresAt.IsZero() || forward.Lifetime != 900*time.Second {
			t.Errorf("a forward asking a lifetime reached the filer as %s and a lifetime of %s", forward.ExpiresAt, forward.Lifetime)
		}
	})
}

// An approved MCP listen's use is done only once the engine holds the grant it activated: while the config's follow
// has not installed the GrantActivate's position, the use has no answer, and once it has, the use is done with the
// grant's id.
func TestSocketListenGrantUseWaitsForItsGrantInTheEngine(t *testing.T) {
	world := newTestListenGrantWorld(t)
	world.rule(world.name, true)
	_, _, err := world.listen()
	request := world.gate.pendingRequest(t, err)
	world.gate.approve(t, request, world.laptop, world.member)
	grantId := AclGrantId(request.ApprovalId(), request.Action.PayloadSha256())

	world.config.hold(true)
	type answer struct {
		action *SidecarAction
		err    error
	}
	answered := make(chan answer, 1)
	go func() {
		action, _, err := world.listenIn(context.Background())
		answered <- answer{action: action, err: err}
	}()
	var position uint64
	select {
	case position = <-world.config.waiting:
	case got := <-answered:
		t.Fatalf("the use answered without waiting for its grant: outcome %+v, %v", testKeptOutcome(got.action), got.err)
	}
	// the GrantActivate is in the log at the receipt's position and not in the engine: the use has no answer yet
	if logPin := world.net.log.State().Pin().GetVersion(); position == 0 || logPin < position {
		t.Fatalf("the use waits for position %d with the log at %d", position, logPin)
	}
	if state := world.engine.State(); state.grantRule(grantId[:]) != nil {
		t.Fatal("the engine held the grant before the wait answered")
	}
	select {
	case got := <-answered:
		t.Fatalf("the use answered before its grant reached the engine: %v", got.err)
	default:
	}
	world.config.release <- nil
	got := <-answered
	if got.err != nil || got.action.Outcome == nil || got.action.Outcome.State != ApprovalOutcomeDone || !bytes.Equal(got.action.Outcome.EffectRef, grantId[:]) {
		t.Fatalf("the use once its grant reached the engine: %v, outcome %+v", got.err, testKeptOutcome(got.action))
	}
	world.config.hold(false)
	if world.api.postCount() != 1 || world.gate.approvals.filedCount() != 1 {
		t.Errorf("%d statements posted, %d requests filed", world.api.postCount(), world.gate.approvals.filedCount())
	}
}

// A grant the engine does not hold within the wait leaves the approved listen's use uncertain, which MCP's tool answers
// unavailable; once the engine holds it, the listen asked again passes the gate under that grant as standing, and its
// effect names the grant, with no second GrantActivate and nothing filed. With no config to wait on at all, the use is
// uncertain too.
func TestSocketListenGrantNotInTheEngineIsUncertainThenNamed(t *testing.T) {
	world := newTestListenGrantWorld(t)
	world.rule(world.name, true)
	_, filed, err := world.listen()
	request := world.gate.pendingRequest(t, err)
	world.gate.approve(t, request, world.laptop, world.member)
	grantId := AclGrantId(request.ApprovalId(), request.Action.PayloadSha256())

	world.config.hold(true)
	world.config.release <- context.DeadlineExceeded
	action, _, err := world.listen()
	if err != nil || action.Outcome == nil || action.Outcome.State != ApprovalOutcomeUncertain || !errors.Is(action.Outcome.Err, ErrAclGrantUnconfirmed) {
		t.Fatalf("a grant not in the engine: %v, outcome %+v", err, testKeptOutcome(action))
	}
	<-world.config.waiting
	if types := world.api.postedTypes(t); !slices.Equal(types, []bridge.SignedType{bridge.SignedType_SIGNED_GRANT_ACTIVATE}) {
		t.Fatalf("the spend posted %v", types)
	}

	// the engine catches up: asked again, the listen passes on the grant its approval activated, which it names
	world.config.hold(false)
	world.install()
	world.advance(time.Minute)
	named, stored, err := world.listen()
	if err != nil || named.Outcome == nil || named.Outcome.State != ApprovalOutcomeDone || !bytes.Equal(named.Outcome.EffectRef, grantId[:]) {
		t.Fatalf("the listen asked again on its grant: %v, outcome %+v", err, testKeptOutcome(named))
	}
	if !bytes.Equal(stored.Bytes, filed.Bytes) {
		t.Error("the listen asked again presented another action than its request's")
	}
	if world.api.postCount() != 1 || world.gate.approvals.filedCount() != 1 {
		t.Errorf("%d statements posted, %d requests filed", world.api.postCount(), world.gate.approvals.filedCount())
	}

	// the awaited grant with no config to wait on: uncertain, the engine not holding it
	other := newTestListenGrantWorld(t)
	other.config = nil
	other.rule(other.name, true)
	_, _, err = other.listen()
	otherRequest := other.gate.pendingRequest(t, err)
	other.gate.approve(t, otherRequest, other.laptop, other.member)
	action, _, err = other.listen()
	if err != nil || action.Outcome == nil || action.Outcome.State != ApprovalOutcomeUncertain || !errors.Is(action.Outcome.Err, ErrAclGrantUnconfirmed) {
		t.Errorf("a grant with no config to wait on: %v, outcome %+v", err, testKeptOutcome(action))
	}
}
