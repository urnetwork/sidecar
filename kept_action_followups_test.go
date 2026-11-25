//go:build !js && !ios && !android && !sdk_mobile_bind && !windows && !sidecar_http && !ios_extension

// Follow-ups to the kept grant actions of listens, publishes and forwards (acl_grant_keep.go), each at §16.6's real
// gate on the bridge file world's sidecar, config log and ACL engine:
//
//   - Sidecar.Listen's tls/ listen keeps its action in a GrantActionKeeper with the ended check: asked again once the
//     grant its decision activated has been revoked, it files a new request, where the kept action's spent decision
//     answered done from its record and the listen registered on a grant that no longer stands; while the grant stands
//     the kept action is presented and passes on it, filing nothing.
//
// Synthetic values only.

package sidecar

import (
	"bytes"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

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
