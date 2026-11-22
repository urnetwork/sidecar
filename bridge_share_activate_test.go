//go:build !sidecar_http && !ios_extension && !js

// A share's activation at §16.6's real gate (bridge_share_invite.go's ActivateShare row; §8.11, §17.9, I-8, AU4, AD2):
// on the share world's admin device, config log and ACL engine, with the share's requests rule, an admin approving.
// The activation's grant action is kept in the invite's record as its request was filed, so the activation asked
// again later, by a filer opened afresh over the same store too, presents the action the request stored, though the
// rule's expiry moved on with the clock and a fresh build seals its detail under a fresh nonce; and the admin's
// decision handed in with it is spent, where a fresh action is a decision on another action. The share's pins then
// carry the grant the decision activated, asked again it files nothing twice, before the engine holds the grant and
// after, and once the grant is revoked the activation asks for a new one. Synthetic values only.

package sidecar

import (
	"bytes"
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The activation asked again after an admin's decision spends it into one grant, which the pins carry; asked again it
// files nothing twice, and once the grant is revoked it asks for a new one.
func TestActivateShareAskedAgainAfterApprovalSpendsIt(t *testing.T) {
	world := newTestBridgeShareWorld(t, true)
	world.withSharesRule()
	world.net.log.settings.AclSpendCheck = NewSpendCheck(nil)
	gate := installTestGrantGate(t, world.testBridgeFileWorld)
	t.Cleanup(world.sidecar.RegisterEffectLookup(SidecarActionForward, world.filer.args.Grants.Lookup))
	ctx := context.Background()
	invite, err := world.filer.Invite(ctx, world.confirmed(), &BridgeShareInviteRequest{Targets: []*BridgeShareTargetRequest{
		{Host: world.hostId, Prefix: netip.MustParsePrefix("192.168.7.0/24")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	world.completed(invite, 0x8100)
	preview, err := world.filer.PreviewShare(ctx, world.confirmed(), invite.ShareId)
	if err != nil {
		t.Fatal(err)
	}

	_, err = world.filer.ActivateShare(ctx, world.confirmed(), preview, 0)
	request := gate.pendingRequest(t, err)
	record, err := world.filer.shareInvite(invite.ShareId)
	if err != nil || !bytes.Equal(record.GrantAction, request.Action.Bytes) || record.GrantLifetimeMs != 0 || len(record.GrantId) != 0 {
		t.Fatalf("the invite's record before the decision: %+v, %v", record, err)
	}
	if SidecarActionKind(request.Action.Action.GetKind()) != SidecarActionForward || !bytes.Equal(request.Action.Action.GetShareNetworkId(), world.other.Bytes()) {
		t.Fatalf("the share's request: %+v", request.Action.Action)
	}

	// asked again a minute on, and by a filer opened afresh over the same store, the activation presents its request's
	// action, filing nothing more
	world.advance(time.Minute)
	for _, filer := range []*BridgeFiler{world.filer, testBridgeShareFilerAgain(t, world.filer)} {
		_, err = filer.ActivateShare(ctx, world.confirmed(), preview, 0)
		if again := gate.pendingRequest(t, err); again.ApprovalId() != request.ApprovalId() {
			t.Fatalf("the activation asked again filed %s beside %s", again.ApprovalId(), request.ApprovalId())
		}
	}
	if gate.approvals.filedCount() != 1 || world.api.postCount() != 0 {
		t.Fatalf("%d requests filed, %d statements posted before the decision", gate.approvals.filedCount(), world.api.postCount())
	}

	// the owner's genesis device approves as an admin, and the activation handed that decision spends it
	decision := &bridge.Signed{}
	if err := proto.Unmarshal(gate.approve(t, request, world.net.owner, world.net.ownerMemberId), decision); err != nil {
		t.Fatal(err)
	}
	filing, err := world.filer.ActivateShare(ctx, &BridgeFileOrigin{Act: SidecarActConfirmed, Decision: decision}, preview, 0)
	grantId := AclGrantId(request.ApprovalId(), request.Action.PayloadSha256())
	if err != nil || !bytes.Equal(filing.GrantId, grantId[:]) || filing.ApprovalId != request.ApprovalId() {
		t.Fatalf("the approved activation: %+v, %v (the log's last verdict %+v)", filing, err, world.net.verdicts[world.net.n])
	}
	if types := world.api.postedTypes(t); !slices.Equal(types, []bridge.SignedType{bridge.SignedType_SIGNED_GRANT_ACTIVATE}) {
		t.Fatalf("the activation posted %v", types)
	}
	head, saves := world.heads.savedHead()
	if pins := ReadBridgeShareGrants(head); len(pins) != 1 || !bytes.Equal(pins[0].GetGrantId(), grantId[:]) {
		t.Fatalf("the pin file: %+v", pins)
	}

	// asked again before the engine holds the grant, and after, the activation files nothing twice
	for _, install := range []bool{false, true} {
		if install {
			world.install()
		}
		again, err := world.filer.ActivateShare(ctx, world.confirmed(), preview, 0)
		if _, after := world.heads.savedHead(); err != nil || !bytes.Equal(again.GrantId, grantId[:]) || after != saves || world.api.postCount() != 1 {
			t.Fatalf("asked again, the engine holding the grant %t: %+v, %v", install, again, err)
		}
	}

	// revoked, the grant no longer stands, and the activation asks for a new one rather than answer the spent decision
	if _, err := world.filer.RevokeShare(ctx, world.confirmed(), invite.ShareId); err != nil {
		t.Fatal(err)
	}
	world.install()
	world.advance(time.Minute)
	_, err = world.filer.ActivateShare(ctx, world.confirmed(), preview, 0)
	if afresh := gate.pendingRequest(t, err); afresh.ApprovalId() == request.ApprovalId() {
		t.Fatalf("the activation after its grant's revocation presented its spent action")
	}
}

// A filer over the same args as filer, as a daemon's restart opens one again over the same store.
func testBridgeShareFilerAgain(t *testing.T, filer *BridgeFiler) *BridgeFiler {
	t.Helper()
	again, err := NewBridgeFiler(filer.args)
	if err != nil {
		t.Fatal(err)
	}
	return again
}
