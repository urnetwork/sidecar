//go:build !sidecar_http && !js

package sidecar

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §22.5's §18 row at the core (CORE-M2-07): ur logout signs, posts, removes, then wipes, and keeps state while its
// sign-out cannot land; a revocation claim, by core hint or refused bind, is verified against the config and never
// trusted, a forged one leaving identity intact.

// Installs a verified state as the sidecar's authority: admitted, nil for none, holds this sidecar's row, revoked at
// a position when revokedAt is not zero.
func installTestRevocationAuthority(t *testing.T, sidecar *Sidecar, sidecarId Id, admitted *bridge.SidecarRow) *testActAuthority {
	t.Helper()
	authority := newTestActAuthority()
	if admitted != nil {
		authority.sidecars[sidecarId] = &AclSidecar{Row: admitted}
	}
	t.Cleanup(sidecar.InstallAuthority(authority))
	return authority
}

// The world's sidecar with a verified state holding row for it, nil for none.
func (self *testEnrollWorld) installAuthority(t *testing.T, row *bridge.SidecarRow) *testActAuthority {
	t.Helper()
	return installTestRevocationAuthority(t, self.sidecar, self.sidecar.currentIdentity().SidecarId, row)
}

// An admission row of sidecarId, revoked at revokedAt when not zero.
func testAdmissionRow(sidecarId Id, revokedAt uint64) *bridge.SidecarRow {
	return &bridge.SidecarRow{SidecarId: sidecarId.Bytes(), AdmittedAt: 7, RevokedAt: revokedAt}
}

// The paths of the requests a logout made, in order: the sign-out's post, then the removal.
func testLogoutPaths(api *testEnrollApi) []string {
	return slices.DeleteFunc(api.requestedPaths(), func(path string) bool {
		return path == "/network/enroll" || path == "/sidecar/bind" || strings.HasPrefix(path, "/sidecar/sync/")
	})
}

// ur logout signs SidecarRevoke{removed} for its own sidecar_id by its identity key and posts it first, then removes
// its client, then wipes.
func TestLogoutSignsThenRemovesThenWipes(t *testing.T) {
	world := newTestEnrollWorld(t)
	if err := world.enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	world.platform.connected.Set(true)
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOnline, 1))
	identity := world.sidecar.currentIdentity()
	world.installAuthority(t, testAdmissionRow(identity.SidecarId, 0))

	if err := world.sidecar.Logout(context.Background()); err != nil {
		t.Fatal(err)
	}
	if paths := testLogoutPaths(world.api); strings.Join(paths, " ") != "/network/config/delta /network/remove-client" {
		t.Fatalf("requests %v", paths)
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(world.api.deltaPosts[0], signed); err != nil {
		t.Fatal(err)
	}
	revoke := &bridge.SidecarRevoke{}
	if err := proto.Unmarshal(signed.GetBody(), revoke); err != nil {
		t.Fatal(err)
	}
	signerId, _ := IdFromBytes(signed.GetSignerId())
	revokedId, _ := IdFromBytes(revoke.GetSidecarId())
	if bridge.SignedType(signed.GetType()) != bridge.SignedType_SIGNED_SIDECAR_REVOKE || signerId != identity.SidecarId ||
		revokedId != identity.SidecarId || revoke.GetReason() != bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED {
		t.Fatalf("the sign-out: type %#x, signer %s, revoked %s, reason %s", signed.GetType(), signerId, revokedId, revoke.GetReason())
	}
	if err := bridge.VerifySigned(signed, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_SIDECAR_REVOKE, bridge.SignedKeyAlgEd25519, identity.IdentityPublicKey); err != nil {
		t.Errorf("the sign-out does not verify under the identity key: %v", err)
	}
	if len(world.api.removed) != 1 || world.api.removed[0] != identity.ClientId {
		t.Errorf("removed %v", world.api.removed)
	}
	if files := networkFiles(t, world.backend, identity.NetworkId); len(files) != 0 {
		t.Errorf("logout left %d network files", len(files))
	}
}

// An offline logout signs and keeps its sign-out, removes nothing and wipes nothing, so the statement is not stranded;
// the next logout posts the same bytes, then removes and wipes.
func TestLogoutOfflineKeepsState(t *testing.T) {
	world := newTestEnrollWorld(t)
	if err := world.enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOffline, 1))
	identity := world.sidecar.currentIdentity()
	world.installAuthority(t, testAdmissionRow(identity.SidecarId, 0))
	world.api.deltaAnswers = []string{"lost"}
	// the generation's own repost of what was pending at its start has run, so only the logouts post
	for {
		number, changed := world.sidecar.runningGenerationNumber.Get()
		if number == 1 {
			break
		}
		<-changed
	}
	<-world.sidecar.runningGeneration().pendingDone

	if err := world.sidecar.Logout(context.Background()); !errors.Is(err, ErrSidecarLogoutPending) {
		t.Fatalf("an offline logout: %v", err)
	}
	if len(world.api.removed) != 0 || len(networkFiles(t, world.backend, identity.NetworkId)) == 0 ||
		world.sidecar.currentIdentity() == nil || len(world.instance.Networks()) != 1 {
		t.Fatal("an offline logout removed or wiped")
	}
	pendings, err := world.sidecar.pendingSignOuts(identity.SidecarId)
	if err != nil || len(pendings) != 1 {
		t.Fatalf("the kept sign-out: %d %v", len(pendings), err)
	}

	if err := world.sidecar.Logout(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(world.api.deltaPosts) != 2 || string(world.api.deltaPosts[0]) != string(world.api.deltaPosts[1]) {
		t.Fatalf("the retry posted other bytes: %d posts", len(world.api.deltaPosts))
	}
	if len(world.api.removed) != 1 || len(networkFiles(t, world.backend, identity.NetworkId)) != 0 {
		t.Error("the retried logout did not remove and wipe")
	}
}

// With no verified config the sign-out cannot be signed, and a logout keeps everything.
func TestLogoutWithoutVerifiedConfigKeepsState(t *testing.T) {
	world := newTestEnrollWorld(t)
	if err := world.enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOffline, 1))
	identity := world.sidecar.currentIdentity()
	before := backendSnapshot(t, world.backend)
	if err := world.sidecar.Logout(context.Background()); !errors.Is(err, ErrSidecarLogoutUnverified) {
		t.Fatalf("%v", err)
	}
	if after := backendSnapshot(t, world.backend); !snapshotsEqual(before, after) || len(world.api.removed) != 0 {
		t.Errorf("an unverified logout changed the disk or removed the client of %s", identity.SidecarId)
	}
}

// A core revocation hint for this sidecar.
func testRevocationHint(t *testing.T, sidecarId Id) []byte {
	t.Helper()
	hint, err := proto.Marshal(&protocol.CoreHint{Kind: protocol.CoreHintKind_CORE_HINT_KIND_REVOCATION, SidecarId: sidecarId.Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	return hint
}

// An online sidecar on an enrolled instance, its events counted by kind.
func newRevocationTestSidecar(t *testing.T) (*Sidecar, *testEnrollment, *MonitorValue[int]) {
	t.Helper()
	instance, enrollment := newTestEnrolledInstance(t)
	platform := newTestSidecarPlatform()
	sidecar := newTestRunningSidecar(t, instance, &enrollment.networkId, testSidecarSettings(platform))
	platform.connected.Set(true)
	awaitSidecarStatus(t, sidecar, atStatus(SidecarStateOnline, 1))
	refused := NewMonitorValue(0)
	t.Cleanup(sidecar.AddEventCallback(func(event SidecarEvent) {
		if event.Kind == SidecarEventRefused {
			refused.Update(func(count int) int { return count + 1 })
		}
	}))
	return sidecar, enrollment, refused
}

// A REVOCATION hint the config does not bear out is a claim that does not verify: Unenrolled(refused) with the refused
// alarm, and the identity, its keys and the keychain stay.
func TestForgedCoreRevocationIsUnenrolledAndAlarms(t *testing.T) {
	sidecar, enrollment, refused := newRevocationTestSidecar(t)
	installTestRevocationAuthority(t, sidecar, enrollment.sidecarId, testAdmissionRow(enrollment.sidecarId, 0))
	// a hint naming another sidecar, and a resync, are no claim of this one's
	sidecar.receiveCoreHint(1, testRevocationHint(t, NewId()))
	sidecar.receiveCoreHint(1, []byte{0x08, byte(protocol.CoreHintKind_CORE_HINT_KIND_RESYNC)})
	if status := sidecar.Status(); status.State != SidecarStateOnline {
		t.Fatalf("a hint of no claim moved the sidecar to %s", status.State)
	}

	sidecar.receiveCoreHint(1, testRevocationHint(t, enrollment.sidecarId))
	awaitSidecarStatus(t, sidecar, func(status SidecarStatus) bool {
		return status.State == SidecarStateUnenrolled && status.Reason == SidecarReasonRefused
	})
	for {
		count, changed := refused.Get()
		if 0 < count {
			break
		}
		<-changed
	}
	identity := sidecar.currentIdentity()
	if identity == nil || identity.SidecarId != enrollment.sidecarId {
		t.Fatal("a forged claim dropped the identity")
	}
	if record, err := loadSidecarIdentity(enrollment.secrets); err != nil || record.identity.SidecarId != enrollment.sidecarId {
		t.Fatalf("a forged claim touched the keychain: %v", err)
	}
}

// A SidecarRevoke the verified state holds is Revoked(signed), and the keys stay the sidecar's own.
func TestSignedRevocationIsRevoked(t *testing.T) {
	sidecar, enrollment, _ := newRevocationTestSidecar(t)
	installTestRevocationAuthority(t, sidecar, enrollment.sidecarId, testAdmissionRow(enrollment.sidecarId, 12))
	sidecar.receiveCoreHint(1, testRevocationHint(t, enrollment.sidecarId))
	awaitSidecarStatus(t, sidecar, func(status SidecarStatus) bool {
		return status.State == SidecarStateRevoked && status.Reason == SidecarReasonSigned
	})
	if record, err := loadSidecarIdentity(enrollment.secrets); err != nil || record.identity.SidecarId != enrollment.sidecarId {
		t.Fatalf("a revocation wiped the keychain: %v", err)
	}
	if revoked, err := sidecar.VerifyRevocationClaim(context.Background()); err != nil || !revoked {
		t.Errorf("a revoked sidecar's claim: %v %v", revoked, err)
	}
}

// A bind refused with sidecar_revoked is a claim too: with the config not bearing it out the re-enrollment fails and
// the sidecar is Unenrolled(refused) with its identity; with the config holding the revocation it is Revoked.
func TestRefusedBindVerifiesAgainstConfig(t *testing.T) {
	for _, revokedAt := range []uint64{0, 12} {
		world := newTestEnrollWorld(t)
		if err := world.enroll(context.Background()); err != nil {
			t.Fatal(err)
		}
		world.platform.connected.Set(true)
		awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOnline, 1))
		identity := world.sidecar.currentIdentity()
		opened := world.platform.awaitOpened(t, 1)
		world.sidecar.runningGeneration().tokenManager.Load().end(SidecarReasonExpired)
		awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateUnenrolled, 1))
		<-opened.closed
		world.installAuthority(t, testAdmissionRow(identity.SidecarId, revokedAt))
		world.api.bindRefusal = &testApiRefusal{status: http.StatusForbidden, code: "sidecar_revoked"}

		err := world.enroll(context.Background())
		status := world.sidecar.Status()
		if revokedAt == 0 {
			if err == nil || errors.Is(err, ErrSidecarRevoked) || status.State != SidecarStateUnenrolled || status.Reason != SidecarReasonRefused {
				t.Fatalf("an unverified refusal: %v, %s %s", err, status.State, status.Reason)
			}
		} else {
			if !errors.Is(err, ErrSidecarRevoked) || status.State != SidecarStateRevoked {
				t.Fatalf("a verified refusal: %v, %s", err, status.State)
			}
		}
		if after := world.sidecar.currentIdentity(); after == nil || after.SidecarId != identity.SidecarId || after.Generation != 1 {
			t.Fatalf("a refused bind changed the identity: %+v", after)
		}
	}
}
