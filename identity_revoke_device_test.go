package sidecar

// CORE-M3-03: RevokeDevice's sign and effects rows and FS-98's race rows, on a scripted delta route and a clock the
// test moves: the target signing between preview and signing (no REVOKE_STALE, the items join); a key registered then
// under a lost revocation (REVOKE_STALE, then the new plan); the post's response lost (the same bytes again); a kill
// after the SidecarRevoke and before a KeyRevoke (each lands once); k = 2 suspending at once; a suspended target that
// cannot revoke back; a failed presence check signing nothing; and no KeyRevoke without presence.

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What a landed revocation handed on, in order.
type revokeTestEffects struct {
	stateLock sync.Mutex
	calls     []string
	positions []uint64
	sidecars  []Id
	// one value per effects run, sent once the tracking is in
	done chan struct{}
}

func newRevokeTestEffects() *revokeTestEffects {
	return &revokeTestEffects{done: make(chan struct{}, 16)}
}

func (self *revokeTestEffects) CommitRevocation(ctx context.Context, sidecarId Id, entry *bridge.AuthPin) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.calls = append(self.calls, "commit")
	self.sidecars = append(self.sidecars, sidecarId)
	return nil
}

func (self *revokeTestEffects) TrackRevocation(position uint64) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.calls = append(self.calls, "track")
		self.positions = append(self.positions, position)
	}()
	self.done <- struct{}{}
}

func (self *revokeTestEffects) snapshot() ([]string, []uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.calls...), append([]uint64{}, self.positions...)
}

// A world whose device holds a live presence key the log covers a revocation, a Suspend, a proposal and a KeyRevoke
// by, and the check that key's holder runs.
func newRevokePresenceWorld(t *testing.T) (*revokeTestWorld, SidecarPresenceCheck) {
	t.Helper()
	world := newRevokeTestWorld(t)
	key, keyId := addTestPresenceKey(t, world.authority.testActAuthority)
	world.authority.edit(func() {
		for _, signedType := range []bridge.SignedType{
			bridge.SignedType_SIGNED_SIDECAR_REVOKE, bridge.SignedType_SIGNED_KEY_REVOKE, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL,
		} {
			world.authority.covered[signedType] = true
		}
	})
	seen := []byte{}
	return world, testPresenceCheck(t, key, keyId, &seen)
}

// The decoded statement of a posted Signed.
func postedBody(t *testing.T, signed *bridge.Signed, message proto.Message) {
	t.Helper()
	if err := proto.Unmarshal(signed.GetBody(), message); err != nil {
		t.Fatal(err)
	}
}

// A lost revocation on a device with no presence key signs one SidecarRevoke{lost} on the person's confirmation
// alone, revoking no key though one was selected; this device then commits its Removes first and shows the
// revocation unwitnessed. A plan this Sidecar never previewed is REVOKE_STALE.
func TestRevokeLostSignsOneSidecarRevoke(t *testing.T) {
	world := newRevokeTestWorld(t)
	ctx := context.Background()
	effects := newRevokeTestEffects()
	t.Cleanup(world.sidecar.InstallRevokeEffects(effects))
	keyId := countingBytes(0x40, 32)
	world.authority.edit(func() {
		world.authority.keys[world.otherId] = []*bridge.KeyRow{{KeyId: keyId, Purpose: bridge.KeyPurpose_KEY_PURPOSE_PRESENCE, Signer: world.otherId.Bytes(), At: 8}}
	})
	if _, _, err := world.sidecar.RevokeDevice(ctx, NewId(), nil, nil); revokeCode(err) != DeviceRevokeCodeStale {
		t.Fatalf("a plan never previewed: %v", err)
	}
	plan, err := world.sidecar.PreviewDeviceRevoke(ctx, world.otherId, DeviceRevokeLost, time.Time{}, 0)
	if err != nil || plan.Presence {
		t.Fatalf("the plan: %+v, %v", plan, err)
	}
	if _, err := world.sidecar.RevokeDevicePlan(ctx, plan.PlanId, [][]byte{countingBytes(0x99, 32)}, SidecarActConfirmed, nil); !errors.Is(err, ErrSidecarRevokeKey) {
		t.Fatalf("a key that is no item of the plan: %v", err)
	}
	// never MCP, a harness hook or an unconfirmed control call
	for _, origin := range []SidecarActOrigin{SidecarActMcp, SidecarActHook, SidecarActUnconfirmed} {
		if _, err := world.sidecar.RevokeDevicePlan(ctx, plan.PlanId, nil, origin, nil); !errors.Is(err, ErrSidecarActMode) {
			t.Errorf("origin %d: %v", origin, err)
		}
	}
	if posts := world.deltaApi.postsSoFar(); len(posts) != 0 {
		t.Fatalf("%d statements posted before the confirmed call", len(posts))
	}
	// TestNoKeyRevokeWithoutPresence: the selected key is not revoked where no presence evidence stands behind it
	revocation, err := world.sidecar.RevokeDevicePlan(ctx, plan.PlanId, [][]byte{keyId}, SidecarActConfirmed, nil)
	if err != nil {
		t.Fatal(err)
	}
	posts := world.posted(t)
	if len(posts) != 1 || bridge.SignedType(posts[0].GetType()) != bridge.SignedType_SIGNED_SIDECAR_REVOKE || posts[0].GetWebauthn() != nil {
		t.Fatalf("posted %d statements", len(posts))
	}
	revoke := &bridge.SidecarRevoke{}
	postedBody(t, posts[0], revoke)
	if !bytes.Equal(revoke.GetSidecarId(), world.otherId.Bytes()) || revoke.GetReason() != bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST || revoke.GetSinceN() != 0 {
		t.Fatalf("the revocation: %+v", revoke)
	}
	if revocation.Entry == nil || len(revocation.RevokedKeyIds) != 0 || revocation.ProposalId != nil || revocation.Pending {
		t.Fatalf("the result: %+v", revocation)
	}
	calls, positions := effects.snapshot()
	if len(calls) != 2 || calls[0] != "commit" || calls[1] != "track" || positions[0] != revocation.Entry.GetVersion() {
		t.Errorf("the effects: %v at %v", calls, positions)
	}
	// the plan is spent
	if _, _, err := world.sidecar.RevokeDevice(ctx, plan.PlanId, nil, nil); revokeCode(err) != DeviceRevokeCodeStale {
		t.Errorf("a plan signed once: %v", err)
	}
}

// TestNoKeyRevokeWithoutPresence, its other half, and FS-124: under Presence the act signs the SidecarRevoke and a
// KeyRevoke of each selected key, each statement carrying the act's one countersignature with its own path; RevokeDevice
// takes the host's check as §5.4 gives it, evidence encoded.
func TestRevokeUnderPresenceRevokesSelectedKeys(t *testing.T) {
	world, check := newRevokePresenceWorld(t)
	ctx := context.Background()
	selectedKeyId, keptKeyId := countingBytes(0x40, 32), countingBytes(0x60, 32)
	world.authority.edit(func() {
		world.authority.keys[world.otherId] = []*bridge.KeyRow{
			{KeyId: selectedKeyId, Purpose: bridge.KeyPurpose_KEY_PURPOSE_PRESENCE, Signer: world.otherId.Bytes(), At: 8},
			{KeyId: keptKeyId, Purpose: bridge.KeyPurpose_KEY_PURPOSE_SSHSIG, Signer: world.otherId.Bytes(), At: 9},
		}
	})
	plan, err := world.sidecar.PreviewDeviceRevoke(ctx, world.otherId, DeviceRevokeLost, time.Time{}, 0)
	if err != nil || !plan.Presence {
		t.Fatalf("the plan: %+v, %v", plan, err)
	}
	checks := 0
	presence := func(challenge []byte) ([]byte, error) {
		checks += 1
		evidence, err := check(challenge)
		if err != nil {
			return nil, err
		}
		return proto.Marshal(evidence)
	}
	entry, proposalId, err := world.sidecar.RevokeDevice(ctx, plan.PlanId, [][]byte{selectedKeyId}, presence)
	if err != nil || entry == nil || proposalId != nil || checks != 1 {
		t.Fatalf("the revocation: %v, %x, %v after %d checks", entry, proposalId, err, checks)
	}
	posts := world.posted(t)
	if len(posts) != 2 || bridge.SignedType(posts[0].GetType()) != bridge.SignedType_SIGNED_SIDECAR_REVOKE ||
		bridge.SignedType(posts[1].GetType()) != bridge.SignedType_SIGNED_KEY_REVOKE {
		t.Fatalf("posted %d statements", len(posts))
	}
	keyRevoke := &protocol.KeyRevoke{}
	postedBody(t, posts[1], keyRevoke)
	if !bytes.Equal(keyRevoke.GetKeyId(), selectedKeyId) {
		t.Errorf("the KeyRevoke names %x", keyRevoke.GetKeyId())
	}
	for index, signed := range posts {
		if signed.GetWebauthn() == nil || signed.GetWebauthn().GetActSize() != 2 || signed.GetWebauthn().GetActIndex() != uint32(index) {
			t.Errorf("statement %d carries no countersignature of the act: %+v", index, signed.GetWebauthn())
		}
	}
}

// TestFailedPresenceSignsNothing: under Presence, a check that fails or is refused, a call sending no check, and
// evidence that does not verify against a live key each answer REVOKE_CANCELLED, with nothing signed, kept or posted,
// and the plan still good for a check that passes.
func TestFailedPresenceSignsNothing(t *testing.T) {
	world, check := newRevokePresenceWorld(t)
	ctx := context.Background()
	plan, err := world.sidecar.PreviewDeviceRevoke(ctx, world.otherId, DeviceRevokeLost, time.Time{}, 0)
	if err != nil || !plan.Presence {
		t.Fatalf("the plan: %+v, %v", plan, err)
	}
	refused := func(countersignedBytes []byte) (*bridge.WebAuthnEvidence, error) {
		return nil, errors.New("the person refused")
	}
	forged := func(countersignedBytes []byte) (*bridge.WebAuthnEvidence, error) {
		evidence, err := check(countersignedBytes)
		if err != nil {
			return nil, err
		}
		evidence.Signature = bytes.Clone(evidence.GetSignature())
		evidence.Signature[len(evidence.Signature)-1] ^= 1
		return evidence, nil
	}
	for name, failing := range map[string]SidecarPresenceCheck{"a refused check": refused, "no check": nil, "evidence that does not verify": forged} {
		if _, err := world.sidecar.RevokeDevicePlan(ctx, plan.PlanId, nil, SidecarActConfirmed, failing); revokeCode(err) != DeviceRevokeCodeCancelled {
			t.Errorf("%s: %v", name, err)
		}
	}
	if posts := world.deltaApi.postsSoFar(); len(posts) != 0 {
		t.Fatalf("%d statements posted after failed checks", len(posts))
	}
	if pendings, err := world.sidecar.pendingStatements(); err != nil || len(pendings) != 0 {
		t.Fatalf("%d statements kept after failed checks: %v", len(pendings), err)
	}
	if _, err := world.sidecar.RevokeDevicePlan(ctx, plan.PlanId, nil, SidecarActConfirmed, check); err != nil {
		t.Fatalf("the check that passes: %v", err)
	}
}

// FS-98's first race: the target signs between the preview and the signing, so the cascade gains park and void items
// resting on its signatures. No REVOKE_STALE: they join unasked and the result lists them. P reaching this sidecar
// is REVOKE_PARKS_SELF, naming the entry.
func TestItemsThatEnterAfterThePreviewJoin(t *testing.T) {
	world := newRevokeTestWorld(t)
	ctx := context.Background()
	sinceN := world.n - 3
	parkedId, lateId := NewId(), NewId()
	world.admit(parkedId, world.memberId, sinceN+1)
	cascade := []DeviceRevokeItem{{Effect: DeviceRevokeEffectPark, Kind: DeviceRevokeKindDevice, Id: parkedId.Bytes(), Position: sinceN + 1}}
	world.authority.edit(func() {
		world.authority.cascades[revokeTestCascadeKey{targetId: world.otherId, sinceN: sinceN}] = cascade
	})
	plan, err := world.sidecar.PreviewDeviceRevoke(ctx, world.otherId, DeviceRevokeCompromise, time.Time{}, sinceN)
	if err != nil {
		t.Fatal(err)
	}
	// the target admits a device and files a share after the preview
	late := world.apply(nil)
	world.admit(lateId, world.memberId, late.Pin.GetVersion())
	joined := []DeviceRevokeItem{
		{Effect: DeviceRevokeEffectPark, Kind: DeviceRevokeKindDevice, Id: lateId.Bytes(), Position: late.Pin.GetVersion()},
		{Effect: DeviceRevokeEffectVoid, Kind: "evs_share", Id: NewId().Bytes(), Position: late.Pin.GetVersion()},
	}
	world.authority.edit(func() {
		world.authority.cascades[revokeTestCascadeKey{targetId: world.otherId, sinceN: sinceN}] = append(append([]DeviceRevokeItem{}, cascade...), joined...)
	})
	revocation, err := world.sidecar.RevokeDevicePlan(ctx, plan.PlanId, nil, SidecarActConfirmed, nil)
	if err != nil {
		t.Fatalf("items that joined made the plan stale: %v", err)
	}
	if len(revocation.Joined) != 2 || !bytes.Equal(revocation.Joined[0].Id, joined[0].Id) || !bytes.Equal(revocation.Joined[1].Id, joined[1].Id) {
		t.Errorf("the result lists %+v", revocation.Joined)
	}
	posts := world.posted(t)
	revoke := &bridge.SidecarRevoke{}
	if len(posts) != 1 {
		t.Fatalf("posted %d statements", len(posts))
	}
	postedBody(t, posts[0], revoke)
	if revoke.GetReason() != bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE || revoke.GetSinceN() != sinceN {
		t.Errorf("the revocation: %+v", revoke)
	}

	// P now holding this sidecar refuses at the signing, naming the entry
	thirdId := NewId()
	world.admit(thirdId, world.memberId, 5)
	again, err := world.sidecar.PreviewDeviceRevoke(ctx, thirdId, DeviceRevokeCompromise, time.Time{}, sinceN)
	if err != nil {
		t.Fatal(err)
	}
	world.authority.edit(func() {
		world.authority.cascades[revokeTestCascadeKey{targetId: thirdId, sinceN: sinceN}] = []DeviceRevokeItem{
			{Effect: DeviceRevokeEffectPark, Kind: DeviceRevokeKindDevice, Id: world.selfId.Bytes(), Position: sinceN + 2},
		}
	})
	_, err = world.sidecar.RevokeDevicePlan(ctx, again.PlanId, nil, SidecarActConfirmed, nil)
	var revokeError *DeviceRevokeError
	if !errors.As(err, &revokeError) || revokeError.Code != DeviceRevokeCodeParksSelf || revokeError.Position != sinceN+2 {
		t.Errorf("P holding the caller at the signing: %v", err)
	}
	if len(world.deltaApi.postsSoFar()) != 1 {
		t.Error("a refused signing posted")
	}
}

// FS-98's second race: a key the target registers after the preview, under a lost revocation, changes the plan's key
// items and so its PlanId: REVOKE_STALE, nothing signed, then the new plan signs.
func TestAKeyRegisteredAfterThePreviewIsStale(t *testing.T) {
	world, check := newRevokePresenceWorld(t)
	ctx := context.Background()
	plan, err := world.sidecar.PreviewDeviceRevoke(ctx, world.otherId, DeviceRevokeLost, time.Time{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	keyId := countingBytes(0x40, 32)
	world.authority.edit(func() {
		world.authority.keys[world.otherId] = []*bridge.KeyRow{{KeyId: keyId, Purpose: bridge.KeyPurpose_KEY_PURPOSE_PRESENCE, Signer: world.otherId.Bytes(), At: world.n}}
	})
	if _, err := world.sidecar.RevokeDevicePlan(ctx, plan.PlanId, nil, SidecarActConfirmed, check); revokeCode(err) != DeviceRevokeCodeStale {
		t.Fatalf("a plan whose key items changed: %v", err)
	}
	if posts := world.deltaApi.postsSoFar(); len(posts) != 0 {
		t.Fatalf("a stale plan posted %d statements", len(posts))
	}
	next, err := world.sidecar.PreviewDeviceRevoke(ctx, world.otherId, DeviceRevokeLost, time.Time{}, 0)
	if err != nil || next.PlanId == plan.PlanId {
		t.Fatalf("the new plan: %+v, %v", next, err)
	}
	revocation, err := world.sidecar.RevokeDevicePlan(ctx, next.PlanId, [][]byte{keyId}, SidecarActConfirmed, check)
	if err != nil || len(revocation.RevokedKeyIds) != 1 || len(world.deltaApi.postsSoFar()) != 2 {
		t.Fatalf("the new plan's signing: %+v, %v", revocation, err)
	}
}

// FS-98's third and fourth races. The post's response lost: the statement stays pending and goes again with the same
// bytes, so the log takes one entry. A kill after the SidecarRevoke and before a KeyRevoke: the revocation landed
// once and is not posted again, and the KeyRevoke lands with the bytes that were kept. A statement api refuses at the
// tip is REVOKE_REFUSED.
func TestRevokeRetriesTheSameBytes(t *testing.T) {
	world, check := newRevokePresenceWorld(t)
	ctx := context.Background()
	keyId := countingBytes(0x40, 32)
	world.authority.edit(func() {
		world.authority.keys[world.otherId] = []*bridge.KeyRow{{KeyId: keyId, Purpose: bridge.KeyPurpose_KEY_PURPOSE_PRESENCE, Signer: world.otherId.Bytes(), At: 8}}
	})
	plan, err := world.sidecar.PreviewDeviceRevoke(ctx, world.otherId, DeviceRevokeLost, time.Time{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	// the SidecarRevoke lands; the KeyRevoke's answer is lost, as a kill between the two leaves it
	world.deltaApi.answers = []string{"ok", "lost"}
	revocation, err := world.sidecar.RevokeDevicePlan(ctx, plan.PlanId, [][]byte{keyId}, SidecarActConfirmed, check)
	if !errors.Is(err, ErrSidecarActPending) || revocation == nil || !revocation.Pending || revocation.Entry == nil {
		t.Fatalf("a lost answer: %+v, %v", revocation, err)
	}
	if err := world.sidecar.PostPendingStatements(ctx); err != nil {
		t.Fatal(err)
	}
	posts := world.deltaApi.postsSoFar()
	if len(posts) != 3 || !bytes.Equal(posts[1], posts[2]) || bytes.Equal(posts[0], posts[1]) {
		t.Fatalf("%d posts, the retry of other bytes or the revocation posted again", len(posts))
	}
	if pendings, err := world.sidecar.pendingStatements(); err != nil || len(pendings) != 0 {
		t.Errorf("%d statements still pending: %v", len(pendings), err)
	}

	// the post's response lost on the revocation itself: one statement, posted again byte for byte, and the effects
	// run once this device sees its entry applied
	effects := newRevokeTestEffects()
	t.Cleanup(world.sidecar.InstallRevokeEffects(effects))
	thirdId := NewId()
	world.admit(thirdId, world.memberId, 5)
	plan, err = world.sidecar.PreviewDeviceRevoke(ctx, thirdId, DeviceRevokeLost, time.Time{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	world.deltaApi.answers = []string{"lost"}
	if _, err := world.sidecar.RevokeDevicePlan(ctx, plan.PlanId, nil, SidecarActConfirmed, check); !errors.Is(err, ErrSidecarActPending) {
		t.Fatalf("a lost answer: %v", err)
	}
	if err := world.sidecar.PostPendingStatements(ctx); err != nil {
		t.Fatal(err)
	}
	posts = world.deltaApi.postsSoFar()
	if len(posts) != 5 || !bytes.Equal(posts[3], posts[4]) {
		t.Fatalf("%d posts, the retry of other bytes", len(posts))
	}
	if calls, _ := effects.snapshot(); len(calls) != 0 {
		t.Fatalf("effects ran before the revocation's entry was seen: %v", calls)
	}
	landed := world.apply(func(entry *SidecarAuthorityEntry) {
		body, _ := proto.Marshal(&bridge.SidecarRevoke{SidecarId: thirdId.Bytes(), Reason: bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST})
		entry.Effects = []*SidecarAuthorityEffect{{Type: bridge.SignedType_SIGNED_SIDECAR_REVOKE, Body: body}}
	})
	<-effects.done
	if calls, positions := effects.snapshot(); len(calls) != 2 || calls[0] != "commit" || positions[0] != landed.Pin.GetVersion() {
		t.Errorf("the effects of a retried revocation: %v at %v", calls, positions)
	}

	// api refuses at the tip
	fourthId := NewId()
	world.admit(fourthId, world.memberId, 6)
	plan, err = world.sidecar.PreviewDeviceRevoke(ctx, fourthId, DeviceRevokeLost, time.Time{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	world.deltaApi.answers = []string{"refused"}
	if _, err := world.sidecar.RevokeDevicePlan(ctx, plan.PlanId, nil, SidecarActConfirmed, check); revokeCode(err) != DeviceRevokeCodeRefused {
		t.Fatalf("a refused statement: %v", err)
	}
	if pendings, err := world.sidecar.pendingStatements(); err != nil || len(pendings) != 0 {
		t.Errorf("%d statements pending after a refusal: %v", len(pendings), err)
	}
}

// TestK2SuspendsAtOnce: an AdminSet member's device needs k = 2, so the act signs the revocation's AuthorityProposal
// and, in the same act, Suspend{target}, both under the one presence check; the call answers the proposal's id, and
// the effects wait for the completing cosign's entry, which this device sees applied.
func TestK2SuspendsAtOnce(t *testing.T) {
	world, check := newRevokePresenceWorld(t)
	ctx := context.Background()
	effects := newRevokeTestEffects()
	t.Cleanup(world.sidecar.InstallRevokeEffects(effects))
	world.authority.edit(func() { world.authority.signatures[world.otherId] = 2 })
	plan, err := world.sidecar.PreviewDeviceRevoke(ctx, world.otherId, DeviceRevokeLost, time.Time{}, 0)
	if err != nil || plan.Signatures != 2 {
		t.Fatalf("the plan: %+v, %v", plan, err)
	}
	revocation, err := world.sidecar.RevokeDevicePlan(ctx, plan.PlanId, nil, SidecarActConfirmed, check)
	if err != nil {
		t.Fatal(err)
	}
	posts := world.posted(t)
	if len(posts) != 2 || bridge.SignedType(posts[0].GetType()) != bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL ||
		bridge.SignedType(posts[1].GetType()) != bridge.SignedType_SIGNED_SUSPEND {
		t.Fatalf("posted %d statements", len(posts))
	}
	proposal, suspend, revoke := &protocol.AuthorityProposal{}, &bridge.Suspend{}, &bridge.SidecarRevoke{}
	postedBody(t, posts[0], proposal)
	postedBody(t, posts[1], suspend)
	if bridge.SignedType(proposal.GetStatementType()) != bridge.SignedType_SIGNED_SIDECAR_REVOKE || proto.Unmarshal(proposal.GetStatement(), revoke) != nil ||
		!bytes.Equal(revoke.GetSidecarId(), world.otherId.Bytes()) || revoke.GetHeader() == nil {
		t.Fatalf("the proposal carries %+v", revoke)
	}
	if !bytes.Equal(suspend.GetSubject(), world.otherId.Bytes()) || len(suspend.GetSuspendId()) != 16 {
		t.Fatalf("the Suspend: %+v", suspend)
	}
	wantId := bridge.SignedBytesSha256(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, posts[0].GetBody())
	if revocation.Entry != nil || !bytes.Equal(revocation.ProposalId, wantId[:]) {
		t.Fatalf("the result: %+v", revocation)
	}
	for index, signed := range posts {
		if signed.GetWebauthn() == nil || signed.GetWebauthn().GetActSize() != 2 {
			t.Errorf("statement %d carries no countersignature", index)
		}
	}
	if calls, _ := effects.snapshot(); len(calls) != 0 {
		t.Fatalf("effects ran before the completing cosign: %v", calls)
	}
	// an entry that completes nothing of this target runs nothing
	world.apply(func(entry *SidecarAuthorityEntry) {
		body, _ := proto.Marshal(&bridge.SidecarRevoke{SidecarId: NewId().Bytes()})
		entry.Effects = []*SidecarAuthorityEffect{{Type: bridge.SignedType_SIGNED_SIDECAR_REVOKE, Body: body}}
	})
	// the k-th cosign applies: the proposed revocation takes effect at its entry
	completing := world.apply(func(entry *SidecarAuthorityEntry) {
		entry.Effects = []*SidecarAuthorityEffect{{Type: bridge.SignedType_SIGNED_SIDECAR_REVOKE, Body: proposal.GetStatement()}}
	})
	<-effects.done
	calls, positions := effects.snapshot()
	if len(calls) != 2 || calls[0] != "commit" || positions[0] != completing.Pin.GetVersion() {
		t.Errorf("the effects at the completing cosign: %v at %v", calls, positions)
	}
}

// TestTargetCannotRevokeBackWhileSuspended: the suspended target, as caller, previews and signs nothing against the
// device that proposed its revocation, a plan it previewed before the Suspend included.
func TestTargetCannotRevokeBackWhileSuspended(t *testing.T) {
	world := newRevokeTestWorld(t)
	ctx := context.Background()
	plan, err := world.sidecar.PreviewDeviceRevoke(ctx, world.otherId, DeviceRevokeLost, time.Time{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	// the other device's Suspend of this one applies
	world.authority.edit(func() { world.authority.suspended[world.selfId] = true })
	world.apply(nil)
	if _, err := world.sidecar.RevokeDevicePlan(ctx, plan.PlanId, nil, SidecarActConfirmed, nil); revokeCode(err) != DeviceRevokeCodeNotCapable {
		t.Errorf("a suspended device signing an earlier plan: %v", err)
	}
	if _, err := world.sidecar.PreviewDeviceRevoke(ctx, world.otherId, DeviceRevokeCompromise, time.Time{}, world.n-1); revokeCode(err) != DeviceRevokeCodeNotCapable {
		t.Errorf("a suspended device previewing: %v", err)
	}
	if posts := world.deltaApi.postsSoFar(); len(posts) != 0 {
		t.Errorf("a suspended device posted %d statements", len(posts))
	}
}

// §18.5's alarm answers that revoke a named device run through RevokeDevice with the since_n the alarm fixes: the
// admission alarm's revoke answer signs a compromise revocation of the admitted device from the alarm's entry, and
// PreviewApprovalRevoke shows its plan first.
func TestAlarmRevokeAnswerRunsRevokeDevice(t *testing.T) {
	world := newRevokeTestWorld(t)
	ctx := context.Background()
	byAdmin := NewId()
	world.admit(byAdmin, world.memberId, world.n+1)
	world.editRow(byAdmin, func(row *bridge.SidecarRow) { row.IdentityPublicKey = bytes.Repeat([]byte{7}, 32) })
	alarmed := world.apply(func(entry *SidecarAuthorityEntry) {
		entry.Effects = []*SidecarAuthorityEffect{alarmTestAdmit(t, byAdmin, world.memberId, alarmTestSigner(NewId()))}
	})
	world.apply(nil)
	items, err := world.sidecar.PendingApprovals()
	if err != nil {
		t.Fatal(err)
	}
	var item *SidecarApprovalItem
	for _, pending := range items {
		if pending.Kind == SidecarApprovalAdmissionAlarm && pending.SidecarId != nil && *pending.SidecarId == byAdmin {
			item = pending
		}
	}
	if item == nil {
		t.Fatalf("no admission alarm among %+v", items)
	}
	plan, err := world.sidecar.PreviewApprovalRevoke(item.ApprovalId)
	if err != nil || plan.SidecarId != byAdmin || plan.Reason != DeviceRevokeCompromise || plan.SinceN != alarmed.Pin.GetVersion() {
		t.Fatalf("the alarm's plan: %+v, %v", plan, err)
	}
	for _, origin := range []SidecarActOrigin{SidecarActMcp, SidecarActHook, SidecarActUnconfirmed} {
		if err := world.sidecar.DecideApproval(ctx, item.ApprovalId, SidecarDecisionRevoke, origin, nil); !errors.Is(err, ErrSidecarActMode) {
			t.Errorf("origin %d: %v", origin, err)
		}
	}
	if err := world.sidecar.DecideApproval(ctx, item.ApprovalId, SidecarDecisionRevoke, SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	posts := world.posted(t)
	revoke := &bridge.SidecarRevoke{}
	if len(posts) != 1 || bridge.SignedType(posts[0].GetType()) != bridge.SignedType_SIGNED_SIDECAR_REVOKE {
		t.Fatalf("posted %d statements", len(posts))
	}
	postedBody(t, posts[0], revoke)
	if !bytes.Equal(revoke.GetSidecarId(), byAdmin.Bytes()) || revoke.GetReason() != bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE ||
		revoke.GetSinceN() != alarmed.Pin.GetVersion() {
		t.Errorf("the alarm's revocation: %+v", revoke)
	}
}
