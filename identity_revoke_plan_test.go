package sidecar

// CORE-M3-02: PlanId's vectors, byte-equal on every leg; FS-98's refusal rows, each signing nothing; Presence set
// from the log; and what a plan lists: the cascade, the confirmations P's sidecars gave, and the target's keys the
// cascade does not void.
//
//	SIDECAR_REGENERATE_REVOKE_PLAN_VECTORS=1 go test -run '^TestRevokePlanIdVectors$' .
//
// writes the vectors while the file holds none, and never changes one already there.

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One vector of testdata/revoke_plan/vectors.json.
type revokePlanVector struct {
	SidecarId      string   `json:"sidecar_id"`
	RevokedAt      uint64   `json:"revoked_at"`
	StandingSinceN uint64   `json:"standing_since_n"`
	Reason         uint32   `json:"reason"`
	SinceN         uint64   `json:"since_n"`
	Signatures     int      `json:"signatures"`
	Presence       bool     `json:"presence"`
	KeyIds         []string `json:"key_ids"`
	PlanId         string   `json:"plan_id"`
}

const revokePlanVectorsPath = "testdata/revoke_plan/vectors.json"

//go:embed testdata/revoke_plan/vectors.json
var revokePlanVectorsJson []byte

// The fields a vector names.
func (self *revokePlanVector) fields(t *testing.T) *deviceRevokePlanIdFields {
	t.Helper()
	sidecarIdBytes, err := hex.DecodeString(self.SidecarId)
	if err != nil {
		t.Fatal(err)
	}
	sidecarId, err := IdFromBytes(sidecarIdBytes)
	if err != nil {
		t.Fatal(err)
	}
	fields := &deviceRevokePlanIdFields{
		sidecarId:      sidecarId,
		revokedAt:      self.RevokedAt,
		standingSinceN: self.StandingSinceN,
		reason:         bridge.SidecarRevokeReason(self.Reason),
		sinceN:         self.SinceN,
		signatures:     self.Signatures,
		presence:       self.Presence,
	}
	for _, keyIdHex := range self.KeyIds {
		keyId, err := hex.DecodeString(keyIdHex)
		if err != nil {
			t.Fatal(err)
		}
		fields.keyIds = append(fields.keyIds, keyId)
	}
	return fields
}

// PlanId's canonical encoding, pinned: every leg computes the vectors' ids, a key list in any order gives one id, and
// each field moves it.
func TestRevokePlanIdVectors(t *testing.T) {
	sidecarIdHex := hex.EncodeToString(countingBytes(0x21, 16))
	keyA, keyB := hex.EncodeToString(countingBytes(0x40, 32)), hex.EncodeToString(countingBytes(0x80, 20))
	inputs := []revokePlanVector{
		{SidecarId: sidecarIdHex, Reason: 1, Signatures: 1},
		{SidecarId: sidecarIdHex, Reason: 1, Signatures: 1, Presence: true, KeyIds: []string{keyA, keyB}},
		{SidecarId: sidecarIdHex, Reason: 4, SinceN: 1042, Signatures: 1},
		{SidecarId: sidecarIdHex, Reason: 4, SinceN: 1042, Signatures: 2, Presence: true, KeyIds: []string{keyB}},
		{SidecarId: sidecarIdHex, RevokedAt: 2000, Reason: 1, Signatures: 1, Presence: true, KeyIds: []string{keyA}},
		{SidecarId: sidecarIdHex, RevokedAt: 2000, StandingSinceN: 1500, Reason: 4, SinceN: 1042, Signatures: 1},
	}
	encoded := revokePlanVectorsJson
	if len(bytes.TrimSpace(encoded)) <= len("[]") && os.Getenv("SIDECAR_REGENERATE_REVOKE_PLAN_VECTORS") == "1" {
		for index := range inputs {
			planId := deviceRevokePlanId(inputs[index].fields(t))
			inputs[index].PlanId = hex.EncodeToString(planId.Bytes())
		}
		generated, err := json.MarshalIndent(inputs, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(generated, '\n')
		if err := os.WriteFile(revokePlanVectorsPath, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	vectors := []revokePlanVector{}
	if err := json.Unmarshal(encoded, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != len(inputs) {
		t.Fatalf("%d vectors", len(vectors))
	}
	seen := map[string]bool{}
	for index, vector := range vectors {
		planId := deviceRevokePlanId(vector.fields(t))
		if hex.EncodeToString(planId.Bytes()) != vector.PlanId {
			t.Errorf("vector %d: computed %x", index, planId.Bytes())
		}
		if seen[vector.PlanId] {
			t.Errorf("vector %d repeats a plan id", index)
		}
		seen[vector.PlanId] = true
	}
	// the key items' order is no part of the id
	fields := vectors[1].fields(t)
	fields.keyIds[0], fields.keyIds[1] = fields.keyIds[1], fields.keyIds[0]
	if planId := deviceRevokePlanId(fields); hex.EncodeToString(planId.Bytes()) != vectors[1].PlanId {
		t.Error("the key items' order moves the plan id")
	}
}

// The refusal's code, "" for no DeviceRevokeError.
func revokeCode(err error) string {
	var revokeError *DeviceRevokeError
	if errors.As(err, &revokeError) {
		return revokeError.Code
	}
	return ""
}

// FS-98's refusal rows of the preview, each signing nothing: this sidecar; another member's device, a tagged agent the
// member sponsors and an unknown id; a read_only page Worker, a quick burner, an unconsented and a suspended device
// as caller; and Locked or Unenrolled.
func TestPreviewDeviceRevokeRefusals(t *testing.T) {
	world := newRevokeTestWorld(t)
	ctx := context.Background()
	preview := func(sidecarId Id) string {
		_, err := world.sidecar.PreviewDeviceRevoke(ctx, sidecarId, DeviceRevokeLost, time.Time{}, 0)
		if err == nil {
			return "ok"
		}
		return revokeCode(err)
	}
	if code := preview(world.otherId); code != "ok" {
		t.Fatalf("a member's other device: %s", code)
	}
	if code := preview(world.selfId); code != DeviceRevokeCodeSelf {
		t.Errorf("this sidecar: %s", code)
	}
	foreignId, agentId := NewId(), NewId()
	world.admit(foreignId, NewId(), 20)
	world.authority.edit(func() {
		world.authority.sidecars[agentId] = &AclSidecar{Row: &bridge.SidecarRow{SidecarId: agentId.Bytes(), Sponsor: world.memberId.Bytes()}, TagIds: []Id{NewId()}}
	})
	for name, sidecarId := range map[string]Id{"another member's device": foreignId, "a tagged agent": agentId, "an unknown id": NewId()} {
		if code := preview(sidecarId); code != DeviceRevokeCodeNotOwn {
			t.Errorf("%s: %s", name, code)
		}
	}
	if _, err := world.sidecar.PreviewDeviceRevoke(ctx, world.otherId, "removed", time.Time{}, 0); !errors.Is(err, ErrSidecarRevokeReason) {
		t.Errorf("a reason that is no member's: %v", err)
	}

	// the caller
	world.editRow(world.selfId, func(row *bridge.SidecarRow) {
		row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	})
	if code := preview(world.otherId); code != DeviceRevokeCodeNotCapable {
		t.Errorf("a read_only page Worker as caller: %s", code)
	}
	world.editRow(world.selfId, func(row *bridge.SidecarRow) { row.Capabilities = 0 })
	world.authority.edit(func() { world.authority.sidecars[world.selfId].Ephemeral = true })
	if code := preview(world.otherId); code != DeviceRevokeCodeNotCapable {
		t.Errorf("a quick burner as caller: %s", code)
	}
	world.authority.edit(func() {
		world.authority.sidecars[world.selfId].Ephemeral = false
		world.authority.consents[[2]Id{world.selfId, world.memberId}] = false
	})
	if code := preview(world.otherId); code != DeviceRevokeCodeNotCapable {
		t.Errorf("an unconsented caller: %s", code)
	}
	world.authority.edit(func() {
		world.authority.consents[[2]Id{world.selfId, world.memberId}] = true
		world.authority.suspended[world.selfId] = true
	})
	if code := preview(world.otherId); code != DeviceRevokeCodeNotCapable {
		t.Errorf("a suspended caller: %s", code)
	}
	world.authority.edit(func() { world.authority.suspended[world.selfId] = false })
	if code := preview(world.otherId); code != "ok" {
		t.Fatalf("the caller restored: %s", code)
	}

	// an authority that cannot say whether this device is approval-capable revokes nothing
	t.Cleanup(world.sidecar.InstallAuthority(world.authority.testActAuthority))
	if code := preview(world.otherId); code != DeviceRevokeCodeNotCapable {
		t.Errorf("an authority with no revoke answers: %s", code)
	}
	world.sidecar.applyTransition(sidecarTransition{to: SidecarStateUnenrolled, generation: 1})
	if _, err := world.sidecar.PreviewDeviceRevoke(ctx, world.otherId, DeviceRevokeLost, time.Time{}, 0); !errors.Is(err, ErrSidecarDevicesPrecondition) {
		t.Errorf("unenrolled: %v", err)
	}
	if posts := world.deltaApi.postsSoFar(); len(posts) != 0 {
		t.Errorf("%d statements posted by previews", len(posts))
	}
}

// since_n: the first entry timed at or after the loss time, which a person moves earlier and never later, never past
// the tip, and never from a loss time in the future (REVOKE_SINCE); lost ignores both.
func TestPreviewSinceComesFromTheLossTime(t *testing.T) {
	world := newRevokeTestWorld(t)
	ctx := context.Background()
	world.apply(nil)
	lostAt := world.clock.Now().Add(10 * time.Second)
	lostEntry := world.apply(nil)
	world.apply(nil)
	proposed := lostEntry.Pin.GetVersion()

	plan, err := world.sidecar.PreviewDeviceRevoke(ctx, world.otherId, DeviceRevokeCompromise, lostAt, 0)
	if err != nil {
		t.Fatal(err)
	}
	if plan.SinceN != proposed || !plan.SinceTime.Equal(time.UnixMilli(lostEntry.TimeMs)) || plan.Reason != DeviceRevokeCompromise {
		t.Fatalf("the proposed since: %+v, want %d", plan, proposed)
	}
	earlier, err := world.sidecar.PreviewDeviceRevoke(ctx, world.otherId, DeviceRevokeCompromise, lostAt, proposed-1)
	if err != nil || earlier.SinceN != proposed-1 || earlier.PlanId == plan.PlanId {
		t.Fatalf("a since moved earlier: %+v, %v", earlier, err)
	}
	for name, sinceN := range map[string]uint64{"later than proposed": proposed + 1, "past the tip": world.n + 1} {
		if _, err := world.sidecar.PreviewDeviceRevoke(ctx, world.otherId, DeviceRevokeCompromise, lostAt, sinceN); revokeCode(err) != DeviceRevokeCodeSince {
			t.Errorf("a since %s: %v", name, err)
		}
	}
	if _, err := world.sidecar.PreviewDeviceRevoke(ctx, world.otherId, DeviceRevokeCompromise, world.clock.Now().Add(time.Hour), 0); revokeCode(err) != DeviceRevokeCodeSince {
		t.Errorf("a loss time in the future: %v", err)
	}
	if _, err := world.sidecar.PreviewDeviceRevoke(ctx, world.otherId, DeviceRevokeCompromise, time.Time{}, 0); revokeCode(err) != DeviceRevokeCodeSince {
		t.Errorf("no loss time and no position: %v", err)
	}
	// a position alone, as an alarm fixes one, stands when it is not past the tip
	if fixed, err := world.sidecar.PreviewDeviceRevoke(ctx, world.otherId, DeviceRevokeCompromise, time.Time{}, proposed); err != nil || fixed.PlanId != plan.PlanId {
		t.Errorf("a position alone: %+v, %v", fixed, err)
	}

	// lost ignores lostAt and sinceN
	lost, err := world.sidecar.PreviewDeviceRevoke(ctx, world.otherId, DeviceRevokeLost, time.Time{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	ignoring, err := world.sidecar.PreviewDeviceRevoke(ctx, world.otherId, DeviceRevokeLost, world.clock.Now().Add(time.Hour), world.n+99)
	if err != nil || ignoring.PlanId != lost.PlanId || ignoring.SinceN != 0 || !ignoring.SinceTime.IsZero() {
		t.Errorf("lost read its loss time or since: %+v, %v", ignoring, err)
	}
}

// A compromise plan lists §7.9's cascade as the authority derives it, each confirmation a sidecar of P gave from the
// position P held it, and each key the target registered that the cascade does not void; REVOKE_PARKS_SELF names the
// entry that puts this sidecar in P, while the target's OwnerConfirm of the already consented caller parks nothing.
func TestCompromisePlanListsCascadeConfirmationsAndKeys(t *testing.T) {
	world := newRevokeTestWorld(t)
	ctx := context.Background()
	sinceN := world.n - 5
	parkedId := NewId()
	world.admit(parkedId, world.memberId, sinceN+1)
	voidedKeyId, keptKeyId, sshKeyId := countingBytes(0x40, 32), countingBytes(0x60, 32), countingBytes(0x70, 32)
	bindingSha256 := countingBytes(0x90, 32)
	cascade := []DeviceRevokeItem{
		{Effect: DeviceRevokeEffectPark, Kind: DeviceRevokeKindDevice, Id: parkedId.Bytes(), Position: sinceN + 1},
		{Effect: DeviceRevokeEffectVoid, Kind: "recovery_binding", Id: bindingSha256, Position: sinceN + 2},
		{Effect: DeviceRevokeEffectVoid, Kind: DeviceRevokeKindKey, Id: voidedKeyId, Position: sinceN + 3},
		{Effect: DeviceRevokeEffectStands, Kind: "suspension", Id: NewId().Bytes(), Position: sinceN + 4},
		{Effect: DeviceRevokeEffectReseal, Kind: DeviceRevokeKindDevice, Id: world.selfId.Bytes()},
	}
	world.authority.edit(func() {
		world.authority.cascades[revokeTestCascadeKey{targetId: world.otherId, sinceN: sinceN}] = cascade
		world.authority.keys[world.otherId] = []*bridge.KeyRow{
			{KeyId: voidedKeyId, Purpose: bridge.KeyPurpose_KEY_PURPOSE_PRESENCE, Signer: world.otherId.Bytes(), At: sinceN + 3},
			{KeyId: keptKeyId, Purpose: bridge.KeyPurpose_KEY_PURPOSE_PRESENCE, Signer: world.otherId.Bytes(), At: 8},
			{KeyId: sshKeyId, Purpose: bridge.KeyPurpose_KEY_PURPOSE_SSHSIG, Signer: world.otherId.Bytes(), At: 9},
		}
	})
	// the target's OwnerConfirm of this, already consented, device after since_n, and its AdmissionConfirm that
	// lifted the parked device's park: rows keep both, with their positions
	world.editRow(world.selfId, func(row *bridge.SidecarRow) {
		row.Confirmations = []*bridge.ConfirmationRow{
			{Kind: 2, Signer: NewId().Bytes(), At: 4},
			{Kind: 2, Signer: world.otherId.Bytes(), At: sinceN + 2},
		}
	})
	world.editRow(parkedId, func(row *bridge.SidecarRow) {
		row.Confirmations = []*bridge.ConfirmationRow{
			// before P held the target: no item
			{Kind: 1, Signer: world.otherId.Bytes(), At: sinceN - 1},
			{Kind: 1, Signer: world.otherId.Bytes(), At: sinceN + 3, LiftedPark: true},
		}
	})

	plan, err := world.sidecar.PreviewDeviceRevoke(ctx, world.otherId, DeviceRevokeCompromise, time.Time{}, sinceN)
	if err != nil {
		t.Fatalf("the redundant OwnerConfirm parked the caller: %v", err)
	}
	count := func(effect string, kind string) int {
		n := 0
		for _, item := range plan.Items {
			if item.Effect == effect && item.Kind == kind {
				n += 1
			}
		}
		return n
	}
	if len(plan.Items) != len(cascade)+2+2 || count(DeviceRevokeEffectPark, DeviceRevokeKindDevice) != 1 ||
		count(DeviceRevokeEffectVoid, DeviceRevokeKindConfirmation) != 2 || count(DeviceRevokeEffectKey, DeviceRevokeKindKey) != 2 ||
		count(DeviceRevokeEffectReseal, DeviceRevokeKindDevice) != 1 {
		t.Fatalf("the plan's items: %+v", plan.Items)
	}
	for _, item := range plan.Items {
		switch {
		case item.Effect == DeviceRevokeEffectKey && bytes.Equal(item.Id, voidedKeyId):
			t.Error("a key the cascade voids is offered for KeyRevoke")
		case item.Effect == DeviceRevokeEffectKey && bytes.Equal(item.Id, sshKeyId) && (item.Name != "ssh" || item.Position != 9):
			t.Errorf("the SSH key's item: %+v", item)
		case item.Kind == DeviceRevokeKindConfirmation && bytes.Equal(item.Id, world.selfId.Bytes()) && (item.Name != "owner_confirm" || item.Position != sinceN+2):
			t.Errorf("the OwnerConfirm's item: %+v", item)
		case item.Kind == DeviceRevokeKindConfirmation && bytes.Equal(item.Id, parkedId.Bytes()) && (item.Name != "admission_confirm" || item.Position != sinceN+3):
			t.Errorf("the AdmissionConfirm's item: %+v", item)
		}
	}
	if plan.Signatures != 1 || plan.Presence || plan.SinceN != sinceN {
		t.Errorf("the plan: %+v", plan)
	}

	// the target admitted the caller, or lifted its park, after since_n: P holds this sidecar
	world.authority.edit(func() {
		world.authority.cascades[revokeTestCascadeKey{targetId: world.otherId, sinceN: sinceN}] = append(cascade,
			DeviceRevokeItem{Effect: DeviceRevokeEffectPark, Kind: DeviceRevokeKindDevice, Id: world.selfId.Bytes(), Position: sinceN + 2})
	})
	_, err = world.sidecar.PreviewDeviceRevoke(ctx, world.otherId, DeviceRevokeCompromise, time.Time{}, sinceN)
	var revokeError *DeviceRevokeError
	if !errors.As(err, &revokeError) || revokeError.Code != DeviceRevokeCodeParksSelf || revokeError.Position != sinceN+2 {
		t.Errorf("P holding the caller: %v", err)
	}
}

// Presence is set from the log's rule over what the act would sign, never by the caller: unset while this sidecar
// holds no live presence key, set once it does and the log covers the revocation.
func TestPlanDerivesPresenceFromLog(t *testing.T) {
	world := newRevokeTestWorld(t)
	ctx := context.Background()
	plan, err := world.sidecar.PreviewDeviceRevoke(ctx, world.otherId, DeviceRevokeLost, time.Time{}, 0)
	if err != nil || plan.Presence {
		t.Fatalf("with no live key: %+v, %v", plan, err)
	}
	addTestPresenceKey(t, world.authority.testActAuthority)
	// a live key alone sets nothing: the log's rule must cover the statement
	uncovered, err := world.sidecar.PreviewDeviceRevoke(ctx, world.otherId, DeviceRevokeLost, time.Time{}, 0)
	if err != nil || uncovered.Presence || uncovered.PlanId != plan.PlanId {
		t.Fatalf("a live key the log does not cover the revocation by: %+v, %v", uncovered, err)
	}
	world.authority.edit(func() { world.authority.covered[bridge.SignedType_SIGNED_SIDECAR_REVOKE] = true })
	covered, err := world.sidecar.PreviewDeviceRevoke(ctx, world.otherId, DeviceRevokeLost, time.Time{}, 0)
	if err != nil || !covered.Presence || covered.PlanId == plan.PlanId {
		t.Fatalf("a covered revocation: %+v, %v", covered, err)
	}
	// an AdminSet member's device needs k counted signatures, this one counting once
	world.authority.edit(func() { world.authority.signatures[world.otherId] = 2 })
	counted, err := world.sidecar.PreviewDeviceRevoke(ctx, world.otherId, DeviceRevokeLost, time.Time{}, 0)
	if err != nil || counted.Signatures != 2 || counted.PlanId == covered.PlanId {
		t.Fatalf("an AdminSet member's device: %+v, %v", counted, err)
	}
}

// A target already revoked answers that entry and its keys still registered; lost then signs no second revocation,
// while compromise after a lost revocation, or from an earlier since_n than a standing compromise one, signs anew.
func TestPlanOfAnAlreadyRevokedTarget(t *testing.T) {
	world := newRevokeTestWorld(t)
	identity := world.sidecar.currentIdentity()
	keyId := countingBytes(0x40, 32)
	world.authority.edit(func() {
		world.authority.keys[world.otherId] = []*bridge.KeyRow{{KeyId: keyId, Purpose: bridge.KeyPurpose_KEY_PURPOSE_PRESENCE, Signer: world.otherId.Bytes(), At: 8}}
	})
	world.editRow(world.otherId, func(row *bridge.SidecarRow) { row.RevokedAt = 30 })
	derive := func(reason string, sinceN uint64) *deviceRevokeDerivation {
		derivation, err := world.sidecar.deriveDeviceRevoke(world.authority, identity, world.otherId, reason, time.Time{}, sinceN, false)
		if err != nil {
			t.Fatal(err)
		}
		return derivation
	}
	lost := derive(DeviceRevokeLost, 0)
	stands, keys := 0, 0
	for _, item := range lost.plan.Items {
		if item.Effect == DeviceRevokeEffectStands && item.Kind == DeviceRevokeKindRevocation && item.Position == 30 {
			stands += 1
		}
		if item.Effect == DeviceRevokeEffectKey && bytes.Equal(item.Id, keyId) {
			keys += 1
		}
	}
	if lost.signsRevoke || stands != 1 || keys != 1 {
		t.Fatalf("lost on a revoked target: signs %t, items %+v", lost.signsRevoke, lost.plan.Items)
	}
	// compromise after a lost revocation signs anew
	if compromise := derive(DeviceRevokeCompromise, 20); !compromise.signsRevoke || compromise.plan.PlanId == lost.plan.PlanId {
		t.Error("compromise after a lost revocation signs nothing")
	}
	// a standing compromise revocation from 20: one from 25 adds nothing, one from 15 signs anew
	world.editRow(world.otherId, func(row *bridge.SidecarRow) {
		row.Cascades = []*bridge.CascadeSpanRow{{From: 20, Until: 30}}
	})
	if later := derive(DeviceRevokeCompromise, 25); later.signsRevoke {
		t.Error("a compromise revocation the standing one covers signs again")
	}
	if earlier := derive(DeviceRevokeCompromise, 15); !earlier.signsRevoke {
		t.Error("a compromise revocation from an earlier since_n signs nothing")
	}
}
