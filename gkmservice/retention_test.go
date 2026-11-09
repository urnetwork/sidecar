package gkmservice

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Runs a whole sweep pass, page by page.
func (self *gkmReconcilerWorld) sweep() {
	self.t.Helper()
	cursor := &GkmSweepCursor{}
	for i := 0; ; i += 1 {
		next, done, err := self.reconciler.SweepPage(self.fixture.ctx, cursor)
		if err != nil {
			self.t.Fatal(err)
		}
		if done {
			return
		}
		if 10000 < i {
			self.t.Fatal("a sweep pass that never ends")
		}
		cursor = next
	}
}

// Writes epoch/<n> of the group, carrying a sealed GroupInfo, as a commit would have.
func (self *gkmReconcilerWorld) putEpoch(epoch uint64) {
	self.t.Helper()
	self.fixture.put("meta-2", GkmEpochKey(self.groupId, epoch), self.fixture.marshal(&protocol.GkmEpochObject{
		Header:              &protocol.GkmCommitHeader{Generation: 1, Auth: fakeGkmPin(1)},
		SealedGroupInfo:     []byte("a sealed GroupInfo"),
		GroupInfoGeneration: 1,
	}))
}

// Writes a leaf's ack straight into {gka_}, at, with since set when absent, as the ack route would.
func (self *gkmReconcilerWorld) putAck(leafId sidecar.Id, epoch uint64, at time.Time) {
	self.t.Helper()
	redis := self.fixture.host.Redis
	key := GkmAckRedisKey(self.groupId)
	fieldValues := map[string][]byte{sidecar.EvsKeyId(leafId): gkmAckValue(epoch, at)}
	if _, found, err := redis.HashGet(self.fixture.ctx, key, gkmAckSinceField); err != nil {
		self.t.Fatal(err)
	} else if !found {
		fieldValues[gkmAckSinceField] = []byte(strconv.FormatInt(at.UnixMilli(), 10))
	}
	if err := redis.HashSet(self.fixture.ctx, key, fieldValues); err != nil {
		self.t.Fatal(err)
	}
	if _, err := redis.Expire(self.fixture.ctx, key, 31*24*time.Hour); err != nil {
		self.t.Fatal(err)
	}
}

// The group's epochs that stand.
func (self *gkmReconcilerWorld) standingEpochs(through uint64) []uint64 {
	standing := []uint64{}
	for epoch := uint64(0); epoch <= through; epoch += 1 {
		if self.fixture.object("meta-2", GkmEpochKey(self.groupId, epoch)) != nil {
			standing = append(standing, epoch)
		}
	}
	return standing
}

// §22.5's retention by acks (Q-KEYS-11): an epoch goes once 30 days old and every ack of the last 30 days has passed
// it, never the newest; the pointer moves to the newest epoch carrying a GroupInfo before its own epoch goes.
func TestGkmRetentionDeletesEpochsByAcks(t *testing.T) {
	world := newGkmReconcilerWorld(t)
	fixture := world.fixture
	world.key1 = world.putGeneration(nil, fakeGkmPin(1))
	for epoch := uint64(0); epoch <= 5; epoch += 1 {
		world.putEpoch(epoch)
	}
	fixture.put("meta-2", GkmGroupInfoKey(world.groupId), fixture.marshal(&protocol.GkmGroupInfoObject{Epoch: 1}))
	world.putAck(testId("sc-leaf-z"), 1, fixture.clock.Now())
	// past 30 days, inside the family's 31 day life
	fixture.clock.Advance(30*24*time.Hour + time.Hour)
	world.putAck(testId("sc-leaf-x"), 3, fixture.clock.Now())
	world.putAck(testId("sc-leaf-y"), 4, fixture.clock.Now())
	world.sweep()
	if standing := world.standingEpochs(5); !slicesEqual(standing, []uint64{4, 5}) {
		t.Errorf("epochs after retention: %v", standing)
	}
	pointer, err := parseGkmGroupInfoObject(fixture.object("meta-2", GkmGroupInfoKey(world.groupId)))
	if err != nil || pointer.GetEpoch() != 5 {
		t.Errorf("the pointer was not moved to the newest epoch before its own went: %v", err)
	}
}

// Whether two lists hold the same numbers in order.
func slicesEqual(a []uint64, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// D-KEYS-20: once every ack has expired, every epoch but the newest goes, and a device returning after 30 days
// commits the next epoch onto the newest.
func TestGkmRetentionKeepsTheNewestEpochForAReturningDevice(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	for i := 0; i < 3; i += 1 {
		world.commitAndAdopt(1, false)
	}
	ackPath := "/gkm/groups/" + sidecar.EvsKeyId(world.groupId) + "/ack"
	if recorder := fixture.serve(http.MethodPost, ackPath, world.adminToken, fixture.marshal(&protocol.GkmAckRequest{Epoch: 3})); recorder.Code != http.StatusOK {
		t.Fatalf("an ack: %d", recorder.Code)
	}
	// every ack older than 30 days, the family still inside its 31 day life
	fixture.clock.Advance(30*24*time.Hour + time.Hour)
	state := newFakeGkmReconcilerState()
	reconciler, err := NewGkmReconciler(fixture.ctx, fixture.host.ServiceHost(), DefaultGkmReconcilerSettings(), &GkmReconcilerDeps{State: state})
	if err != nil {
		t.Fatal(err)
	}
	defer reconciler.Close()
	sweeper := &gkmReconcilerWorld{t: t, fixture: fixture, reconciler: reconciler, groupId: world.groupId}
	sweeper.sweep()
	if standing := sweeper.standingEpochs(3); !slicesEqual(standing, []uint64{3}) {
		t.Fatalf("epochs once every ack expired: %v", standing)
	}
	world.adminToken = fixture.token(world.admin.sidecarId, repoScope(world.repoId, "admin"))
	world.commitAndAdopt(1, false)
	if world.storedEpoch(4) == nil {
		t.Errorf("the returning device's commit onto the newest epoch")
	}
}

// §10.6: a lost ack family deletes nothing for 30 days, since retention reads acks only from a family that has
// existed that long.
func TestGkmRetentionLostAckFamilyDeletesNothingFor30Days(t *testing.T) {
	world := newGkmReconcilerWorld(t)
	fixture := world.fixture
	world.key1 = world.putGeneration(nil, fakeGkmPin(1))
	for epoch := uint64(0); epoch <= 3; epoch += 1 {
		world.putEpoch(epoch)
	}
	fixture.clock.Advance(31 * 24 * time.Hour)
	world.sweep()
	if standing := world.standingEpochs(3); len(standing) != 4 {
		t.Fatalf("epochs with no ack family: %v", standing)
	}
	world.putAck(testId("sc-leaf-x"), 3, fixture.clock.Now())
	fixture.clock.Advance(29 * 24 * time.Hour)
	world.sweep()
	if standing := world.standingEpochs(3); len(standing) != 4 {
		t.Fatalf("epochs with a family 29 days old: %v", standing)
	}
	fixture.clock.Advance(24 * time.Hour)
	world.putAck(testId("sc-leaf-x"), 3, fixture.clock.Now())
	world.sweep()
	if standing := world.standingEpochs(3); !slicesEqual(standing, []uint64{3}) {
		t.Errorf("epochs with a family 30 days old: %v", standing)
	}
}

// The objects a sweep's TTLs judge, each put at the clock's time.
type gkmTtlWorld struct {
	*gkmReconcilerWorld
	key2         *sidecar.EvsRepoKey
	leaf         sidecar.Id
	revoked      sidecar.Id
	recipient    sidecar.Id
	ref          []byte
	staleWrapKey string
	oldKeyWrap   string
	newKeyWrap   string
	g1WrapKey    string
	staleRecover string
	welcomeKey   string
	pointerKey   string
	kpKey        string
	kpClaimKey   string
	revokedKpKey string
	readerKeyKey string
}

// A delivery key of the group under generation, c8 and recipient, k8 from fill.
func (self *gkmReconcilerWorld) wrapKey(generation uint64, c8 string, recipient sidecar.Id, fill byte) string {
	return GkmWrapRecipientPrefix(self.groupId, generation, c8, "s:"+sidecar.EvsKeyId(recipient)) + hex.EncodeToString(bytes.Repeat([]byte{fill}, 8))
}

// §2.8's TTLs on a fake clock: a lost claim's staged deliveries and recovery wraps at 24 h, a generation's deliveries
// once the next generation exists, a delivery to an older key 30 days after one to a newer key, KeyPackages and
// claims at 90 days and a revoked sidecar's KeyPackages at once, a ReaderKey past its not_after, and Welcomes at 90
// days with a pointer gone at its recipient's ack.
func TestGkmSweepHonorsEachTtl(t *testing.T) {
	world := newGkmReconcilerWorld(t)
	fixture := world.fixture
	leaf, revoked, recipient := testId("sc-leaf"), testId("sc-revoked"), testId("sc-recipient")
	for _, sidecarId := range []sidecar.Id{leaf, revoked, recipient} {
		world.state.sidecarNetworks[sidecarId] = world.networkId
	}
	world.state.revokedIds[revoked] = true
	world.key1 = world.putGeneration(nil, fakeGkmPin(1))
	key2 := world.putGeneration(world.key1, fakeGkmPin(1))
	c8 := gkmTestC8(key2)
	start := fixture.clock.Now()

	// deliveries
	g1WrapKey := world.wrapKey(1, gkmTestC8(world.key1), recipient, 1)
	staleWrapKey := world.wrapKey(2, "00000000000000ff", recipient, 1)
	oldKeyWrap := world.wrapKey(2, c8, recipient, 1)
	staleRecovery := GkmRecoveryWrapKey(world.memberId, world.groupId, 2, "00000000000000ff", "00000000000000b1")
	for _, key := range []string{g1WrapKey, staleWrapKey, oldKeyWrap} {
		fixture.put("meta-2", key, []byte("a delivery"))
	}
	fixture.put("meta-2", staleRecovery, gkmTestRecoveryCiphertext(1))
	// a Welcome and its pointer, and the recipient's ack past it
	welcomeKey := GkmWelcomeKey(world.groupId, 1)
	fixture.put("meta-2", welcomeKey, []byte("a Welcome"))
	ref := bytes.Repeat([]byte{0xcd}, gkmKeyPackageRefByteCount)
	pointerKey, _ := GkmWelcomePointerKey(recipient, ref)
	fixture.put("meta-1", pointerKey, fixture.marshal(&protocol.GkmWelcomePointer{GroupId: world.groupId.Bytes(), Epoch: 1}))
	// KeyPackages and a claim
	kpKey, _ := GkmKeyPackageKey(leaf, bytes.Repeat([]byte{0x11}, gkmKeyPackageRefByteCount))
	kpClaimKey, _ := GkmKeyPackageClaimKey(leaf, bytes.Repeat([]byte{0x22}, gkmKeyPackageRefByteCount))
	revokedKpKey, _ := GkmKeyPackageKey(revoked, bytes.Repeat([]byte{0x33}, gkmKeyPackageRefByteCount))
	for _, key := range []string{kpKey, kpClaimKey, revokedKpKey} {
		fixture.put("meta-1", key, []byte("a KeyPackage or claim"))
	}
	// a ReaderKey lapsing in 7 days
	readerKeyKey := GkmReaderKeyKey(leaf)
	readerKeyBody := fixture.marshal(&protocol.ReaderKey{SidecarId: leaf.Bytes(), XwingPublicKey: bytes.Repeat([]byte{1}, 1216), NotAfter: start.Add(7 * 24 * time.Hour).UnixMilli()})
	fixture.put("meta-1", readerKeyKey, fixture.marshal(&bridge.Signed{Body: readerKeyBody, Type: uint32(bridge.SignedType_SIGNED_READER_KEY)}))

	fixture.clock.Advance(23 * time.Hour)
	newKeyWrap := world.wrapKey(2, c8, recipient, 2)
	fixture.put("meta-2", newKeyWrap, []byte("a delivery to a newer key"))
	world.sweep()
	stands := func(clusterId string, key string) bool {
		return fixture.object(clusterId, key) != nil
	}
	if stands("meta-2", g1WrapKey) {
		t.Errorf("generation 1's delivery outlived gen/2")
	}
	if !stands("meta-2", staleWrapKey) || !stands("meta-2", staleRecovery) {
		t.Errorf("a lost claim's staged objects went before 24 h")
	}
	if stands("meta-1", revokedKpKey) {
		t.Errorf("a revoked sidecar's KeyPackage stayed")
	}

	fixture.clock.Advance(time.Hour)
	world.sweep()
	if stands("meta-2", staleWrapKey) || stands("meta-2", staleRecovery) {
		t.Errorf("a lost claim's staged objects stayed past 24 h")
	}
	if !stands("meta-2", oldKeyWrap) || !stands("meta-2", newKeyWrap) {
		t.Errorf("a current generation's deliveries went early")
	}

	world.putAck(recipient, 1, fixture.clock.Now())
	fixture.clock.Advance(7 * 24 * time.Hour)
	world.sweep()
	if stands("meta-1", pointerKey) {
		t.Errorf("a Welcome pointer stayed past its recipient's ack")
	}
	if stands("meta-1", readerKeyKey) {
		t.Errorf("a ReaderKey stayed past its not_after")
	}
	if !stands("meta-2", welcomeKey) || !stands("meta-1", kpKey) || !stands("meta-1", kpClaimKey) {
		t.Errorf("an object went before its 90 days")
	}

	fixture.clock.Advance(30 * 24 * time.Hour)
	world.sweep()
	if stands("meta-2", oldKeyWrap) || !stands("meta-2", newKeyWrap) {
		t.Errorf("a delivery to an older key 30 days after one to a newer key")
	}

	fixture.clock.Advance(60 * 24 * time.Hour)
	world.sweep()
	if stands("meta-2", welcomeKey) || stands("meta-1", kpKey) || stands("meta-1", kpClaimKey) {
		t.Errorf("a Welcome, KeyPackage or claim stayed past 90 days")
	}
}

// A preservation hold pauses every sweep in its scope, and no hold pauses ShredGroup (owner decision 133).
func TestGkmHoldPausesEverySweepButNotShredGroup(t *testing.T) {
	world := newGkmReconcilerWorld(t)
	fixture := world.fixture
	leaf := testId("sc-leaf")
	world.state.sidecarNetworks[leaf] = world.networkId
	world.key1 = world.putGeneration(nil, fakeGkmPin(1))
	for epoch := uint64(0); epoch <= 3; epoch += 1 {
		world.putEpoch(epoch)
	}
	staleWrapKey := world.wrapKey(1, "00000000000000ff", leaf, 1)
	fixture.put("meta-2", staleWrapKey, []byte("a lost claim's delivery"))
	kpKey, _ := GkmKeyPackageKey(leaf, bytes.Repeat([]byte{0x11}, gkmKeyPackageRefByteCount))
	fixture.put("meta-1", kpKey, []byte("a KeyPackage"))
	recoveryKey := GkmRecoveryWrapKey(world.memberId, world.groupId, 1, gkmTestC8(world.key1), "00000000000000b1")
	fixture.put("meta-1", recoveryKey, gkmTestRecoveryCiphertext(1))
	world.putAck(leaf, 3, fixture.clock.Now())
	caseId := testId("case-1")
	holdBytes, err := sidecar.EncodeHoldRecord(&sidecar.HoldRecord{
		NetworkId:  world.networkId,
		CaseId:     caseId,
		Kind:       sidecar.HoldKindPreserve2703f,
		Scope:      sidecar.HoldScopeNetwork(),
		PlaceTime:  fixture.clock.Now(),
		ExpireTime: fixture.clock.Now().Add(365 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.put("meta-1", sidecar.HoldObjectKey(world.networkId, caseId), holdBytes)
	fixture.clock.Advance(91 * 24 * time.Hour)
	world.putAck(leaf, 3, fixture.clock.Now())
	world.sweep()
	if len(world.standingEpochs(3)) != 4 || fixture.object("meta-2", staleWrapKey) == nil || fixture.object("meta-1", kpKey) == nil {
		t.Fatalf("a sweep deleted under a hold")
	}
	if err := ShredGroup(fixture.ctx, fixture.host.ServiceHost(), fixture.cluster("meta-2"), world.repoId, true, fixture.settings); err != nil {
		t.Fatal(err)
	}
	if len(world.standingEpochs(3)) != 0 || fixture.object("meta-2", staleWrapKey) != nil || fixture.object("meta-1", recoveryKey) != nil {
		t.Errorf("ShredGroup kept the group's objects under a hold")
	}
}

// ShredGroup deletes the group's objects, its recovery wraps on every cluster and {gka_}; a straggler a write in
// flight lands after it is deleted by the repeat, which then deletes the forms, and a third run is harmless.
func TestGkmShredGroupDeletesTheGroupAndIsSafeToRepeat(t *testing.T) {
	world := newGkmReconcilerWorld(t)
	fixture := world.fixture
	world.key1 = world.putGeneration(nil, fakeGkmPin(1))
	world.putEpoch(0)
	world.putEpoch(1)
	recoveryKeys := []string{
		GkmRecoveryWrapKey(world.memberId, world.groupId, 1, gkmTestC8(world.key1), "00000000000000b1"),
		GkmRecoveryWrapKey(testId("member-b"), world.groupId, 1, gkmTestC8(world.key1), "00000000000000b2"),
	}
	otherGroupRecovery := GkmRecoveryWrapKey(world.memberId, testId("group-other"), 1, gkmTestC8(world.key1), "00000000000000b1")
	fixture.put("meta-1", recoveryKeys[0], gkmTestRecoveryCiphertext(1))
	fixture.put("meta-2", recoveryKeys[1], gkmTestRecoveryCiphertext(2))
	fixture.put("meta-1", otherGroupRecovery, gkmTestRecoveryCiphertext(3))
	world.putAck(testId("sc-leaf"), 1, fixture.clock.Now())
	shred := func(final bool) {
		if err := ShredGroup(fixture.ctx, fixture.host.ServiceHost(), fixture.cluster("meta-2"), world.repoId, final, fixture.settings); err != nil {
			t.Fatal(err)
		}
	}
	shred(false)
	if fixture.object("meta-2", GkmGenerationKey(world.groupId, 1)) != nil || len(world.standingEpochs(1)) != 0 ||
		fixture.object("meta-1", recoveryKeys[0]) != nil || fixture.object("meta-2", recoveryKeys[1]) != nil {
		t.Errorf("step 3 left the group's objects")
	}
	if fixture.object("meta-1", otherGroupRecovery) == nil {
		t.Errorf("step 3 deleted another group's recovery wrap")
	}
	if fieldValues, _ := fixture.host.Redis.HashGetAll(fixture.ctx, GkmAckRedisKey(world.groupId)); len(fieldValues) != 0 {
		t.Errorf("step 3 left {gka_}")
	}
	if fixture.object("meta-2", GkmFormKey(world.repoId, 1)) == nil {
		t.Fatalf("step 3 deleted the forms the repeat reads")
	}
	// a commit in flight at step 3 lands after it
	world.putEpoch(2)
	fixture.clock.Advance(10 * time.Minute)
	shred(true)
	if len(world.standingEpochs(2)) != 0 || fixture.object("meta-2", GkmFormKey(world.repoId, 1)) != nil {
		t.Errorf("step 6 left a straggler or the forms")
	}
	shred(true)
}
