package gkmservice

// KEYS-M8-01 at gkm (DESIGN-DETAILS 4.2.2): a forwarding Delegation's reader key object, its upload held to the
// Delegation's own sidecar and the row's digest, each refusal beside its twin; its read by the config's readers alone;
// the wrap checks holding a DelegationWrap to the key its row names; a forwarding sidecar reading its own
// Delegations' wraps; and the reconciler's deletion of the object a day after its Delegation ended or was superseded,
// a hold keeping it.

import (
	"bytes"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A forwarding Delegation's reader key: its X-Wing public key, the key's digest and the Delegation's id.
type gkmTestForwardingKey struct {
	delegationId []byte
	publicKey    []byte
	keySha256    []byte
	privateKey   hpke.PrivateKey
}

// A fresh reader key for a Delegation named by label.
func newGkmTestForwardingKey(t *testing.T, label string) *gkmTestForwardingKey {
	t.Helper()
	privateKey, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	publicKey := privateKey.PublicKey().Bytes()
	delegationId := sha256.Sum256([]byte("forwarding delegation " + label))
	keySha256 := sha256.Sum256(publicKey)
	return &gkmTestForwardingKey{delegationId: delegationId[:], publicKey: publicKey, keySha256: keySha256[:], privateKey: privateKey}
}

// The path of a Delegation's key object at gkm's route.
func gkmTestDelegationKeyPath(delegationId []byte) string {
	return "/gkm/delegation-keys/" + hex.EncodeToString(delegationId)
}

// The object a Delegation's key is stored at on the first cluster, nil for none.
func (self *gkmFixture) delegationKeyObject(delegationId []byte) []byte {
	self.t.Helper()
	key, err := GkmDelegationKeyKey(delegationId)
	if err != nil {
		self.t.Fatal(err)
	}
	return self.object("meta-1", key)
}

// The format value holds X-Wing's public key size.
func TestGkmDelegationKeyByteCountIsXWings(t *testing.T) {
	privateKey, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if size := len(privateKey.PublicKey().Bytes()); size != gkmDelegationKeyByteCount {
		t.Errorf("an X-Wing public key is %d bytes", size)
	}
}

// PUT /gkm/delegation-keys/<delegation_id>: 409 until gkm's state holds the row; then only the sidecar the row names,
// and only the key whose SHA-256 is the row's digest; a Delegation that does not forward takes none; a parked sidecar
// none; the same bytes again answer 200, and the object holds the key.
func TestGkmDelegationKeyUploadIsTheForwardingSidecarsAndHeldToTheRowsDigest(t *testing.T) {
	fixture := newGkmFixture(t)
	memberId := testId("member-a")
	configRepoId := testId("repo-config")
	fixture.placeRepo(configRepoId, "meta-2", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	forwarding := fixture.newSidecar("sc-forwarding", memberDeviceFacts(memberId))
	other := fixture.newSidecar("sc-other", memberDeviceFacts(memberId))
	for _, testSidecar := range []*gkmTestSidecar{forwarding, other} {
		fixture.auth.grant(testSidecar.sidecarId, configRepoId, sidecar.AclEvsRead)
	}
	forwardingToken := fixture.token(forwarding.sidecarId, repoScope(configRepoId, "r"))
	otherToken := fixture.token(other.sidecarId, repoScope(configRepoId, "r"))
	key := newGkmTestForwardingKey(t, "first")
	path := gkmTestDelegationKeyPath(key.delegationId)

	if recorder := fixture.serve(http.MethodPut, path, forwardingToken, key.publicKey); recorder.Code != http.StatusConflict {
		t.Errorf("an upload before gkm's state holds the row: %d", recorder.Code)
	}
	if fixture.delegationKeyObject(key.delegationId) != nil {
		t.Fatal("an upload gkm answered 409 stored the key")
	}
	forwardingId := forwarding.sidecarId
	fixture.auth.setDelegationKey(key.delegationId, &GkmDelegationKeyFacts{ReaderKeySha256: key.keySha256, ForwardSidecarId: &forwardingId, ConfigRepoId: configRepoId})

	other1216 := newGkmTestForwardingKey(t, "another key").publicKey
	for _, c := range []struct {
		name   string
		path   string
		token  string
		body   []byte
		status int
	}{
		{name: "another sidecar's upload", path: path, token: otherToken, body: key.publicKey, status: http.StatusForbidden},
		{name: "a key the row does not name", path: path, token: forwardingToken, body: other1216, status: http.StatusForbidden},
		{name: "a key one byte short", path: path, token: forwardingToken, body: key.publicKey[1:], status: http.StatusBadRequest},
		{name: "a key one byte long", path: path, token: forwardingToken, body: append(bytes.Clone(key.publicKey), 0), status: http.StatusBadRequest},
		{name: "an id out of form", path: "/gkm/delegation-keys/" + strings.ToUpper(hex.EncodeToString(key.delegationId)), token: forwardingToken, body: key.publicKey, status: http.StatusBadRequest},
		{name: "a short id", path: "/gkm/delegation-keys/" + hex.EncodeToString(key.delegationId[1:]), token: forwardingToken, body: key.publicKey, status: http.StatusBadRequest},
	} {
		if recorder := fixture.serve(http.MethodPut, c.path, c.token, c.body); recorder.Code != c.status {
			t.Errorf("%s: %d, want %d", c.name, recorder.Code, c.status)
		}
	}
	if fixture.delegationKeyObject(key.delegationId) != nil {
		t.Fatal("a refused upload stored a key")
	}

	// the twin: the Delegation's own sidecar, its row's key
	if recorder := fixture.serve(http.MethodPut, path, forwardingToken, key.publicKey); recorder.Code != http.StatusOK {
		t.Fatalf("the forwarding sidecar's upload: %d", recorder.Code)
	}
	if !bytes.Equal(fixture.delegationKeyObject(key.delegationId), key.publicKey) {
		t.Fatal("the object does not hold the key")
	}
	// a retry after a lost answer
	if recorder := fixture.serve(http.MethodPut, path, forwardingToken, key.publicKey); recorder.Code != http.StatusOK {
		t.Errorf("the same bytes again: %d", recorder.Code)
	}

	// a Delegation that does not forward keeps its key in its row
	agentKey := newGkmTestForwardingKey(t, "an auth key's")
	fixture.auth.setDelegationKey(agentKey.delegationId, &GkmDelegationKeyFacts{ReaderKeySha256: agentKey.keySha256, ConfigRepoId: configRepoId})
	if recorder := fixture.serve(http.MethodPut, gkmTestDelegationKeyPath(agentKey.delegationId), forwardingToken, agentKey.publicKey); recorder.Code != http.StatusForbidden {
		t.Errorf("an upload for a Delegation that does not forward: %d", recorder.Code)
	}

	// a parked sidecar writes nothing, its own record included
	parkedKey := newGkmTestForwardingKey(t, "parked")
	fixture.auth.setDelegationKey(parkedKey.delegationId, &GkmDelegationKeyFacts{ReaderKeySha256: parkedKey.keySha256, ForwardSidecarId: &forwardingId, ConfigRepoId: configRepoId})
	fixture.auth.update(forwarding.sidecarId, func(facts *GkmSidecarFacts) { facts.Parked = true })
	if recorder := fixture.serve(http.MethodPut, gkmTestDelegationKeyPath(parkedKey.delegationId), forwardingToken, parkedKey.publicKey); recorder.Code != http.StatusForbidden {
		t.Errorf("a parked sidecar's upload: %d", recorder.Code)
	}
	fixture.auth.update(forwarding.sidecarId, func(facts *GkmSidecarFacts) { facts.Parked = false })

	// a state not loaded allows nothing
	fixture.auth.unloaded = true
	if recorder := fixture.serve(http.MethodPut, gkmTestDelegationKeyPath(parkedKey.delegationId), forwardingToken, parkedKey.publicKey); recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("an upload while the state is cold: %d", recorder.Code)
	}
}

// GET /gkm/delegation-keys/<delegation_id>: the stored bytes to a token reading the network's config repo; 403 to one
// that reads only another repo; 404 for a Delegation with no object, one gkm's state does not hold and one that does
// not forward; 503 while the state is cold.
func TestGkmDelegationKeyReadIsTheConfigsReaders(t *testing.T) {
	fixture := newGkmFixture(t)
	memberId := testId("member-a")
	configRepoId := testId("repo-config")
	otherRepoId := testId("repo-other")
	fixture.placeRepo(configRepoId, "meta-2", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	fixture.placeRepo(otherRepoId, "meta-2", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	forwarding := fixture.newSidecar("sc-forwarding", memberDeviceFacts(memberId))
	reader := fixture.newSidecar("sc-reader", memberDeviceFacts(memberId))
	outsider := fixture.newSidecar("sc-outsider", memberDeviceFacts(memberId))
	fixture.auth.grant(forwarding.sidecarId, configRepoId, sidecar.AclEvsRead)
	fixture.auth.grant(reader.sidecarId, configRepoId, sidecar.AclEvsRead)
	fixture.auth.grant(outsider.sidecarId, otherRepoId, sidecar.AclEvsRead)
	forwardingId := forwarding.sidecarId
	key := newGkmTestForwardingKey(t, "read")
	fixture.auth.setDelegationKey(key.delegationId, &GkmDelegationKeyFacts{ReaderKeySha256: key.keySha256, ForwardSidecarId: &forwardingId, ConfigRepoId: configRepoId})
	readerToken := fixture.token(reader.sidecarId, repoScope(configRepoId, "r"))
	path := gkmTestDelegationKeyPath(key.delegationId)

	if recorder := fixture.serve(http.MethodGet, path, readerToken, nil); recorder.Code != http.StatusNotFound {
		t.Errorf("a read before the upload: %d", recorder.Code)
	}
	if recorder := fixture.serve(http.MethodPut, path, fixture.token(forwarding.sidecarId, repoScope(configRepoId, "r")), key.publicKey); recorder.Code != http.StatusOK {
		t.Fatalf("the upload: %d", recorder.Code)
	}
	recorder := fixture.serve(http.MethodGet, path, readerToken, nil)
	if recorder.Code != http.StatusOK || !bytes.Equal(recorder.Body.Bytes(), key.publicKey) {
		t.Errorf("a config reader's read: %d", recorder.Code)
	}
	if recorder := fixture.serve(http.MethodGet, path, fixture.token(outsider.sidecarId, repoScope(otherRepoId, "r")), nil); recorder.Code != http.StatusForbidden {
		t.Errorf("a read by a token that does not read the config: %d", recorder.Code)
	}
	// the state drops the reader from the config: its token, unexpired, reads nothing
	fixture.auth.drop(reader.sidecarId, configRepoId)
	if recorder := fixture.serve(http.MethodGet, path, readerToken, nil); recorder.Code != http.StatusForbidden {
		t.Errorf("a read by a sidecar the state no longer lets read the config: %d", recorder.Code)
	}
	fixture.auth.grant(reader.sidecarId, configRepoId, sidecar.AclEvsRead)

	unknown := newGkmTestForwardingKey(t, "unknown")
	if recorder := fixture.serve(http.MethodGet, gkmTestDelegationKeyPath(unknown.delegationId), readerToken, nil); recorder.Code != http.StatusNotFound {
		t.Errorf("a Delegation gkm's state holds no row of: %d", recorder.Code)
	}
	agentKey := newGkmTestForwardingKey(t, "an auth key's")
	fixture.auth.setDelegationKey(agentKey.delegationId, &GkmDelegationKeyFacts{ReaderKeySha256: agentKey.keySha256, ConfigRepoId: configRepoId})
	if recorder := fixture.serve(http.MethodGet, gkmTestDelegationKeyPath(agentKey.delegationId), readerToken, nil); recorder.Code != http.StatusNotFound {
		t.Errorf("a Delegation that does not forward: %d", recorder.Code)
	}
	fixture.auth.unloaded = true
	if recorder := fixture.serve(http.MethodGet, path, readerToken, nil); recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("a read while the state is cold: %d", recorder.Code)
	}
}

// A Signed DelegationWrap of key's generation to a Delegation, sealed to publicKey, staged or late at pin and at.
func (self *gkmGroupWorld) delegationWrap(signer *gkmTestSidecar, key *sidecar.EvsRepoKey, delegationId []byte, publicKey []byte, kind sidecar.GkmDeliveryKind, pin *bridge.AuthPin, at time.Time) []byte {
	self.t.Helper()
	args := &sidecar.GkmDeliveryArgs{
		GroupId:            self.groupId,
		Type:               sidecar.GkmWrapTypeDelegation,
		Recipient:          delegationId,
		RecipientPublicKey: publicKey,
		Kind:               kind,
	}
	if kind == sidecar.GkmDeliveryLate {
		args.Auth = pin
		args.Time = at
	}
	delivery, err := sidecar.SealGkmDelivery(key, args)
	if err != nil {
		self.t.Fatal(err)
	}
	signed, err := sidecar.SignGkmDelivery(delivery, sidecar.GkmWrapTypeDelegation, signer.sign)
	if err != nil {
		self.t.Fatal(err)
	}
	return self.fixture.marshal(signed)
}

// A STAGED DelegationWrap is held to the key its Delegation's row names wherever gkm's state holds the row: sealed to
// another key it answers 409; with the row's key 201; to a Delegation gkm's state does not hold yet it passes to the
// members' checks, since a rotator's state may be ahead of gkm's.
func TestGkmStagedDelegationWrapIsHeldToItsRowsKey(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	key2, _ := world.nextGeneration(world.admin, world.key1, nil)
	forwardingId := testId("sc-forwarding")
	held := newGkmTestForwardingKey(t, "held")
	fixture.auth.setDelegationKey(held.delegationId, &GkmDelegationKeyFacts{ReaderKeySha256: held.keySha256, ForwardSidecarId: &forwardingId, ConfigRepoId: world.repoId})
	ahead := newGkmTestForwardingKey(t, "ahead of gkm")
	stray := newGkmTestForwardingKey(t, "stray").publicKey
	now := fixture.clock.Now()
	toStray := world.delegationWrap(world.admin, key2, held.delegationId, stray, sidecar.GkmDeliveryStaged, nil, now)
	if status := world.postWrap(world.adminToken, 2, gkmTestC8(key2), toStray); status != http.StatusConflict {
		t.Errorf("a staged wrap to a key the row does not name: %d", status)
	}
	toRowKey := world.delegationWrap(world.admin, key2, held.delegationId, held.publicKey, sidecar.GkmDeliveryStaged, nil, now)
	if status := world.postWrap(world.adminToken, 2, gkmTestC8(key2), toRowKey); status != http.StatusCreated {
		t.Errorf("a staged wrap to the row's key: %d", status)
	}
	toAhead := world.delegationWrap(world.admin, key2, ahead.delegationId, ahead.publicKey, sidecar.GkmDeliveryStaged, nil, now)
	if status := world.postWrap(world.adminToken, 2, gkmTestC8(key2), toAhead); status != http.StatusCreated {
		t.Errorf("a staged wrap to a Delegation gkm's state does not hold yet: %d", status)
	}
}

// A forwarding sidecar reads its own forwarding Delegations' deliveries, d:<delegation_id>, as its VPN component's
// forwarding client does acting as it; another sidecar's forwarding Delegation, and a Delegation gkm's state does not
// hold, it does not.
func TestGkmForwardingSidecarReadsItsOwnDelegationsWraps(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	forwarding := fixture.newSidecar("sc-forwarding", memberDeviceFacts(world.memberId))
	other := fixture.newSidecar("sc-other", memberDeviceFacts(world.memberId))
	for _, testSidecar := range []*gkmTestSidecar{forwarding, other} {
		fixture.auth.grant(testSidecar.sidecarId, world.repoId, sidecar.AclEvsRead)
	}
	forwardingId, otherId := forwarding.sidecarId, other.sidecarId
	own := newGkmTestForwardingKey(t, "own")
	others := newGkmTestForwardingKey(t, "other's")
	unknown := newGkmTestForwardingKey(t, "unknown")
	fixture.auth.setDelegationKey(own.delegationId, &GkmDelegationKeyFacts{ReaderKeySha256: own.keySha256, ForwardSidecarId: &forwardingId, ConfigRepoId: world.repoId})
	fixture.auth.setDelegationKey(others.delegationId, &GkmDelegationKeyFacts{ReaderKeySha256: others.keySha256, ForwardSidecarId: &otherId, ConfigRepoId: world.repoId})
	key2, claim2 := world.nextGeneration(world.admin, world.key1, nil)
	staged := world.delegationWrap(world.admin, key2, own.delegationId, own.publicKey, sidecar.GkmDeliveryStaged, nil, fixture.clock.Now())
	if status := world.postWrap(world.adminToken, 2, gkmTestC8(key2), staged); status != http.StatusCreated {
		t.Fatalf("the staged wrap: %d", status)
	}
	if recorder := world.postClaim(world.adminToken, 2, claim2); recorder.Code != http.StatusCreated {
		t.Fatalf("the claim: %d", recorder.Code)
	}
	read := func(token string, delegationId []byte) (int, []*bridge.Signed) {
		path := "/gkm/groups/" + sidecar.EvsKeyId(world.groupId) + "/wraps/2?recipient=d:" + hex.EncodeToString(delegationId)
		recorder := fixture.serve(http.MethodGet, path, token, nil)
		reply := &protocol.GkmWrapsReply{}
		if recorder.Code == http.StatusOK && proto.Unmarshal(recorder.Body.Bytes(), reply) != nil {
			t.Fatal("a wraps answer that does not parse")
		}
		return recorder.Code, reply.GetWraps()
	}
	forwardingToken := fixture.token(forwarding.sidecarId, repoScope(world.repoId, "r"))
	if code, wraps := read(forwardingToken, own.delegationId); code != http.StatusOK || len(wraps) != 1 || !bytes.Equal(fixture.marshal(wraps[0]), staged) {
		t.Errorf("its own forwarding Delegation's wraps: %d, %d", code, len(wraps))
	}
	if code, _ := read(forwardingToken, others.delegationId); code != http.StatusForbidden {
		t.Errorf("another sidecar's forwarding Delegation's wraps: %d", code)
	}
	if code, _ := read(forwardingToken, unknown.delegationId); code != http.StatusForbidden {
		t.Errorf("a Delegation gkm's state does not hold: %d", code)
	}
	if code, _ := read(fixture.token(other.sidecarId, repoScope(world.repoId, "r")), own.delegationId); code != http.StatusForbidden {
		t.Errorf("another sidecar reading the forwarding Delegation's wraps: %d", code)
	}
}

// Sets a network's state with PositionTime answering from a copy of positionTimes, and announces it.
func (self *gkmReconcilerWorld) setWithTimes(view sidecar.GkmAuthView, positionTimes map[uint64]time.Time) {
	positionTimes = maps.Clone(positionTimes)
	changed := func() func(change *GkmStateChange) {
		self.state.stateLock.Lock()
		defer self.state.stateLock.Unlock()
		self.state.networkStates[self.networkId] = &GkmNetworkState{
			View:    view,
			RepoIds: []sidecar.Id{self.repoId},
			PositionTime: func(n uint64) (time.Time, bool) {
				at, ok := positionTimes[n]
				return at, ok
			},
		}
		return self.state.changed
	}()
	if changed != nil {
		changed(&GkmStateChange{NetworkId: self.networkId})
	}
}

// A state whose rows hold the Delegations given, a member device of the world's reading and writing the repo.
func (self *gkmReconcilerWorld) appendDelegations(delegations []*bridge.DelegationRow) *sidecartest.FakeGkmAuthView {
	writer := testId("sc-writer")
	fixture := &sidecartest.FakeGkmAuthFixture{
		Rows:         sidecartest.FakeGkmAuthRows(&protocol.AclRepo{RepoId: self.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL}),
		IdentityKeys: map[sidecar.Id][]byte{},
		RepoReaders:  map[sidecar.Id][]sidecar.Id{self.repoId: {writer}},
		RepoWriters:  map[sidecar.Id][]sidecar.Id{self.repoId: {writer}},
	}
	sidecarRows, memberRow := sidecartest.FakeGkmAuthMemberDevices(self.memberId, writer)
	fixture.Rows.Sidecars = sidecarRows
	fixture.Rows.Members = []*bridge.MemberRow{memberRow}
	fixture.Rows.Delegations = delegations
	return self.log.Append(fixture)
}

// Waits until the key objects' deleter has finished count deletions in all.
func (self *gkmReconcilerWorld) awaitDelegationKeyDeletes(count int) {
	self.t.Helper()
	for {
		finished, changed := self.reconciler.DelegationKeyDeletes()
		if count <= finished {
			return
		}
		select {
		case <-changed:
		case <-self.fixture.ctx.Done():
			self.t.Fatal("the deleter never finished")
		}
	}
}

// A forwarding Delegation's row for a sidecar, at position at.
func gkmTestForwardingRow(key *gkmTestForwardingKey, sidecarId sidecar.Id, at uint64) *bridge.DelegationRow {
	return &bridge.DelegationRow{
		DelegationId:     bytes.Clone(key.delegationId),
		Signer:           sidecarId.Bytes(),
		At:               at,
		ForwardSidecarId: sidecarId.Bytes(),
		ReaderKeySha256:  bytes.Clone(key.keySha256),
	}
}

// The reconciler deletes a forwarding Delegation's key object DelegationKeyRetention after its Delegation ended or
// was superseded, at the time its state gives that position: an end a day old at once, one 23 hours old an hour later;
// the live Delegation's object stays, and so does an object while a hold covers the network, which goes at the retry
// once the hold is gone.
func TestGkmReconcilerDeletesAForwardingKeyObjectADayAfterItsEnd(t *testing.T) {
	world := newGkmReconcilerWorld(t)
	fixture := world.fixture
	settings := world.reconciler.settings
	appSidecarId, laptopSidecarId := testId("sc-app"), testId("sc-laptop")
	superseded := newGkmTestForwardingKey(t, "superseded")
	live := newGkmTestForwardingKey(t, "live")
	revoked := newGkmTestForwardingKey(t, "revoked")
	for _, key := range []*gkmTestForwardingKey{superseded, live, revoked} {
		objectKey, err := GkmDelegationKeyKey(key.delegationId)
		if err != nil {
			t.Fatal(err)
		}
		fixture.put("meta-1", objectKey, key.publicKey)
	}
	now := fixture.clock.Now()
	supersededRow := gkmTestForwardingRow(superseded, appSidecarId, 2)
	supersededRow.SupersededAt = 4
	liveRow := gkmTestForwardingRow(live, appSidecarId, 4)
	revokedRow := gkmTestForwardingRow(revoked, laptopSidecarId, 3)
	revokedRow.EndedAt = 5
	positionTimes := map[uint64]time.Time{
		4: now.Add(-settings.DelegationKeyRetention + time.Hour),
		5: now.Add(-settings.DelegationKeyRetention - time.Hour),
	}
	view := world.appendDelegations([]*bridge.DelegationRow{supersededRow, liveRow, revokedRow})
	world.awaitState(view, func() { world.setWithTimes(view, positionTimes) })
	world.awaitDelegationKeyDeletes(1)
	if fixture.delegationKeyObject(revoked.delegationId) != nil {
		t.Errorf("a revoked Delegation's object a day and an hour after its end stands")
	}
	if fixture.delegationKeyObject(superseded.delegationId) == nil || fixture.delegationKeyObject(live.delegationId) == nil {
		t.Fatalf("an object deleted before its day")
	}
	// the superseded one's day ends in an hour: the network's wake deletes it then
	world.awaitPass(func() { fixture.clock.Advance(time.Hour) })
	world.awaitDelegationKeyDeletes(2)
	if fixture.delegationKeyObject(superseded.delegationId) != nil {
		t.Errorf("a superseded Delegation's object a day after its supersession stands")
	}
	if fixture.delegationKeyObject(live.delegationId) == nil {
		t.Errorf("the live forwarding Delegation's object was deleted")
	}

	// a hold covering the network keeps a due object, which goes at the retry once the hold ends
	caseId := testId("case-dkey")
	if err := sidecartest.PlaceHold(fixture.ctx, fixture.host.Blobs, &sidecar.HoldRecord{
		NetworkId:  world.networkId,
		CaseId:     caseId,
		Kind:       sidecar.HoldKindPreserve2703f,
		Scope:      sidecar.HoldScopeNetwork(),
		PlaceTime:  fixture.clock.Now(),
		ExpireTime: fixture.clock.Now().Add(365 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	// past the hold set's reread, as any reader of holds is
	fixture.clock.Advance(sidecar.DefaultHoldSetSettings().RereadInterval)
	held := newGkmTestForwardingKey(t, "held")
	heldKey, _ := GkmDelegationKeyKey(held.delegationId)
	fixture.put("meta-1", heldKey, held.publicKey)
	heldRow := gkmTestForwardingRow(held, laptopSidecarId, 6)
	heldRow.EndedAt = 7
	positionTimes[7] = fixture.clock.Now().Add(-2 * settings.DelegationKeyRetention)
	heldView := world.appendDelegations([]*bridge.DelegationRow{supersededRow, liveRow, revokedRow, heldRow})
	world.awaitState(heldView, func() { world.setWithTimes(heldView, positionTimes) })
	world.awaitDelegationKeyDeletes(3)
	if fixture.delegationKeyObject(held.delegationId) == nil {
		t.Fatalf("an object deleted under a hold")
	}
	if err := sidecartest.RemoveHold(fixture.ctx, fixture.host.Blobs, world.networkId, caseId); err != nil {
		t.Fatal(err)
	}
	// the pass that queued it woke the network again for the retry
	world.awaitPass(func() { fixture.clock.Advance(settings.DelegationKeyRetryInterval) })
	world.awaitDelegationKeyDeletes(4)
	if fixture.delegationKeyObject(held.delegationId) != nil {
		t.Errorf("an object a hold kept still stands at the retry after its hold ended")
	}
	if fixture.delegationKeyObject(live.delegationId) == nil {
		t.Errorf("the live forwarding Delegation's object was deleted")
	}
}
