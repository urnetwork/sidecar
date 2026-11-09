package gkmservice

import (
	"bytes"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A reader of the world's repo with a ReaderKey gkm serves at rk/.
type gkmTestReader struct {
	*gkmTestSidecar
	xwingPublicKey []byte
	keySha256      []byte
}

// A member device reading the repo, its ReaderKey stored at rk/<sidecar_id> as an upload would leave it.
func (self *gkmGroupWorld) newReader(label string) *gkmTestReader {
	self.t.Helper()
	fixture := self.fixture
	testSidecar := fixture.newSidecar(label, memberDeviceFacts(self.memberId))
	fixture.auth.grant(testSidecar.sidecarId, self.repoId, sidecar.AclEvsRead)
	return self.withReaderKey(testSidecar)
}

// Gives a sidecar a fresh ReaderKey at rk/, replacing any.
func (self *gkmGroupWorld) withReaderKey(testSidecar *gkmTestSidecar) *gkmTestReader {
	self.t.Helper()
	fixture := self.fixture
	now := fixture.clock.Now()
	signed, _, err := sidecar.NewGkmReaderKey(testSidecar.sidecarId, now, now.Add(6*24*time.Hour), testSidecar.sign)
	if err != nil {
		self.t.Fatal(err)
	}
	body := &protocol.ReaderKey{}
	if err := proto.Unmarshal(signed.GetBody(), body); err != nil {
		self.t.Fatal(err)
	}
	cluster := fixture.cluster("meta-1")
	key := GkmReaderKeyKey(testSidecar.sidecarId)
	etag := ""
	if info, err := cluster.Head(fixture.ctx, key); err == nil {
		etag = info.Etag
	}
	if err := replaceGkmObject(fixture.ctx, cluster, key, etag, fixture.marshal(signed)); err != nil {
		self.t.Fatal(err)
	}
	keySha256 := sha256.Sum256(body.GetXwingPublicKey())
	return &gkmTestReader{gkmTestSidecar: testSidecar, xwingPublicKey: body.GetXwingPublicKey(), keySha256: keySha256[:]}
}

// One Signed delivery's bytes: key's RK_g to the reader's key (or another key), staged or late at pin and at.
func (self *gkmGroupWorld) readerWrap(signer *gkmTestSidecar, key *sidecar.EvsRepoKey, recipient sidecar.Id, xwingPublicKey []byte, kind sidecar.GkmDeliveryKind, pin *bridge.AuthPin, at time.Time) []byte {
	self.t.Helper()
	args := &sidecar.GkmDeliveryArgs{
		GroupId:            self.groupId,
		Type:               sidecar.GkmWrapTypeReader,
		Recipient:          recipient.Bytes(),
		RecipientPublicKey: xwingPublicKey,
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
	signed, err := sidecar.SignGkmDelivery(delivery, sidecar.GkmWrapTypeReader, signer.sign)
	if err != nil {
		self.t.Fatal(err)
	}
	return self.fixture.marshal(signed)
}

// c8 of a key's commitment.
func gkmTestC8(key *sidecar.EvsRepoKey) string {
	return hex.EncodeToString(key.Commitment()[:8])
}

// POST wraps/<g>/<c8> with token: the status and, on 200, each result.
func (self *gkmGroupWorld) postWraps(token string, generation uint64, c8 string, deliveries ...[]byte) (int, []*protocol.GkmWrapResult) {
	self.t.Helper()
	path := "/gkm/groups/" + sidecar.EvsKeyId(self.groupId) + "/wraps/" + strconv.FormatUint(generation, 10) + "/" + c8
	recorder := self.fixture.serve(http.MethodPost, path, token, self.fixture.marshal(&protocol.GkmWrapBatch{Deliveries: deliveries}))
	reply := &protocol.GkmWrapBatchReply{}
	if recorder.Code == http.StatusOK {
		if err := proto.Unmarshal(recorder.Body.Bytes(), reply); err != nil {
			self.t.Fatal(err)
		}
	}
	return recorder.Code, reply.GetResults()
}

// The status of one delivery posted alone.
func (self *gkmGroupWorld) postWrap(token string, generation uint64, c8 string, delivery []byte) int {
	self.t.Helper()
	code, results := self.postWraps(token, generation, c8, delivery)
	if code != http.StatusOK {
		return code
	}
	return int(results[0].GetStatus())
}

// §10.6's wrap checks for STAGED deliveries, each a refusal with a twin that passes: STAGED only while gen/<g> is
// absent, the body agreeing with the path, a signer in standing, one object per (recipient, key).
func TestGkmStagedWrapChecksRefuseAndTheirTwinsPass(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	reader := world.newReader("sc-reader")
	readOnlyFacts := memberDeviceFacts(world.memberId)
	readOnlyFacts.ReadOnly = true
	readOnly := fixture.newSidecar("sc-readonly", readOnlyFacts)
	key2, claim2 := world.nextGeneration(world.admin, world.key1, nil)
	now := fixture.clock.Now()
	staged := world.readerWrap(world.admin, key2, reader.sidecarId, reader.xwingPublicKey, sidecar.GkmDeliveryStaged, nil, now)
	byReadOnly := world.readerWrap(readOnly, key2, reader.sidecarId, reader.xwingPublicKey, sidecar.GkmDeliveryStaged, nil, now)
	ofGeneration1 := world.readerWrap(world.admin, world.key1, reader.sidecarId, reader.xwingPublicKey, sidecar.GkmDeliveryStaged, nil, now)
	for _, c := range []struct {
		name       string
		generation uint64
		c8         string
		delivery   []byte
		status     int
	}{
		{name: "a delivery under another commitment prefix", generation: 2, c8: gkmTestC8(world.key1), delivery: staged, status: http.StatusConflict},
		{name: "a delivery of another generation than the path's", generation: 2, c8: gkmTestC8(key2), delivery: ofGeneration1, status: http.StatusConflict},
		{name: "a delivery a read_only sidecar signed", generation: 2, c8: gkmTestC8(key2), delivery: byReadOnly, status: http.StatusForbidden},
		{name: "a GenRotate in a delivery's place", generation: 2, c8: gkmTestC8(key2), delivery: fixture.marshal(claim2), status: http.StatusConflict},
		{name: "bytes that are no Signed", generation: 2, c8: gkmTestC8(key2), delivery: []byte{0xff, 0xff}, status: http.StatusForbidden},
	} {
		if status := world.postWrap(world.adminToken, c.generation, c.c8, c.delivery); status != c.status {
			t.Errorf("%s: %d, not %d", c.name, status, c.status)
		}
	}
	if status := world.postWrap(world.adminToken, 2, gkmTestC8(key2), staged); status != http.StatusCreated {
		t.Fatalf("the twin STAGED delivery: %d", status)
	}
	if status := world.postWrap(world.adminToken, 2, gkmTestC8(key2), staged); status != http.StatusCreated {
		t.Errorf("the same delivery again, a lost answer's retry: %d", status)
	}
	other := world.readerWrap(world.admin, key2, reader.sidecarId, reader.xwingPublicKey, sidecar.GkmDeliveryStaged, nil, now)
	code, results := world.postWraps(world.adminToken, 2, gkmTestC8(key2), other)
	if code != http.StatusOK || results[0].GetStatus() != http.StatusPreconditionFailed || !bytes.Equal(results[0].GetWinner(), staged) {
		t.Errorf("another delivery to the same key: %d", code)
	}
	if recorder := world.postClaim(world.adminToken, 2, claim2); recorder.Code != http.StatusCreated {
		t.Fatalf("the claim after its staging: %d", recorder.Code)
	}
	afterClaim := world.readerWrap(world.admin, key2, testId("sc-someone"), reader.xwingPublicKey, sidecar.GkmDeliveryStaged, nil, now)
	if status := world.postWrap(world.adminToken, 2, gkmTestC8(key2), afterClaim); status != http.StatusConflict {
		t.Errorf("a STAGED delivery once gen/2 exists: %d", status)
	}
	readOnlyToken := fixture.token(readOnly.sidecarId, repoScope(world.repoId, "r"))
	fixture.auth.grant(readOnly.sidecarId, world.repoId, sidecar.AclEvsRead)
	if code, _ := world.postWraps(readOnlyToken, 2, gkmTestC8(key2), staged); code != http.StatusForbidden {
		t.Errorf("a read_only uploader: %d", code)
	}
	deliveries := make([][]byte, gkmWrapBatchMaxCount+1)
	for i := range deliveries {
		deliveries[i] = staged
	}
	if code, _ := world.postWraps(world.adminToken, 2, gkmTestC8(key2), deliveries...); code != http.StatusBadRequest {
		t.Errorf("a batch of 257: %d", code)
	}
}

// KF1: while the repo is keying, generation 1's STAGED deliveries come only from gen/1's signer, and no LATE one.
func TestGkmKeyingRepoTakesOnlyItsCreatorsFirstDeliveries(t *testing.T) {
	world := newGkmGroupWorld(t)
	fixture := world.fixture
	if recorder := world.postCreate(world.createRequest(world.groupId)); recorder.Code != http.StatusOK {
		t.Fatalf("a creation: %d", recorder.Code)
	}
	reader := world.newReader("sc-reader")
	other := fixture.newSidecar("sc-other-admin", memberDeviceFacts(world.memberId))
	fixture.auth.grant(other.sidecarId, world.repoId, sidecar.AclEvsAdmin)
	otherToken := fixture.token(other.sidecarId, repoScope(world.repoId, "admin"))
	now := fixture.clock.Now()
	staged := world.readerWrap(world.admin, world.key1, reader.sidecarId, reader.xwingPublicKey, sidecar.GkmDeliveryStaged, nil, now)
	if status := world.postWrap(otherToken, 1, gkmTestC8(world.key1), staged); status != http.StatusConflict {
		t.Errorf("generation 1's delivery uploaded by another than gen/1's signer: %d", status)
	}
	late := world.readerWrap(world.admin, world.key1, reader.sidecarId, reader.xwingPublicKey, sidecar.GkmDeliveryLate, fakeGkmPin(10), now)
	if status := world.postWrap(world.adminToken, 1, gkmTestC8(world.key1), late); status != http.StatusConflict {
		t.Errorf("a LATE delivery while keying: %d", status)
	}
	if status := world.postWrap(world.adminToken, 1, gkmTestC8(world.key1), staged); status != http.StatusCreated {
		t.Errorf("gen/1's signer's first delivery while keying: %d", status)
	}
}

// §10.6's late row, each a refusal with the twin that passes: gen/<g> existing and newest under the body's
// commitment, a pin at or past gen/<g>'s that gkm's state judges, a time within skew, a recipient that reads R, and a
// ReaderWrap sealed to the ReaderKey gkm serves (FI-28).
func TestGkmLateWrapChecksRefuseAndTheirTwinPasses(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	reader := world.newReader("sc-reader")
	outsider := world.withReaderKey(fixture.newSidecar("sc-outsider", memberDeviceFacts(world.memberId)))
	key2, claim2 := world.nextGeneration(world.admin, world.key1, nil)
	now := fixture.clock.Now()
	late := func(key *sidecar.EvsRepoKey, recipient *gkmTestReader, xwingPublicKey []byte, pin *bridge.AuthPin, at time.Time) []byte {
		return world.readerWrap(world.admin, key, recipient.sidecarId, xwingPublicKey, sidecar.GkmDeliveryLate, pin, at)
	}
	valid := late(key2, reader, reader.xwingPublicKey, fakeGkmPin(10), now)
	if status := world.postWrap(world.adminToken, 2, gkmTestC8(key2), valid); status != http.StatusConflict {
		t.Errorf("a LATE delivery before gen/2 exists: %d", status)
	}
	if recorder := world.postClaim(world.adminToken, 2, claim2); recorder.Code != http.StatusCreated {
		t.Fatalf("the claim: %d", recorder.Code)
	}
	otherKey := world.withReaderKey(fixture.newSidecar("sc-elsewhere", memberDeviceFacts(world.memberId)))
	for _, c := range []struct {
		name     string
		delivery []byte
		status   int
	}{
		{name: "a pin below gen/2's", delivery: late(key2, reader, reader.xwingPublicKey, fakeGkmPin(9), now), status: http.StatusForbidden},
		{name: "a pin past gkm's state", delivery: late(key2, reader, reader.xwingPublicKey, fakeGkmPin(11), now), status: http.StatusServiceUnavailable},
		{name: "a time eleven minutes ahead", delivery: late(key2, reader, reader.xwingPublicKey, fakeGkmPin(10), now.Add(11*time.Minute)), status: http.StatusForbidden},
		{name: "a recipient that does not read the repo", delivery: late(key2, outsider, outsider.xwingPublicKey, fakeGkmPin(10), now), status: http.StatusForbidden},
		{name: "a key gkm does not serve for the recipient", delivery: late(key2, reader, otherKey.xwingPublicKey, fakeGkmPin(10), now), status: http.StatusConflict},
	} {
		code, results := world.postWraps(world.adminToken, 2, gkmTestC8(key2), c.delivery)
		status := code
		if code == http.StatusOK {
			status = int(results[0].GetStatus())
		}
		if status != c.status {
			t.Errorf("%s: %d, not %d", c.name, status, c.status)
		}
	}
	if status := world.postWrap(world.adminToken, 2, gkmTestC8(key2), valid); status != http.StatusCreated {
		t.Fatalf("the twin LATE delivery: %d", status)
	}
	world.putGeneration(world.admin, key2)
	stale := late(key2, otherKey, otherKey.xwingPublicKey, fakeGkmPin(10), now)
	fixture.auth.grant(otherKey.sidecarId, world.repoId, sidecar.AclEvsRead)
	if status := world.postWrap(world.adminToken, 2, gkmTestC8(key2), stale); status != http.StatusConflict {
		t.Errorf("a LATE delivery of a generation that is no longer gen/'s newest: %d", status)
	}
}

// A DelegationWrap's late recipient must be a live Delegation whose reach holds the repo.
func TestGkmLateDelegationWrapNeedsALiveDelegationReachingTheRepo(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	key2, claim2 := world.nextGeneration(world.admin, world.key1, nil)
	if recorder := world.postClaim(world.adminToken, 2, claim2); recorder.Code != http.StatusCreated {
		t.Fatalf("the claim: %d", recorder.Code)
	}
	delegationKey, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	delegationPublicKey := delegationKey.PublicKey().Bytes()
	delegationId := bytes.Repeat([]byte{0x44}, 32)
	delivery, err := sidecar.SealGkmDelivery(key2, &sidecar.GkmDeliveryArgs{
		GroupId:            world.groupId,
		Type:               sidecar.GkmWrapTypeDelegation,
		Recipient:          delegationId,
		RecipientPublicKey: delegationPublicKey,
		Kind:               sidecar.GkmDeliveryLate,
		Auth:               fakeGkmPin(10),
		Time:               fixture.clock.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := sidecar.SignGkmDelivery(delivery, sidecar.GkmWrapTypeDelegation, world.admin.sign)
	if err != nil {
		t.Fatal(err)
	}
	if status := world.postWrap(world.adminToken, 2, gkmTestC8(key2), fixture.marshal(signed)); status != http.StatusForbidden {
		t.Errorf("a DelegationWrap to a Delegation that does not reach the repo: %d", status)
	}
	fixture.auth.setDelegationReads(world.repoId, delegationId, true)
	if status := world.postWrap(world.adminToken, 2, gkmTestC8(key2), fixture.marshal(signed)); status != http.StatusCreated {
		t.Errorf("a DelegationWrap to a live Delegation reaching the repo: %d", status)
	}
}

// §10.6's late wraps: two holders deliver late to one recipient's key at once; one gets 201, the other 412 carrying
// the winner, which it judges (§10.9).
func TestGkmTwoLateDeliverersOneWins(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	reader := world.newReader("sc-reader")
	writer := fixture.newSidecar("sc-writer", memberDeviceFacts(world.memberId))
	fixture.auth.grant(writer.sidecarId, world.repoId, sidecar.AclEvsWrite)
	writerToken := fixture.token(writer.sidecarId, repoScope(world.repoId, "rw"))
	key2, claim2 := world.nextGeneration(world.admin, world.key1, nil)
	if recorder := world.postClaim(world.adminToken, 2, claim2); recorder.Code != http.StatusCreated {
		t.Fatalf("the claim: %d", recorder.Code)
	}
	now := fixture.clock.Now()
	first := world.readerWrap(world.admin, key2, reader.sidecarId, reader.xwingPublicKey, sidecar.GkmDeliveryLate, fakeGkmPin(10), now)
	second := world.readerWrap(writer, key2, reader.sidecarId, reader.xwingPublicKey, sidecar.GkmDeliveryLate, fakeGkmPin(10), now)
	if status := world.postWrap(world.adminToken, 2, gkmTestC8(key2), first); status != http.StatusCreated {
		t.Fatalf("the first late deliverer: %d", status)
	}
	code, results := world.postWraps(writerToken, 2, gkmTestC8(key2), second)
	if code != http.StatusOK || results[0].GetStatus() != http.StatusPreconditionFailed || !bytes.Equal(results[0].GetWinner(), first) {
		t.Errorf("the second late deliverer: %d", code)
	}
}

// Reads return only the caller's own deliveries: the wanted key's first; a miss is a late delivery's ask, which hints
// wrap-pending naming the recipient to the writers, and once since is 15 minutes old to other holders too.
func TestGkmWrapsReadServesTheCallersOwnAndAMissHints(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	fixture.clientOf(world.admin.sidecarId)
	reader := world.newReader("sc-reader")
	holder := fixture.newSidecar("sc-holder", memberDeviceFacts(world.memberId))
	fixture.clientOf(holder.sidecarId)
	fixture.auth.setLateHolders(world.repoId, []sidecar.Id{reader.sidecarId, holder.sidecarId})
	key2, claim2 := world.nextGeneration(world.admin, world.key1, nil)
	staged := world.readerWrap(world.admin, key2, reader.sidecarId, reader.xwingPublicKey, sidecar.GkmDeliveryStaged, nil, fixture.clock.Now())
	if status := world.postWrap(world.adminToken, 2, gkmTestC8(key2), staged); status != http.StatusCreated {
		t.Fatalf("a staged delivery: %d", status)
	}
	if recorder := world.postClaim(world.adminToken, 2, claim2); recorder.Code != http.StatusCreated {
		t.Fatalf("the claim: %d", recorder.Code)
	}
	read := func(query string) (int, []*bridge.Signed) {
		token := fixture.token(reader.sidecarId, repoScope(world.repoId, "r"))
		path := "/gkm/groups/" + sidecar.EvsKeyId(world.groupId) + "/wraps/2" + query
		recorder := fixture.serve(http.MethodGet, path, token, nil)
		reply := &protocol.GkmWrapsReply{}
		if recorder.Code == http.StatusOK && proto.Unmarshal(recorder.Body.Bytes(), reply) != nil {
			t.Fatal("a wraps answer that does not parse")
		}
		return recorder.Code, reply.GetWraps()
	}
	if code, wraps := read("?want=" + hex.EncodeToString(reader.keySha256[:8])); code != http.StatusOK || len(wraps) != 1 || !bytes.Equal(fixture.marshal(wraps[0]), staged) {
		t.Errorf("the wanted key's delivery: %d", code)
	}
	if code, _ := read("?recipient=s:" + sidecar.EvsKeyId(holder.sidecarId)); code != http.StatusForbidden {
		t.Errorf("another sidecar's deliveries: %d", code)
	}
	wrapPending := func(sidecarId sidecar.Id) int {
		count := 0
		for _, hint := range fixture.hints(sidecarId) {
			if hint.GetKind() == protocol.GkmHintKind_GKM_HINT_WRAP_PENDING && string(hint.GetRecipient()) == "s:"+sidecar.EvsKeyId(reader.sidecarId) {
				count += 1
			}
		}
		return count
	}
	since := fixture.clock.Now()
	missQuery := "?want=0011223344556677&since=" + strconv.FormatInt(since.UnixMilli(), 10)
	if code, wraps := read(missQuery); code != http.StatusOK || len(wraps) != 1 {
		t.Errorf("a miss answers the recipient's other deliveries: %d", code)
	}
	if wrapPending(world.admin.sidecarId) != 1 || wrapPending(holder.sidecarId) != 0 {
		t.Errorf("a fresh ask hints the writers alone")
	}
	read(missQuery)
	if wrapPending(world.admin.sidecarId) != 1 {
		t.Errorf("a second ask within the minute hinted again")
	}
	fixture.clock.Advance(fixture.settings.LateAskWidenAge)
	read(missQuery)
	if wrapPending(world.admin.sidecarId) != 2 || wrapPending(holder.sidecarId) != 1 {
		t.Errorf("an ask 15 minutes old hints the other holders")
	}
}
