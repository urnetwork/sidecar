package gkmservice

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The next generation after parent, signed by signer at the log's position 10 and now, edit changing its args first.
func (self *gkmGroupWorld) nextGeneration(signer *gkmTestSidecar, parent *sidecar.EvsRepoKey, edit func(args *sidecar.GkmGenerationArgs)) (*sidecar.EvsRepoKey, *bridge.Signed) {
	self.t.Helper()
	args := &sidecar.GkmGenerationArgs{
		Cause:         sidecar.GkmCauseRemove,
		Auth:          fakeGkmPin(10),
		Time:          self.fixture.clock.Now(),
		HoldersSha256: gkmTestHoldersSha256(),
	}
	if edit != nil {
		edit(args)
	}
	key, rotate, err := parent.NextGeneration(args)
	if err != nil {
		self.t.Fatal(err)
	}
	signed, err := sidecar.SignGenRotate(rotate, signer.sign)
	if err != nil {
		self.t.Fatal(err)
	}
	return key, signed
}

// POST gen/<generation> with token.
func (self *gkmGroupWorld) postClaim(token string, generation uint64, signed *bridge.Signed) *httptest.ResponseRecorder {
	path := "/gkm/groups/" + sidecar.EvsKeyId(self.groupId) + "/gen/" + strconv.FormatUint(generation, 10)
	return self.fixture.serve(http.MethodPost, path, token, self.fixture.marshal(signed))
}

// §10.6's claim checks, each a refusal that writes nothing, and the twin that passes them all: 201, gen/<g> holding
// its bytes, and a commit hint on gkm:<group_id> at the newest epoch and g (D-KEYS-19).
func TestGkmClaimChecksRefuseAndTheirTwinPasses(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	readOnlyFacts := memberDeviceFacts(world.memberId)
	readOnlyFacts.ReadOnly = true
	readOnly := fixture.newSidecar("sc-readonly", readOnlyFacts)
	parked := fixture.newSidecar("sc-parked", memberDeviceFacts(world.memberId))
	fixture.auth.update(parked.sidecarId, func(facts *GkmSidecarFacts) { facts.Parked = true })
	reader := fixture.newSidecar("sc-reader", memberDeviceFacts(world.memberId))
	fixture.auth.grant(reader.sidecarId, world.repoId, sidecar.AclEvsRead)
	readerClientId := fixture.clientOf(reader.sidecarId)
	otherChain, _ := world.firstGeneration(world.admin, world.groupId, fixture.clock.Now(), fakeGkmPin(10))

	type claimCase struct {
		name       string
		token      string
		generation uint64
		signed     *bridge.Signed
		status     int
	}
	readerToken := fixture.token(reader.sidecarId, repoScope(world.repoId, "r"))
	_, valid := world.nextGeneration(world.admin, world.key1, nil)
	_, offChain := world.nextGeneration(world.admin, otherChain, nil)
	_, fallingPin := world.nextGeneration(world.admin, world.key1, func(args *sidecar.GkmGenerationArgs) { args.Auth = fakeGkmPin(9) })
	_, aheadPin := world.nextGeneration(world.admin, world.key1, func(args *sidecar.GkmGenerationArgs) { args.Auth = fakeGkmPin(11) })
	_, late := world.nextGeneration(world.admin, world.key1, func(args *sidecar.GkmGenerationArgs) { args.Time = fixture.clock.Now().Add(-11 * time.Minute) })
	_, byReadOnly := world.nextGeneration(readOnly, world.key1, nil)
	_, byParked := world.nextGeneration(parked, world.key1, nil)
	_, noLeafEpoch := world.nextGeneration(world.admin, world.key1, func(args *sidecar.GkmGenerationArgs) {
		args.LeafWrapKek = bytes.Repeat([]byte{3}, 32)
		args.LeafWrapEpoch = 99
	})
	for _, c := range []claimCase{
		{name: "a claim under r alone", token: readerToken, generation: 2, signed: valid, status: http.StatusForbidden},
		{name: "a claim of gen/1", token: world.adminToken, generation: 1, signed: world.rotate1, status: http.StatusBadRequest},
		{name: "a GenRotate of another generation than the path's", token: world.adminToken, generation: 3, signed: valid, status: http.StatusBadRequest},
		{name: "a parent commitment that is not gen/1's", token: world.adminToken, generation: 2, signed: offChain, status: http.StatusForbidden},
		{name: "an auth pin below gen/1's", token: world.adminToken, generation: 2, signed: fallingPin, status: http.StatusForbidden},
		{name: "an auth pin past gkm's state", token: world.adminToken, generation: 2, signed: aheadPin, status: http.StatusServiceUnavailable},
		{name: "a time eleven minutes behind gkm's clock", token: world.adminToken, generation: 2, signed: late, status: http.StatusForbidden},
		{name: "a read_only signer", token: world.adminToken, generation: 2, signed: byReadOnly, status: http.StatusForbidden},
		{name: "a parked signer", token: world.adminToken, generation: 2, signed: byParked, status: http.StatusForbidden},
		{name: "a leaf wrap of an epoch that does not exist", token: world.adminToken, generation: 2, signed: noLeafEpoch, status: http.StatusForbidden},
	} {
		if recorder := world.postClaim(c.token, c.generation, c.signed); recorder.Code != c.status {
			t.Errorf("%s: %d, not %d", c.name, recorder.Code, c.status)
		}
		if fixture.object("meta-2", GkmGenerationKey(world.groupId, 2)) != nil {
			t.Fatalf("%s: gen/2 written", c.name)
		}
	}
	if recorder := world.postClaim(world.adminToken, 2, valid); recorder.Code != http.StatusCreated {
		t.Fatalf("the twin that passes every check: %d", recorder.Code)
	}
	if !bytes.Equal(fixture.object("meta-2", GkmGenerationKey(world.groupId, 2)), fixture.marshal(valid)) {
		t.Errorf("gen/2 does not hold the claim's bytes")
	}
	if err := fixture.engine.AwaitHints(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	hints := fixture.host.Push.Hints(connect.Id(readerClientId))
	if len(hints) != 1 || hints[0].Topic != sidecar.PushTopicGkmGroup(world.groupId) || hints[0].Version != 2 {
		t.Errorf("the claim's commit hint at epoch 0 and generation 2: %d hints", len(hints))
	}
}

// A claim whose answer was lost, sent again, succeeds once: both answers are 201 and gen/<g> holds one generation;
// another rotator's claim of g then answers 412 with the winner, which it judges (§10.5's Rotate, step 4).
func TestGkmClaimLostResponseRetriedSucceedsOnce(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	_, claim := world.nextGeneration(world.admin, world.key1, nil)
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op:        sidecartest.FaultOpPut,
		KeyPrefix: GkmGenerationKey(world.groupId, 2),
		Result:    sidecartest.ApplyThenDrop,
	}); err != nil {
		t.Fatal(err)
	}
	if recorder := world.postClaim(world.adminToken, 2, claim); recorder.Code != http.StatusCreated {
		t.Fatalf("a claim whose PUT's answer was lost: %d", recorder.Code)
	}
	if recorder := world.postClaim(world.adminToken, 2, claim); recorder.Code != http.StatusCreated {
		t.Errorf("the claim sent again: %d", recorder.Code)
	}
	_, rival := world.nextGeneration(world.admin, world.key1, nil)
	recorder := world.postClaim(world.adminToken, 2, rival)
	if recorder.Code != http.StatusPreconditionFailed || !bytes.Equal(recorder.Body.Bytes(), fixture.marshal(claim)) {
		t.Errorf("a rival claim of gen/2: %d", recorder.Code)
	}
}

// A re-formed group takes no claim at or below its form's generation, which its ladder carries (QD-074(5)).
func TestGkmReformedGroupTakesNoClaimAtOrBelowItsFormsGeneration(t *testing.T) {
	world := newGkmGroupWorld(t)
	fixture := world.fixture
	world.createAndActivate()
	reformedGroupId := testId("group-reformed")
	request := &protocol.GkmGroupReformRequest{
		Form:            world.form(world.admin, reformedGroupId, &world.groupId, 2),
		GenWrap:         bytes.Repeat([]byte{5}, gkmSealedKeyByteCount),
		SealedGroupInfo: []byte("sealed"),
		CipherSuite:     gkmCipherSuiteXWing,
	}
	if recorder := fixture.serve(http.MethodPost, "/gkm/repos/"+sidecar.EvsKeyId(world.repoId)+"/forms", world.adminToken, fixture.marshal(request)); recorder.Code != http.StatusOK {
		t.Fatalf("a re-form: %d", recorder.Code)
	}
	// the new group's generations as the ladder (KEYS-M2-25) and later rotations would name them
	world.groupId = reformedGroupId
	reformedKey1, reformedRotate1 := world.firstGeneration(world.admin, reformedGroupId, fixture.clock.Now(), fakeGkmPin(10))
	fixture.put("meta-2", GkmGenerationKey(reformedGroupId, 1), fixture.marshal(reformedRotate1))
	reformedKey2, claim2 := world.nextGeneration(world.admin, reformedKey1, nil)
	if recorder := world.postClaim(world.adminToken, 2, claim2); recorder.Code != http.StatusForbidden {
		t.Errorf("a claim at the form's generation: %d", recorder.Code)
	}
	fixture.put("meta-2", GkmGenerationKey(reformedGroupId, 2), fixture.marshal(claim2))
	_, claim3 := world.nextGeneration(world.admin, reformedKey2, nil)
	if recorder := world.postClaim(world.adminToken, 3, claim3); recorder.Code != http.StatusCreated {
		t.Errorf("a claim past the form's generation: %d", recorder.Code)
	}
}

// GET .../gen?since= answers the GenRotates after since in order, up to its bound.
func TestGkmGenerationsReadAnswersInOrderUpToItsBound(t *testing.T) {
	world := newGkmGroupWorld(t)
	world.fixture.settings.GenerationsReplyMaxCount = 2
	world.fixture.start()
	world.createAndActivate()
	key2, rotate2 := world.putGeneration(world.admin, world.key1)
	_, rotate3 := world.putGeneration(world.admin, key2)
	read := func(since string) []*bridge.Signed {
		path := "/gkm/groups/" + sidecar.EvsKeyId(world.groupId) + "/gen"
		if since != "" {
			path += "?since=" + since
		}
		recorder := world.fixture.serve(http.MethodGet, path, world.adminToken, nil)
		reply := &protocol.GkmGenerationsReply{}
		if recorder.Code != http.StatusOK || proto.Unmarshal(recorder.Body.Bytes(), reply) != nil {
			t.Fatalf("GET gen since %q: %d", since, recorder.Code)
		}
		return reply.GetGenerations()
	}
	first := read("")
	if len(first) != 2 || !proto.Equal(first[0], world.rotate1) || !proto.Equal(first[1], rotate2) {
		t.Errorf("the first page: %d", len(first))
	}
	if second := read("2"); len(second) != 1 || !proto.Equal(second[0], rotate3) {
		t.Errorf("after generation 2: %d", len(second))
	}
	if third := read("3"); len(third) != 0 {
		t.Errorf("after the newest: %d", len(third))
	}
}

// QD-177, QD-156: a deposit-only token reaches the repo's drop-key route and no other, which answers the newest
// GenRotates after since; a drop key with under 7 days left hints pending to the writers at most once an hour
// (QD-065).
func TestGkmDepositScopeReachesTheDropKeyRouteAlone(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	fixture.clientOf(world.admin.sidecarId)
	depositor := fixture.newSidecar("sc-depositor", &GkmSidecarFacts{})
	fixture.auth.grant(depositor.sidecarId, world.repoId, sidecar.AclEvsDeposit)
	depositToken := fixture.token(depositor.sidecarId, repoScope(world.repoId, "deposit"))
	key2, rotate2 := world.putGeneration(world.admin, world.key1)
	dropKey := func(since string) (int, []*bridge.Signed) {
		path := "/gkm/repos/" + sidecar.EvsKeyId(world.repoId) + "/drop-key?since=" + since
		recorder := fixture.serve(http.MethodGet, path, depositToken, nil)
		reply := &protocol.GkmGenerationsReply{}
		if recorder.Code == http.StatusOK && proto.Unmarshal(recorder.Body.Bytes(), reply) != nil {
			t.Fatal("a drop-key answer that does not parse")
		}
		return recorder.Code, reply.GetGenerations()
	}
	if code, generations := dropKey("1"); code != http.StatusOK || len(generations) != 1 || !proto.Equal(generations[0], rotate2) {
		t.Errorf("the drop key after generation 1: %d", code)
	}
	groupPath := "/gkm/groups/" + sidecar.EvsKeyId(world.groupId)
	for _, probe := range []struct{ method, path string }{
		{http.MethodGet, groupPath},
		{http.MethodGet, groupPath + "/epochs"},
		{http.MethodGet, groupPath + "/gen"},
		{http.MethodGet, groupPath + "/wraps/2"},
		{http.MethodPost, groupPath + "/ack"},
		{http.MethodGet, "/gkm/welcomes"},
		{http.MethodPost, "/gkm/reader-key"},
	} {
		if recorder := fixture.serve(probe.method, probe.path, depositToken, nil); recorder.Code != http.StatusForbidden {
			t.Errorf("a deposit-only token at %s %s: %d", probe.method, probe.path, recorder.Code)
		}
	}
	// a drop key about to lapse hints the writers to renew it, once an hour
	drop := func(args *sidecar.GkmGenerationArgs) { args.DropNotAfter = fixture.clock.Now().Add(3 * 24 * time.Hour) }
	_, rotate3 := world.nextGeneration(world.admin, key2, drop)
	fixture.put("meta-2", GkmGenerationKey(world.groupId, 3), fixture.marshal(rotate3))
	countPending := func() int {
		count := 0
		for _, hint := range fixture.hints(world.admin.sidecarId) {
			if hint.GetKind() == protocol.GkmHintKind_GKM_HINT_PENDING {
				count += 1
			}
		}
		return count
	}
	dropKey("2")
	dropKey("2")
	if count := countPending(); count != 1 {
		t.Errorf("renewal hints within the hour: %d", count)
	}
	fixture.clock.Advance(fixture.settings.DropKeyRenewalHintInterval)
	depositToken = fixture.token(depositor.sidecarId, repoScope(world.repoId, "deposit"))
	dropKey("2")
	if count := countPending(); count != 2 {
		t.Errorf("renewal hints an hour later: %d", count)
	}
}
