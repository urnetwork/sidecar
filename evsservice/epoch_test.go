// EVS1-M2-16's tests: FS-4's commit half on T2. A crossing of a REMOVE generation records its due, immediate on a
// shrink and blocking creation in a general repo, batched on expiries alone; map parts stored through
// POST .../path-epoch; a block 10 min past due; and a PATH_EPOCH commit that makes the new epoch current, lists the
// old one as a source and clears the due, its refusals included: the tail naming a missed creation, missing parts,
// an old epoch after cut-over, and a fourth source.

package evsservice

import (
	"bytes"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// gen/2 of the fixture's group under cause, pinned to the newest state, and its commitment.
func (self *pushFixture) putGenerationTwo(cause sidecar.GkmCause) []byte {
	commitment := bytes.Repeat([]byte{9}, 32)
	record := &protocol.GenRotate{
		GroupId: self.check.groupId.Bytes(), RepoId: self.check.repoId.Bytes(), Generation: 2, Commitment: commitment,
		ParentCommitment: bytes.Clone(self.check.commitment), Genlink: make([]byte, 72), Cause: uint32(cause),
		Auth: self.check.auth.Pin(), TimeMs: self.clock.Now().UnixMilli(), HoldersSha256: bytes.Repeat([]byte{4}, 32),
	}
	signed, err := sidecar.SignGenRotate(record, sidecar.GkmSignFunction(checkTestSign(self.check.signingKey, self.check.signerId)))
	if err != nil {
		self.t.Fatal(err)
	}
	signedBytes, err := proto.Marshal(signed)
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := self.cluster.PutIfNoneMatch(self.ctx, sidecar.GkmGenerationPath(self.check.groupId, 2), signedBytes, nil); err != nil {
		self.t.Fatal(err)
	}
	return commitment
}

// A plan at generation 2 under commitment and the newest state's pin.
func (self *pushFixture) planAtTwo(commitment []byte) *sidecar.EvsPushPlan {
	plan := self.plan()
	plan.Generation = 2
	plan.GenerationCommitment = commitment
	plan.Auth = self.check.auth.Pin()
	return plan
}

// A write of path a's file at its next version over base.
func (self *pushFixture) write(plan *sidecar.EvsPushPlan, base uint64, labels ...string) {
	plan.Changes = append(plan.Changes, self.check.change(plan, checkTestPath(labels...), base, base+1))
}

// Commits a, then crosses to generation 2 under cause with a write of a, the state having shrunk or not: the head
// then carries the due.
func (self *pushFixture) crossRemove(shrink bool) []byte {
	plan := self.plan()
	self.create(plan, "a")
	self.requireCommitted(self.push(plan), 1)
	holdersShrunkAt := uint64(0)
	if shrink {
		holdersShrunkAt = self.check.firstView.Pin().GetVersion() + 1
	}
	self.check.appendState(holdersShrunkAt, nil)
	commitment := self.putGenerationTwo(sidecar.GkmCauseRemove)
	crossing := self.planAtTwo(commitment)
	self.write(crossing, 1, "a")
	self.requireCommitted(self.push(crossing), 2)
	return commitment
}

func TestPathEpochDueImmediateBlocksCreation(t *testing.T) {
	fixture := newPushFixture(t, nil)
	commitment := fixture.crossRemove(true)
	pathEpoch := fixture.head().Head.GetPathEpoch()
	if pathEpoch.GetDueGeneration() != 2 || !pathEpoch.GetDueBlocksCreation() || pathEpoch.GetDueByMs() != fixture.clock.Now().UnixMilli() {
		t.Fatalf("due %v", pathEpoch)
	}
	creation := fixture.planAtTwo(commitment)
	fixture.create(creation, "new")
	requireRefusal(t, fixture.push(creation), http.StatusPreconditionFailed, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH_DUE)
	fixture.clock.Advance(fixture.settings.RefusalFenceInterval)
	modification := fixture.planAtTwo(commitment)
	fixture.write(modification, 2, "a")
	fixture.requireCommitted(fixture.push(modification), 3)
	if fixture.head().Head.GetPathEpoch().GetDueGeneration() != 2 {
		t.Fatal("a later commit cleared the due")
	}
}

func TestPathEpochDueBatchedOnExpiriesAlone(t *testing.T) {
	fixture := newPushFixture(t, nil)
	commitment := fixture.crossRemove(false)
	pathEpoch := fixture.head().Head.GetPathEpoch()
	if pathEpoch.GetDueGeneration() != 2 || pathEpoch.GetDueBlocksCreation() ||
		pathEpoch.GetDueByMs() != fixture.clock.Now().Add(evsPathEpochBatchedDelay).UnixMilli() {
		t.Fatalf("due %v", pathEpoch)
	}
	creation := fixture.planAtTwo(commitment)
	fixture.create(creation, "new")
	fixture.requireCommitted(fixture.push(creation), 3)
}

// A REQUEST rotation records nothing.
func TestPathEpochNoDueOnARequestRotation(t *testing.T) {
	fixture := newPushFixture(t, nil)
	plan := fixture.plan()
	fixture.create(plan, "a")
	fixture.requireCommitted(fixture.push(plan), 1)
	fixture.check.appendState(0, nil)
	commitment := fixture.putGenerationTwo(sidecar.GkmCauseRequest)
	next := fixture.planAtTwo(commitment)
	fixture.write(next, 1, "a")
	fixture.requireCommitted(fixture.push(next), 2)
	if fixture.head().Head.GetPathEpoch().GetDueGeneration() != 0 {
		t.Fatal("a REQUEST rotation recorded a due")
	}
}

// One map part for epoch 2 over the head as it stands, moving paths, signed by the fixture's writer: its bytes
// and its map's hash.
func (self *pushFixture) mapPart(moves ...*protocol.EvsPathMove) ([]byte, []byte) {
	head := self.head()
	body, err := proto.Marshal(&protocol.EvsPathMap{
		RepoId: self.check.repoId.Bytes(), RefId: self.check.refId.Bytes(), PathEpoch: 2, Part: 1, Parts: 1, Moves: moves,
		SourceVersion: head.Version(), SourceChain: head.Head.GetChain(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	signed, err := checkTestSign(self.check.signingKey, self.check.signerId)(evsPathMapPurpose, bridge.SignedType_SIGNED_EVS_PATH_MAP, body, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	partBytes, err := proto.Marshal(signed)
	if err != nil {
		self.t.Fatal(err)
	}
	partSum := sha256.Sum256(partBytes)
	mapSum := sha256.Sum256(partSum[:])
	return partBytes, mapSum[:]
}

// One POST of a route's body under the writer's token.
func (self *pushFixture) postRoute(path string, message proto.Message) *httptest.ResponseRecorder {
	bodyBytes, err := proto.Marshal(message)
	if err != nil {
		self.t.Fatal(err)
	}
	request := httptest.NewRequestWithContext(self.ctx, http.MethodPost, "/evs/v1/repos/"+sidecar.EvsKeyId(self.check.repoId)+path, bytes.NewReader(bodyBytes))
	request.Header.Set("Authorization", "Bearer "+self.token(self.check.signerId))
	recorder := httptest.NewRecorder()
	self.engine.Handler().ServeHTTP(recorder, request)
	return recorder
}

// A move of a path in epoch 1 to its epoch-2 token path.
func pathEpochTestMove(labels ...string) *protocol.EvsPathMove {
	return &protocol.EvsPathMove{
		NewTokenPath: checkTestPath(append([]string{"epoch 2"}, labels...)...).Components(),
		Sources:      []*protocol.EvsSourcePath{{Epoch: 1, TokenPath: checkTestPath(labels...).Components()}},
		SealedName:   []byte("sealed name"),
	}
}

// The PATH_EPOCH push to epoch 2 over map, sourced at the head as it stood when the map was made, with tail.
func (self *pushFixture) pathEpochPlan(commitment []byte, mapSha256 []byte, sourceVersion uint64, sourceChain []byte, tail ...*protocol.EvsPathMove) *sidecar.EvsPushPlan {
	plan := self.planAtTwo(commitment)
	plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH)
	plan.PathEpoch = 2
	plan.PathMapSha256 = mapSha256
	plan.MapSourceVersion = sourceVersion
	plan.MapSourceChain = sourceChain
	for _, move := range tail {
		moveBytes, err := proto.Marshal(move)
		if err != nil {
			self.t.Fatal(err)
		}
		plan.TailMoves = append(plan.TailMoves, moveBytes)
	}
	return plan
}

// FS-4's commit half: the map's parts land, a creation after the map's source makes the tail name it, and the
// PATH_EPOCH commits; the head makes epoch 2 current with epoch 1 its source and the due cleared, and a push
// declaring epoch 1 after the cut-over gets 412 PATH_EPOCH.
func TestPathEpochCommitsWithItsMapAndTail(t *testing.T) {
	fixture := newPushFixture(t, nil)
	commitment := fixture.crossRemove(false)
	partBytes, mapSha256 := fixture.mapPart(pathEpochTestMove("a"))
	source := fixture.head()
	if recorder := fixture.postRoute("/path-epoch", &protocol.EvsPathMapRequest{PathMapSha256: mapSha256, Part: partBytes}); recorder.Code != http.StatusOK {
		t.Fatalf("map part answered %d (%s)", recorder.Code, refusalOf(t, recorder).GetCode())
	}
	// a retry of the part is success; another repo's part is refused
	if recorder := fixture.postRoute("/path-epoch", &protocol.EvsPathMapRequest{PathMapSha256: mapSha256, Part: partBytes}); recorder.Code != http.StatusOK {
		t.Fatalf("a retried part answered %d", recorder.Code)
	}
	// a batched epoch: creation goes on after the map's source
	creation := fixture.planAtTwo(commitment)
	fixture.create(creation, "late")
	fixture.requireCommitted(fixture.push(creation), 3)

	missing := fixture.pathEpochPlan(commitment, mapSha256, source.Version(), source.Head.GetChain())
	recorder := fixture.push(missing)
	requireRefusal(t, recorder, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT)
	if paths := refusalOf(t, recorder).GetPaths(); len(paths) != 1 {
		t.Fatalf("the tail's refusal names %d paths", len(paths))
	}

	covered := fixture.pathEpochPlan(commitment, mapSha256, source.Version(), source.Head.GetChain(), pathEpochTestMove("late"))
	fixture.requireCommitted(fixture.push(covered), 4)
	pathEpoch := fixture.head().Head.GetPathEpoch()
	if pathEpoch.GetCurrent() != 2 || len(pathEpoch.GetSources()) != 1 || pathEpoch.GetSources()[0].GetEpoch() != 1 ||
		!bytes.Equal(pathEpoch.GetSources()[0].GetMapSha256(), mapSha256) || pathEpoch.GetDueGeneration() != 0 {
		t.Fatalf("path epoch %v", pathEpoch)
	}
	if head := fixture.head(); head.Head.GetFoldedThrough() != 3 {
		t.Fatalf("folded through %d after a PATH_EPOCH over version 3", head.Head.GetFoldedThrough())
	}
	old := fixture.planAtTwo(commitment)
	fixture.write(old, 2, "a")
	requireRefusal(t, fixture.push(old), http.StatusPreconditionFailed, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH)
}

// A PATH_EPOCH whose map's parts do not stand gets 409 MAP_PARTS, recorded.
func TestPathEpochRefusesMissingParts(t *testing.T) {
	fixture := newPushFixture(t, nil)
	commitment := fixture.crossRemove(false)
	source := fixture.head()
	_, mapSha256 := fixture.mapPart()
	plan := fixture.pathEpochPlan(commitment, mapSha256, source.Version(), source.Head.GetChain())
	requireRefusal(t, fixture.push(plan), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_MAP_PARTS)
	if len(fixture.head().Head.GetRefused()) == 0 {
		t.Fatal("MAP_PARTS was not recorded")
	}
}

// §11.6's block row: nothing due answers 412 PATH_EPOCH; a block before 10 min past due 429 WAIT; then one head CAS
// raising only the fence sets block_until_ms, creation answering 412 PATH_EPOCH_DUE until it passes; another within
// 10 min 429 WAIT.
func TestPathEpochBlock(t *testing.T) {
	fixture := newPushFixture(t, nil)
	plan := fixture.plan()
	fixture.create(plan, "a")
	fixture.requireCommitted(fixture.push(plan), 1)
	block := &protocol.EvsPathEpochBlockRequest{RefId: fixture.check.refId.Bytes(), Ms: 60 * 1000}
	requireRefusal(t, fixture.postRoute("/path-epoch/block", block), http.StatusPreconditionFailed, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH)

	// a batched due, 24 h out
	fixture2 := newPushFixture(t, nil)
	commitment := fixture2.crossRemove(false)
	block.RefId = fixture2.check.refId.Bytes()
	requireRefusal(t, fixture2.postRoute("/path-epoch/block", block), http.StatusTooManyRequests, protocol.EvsRefusalCode_EVS_REFUSAL_WAIT)
	fixture2.clock.Advance(evsPathEpochBatchedDelay + evsPathEpochBlockAfterDue)
	before := fixture2.head()
	if recorder := fixture2.postRoute("/path-epoch/block", block); recorder.Code != http.StatusOK {
		t.Fatalf("block answered %d (%s)", recorder.Code, refusalOf(t, recorder).GetCode())
	}
	after := fixture2.head()
	if after.Version() != before.Version() || after.Head.GetFence() != before.Head.GetFence()+1 ||
		after.Head.GetPathEpoch().GetBlockUntilMs() != fixture2.clock.Now().Add(time.Minute).UnixMilli() {
		t.Fatalf("block head %v", after.Head.GetPathEpoch())
	}
	creation := fixture2.planAtTwo(commitment)
	fixture2.create(creation, "blocked")
	requireRefusal(t, fixture2.push(creation), http.StatusPreconditionFailed, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH_DUE)
	fixture2.clock.Advance(time.Minute + time.Second)
	requireRefusal(t, fixture2.postRoute("/path-epoch/block", block), http.StatusTooManyRequests, protocol.EvsRefusalCode_EVS_REFUSAL_WAIT)
	unblocked := fixture2.planAtTwo(commitment)
	fixture2.create(unblocked, "unblocked")
	fixture2.requireCommitted(fixture2.push(unblocked), 3)
}

// The fourth source waits: 412 EPOCH_SOURCES_FULL, recorded.
func TestPathEpochRefusesAFourthSource(t *testing.T) {
	fixture := newPushFixture(t, nil)
	commitment := fixture.crossRemove(false)
	// three sources stand, as three earlier epochs' copies have not drained
	head := fixture.head()
	next := CloneEvsHead(head.Head)
	next.Fence += 1
	next.PathEpoch.Sources = []*protocol.EvsEpochSource{{Epoch: 1}, {Epoch: 1}, {Epoch: 1}}
	if _, err := fixture.engine.heads.Commit(fixture.paidContext(), fixture.cluster, fixture.check.repoId, fixture.check.refId, head, next); err != nil {
		t.Fatal(err)
	}
	source := fixture.head()
	partBytes, mapSha256 := fixture.mapPart()
	fixture.postRoute("/path-epoch", &protocol.EvsPathMapRequest{PathMapSha256: mapSha256, Part: partBytes})
	plan := fixture.pathEpochPlan(commitment, mapSha256, source.Version(), source.Head.GetChain())
	requireRefusal(t, fixture.push(plan), http.StatusPreconditionFailed, protocol.EvsRefusalCode_EVS_REFUSAL_EPOCH_SOURCES_FULL)
}
