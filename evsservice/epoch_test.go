// EVS1-M2-16's tests: FS-4's commit half on T2. A crossing of a REMOVE generation records its due, immediate on a
// shrink and blocking creation in a general repo, batched on expiries alone; map parts stored through
// POST .../path-epoch; a block 10 min past due; and a PATH_EPOCH commit that makes the new epoch current, lists the
// old one as a source and clears the due, its refusals included: the tail naming a missed creation, missing parts,
// an old epoch after cut-over, and a fourth source.

package evsservice

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// gen/2 of the fixture's group under cause, pinned to the newest state, and its commitment.
func (self *pushFixture) putGenerationTwo(cause sidecar.GkmCause) []byte {
	return self.putGenerationAt(2, cause, self.check.commitment)
}

// gen/<generation> of the fixture's group under cause, after the generation whose commitment is parent, pinned to the
// newest state, and its commitment.
func (self *pushFixture) putGenerationAt(generation uint64, cause sidecar.GkmCause, parent []byte) []byte {
	commitment := bytes.Repeat([]byte{byte(7 + generation)}, 32)
	record := &protocol.GenRotate{
		GroupId: self.check.groupId.Bytes(), RepoId: self.check.repoId.Bytes(), Generation: generation, Commitment: commitment,
		ParentCommitment: bytes.Clone(parent), Genlink: make([]byte, 72), Cause: uint32(cause),
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
	if _, err := self.cluster.PutIfNoneMatch(self.ctx, sidecar.GkmGenerationPath(self.check.groupId, generation), signedBytes, nil); err != nil {
		self.t.Fatal(err)
	}
	return commitment
}

// A plan at generation 2 under commitment and the newest state's pin.
func (self *pushFixture) planAtTwo(commitment []byte) *sidecar.EvsPushPlan {
	return self.planAt(2, commitment)
}

// A plan at generation under commitment and the newest state's pin, in path epoch 1.
func (self *pushFixture) planAt(generation uint64, commitment []byte) *sidecar.EvsPushPlan {
	plan := self.plan()
	plan.Generation = generation
	plan.GenerationCommitment = commitment
	plan.Auth = self.check.auth.Pin()
	return plan
}

// As planAt, in the head's current path epoch, carrying source paths while the head lists sources.
func (self *pushFixture) planOnHead(generation uint64, commitment []byte) *sidecar.EvsPushPlan {
	plan := self.planAt(generation, commitment)
	if head := self.head(); !head.Absent() {
		plan.PathEpoch = EvsHeadCurrentEpoch(head.Head)
		plan.SourcesStand = 0 < len(head.Head.GetPathEpoch().GetSources())
	}
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
	return partBytes, sidecar.EvsPathMapSha256([][]byte{partBytes})
}

// A map to epoch over the head at sourceVersion under sourceChain, one part per list of moves, signed by the
// fixture's writer: the parts' bytes and the map's hash over them (DESIGN-DETAILS 9.2.2).
func (self *pushFixture) mapPartsAt(epoch uint64, sourceVersion uint64, sourceChain []byte, partMoves ...[]*protocol.EvsPathMove) ([][]byte, []byte) {
	parts := [][]byte{}
	for i, moves := range partMoves {
		moves = slices.Clone(moves)
		slices.SortFunc(moves, func(a *protocol.EvsPathMove, b *protocol.EvsPathMove) int {
			return epochTestTokenPath(a.GetNewTokenPath()).Compare(epochTestTokenPath(b.GetNewTokenPath()))
		})
		body, err := proto.Marshal(&protocol.EvsPathMap{
			RepoId: self.check.repoId.Bytes(), RefId: self.check.refId.Bytes(), PathEpoch: epoch, Part: uint32(i + 1),
			Parts: uint32(len(partMoves)), Moves: moves, SourceVersion: sourceVersion, SourceChain: sourceChain,
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
		parts = append(parts, partBytes)
	}
	return parts, sidecar.EvsPathMapSha256(parts)
}

// A move's token path, for sorting.
func epochTestTokenPath(components [][]byte) sidecar.EvsTokenPath {
	tokenPath, _ := sidecar.ParseEvsTokenPath(components)
	return tokenPath
}

// Uploads a map's parts under mapSha256 through POST .../path-epoch, each answering 200.
func (self *pushFixture) uploadParts(parts [][]byte, mapSha256 []byte) {
	self.t.Helper()
	for i, partBytes := range parts {
		if recorder := self.postRoute("/path-epoch", &protocol.EvsPathMapRequest{PathMapSha256: mapSha256, Part: partBytes}); recorder.Code != http.StatusOK {
			self.t.Fatalf("map part %d answered %d (%s)", i+1, recorder.Code, refusalOf(self.t, recorder).GetCode())
		}
	}
}

// The PATH_EPOCH push to epoch at generation under commitment over a map, sourced at sourceVersion under
// sourceChain, with tail.
func (self *pushFixture) pathEpochPlanAt(epoch uint64, generation uint64, commitment []byte, mapSha256 []byte, sourceVersion uint64, sourceChain []byte, tail ...*protocol.EvsPathMove) *sidecar.EvsPushPlan {
	plan := self.planAt(generation, commitment)
	plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH)
	plan.PathEpoch = epoch
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

// A move of a path from its token path in each of the from epochs to its token path in epoch, the paths labeled as
// epochPath labels them.
func pathEpochTestMoveAt(epoch uint64, from []uint64, labels ...string) *protocol.EvsPathMove {
	move := &protocol.EvsPathMove{NewTokenPath: epochPath(epoch, labels...).Components(), SealedName: []byte("sealed name")}
	for _, source := range from {
		move.Sources = append(move.Sources, &protocol.EvsSourcePath{Epoch: source, TokenPath: epochPath(source, labels...).Components()})
	}
	return move
}

// A path's token path in epoch as these tests name it: the labels in epoch 1, and behind "epoch <n>" past it, as
// pathEpochTestMove names epoch 2's.
func epochPath(epoch uint64, labels ...string) sidecar.EvsTokenPath {
	if epoch <= 1 {
		return checkTestPath(labels...)
	}
	return checkTestPath(append([]string{fmt.Sprintf("epoch %d", epoch)}, labels...)...)
}

// The encoded source path of a path in epoch, as a change names it while sources stand.
func epochSourcePath(t *testing.T, epoch uint64, labels ...string) []byte {
	encoded, err := proto.Marshal(&protocol.EvsSourcePath{Epoch: epoch, TokenPath: epochPath(epoch, labels...).Components()})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
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

// An immediate due blocks creation until its epoch lands: once the PATH_EPOCH commits, the due and its block are
// gone and a creation in the new epoch commits.
func TestPathEpochClearsAnImmediateDue(t *testing.T) {
	fixture := newPushFixture(t, nil)
	commitment := fixture.crossRemove(true)
	source := fixture.head()
	partBytes, mapSha256 := fixture.mapPart(pathEpochTestMove("a"))
	if recorder := fixture.postRoute("/path-epoch", &protocol.EvsPathMapRequest{PathMapSha256: mapSha256, Part: partBytes}); recorder.Code != http.StatusOK {
		t.Fatalf("map part answered %d", recorder.Code)
	}
	fixture.requireCommitted(fixture.push(fixture.pathEpochPlan(commitment, mapSha256, source.Version(), source.Head.GetChain())), 3)
	pathEpoch := fixture.head().Head.GetPathEpoch()
	if pathEpoch.GetCurrent() != 2 || pathEpoch.GetDueGeneration() != 0 || pathEpoch.GetDueBlocksCreation() || pathEpoch.GetBlockUntilMs() != 0 {
		t.Fatalf("path epoch %v", pathEpoch)
	}
	creation := fixture.planAtTwo(commitment)
	creation.PathEpoch = 2
	creation.SourcesStand = true
	fixture.create(creation, "epoch 2", "new")
	fixture.requireCommitted(fixture.push(creation), 4)
}

// DESIGN-DETAILS 9.2.6's crossing creation: the first push across an immediate removal that creates a path gets 412
// PATH_EPOCH_DUE, recorded, and its refusal's fence write records the due as its commit would have, so the next
// creation meets the due on the head; a retry of the same statement is answered from the record; a push across it
// that only modifies commits.
func TestPathEpochCrossingCreationIsRefusedAndRecordsTheDue(t *testing.T) {
	fixture := newPushFixture(t, nil)
	plan := fixture.plan()
	fixture.create(plan, "a")
	fixture.requireCommitted(fixture.push(plan), 1)
	fixture.check.appendState(fixture.check.firstView.Pin().GetVersion()+1, nil)
	commitment := fixture.putGenerationTwo(sidecar.GkmCauseRemove)
	refusedAt := fixture.clock.Now()

	crossing := fixture.planAtTwo(commitment)
	fixture.create(crossing, "new")
	recorder := fixture.push(crossing)
	requireRefusal(t, recorder, http.StatusPreconditionFailed, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH_DUE)
	if paths := refusalOf(t, recorder).GetPaths(); len(paths) != 1 {
		t.Fatalf("the crossing creation's refusal names %d paths", len(paths))
	}
	head := fixture.head()
	pathEpoch := head.Head.GetPathEpoch()
	if head.Version() != 1 || len(head.Head.GetRefused()) == 0 {
		t.Fatalf("head at %d with %d refusal bytes: the refusal was not recorded", head.Version(), len(head.Head.GetRefused()))
	}
	if pathEpoch.GetDueGeneration() != 2 || !pathEpoch.GetDueBlocksCreation() || pathEpoch.GetDueByMs() != refusedAt.UnixMilli() || pathEpoch.GetCurrent() != 1 {
		t.Fatalf("the refusal's fence wrote path epoch %v", pathEpoch)
	}

	// the same statement again: the record answers
	again := fixture.post(fixture.token(fixture.check.signerId), fixture.body(crossing))
	requireRefusal(t, again, http.StatusPreconditionFailed, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH_DUE)
	if !refusalOf(t, again).GetRecorded() {
		t.Fatal("a retry of the refused statement was not answered from the record")
	}

	modification := fixture.planAtTwo(commitment)
	fixture.write(modification, 1, "a")
	fixture.requireCommitted(fixture.push(modification), 2)
	if due := fixture.head().Head.GetPathEpoch(); due.GetDueGeneration() != 2 || !due.GetDueBlocksCreation() {
		t.Fatalf("a modification after the refusal left path epoch %v", due)
	}
}

// The crossing creation blocks only where an immediate due does: a mailbox repo's crossing push creates and commits,
// recording its due.
func TestPathEpochCrossingCreationWhereCreationIsNotBlocked(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.putRepo(protocol.RepoKind_REPO_KIND_MAILBOX, protocol.EvsRepoState_EVS_REPO_ACTIVE)
	plan := fixture.plan()
	fixture.create(plan, "a")
	fixture.requireCommitted(fixture.push(plan), 1)
	fixture.check.appendState(fixture.check.firstView.Pin().GetVersion()+1, nil)
	commitment := fixture.putGenerationTwo(sidecar.GkmCauseRemove)
	crossing := fixture.planAtTwo(commitment)
	fixture.create(crossing, "new")
	fixture.requireCommitted(fixture.push(crossing), 2)
	if pathEpoch := fixture.head().Head.GetPathEpoch(); pathEpoch.GetDueGeneration() != 2 || pathEpoch.GetDueBlocksCreation() {
		t.Fatalf("a mailbox's crossing recorded %v", pathEpoch)
	}
}

// DESIGN-DETAILS 9.2.6's first push (QD-632): on a ref with no head across an immediate removal its pin covers, a first
// push naming the crossed generation commits with the head in that epoch, no source and no due; one naming 1 crosses
// the removal and answers 412 PATH_EPOCH_DUE, recorded in a placeholder head that carries no due, so the next attempt
// computes it again; across a batched removal a first push naming 1 commits and records the due; and a first push
// naming an epoch past its generation is 412 PATH_EPOCH.
func TestPathEpochARefsFirstPushNamesTheEpochItStartsIn(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.check.appendState(fixture.check.firstView.Pin().GetVersion()+1, nil)
	commitment := fixture.putGenerationTwo(sidecar.GkmCauseRemove)

	low := fixture.planAtTwo(commitment)
	fixture.create(low, "a")
	requireRefusal(t, fixture.push(low), http.StatusPreconditionFailed, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH_DUE)
	head := fixture.head()
	if head.Version() != 0 || head.Head.GetPathEpoch().GetDueGeneration() != 0 || len(head.Head.GetRefused()) == 0 {
		t.Fatalf("a first push across the removal left head %d with path epoch %v and %d refusal bytes", head.Version(), head.Head.GetPathEpoch(), len(head.Head.GetRefused()))
	}
	past := fixture.planAtTwo(commitment)
	past.PathEpoch = 3
	fixture.create(past, "a")
	requireRefusal(t, fixture.push(past), http.StatusPreconditionFailed, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH)

	crossed := fixture.planAtTwo(commitment)
	crossed.PathEpoch = 2
	fixture.create(crossed, "a")
	fixture.requireCommitted(fixture.push(crossed), 1)
	if pathEpoch := fixture.head().Head.GetPathEpoch(); pathEpoch.GetCurrent() != 2 || len(pathEpoch.GetSources()) != 0 || pathEpoch.GetDueGeneration() != 0 {
		t.Fatalf("the first push in the crossed generation's epoch left path epoch %v", pathEpoch)
	}

	batched := newPushFixture(t, nil)
	batchedCommitment := batched.putGenerationTwo(sidecar.GkmCauseRemove)
	plan := batched.planAtTwo(batchedCommitment)
	batched.create(plan, "a")
	batched.requireCommitted(batched.push(plan), 1)
	if pathEpoch := batched.head().Head.GetPathEpoch(); pathEpoch.GetCurrent() != 1 || pathEpoch.GetDueGeneration() != 2 || pathEpoch.GetDueBlocksCreation() {
		t.Fatalf("a first push across a batched removal left path epoch %v", pathEpoch)
	}
}

// An overlay's first push (DESIGN-DETAILS 9.2.6): its base ref created in epoch 2, the overlay's first push in epoch 2
// commits with its head in epoch 2, and one in epoch 1 is 412 PATH_EPOCH; while the base ref's head blocks creation, a
// creating first push of the overlay is 412 PATH_EPOCH_DUE.
func TestPathEpochAnOverlaysFirstPushTakesItsBaseRefsEpoch(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.check.appendState(fixture.check.firstView.Pin().GetVersion()+1, nil)
	commitment := fixture.putGenerationTwo(sidecar.GkmCauseRemove)
	baseRefId, overlayRefId := testId("base ref"), testId("overlay ref")
	atTwo := func(plan *sidecar.EvsPushPlan, epoch uint64) *sidecar.EvsPushPlan {
		plan.Generation, plan.GenerationCommitment, plan.Auth, plan.PathEpoch = 2, commitment, fixture.check.auth.Pin(), epoch
		return plan
	}
	fixture.requireCommitted(fixture.push(atTwo(fixture.gitPlanOn(baseRefId, "base-file", 1), 2)), 1)
	fixture.awaitStepEights()
	base := &protocol.EvsOverlay{RefId: baseRefId.Bytes(), Version: 1}

	low := atTwo(fixture.gitPlanOn(overlayRefId, "overlay-file", 2), 1)
	low.Base = base
	requireRefusal(t, fixture.push(low), http.StatusPreconditionFailed, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH)
	inBase := atTwo(fixture.gitPlanOn(overlayRefId, "overlay-file", 2), 2)
	inBase.Base = base
	fixture.requireCommitted(fixture.push(inBase), 1)
	if pathEpoch := fixture.headOf(overlayRefId).Head.GetPathEpoch(); pathEpoch.GetCurrent() != 2 || pathEpoch.GetDueGeneration() != 0 {
		t.Fatalf("the overlay's head starts in %v", pathEpoch)
	}

	// a second overlay of a base whose head blocks creation
	fixture.rewriteHeadOf(baseRefId, func(head *protocol.EvsHead) {
		head.PathEpoch.BlockUntilMs = fixture.clock.Now().Add(time.Hour).UnixMilli()
	})
	blocked := atTwo(fixture.gitPlanOn(testId("second overlay"), "second-file", 2), 2)
	blocked.Base = base
	requireRefusal(t, fixture.push(blocked), http.StatusPreconditionFailed, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH_DUE)
}

// 5e's once line (DESIGN-DETAILS 9.2.6): a push planned on no head, on a ref that has one, is 409 before its epoch is
// compared: BASE_STALE in file mode, non-fast-forward in git mode.
func TestPathEpochAPushPlannedOnNoHeadIsRefusedOnARefThatHasOne(t *testing.T) {
	fixture := newPushFixture(t, nil)
	plan := fixture.plan()
	fixture.create(plan, "a")
	fixture.requireCommitted(fixture.push(plan), 1)
	stale := fixture.plan()
	stale.BaseVersion, stale.BaseChain, stale.PathEpoch = 0, sidecar.EvsChainStart(fixture.check.repoId, fixture.check.refId), 7
	fixture.create(stale, "b")
	requireRefusal(t, fixture.push(stale), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE)

	gitRefId := testId("git ref")
	fixture.requireCommitted(fixture.push(fixture.gitPlanOn(gitRefId, "x", 1)), 1)
	fixture.awaitStepEights()
	gitStale := fixture.gitPlanOn(testId("unused"), "y", 1)
	gitStale.RefId, gitStale.PathEpoch = gitRefId, 7
	requireRefusal(t, fixture.push(gitStale), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_NON_FAST_FORWARD)
}

// PathEpochTwin-StaleFirstPush end to end (DESIGN-DETAILS 9.2.3): A, holding the removal, plans the ref's first push in
// epoch 2; B, not yet told, creates the same file in epoch 1 and lands first; a mapper cuts the ref over to epoch 2,
// and the copy has not run. A's push, planned on no head, is refused 409 before its epoch is compared, and A plans
// again on the head. The twin: with the once line off, A's creation commits over B's standing file, which no change of
// A's names in epoch 1, so evs finds no entry for it.
func TestPathEpochStaleFirstPushIsRefusedWhereItsTwinCreatesOverAFile(t *testing.T) {
	fixture := newPushFixture(t, nil)
	// B, not yet told of the removal, creates a in epoch 1 at generation 1 and lands first
	b := fixture.plan()
	fixture.create(b, "a")
	fixture.requireCommitted(fixture.push(b), 1)
	fixture.awaitStepEights()
	// A holds the removal and planned the ref's first push on no head, in epoch 2
	fixture.check.appendState(fixture.check.firstView.Pin().GetVersion()+1, nil)
	commitment := fixture.putGenerationTwo(sidecar.GkmCauseRemove)
	planned := fixture.planAtTwo(commitment)
	planned.PathEpoch, planned.BaseVersion, planned.BaseChain = 2, 0, sidecar.EvsChainStart(fixture.check.repoId, fixture.check.refId)
	planned.Changes = append(planned.Changes, fixture.check.change(planned, epochPath(2, "a"), 0, 1))
	// a mapper cuts the ref over to epoch 2, and the copy has not run
	fixture.cutOverToEpochTwo(commitment, pathEpochTestMoveAt(2, []uint64{1}, "a"))
	if pathEpoch := fixture.head().Head.GetPathEpoch(); pathEpoch.GetCurrent() != 2 || len(pathEpoch.GetSources()) != 1 {
		t.Fatalf("the cut-over: %v", pathEpoch)
	}
	requireRefusal(t, fixture.push(planned), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE)

	// the twin, a fresh statement of the same plan
	evsFirstPushOnceSkipped = true
	defer func() { evsFirstPushOnceSkipped = false }()
	twin := fixture.planAtTwo(commitment)
	twin.PathEpoch, twin.BaseVersion, twin.BaseChain = 2, 0, sidecar.EvsChainStart(fixture.check.repoId, fixture.check.refId)
	twin.Changes = append(twin.Changes, fixture.check.change(twin, epochPath(2, "a"), 0, 1))
	fixture.requireCommitted(fixture.push(twin), 3)
	if fixture.entryAt(1, "a").Absent() {
		t.Fatal("B's file in epoch 1 is gone")
	}
}

// DESIGN-DETAILS 9.1 D and the between fence: two mappers map from one head in epoch 1, a to generation 2 and b to
// generation 3. a's PATH_EPOCH commits; b's, whose source is of epoch 1 and no longer current, gets 409 MAP_SOURCE,
// final, recorded nowhere; b maps again from the new head and commits, epoch 3 current over sources 2 and 1.
func TestPathEpochBetweenFenceRefusesTheSecondOfTwoMappers(t *testing.T) {
	fixture := newPushFixture(t, nil)
	commitmentTwo := fixture.crossRemove(false)
	commitmentThree := fixture.putGenerationAt(3, sidecar.GkmCauseRemove, commitmentTwo)
	source := fixture.head()

	partsTwo, mapTwo := fixture.mapPartsAt(2, source.Version(), source.Head.GetChain(), []*protocol.EvsPathMove{pathEpochTestMoveAt(2, []uint64{1}, "a")})
	fixture.uploadParts(partsTwo, mapTwo)
	partsThree, mapThree := fixture.mapPartsAt(3, source.Version(), source.Head.GetChain(), []*protocol.EvsPathMove{pathEpochTestMoveAt(3, []uint64{1}, "a")})
	fixture.uploadParts(partsThree, mapThree)

	fixture.requireCommitted(fixture.push(fixture.pathEpochPlanAt(2, 2, commitmentTwo, mapTwo, source.Version(), source.Head.GetChain())), 3)
	refusedBefore := fixture.head().Head.GetRefused()
	stale := fixture.pathEpochPlanAt(3, 3, commitmentThree, mapThree, source.Version(), source.Head.GetChain())
	requireRefusal(t, fixture.push(stale), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_MAP_SOURCE)
	if head := fixture.head(); head.Version() != 3 || !bytes.Equal(head.Head.GetRefused(), refusedBefore) || EvsHeadCurrentEpoch(head.Head) != 2 {
		t.Fatalf("the refused map left head %d at epoch %d, refused %x", head.Version(), EvsHeadCurrentEpoch(head.Head), head.Head.GetRefused())
	}

	// b maps again from the epoch it now finds: the path in epoch 2, and in epoch 1 where it stood before
	again := fixture.head()
	partsAgain, mapAgain := fixture.mapPartsAt(3, again.Version(), again.Head.GetChain(), []*protocol.EvsPathMove{pathEpochTestMoveAt(3, []uint64{2, 1}, "a")})
	fixture.uploadParts(partsAgain, mapAgain)
	fixture.requireCommitted(fixture.push(fixture.pathEpochPlanAt(3, 3, commitmentThree, mapAgain, again.Version(), again.Head.GetChain())), 4)
	pathEpoch := fixture.head().Head.GetPathEpoch()
	if pathEpoch.GetCurrent() != 3 || len(pathEpoch.GetSources()) != 2 || pathEpoch.GetSources()[0].GetEpoch() != 2 ||
		pathEpoch.GetSources()[1].GetEpoch() != 1 || !bytes.Equal(pathEpoch.GetSources()[0].GetMapSha256(), mapAgain) {
		t.Fatalf("path epoch %v", pathEpoch)
	}
}

// DESIGN-DETAILS 9.2.6's source rule: a map whose source has left the window commits from the log page just below it,
// C_S carried from the page's first chain; a source two pages below the window gets 409 MAP_SOURCE, and so does a
// source past the head, or under another chain.
func TestPathEpochSourceBelowTheWindow(t *testing.T) {
	fixture := newPushFixture(t, nil)
	commitment := fixture.crossRemove(false)
	chains := map[uint64][]byte{2: fixture.head().Head.GetChain()}
	for version := uint64(3); EvsHeadWindowFirstVersion(fixture.head().Head) < 2*EvsLogPageVersionCount; version += 1 {
		plan := fixture.planAtTwo(commitment)
		fixture.write(plan, version-1, "a")
		fixture.requireCommitted(fixture.push(plan), version)
		chains[version] = fixture.head().Head.GetChain()
	}
	head := fixture.head()
	if first := EvsHeadWindowFirstVersion(head.Head); first != 2*EvsLogPageVersionCount {
		t.Fatalf("the window starts at %d", first)
	}
	refuse := func(name string, sourceVersion uint64, sourceChain []byte) {
		t.Helper()
		parts, mapSha256 := fixture.mapPartsAt(2, sourceVersion, sourceChain, []*protocol.EvsPathMove{pathEpochTestMoveAt(2, []uint64{1}, "a")})
		fixture.uploadParts(parts, mapSha256)
		recorder := fixture.push(fixture.pathEpochPlanAt(2, 2, commitment, mapSha256, sourceVersion, sourceChain))
		if recorder.Code != http.StatusConflict || refusalOf(t, recorder).GetCode() != protocol.EvsRefusalCode_EVS_REFUSAL_MAP_SOURCE {
			t.Fatalf("%s: %d (%s), want 409 MAP_SOURCE", name, recorder.Code, refusalOf(t, recorder).GetCode())
		}
	}
	refuse("a source two pages below the window", 10, chains[10])
	refuse("a source one page below under another chain", 100, chains[99])
	refuse("a source past the head", head.Version()+1, head.Head.GetChain())
	if fixture.head().Version() != head.Version() {
		t.Fatal("a refused PATH_EPOCH committed")
	}

	parts, mapSha256 := fixture.mapPartsAt(2, 100, chains[100], []*protocol.EvsPathMove{pathEpochTestMoveAt(2, []uint64{1}, "a")})
	fixture.uploadParts(parts, mapSha256)
	fixture.requireCommitted(fixture.push(fixture.pathEpochPlanAt(2, 2, commitment, mapSha256, 100, chains[100])), head.Version()+1)
	if pathEpoch := fixture.head().Head.GetPathEpoch(); pathEpoch.GetCurrent() != 2 || len(pathEpoch.GetSources()) != 1 {
		t.Fatalf("path epoch %v", pathEpoch)
	}
}

// A map part posted under a hash whose key already holds another part gets 409 MAP_SOURCE: the mapper maps again
// under a new hash, where MAP_PARTS would only have it upload again.
func TestPathMapPartUnderAnotherPartsKeyAnswersMapSource(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.crossRemove(false)
	source := fixture.head()
	parts, mapSha256 := fixture.mapPartsAt(2, source.Version(), source.Head.GetChain(), []*protocol.EvsPathMove{pathEpochTestMoveAt(2, []uint64{1}, "a")})
	fixture.uploadParts(parts, mapSha256)
	other, _ := fixture.mapPartsAt(2, source.Version(), source.Head.GetChain(), []*protocol.EvsPathMove{pathEpochTestMoveAt(2, []uint64{1}, "b")})
	recorder := fixture.postRoute("/path-epoch", &protocol.EvsPathMapRequest{PathMapSha256: mapSha256, Part: other[0]})
	requireRefusal(t, recorder, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_MAP_SOURCE)
	if !sidecar.IsEvsMapSource(&sidecar.EvsError{Status: recorder.Code, Code: refusalOf(t, recorder).GetCode()}) {
		t.Fatal("the client does not read MAP_SOURCE as such")
	}
}

// Writes ref's head again with mutate applied under a raised fence, as a fence write such as the block's does.
func (self *pushFixture) rewriteHeadOf(refId sidecar.Id, mutate func(head *protocol.EvsHead)) {
	self.t.Helper()
	prior := self.headOf(refId)
	next := CloneEvsHead(prior.Head)
	mutate(next)
	next.Fence = prior.Head.GetFence() + 1
	next.FenceMs = self.clock.Now().UnixMilli()
	if _, err := self.engine.heads.Commit(self.ctx, self.cluster, self.check.repoId, refId, prior, next); err != nil {
		self.t.Fatal(err)
	}
}
