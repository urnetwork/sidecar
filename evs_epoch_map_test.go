// EVS1-M2-47's tests (DESIGN-DETAILS 9.6's mapper row, FS-4's mapper half) over the stand-in evs, whose push route
// holds map parts and commits a PATH_EPOCH by 5e's rules (evs_plan_test.go): a writer that rotated maps a ref whose
// epoch is due, from the listed index, its moves each path's tokens in the new epoch with its name sealed there and the
// root first; a kill between parts resumes from the job record, uploading the rest byte-equal; a creation after the
// map's source reaches the tail; a refused tail asks again; a batched due with two sources builds nothing; and a job
// past MapMaxAge is abandoned and built again.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A writer with a small tree in epoch 1, holding a REMOVE generation 2 whose crossing is immediate, that rotated to it
// by its own write, so its mapper starts at once.
func newEvsTestMapperWriter(t *testing.T) *evsTestWriter {
	t.Helper()
	writer := newEvsTestWriter(t)
	writer.server.uploadMs = writer.test.clock.Now().UnixMilli()
	for _, path := range []string{"a", "d/b", "d/c"} {
		if _, err := writer.write(t, path, []byte("content of "+path)); err != nil {
			t.Fatal(err)
		}
	}
	writer.gkm.newest = 2
	writer.world.generation = 2
	writer.gkm.causes[2] = GkmCauseRemove
	writer.gkm.auths[1] = 3
	writer.world.config.repo.HoldersShrunkAt = 5
	// a modification at the new generation: this device's EnsureWritable returned the REMOVE generation, and the push
	// crossing it recorded the immediate due, as evs's 5e does
	if _, err := writer.write(t, "a", []byte("a again")); err != nil {
		t.Fatal(err)
	}
	writer.world.due = &protocol.EvsPathEpoch{DueGeneration: 2, DueBlocksCreation: true, DueByMs: writer.test.clock.Now().UnixMilli()}
	return writer
}

// Opens every move of a committed map's parts in order.
func evsTestMapMoves(t *testing.T, parts [][]byte) []*protocol.EvsPathMove {
	t.Helper()
	moves := []*protocol.EvsPathMove{}
	for _, part := range parts {
		_, pathMap, err := ParseEvsPathMap(part)
		if err != nil {
			t.Fatal(err)
		}
		moves = append(moves, pathMap.GetMoves()...)
	}
	return moves
}

// The mapper maps the ref: one PATH_EPOCH to epoch 2 with epoch 1 its source; its map moves the root first, then every
// path, each to its token path in epoch 2 from its token path in epoch 1, its name sealed in epoch 2; the files read
// after it from the source.
func TestEvsMapperMapsAndCommits(t *testing.T) {
	writer := newEvsTestMapperWriter(t)
	if err := writer.repo.TickMapper(context.Background(), writer.world.refId); err != nil {
		t.Fatalf("the tick: %v", err)
	}
	if writer.world.currentEpoch != 2 || len(writer.world.sourceEpochs) != 1 || len(writer.server.committedMap) != 1 {
		t.Fatalf("epoch %d, sources %v, %d maps", writer.world.currentEpoch, writer.world.sourceEpochs, len(writer.server.committedMap))
	}
	moves := evsTestMapMoves(t, writer.server.committedMap[0])
	if len(moves) != 5 || len(moves[0].GetNewTokenPath()) != 0 || len(moves[0].GetSealedName()) != 0 {
		t.Fatalf("%d moves, the first of %d components", len(moves), len(moves[0].GetNewTokenPath()))
	}
	keys := evsTestKeys(t, writer.world.repoId, 2)
	for _, path := range []string{"a", "d", "d/b", "d/c"} {
		newPath := writer.world.tokensAt(path, 2)
		found := false
		for _, move := range moves {
			tokenPath, _ := ParseEvsChangedTokenPath(move.GetNewTokenPath())
			if !tokenPath.Equal(newPath) {
				continue
			}
			found = true
			sourcePath, _ := ParseEvsChangedTokenPath(move.GetSources()[0].GetTokenPath())
			if move.GetSources()[0].GetEpoch() != 1 || !sourcePath.Equal(writer.world.tokensAt(path, 1)) {
				t.Errorf("%s's sources %v", path, move.GetSources())
			}
			_, name := evsSplitParent(path)
			opened, err := EvsNameOpen(keys.manifest, evsTestPathKey(t, writer.world.repoId, 2), newPath.Parent(), newPath.Last(), move.GetSealedName())
			if err != nil || !bytes.Equal(opened, name) {
				t.Errorf("%s's sealed name: %q %v", path, opened, err)
			}
		}
		if !found {
			t.Errorf("no move of %s", path)
		}
	}
	for i := 1; i < len(moves); i += 1 {
		previous, _ := ParseEvsChangedTokenPath(moves[i-1].GetNewTokenPath())
		next, _ := ParseEvsChangedTokenPath(moves[i].GetNewTokenPath())
		if 0 <= bytes.Compare(previous.Bytes(), next.Bytes()) {
			t.Errorf("moves out of order at %d", i)
		}
	}
	if job, err := writer.repo.loadMapJob(writer.world.refId); err != nil || job != nil {
		t.Errorf("a job left after the commit: %v %v", job, err)
	}
	if read, _, err := writer.read(t, "d/b"); err != nil || string(read) != "content of d/b" {
		t.Fatalf("d/b after the cut-over: %q %v", read, err)
	}
}

// A kill between the map's parts: the job record and the parts are on disk, and a restarted mapper uploads the rest,
// byte-equal, and commits; nothing uploaded is uploaded twice.
func TestEvsMapperResumesAfterAKill(t *testing.T) {
	writer := newEvsTestMapperWriter(t)
	writer.test.client.settings.MapPartFillByteCount = 300
	writer.test.client.settings.MapUploadCount = 1
	killed := false
	writer.server.onMapPart = func(part uint32) error {
		if part == 2 && !killed {
			killed = true
			return errors.New("killed")
		}
		return nil
	}
	writer.test.client.settings.PushRetryCount = 0
	if err := writer.repo.TickMapper(context.Background(), writer.world.refId); err == nil {
		t.Fatal("a tick past a killed part committed")
	}
	job, err := writer.repo.loadMapJob(writer.world.refId)
	if err != nil || job == nil || job.PartCount < 3 || !job.Uploaded[0] || job.Uploaded[1] {
		t.Fatalf("the job after the kill: %+v %v", job, err)
	}
	if err := writer.repo.TickMapper(context.Background(), writer.world.refId); err != nil {
		t.Fatalf("the resumed tick: %v", err)
	}
	if writer.world.currentEpoch != 2 || writer.server.partUploads[1] != 1 {
		t.Fatalf("epoch %d, part 1 uploaded %d times", writer.world.currentEpoch, writer.server.partUploads[1])
	}
}

// A creation after the map's source, before its commit, reaches the tail from the creating push's record; a tail
// refusal asks again on a new head.
func TestEvsMapperTailCoversLaterCreations(t *testing.T) {
	writer := newEvsTestMapperWriter(t)
	created := false
	writer.server.onMapPart = func(part uint32) error {
		if !created {
			created = true
			// another writer's creation between the map's source and its commit
			writer.world.push(&evsTestChange{path: "late", content: []byte("late")}, &evsTestChange{path: "", children: []string{"late"}})
		}
		return nil
	}
	writer.server.know("late")
	writer.server.pushRefusals = []*evsTestRefusal{{status: http.StatusConflict, reply: &protocol.EvsRefusalReply{
		Code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT, Paths: []*protocol.EvsTokenPath{writer.world.tokensAt("late", 1).Proto()},
	}}}
	if err := writer.repo.TickMapper(context.Background(), writer.world.refId); err != nil {
		t.Fatalf("the tick: %v", err)
	}
	statement := writer.world.commits[len(writer.world.commits)-1]
	checked, err := EvsCheckPayload(statement.parsed, statement.built.Payload)
	if err != nil || writer.world.currentEpoch != 2 || len(checked.TailMoves) != 1 {
		t.Fatalf("the commit: epoch %d, %d tail moves %v", writer.world.currentEpoch, len(checked.TailMoves), err)
	}
	move := &protocol.EvsPathMove{}
	proto.Unmarshal(checked.TailMoves[0], move)
	tokenPath, _ := ParseEvsChangedTokenPath(move.GetNewTokenPath())
	if !tokenPath.Equal(writer.world.tokensAt("late", 2)) || len(move.GetSources()) != 1 || move.GetSources()[0].GetEpoch() != 1 {
		t.Errorf("the tail move %v", move)
	}
}

// A batched due waits while two sources stand, building nothing; three sources wait any due.
func TestEvsMapperWaitsOnSources(t *testing.T) {
	writer := newEvsTestMapperWriter(t)
	writer.world.cutOver(2)
	writer.world.cutOver(3)
	writer.gkm.newest = 4
	writer.gkm.causes[4] = GkmCauseRemove
	writer.world.due = &protocol.EvsPathEpoch{DueGeneration: 4, DueByMs: writer.test.clock.Now().UnixMilli()}
	if err := writer.repo.TickMapper(context.Background(), writer.world.refId); !errors.Is(err, errEvsMapperWait) {
		t.Fatalf("a batched due with two sources: %v", err)
	}
	if job, _ := writer.repo.loadMapJob(writer.world.refId); job != nil || 0 < len(writer.server.mapParts) {
		t.Fatal("a map built while two sources stand")
	}
}

// A job whose parts passed MapMaxAge is abandoned and the map built again, under another hash.
func TestEvsMapperAbandonsAnOldJob(t *testing.T) {
	writer := newEvsTestMapperWriter(t)
	writer.server.onMapPart = func(part uint32) error { return errors.New("down") }
	writer.test.client.settings.PushRetryCount = 0
	writer.repo.TickMapper(context.Background(), writer.world.refId)
	first, err := writer.repo.loadMapJob(writer.world.refId)
	if err != nil || first == nil {
		t.Fatalf("no job: %v", err)
	}
	writer.server.onMapPart = nil
	writer.test.clock.advance(21 * time.Hour)
	if err := writer.repo.TickMapper(context.Background(), writer.world.refId); err != nil {
		t.Fatalf("the tick past MapMaxAge: %v", err)
	}
	if writer.world.currentEpoch != 2 || len(writer.server.committedMap) != 1 ||
		bytes.Equal(EvsPathMapSha256(writer.server.committedMap[0]), mustHex(t, first.PathMapSha256)) {
		t.Fatalf("epoch %d, the old map committed", writer.world.currentEpoch)
	}
}

// The moves sort on disk (QD-641): runs small enough that the map's five moves span several, merged into several
// parts, every move present once, ascending by new token path within and across parts, the root first; and no run
// is left on disk once the parts are.
func TestEvsMapperSortsOnDisk(t *testing.T) {
	writer := newEvsTestMapperWriter(t)
	writer.test.client.settings.MapPartFillByteCount = 300
	if err := writer.repo.TickMapper(context.Background(), writer.world.refId); err != nil {
		t.Fatalf("the tick: %v", err)
	}
	if len(writer.server.committedMap) != 1 || len(writer.server.committedMap[0]) < 3 {
		t.Fatalf("%d maps, %d parts", len(writer.server.committedMap), len(writer.server.committedMap[0]))
	}
	moves := evsTestMapMoves(t, writer.server.committedMap[0])
	if len(moves) != 5 || len(moves[0].GetNewTokenPath()) != 0 {
		t.Fatalf("%d moves", len(moves))
	}
	for i := 1; i < len(moves); i += 1 {
		previous, _ := ParseEvsChangedTokenPath(moves[i-1].GetNewTokenPath())
		next, _ := ParseEvsChangedTokenPath(moves[i].GetNewTokenPath())
		if 0 <= bytes.Compare(previous.Bytes(), next.Bytes()) {
			t.Errorf("moves out of order at %d", i)
		}
	}
	entries, err := writer.test.client.args.Store.List(evsMapJobDirectory(writer.world.repoId, writer.world.refId))
	if err != nil || len(entries) != 0 {
		t.Fatalf("%d files left beside the job: %v", len(entries), err)
	}
}

// MapUploadCount parts at once: with four, a part waits at evs until a second one arrives beside it, which an
// upload of one at a time never sends; every part goes once and the map commits.
func TestEvsMapperUploadsPartsAtOnce(t *testing.T) {
	writer := newEvsTestMapperWriter(t)
	writer.test.client.settings.MapPartFillByteCount = 300
	writer.test.client.settings.MapUploadCount = 4
	arrived := make(chan uint32, 64)
	second := make(chan struct{})
	var once sync.Once
	writer.server.onMapPart = func(part uint32) error {
		arrived <- part
		if len(arrived) == 2 {
			once.Do(func() { close(second) })
		}
		select {
		case <-second:
			return nil
		case <-time.After(10 * time.Second):
			return errors.New("no second part arrived beside the first")
		}
	}
	if err := writer.repo.TickMapper(context.Background(), writer.world.refId); err != nil {
		t.Fatalf("the tick: %v", err)
	}
	if writer.world.currentEpoch != 2 {
		t.Fatalf("epoch %d", writer.world.currentEpoch)
	}
	for part, count := range writer.server.partUploads {
		if count != 1 {
			t.Errorf("part %d uploaded %d times", part, count)
		}
	}
}

// A git-mode ref maps as a file-mode one and commits on its tip: an attempt that loses the tip to another push answers
// 409 NON_FAST_FORWARD, and the next attempt takes the seal lease before it posts, then commits on the new tip.
func TestEvsMapperGitModeTakesTheLeaseAfterALostTip(t *testing.T) {
	writer := newEvsTestMapperWriter(t)
	writer.world.mode = protocol.EvsRefMode_EVS_REF_GIT
	landed := false
	writer.server.onPush = func(statement *EvsStatement) {
		if landed || statement.Push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) == 0 {
			return
		}
		landed = true
		// another device's push takes the tip between the mapper's head read and its post
		writer.world.push(&evsTestChange{path: "a", content: []byte("a on the tip")})
	}
	if err := writer.repo.TickMapper(context.Background(), writer.world.refId); err != nil {
		t.Fatalf("the tick: %v", err)
	}
	if !landed || writer.world.currentEpoch != 2 || writer.server.leases != 1 {
		t.Fatalf("landed %v, epoch %d, %d leases", landed, writer.world.currentEpoch, writer.server.leases)
	}
	commit := writer.world.commits[len(writer.world.commits)-1]
	if commit.parsed.Push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) == 0 ||
		commit.parsed.Push.GetBaseVersion() != uint64(len(writer.world.commits)-1) ||
		protocol.EvsRefMode(commit.parsed.Push.GetRefMode()) != protocol.EvsRefMode_EVS_REF_GIT {
		t.Fatalf("the commit: %v", commit.parsed.Push)
	}
}

// A ref evs refuses a map, 409 REF_MODE as for an IMMUTABLE tag: the job goes and nothing more is mapped there
// through that generation.
func TestEvsMapperStopsOnARefModeRefusal(t *testing.T) {
	writer := newEvsTestMapperWriter(t)
	writer.server.pushRefusals = []*evsTestRefusal{{status: http.StatusConflict, reply: &protocol.EvsRefusalReply{
		Code: protocol.EvsRefusalCode_EVS_REFUSAL_REF_MODE,
	}}}
	if err := writer.repo.TickMapper(context.Background(), writer.world.refId); !errors.Is(err, ErrEvsMapperNotEligible) {
		t.Fatalf("the refused tick: %v", err)
	}
	if job, _ := writer.repo.loadMapJob(writer.world.refId); job != nil {
		t.Fatal("a job left after REF_MODE")
	}
	parts := len(writer.server.partUploads)
	if err := writer.repo.TickMapper(context.Background(), writer.world.refId); !errors.Is(err, ErrEvsMapperNotEligible) {
		t.Fatalf("the next tick: %v", err)
	}
	if len(writer.server.partUploads) != parts || 1 < writer.world.currentEpoch {
		t.Fatalf("the mapper mapped again after REF_MODE: %d parts then %d, epoch %d", parts, len(writer.server.partUploads), writer.world.currentEpoch)
	}
}

// A verified head that shows a due asks the mapper's loop for a tick, once per head version and not while that ref's
// tick runs; a new generation asks one for each pinned ref of the repo.
func TestEvsMapperWakesOnAVerifiedHead(t *testing.T) {
	writer := newEvsTestMapperWriter(t)
	mapper := writer.test.client.mapper()
	drain := func() []evsRefKey {
		keys := []evsRefKey{}
		for {
			select {
			case key := <-mapper.wakeups:
				keys = append(keys, key)
			default:
				return keys
			}
		}
	}
	drain()
	if _, err := writer.repo.readHeadAlone(context.Background(), writer.world.refId, true); err != nil {
		t.Fatal(err)
	}
	if woken := drain(); len(woken) != 1 || woken[0].refId != writer.world.refId {
		t.Fatalf("woken %v by the head", woken)
	}
	if _, err := writer.repo.readHeadAlone(context.Background(), writer.world.refId, true); err != nil {
		t.Fatal(err)
	}
	if woken := drain(); len(woken) != 0 {
		t.Fatalf("woken %v by the same head again", woken)
	}
	writer.test.client.NoteGeneration(writer.world.repoId)
	if woken := drain(); len(woken) != 1 || woken[0].refId != writer.world.refId {
		t.Fatalf("woken %v by a new generation", woken)
	}
}
