// The creation retry of evs_write.go (§11.7's versions and directory rows, §11.8's 5g) at the stand-in, whose 5g
// refuses a directory's creation over a standing one and merges a delta with no path-level CAS, as evs does: writers
// creating their own files under one directory that does not stand yet, all at once, all land, each in its own path
// (the e2e-evs-concurrency finding, its case in server/sidecare2e/evs_concurrency_test.go); a creation of a path
// another writer created meanwhile still answers 409 naming it, the winner's content kept; a 409 naming a parent
// alone, even to the plan made again, names no written path; the plan made again is an attempt like the first; and a
// file the index writer's hook added stays the hook's to plan again, never one of the write's own creations.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// Writers, each its own sidecar, create their own files under a directory that does not stand yet, one level or two
// below a standing one, every first push held until all have arrived, so each first plan read the directory absent
// and creates it. One push creates it; every other is refused 409 on the directories it created alone, and each of
// those writes is planned once more, its delta on the standing directory merging with the others' (§11.7's directory
// row). Every write lands in its own path, each refused writer posting twice, and every writer reads every file and
// lists the directory whole, with no alarm. Before the fix every write but one came back 409 naming no written path.
func TestEvsWriteCreationsUnderANewDirectoryAllLand(t *testing.T) {
	const writerCount = 8
	for _, parent := range []string{"fresh", "deep/fresh"} {
		writer := newEvsTestWriter(t)
		writer.seed(t)
		writers := []*evsTestWriter{writer}
		for i := 1; i < writerCount; i += 1 {
			writers = append(writers, writer.otherWriter(t, fmt.Sprintf("%s writer %d", parent, i)))
		}
		var arrivedLock sync.Mutex
		arrived := 0
		held := make(chan struct{}, writerCount)
		release := make(chan struct{})
		func() {
			writer.server.stateLock.Lock()
			defer writer.server.stateLock.Unlock()
			writer.server.onPush = func(statement *EvsStatement) {
				first := func() bool {
					arrivedLock.Lock()
					defer arrivedLock.Unlock()
					arrived += 1
					return arrived <= writerCount
				}()
				if first {
					held <- struct{}{}
					<-release
				}
			}
		}()
		type written struct {
			index int
			err   error
		}
		writes := make(chan *written, writerCount)
		for i, each := range writers {
			go func() {
				_, err := each.write(t, fmt.Sprintf("%s/%d.txt", parent, i), fmt.Appendf(nil, "content %d", i))
				writes <- &written{index: i, err: err}
			}()
		}
		for range writerCount {
			select {
			case <-held:
			case early := <-writes:
				close(release)
				t.Fatalf("%s: writer %d returned before every first push arrived: %v", parent, early.index, early.err)
			}
		}
		close(release)
		for range writerCount {
			if done := <-writes; done.err != nil {
				t.Errorf("%s: writer %d: %v", parent, done.index, done.err)
			}
		}
		// the push that created the directory, and each other writer's refused push and its plan made again
		if posted := writer.server.postCount(); posted != 2*writerCount-1 {
			t.Errorf("%s: %d posts, not %d", parent, posted, 2*writerCount-1)
		}
		names := []string{}
		for i := range writerCount {
			names = append(names, fmt.Sprintf("%d.txt", i))
		}
		for i, each := range writers {
			for j := range writerCount {
				path := fmt.Sprintf("%s/%d.txt", parent, j)
				if read, _, err := each.read(t, path); err != nil || string(read) != fmt.Sprintf("content %d", j) {
					t.Errorf("%s: writer %d reads %s as %q: %v", parent, i, path, read, err)
				}
			}
			listing, err := each.repo.List(context.Background(), &EvsReadArgs{Path: parent, Fresh: true})
			if err != nil || evsTestListedNames(listing) != strings.Join(names, ",") {
				t.Errorf("%s: writer %d lists %v: %v", parent, i, listing, err)
			}
			if alarms := each.test.alarms(); len(alarms) != 0 {
				t.Errorf("%s: writer %d alarms %v", parent, i, alarms)
			}
		}
	}
}

// A creation of a path another writer created meanwhile is a real conflict, whether the parent stood or the same race
// created it: the plan made again finds the path standing and sends nothing, and evs's 409 to the first push goes
// back naming the path, the winner's content standing. A write held to version 0 finds it on the plan made again
// too, which answers the planner's own 409 (QD-721).
func TestEvsWriteCreationOfAPathAnotherCreatedStillAnswers409(t *testing.T) {
	cases := []struct {
		parent string
		stands bool
		held   bool
	}{
		{parent: "fresh"},
		{parent: "kept", stands: true},
		{parent: "fresh", held: true},
	}
	for _, c := range cases {
		writer := newEvsTestWriter(t)
		writer.seed(t)
		if c.stands {
			if _, err := writer.write(t, c.parent+"/seed.txt", []byte("seed")); err != nil {
				t.Fatal(err)
			}
		}
		other := writer.otherWriter(t, "racing writer")
		path := c.parent + "/same.txt"
		writer.server.raceNextPush(func() {
			if _, err := writer.write(t, path, []byte("theirs")); err != nil {
				t.Error(err)
			}
		})
		posted := writer.server.postCount()
		var err error
		if c.held {
			_, err = other.writeHeld(path, 0, "mine")
		} else {
			_, err = other.write(t, path, []byte("mine"))
		}
		conflict := evsTestRequirePathConflict(t, err, path)
		if errors.Is(err, ErrEvsPathMoved) != c.held || len(conflict.Refusal.Paths) == 0 {
			t.Errorf("%+v: the conflict: %v", c, err)
		}
		// the refused push and the racing write's: the plan made again sent nothing
		if got := writer.server.postCount() - posted; got != 2 {
			t.Errorf("%+v: %d posts", c, got)
		}
		if read, _, err := writer.read(t, path); err != nil || string(read) != "theirs" {
			t.Errorf("%+v: the path reads %q: %v", c, read, err)
		}
	}
}

// The e2e finding with one racing writer: a write whose push meets another writer's creation in the directory its
// plan created is refused 409 on that directory alone, and planned once more, it lands beside the other's, its hold
// to version 0 checked again and borne out (QD-721). Before the fix the 409 went back, naming no written path.
func TestEvsWriteCreationRacingItsParentsCreationLands(t *testing.T) {
	writer := newEvsTestWriter(t)
	writer.seed(t)
	other := writer.otherWriter(t, "sibling writer")
	writer.server.raceNextPush(func() {
		if _, err := writer.write(t, "fresh/b.txt", []byte("b")); err != nil {
			t.Error(err)
		}
	})
	posted := writer.server.postCount()
	written, err := other.writeHeld("fresh/a.txt", 0, "a")
	if err != nil {
		t.Fatalf("a creation beside a racing one: %v", err)
	}
	// the refused push, the racing write's and the one planned again
	if got := writer.server.postCount() - posted; got != 3 {
		t.Errorf("%d posts", got)
	}
	read, info, err := writer.read(t, "fresh/a.txt")
	if err != nil || string(read) != "a" || info.Version != written.PathVersions[0] {
		t.Errorf("fresh/a.txt reads %q: %v", read, err)
	}
	if read, _, err := writer.read(t, "fresh/b.txt"); err != nil || string(read) != "b" {
		t.Errorf("fresh/b.txt reads %q: %v", read, err)
	}
	listing, err := other.repo.List(context.Background(), &EvsReadArgs{Path: "fresh", Fresh: true})
	if err != nil || evsTestListedNames(listing) != "a.txt,b.txt" {
		t.Errorf("the directory lists %v: %v", listing, err)
	}
}

// evs's 409 naming a parent directory alone, to the first push and to the plan made again, goes back as an
// *EvsPathConflictError naming no written path, the write's own path not having moved: a second creation's 409 is not
// planned again. The same write made again commits.
func TestEvsWriteConflictOnAParentAloneNamesNoWrittenPath(t *testing.T) {
	writer := newEvsTestWriter(t)
	writer.seed(t)
	writer.server.know("fresh/a.txt")
	parent := writer.world.tokens("fresh")
	refusal := func() *evsTestRefusal {
		return &evsTestRefusal{status: http.StatusConflict, reply: &protocol.EvsRefusalReply{
			Code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT, Paths: []*protocol.EvsTokenPath{parent.Proto()},
		}}
	}
	writer.server.pushRefusals = []*evsTestRefusal{refusal(), refusal()}
	posted := writer.server.postCount()
	_, err := writer.writeHeld("fresh/a.txt", 0, "a")
	conflict := evsTestRequirePathConflict(t, err)
	if errors.Is(err, ErrEvsPathMoved) || len(conflict.Refusal.Paths) != 1 || !conflict.Refusal.Paths[0].Equal(parent) {
		t.Errorf("a parent's conflict: %v", err)
	}
	if got := writer.server.postCount() - posted; got != 2 {
		t.Errorf("%d posts", got)
	}
	if _, _, err := writer.read(t, "fresh/a.txt"); !errors.Is(err, ErrEvsPathAbsent) {
		t.Fatalf("the refused creation: %v", err)
	}
	if _, err := writer.writeHeld("fresh/a.txt", 0, "a"); err != nil {
		t.Fatalf("the write made again: %v", err)
	}
	if read, _, err := writer.read(t, "fresh/a.txt"); err != nil || string(read) != "a" {
		t.Errorf("fresh/a.txt reads %q: %v", read, err)
	}
}

// The plan made again after a creation's 409 is an attempt like the first: a refusal asking for a rebuild is rebuilt
// from a fresh read, and a mapper's block, 412 PATH_EPOCH_DUE, is waited out for its retry_after_ms, both of which
// once went back to the caller from the plan made again, and the write lands.
func TestEvsWriteCreationPlannedAgainRebuildsAndWaits(t *testing.T) {
	writer := newEvsTestWriter(t)
	writer.seed(t)
	writer.server.pushRefusals = []*evsTestRefusal{
		{status: http.StatusConflict, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT}},
		{status: http.StatusConflict, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE}},
		{status: http.StatusPreconditionFailed, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH_DUE, RetryAfterMs: 1500}},
	}
	posted := writer.server.postCount()
	waits := len(writer.test.clock.waited())
	if _, err := writer.write(t, "new.txt", []byte("new")); err != nil {
		t.Fatalf("a creation refused, rebuilt and held: %v", err)
	}
	if got := writer.server.postCount() - posted; got != 4 {
		t.Errorf("%d posts", got)
	}
	if !slices.Contains(writer.test.clock.waited()[waits:], 1500*time.Millisecond) {
		t.Errorf("waits %v, not the block's", writer.test.clock.waited()[waits:])
	}
	if read, _, err := writer.read(t, "new.txt"); err != nil || string(read) != "new" {
		t.Errorf("new.txt reads %q: %v", read, err)
	}
}

// A file the index writer's hook added is the hook's, which plans it again on what stands at every plan, never one of
// the write's own creations: a push refused 409 on directories another writer created at once and on the hook's file,
// which that writer's hook created too, is planned once more, the hook's file written over the standing one and the
// write landing, where the 409 went back while every path the plan created counted, directories and hook files alike.
func TestEvsWriteCreationLeavesTheHooksFilesToTheHook(t *testing.T) {
	writer := newEvsTestWriter(t)
	writer.server.format2 = true
	other := writer.otherWriter(t, "indexing writer")
	for _, each := range []*evsTestWriter{writer, other} {
		each.test.client.SetFormat2Source(func() bool { return true })
		each.test.client.EnableFormat2Reader()
	}
	writer.seed(t)
	// a head's path, one of §11.14's, which a reader takes at versioning 2
	indexPath := indexFileModePrefix + "i1/b/20340/w/aa/" + strings.Repeat("aa", 16) + "/0"
	writer.server.know(indexPath)
	for label, each := range map[string]*evsTestWriter{"mine": writer, "theirs": other} {
		each.test.client.SetWritePlanHook(func(ctx context.Context, plan *EvsWritePlan) error {
			// the index writer's stand-in: a file of its own under the index root in every push, on what stands
			plan.addIndexWrites(&EvsPathWrite{
				Path: indexPath, Content: strings.NewReader(label), Options: &EvsWriteOptions{Reserved: EvsReservedIndex},
			})
			return nil
		})
	}
	writer.server.raceNextPush(func() {
		if _, err := other.write(t, "notes/theirs.txt", []byte("theirs")); err != nil {
			t.Error(err)
		}
	})
	posted := writer.server.postCount()
	written, err := writer.write(t, "notes/mine.txt", []byte("mine"))
	if err != nil {
		t.Fatalf("a write whose hook's file another writer's hook created: %v", err)
	}
	// the refused push, the racing write's and the one planned again
	if got := writer.server.postCount() - posted; got != 3 {
		t.Errorf("%d posts", got)
	}
	for path, want := range map[string]string{"notes/mine.txt": "mine", "notes/theirs.txt": "theirs"} {
		content := &strings.Builder{}
		if _, err := writer.repo.ReadHead(context.Background(), &EvsReadArgs{Path: path, Fresh: true}, content); err != nil || content.String() != want {
			t.Errorf("%s reads %q: %v", path, content.String(), err)
		}
	}
	// the racing write's creation, and the write's own push over it
	versionCount, newestPushId := func() (int, []byte) {
		writer.world.stateLock.Lock()
		defer writer.world.stateLock.Unlock()
		state := writer.world.paths[indexPath]
		if state == nil || state.versions[state.newest] == nil {
			return 0, nil
		}
		return len(state.versions), state.versions[state.newest].pushId
	}()
	if versionCount != 2 || !bytes.Equal(newestPushId, written.PushId.Bytes()) {
		t.Errorf("the hook's file holds %d versions, its newest not the write's push", versionCount)
	}
}
