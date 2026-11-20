//go:build sidecar_testhooks && !ios_extension && !js

// The check by hosts with the text through the search world's CheckPushWithText, as FS-76 runs it on every honest
// push (§11.14's coverage row; D-EVS-56; QD-1098): a push past DirectBytes merges its entries into the bucket's shards,
// and the host with the text judges the rows it added there, not those its merge carried over from the shards at its
// base, which the world hands the check by partition.

package sidecar

import (
	"context"
	"sync"
	"testing"
	"time"
)

// A search world's clock the test moves. Its waits fire at once, since nothing here waits.
type testTextCheckClock struct {
	stateLock sync.Mutex
	now       time.Time
}

func (self *testTextCheckClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

func (self *testTextCheckClock) After(timeout time.Duration) <-chan time.Time {
	fired := make(chan time.Time, 1)
	fired <- self.Now()
	return fired
}

func (self *testTextCheckClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return func() bool { return true }
}

func (self *testTextCheckClock) Advance(timeout time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.now = self.now.Add(timeout)
}

// A writer's push, its head first, then two pushes past DirectBytes: the first opens the bucket's shards, and the
// second writes again the shard holding b.txt's older row, carrying the rows beside it over. Each checks clean, and
// each judges only the entries it added: the second's head carried its seed entry over, and the third's shard its
// neighbours' rows.
func TestSearchTestWorldChecksTheRowsAPushMergedPastDirectBytes(t *testing.T) {
	ctx := context.Background()
	clock := &testTextCheckClock{now: testDayTime(20341, 0)}
	world, err := NewSearchTestWorld(&SearchTestWorldArgs{RepoId: evsTestId("check repo"), RefId: evsTestId("check ref"), Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	writer := evsTestId("writer w")
	// writer's push of changes, checked by a host with the text: clean, with count entries judged
	pushChecked := func(label string, count int, changes ...testContentChange) {
		clock.Advance(time.Minute)
		searchChanges := []*SearchTestChange{}
		for _, change := range changes {
			searchChanges = append(searchChanges, &SearchTestChange{Path: change.path, Content: change.content})
		}
		commit, err := world.CommitIndexedMerging(ctx, writer, clock.Now(), searchChanges)
		if err != nil {
			t.Fatal(err)
		}
		check, err := world.CheckPushWithText(ctx, commit.RefVersion)
		if err != nil {
			t.Fatal(err)
		}
		if len(check.Mismatched) != 0 || len(check.Own) != 0 || len(check.Events) != 0 || len(check.Repairs) != 0 || check.Checked != count {
			t.Fatalf("%s: a host with the text made %+v of an honest push, not %d entries judged", label, check, count)
		}
	}
	// the shard holding path's row at the head, and its version there
	shardOf := func(path string) (string, uint64) {
		held, err := world.FilesHolding(path, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, one := range held {
			if parsed, ok := indexParsePath(one.Path, false); !ok || parsed.kind != indexPathBucketShard {
				continue
			}
			for _, file := range world.Files() {
				if file.Path == one.Path {
					return file.Path, file.Version
				}
			}
		}
		return "", 0
	}

	pushChecked("the seed push", 1, testContentChange{path: "seed.txt", content: []byte("a first page of plums")})
	bulks, bulkPaths := testBulkChanges(7, "a", "b", "c")
	pushChecked("the push opening the shards", 4, append(bulks, testContentChange{path: "b.txt", content: []byte("radishes and parsnips")})...)
	shard, version := shardOf("b.txt")
	if shard == "" {
		t.Fatal("b.txt's row is in no shard: the push did not merge")
	}
	beside := []string{}
	for _, path := range bulkPaths {
		if held, _ := shardOf(path); held == shard {
			beside = append(beside, path)
		}
	}
	if len(beside) == 0 {
		t.Fatal("no bulk text's row shares a shard with b.txt's")
	}

	more, _ := testBulkChanges(10, "d", "e", "f")
	pushChecked("the push carrying rows over", 4, append(more, testContentChange{path: "b.txt", content: []byte("radishes, parsnips and leeks")})...)
	for _, path := range beside {
		if held, after := shardOf(path); held != shard || after <= version {
			t.Fatalf("%s's row is in %s at %d, not carried over in %s written again past %d", path, held, after, shard, version)
		}
	}
}
