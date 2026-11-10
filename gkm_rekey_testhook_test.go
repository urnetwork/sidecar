//go:build sidecar_testhooks

// Under the tag, the rekey job's barriers hold its order (§22.8): a push's barriers come before and after its commit,
// the progress record is written only between the second and the third, and each is keyed by the repo, so a schedule
// holds one repo's job and no other's.

package sidecar

import (
	"context"
	"testing"
)

// What the job's record and the stand-in held at one barrier.
type rekeyBarrierSight struct {
	name      string
	commits   int
	rewritten uint64
	after     string
}

// At push.before neither the commit nor the record has moved; at push.after the commit stands and the record still
// names the push before it; at progress.after the record names this push. A kill at any of them therefore leaves a
// record at or behind what committed, never ahead.
func TestEvsRekeyBarriersHoldTheRecordBehindTheCommit(t *testing.T) {
	test := newRekeyTest(t)
	paths := test.writeFiles("b", 4)
	test.rotate(2, GkmCauseRemove)
	test.settings.PushEntryWriteCount = 2
	repoId := test.writer.world.repoId
	rekey := test.rekey()
	sights := []*rekeyBarrierSight{}
	t.Cleanup(func() { SetTestHooks(nil) })
	SetTestHooks(&TestHooks{Barrier: func(name string, key string) {
		switch name {
		case gkmBarrierRekeyPushBefore, gkmBarrierRekeyPushAfter, gkmBarrierRekeyProgressAfter:
		default:
			return
		}
		if key != repoId.String() {
			t.Errorf("%s keyed %q, not the repo", name, key)
		}
		record, err := rekey.loadRecord(repoId)
		if err != nil || record == nil {
			t.Errorf("%s: the record: %v", name, err)
			return
		}
		sights = append(sights, &rekeyBarrierSight{name: name, commits: test.commits(), rewritten: record.RewrittenCount, after: record.AfterPath})
	}})
	base := test.commits()
	if _, err := rekey.Run(context.Background(), &GkmRekeyRequest{RepoId: repoId, Paths: []string{"b"}}); err != nil {
		t.Fatal(err)
	}
	SetTestHooks(nil)
	want := []*rekeyBarrierSight{
		{name: gkmBarrierRekeyPushBefore, commits: base},
		{name: gkmBarrierRekeyPushAfter, commits: base + 1},
		{name: gkmBarrierRekeyProgressAfter, commits: base + 1, rewritten: 2, after: paths[1]},
		{name: gkmBarrierRekeyPushBefore, commits: base + 1, rewritten: 2, after: paths[1]},
		{name: gkmBarrierRekeyPushAfter, commits: base + 2, rewritten: 2, after: paths[1]},
		{name: gkmBarrierRekeyProgressAfter, commits: base + 2, rewritten: 4, after: paths[3]},
	}
	if len(sights) != len(want) {
		t.Fatalf("%d barriers, want %d", len(sights), len(want))
	}
	for i, sight := range sights {
		if *sight != *want[i] {
			t.Errorf("barrier %d: %+v, want %+v", i, *sight, *want[i])
		}
	}
}
