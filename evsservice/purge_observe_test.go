package evsservice

// EVS2-M10-33's observe check (D-TEST-12), on T2: on an honest history every candidate of a committed record's list is
// clean; a seeded bug, a candidate a later version of the ref names, is retained, paged and counted; a candidate a
// version on another ref names, as a cross-ref copy's would be, is retained too; a marked list is counted unchecked;
// and the sweep under purge: observe runs the check and keeps every candidate, deleting nothing.

import (
	"context"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The record of the push the fixture committed at version, as the sweep takes its list.
func (self *pushFixture) sweepTargetAt(version uint64, list *protocol.EvsPurgeList) *SweepTarget {
	self.t.Helper()
	entry := self.windowEntryAt(version)
	recordBytes, err := self.engine.readRecordBytesAt(self.ctx, self.cluster, self.check.repoId, self.check.refId, entry.Place)
	if err != nil {
		self.t.Fatal(err)
	}
	record, tail, err := sidecar.ParseEvsBatchRecordFormat2(recordBytes)
	if err != nil {
		self.t.Fatal(err)
	}
	if list == nil {
		if list, err = tail.PurgeListValue(); err != nil {
			self.t.Fatal(err)
		}
	}
	object, _ := self.repo()
	return &SweepTarget{
		RepoId: self.check.repoId, RefId: self.check.refId, Repo: object, PathEpoch: 1, Record: record, CommitVersion: version, List: list,
	}
}

// A check over the fixture's host, its alarms kept.
func (self *pushFixture) observeCheck() (*PurgeObserveCheck, *format2Lines) {
	self.t.Helper()
	lines := &format2Lines{}
	check, err := NewPurgeObserveCheck(self.host.ServiceHost(), &PurgeObserveDeps{EvsSettings: self.settings, Log: lines})
	if err != nil {
		self.t.Fatal(err)
	}
	return check, lines
}

// Two versionless versions of x: the second's record lists the first's segment, which no retained version names.
func (self *pushFixture) versionlessTwice() ([32]byte, [32]byte) {
	self.t.Helper()
	x := checkTestPath("x")
	token := self.token(self.check.signerId)
	first := self.plan()
	firstId, firstReceipt := self.versionlessWrite(first, x, 0, 1, "observe one")
	body := self.bodyFormat2(first)
	body.Receipts = append(body.Receipts, firstReceipt)
	self.requireCommitted(self.post(token, body), 1)
	second := self.plan()
	secondId, secondReceipt := self.versionlessWrite(second, x, 1, 2, "observe two")
	body = self.bodyFormat2(second)
	body.Receipts = append(body.Receipts, secondReceipt)
	self.requireCommitted(self.post(token, body), 2)
	self.awaitStepEights()
	return firstId, secondId
}

func TestPurgeObserveCleanOnAnHonestHistory(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.openFormat2Checked()
	firstId, _ := fixture.versionlessTwice()
	target := fixture.sweepTargetAt(2, nil)
	if target.List == nil || len(target.List.GetCandidates()) != 1 || [32]byte(target.List.GetCandidates()[0].GetSegmentIds()[0]) != firstId {
		t.Fatalf("the replacing record lists %v", target.List)
	}
	check, lines := fixture.observeCheck()
	result := check.Check(fixture.ctx, fixture.cluster, target)
	if result.CleanCount != 1 || result.RetainedCount != 0 || result.UncheckedCount != 0 {
		t.Fatalf("an honest history: %+v", result)
	}
	if got := fixture.host.Metrics.Value(purgeObserveMetricName, purgeObserveClean); got != 1 {
		t.Fatalf("clean counted %v", got)
	}
	if lines.count("purge_observe_retained") != 0 {
		t.Fatal("an honest history paged")
	}
}

// A seeded bug: the first record's list naming the second version's segment, which the retained newest version names.
func TestPurgeObserveCatchesACandidateALaterVersionNames(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.openFormat2Checked()
	_, secondId := fixture.versionlessTwice()
	seeded := &protocol.EvsPurgeList{Candidates: []*protocol.EvsPurgeCandidate{{
		TokenPath: checkTestPath("x").Components(), ReplacedVersion: 1, SegmentIds: [][]byte{secondId[:]},
	}}}
	check, lines := fixture.observeCheck()
	result := check.Check(fixture.ctx, fixture.cluster, fixture.sweepTargetAt(1, seeded))
	if result.RetainedCount != 1 || result.CleanCount != 0 {
		t.Fatalf("a seeded bug: %+v", result)
	}
	if lines.count("purge_observe_retained") != 1 {
		t.Fatal("a retained candidate did not page")
	}
	if got := fixture.host.Metrics.Value(purgeObserveMetricName, purgeObserveRetained); got != 1 {
		t.Fatalf("retained counted %v", got)
	}
}

// A marked list names no ids: unchecked, its content kept.
func TestPurgeObserveCountsAMarkedListUnchecked(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.openFormat2Checked()
	fixture.versionlessTwice()
	check, _ := fixture.observeCheck()
	result := check.Check(fixture.ctx, fixture.cluster, fixture.sweepTargetAt(2, &protocol.EvsPurgeList{Marked: true}))
	if result.UncheckedCount != 1 || result.CleanCount != 0 || result.RetainedCount != 0 {
		t.Fatalf("a marked list: %+v", result)
	}
}

// The sweep under purge: observe hands the list to the check and keeps every candidate: nothing is deleted.
func TestSweepUnderObserveRunsTheCheckAndKeepsEverything(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.openFormat2Checked()
	fixture.versionlessTwice()
	check, _ := fixture.observeCheck()
	sweep, err := NewSweep(fixture.host.ServiceHost(), &SweepDeps{
		Format2: NewFormat2Gate(fixture.host.ServiceHost()), EvsSettings: fixture.settings, Observe: check,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := sweep.SweepList(context.WithoutCancel(fixture.ctx), fixture.cluster, fixture.sweepTargetAt(2, nil), sidecar.WriteP2RankGc, true, fixture.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if result.DeletedCount != 0 || result.KeptCount != 1 {
		t.Fatalf("observe's sweep: %+v", result)
	}
	if got := fixture.host.Metrics.Value(purgeObserveMetricName, purgeObserveClean); got != 1 {
		t.Fatalf("the sweep's check counted %v clean", got)
	}
	if got := fixture.host.Blobs.RequestCount("seg-1", sidecartest.FaultOpDelete); got != 0 {
		t.Fatalf("observe's sweep issued %d DELETEs", got)
	}
}
