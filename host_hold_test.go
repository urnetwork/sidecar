//go:build !sidecar_http

// The hold record and HoldSet (ABUSE-M2-01). T1: testdata/hold/'s vectors round-trip byte-equal, the
// encoder refuses what no reader reads back, and every doubtful body covers the network. T2, on
// FakeBlobs and a fake clock: the 5 s reread, expiry, a failed LIST, overlapping holds and repo scopes.

package sidecar_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The vectors' ids, visibly synthetic.
var (
	testHoldNetworkId = mustTestHoldId("00000000-0000-0000-0000-0000000a0001")
	testHoldCaseId1   = mustTestHoldId("00000000-0000-0000-0000-0000000c0001")
	testHoldCaseId2   = mustTestHoldId("00000000-0000-0000-0000-0000000c0002")
	testHoldRepoId1   = mustTestHoldId("00000000-0000-0000-0000-0000000e0001")
	testHoldRepoId2   = mustTestHoldId("00000000-0000-0000-0000-0000000e0002")
	testHoldRepoId3   = mustTestHoldId("00000000-0000-0000-0000-0000000e0003")
)

func mustTestHoldId(idStr string) sidecar.Id {
	id, err := sidecar.ParseId(idStr)
	if err != nil {
		panic(err)
	}
	return id
}

// A FakeBlobs and a HoldSet on one fake clock, with the default 5 s reread.
func newTestHoldSet() (*sidecartest.FakeClock, *sidecartest.FakeBlobs, *sidecar.HoldSet) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	blobs := sidecartest.NewFakeBlobs(clock, nil, nil, nil)
	return clock, blobs, sidecar.NewHoldSet(blobs, clock, nil)
}

// A network-wide §2703(f) hold placed at now, expiring after.
func testPreserveHold(networkId sidecar.Id, caseId sidecar.Id, now time.Time, after time.Duration) *sidecar.HoldRecord {
	return &sidecar.HoldRecord{
		NetworkId:  networkId,
		CaseId:     caseId,
		Kind:       sidecar.HoldKindPreserve2703f,
		Scope:      sidecar.HoldScopeNetwork(),
		PlaceTime:  now.Truncate(time.Millisecond),
		ExpireTime: now.Add(after).Truncate(time.Millisecond),
	}
}

func testListCount(blobs *sidecartest.FakeBlobs) int {
	return len(blobs.Faults().OpResults(sidecartest.FaultOpList))
}

func TestHoldRecordVectorsRoundTrip(t *testing.T) {
	for _, c := range []struct {
		path   string
		record *sidecar.HoldRecord
	}{
		{
			path: "testdata/hold/preserve_2703f.json",
			record: &sidecar.HoldRecord{
				NetworkId:  testHoldNetworkId,
				CaseId:     testHoldCaseId1,
				Kind:       sidecar.HoldKindPreserve2703f,
				Scope:      sidecar.HoldScopeNetwork(),
				PlaceTime:  time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
				ExpireTime: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC).Add(90 * 24 * time.Hour),
			},
		},
		{
			// the NCMEC report two days before placement starts the year (§2258A(h))
			path: "testdata/hold/report_2258a.json",
			record: &sidecar.HoldRecord{
				NetworkId:  testHoldNetworkId,
				CaseId:     testHoldCaseId2,
				Kind:       sidecar.HoldKindReport2258a,
				Scope:      sidecar.HoldScopeRepos(testHoldRepoId1, testHoldRepoId2),
				PlaceTime:  time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC),
				ExpireTime: time.Date(2027, 11, 1, 0, 0, 0, 0, time.UTC),
			},
		},
	} {
		body, err := os.ReadFile(c.path)
		if err != nil {
			t.Fatal(err)
		}
		record, err := sidecar.ParseHoldRecord(body)
		if err != nil {
			t.Fatalf("%s: %v", c.path, err)
		}
		if record.NetworkId != c.record.NetworkId || record.CaseId != c.record.CaseId || record.Kind != c.record.Kind {
			t.Errorf("%s: parsed %+v, want %+v", c.path, record, c.record)
		}
		if !record.PlaceTime.Equal(c.record.PlaceTime) || !record.ExpireTime.Equal(c.record.ExpireTime) {
			t.Errorf("%s: times %s to %s, want %s to %s", c.path, record.PlaceTime, record.ExpireTime, c.record.PlaceTime, c.record.ExpireTime)
		}
		if fmt.Sprint(record.Scope.RepoIds) != fmt.Sprint(c.record.Scope.RepoIds) {
			t.Errorf("%s: scope %v, want %v", c.path, record.Scope.RepoIds, c.record.Scope.RepoIds)
		}
		encoded, err := sidecar.EncodeHoldRecord(record)
		if err != nil {
			t.Fatalf("%s: %v", c.path, err)
		}
		if !bytes.Equal(encoded, body) {
			t.Errorf("%s does not round-trip:\n got %s\nwant %s", c.path, encoded, body)
		}
		encoded, err = sidecar.EncodeHoldRecord(c.record)
		if err != nil {
			t.Fatalf("%s: %v", c.path, err)
		}
		if !bytes.Equal(encoded, body) {
			t.Errorf("%s is not what the record encodes to:\n got %s\nwant %s", c.path, encoded, body)
		}
	}
}

// §11.8's 1 KiB, checked before the scope's count, so a scope long enough to pass it is refused for
// its size; 17 repos fit in it and are refused for their count; 16 encode.
func TestHoldRecordOverOneKibRefusedAtEncode(t *testing.T) {
	now := sidecartest.DefaultClockStart()
	repoIds := func(count int) []sidecar.Id {
		ids := []sidecar.Id{}
		for range count {
			ids = append(ids, sidecar.NewId())
		}
		return ids
	}
	record := testPreserveHold(testHoldNetworkId, testHoldCaseId1, now, time.Hour)

	record.Scope = sidecar.HoldScopeRepos(repoIds(32)...)
	if _, err := sidecar.EncodeHoldRecord(record); !errors.Is(err, sidecar.ErrHoldRecordTooLarge) {
		t.Errorf("a 32-repo scope encodes: %v", err)
	}
	record.Scope = sidecar.HoldScopeRepos(repoIds(17)...)
	if _, err := sidecar.EncodeHoldRecord(record); !errors.Is(err, sidecar.ErrHoldRecordInvalid) {
		t.Errorf("a 17-repo scope encodes: %v", err)
	}
	record.Scope = sidecar.HoldScopeRepos(repoIds(16)...)
	body, err := sidecar.EncodeHoldRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if sidecar.HoldRecordMaxByteCount < len(body) {
		t.Fatalf("16 repos take %d bytes", len(body))
	}
	if _, err := sidecar.ParseHoldRecord(body); err != nil {
		t.Fatal(err)
	}
}

// What a reader could not read back as the same hold is never written.
func TestHoldRecordEncodeRefusesWhatNoReaderReadsBack(t *testing.T) {
	now := sidecartest.DefaultClockStart()
	for _, c := range []struct {
		name   string
		change func(record *sidecar.HoldRecord)
	}{
		{name: "a zero network", change: func(record *sidecar.HoldRecord) { record.NetworkId = sidecar.Id{} }},
		{name: "a zero case", change: func(record *sidecar.HoldRecord) { record.CaseId = sidecar.Id{} }},
		{name: "an unknown kind", change: func(record *sidecar.HoldRecord) { record.Kind = "preserve_other" }},
		{name: "a zero repo", change: func(record *sidecar.HoldRecord) { record.Scope = sidecar.HoldScopeRepos(sidecar.Id{}) }},
		{name: "no placement", change: func(record *sidecar.HoldRecord) { record.PlaceTime = time.Time{} }},
		{name: "an expiry at placement", change: func(record *sidecar.HoldRecord) { record.ExpireTime = record.PlaceTime }},
		{name: "an expiry before placement", change: func(record *sidecar.HoldRecord) {
			record.ExpireTime = record.PlaceTime.Add(-time.Hour)
		}},
	} {
		record := testPreserveHold(testHoldNetworkId, testHoldCaseId1, now, time.Hour)
		c.change(record)
		if body, err := sidecar.EncodeHoldRecord(record); !errors.Is(err, sidecar.ErrHoldRecordInvalid) {
			t.Errorf("%s encodes to %s: %v", c.name, body, err)
		}
	}
}

// Each body no reader can read as a known hold: ParseHoldRecord refuses it, and once placed it covers
// every repo of its network, with no end, even one far past any expiry it names.
func TestDoubtfulHoldCoversTheNetwork(t *testing.T) {
	ctx := context.Background()
	now := sidecartest.DefaultClockStart()
	good, err := sidecar.EncodeHoldRecord(testPreserveHold(testHoldNetworkId, testHoldCaseId1, now, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	replace := func(old string, new string) []byte {
		if !bytes.Contains(good, []byte(old)) {
			t.Fatalf("the body holds no %q", old)
		}
		return bytes.Replace(good, []byte(old), []byte(new), 1)
	}
	manyRepos := []string{}
	for range 17 {
		manyRepos = append(manyRepos, `"`+sidecar.NewId().String()+`"`)
	}
	for _, c := range []struct {
		name string
		body []byte
	}{
		{name: "not json", body: []byte("hold")},
		{name: "empty", body: []byte{}},
		{name: "truncated", body: good[:len(good)-1]},
		{name: "trailing bytes", body: append(bytes.Clone(good), []byte(" {}")...)},
		{name: "a newer version", body: replace(`"version":1`, `"version":2`)},
		{name: "an unknown kind", body: replace(`"preserve_2703f"`, `"preserve_2703g"`)},
		{name: "an unknown scope", body: replace(`"scope":"network"`, `"scope":"member"`)},
		{name: "an empty scope", body: replace(`"scope":"network"`, `"scope":[]`)},
		{name: "a scope of 17 repos", body: replace(`"scope":"network"`, `"scope":[`+strings.Join(manyRepos, ",")+`]`)},
		{name: "a scope that is no id", body: replace(`"scope":"network"`, `"scope":["repo"]`)},
		{name: "an unknown key", body: replace(`"version":1`, `"version":1,"renewed":true`)},
		{name: "a missing key", body: replace(`"kind":"preserve_2703f",`, ``)},
		{name: "expiry before placement", body: replace(`"expire_time_ms":`, `"expire_time_ms":-`)},
		{name: "over 1 KiB", body: replace(`"version":1`, `"version":1`+strings.Repeat(" ", sidecar.HoldRecordMaxByteCount))},
	} {
		if record, err := sidecar.ParseHoldRecord(c.body); !errors.Is(err, sidecar.ErrHoldRecordInvalid) {
			t.Errorf("%s parses as %+v: %v", c.name, record, err)
		}
		_, blobs, holds := newTestHoldSet()
		if err := sidecartest.PlaceHoldBytes(ctx, blobs, sidecar.HoldObjectKey(testHoldNetworkId, testHoldCaseId1), c.body); err != nil {
			t.Fatal(err)
		}
		cover, err := holds.Covering(ctx, testHoldNetworkId, testHoldRepoId3)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !cover.Unknown || !cover.Covered() {
			t.Errorf("%s does not cover the network: %+v", c.name, cover)
		}
		if _, bounded := cover.ExpireTime(); bounded {
			t.Errorf("%s gives the cover an end", c.name)
		}
		if !cover.Keeps(now.Add(365 * 24 * time.Hour)) {
			t.Errorf("%s keeps nothing created later", c.name)
		}
	}

	// a body that reads, under a key that does not match it, or a key of another shape
	otherNetwork, err := sidecar.EncodeHoldRecord(testPreserveHold(sidecar.NewId(), testHoldCaseId1, now, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		key  string
		body []byte
	}{
		{name: "another network's body", key: sidecar.HoldObjectKey(testHoldNetworkId, testHoldCaseId1), body: otherNetwork},
		{name: "another case's body", key: sidecar.HoldObjectKey(testHoldNetworkId, testHoldCaseId2), body: good},
		{name: "a key not ending /_", key: "hold/" + testHoldNetworkId.String() + "/" + testHoldCaseId1.String() + "/x", body: good},
		{name: "a key with no case id", key: "hold/" + testHoldNetworkId.String() + "/case/_", body: good},
	} {
		_, blobs, holds := newTestHoldSet()
		if err := sidecartest.PlaceHoldBytes(ctx, blobs, c.key, c.body); err != nil {
			t.Fatal(err)
		}
		cover, err := holds.Covering(ctx, testHoldNetworkId, testHoldRepoId3)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !cover.Unknown {
			t.Errorf("%s does not cover the network: %+v", c.name, cover)
		}
	}
}

// A second read inside 5 s costs no LIST and sees no newer hold; at 5 s the next read lists and sees
// it. An unchanged object is not read again.
func TestHoldSetRereadsAfterFiveSeconds(t *testing.T) {
	ctx := context.Background()
	clock, blobs, holds := newTestHoldSet()
	if err := sidecartest.PlaceHold(ctx, blobs, testPreserveHold(testHoldNetworkId, testHoldCaseId1, clock.Now(), 90*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	cover, err := holds.Covering(ctx, testHoldNetworkId, testHoldRepoId1)
	if err != nil {
		t.Fatal(err)
	}
	if len(cover.Holds) != 1 || cover.Unknown {
		t.Fatalf("the first read: %+v", cover)
	}
	if got := testListCount(blobs); got != 1 {
		t.Fatalf("%d LISTs", got)
	}
	getCount := blobs.RequestCount("meta-1", sidecartest.FaultOpGet)

	second := testPreserveHold(testHoldNetworkId, testHoldCaseId2, clock.Now(), 365*24*time.Hour)
	second.Kind = sidecar.HoldKindReport2258a
	if err := sidecartest.PlaceHold(ctx, blobs, second); err != nil {
		t.Fatal(err)
	}
	clock.Advance(5*time.Second - time.Millisecond)
	cover, err = holds.Covering(ctx, testHoldNetworkId, testHoldRepoId1)
	if err != nil {
		t.Fatal(err)
	}
	if got := testListCount(blobs); got != 1 {
		t.Fatalf("a read inside 5 s listed: %d LISTs", got)
	}
	if len(cover.Holds) != 1 {
		t.Fatalf("a cached read sees %d holds", len(cover.Holds))
	}

	clock.Advance(time.Millisecond)
	cover, err = holds.Covering(ctx, testHoldNetworkId, testHoldRepoId1)
	if err != nil {
		t.Fatal(err)
	}
	if got := testListCount(blobs); got != 2 {
		t.Fatalf("a read at 5 s did not list: %d LISTs", got)
	}
	if len(cover.Holds) != 2 {
		t.Fatalf("a reread sees %d holds", len(cover.Holds))
	}
	// the second hold only was fetched: the first's ETag had not moved
	if got := blobs.RequestCount("meta-1", sidecartest.FaultOpGet) - getCount; got != 1 {
		t.Fatalf("the reread made %d GETs", got)
	}
}

// A record past its own expiry covers nothing, though its object is still there, since a reader does
// not wait on api's sweep.
func TestHoldSetExpiredRecordCoversNothing(t *testing.T) {
	ctx := context.Background()
	clock, blobs, holds := newTestHoldSet()
	if err := sidecartest.PlaceHold(ctx, blobs, testPreserveHold(testHoldNetworkId, testHoldCaseId1, clock.Now(), time.Hour)); err != nil {
		t.Fatal(err)
	}
	cover, err := holds.Covering(ctx, testHoldNetworkId, testHoldRepoId1)
	if err != nil {
		t.Fatal(err)
	}
	if !cover.Covered() {
		t.Fatal("a live hold does not cover")
	}
	clock.Advance(time.Hour - time.Millisecond)
	if cover, _ := holds.Covering(ctx, testHoldNetworkId, testHoldRepoId1); !cover.Covered() {
		t.Fatal("a hold stopped covering before its expiry")
	}
	clock.Advance(time.Millisecond)
	cover, err = holds.Covering(ctx, testHoldNetworkId, testHoldRepoId1)
	if err != nil {
		t.Fatal(err)
	}
	if cover.Covered() {
		t.Fatalf("an expired record covers: %+v", cover)
	}
	if _, ok := blobs.Dump()["meta-1/"+sidecar.HoldObjectKey(testHoldNetworkId, testHoldCaseId1)]; !ok {
		t.Fatal("the object went, so the case proves nothing")
	}
}

// A LIST that fails answers covered with the error, and caches nothing: the next read lists again.
func TestHoldSetListFailureReportsCovered(t *testing.T) {
	ctx := context.Background()
	_, blobs, holds := newTestHoldSet()
	if _, err := blobs.Faults().Add(&sidecartest.FaultPlan{
		Op:        sidecartest.FaultOpList,
		KeyPrefix: "hold/",
		Result:    sidecartest.FailBeforeApply,
	}); err != nil {
		t.Fatal(err)
	}
	cover, err := holds.Covering(ctx, testHoldNetworkId, testHoldRepoId1)
	if err == nil {
		t.Fatal("a failed LIST answered no error")
	}
	if !cover.Covered() || !cover.Unknown {
		t.Fatalf("a failed LIST does not cover: %+v", cover)
	}
	cover, err = holds.Covering(ctx, testHoldNetworkId, testHoldRepoId1)
	if err != nil {
		t.Fatal(err)
	}
	if cover.Covered() {
		t.Fatalf("an empty prefix covers: %+v", cover)
	}
	if got := testListCount(blobs); got != 2 {
		t.Fatalf("%d LISTs, so the failure was cached", got)
	}
}

// A GET that fails after the LIST also answers covered with the error.
func TestHoldSetGetFailureReportsCovered(t *testing.T) {
	ctx := context.Background()
	clock, blobs, holds := newTestHoldSet()
	if err := sidecartest.PlaceHold(ctx, blobs, testPreserveHold(testHoldNetworkId, testHoldCaseId1, clock.Now(), time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := blobs.Faults().Add(&sidecartest.FaultPlan{
		Op:        sidecartest.FaultOpGet,
		KeyPrefix: "hold/",
		Result:    sidecartest.FailBeforeApply,
	}); err != nil {
		t.Fatal(err)
	}
	cover, err := holds.Covering(ctx, testHoldNetworkId, testHoldRepoId1)
	if err == nil || !cover.Unknown {
		t.Fatalf("a failed GET: %+v, %v", cover, err)
	}
}

// Two holds over one network: each its own object, the union governing, so the later expiry decides
// when the network is free.
func TestHoldSetOverlappingHoldsLaterExpiryGoverns(t *testing.T) {
	ctx := context.Background()
	clock, blobs, holds := newTestHoldSet()
	start := clock.Now()
	first := testPreserveHold(testHoldNetworkId, testHoldCaseId1, start, 90*24*time.Hour)
	second := testPreserveHold(testHoldNetworkId, testHoldCaseId2, start, 365*24*time.Hour)
	second.Kind = sidecar.HoldKindReport2258a
	for _, record := range []*sidecar.HoldRecord{first, second} {
		if err := sidecartest.PlaceHold(ctx, blobs, record); err != nil {
			t.Fatal(err)
		}
	}
	cover, err := holds.Covering(ctx, testHoldNetworkId, testHoldRepoId1)
	if err != nil {
		t.Fatal(err)
	}
	if len(cover.Holds) != 2 {
		t.Fatalf("%d holds", len(cover.Holds))
	}
	if expireTime, bounded := cover.ExpireTime(); !bounded || !expireTime.Equal(second.ExpireTime) {
		t.Fatalf("the cover ends at %s, %t, want %s", expireTime, bounded, second.ExpireTime)
	}

	clock.AdvanceTo(first.ExpireTime)
	cover, err = holds.Covering(ctx, testHoldNetworkId, testHoldRepoId1)
	if err != nil {
		t.Fatal(err)
	}
	if len(cover.Holds) != 1 || cover.Holds[0].CaseId != testHoldCaseId2 {
		t.Fatalf("past the first expiry: %+v", cover.Holds)
	}
	if expireTime, _ := cover.ExpireTime(); !expireTime.Equal(second.ExpireTime) {
		t.Fatalf("the cover ends at %s", expireTime)
	}

	clock.AdvanceTo(second.ExpireTime)
	cover, err = holds.Covering(ctx, testHoldNetworkId, testHoldRepoId1)
	if err != nil {
		t.Fatal(err)
	}
	if cover.Covered() {
		t.Fatalf("past both expiries: %+v", cover)
	}
}

// A repo scope covers its repos alone, and every hold covers what is the network's and no one repo's.
func TestHoldSetRepoScopedHoldCoversOnlyItsRepos(t *testing.T) {
	ctx := context.Background()
	clock, blobs, holds := newTestHoldSet()
	record := testPreserveHold(testHoldNetworkId, testHoldCaseId1, clock.Now(), time.Hour)
	record.Scope = sidecar.HoldScopeRepos(testHoldRepoId1, testHoldRepoId2)
	if err := sidecartest.PlaceHold(ctx, blobs, record); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		repoId  sidecar.Id
		covered bool
	}{
		{repoId: testHoldRepoId1, covered: true},
		{repoId: testHoldRepoId2, covered: true},
		{repoId: testHoldRepoId3, covered: false},
		{repoId: sidecar.Id{}, covered: true},
	} {
		cover, err := holds.Covering(ctx, testHoldNetworkId, c.repoId)
		if err != nil {
			t.Fatal(err)
		}
		if cover.Covered() != c.covered {
			t.Errorf("repo %s covered %t, want %t", c.repoId, cover.Covered(), c.covered)
		}
	}
	// another network's holds reach none of these
	cover, err := holds.Covering(ctx, sidecar.NewId(), testHoldRepoId1)
	if err != nil {
		t.Fatal(err)
	}
	if cover.Covered() {
		t.Fatal("a hold covers another network")
	}
}

// A caller that does not know a repo's network keeps everything, and asks no store.
func TestHoldSetUnknownNetworkIsCovered(t *testing.T) {
	_, blobs, holds := newTestHoldSet()
	cover, err := holds.Covering(context.Background(), sidecar.Id{}, testHoldRepoId1)
	if err != nil {
		t.Fatal(err)
	}
	if !cover.Unknown {
		t.Fatalf("a repo with no network is not covered: %+v", cover)
	}
	if got := testListCount(blobs); got != 0 {
		t.Fatalf("%d LISTs", got)
	}
}

// What existed at a covering hold's placement is kept, and what came since is not (FS-69), the
// placement surviving a renewal's rewrite.
func TestHoldCoverKeepsWhatExistedAtPlacement(t *testing.T) {
	ctx := context.Background()
	clock, blobs, holds := newTestHoldSet()
	placeTime := clock.Now().Truncate(time.Millisecond)
	record := testPreserveHold(testHoldNetworkId, testHoldCaseId1, placeTime, 90*24*time.Hour)
	if err := sidecartest.PlaceHold(ctx, blobs, record); err != nil {
		t.Fatal(err)
	}
	// renewed once, a month on: the object is rewritten and keeps its placement
	clock.Advance(30 * 24 * time.Hour)
	record.ExpireTime = record.ExpireTime.Add(90 * 24 * time.Hour)
	if err := sidecartest.PlaceHold(ctx, blobs, record); err != nil {
		t.Fatal(err)
	}
	cover, err := holds.Covering(ctx, testHoldNetworkId, testHoldRepoId1)
	if err != nil {
		t.Fatal(err)
	}
	if !cover.Keeps(placeTime.Add(-time.Hour)) || !cover.Keeps(placeTime) {
		t.Error("what existed at placement is not kept")
	}
	if cover.Keeps(placeTime.Add(time.Millisecond)) {
		t.Error("what came after placement is kept")
	}
	if expireTime, _ := cover.ExpireTime(); !expireTime.Equal(record.ExpireTime) {
		t.Errorf("the renewal did not move the expiry: %s", expireTime)
	}
}

// Callers of one network while its read is in flight share that read: one LIST answers both.
func TestHoldSetConcurrentReadsShareOneList(t *testing.T) {
	ctx := context.Background()
	clock, blobs, holds := newTestHoldSet()
	if err := sidecartest.PlaceHold(ctx, blobs, testPreserveHold(testHoldNetworkId, testHoldCaseId1, clock.Now(), time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := blobs.Faults().Add(&sidecartest.FaultPlan{
		Op:        sidecartest.FaultOpList,
		KeyPrefix: "hold/",
		Result:    sidecartest.Delay,
		Delay:     sidecartest.DelayInNetwork,
	}); err != nil {
		t.Fatal(err)
	}
	type answer struct {
		cover *sidecar.HoldCover
		err   error
	}
	answers := make(chan answer, 2)
	read := func() {
		cover, err := holds.Covering(ctx, testHoldNetworkId, testHoldRepoId1)
		answers <- answer{cover: cover, err: err}
	}
	go read()
	// the parked LIST's client timeout is the one timer, so it is parked once this returns
	if err := clock.AwaitTimers(ctx, 1); err != nil {
		t.Fatal(err)
	}
	go read()
	if delivered := blobs.DeliverDelayed("meta-1", "hold/"); delivered != 1 {
		t.Fatalf("%d parked LISTs", delivered)
	}
	for range 2 {
		a := <-answers
		if a.err != nil {
			t.Fatal(a.err)
		}
		if len(a.cover.Holds) != 1 {
			t.Fatalf("a shared read answers %+v", a.cover)
		}
	}
	if got := testListCount(blobs); got != 1 {
		t.Fatalf("%d LISTs", got)
	}
}
