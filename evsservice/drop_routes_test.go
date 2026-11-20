package evsservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/http"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// An active repo behind the engine, admin and reader tokens, and the table the routes read.
type dropRoutesFixture struct {
	*evsFixture
	repoId sidecar.Id
	admin  sidecar.Id
	reader sidecar.Id
}

func newDropRoutesFixture(t *testing.T) *dropRoutesFixture {
	fixture := &dropRoutesFixture{evsFixture: newEvsFixture(t), repoId: testId("drop-repo"), admin: testId("admin"), reader: testId("reader")}
	fixture.activeRepo(fixture.repoId, fixture.admin)
	fixture.auth.grant(fixture.reader, fixture.repoId, sidecar.AclEvsRead)
	fixture.host.Quota.SetLimits(fixture.networkId, &sidecar.QuotaLimits{Tier: "pro", Limits: map[string]int64{"evs_drop_previews_per_day": 2}})
	return fixture
}

func (self *dropRoutesFixture) path(suffix string) string {
	return "/evs/v1/repos/" + sidecar.EvsKeyId(self.repoId) + "/drops" + suffix
}

// Writes the table as the job and step 8 would, through a paid write.
func (self *dropRoutesFixture) setTable(decide func(state *DropTableState, now time.Time)) {
	cluster, err := self.engine.Blobs().Cluster("meta-1")
	if err != nil {
		self.t.Fatal(err)
	}
	grant, err := self.host.Budget.AdmitP1(self.ctx, "meta-1", self.networkId, sidecar.WriteCost{ImmediateByteCount: 1})
	if err != nil {
		self.t.Fatal(err)
	}
	defer grant.Close()
	_, err = self.engine.Drops().Update(grant.Context(), cluster, self.repoId, func(state *DropTableState, now time.Time) (bool, error) {
		decide(state, now)
		return true, nil
	})
	if err != nil {
		self.t.Fatal(err)
	}
}

func (self *dropRoutesFixture) table() *DropTableState {
	read, err := self.engine.Drops().Read(self.ctx, self.rawCluster("meta-1"), self.repoId)
	if err != nil {
		self.t.Fatal(err)
	}
	return read.State
}

// A request a DROP would carry for one path.
func dropTestPreviewRequest(refId sidecar.Id, count uint32) *protocol.EvsDropPreviewRequest {
	listed := sha256.Sum256([]byte("listed"))
	return &protocol.EvsDropPreviewRequest{
		RefId: refId.Bytes(),
		Paths: []*protocol.EvsDropPath{{
			Lineage:        []*protocol.EvsSourcePath{{Epoch: 2, TokenPath: [][]byte{bytes.Repeat([]byte{1}, 16)}}, {Epoch: 1, TokenPath: [][]byte{bytes.Repeat([]byte{2}, 16)}}},
			ThroughVersion: uint64(count) + 1, Boundary: 1, Count: count, ListedSha256: listed[:],
		}},
	}
}

// §11.20's listing: void records whose entries left by id and state alone, then each entry oldest first, a held drop
// reading done with its held bytes counted as freed (owner decision 184).
func TestDropRoutesListTheTable(t *testing.T) {
	fixture := newDropRoutesFixture(t)
	place := &protocol.EvsPlace{Minute: 1, Length: 100}
	fixture.setTable(func(state *DropTableState, now time.Time) {
		state.Voids = append(state.Voids, &DropVoidRecord{DropId: testId("old-cancel"), State: DropStateCancelled})
		state.Drops = append(state.Drops,
			&DropTableEntry{DropId: testId("pending"), RefId: testId("ref"), PushId: testId("p1"), Version: 4, Place: place, NotBeforeMs: 77, State: DropStatePending},
			&DropTableEntry{DropId: testId("executing"), Place: place, State: DropStateExecuting, Phase: protocol.EvsDropPhase_EVS_DROP_HORIZON},
			&DropTableEntry{DropId: testId("held"), Place: place, State: DropStateHeld, FreedByteCount: 10, HeldByteCount: 5, EndedDay: dropDay(now)},
			&DropTableEntry{DropId: testId("done"), Place: place, State: DropStateDone, FreedByteCount: 15, EndedDay: dropDay(now)},
		)
	})
	recorder := fixture.serve(http.MethodGet, fixture.path(""), fixture.token(fixture.reader, repoScope(fixture.repoId, "r")), nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d", recorder.Code)
	}
	reply := &protocol.EvsDropsReply{}
	if err := proto.Unmarshal(recorder.Body.Bytes(), reply); err != nil {
		t.Fatal(err)
	}
	if len(reply.Drops) != 5 {
		t.Fatalf("%d drops listed", len(reply.Drops))
	}
	void := reply.Drops[0]
	if sidecar.Id(void.DropId) != testId("old-cancel") || void.State != protocol.EvsDropState_EVS_DROP_CANCELLED || len(void.RefId) != 0 {
		t.Fatalf("the void record: %+v", void)
	}
	if pending := reply.Drops[1]; pending.State != protocol.EvsDropState_EVS_DROP_PENDING || pending.Version != 4 || pending.NotBeforeMs != 77 {
		t.Fatalf("the pending drop: %+v", pending)
	}
	if executing := reply.Drops[2]; executing.State != protocol.EvsDropState_EVS_DROP_EXECUTING || executing.Phase != protocol.EvsDropPhase_EVS_DROP_HORIZON {
		t.Fatalf("the waiting drop: %+v", executing)
	}
	held, done := reply.Drops[3], reply.Drops[4]
	held.DropId, done.DropId = nil, nil
	if !proto.Equal(held, done) {
		t.Fatalf("a held drop lists apart from its done twin: %+v and %+v", held, done)
	}
}

// Owner decisions 184 and 643 (QD-1113): a held drop lists as a done one that ended the same day, alike to the second
// before their 30 d end, and leaves the listing at that second with it, though the table keeps the held entry for its
// deletions. The listing judges age itself, so a done or cancelled entry has left it then whether or not a write has
// evicted it yet, a cancelled one's void record standing in, and the write that evicts them leaves the listing as it
// was: the held drop leaves exactly when its done twin's entry would.
func TestDropRoutesListAHeldDropUntilItsDoneTwinLeaves(t *testing.T) {
	fixture := newDropRoutesFixture(t)
	place := &protocol.EvsPlace{Minute: 1, Length: 100}
	var endedDay uint16
	fixture.setTable(func(state *DropTableState, now time.Time) {
		endedDay = dropDay(now)
		state.Voids = append(state.Voids, &DropVoidRecord{DropId: testId("cancelled"), State: DropStateCancelled})
		state.Drops = append(state.Drops,
			&DropTableEntry{DropId: testId("pending"), Place: place, NotBeforeMs: now.Add(90 * 24 * time.Hour).UnixMilli(), State: DropStatePending},
			&DropTableEntry{DropId: testId("cancelled"), Place: place, State: DropStateCancelled, EndedDay: endedDay},
			&DropTableEntry{DropId: testId("held"), Place: place, State: DropStateHeld, FreedByteCount: 10, HeldByteCount: 5, EndedDay: endedDay},
			&DropTableEntry{DropId: testId("done"), Place: place, State: DropStateDone, FreedByteCount: 15, EndedDay: endedDay},
		)
	})
	list := func() *protocol.EvsDropsReply {
		t.Helper()
		recorder := fixture.serve(http.MethodGet, fixture.path(""), fixture.token(fixture.reader, repoScope(fixture.repoId, "r")), nil)
		if recorder.Code != http.StatusOK {
			t.Fatalf("status %d", recorder.Code)
		}
		reply := &protocol.EvsDropsReply{}
		if err := proto.Unmarshal(recorder.Body.Bytes(), reply); err != nil {
			t.Fatal(err)
		}
		return reply
	}
	labels := func(reply *protocol.EvsDropsReply) []string {
		labels := []string{}
		for _, status := range reply.Drops {
			labels = append(labels, string(bytes.TrimRight(status.DropId, " ")))
		}
		return labels
	}
	retained := dropDayStart(endedDay).Add(fixture.engine.Drops().Settings().EndedRetention + 24*time.Hour)

	// a second before the 30 d end: every entry listed, the held drop alike to the done one
	fixture.clock.AdvanceTo(retained.Add(-time.Second))
	before := list()
	if got := labels(before); !slices.Equal(got, []string{"pending", "cancelled", "held", "done"}) {
		t.Fatalf("listed %v", got)
	}
	held, done := proto.Clone(before.Drops[2]).(*protocol.EvsDropStatus), proto.Clone(before.Drops[3]).(*protocol.EvsDropStatus)
	held.DropId, done.DropId = nil, nil
	if !proto.Equal(held, done) || held.State != protocol.EvsDropState_EVS_DROP_DONE || held.FreedBytes != 15 {
		t.Fatalf("a held drop lists apart from its done twin: %+v and %+v", held, done)
	}

	// at it: the held, done and cancelled entries have left the listing, the cancelled one's void record standing in
	fixture.clock.AdvanceTo(retained)
	at := list()
	if got := labels(at); !slices.Equal(got, []string{"cancelled", "pending"}) {
		t.Fatalf("listed %v at the retention's end", got)
	}
	if void := at.Drops[0]; void.State != protocol.EvsDropState_EVS_DROP_CANCELLED || len(void.RefId) != 0 || void.Version != 0 {
		t.Fatalf("the cancelled drop is not its void record: %+v", void)
	}
	if table := fixture.table(); table.Drop(testId("held")) == nil || table.Drop(testId("done")) == nil {
		t.Fatal("the listing's judgement wrote the table")
	}

	// the next write evicts the done and cancelled entries and keeps the held one; the listing does not move
	fixture.setTable(func(state *DropTableState, now time.Time) {})
	table := fixture.table()
	if table.Drop(testId("held")) == nil || table.Drop(testId("done")) != nil || table.Drop(testId("cancelled")) != nil ||
		table.Void(testId("cancelled")) == nil {
		t.Fatalf("the write kept %v", dropTestLabels(table))
	}
	if after := list(); !proto.Equal(after, at) {
		t.Fatalf("the write moved the listing: %v, was %v", labels(after), labels(at))
	}
}

// POST .../drops/preview: the request stored, the dry run queued, 202 with its id; GET answers its state, and 404 for
// one the table does not hold.
func TestDropRoutesQueueADryRun(t *testing.T) {
	fixture := newDropRoutesFixture(t)
	request := dropTestPreviewRequest(testId("ref"), 3)
	body, _ := proto.Marshal(request)
	adminToken := fixture.token(fixture.admin, repoScope(fixture.repoId, "admin"))
	recorder := fixture.serve(http.MethodPost, fixture.path("/preview"), adminToken, body)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status %d (%s)", recorder.Code, refusalOf(t, recorder).GetCode())
	}
	reply := &protocol.EvsDropPreviewReply{}
	if err := proto.Unmarshal(recorder.Body.Bytes(), reply); err != nil {
		t.Fatal(err)
	}
	previewId, err := sidecar.IdFromBytes(reply.PreviewId)
	if err != nil {
		t.Fatal(err)
	}
	preview := fixture.table().Preview(previewId)
	if preview == nil || preview.State != protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_QUEUED || preview.RefId != testId("ref") {
		t.Fatalf("the queued dry run: %+v", preview)
	}
	ask, err := NewDropFiles(fixture.rawCluster("seg-1"), fixture.repoId, previewId, DefaultDropSettings()).Read(fixture.ctx, DropFileAsk, 0)
	if err != nil || ask == nil {
		t.Fatalf("no ask file: %v", err)
	}
	stored := &protocol.EvsDropPreviewRequest{}
	if err := proto.Unmarshal(ask.Message, stored); err != nil || !proto.Equal(stored, request) {
		t.Fatal("the ask file holds another request")
	}
	if _, found, _ := fixture.host.Redis.Get(fixture.ctx, DropHintKey(fixture.repoId)); !found {
		t.Fatal("a dry run set no hint")
	}
	recorder = fixture.serve(http.MethodGet, fixture.path("/preview/"+sidecar.EvsKeyId(previewId)), adminToken, nil)
	got := &protocol.EvsDropPreviewReply{}
	if recorder.Code != http.StatusOK || proto.Unmarshal(recorder.Body.Bytes(), got) != nil || got.State != protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_QUEUED {
		t.Fatalf("GET of a queued dry run: %d", recorder.Code)
	}
	requireRefusal(t, fixture.serve(http.MethodGet, fixture.path("/preview/"+sidecar.EvsKeyId(testId("unknown"))), adminToken, nil),
		http.StatusNotFound, protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND)
}

// A dry run past evs_drop_previews_per_day answers 429, refusing nothing durable; a malformed request 400, lists past
// 2^20 in all 409 DROP_LIST, and a reader 403.
func TestDropRoutesRefuseDryRunsPastTheirBounds(t *testing.T) {
	fixture := newDropRoutesFixture(t)
	adminToken := fixture.token(fixture.admin, repoScope(fixture.repoId, "admin"))
	body, _ := proto.Marshal(dropTestPreviewRequest(testId("ref"), 3))
	for range 2 {
		if recorder := fixture.serve(http.MethodPost, fixture.path("/preview"), adminToken, body); recorder.Code != http.StatusAccepted {
			t.Fatalf("a dry run inside the limit: %d", recorder.Code)
		}
	}
	requireRefusal(t, fixture.serve(http.MethodPost, fixture.path("/preview"), adminToken, body), http.StatusTooManyRequests, protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED)
	if previews := fixture.table().Previews; len(previews) != 2 {
		t.Fatalf("%d dry runs queued", len(previews))
	}
	bad := dropTestPreviewRequest(testId("ref"), 3)
	bad.Paths[0].Lineage[1].Epoch = 3
	badBody, _ := proto.Marshal(bad)
	requireRefusal(t, fixture.serve(http.MethodPost, fixture.path("/preview"), adminToken, badBody), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	large := dropTestPreviewRequest(testId("ref"), 1048576)
	large.Paths = append(large.Paths, dropTestPreviewRequest(testId("ref"), 1).Paths[0])
	largeBody, _ := proto.Marshal(large)
	requireRefusal(t, fixture.serve(http.MethodPost, fixture.path("/preview"), adminToken, largeBody), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_DROP_LIST)
	requireRefusal(t, fixture.serve(http.MethodPost, fixture.path("/preview"), fixture.token(fixture.reader, repoScope(fixture.repoId, "r")), body),
		http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
}

// A dry run end to end: resolve and mark at a snapshot (EVSB-M10-04's stand-ins), then one HEAD a candidate: shared
// for a marked one, young for one whose LastModified + AdoptionBound the snapshot's horizon has not passed, freed for
// the rest; one at a time a repo; and failed when its resolve is not built.
func TestDropPreviewsRunToDone(t *testing.T) {
	fixture := newDropRoutesFixture(t)
	adminToken := fixture.token(fixture.admin, repoScope(fixture.repoId, "admin"))
	body, _ := proto.Marshal(dropTestPreviewRequest(testId("ref"), 3))
	first := &protocol.EvsDropPreviewReply{}
	proto.Unmarshal(fixture.serve(http.MethodPost, fixture.path("/preview"), adminToken, body).Body.Bytes(), first)
	second := &protocol.EvsDropPreviewReply{}
	proto.Unmarshal(fixture.serve(http.MethodPost, fixture.path("/preview"), adminToken, body).Body.Bytes(), second)
	segment := fixture.rawCluster("seg-1")
	put := func(segmentId [32]byte, byteCount int) {
		if _, err := segment.PutIfNoneMatch(fixture.ctx, SegmentKey(fixture.repoId, segmentId), bytes.Repeat([]byte{7}, byteCount), nil); err != nil {
			t.Fatal(err)
		}
	}
	old, shared, young := [32]byte{1}, [32]byte{2}, [32]byte{3}
	put(old, 100)
	put(shared, 200)
	fixture.clock.Advance(30 * time.Hour)
	put(young, 400)
	events := &dropJobEvents{}
	resolver := &fakeDropResolver{
		events:     events,
		candidates: []DropScanId{DropSegmentId(old), DropSegmentId(shared), DropSegmentId(young), DropSegmentId([32]byte{4})},
		preview: &DropPreviewResolveResult{
			Paths:           []*protocol.EvsDropPreviewPath{{ListMatch: true, Count: 3, MapParts: []uint32{0}, Linked: true}},
			SnapshotVersion: 9, InlineByteCount: 33, VersionCount: 12,
		},
	}
	marker := &fakeDropMarker{events: events, marks: []DropScanId{DropSegmentId(shared)}}
	horizon := &fakeDropHorizon{events: events, horizon: fixture.clock.Now().Add(-time.Hour)}
	previews, err := NewDropPreviews(fixture.host.ServiceHost(), &DropPreviewDeps{Resolver: resolver, Marker: marker, Horizon: horizon})
	if err != nil {
		t.Fatal(err)
	}
	result, err := previews.Run(fixture.ctx, "meta-1", fixture.repoId)
	if err != nil || result.State != protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_DONE || result.PreviewId != sidecar.Id(first.PreviewId) {
		t.Fatalf("the run: %+v %v", result, err)
	}
	if result.Next.IsZero() {
		t.Fatal("a queued dry run behind the first asked for no run")
	}
	adminToken = fixture.token(fixture.admin, repoScope(fixture.repoId, "admin"))
	recorder := fixture.serve(http.MethodGet, fixture.path("/preview/"+sidecar.EvsKeyId(sidecar.Id(first.PreviewId))), adminToken, nil)
	reply := &protocol.EvsDropPreviewReply{}
	if recorder.Code != http.StatusOK || proto.Unmarshal(recorder.Body.Bytes(), reply) != nil {
		t.Fatalf("GET of a done dry run: %d", recorder.Code)
	}
	if reply.State != protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_DONE || reply.FreedBytes != 100 || reply.SharedBytes != 200 || reply.YoungBytes != 400 ||
		reply.InlineBytes != 33 || reply.SnapshotVersion != 9 || len(reply.Paths) != 1 || !reply.Paths[0].Linked || !reply.Paths[0].ListMatch {
		t.Fatalf("the results: %+v", reply)
	}
	if marker.requests[0].JobId != sidecar.Id(first.PreviewId) || !marker.requests[0].Horizon.Equal(horizon.horizon) {
		t.Fatal("mark was not asked at the dry run's snapshot")
	}
	// the second runs once the first has ended; with no resolve built it fails
	unbuilt, err := NewDropPreviews(fixture.host.ServiceHost(), &DropPreviewDeps{Marker: marker, Horizon: horizon})
	if err != nil {
		t.Fatal(err)
	}
	result, err = unbuilt.Run(fixture.ctx, "meta-1", fixture.repoId)
	if err != nil || result.State != protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_FAILED || result.PreviewId != sidecar.Id(second.PreviewId) {
		t.Fatalf("an unbuilt dry run: %+v %v", result, err)
	}
	if preview := fixture.table().Preview(sidecar.Id(second.PreviewId)); preview.State != protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_FAILED {
		t.Fatal("the failed dry run's record")
	}
}

// One at a time a repo: a running dry run under a live lease keeps the next queued.
func TestDropPreviewsRunOneAtATime(t *testing.T) {
	fixture := newDropRoutesFixture(t)
	adminToken := fixture.token(fixture.admin, repoScope(fixture.repoId, "admin"))
	body, _ := proto.Marshal(dropTestPreviewRequest(testId("ref"), 3))
	fixture.serve(http.MethodPost, fixture.path("/preview"), adminToken, body)
	fixture.serve(http.MethodPost, fixture.path("/preview"), adminToken, body)
	fixture.setTable(func(state *DropTableState, now time.Time) {
		state.Previews[0].State = protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_RUNNING
		state.Previews[0].UntilMs = now.Add(time.Minute).UnixMilli()
	})
	previews, err := NewDropPreviews(fixture.host.ServiceHost(), &DropPreviewDeps{Horizon: &fakeDropHorizon{events: &dropJobEvents{}}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := previews.Run(context.Background(), "meta-1", fixture.repoId)
	if err != nil || result.PreviewId != (sidecar.Id{}) || result.Next.IsZero() {
		t.Fatalf("a run beside a running dry run: %+v %v", result, err)
	}
	if fixture.table().Previews[1].State != protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_QUEUED {
		t.Fatal("a second dry run started beside the first")
	}
}
