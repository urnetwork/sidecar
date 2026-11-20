//go:build !ios_extension

// A DROP at the storage limit and on a full cluster (QD-1088, QD-1099; owner decision 620; §11.14's limit and drop
// rows, §19.9's cohorts row, §20.7; EVS2-M10-21's loop with SEARCH-M10-18's rewriter): against the stand-in evs behind
// a model of evs's storage gate, which refuses a segment upload and a push that adds payload while a network is over
// its limit or spent, or while its repo's metadata cluster stands at its cohort limit, a DROP naming no new segment
// excepted. A DROP whose index rewrites take a bucket shard, an upload, is refused for it and lands on its second send
// without them, the listed versions staying in the shard, masked by the kept version's entry, while the backfill's
// rewrite waits, each look refused with its floor kept, and gone once it runs with the limit lifted; a DROP whose
// rewrites are all staged lands at once with them; a DROP whose kept head needs an upload is refused with or without
// rewrites, evs's refusal going back to the person as it is, and lands with its rewrites when the command is run again
// once the limit lifts. Each holds at the storage limit's 403 QUOTA_LIMIT and on a full cluster's 507 CLUSTER_FULL
// with its wait; while spent the 402 is answered as the 403, the hook never asked again; and a 507 at the push itself,
// step 5c's, recorded, is answered as an upload's.

package sidecar

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// evs's storage gate as the stand-in's front (evsservice/quota_gate.go's CheckUpload and CheckPush with
// QuotaRefusesAtLimit; §20.7): while over, a segment upload is refused, and so is a one-part push naming a new segment,
// a staged segment or an inline record, but a DROP or a CUT, refused only when it names a new segment, and maintenance
// that adds nothing. Closure and re-seed uploads, lifecycle and authorization pushes and parted pushes are not
// modelled, and none is sent here. A cluster at its cohort limit refuses the same pushes and uploads, 507 CLUSTER_FULL
// with Retry-After (evsservice/cluster_limit.go; §19.9's cohorts row).
type evsTestDropLimitGate struct {
	t       *testing.T
	handler http.Handler

	stateLock sync.Mutex
	limit     evsTestDropLimit
	// the uploads and pushes refused so far
	refusedUploadCount int
	refusedPushCount   int
}

// What holds the stand-in's network to what the storage limit accepts.
type evsTestDropLimit int

const (
	// nothing: under its limit
	evsTestDropLimitNone evsTestDropLimit = iota
	// its storage limit: 403 QUOTA_LIMIT
	evsTestDropLimitStorage
	// out of balance, which a purchase lifts: 402 QUOTA_PAYMENT
	evsTestDropLimitSpent
	// its repo's cluster at the cohort limit: 507 CLUSTER_FULL
	evsTestDropLimitClusterFull
)

// Puts a gate, under its limit, between capture and the stand-in it hands to.
func newEvsTestDropLimitGate(t *testing.T, capture *evsTestDropCapture) *evsTestDropLimitGate {
	gate := &evsTestDropLimitGate{t: t, handler: capture.handler}
	capture.handler = gate
	return gate
}

// Sets what holds the network.
func (self *evsTestDropLimitGate) set(limit evsTestDropLimit) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.limit = limit
}

// The uploads and the pushes refused so far.
func (self *evsTestDropLimitGate) refused() (int, int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.refusedUploadCount, self.refusedPushCount
}

// What evs answers under limit: the QuotaRefusal, 403 QUOTA_LIMIT at the storage limit and 402 QUOTA_PAYMENT while
// spent, or a full cluster's 507 CLUSTER_FULL with its wait.
func evsTestDropLimitRefusal(limit evsTestDropLimit) *evsTestRefusal {
	switch limit {
	case evsTestDropLimitSpent:
		return &evsTestRefusal{status: http.StatusPaymentRequired, reply: &protocol.EvsRefusalReply{
			Code: protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_PAYMENT, Quota: &protocol.EvsQuotaRefusal{LimitKey: "balance", Upgrade: true},
		}}
	case evsTestDropLimitClusterFull:
		return &evsTestRefusal{status: http.StatusInsufficientStorage, reply: &protocol.EvsRefusalReply{
			Code: protocol.EvsRefusalCode_EVS_REFUSAL_CLUSTER_FULL, RetryAfterMs: uint32((7 * time.Minute).Milliseconds()),
		}}
	}
	return &evsTestRefusal{status: http.StatusForbidden, reply: &protocol.EvsRefusalReply{
		Code: protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_LIMIT, Quota: &protocol.EvsQuotaRefusal{LimitKey: "evs_storage_bytes", Limit: 1, Used: 2},
	}}
}

func (self *evsTestDropLimitGate) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	self.stateLock.Lock()
	limit := self.limit
	self.stateLock.Unlock()
	path := request.URL.Path
	switch {
	case limit == evsTestDropLimitNone:
	case request.Method == http.MethodPut && strings.Contains(path, "/segments/"):
		self.stateLock.Lock()
		self.refusedUploadCount += 1
		self.stateLock.Unlock()
		evsTestRefuse(writer, evsTestDropLimitRefusal(limit))
		return
	case request.Method == http.MethodPost && strings.HasSuffix(path, "/push"):
		body, _ := io.ReadAll(request.Body)
		request.Body = io.NopCloser(bytes.NewReader(body))
		if self.refusesPush(body) {
			self.stateLock.Lock()
			self.refusedPushCount += 1
			self.stateLock.Unlock()
			evsTestRefuse(writer, evsTestDropLimitRefusal(limit))
			return
		}
	}
	self.handler.ServeHTTP(writer, request)
}

// Whether the limit refuses a posted push, as QuotaRefusesAtLimit classifies it from its flags and what it adds. A push
// the gate cannot read is the stand-in's to answer.
func (self *evsTestDropLimitGate) refusesPush(body []byte) bool {
	pushRequest := &protocol.EvsPushRequest{}
	if proto.Unmarshal(body, pushRequest) != nil {
		return false
	}
	statement, err := ParseEvsStatementFormat2(pushRequest.GetStatement())
	if err != nil {
		return false
	}
	if 0 < len(pushRequest.GetPartPlaces()) {
		self.t.Errorf("a parted push at the limit gate, which models none")
		return true
	}
	checked, err := EvsCheckPayloadFormat2(statement, pushRequest.GetPayload(), pushRequest.GetStaged())
	if err != nil {
		return false
	}
	newSegmentCount, stagedSegmentCount, inlineRecordCount := testDropLimitNewSegmentCount(checked), 0, 0
	for _, object := range checked.NewObjects {
		if object.Kind == protocol.EvsNewObjectKind_EVS_NEW_OBJECT_STAGED_SEGMENT {
			stagedSegmentCount += 1
		}
	}
	for _, change := range checked.Changes {
		entry := &protocol.EvsEntryVersion{}
		if change.EntryVersion == nil || proto.Unmarshal(change.EntryVersion, entry) != nil {
			continue
		}
		for _, locator := range entry.GetChain() {
			if locator.GetKind() == uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE) {
				inlineRecordCount += 1
			}
		}
	}
	flags := statement.Push.GetFlags()
	switch {
	case flags&uint32(protocol.EvsPushFlag_EVS_PUSH_CLOSURE) != 0:
		return false
	case flags&uint32(protocol.EvsPushFlag_EVS_PUSH_DROP|protocol.EvsPushFlag_EVS_PUSH_CUT) != 0:
		return newSegmentCount != 0
	}
	return newSegmentCount != 0 || stagedSegmentCount != 0 || inlineRecordCount != 0
}

// The new segments a checked push names: what the limit refuses a DROP for.
func testDropLimitNewSegmentCount(checked *EvsCheckedPayload) int {
	count := 0
	for _, object := range checked.NewObjects {
		if object.Kind == protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT {
			count += 1
		}
	}
	return count
}

// Fails t unless err is the refusal evs answers under limit, as it answered it: its status, code, quota and wait.
func testDropLimitGoesBack(t testing.TB, err error, limit evsTestDropLimit) {
	t.Helper()
	want := evsTestDropLimitRefusal(limit)
	refusal, ok := EvsErrorOf(err)
	if !ok || refusal.Status != want.status || refusal.Code != want.reply.GetCode() || !proto.Equal(refusal.Quota, want.reply.GetQuota()) ||
		refusal.RetryAfter != time.Duration(want.reply.GetRetryAfterMs())*time.Millisecond {
		t.Fatalf("not evs's refusal under the limit as it answered it: %v", err)
	}
}

// Whether err is a backfill's look waiting under limit: the index's quota refusal at the storage limit or while spent,
// and evs's 507 on a full cluster, which the index store hands on as it is.
func testDropLimitBackfillWaits(limit evsTestDropLimit, err error) bool {
	if limit == evsTestDropLimitClusterFull {
		return IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_CLUSTER_FULL)
	}
	return isIndexRefusal(err, indexRefusalQuota)
}

// The index of the stand-in's main ref as a reader of its head loads it.
func testDropLimitView(t testing.TB, writer *evsTestWriter) *indexView {
	t.Helper()
	view, err := indexLoadView(context.Background(), &indexViewArgs{
		store: newIndexEvsStore(writer.repo, nil, false), repoId: writer.world.repoId, refId: writer.world.refId,
		repoKind: protocol.RepoKind_REPO_KIND_GENERAL, isAdmin: func(*indexFileVersion) bool { return true }, settings: DefaultIndexFormatSettings(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return view
}

// One head push of the stand-in writer's own index entries, planned at the head as any writer's is and committed
// through the client, the clock moving a minute; the plan.
func testDropLimitIndexPush(t testing.TB, writer *evsTestWriter, pending ...*indexPendingDocument) *indexHeadPlan {
	t.Helper()
	view := testDropLimitView(t, writer)
	signedTimeMs := writer.test.clock.Now().UnixMilli()
	plan, err := indexPlanHead(context.Background(), &indexHeadPlanArgs{
		view: view, root: view.writeRoot(), writer: writer.world.signer.sidecarId, signedTimeMs: signedTimeMs, tables: testHeadTables,
		pending: pending, mayMerge: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.mergeFirst || plan.mergeInPush {
		t.Fatalf("an index push that cannot commit by itself")
	}
	if _, err := newIndexEvsStore(writer.repo, nil, false).Commit(context.Background(), &indexPush{
		pushId: NewId(), baseVersion: view.head.version, indexEpoch: view.head.indexEpoch, signedTimeMs: signedTimeMs,
		files: plan.files(), removals: plan.removals(),
	}); err != nil {
		t.Fatal(err)
	}
	writer.test.clock.advance(time.Minute)
	return plan
}

// The stand-in's DROP world with a bucket shard: a.txt written three times, and the writer's own index of the main ref
// holding a.txt's first version in a merged shard, among the documents that sealed its slot, and its third, the head's,
// in its head's slot; a.txt's doc_key.
func testDropLimitShardWorld(t *testing.T) (*evsTestWriter, *evsTestDropCapture, *evsTestDropLimitGate, [indexIdByteCount]byte) {
	t.Helper()
	writer, server, capture := newEvsTestDropPusher(t)
	gate := newEvsTestDropLimitGate(t, capture)
	writer.server.indexEpochs = true
	writer.test.client.SetWritePlanHook(func(ctx context.Context, plan *EvsWritePlan) error {
		for _, planned := range plan.Paths {
			writer.server.know(planned.Path)
		}
		return nil
	})
	t.Cleanup(func() { writer.test.client.SetWritePlanHook(nil) })
	evsTestDropHistory(t, writer, server, "a.txt", 500, 3)
	key := testIndexDropEvsKey(t, writer, "a.txt")
	testDropLimitIndexPush(t, writer, testIndexDropLive(key, 1, testIndexDropKeys(1)))
	for index := 0; ; index += 1 {
		plan := testDropLimitIndexPush(t, writer, testLive("fill", index, 1, testIndexKeys(0x300000+index*0x1000, 1500, 1)))
		if len(plan.buckets[0].sealedSlots) != 0 {
			break
		}
		if 256 < index {
			t.Fatal("no seal")
		}
	}
	store := newIndexEvsStore(writer.repo, nil, false)
	merger, err := indexNewMerger(&indexMergerArgs{
		store: store, repoId: writer.world.repoId, refId: writer.world.refId, repoKind: protocol.RepoKind_REPO_KIND_GENERAL,
		isAdmin: func(*indexFileVersion) bool { return true }, format: DefaultIndexFormatSettings(),
		padKey: func(ctx context.Context) (*indexPadKey, error) {
			return testPadKey(t, 2), nil
		},
		tables: testHeadTables, clock: writer.test.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	startDay := testDropLimitView(t, writer).writeRoot().newestBucket().window.startDay
	outcome, err := merger.Merge(context.Background(), indexRootNumber, startDay)
	if err != nil || outcome.committed == nil {
		t.Fatalf("the merge: %+v, %v", outcome, err)
	}
	writer.test.clock.advance(time.Minute)
	testDropLimitIndexPush(t, writer, testIndexDropLive(key, 3, testIndexDropKeys(3)))
	return writer, capture, gate, key
}

// The paths of the bucket and all shards holding key at version.
func testDropLimitShardsHolding(t testing.TB, view *indexView, key [indexIdByteCount]byte, version uint64) []string {
	t.Helper()
	paths := []string{}
	for _, held := range testIndexDropHolding(t, view, key) {
		parsed, ok := indexParsePath(held.path, false)
		if ok && held.version == version && (parsed.kind == indexPathBucketShard || parsed.kind == indexPathAllShard) {
			paths = append(paths, held.path)
		}
	}
	return paths
}

// Under limit the DROP's rewrite of the shard holding a.txt's first version is an upload, which evs refuses, so the
// DROP goes again once without its rewrites and commits. The listed version stays in the shard, masked by the kept
// version's entry in every search, while the backfill's rewrite, the payload it is, is refused at each look under the
// limit, its floor where it was, and the look after the limit lifts takes it out, no search changing.
func testDropLimitLandsWithoutAShardRewrite(t *testing.T, limit evsTestDropLimit) {
	writer, capture, gate, key := testDropLimitShardWorld(t)
	before := testDropLimitView(t, writer)
	if len(testDropLimitShardsHolding(t, before, key, 1)) != 1 {
		t.Fatal("no shard holds the listed version")
	}
	searches := testIndexDropSearches(t, before)
	if hits := testIndexDropSearch(t, before, testIndexDropVersionKey(3)); hits[key] != 3 {
		t.Fatalf("a search missed the head's version: %v", hits)
	}
	rewriter := testIndexDropEvsRewriter(t, writer, true)
	calls := []bool{}
	writer.test.client.SetDropIndexHook(func(ctx context.Context, repo *EvsRepo, args *EvsDropIndexArgs) (*EvsDropIndexRewrites, error) {
		calls = append(calls, args.Rebuild)
		return rewriter.Hook(ctx, repo, args)
	})
	t.Cleanup(func() { writer.test.client.SetDropIndexHook(nil) })
	gate.set(limit)
	result := testIndexDropEvsDrop(t, writer)
	if len(result.Pushes) != 1 || result.Pushes[0].IndexRewritten {
		t.Fatalf("the DROP's pushes %+v", result.Pushes)
	}
	// the first send stopped at the shard's upload; the second, the hook not asked again, posted the kept head alone
	uploads, pushes := gate.refused()
	if uploads != 1 || pushes != 0 || !slices.Equal(calls, []bool{false}) {
		t.Fatalf("%d uploads and %d pushes refused, hook calls %v", uploads, pushes, calls)
	}
	if drops := capture.drops(t); len(drops) != 1 || len(drops[0].Changes) != 1 {
		t.Fatalf("%d DROP pushes posted", len(drops))
	}
	if _, info, err := evsTestReadFormat2(t, writer, "a.txt"); err != nil || info.Version != 4 {
		t.Fatalf("the kept head after the DROP: %+v, %v", info, err)
	}
	masked := testDropLimitView(t, writer)
	if len(testDropLimitShardsHolding(t, masked, key, 1)) != 1 {
		t.Fatal("the shard moved with a DROP sent without rewrites")
	}
	if hits := testIndexDropSearch(t, masked, testIndexDropVersionKey(1)); len(hits) != 0 {
		t.Fatalf("a search found a listed version: %v", hits)
	}
	testIndexDropSearchesEqual(t, searches, testIndexDropSearches(t, masked))

	// the backfill: each look under the limit refused at the shard's upload, its floor where it was, and done by the
	// look after the limit lifts
	store := newIndexEvsStore(writer.repo, nil, false)
	head, err := store.Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	content := &testIndexDropContent{refId: writer.world.refId, head: head.version, drops: []*indexContentDrop{{
		version: result.Pushes[0].Version, signedTimeMs: writer.test.clock.Now().UnixMilli(),
		paths: []*indexDroppedPath{testIndexDroppedPath("a.txt", 3, 1, 2, 3)},
	}}}
	drops := indexNewDropBackfill(&IndexDropSettings{ChunkScanCount: 4, AttemptCount: 2})
	backfiller, err := indexNewBackfiller(&indexBackfillArgs{
		store: store, repoId: writer.world.repoId, refId: writer.world.refId, repoKind: protocol.RepoKind_REPO_KIND_GENERAL,
		isAdmin: func(*indexFileVersion) bool { return true }, format: DefaultIndexFormatSettings(), tables: testHeadTables,
		clock: writer.test.clock, writer: writer.world.signer.sidecarId, refKey: testIndexDropEvsRefKey(t, writer),
		contents: []indexContentRef{content}, drops: drops,
	})
	if err != nil {
		t.Fatal(err)
	}
	writer.test.clock.advance(DefaultIndexBackfillSettings().BackfillAge)
	lookCount := 2
	for look := 0; look < lookCount; look += 1 {
		if _, err := backfiller.backfillDrops(context.Background()); !testDropLimitBackfillWaits(limit, err) {
			t.Fatalf("look %d of the backfill under the limit: %v", look, err)
		}
		if floor := drops.floor(writer.world.refId); floor != 0 {
			t.Fatalf("a refused look raised the floor to %d", floor)
		}
		waiting := testDropLimitView(t, writer)
		if len(testDropLimitShardsHolding(t, waiting, key, 1)) != 1 {
			t.Fatal("a refused backfill moved the shard")
		}
		testIndexDropSearchesEqual(t, searches, testIndexDropSearches(t, waiting))
		// the schedule's next tick
		writer.test.clock.advance(time.Minute)
	}
	if uploads, pushes := gate.refused(); uploads != 1+lookCount || pushes != 0 {
		t.Fatalf("%d uploads and %d pushes refused after the backfill's looks", uploads, pushes)
	}
	gate.set(evsTestDropLimitNone)
	outcome, err := backfiller.backfillDrops(context.Background())
	if err != nil || outcome.committedCount != 1 {
		t.Fatalf("the look after the limit: %+v, %v", outcome, err)
	}
	if floor := drops.floor(writer.world.refId); floor != result.Pushes[0].Version {
		t.Fatalf("the floor after the look %d, the DROP's version %d", floor, result.Pushes[0].Version)
	}
	after := testDropLimitView(t, writer)
	testIndexDropNoneHeld(t, after, key, 1, 2)
	testIndexDropHeldLive(t, after, key, 3)
	testIndexDropSearchesEqual(t, searches, testIndexDropSearches(t, after))
}

// QD-1088 at the storage limit: the shard's upload is refused 403 QUOTA_LIMIT, the DROP lands without its rewrites,
// and the backfill's rewrite waits at the limit and runs under it.
func TestEvsDropAtTheLimitLandsWithoutAShardRewrite(t *testing.T) {
	testDropLimitLandsWithoutAShardRewrite(t, evsTestDropLimitStorage)
}

// QD-1099 on a metadata cluster at its cohort limit: the shard's upload is refused 507 CLUSTER_FULL, and the DROP,
// which §19.9's cohorts row lets pass there, lands without its rewrites as at the storage limit; the backfill's
// rewrite, refused 507 at each look while the cluster is full, comes in again and takes the listed version out once
// the cluster has room.
func TestEvsDropOnAFullClusterLandsWithoutAShardRewrite(t *testing.T) {
	testDropLimitLandsWithoutAShardRewrite(t, evsTestDropLimitClusterFull)
}

// Under limit a DROP whose rewrites are all staged, a slot's here, uploads nothing and lands at once with them: evs
// takes a DROP that names no new segment, its staged rewrites and its inline kept head with it. What the limit refuses
// is still refused: a content write is payload.
func testDropLimitLandsWithStagedRewrites(t *testing.T, limit evsTestDropLimit) {
	writer, _, capture, path := testIndexDropEvsWorld(t)
	gate := newEvsTestDropLimitGate(t, capture)
	before := testIndexDropEvsSlot(t, writer, path)
	t.Cleanup(testIndexDropEvsRewriter(t, writer, true).Install())
	gate.set(limit)
	result := testIndexDropEvsDrop(t, writer)
	if len(result.Pushes) != 1 || !result.Pushes[0].IndexRewritten {
		t.Fatalf("the DROP's pushes %+v", result.Pushes)
	}
	if uploads, pushes := gate.refused(); uploads != 0 || pushes != 0 {
		t.Fatalf("%d uploads and %d pushes refused", uploads, pushes)
	}
	drops := capture.drops(t)
	if len(drops) != 1 || len(drops[0].Changes) != 2 || len(drops[0].Staged) == 0 {
		t.Fatalf("%d DROP pushes posted", len(drops))
	}
	after := testIndexDropEvsSlot(t, writer, path)
	if after.file.version == before.file.version || len(after.slot.entries) != 1 || after.slot.entries[0].key != testIndexDropEvsKey(t, writer, "b.txt") {
		t.Fatalf("the slot after the DROP: version %d, %d entries", after.file.version, len(after.slot.entries))
	}
	_, err := writer.write(t, "c.txt", []byte("payload at the limit"))
	testDropLimitGoesBack(t, err, limit)
}

// At the storage limit a DROP naming no new segment passes, its staged rewrites with it.
func TestEvsDropAtTheLimitLandsWithStagedRewrites(t *testing.T) {
	testDropLimitLandsWithStagedRewrites(t, evsTestDropLimitStorage)
}

// A full cluster passes a DROP that names no new segment (§19.9's cohorts row): its staged rewrites ride it, and are
// not left to the backfill for want of a refusal.
func TestEvsDropOnAFullClusterLandsWithStagedRewrites(t *testing.T) {
	testDropLimitLandsWithStagedRewrites(t, evsTestDropLimitClusterFull)
}

// Under limit a DROP whose kept head needs an upload is refused, evs's refusal going back to the person as it is: at
// once where it carries no rewrites, and after one more send without them where it does, never a third. Nothing is
// dropped and no index file moves, and the same command run again once the limit lifts lands with its rewrites.
func testDropLimitRefusedForItsKeptHead(t *testing.T, limit evsTestDropLimit) {
	writer, server, capture, _ := testIndexDropEvsWorld(t)
	gate := newEvsTestDropLimitGate(t, capture)
	writer.server.stateLock.Lock()
	uploaded := len(writer.server.uploads)
	writer.server.stateLock.Unlock()
	evsTestDropHistory(t, writer, server, "big.bin", 40000, 3)
	writer.server.stateLock.Lock()
	uploaded = len(writer.server.uploads) - uploaded
	writer.server.stateLock.Unlock()
	if uploaded == 0 {
		t.Fatal("a head that is no upload")
	}
	_, head, err := evsTestReadFormat2(t, writer, "big.bin")
	if err != nil {
		t.Fatal(err)
	}
	// a third writer's slot holding big.bin's first version, which the DROP's rewrite takes out, staged
	third := evsTestId("third writer")
	header := indexNewFileHeader(indexFileSlot, indexLinkedTables())
	header.BucketStartDay, header.BucketDays, header.WriterSidecarId, header.Seq = 20340, 30, third.Bytes(), 1
	bigKey := testIndexDropEvsKey(t, writer, "big.bin")
	slot, err := indexEncodeSlot(&indexSlot{header: header, entries: []*indexEntry{
		{kind: indexEntryFull, key: bigKey, version: head.Version - 2, timeSeconds: 1757400000, row: testFileRow(testIndexDropKeys(1)), keys: testIndexDropKeys(1)},
		{kind: indexEntryFull, key: testIndexDropEvsKey(t, writer, "b.txt"), version: 2, timeSeconds: 1757400000, row: testFileRow(testIndexDropKeys(100)), keys: testIndexDropKeys(100)},
	}}, false, DefaultIndexFormatSettings())
	if err != nil {
		t.Fatal(err)
	}
	slotPath, err := indexNewPaths(false, indexRootNumber).slot(20340, [indexIdByteCount]byte(third.Bytes()), 0)
	if err != nil {
		t.Fatal(err)
	}
	testIndexDropEvsCommitSlot(t, writer, slotPath, slot, 0)
	before := testIndexDropEvsSlot(t, writer, slotPath)
	preview, err := writer.repo.DropHistoryPreview(context.Background(), &EvsDropPreviewArgs{Paths: []string{"big.bin"}})
	if err != nil {
		t.Fatal(err)
	}
	drop := func() (*EvsDropHistoryResult, error) {
		return writer.repo.DropHistory(context.Background(), &EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: "big.bin"})
	}
	gate.set(limit)

	// with no rewrites: one send, refused at the kept head's upload
	_, err = drop()
	testDropLimitGoesBack(t, err, limit)
	if uploads, pushes := gate.refused(); uploads != 1 || pushes != 0 {
		t.Fatalf("%d uploads and %d pushes refused", uploads, pushes)
	}

	// with rewrites: sent with them, then once without, and the second refusal goes back as it is
	rewriter := testIndexDropEvsRewriter(t, writer, true)
	calls := []bool{}
	writer.test.client.SetDropIndexHook(func(ctx context.Context, repo *EvsRepo, args *EvsDropIndexArgs) (*EvsDropIndexRewrites, error) {
		calls = append(calls, args.Rebuild)
		return rewriter.Hook(ctx, repo, args)
	})
	t.Cleanup(func() { writer.test.client.SetDropIndexHook(nil) })
	_, err = drop()
	testDropLimitGoesBack(t, err, limit)
	if uploads, pushes := gate.refused(); uploads != 3 || pushes != 0 || !slices.Equal(calls, []bool{false}) {
		t.Fatalf("%d uploads and %d pushes refused, hook calls %v", uploads, pushes, calls)
	}
	if drops := capture.drops(t); len(drops) != 0 {
		t.Fatalf("%d DROP pushes posted at the limit", len(drops))
	}
	if _, info, err := evsTestReadFormat2(t, writer, "big.bin"); err != nil || info.Version != head.Version {
		t.Fatalf("the head after a refused DROP: %+v, %v", info, err)
	}
	if after := testIndexDropEvsSlot(t, writer, slotPath); after.file.version != before.file.version {
		t.Fatal("the slot moved with a refused DROP")
	}

	// once the limit lifts the same dry run's command lands, its rewrites with it
	gate.set(evsTestDropLimitNone)
	result, err := drop()
	if err != nil || len(result.Pushes) != 1 || !result.Pushes[0].IndexRewritten {
		t.Fatalf("the DROP under the limit: %+v, %v", result, err)
	}
	if drops := capture.drops(t); len(drops) != 1 || len(drops[0].Changes) != 2 {
		t.Fatalf("%d DROP pushes posted under the limit", len(drops))
	}
	after := testIndexDropEvsSlot(t, writer, slotPath)
	if len(after.slot.entries) != 1 || after.slot.entries[0].key == bigKey {
		t.Fatalf("the slot after the DROP holds %d entries", len(after.slot.entries))
	}
}

// At the storage limit a kept head that needs an upload is refused it, and the 403 QUOTA_LIMIT goes back to the person.
func TestEvsDropAtTheLimitRefusedForItsKeptHead(t *testing.T) {
	testDropLimitRefusedForItsKeptHead(t, evsTestDropLimitStorage)
}

// QD-1099's other half: on a full cluster a kept head that needs an upload is refused it, 507 CLUSTER_FULL, and that
// 507 goes back to the person with its wait, after one more send without the rewrites where the DROP carries them;
// once the cluster has room the same command lands with its rewrites.
func TestEvsDropOnAFullClusterRefusedForItsKeptHead(t *testing.T) {
	testDropLimitRefusedForItsKeptHead(t, evsTestDropLimitClusterFull)
}

// While spent evs answers 402 QUOTA_PAYMENT, and the loop treats it as the storage limit's 403: a DROP whose rewrite
// is an upload goes again once without it, the hook not asked a second time, and lands; with nothing to leave out the
// 402 goes back to the person.
func TestEvsDropWhileSpentLandsWithoutAnUploadedRewrite(t *testing.T) {
	writer, server, capture := newEvsTestDropPusher(t)
	gate := newEvsTestDropLimitGate(t, capture)
	evsTestDropHistory(t, writer, server, "a.txt", 500, 2)
	evsTestDropHistory(t, writer, server, "big.bin", 40000, 2)
	writer.server.know(".ur-index/x")
	calls := []bool{}
	writer.test.client.SetDropIndexHook(func(ctx context.Context, repo *EvsRepo, args *EvsDropIndexArgs) (*EvsDropIndexRewrites, error) {
		calls = append(calls, args.Rebuild)
		return &EvsDropIndexRewrites{Writes: []*EvsPathWrite{{
			Path: ".ur-index/x", Content: bytes.NewReader(evsTestContent("a shard's rewrite", 40000)), Options: &EvsWriteOptions{Reserved: EvsReservedIndex},
		}}}, nil
	})
	t.Cleanup(func() { writer.test.client.SetDropIndexHook(nil) })
	preview, err := writer.repo.DropHistoryPreview(context.Background(), &EvsDropPreviewArgs{Paths: []string{"a.txt"}})
	if err != nil {
		t.Fatal(err)
	}
	gate.set(evsTestDropLimitSpent)
	result, err := writer.repo.DropHistory(context.Background(), &EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: "a.txt"})
	if err != nil || len(result.Pushes) != 1 || result.Pushes[0].IndexRewritten {
		t.Fatalf("the DROP while spent: %+v, %v", result, err)
	}
	if uploads, pushes := gate.refused(); uploads != 1 || pushes != 0 || !slices.Equal(calls, []bool{false}) {
		t.Fatalf("%d uploads and %d pushes refused, hook calls %v", uploads, pushes, calls)
	}
	if drops := capture.drops(t); len(drops) != 1 || len(drops[0].Changes) != 1 {
		t.Fatalf("%d DROP pushes posted", len(drops))
	}
	// a kept head needing an upload: the 402 goes back, after the one send without the rewrite
	preview, err = writer.repo.DropHistoryPreview(context.Background(), &EvsDropPreviewArgs{Paths: []string{"big.bin"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = writer.repo.DropHistory(context.Background(), &EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: "big.bin"})
	testDropLimitGoesBack(t, err, evsTestDropLimitSpent)
	if !slices.Equal(calls, []bool{false, false}) {
		t.Fatalf("hook calls %v", calls)
	}
	if drops := capture.drops(t); len(drops) != 1 {
		t.Fatalf("%d DROP pushes posted", len(drops))
	}
}

// Step 5c's 507 (evsservice/check_refs.go's checkStorageLimit): where the cluster fills between a DROP's uploads and
// its push, evs refuses the push itself, recorded, for the new segment its rewrite names, and the loop answers it as an
// upload's 507: the DROP goes again once without its rewrites, the hook not asked again, names no new segment and
// lands. A kept head that is a new segment itself is refused at the push again then, and that 507 goes back to the
// person as it is, after two sends.
func TestEvsDropOnAFullClusterRefusedAtItsPushGoesWithoutItsRewrites(t *testing.T) {
	writer, server, capture := newEvsTestDropPusher(t)
	evsTestDropHistory(t, writer, server, "a.txt", 500, 2)
	evsTestDropHistory(t, writer, server, "big.bin", 40000, 2)
	writer.server.know(".ur-index/x")
	calls := []bool{}
	writer.test.client.SetDropIndexHook(func(ctx context.Context, repo *EvsRepo, args *EvsDropIndexArgs) (*EvsDropIndexRewrites, error) {
		calls = append(calls, args.Rebuild)
		return &EvsDropIndexRewrites{Writes: []*EvsPathWrite{{
			Path: ".ur-index/x", Content: bytes.NewReader(evsTestContent("a shard's rewrite", 40000)), Options: &EvsWriteOptions{Reserved: EvsReservedIndex},
		}}}, nil
	})
	t.Cleanup(func() { writer.test.client.SetDropIndexHook(nil) })
	// the next count pushes posted are refused as step 5c refuses them on a full cluster, each recorded
	refuseFull := func(count int) {
		refusals := []*evsTestRefusal{}
		for i := 0; i < count; i += 1 {
			refusal := evsTestDropLimitRefusal(evsTestDropLimitClusterFull)
			refusal.reply.Recorded = true
			refusals = append(refusals, refusal)
		}
		writer.server.stateLock.Lock()
		defer writer.server.stateLock.Unlock()
		writer.server.pushRefusals = refusals
	}
	drop := func(path string) (*EvsDropHistoryResult, error) {
		preview, err := writer.repo.DropHistoryPreview(context.Background(), &EvsDropPreviewArgs{Paths: []string{path}})
		if err != nil {
			t.Fatal(err)
		}
		return writer.repo.DropHistory(context.Background(), &EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: path})
	}

	refuseFull(1)
	result, err := drop("a.txt")
	if err != nil || len(result.Pushes) != 1 || result.Pushes[0].IndexRewritten || !slices.Equal(calls, []bool{false}) {
		t.Fatalf("a DROP refused 507 at its push: %+v, %v, hook calls %v", result, err, calls)
	}
	// the first push carries the kept head and the rewrite, the index directories it creates on the stand-in with it
	drops := capture.drops(t)
	if len(drops) != 2 || len(drops[0].Changes) < 2 || testDropLimitNewSegmentCount(drops[0].EvsCheckedPayload) == 0 ||
		len(drops[1].Changes) != 1 || testDropLimitNewSegmentCount(drops[1].EvsCheckedPayload) != 0 {
		t.Fatalf("%d DROP pushes posted", len(drops))
	}
	if _, info, err := evsTestReadFormat2(t, writer, "a.txt"); err != nil || info.Version != 3 {
		t.Fatalf("the kept head after the DROP: %+v, %v", info, err)
	}

	// a kept head that is a new segment: refused at the push again without the rewrite, and the 507 goes back
	_, head, err := evsTestReadFormat2(t, writer, "big.bin")
	if err != nil {
		t.Fatal(err)
	}
	refuseFull(2)
	_, err = drop("big.bin")
	testDropLimitGoesBack(t, err, evsTestDropLimitClusterFull)
	if refusal, _ := EvsErrorOf(err); !refusal.Recorded {
		t.Fatalf("a recorded 507 that goes back unrecorded: %v", err)
	}
	if !slices.Equal(calls, []bool{false, false}) {
		t.Fatalf("hook calls %v", calls)
	}
	drops = capture.drops(t)
	if len(drops) != 4 || len(drops[2].Changes) < 2 || len(drops[3].Changes) != 1 || testDropLimitNewSegmentCount(drops[3].EvsCheckedPayload) == 0 {
		t.Fatalf("%d DROP pushes posted", len(drops))
	}
	if _, info, err := evsTestReadFormat2(t, writer, "big.bin"); err != nil || info.Version != head.Version {
		t.Fatalf("the head after a refused DROP: %+v, %v", info, err)
	}
}
