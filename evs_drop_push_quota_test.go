//go:build !ios_extension

// A DROP at the storage limit (QD-1088; §11.14's limit and drop rows, §20.7; EVS2-M10-21's loop with SEARCH-M10-18's
// rewriter): against the stand-in evs behind a model of evs's storage gate, which refuses a segment upload and a push
// that adds payload while a network is over its limit or spent, a DROP naming no new segment excepted. A DROP whose
// index rewrites take a bucket shard, an upload, is refused for it and lands on its second send without them, the
// listed versions staying in the shard, masked by the kept version's entry, while the backfill's rewrite waits at the
// limit, and gone once it runs under it; a DROP whose rewrites are all staged lands at once with them; a DROP whose
// kept head needs an upload is refused with or without rewrites, the QuotaRefusal going back to the person, and lands
// with its rewrites when the command is run again under the limit; and while spent the 402 is answered the same way,
// the hook never asked again. A cluster at its cohort limit answers 507 CLUSTER_FULL where the storage limit would
// refuse, which QD-1088 does not name: that DROP goes back to the person as it is (question
// drop-quota-resend-without-rewrites-cluster-full).

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
	newSegmentCount, stagedSegmentCount, inlineRecordCount := 0, 0, 0
	for _, object := range checked.NewObjects {
		switch object.Kind {
		case protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT:
			newSegmentCount += 1
		case protocol.EvsNewObjectKind_EVS_NEW_OBJECT_STAGED_SEGMENT:
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

// QD-1088 at the storage limit: the DROP's rewrite of the shard holding a.txt's first version is an upload, which evs
// refuses, so the DROP goes again once without its rewrites and commits. The listed version stays in the shard, masked
// by the kept version's entry in every search, while the backfill's rewrite is refused at the limit as the payload it
// is, and the look after the limit lifts takes it out, no search changing.
func TestEvsDropAtTheLimitLandsWithoutAShardRewrite(t *testing.T) {
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
	gate.set(evsTestDropLimitStorage)
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

	// the backfill: refused at the limit, its floor where it was, and done by the look after the limit lifts
	store := newIndexEvsStore(writer.repo, nil, false)
	head, err := store.Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	content := &testIndexDropContent{refId: writer.world.refId, head: head.version, drops: []*indexContentDrop{{
		version: result.Pushes[0].Version, signedTimeMs: writer.test.clock.Now().UnixMilli(),
		paths: []*indexDroppedPath{testIndexDroppedPath("a.txt", 3, 1, 2, 3)},
	}}}
	backfiller, err := indexNewBackfiller(&indexBackfillArgs{
		store: store, repoId: writer.world.repoId, refId: writer.world.refId, repoKind: protocol.RepoKind_REPO_KIND_GENERAL,
		isAdmin: func(*indexFileVersion) bool { return true }, format: DefaultIndexFormatSettings(), tables: testHeadTables,
		clock: writer.test.clock, writer: writer.world.signer.sidecarId, refKey: testIndexDropEvsRefKey(t, writer),
		contents: []indexContentRef{content}, drops: indexNewDropBackfill(&IndexDropSettings{ChunkScanCount: 4, AttemptCount: 2}),
	})
	if err != nil {
		t.Fatal(err)
	}
	writer.test.clock.advance(DefaultIndexBackfillSettings().BackfillAge)
	if _, err := backfiller.backfillDrops(context.Background()); !isIndexRefusal(err, indexRefusalQuota) {
		t.Fatalf("a backfill's rewrite at the limit: %v", err)
	}
	waiting := testDropLimitView(t, writer)
	if len(testDropLimitShardsHolding(t, waiting, key, 1)) != 1 {
		t.Fatal("a refused backfill moved the shard")
	}
	testIndexDropSearchesEqual(t, searches, testIndexDropSearches(t, waiting))
	gate.set(evsTestDropLimitNone)
	outcome, err := backfiller.backfillDrops(context.Background())
	if err != nil || outcome.committedCount != 1 {
		t.Fatalf("the look after the limit: %+v, %v", outcome, err)
	}
	after := testDropLimitView(t, writer)
	testIndexDropNoneHeld(t, after, key, 1, 2)
	testIndexDropHeldLive(t, after, key, 3)
	testIndexDropSearchesEqual(t, searches, testIndexDropSearches(t, after))
}

// At the storage limit a DROP whose rewrites are all staged, a slot's here, uploads nothing and lands at once with
// them: evs takes a DROP that names no new segment, its staged rewrites and its inline kept head with it.
func TestEvsDropAtTheLimitLandsWithStagedRewrites(t *testing.T) {
	writer, _, capture, path := testIndexDropEvsWorld(t)
	gate := newEvsTestDropLimitGate(t, capture)
	before := testIndexDropEvsSlot(t, writer, path)
	t.Cleanup(testIndexDropEvsRewriter(t, writer, true).Install())
	gate.set(evsTestDropLimitStorage)
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
	// and what the limit refuses is still refused: a content write is payload
	if _, err := writer.write(t, "c.txt", []byte("payload at the limit")); !IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_LIMIT) {
		t.Fatalf("a write at the limit: %v", err)
	}
}

// At the storage limit a DROP whose kept head needs an upload is refused, the QuotaRefusal going back to the person:
// at once where it carries no rewrites, and after one more send without them where it does, never a third. Nothing is
// dropped and no index file moves, and the same command run again under the limit lands with its rewrites.
func TestEvsDropAtTheLimitRefusedForItsKeptHead(t *testing.T) {
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
	gate.set(evsTestDropLimitStorage)

	// with no rewrites: one send, refused at the kept head's upload
	_, err = drop()
	refusal, ok := EvsErrorOf(err)
	if !ok || refusal.Code != protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_LIMIT || refusal.Quota.GetLimitKey() != "evs_storage_bytes" {
		t.Fatalf("a DROP whose kept head needs an upload, at the limit: %v", err)
	}
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
	refusal, ok = EvsErrorOf(err)
	if !ok || refusal.Code != protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_LIMIT || refusal.Quota.GetLimitKey() != "evs_storage_bytes" {
		t.Fatalf("a DROP whose kept head needs an upload, with rewrites, at the limit: %v", err)
	}
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

	// under the limit the same dry run's command lands, its rewrites with it
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
	refusal, ok := EvsErrorOf(err)
	if !ok || refusal.Code != protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_PAYMENT || !refusal.Quota.GetUpgrade() {
		t.Fatalf("a DROP whose kept head needs an upload, while spent: %v", err)
	}
	if !slices.Equal(calls, []bool{false, false}) {
		t.Fatalf("hook calls %v", calls)
	}
	if drops := capture.drops(t); len(drops) != 1 {
		t.Fatalf("%d DROP pushes posted", len(drops))
	}
}

// QD-1088 names the QuotaRefusal, the storage limit's and a spent network's. A cluster at its cohort limit refuses the
// same upload 507 CLUSTER_FULL, which the answer does not name: until the question
// drop-quota-resend-without-rewrites-cluster-full is answered that refusal goes back to the person as it is, the DROP
// sent once and nothing dropped.
func TestEvsDropOnAFullClusterGoesBackWithItsRewrite(t *testing.T) {
	writer, server, capture := newEvsTestDropPusher(t)
	gate := newEvsTestDropLimitGate(t, capture)
	evsTestDropHistory(t, writer, server, "a.txt", 500, 2)
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
	gate.set(evsTestDropLimitClusterFull)
	_, err = writer.repo.DropHistory(context.Background(), &EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: "a.txt"})
	if !IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_CLUSTER_FULL) {
		t.Fatalf("a DROP whose rewrite is an upload, on a full cluster: %v", err)
	}
	if uploads, pushes := gate.refused(); uploads != 1 || pushes != 0 || !slices.Equal(calls, []bool{false}) {
		t.Fatalf("%d uploads and %d pushes refused, hook calls %v", uploads, pushes, calls)
	}
	if drops := capture.drops(t); len(drops) != 0 {
		t.Fatalf("%d DROP pushes posted", len(drops))
	}
	if _, info, err := evsTestReadFormat2(t, writer, "a.txt"); err != nil || info.Version != 2 {
		t.Fatalf("the head after a refused DROP: %+v, %v", info, err)
	}
}
