//go:build !ios_extension

package sidecar

// SEARCH-M10-15's off on a full cluster (§11.14's off and limit rows; §19.9's cohorts row; D-OPS-22; owner decision
// 620; QD-1118), against the stand-in evs behind the limit gate of QD-1088's and QD-1099's DROP tests
// (evs_drop_push_quota_test.go): on a metadata cluster at its cohort limit evs refuses the off version, a new inline
// record, 507 CLUSTER_FULL with Retry-After, and takes a push that only removes. The index reads that 507 as the
// storage limit's refusal, so the off goes in steps there: the files first, a deletion the full cluster accepts, and
// the off version once there is room, waiting meanwhile; a head a writer re-created while it waits goes first when the
// off is asked again; and a 507 that names no wait is answered alike.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A front on the limit gate whose 507s name no wait: each refusal of an upload or a push the gate answers 507 loses its
// retry_after_ms, and no Retry-After goes with it, as an evs that set none would answer. Every other answer, and a
// body that does not parse, is the gate's as it is.
type testIndexNoWaitFront struct {
	handler http.Handler
}

func (self *testIndexNoWaitFront) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	refusable := request.Method == http.MethodPut && strings.Contains(request.URL.Path, "/segments/") ||
		request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/push")
	if !refusable {
		self.handler.ServeHTTP(writer, request)
		return
	}
	recorder := httptest.NewRecorder()
	self.handler.ServeHTTP(recorder, request)
	body := recorder.Body.Bytes()
	if recorder.Code == http.StatusInsufficientStorage {
		reply := &protocol.EvsRefusalReply{}
		if proto.Unmarshal(body, reply) == nil {
			reply.RetryAfterMs = 0
			if encoded, err := proto.Marshal(reply); err == nil {
				body = encoded
			}
		}
		recorder.Header().Del("Retry-After")
	}
	for key, values := range recorder.Header() {
		writer.Header()[key] = values
	}
	writer.WriteHeader(recorder.Code)
	writer.Write(body)
}

// Puts a front whose 507s name no wait between capture and the gate it hands to.
func testIndexNoWaitBehind(capture *evsTestDropCapture, gate *evsTestDropLimitGate) {
	capture.handler = &testIndexNoWaitFront{handler: gate}
}

// The wait a full cluster's 507 names at the gate: its retry_after_ms, or none behind a no-wait front.
func testIndexClusterFullWait(noWait bool) time.Duration {
	if noWait {
		return 0
	}
	return time.Duration(evsTestDropLimitRefusal(evsTestDropLimitClusterFull).reply.GetRetryAfterMs()) * time.Millisecond
}

// The stand-in's index world behind the limit gate, under its limit: a format-2 writer that is the repo's admin, 5d's
// epoch modelled, every planned path registered with the stand-in, and its 507s naming no wait where noWait.
func testIndexLimitWorld(t *testing.T, noWait bool) (*evsTestWriter, *evsTestDropLimitGate) {
	t.Helper()
	writer, _, capture := newEvsTestDropPusher(t)
	gate := newEvsTestDropLimitGate(t, capture)
	if noWait {
		testIndexNoWaitBehind(capture, gate)
	}
	writer.server.indexEpochs = true
	writer.test.client.SetWritePlanHook(func(ctx context.Context, plan *EvsWritePlan) error {
		for _, planned := range plan.Paths {
			writer.server.know(planned.Path)
		}
		return nil
	})
	t.Cleanup(func() { writer.test.client.SetWritePlanHook(nil) })
	return writer, gate
}

// The paths the stand-in's main ref holds under its index root, its settings included.
func testIndexLimitRootPaths(t testing.TB, writer *evsTestWriter) []string {
	t.Helper()
	listing, err := newIndexEvsStore(writer.repo, nil, false).List(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	prefix := indexNewPaths(false, indexRootNumber).root + "/"
	paths := []string{}
	for _, file := range listing.files {
		if strings.HasPrefix(file.path, prefix) {
			paths = append(paths, file.path)
		}
	}
	return paths
}

// A settings write on the stand-in's main ref, every version counting, as EvsRepo.IndexSettings writes one root for
// the repo's admin.
func testIndexLimitSettingsArgs(writer *evsTestWriter) *indexSettingsArgs {
	return &indexSettingsArgs{
		store: newIndexEvsStore(writer.repo, nil, false), repoId: writer.world.repoId, refId: writer.world.refId,
		repoKind: protocol.RepoKind_REPO_KIND_GENERAL, isAdmin: func(*indexFileVersion) bool { return true },
		format: DefaultIndexFormatSettings(), attemptCount: DefaultIndexBuilderSettings().AttemptCount, clock: writer.test.clock,
	}
}

// One off on the stand-in's main ref, failing on an error: its root's outcome.
func testIndexLimitOff(t *testing.T, writer *evsTestWriter) *indexSettingsOutcome {
	t.Helper()
	off, err := indexSettingsChangeOf(EvsIndexOff, 0)
	if err != nil {
		t.Fatal(err)
	}
	outcomes, err := indexApplySettings(context.Background(), testIndexLimitSettingsArgs(writer), off)
	if err != nil || len(outcomes) != 1 {
		t.Fatalf("the off: %d outcomes, %v", len(outcomes), err)
	}
	return outcomes[0]
}

// On a full cluster the off goes in steps: the off version and its removals are refused 507, the removals alone are a
// deletion the cluster takes, and the off version waits, refused again, the root holding nothing and not off. Asked
// again while the cluster is full it waits as it was, nothing left to remove; a head a writer re-created in a moment of
// room goes first when it is asked on the full cluster again; and once the cluster has room the off version lands and
// the root holds it alone. The 507's wait, or its want of one, changes none of it.
func testIndexOffOnAFullCluster(t *testing.T, noWait bool) {
	writer, gate := testIndexLimitWorld(t, noWait)
	for index := range 3 {
		testDropLimitIndexPush(t, writer, testLive("doc", index, 1, testHeadKeys(index, 0)))
	}
	testDropLimitIndexPush(t, writer, testLive("big", 0, 1, testLargeKeys(0, 6000)))
	built := testIndexLimitRootPaths(t, writer)
	if len(built) < 2 {
		t.Fatalf("the index holds %d files, not a head and a large entry", len(built))
	}

	// the files first, the off version waiting
	gate.set(evsTestDropLimitClusterFull)
	outcome := testIndexLimitOff(t, writer)
	if !outcome.waiting || outcome.removedCount != len(built) || outcome.version != 0 {
		t.Fatalf("the off on a full cluster: %+v", outcome)
	}
	// the off version with the removals, then the off version alone, each refused at its push
	if uploads, pushes := gate.refused(); uploads != 0 || pushes != 2 {
		t.Fatalf("%d uploads and %d pushes refused", uploads, pushes)
	}
	if paths := testIndexLimitRootPaths(t, writer); len(paths) != 0 || testDropLimitView(t, writer).writeRoot().off() {
		t.Fatalf("the root after the files went first: %v", paths)
	}

	// asked again while the cluster is full: nothing left to remove, and the off version waits as it was
	outcome = testIndexLimitOff(t, writer)
	if !outcome.waiting || outcome.removedCount != 0 || outcome.version != 0 {
		t.Fatalf("the off asked again on a full cluster: %+v", outcome)
	}
	if uploads, pushes := gate.refused(); uploads != 0 || pushes != 4 {
		t.Fatalf("%d uploads and %d pushes refused", uploads, pushes)
	}

	// a writer re-creates its head in a moment of room; on the full cluster again that head goes first
	gate.set(evsTestDropLimitNone)
	testDropLimitIndexPush(t, writer, testLive("doc", 3, 1, testHeadKeys(3, 0)))
	if recreated := testIndexLimitRootPaths(t, writer); len(recreated) != 1 {
		t.Fatalf("the re-created root holds %v", recreated)
	}
	gate.set(evsTestDropLimitClusterFull)
	outcome = testIndexLimitOff(t, writer)
	if !outcome.waiting || outcome.removedCount != 1 || outcome.version != 0 {
		t.Fatalf("the off on a full cluster after a writer re-created its head: %+v", outcome)
	}
	if paths := testIndexLimitRootPaths(t, writer); len(paths) != 0 {
		t.Fatalf("the re-created head stands: %v", paths)
	}

	// once there is room the off version lands, and the root holds it alone
	gate.set(evsTestDropLimitNone)
	outcome = testIndexLimitOff(t, writer)
	if outcome.waiting || outcome.removedCount != 0 || outcome.version == 0 {
		t.Fatalf("the off once there is room: %+v", outcome)
	}
	root := testDropLimitView(t, writer).writeRoot()
	if paths := testIndexLimitRootPaths(t, writer); len(paths) != 1 || paths[0] != root.paths.settings() || !root.off() {
		t.Fatalf("the root after the off holds %v", paths)
	}
	if uploads, pushes := gate.refused(); uploads != 0 || pushes != 6 {
		t.Fatalf("%d uploads and %d pushes refused", uploads, pushes)
	}
}

// QD-1118: the full cluster's 507 with its wait.
func TestIndexOffOnAFullClusterInItsSteps(t *testing.T) {
	testIndexOffOnAFullCluster(t, false)
}

// A 507 naming no wait is a full cluster's all the same.
func TestIndexOffOnAFullClusterWithoutRetryAfterInItsSteps(t *testing.T) {
	testIndexOffOnAFullCluster(t, true)
}
