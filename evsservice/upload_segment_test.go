package evsservice

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// An engine with the upload route's deps over the fake host, a repo projected, placed and granted.
type uploadFixture struct {
	*evsFixture
	keys     *ReceiptKeys
	gate     *QuotaGate
	hdd      *HddAdmission
	usage    *UsageBatcher
	repoId   sidecar.Id
	writer   sidecar.Id
	admin    sidecar.Id
	reader   sidecar.Id
	priorRun int
}

func newUploadFixture(t *testing.T) *uploadFixture {
	return newUploadFixtureWith(t, nil)
}

// An upload fixture whose engine runs on settings, nil for the defaults.
func newUploadFixtureWith(t *testing.T, settings *EvsSettings) *uploadFixture {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	hostSettings := sidecartest.DefaultFakeHostSettings()
	hostSettings.Blobs.Report = func(violation string) { t.Errorf("blobs: %s", violation) }
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, hostSettings)
	sidecartest.RegisterEvsTwins(host.Redis)
	networkId := connect.Id(testId("network-a"))
	host.Gates.OpenService(sidecar.ServiceGateEvs, networkId)
	keys := testReceiptKeys(t, testReceiptKey(1, clock.Now().Add(-time.Hour)))
	gate, err := newQuotaGate(ctx, host.ServiceHost(), nil)
	if err != nil {
		t.Fatal(err)
	}
	gate.refresh(ctx)
	hdd, err := newHddAdmission(ctx, host.ServiceHost(), "seg-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	usage, err := NewUsageBatcher(ctx, host.ServiceHost(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(usage.Close)
	auth := newFakeAuthState()
	engine, err := NewEvsEngine(ctx, host.ServiceHost(), settings, &EvsEngineDeps{
		AuthState:  auth,
		ServiceLog: &recordingServiceLog{},
		Uploads:    &EvsUploadDeps{Keys: keys, Quota: gate, Hdd: hdd, Usage: usage},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	fixture := &uploadFixture{
		evsFixture: &evsFixture{t: t, ctx: ctx, clock: clock, host: host, auth: auth, engine: engine, networkId: networkId},
		keys:       keys,
		gate:       gate,
		hdd:        hdd,
		usage:      usage,
		repoId:     testId("upload repo"),
		writer:     testId("upload writer"),
		admin:      testId("upload admin"),
		reader:     testId("upload reader"),
	}
	fixture.projectRepo(fixture.repoId, fixture.admin)
	if code := fixture.putRepo(fixture.repoId, fixture.admin); code != http.StatusOK {
		t.Fatalf("placing the repo: %d", code)
	}
	fixture.auth.grant(fixture.writer, fixture.repoId, sidecar.AclEvsWrite)
	fixture.auth.grant(fixture.reader, fixture.repoId, sidecar.AclEvsRead)
	return fixture
}

// A segment of byteCount bytes: a format-1 header for repoId at generation 1, then filler.
func testSegment(repoId sidecar.Id, byteCount int, fill byte) []byte {
	segment := bytes.Repeat([]byte{fill}, byteCount)
	copy(segment[0:4], "URvs")
	segment[4], segment[5], segment[6], segment[7] = 1, 0, 0, 0
	copy(segment[8:24], repoId[:])
	binary.BigEndian.PutUint64(segment[24:32], 1)
	return segment
}

// One upload by sidecarId of segment under the id it names, closure or not.
func (self *uploadFixture) upload(sidecarId sidecar.Id, role string, segment []byte, segmentId [32]byte, closure bool) *httptest.ResponseRecorder {
	path := "/evs/v1/repos/" + sidecar.EvsKeyId(self.repoId) + "/segments/" + hex.EncodeToString(segmentId[:]) + "?push=" + sidecar.EvsKeyId(testId("push"))
	if closure {
		path += "&closure=1"
	}
	return self.serve(http.MethodPut, path, self.token(sidecarId, repoScope(self.repoId, role)), segment)
}

func (self *uploadFixture) receipt(recorder *httptest.ResponseRecorder) *protocol.EvsUploadReceipt {
	self.t.Helper()
	if recorder.Code != http.StatusOK {
		self.t.Fatalf("status %d (%s)", recorder.Code, refusalOf(self.t, recorder).GetCode())
	}
	receipt := &protocol.EvsUploadReceipt{}
	if err := proto.Unmarshal(recorder.Body.Bytes(), receipt); err != nil {
		self.t.Fatal(err)
	}
	return receipt
}

// A full 8 MiB segment streams to seg/ and answers a receipt check h accepts, its bytes counted once; a re-upload
// answers the first upload's time, and past 23 h SEGMENT_STALE.
func TestUploadSegmentStoresAndAnswersAReceipt(t *testing.T) {
	fixture := newUploadFixture(t)
	segment := testSegment(fixture.repoId, 8*1024*1024, 0x5a)
	segmentId := sha256.Sum256(segment)
	first := fixture.clock.Now()
	receipt := fixture.receipt(fixture.upload(fixture.writer, "rw", segment, segmentId, false))
	if err := CheckUploadReceipt(fixture.keys, receipt, fixture.repoId, fixture.writer, first); err != nil {
		t.Fatal(err)
	}
	if receipt.GetPaddedSize() != uint64(len(segment)) || receipt.GetUploadMs() != first.UnixMilli() || receipt.GetVersionless() {
		t.Fatalf("receipt %v", receipt)
	}
	if !bytes.Equal(fixture.object("seg-1", SegmentKey(fixture.repoId, segmentId)), segment) {
		t.Fatal("seg/ does not hold the segment")
	}
	// the metadata cluster took only the repo's place/ and repo/, before the upload
	if writes := fixture.host.Blobs.RequestCount("meta-1", string(sidecartest.FaultOpPut)); writes != 2 {
		t.Fatalf("meta-1 took %d writes, want only the repo's place/ and repo/", writes)
	}

	fixture.clock.Advance(time.Hour)
	again := fixture.receipt(fixture.upload(fixture.writer, "rw", segment, segmentId, false))
	if again.GetUploadMs() != first.UnixMilli() {
		t.Fatalf("a re-upload's upload_ms %d, want the first's %d", again.GetUploadMs(), first.UnixMilli())
	}
	if err := fixture.usage.Drain(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	if got := fixture.host.Quota.StoredDelta(fixture.networkId); got != int64(len(segment)) {
		t.Fatalf("stored delta %d, want the segment counted once", got)
	}
	fixture.clock.Advance(23 * time.Hour)
	requireRefusal(t, fixture.upload(fixture.writer, "rw", segment, segmentId, false), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SEGMENT_STALE)
}

// A non-admin closure upload is refused before any write; a reader cannot upload at all.
func TestUploadSegmentClosureTakesAdmin(t *testing.T) {
	fixture := newUploadFixture(t)
	segment := testSegment(fixture.repoId, 4096, 1)
	segmentId := sha256.Sum256(segment)
	requireRefusal(t, fixture.upload(fixture.writer, "rw", segment, segmentId, true), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	if fixture.object("seg-1", SegmentKey(fixture.repoId, segmentId)) != nil {
		t.Fatal("a refused closure upload wrote")
	}
	requireRefusal(t, fixture.upload(fixture.reader, "r", segment, segmentId, false), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	fixture.receipt(fixture.upload(fixture.admin, "admin", segment, segmentId, true))
}

// The header is checked before the body moves, and the checksum by the store: another repo's header, a kind-5
// header naming another push (upload_versionless_test.go holds the rest of format 2's) and bytes that are not their
// id write nothing.
func TestUploadSegmentRefusesABadHeaderOrChecksum(t *testing.T) {
	fixture := newUploadFixture(t)
	otherRepo := testSegment(testId("other repo"), 4096, 2)
	otherRepoId := sha256.Sum256(otherRepo)
	requireRefusal(t, fixture.upload(fixture.writer, "rw", otherRepo, otherRepoId, false), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	kind5 := testSegment(fixture.repoId, 4096, 3)
	kind5[4] = 2
	kind5Id := sha256.Sum256(kind5)
	requireRefusal(t, fixture.upload(fixture.writer, "rw", kind5, kind5Id, false), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_VERSIONING)
	if fixture.object("seg-1", SegmentKey(fixture.repoId, kind5Id)) != nil {
		t.Fatal("another push's kind-5 segment was stored")
	}
	segment := testSegment(fixture.repoId, 4096, 4)
	wrongId := sha256.Sum256([]byte("not these bytes"))
	requireRefusal(t, fixture.upload(fixture.writer, "rw", segment, wrongId, false), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	if fixture.object("seg-1", SegmentKey(fixture.repoId, wrongId)) != nil {
		t.Fatal("bytes under another id were stored")
	}
}

// A segment the cluster stores counts one PUT toward the cluster's rate (§19.8's urnetwork_filecluster_hdd_puts);
// a re-upload's 412, bytes that are not their id and an upload refused before the write count none.
func TestUploadSegmentCountsOnlyStoredPuts(t *testing.T) {
	fixture := newUploadFixture(t)
	segment := testSegment(fixture.repoId, 4096, 6)
	segmentId := sha256.Sum256(segment)
	fixture.receipt(fixture.upload(fixture.writer, "rw", segment, segmentId, false))
	fixture.receipt(fixture.upload(fixture.writer, "rw", segment, segmentId, false))
	wrongId := sha256.Sum256([]byte("not these bytes"))
	requireRefusal(t, fixture.upload(fixture.writer, "rw", segment, wrongId, false), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	requireRefusal(t, fixture.upload(fixture.reader, "r", segment, segmentId, false), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	if got := fixture.hdd.putCount.Load(); got != 1 {
		t.Fatalf("%d PUTs counted, want the one stored", got)
	}
}

// At the storage limit an upload gets §20.7's QuotaRefusal, and past the HDD line 503 with Retry-After, the
// quota first.
func TestUploadSegmentRefusesAtTheLimitAndPastTheHddLine(t *testing.T) {
	fixture := newUploadFixture(t)
	segment := testSegment(fixture.repoId, 4096, 5)
	segmentId := sha256.Sum256(segment)
	fixture.host.Quota.SetStorageRefusal(fixture.networkId, &sidecar.QuotaRefusal{LimitKey: "storage", Limit: 10, Used: 10, Upgrade: true})
	fixture.gate.refresh(fixture.ctx)
	recorder := fixture.upload(fixture.writer, "rw", segment, segmentId, false)
	requireRefusal(t, recorder, http.StatusPaymentRequired, protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_PAYMENT)
	if refusal := refusalOf(t, recorder).GetQuota(); refusal.GetLimitKey() != "storage" || !refusal.GetUpgrade() {
		t.Fatalf("quota %v", refusal)
	}
	fixture.host.Quota.SetStorageRefusal(fixture.networkId, nil)
	fixture.gate.refresh(fixture.ctx)

	// the network's uploads are the heaviest past the line
	fixture.hdd.Admit(fixture.networkId, 1000000, HddUploadOrdinary)
	if err := publishHddFigures(fixture.ctx, fixture.host.Redis, &HddFigures{ClusterId: "seg-1", DriveOpsPerSecond: 900, CapacityOps: 1000}, 15*time.Second); err != nil {
		t.Fatal(err)
	}
	fixture.hdd.tick(fixture.ctx)
	recorder = fixture.upload(fixture.writer, "rw", segment, segmentId, false)
	requireRefusal(t, recorder, http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	if recorder.Header().Get("Retry-After") == "" {
		t.Fatal("an HDD refusal with no Retry-After")
	}
	if fixture.object("seg-1", SegmentKey(fixture.repoId, segmentId)) != nil {
		t.Fatal("a refused upload wrote")
	}
}
