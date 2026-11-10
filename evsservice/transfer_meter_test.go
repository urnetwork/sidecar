// QUOTA-M2-10's transfer tests on T2's fakes: every request's and reply's body bytes counted once on meter evs to
// the caller's network, the token's and never the repo's, on a read, an upload and a push; a request with no
// verified token counted for no one; and bytes reaching the batcher while a reply still streams.

package evsservice

import (
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The bytes api has applied on meter evs for the network, the open window sent first.
func drainedTransfer(t *testing.T, usage *UsageBatcher, quota *sidecartest.FakeQuota, networkId connect.Id) int64 {
	t.Helper()
	if err := usage.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	return quota.TransferUsed(networkId, sidecar.QuotaMeterEvs)
}

// An upload's body and its receipt count as the caller's transfer, and its stored bytes as the repo's network's:
// neither network takes the other's.
func TestMeterTransferCountsAnUploadToTheCallerNeverTheRepo(t *testing.T) {
	fixture := newUploadFixture(t)
	repoNetworkId := connect.Id(testId("network-b"))
	fixture.auth.setRepo(fixture.repoId, &EvsRepoFacts{Kind: protocol.RepoKind_REPO_KIND_GENERAL, NetworkId: sidecar.Id(repoNetworkId)})
	prior := drainedTransfer(t, fixture.usage, fixture.host.Quota, fixture.networkId)
	segment := testSegment(fixture.repoId, 300*1024, 0x41)
	recorder := fixture.upload(fixture.writer, "rw", segment, sha256.Sum256(segment), false)
	fixture.receipt(recorder)
	want := int64(len(segment) + recorder.Body.Len())
	if got := drainedTransfer(t, fixture.usage, fixture.host.Quota, fixture.networkId) - prior; got != want {
		t.Fatalf("the caller's transfer %d, want the segment's and the receipt's %d", got, want)
	}
	if got := fixture.host.Quota.TransferUsed(repoNetworkId, sidecar.QuotaMeterEvs); got != 0 {
		t.Fatalf("the repo's network took %d of the caller's transfer", got)
	}
	if got := fixture.host.Quota.StoredDelta(repoNetworkId); got != int64(len(segment)) {
		t.Fatalf("the repo's network stored %d, want the segment's %d", got, len(segment))
	}
	if got := fixture.host.Quota.StoredDelta(fixture.networkId); got != 0 {
		t.Fatalf("the caller's network stored %d of the repo's bytes", got)
	}
	for _, batch := range fixture.host.Quota.Batches() {
		if batch.Producer != sidecar.QuotaProducerEvs {
			t.Fatalf("producer %q", batch.Producer)
		}
	}
}

// A read's request and its framed reply count as the caller's transfer, each byte once.
func TestMeterTransferCountsARead(t *testing.T) {
	fixture := newUploadFixture(t)
	segment := testSegment(fixture.repoId, 700*1024, 0x42)
	segmentId := sha256.Sum256(segment)
	fixture.receipt(fixture.upload(fixture.writer, "rw", segment, segmentId, false))
	prior := drainedTransfer(t, fixture.usage, fixture.host.Quota, fixture.networkId)
	body := &protocol.EvsReadRequest{
		RefId:  testId("metered ref").Bytes(),
		Ranges: []*protocol.EvsReadRange{{SegmentId: segmentId[:], Offset: 0, Length: uint32(len(segment))}},
	}
	bodyBytes, err := proto.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	recorder := fixture.serve(http.MethodPost, "/evs/v1/repos/"+sidecar.EvsKeyId(fixture.repoId)+"/read", fixture.token(fixture.reader, repoScope(fixture.repoId, "r")), bodyBytes)
	if recorder.Code != http.StatusOK || recorder.Body.Len() < len(segment) {
		t.Fatalf("read: %d, %d bytes", recorder.Code, recorder.Body.Len())
	}
	want := int64(len(bodyBytes) + recorder.Body.Len())
	if got := drainedTransfer(t, fixture.usage, fixture.host.Quota, fixture.networkId) - prior; got != want {
		t.Fatalf("transfer %d, want the request's and the reply's %d", got, want)
	}
	// a second drain finds nothing more: no byte counts twice
	if got := drainedTransfer(t, fixture.usage, fixture.host.Quota, fixture.networkId) - prior; got != want {
		t.Fatalf("transfer %d after a second drain, want %d", got, want)
	}
}

// A push's body and its reply count as the caller's transfer once, and step 8 adds none of its own; a refused
// push's bytes moved too, and count.
func TestMeterTransferCountsAPush(t *testing.T) {
	fixture := newPushFixture(t, nil)
	usage := fixture.engine.deps.Uploads.Usage
	networkId := connect.Id(fixture.check.networkId)
	prior := drainedTransfer(t, usage, fixture.host.Quota, networkId)
	plan := fixture.plan()
	fixture.create(plan, "metered")
	body := fixture.body(plan)
	bodyBytes, err := proto.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	recorder := fixture.post(fixture.token(fixture.check.signerId), body)
	fixture.requireCommitted(recorder, 1)
	fixture.awaitStepEights()
	want := int64(len(bodyBytes) + recorder.Body.Len())
	if got := drainedTransfer(t, usage, fixture.host.Quota, networkId) - prior; got != want {
		t.Fatalf("transfer %d, want the push's and its reply's %d", got, want)
	}
	// the same statement again answers its commit, and its bytes moved again
	again := fixture.post(fixture.token(fixture.check.signerId), body)
	fixture.requireCommitted(again, 1)
	fixture.awaitStepEights()
	want += int64(len(bodyBytes) + again.Body.Len())
	// a deposit-only token is refused the read route: the refusal's bytes are its network's
	fixture.auth.grant(fixture.check.otherId, fixture.check.repoId, sidecar.AclEvsDeposit)
	refused := fixture.call(fixture.token(fixture.check.otherId, "deposit"), http.MethodGet, "/refs", nil)
	requireRefusal(t, refused, http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	want += int64(refused.Body.Len())
	if got := drainedTransfer(t, usage, fixture.host.Quota, networkId) - prior; got != want {
		t.Fatalf("transfer %d, want %d", got, want)
	}
}

// A request with no token, or one that does not verify, names no network: its bytes count for no one.
func TestMeterTransferCountsNothingWithoutAVerifiedToken(t *testing.T) {
	fixture := newUploadFixture(t)
	prior := drainedTransfer(t, fixture.usage, fixture.host.Quota, fixture.networkId)
	sent := len(fixture.host.Quota.SentBatches())
	path := "/evs/v1/repos/" + sidecar.EvsKeyId(fixture.repoId)
	for _, token := range []string{"", "not a token"} {
		if recorder := fixture.serve(http.MethodGet, path, token, []byte("a body no one reads")); recorder.Code != http.StatusUnauthorized {
			t.Fatalf("token %q: %d", token, recorder.Code)
		}
	}
	if got := drainedTransfer(t, fixture.usage, fixture.host.Quota, fixture.networkId) - prior; got != 0 {
		t.Fatalf("transfer %d for requests with no verified token", got)
	}
	if got := len(fixture.host.Quota.SentBatches()) - sent; got != 0 {
		t.Fatalf("%d batches sent for requests with no verified token", got)
	}
}

// Bytes reach the batcher as they move, past the flush count and at the request's end, so a reply still
// streaming has already counted what it sent; the body read counts with the reply written.
func TestMeterTransferCountsWhileAReplyStreams(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	quota := sidecartest.NewFakeQuota(clock, nil, nil)
	host := &sidecar.ServiceHost{Quota: quota, Metrics: sidecartest.NewFakeMetrics(nil), Clock: clock}
	usage, err := NewUsageBatcher(t.Context(), host, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(usage.Close)
	networkId := connect.NewId()
	quota.SetBalance(networkId, 1024*1024*1024)
	var streamingTransfer int64
	var beforeCallerTransfer int64
	handler := MeterTransfer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if _, err := io.ReadAll(request.Body); err != nil {
			t.Error(err)
		}
		writer.Write(make([]byte, 100*1024))
		// no caller yet: nothing has been counted for anyone
		beforeCallerTransfer = drainedTransfer(t, usage, quota, networkId)
		meterTransferCaller(writer, networkId)
		// another network named later changes nothing: a request has one token
		meterTransferCaller(writer, connect.NewId())
		writer.Write(make([]byte, 100*1024))
		streamingTransfer = drainedTransfer(t, usage, quota, networkId)
		writer.Write(make([]byte, 10))
		if _, ok := writer.(http.Flusher); !ok {
			t.Error("the metered writer does not flush")
		}
	}), usage, &TransferMeterSettings{FlushByteCount: 64 * 1024}, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/evs/v1/x", strings.NewReader("ten bytes!")))
	if beforeCallerTransfer != 0 {
		t.Fatalf("transfer %d before the token verified", beforeCallerTransfer)
	}
	if want := int64(10 + 200*1024); streamingTransfer != want {
		t.Fatalf("transfer %d while streaming, want %d", streamingTransfer, want)
	}
	if got, want := drainedTransfer(t, usage, quota, networkId), int64(10+200*1024+10); got != want {
		t.Fatalf("transfer %d at the end, want %d", got, want)
	}
	if recorder.Body.Len() != 200*1024+10 {
		t.Fatalf("the reply holds %d bytes", recorder.Body.Len())
	}
	if len(quota.Batches()) == 0 {
		t.Fatal("no batch applied")
	}
	for _, batch := range quota.Batches() {
		for _, event := range batch.Events {
			if event.NetworkId != networkId || event.Meter != sidecar.QuotaMeterEvs || event.StoredByteDelta != 0 {
				t.Fatalf("event %+v", event)
			}
		}
	}
}

// With no batcher there is nothing to count into, and the handler is served as it is.
func TestMeterTransferWithoutABatcherPassesThrough(t *testing.T) {
	served := 0
	handler := MeterTransfer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		served += 1
		if _, ok := writer.(*transferMeterWriter); ok {
			t.Error("metered with no batcher")
		}
		// no meter serves this writer, so naming a caller is a no-op
		meterTransferCaller(writer, connect.NewId())
	}), nil, nil, nil)
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/evs/v1/x", nil))
	if served != 1 {
		t.Fatalf("served %d times", served)
	}
}
