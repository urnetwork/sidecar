//go:build !sidecar_http

// rev/'s object and RevocationChecker (TEAM-M1-07). T1: the payload's bytes, its key, and every doubt a
// reader refuses. T2, on FakeBlobs and a fake clock: a removed client's token refused once the 5 s cache
// rereads, a token issued after not_before honored, each of the three subjects voiding, a failed read or
// a forged object answering unknown and never a revocation, and concurrent checks sharing one read.
//
// The signature check is the host's (server's oauth.VerifyRevocation), so here a stand-in "signs" an
// object by prefixing its payload: the root never sees a JWS's insides.

package sidecar_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Visibly synthetic ids.
var (
	testRevNetworkId = mustTestHoldId("00000000-0000-0000-0000-00000000a701")
	testRevClientId  = mustTestHoldId("00000000-0000-0000-0000-00000000c701")
	testRevSidecarId = mustTestHoldId("00000000-0000-0000-0000-00000000d701")
	testRevMemberId  = mustTestHoldId("00000000-0000-0000-0000-00000000e701")
)

// The stand-in signature: an object is this prefix and its payload.
const testRevSignature = "test-signed:"

func testRevSign(payload []byte) []byte {
	return append([]byte(testRevSignature), payload...)
}

func testRevVerify(object []byte) ([]byte, error) {
	payload, ok := bytes.CutPrefix(object, []byte(testRevSignature))
	if !ok {
		return nil, errors.New("not signed")
	}
	return payload, nil
}

// Writes record's object, as api's writer would, on blobs' first cluster.
func testRevPut(t *testing.T, blobs *sidecartest.FakeBlobs, record *sidecar.RevocationRecord) {
	t.Helper()
	payload, err := sidecar.EncodeRevocationPayload(record)
	if err != nil {
		t.Fatal(err)
	}
	cluster, err := blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.PutIfNoneMatch(context.Background(), record.Key(), testRevSign(payload), nil); err != nil {
		t.Fatal(err)
	}
}

func testRevRecord(kind sidecar.RevocationKind, subjectId sidecar.Id, notBefore time.Time) *sidecar.RevocationRecord {
	return &sidecar.RevocationRecord{
		NetworkId: testRevNetworkId,
		Kind:      kind,
		SubjectId: subjectId,
		NotBefore: sidecar.RevocationNotBefore(notBefore),
		Reason:    sidecar.RevocationReasonRemoved,
		Time:      sidecar.RevocationNotBefore(notBefore),
	}
}

// A sidecar's evs token, issued at issuedAt, naming all three subjects.
func testRevPrincipal(issuedAt time.Time) *sidecar.Principal {
	sidecarId := connect.Id(testRevSidecarId)
	memberId := connect.Id(testRevMemberId)
	return &sidecar.Principal{
		NetworkId: connect.Id(testRevNetworkId),
		ClientId:  connect.Id(testRevClientId),
		SidecarId: &sidecarId,
		MemberId:  &memberId,
		Audience:  "evs",
		IssuedAt:  issuedAt.Truncate(time.Second),
		ExpiresAt: issuedAt.Add(15 * time.Minute),
	}
}

func newTestRevChecker() (*sidecartest.FakeClock, *sidecartest.FakeBlobs, *sidecar.RevocationChecker) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	blobs := sidecartest.NewFakeBlobs(clock, nil, nil, nil)
	settings := sidecar.DefaultRevocationSettings()
	settings.Clock = clock
	return clock, blobs, sidecar.NewRevocationChecker(blobs, testRevVerify, settings)
}

// The payload's bytes are fixed: keys in order, whole seconds, no trailing newline.
func TestRevocationPayloadVector(t *testing.T) {
	record := &sidecar.RevocationRecord{
		NetworkId: testRevNetworkId,
		Kind:      sidecar.RevocationKindSidecar,
		SubjectId: testRevSidecarId,
		NotBefore: time.Unix(1767323045, 0),
		Reason:    sidecar.RevocationReasonSuspended,
		Time:      time.Unix(1767323046, 0),
	}
	payload, err := sidecar.EncodeRevocationPayload(record)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"subject":"00000000-0000-0000-0000-00000000a701/sidecar/00000000-0000-0000-0000-00000000d701",` +
		`"not_before":1767323045,"reason":"suspended","time":1767323046}`
	if string(payload) != expected {
		t.Fatalf("payload\n%s\nnot\n%s", payload, expected)
	}
	parsed, err := sidecar.ParseRevocationPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.NetworkId != record.NetworkId || parsed.Kind != record.Kind || parsed.SubjectId != record.SubjectId ||
		!parsed.NotBefore.Equal(record.NotBefore) || parsed.Reason != record.Reason || !parsed.Time.Equal(record.Time) {
		t.Fatalf("round trip %+v", parsed)
	}
	if key := record.Key(); key != "rev/00000000-0000-0000-0000-00000000a701/sidecar/00000000-0000-0000-0000-00000000d701/_" {
		t.Fatalf("key %s", key)
	}
}

func TestRevocationKeyParse(t *testing.T) {
	key := sidecar.RevocationKey(testRevNetworkId, sidecar.RevocationKindMember, testRevMemberId)
	networkId, kind, subjectId, ok := sidecar.ParseRevocationKey(key)
	if !ok || networkId != testRevNetworkId || kind != sidecar.RevocationKindMember || subjectId != testRevMemberId {
		t.Fatalf("parse of %s", key)
	}
	for _, bad := range []string{
		"rev/00000000-0000-0000-0000-00000000a701/device/00000000-0000-0000-0000-00000000d701/_",
		"rev/00000000000000000000000000000a701/client/00000000-0000-0000-0000-00000000c701/_",
		"rev/00000000-0000-0000-0000-00000000A701/client/00000000-0000-0000-0000-00000000c701/_",
		"rev/00000000-0000-0000-0000-00000000a701/client/00000000-0000-0000-0000-00000000c701",
		"hold/00000000-0000-0000-0000-00000000a701/client/00000000-0000-0000-0000-00000000c701/_",
		"rev/00000000-0000-0000-0000-000000000000/client/00000000-0000-0000-0000-00000000c701/_",
		"rev/00000000-0000-0000-0000-00000000a701/client/00000000-0000-0000-0000-00000000c701/x/_",
	} {
		if _, _, _, ok := sidecar.ParseRevocationKey(bad); ok {
			t.Errorf("parsed %s", bad)
		}
	}
}

// Whatever a reader could not read back is refused at encode, and every doubtful payload at parse.
func TestRevocationPayloadRefusals(t *testing.T) {
	good := testRevRecord(sidecar.RevocationKindClient, testRevClientId, time.Unix(1767323045, 0))
	encodeRefusals := []func(record *sidecar.RevocationRecord){
		func(record *sidecar.RevocationRecord) { record.NetworkId = sidecar.Id{} },
		func(record *sidecar.RevocationRecord) { record.SubjectId = sidecar.Id{} },
		func(record *sidecar.RevocationRecord) { record.Kind = "device" },
		func(record *sidecar.RevocationRecord) { record.Reason = "" },
		func(record *sidecar.RevocationRecord) { record.Reason = "Removed" },
		func(record *sidecar.RevocationRecord) {
			record.Reason = sidecar.RevocationReason(strings.Repeat("a", 33))
		},
		func(record *sidecar.RevocationRecord) { record.NotBefore = record.NotBefore.Add(time.Millisecond) },
		func(record *sidecar.RevocationRecord) { record.Time = time.Time{} },
	}
	for i, refuse := range encodeRefusals {
		record := *good
		refuse(&record)
		if _, err := sidecar.EncodeRevocationPayload(&record); !errors.Is(err, sidecar.ErrRevocationInvalid) {
			t.Errorf("encode refusal %d: %v", i, err)
		}
	}

	subject := `"00000000-0000-0000-0000-00000000a701/client/00000000-0000-0000-0000-00000000c701"`
	for _, bad := range []string{
		`{"subject":` + subject + `,"not_before":1,"reason":"removed"}`,
		`{"subject":` + subject + `,"not_before":1,"reason":"removed","time":1,"extra":1}`,
		`{"subject":` + subject + `,"not_before":1,"reason":"removed","time":1} {}`,
		`{"subject":` + subject + `,"not_before":-1,"reason":"removed","time":1}`,
		`{"subject":` + subject + `,"not_before":1,"reason":"Removed","time":1}`,
		`{"subject":"00000000-0000-0000-0000-00000000a701/client","not_before":1,"reason":"removed","time":1}`,
		`{"subject":"00000000-0000-0000-0000-00000000a701/device/00000000-0000-0000-0000-00000000c701","not_before":1,"reason":"removed","time":1}`,
		`not json`,
		`{"subject":` + subject + `,"not_before":1,"reason":"removed","time":1,"pad":"` + strings.Repeat("x", 512) + `"}`,
	} {
		if _, err := sidecar.ParseRevocationPayload([]byte(bad)); !errors.Is(err, sidecar.ErrRevocationInvalid) {
			t.Errorf("parsed %s: %v", bad, err)
		}
	}
	// a reason this build does not name still reads: it decides nothing
	if _, err := sidecar.ParseRevocationPayload([]byte(`{"subject":` + subject + `,"not_before":1,"reason":"later_reason","time":1}`)); err != nil {
		t.Fatal(err)
	}
}

// not_before is the whole second at or after the revocation, so a token issued in that second is void.
func TestRevocationNotBeforeRoundsUp(t *testing.T) {
	at := time.Unix(1000, 300*int64(time.Millisecond))
	notBefore := sidecar.RevocationNotBefore(at)
	if !notBefore.Equal(time.Unix(1001, 0)) {
		t.Fatalf("not_before %v", notBefore)
	}
	if !sidecar.RevocationNotBefore(time.Unix(1000, 0)).Equal(time.Unix(1000, 0)) {
		t.Fatal("a whole second moved")
	}
	record := &sidecar.RevocationRecord{NotBefore: notBefore}
	if !record.Voids(time.Unix(1000, 0)) {
		t.Fatal("a token issued in the revocation's second survives")
	}
	if record.Voids(time.Unix(1001, 0)) {
		t.Fatal("a token issued at not_before is void")
	}
	if !record.Voids(time.Time{}) {
		t.Fatal("a token with no iat survives")
	}
}

// §7.8's check row: a removed client's token is refused at evs once the subject's cached answer, at most
// 5 s old, is read again; a token issued after not_before is honored.
func TestRevocationRefusesRemovedClientWithinCacheTimeout(t *testing.T) {
	ctx := context.Background()
	clock, blobs, checker := newTestRevChecker()
	issuedAt := clock.Now()
	principal := testRevPrincipal(issuedAt)

	if err := checker.Check(ctx, principal); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Second)
	testRevPut(t, blobs, testRevRecord(sidecar.RevocationKindClient, testRevClientId, clock.Now()))

	// inside the cache's 5 s the earlier answer stands
	clock.Advance(2 * time.Second)
	if err := checker.Check(ctx, principal); err != nil {
		t.Fatalf("a cached answer was read again early: %v", err)
	}
	clock.Advance(time.Second)
	if err := checker.Check(ctx, principal); !errors.Is(err, sidecar.ErrRevocationVoidsToken) {
		t.Fatalf("a removed client's token after the cache: %v", err)
	}

	// a token issued after not_before is honored
	clock.Advance(time.Minute)
	if err := checker.Check(ctx, testRevPrincipal(clock.Now())); err != nil {
		t.Fatalf("a token issued after not_before: %v", err)
	}
}

// Each of a token's three subjects voids it, and a token naming no sidecar or member reads only its
// client.
func TestRevocationEachSubjectVoids(t *testing.T) {
	ctx := context.Background()
	for _, subject := range []struct {
		kind sidecar.RevocationKind
		id   sidecar.Id
	}{
		{kind: sidecar.RevocationKindClient, id: testRevClientId},
		{kind: sidecar.RevocationKindSidecar, id: testRevSidecarId},
		{kind: sidecar.RevocationKindMember, id: testRevMemberId},
	} {
		clock, blobs, checker := newTestRevChecker()
		principal := testRevPrincipal(clock.Now())
		clock.Advance(time.Second)
		testRevPut(t, blobs, testRevRecord(subject.kind, subject.id, clock.Now()))
		if err := checker.Check(ctx, principal); !errors.Is(err, sidecar.ErrRevocationVoidsToken) {
			t.Errorf("%s: %v", subject.kind, err)
		}
	}

	clock, blobs, checker := newTestRevChecker()
	principal := testRevPrincipal(clock.Now())
	principal.SidecarId = nil
	principal.MemberId = nil
	clock.Advance(time.Second)
	testRevPut(t, blobs, testRevRecord(sidecar.RevocationKindSidecar, testRevSidecarId, clock.Now()))
	if err := checker.Check(ctx, principal); err != nil {
		t.Fatalf("a token naming no sidecar: %v", err)
	}
	if count := len(blobs.Faults().OpResults(sidecartest.FaultOpGet)); count != 1 {
		t.Fatalf("%d reads for one subject", count)
	}
}

// Every doubt answers unknown, which an engine answers 503: never a revocation and never an allow.
func TestRevocationDoubtAnswersUnknown(t *testing.T) {
	ctx := context.Background()

	// the store's read fails
	clock, blobs, checker := newTestRevChecker()
	if _, err := blobs.Faults().Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpGet, KeyPrefix: "rev/", Result: sidecartest.FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	err := checker.Check(ctx, testRevPrincipal(clock.Now()))
	if err == nil || errors.Is(err, sidecar.ErrRevocationVoidsToken) {
		t.Fatalf("a failed read: %v", err)
	}
	// a failed read is not kept, so the next check reads again
	if err := checker.Check(ctx, testRevPrincipal(clock.Now())); err != nil {
		t.Fatalf("after the fault: %v", err)
	}

	cluster, _ := blobs.FirstCluster()
	put := func(key string, body []byte) {
		if _, err := cluster.PutIfNoneMatch(ctx, key, body, nil); err != nil {
			t.Fatal(err)
		}
	}
	payloadOf := func(record *sidecar.RevocationRecord) []byte {
		payload, err := sidecar.EncodeRevocationPayload(record)
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
	for i, plant := range []func(){
		// an object whose signature does not verify
		func() {
			put(sidecar.RevocationKey(testRevNetworkId, sidecar.RevocationKindClient, testRevClientId),
				payloadOf(testRevRecord(sidecar.RevocationKindClient, testRevClientId, clock.Now())))
		},
		// another subject's signed object copied to this key
		func() {
			put(sidecar.RevocationKey(testRevNetworkId, sidecar.RevocationKindClient, testRevClientId),
				testRevSign(payloadOf(testRevRecord(sidecar.RevocationKindSidecar, testRevSidecarId, clock.Now()))))
		},
		// an object over its bound
		func() {
			put(sidecar.RevocationKey(testRevNetworkId, sidecar.RevocationKindClient, testRevClientId),
				testRevSign(bytes.Repeat([]byte{'x'}, sidecar.RevocationObjectMaxByteCount)))
		},
	} {
		clock, blobs, checker = newTestRevChecker()
		cluster, _ = blobs.FirstCluster()
		plant()
		err := checker.Check(ctx, testRevPrincipal(clock.Now().Add(-time.Hour)))
		if err == nil || errors.Is(err, sidecar.ErrRevocationVoidsToken) || !errors.Is(err, sidecar.ErrRevocationInvalid) {
			t.Errorf("plant %d: %v", i, err)
		}
	}

	// a host with no store or no verifier reads nothing and allows nothing
	unhosted := sidecar.NewRevocationChecker(nil, testRevVerify, nil)
	if err := unhosted.Check(ctx, testRevPrincipal(clock.Now())); err == nil || errors.Is(err, sidecar.ErrRevocationVoidsToken) {
		t.Fatalf("no store: %v", err)
	}
	// a principal Validate refuses is refused
	principal := testRevPrincipal(clock.Now())
	principal.ClientId = connect.Id{}
	if err := checker.Check(ctx, principal); !errors.Is(err, sidecar.ErrAuthenticationRefused) {
		t.Fatalf("a principal with no client: %v", err)
	}
}

// Checks of one subject while its read is under way wait on that read rather than reading again, and a
// read cut short by its caller is not kept.
func TestRevocationConcurrentChecksShareOneRead(t *testing.T) {
	ctx := context.Background()
	clock, blobs, checker := newTestRevChecker()
	if _, err := blobs.Faults().Add(&sidecartest.FaultPlan{
		Op:        sidecartest.FaultOpGet,
		KeyPrefix: "rev/",
		Result:    sidecartest.Delay,
		Delay:     sidecartest.DelayInNetwork,
	}); err != nil {
		t.Fatal(err)
	}
	principal := testRevPrincipal(clock.Now())
	principal.SidecarId = nil
	principal.MemberId = nil
	answers := make(chan error, 2)
	go func() {
		answers <- checker.Check(ctx, principal)
	}()
	// the parked GET's client timeout is the one timer, so it is parked once this returns
	if err := clock.AwaitTimers(ctx, 1); err != nil {
		t.Fatal(err)
	}
	go func() {
		answers <- checker.Check(ctx, principal)
	}()
	if delivered := blobs.DeliverDelayed("meta-1", "rev/"); delivered != 1 {
		t.Fatalf("%d parked reads", delivered)
	}
	for range 2 {
		if err := <-answers; err != nil {
			t.Fatal(err)
		}
	}
	if count := len(blobs.Faults().OpResults(sidecartest.FaultOpGet)); count != 1 {
		t.Fatalf("%d reads", count)
	}

	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()
	clock.Advance(10 * time.Second)
	if err := checker.Check(canceledCtx, principal); err == nil {
		t.Fatal("a canceled check allowed")
	}
	if err := checker.Check(ctx, principal); err != nil {
		t.Fatalf("after a canceled read: %v", err)
	}
}
