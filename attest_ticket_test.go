//go:build !ios_extension && !sidecar_http

// Freshness tickets (ATTEST-M12-01): a sitting's batch as §5.4's pipeline makes it, each bound refused past §5.4's
// numbers whatever its signature says, and the strict encodings that keep a ticket and a policy from passing for each
// other.

package sidecar

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The test sitting: 2026-12-01 10:00 UTC, its batch expiring 14 days later.
var testAttestSitting = time.Date(2026, time.December, 1, 10, 0, 0, 0, time.UTC)

// A test ticket and its file.
type testAttestTicket struct {
	ticket *ComputePolicyTicket
	file   []byte
}

// A batch id from label, the same every run.
func testAttestBatchId(label string) Id {
	sum := sha256.Sum256([]byte("urnetwork-sidecar test attest batch " + label))
	id, _ := IdFromBytes(sum[:16])
	return id
}

// The UTC midnight starting at's day.
func testAttestDay(at time.Time) time.Time {
	at = at.UTC()
	return time.Date(at.Year(), at.Month(), at.Day(), 0, 0, 0, 0, time.UTC)
}

// ticket's file, signed by signer under namespace.
func testAttestSignTicket(t testing.TB, signer ssh.Signer, namespace string, ticket *ComputePolicyTicket) []byte {
	t.Helper()
	file, err := SignComputePolicyTicket(testAttestRandom("ticket"), signer, namespace, ticket)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

// A sitting's batch as §5.4 makes it: signed at signedAt, expiring 14 days later, naming version; one ticket for
// each day from the day after the sitting until it expires, each starting 00:00 UTC, ending 72 hours later cut to
// the batch's expiry; a revocation's batch starts its first ticket at signedAt.
func testAttestBatch(t testing.TB, signer ssh.Signer, namespace string, signedAt time.Time, version uint64, revocation bool) []*testAttestTicket {
	t.Helper()
	batch := ComputePolicyTicketBatch{
		Id:       testAttestBatchId(signedAt.Format(time.RFC3339) + namespace),
		SignedAt: signedAt,
		Expires:  signedAt.Add(14 * 24 * time.Hour),
	}
	starts := []time.Time{}
	if revocation {
		starts = append(starts, signedAt)
	}
	for day := testAttestDay(signedAt).AddDate(0, 0, 1); day.Before(batch.Expires); day = day.AddDate(0, 0, 1) {
		starts = append(starts, day)
	}
	tickets := []*testAttestTicket{}
	for _, start := range starts {
		ticket := &ComputePolicyTicket{
			Batch:         batch,
			PolicyVersion: version,
			NotBefore:     start,
			NotAfter:      computePolicyMinTime(start.Add(72*time.Hour), batch.Expires),
		}
		tickets = append(tickets, &testAttestTicket{ticket: ticket, file: testAttestSignTicket(t, signer, namespace, ticket)})
	}
	return tickets
}

// The batch's ticket starting at start.
func testAttestTicketAt(t testing.TB, tickets []*testAttestTicket, start time.Time) *testAttestTicket {
	t.Helper()
	for _, ticket := range tickets {
		if ticket.ticket.NotBefore.Equal(start) {
			return ticket
		}
	}
	t.Fatalf("no ticket starts at %s", start)
	return nil
}

// A sitting's batch holds one ticket a day from the day after the sitting, each verifying under the same key and
// namespace as the policy, its window 72 hours cut to the batch's expiry 14 days after the sitting.
func TestTicketBatchVerifies(t *testing.T) {
	keys := newTestAttestKeys(t)
	verifier := keys.verifier(false)
	tickets := testAttestBatch(t, keys.policy, ComputePolicyNamespace, testAttestSitting, 3, false)
	if len(tickets) != 14 {
		t.Fatalf("%d tickets", len(tickets))
	}
	for _, made := range tickets {
		ticket, err := verifier.VerifyTicket(made.file, testAttestSitting)
		if err != nil {
			t.Fatalf("the ticket of %s: %v", made.ticket.NotBefore, err)
		}
		if ticket.PolicyVersion != 3 || !ticket.NotBefore.Equal(made.ticket.NotBefore) || !ticket.NotAfter.Equal(made.ticket.NotAfter) ||
			ticket.Batch != made.ticket.Batch || ticket.Signer().Namespace != ComputePolicyNamespace {
			t.Errorf("verified %+v, made %+v", ticket, made.ticket)
		}
	}
	last := tickets[len(tickets)-1].ticket
	if !last.NotBefore.Equal(time.Date(2026, time.December, 15, 0, 0, 0, 0, time.UTC)) || !last.NotAfter.Equal(testAttestSitting.Add(14*24*time.Hour)) {
		t.Errorf("the last ticket's window %s to %s", last.NotBefore, last.NotAfter)
	}
	revocation := testAttestBatch(t, keys.policy, ComputePolicyNamespace, testAttestSitting, 4, true)
	if !revocation[0].ticket.NotBefore.Equal(testAttestSitting) {
		t.Errorf("a revocation's first ticket starts at %s", revocation[0].ticket.NotBefore)
	}
}

// A ticket refused as a bounds or format refusal.
func testAttestWantTicketRefused(t *testing.T, name string, file []byte) {
	t.Helper()
	ticket, err := newTestAttestKeys(t).verifier(false).VerifyTicket(file, testAttestSitting)
	if ticket != nil || !errors.Is(err, ErrComputePolicyRefused) {
		t.Errorf("%s: %v, %v", name, ticket, err)
	}
}

// A window past 72 hours, past its batch's expiry, empty, or starting before its sitting is refused, signature or not.
func TestTicketWindowPastBoundsRefused(t *testing.T) {
	keys := newTestAttestKeys(t)
	batch := ComputePolicyTicketBatch{Id: testAttestBatchId("bounds"), SignedAt: testAttestSitting, Expires: testAttestSitting.Add(14 * 24 * time.Hour)}
	start := testAttestDay(testAttestSitting).AddDate(0, 0, 1)
	sign := func(notBefore time.Time, notAfter time.Time) []byte {
		return testAttestSignTicket(t, keys.policy, ComputePolicyNamespace, &ComputePolicyTicket{Batch: batch, PolicyVersion: 3, NotBefore: notBefore, NotAfter: notAfter})
	}
	if _, err := keys.verifier(false).VerifyTicket(sign(start, start.Add(72*time.Hour)), testAttestSitting); err != nil {
		t.Fatalf("a window of exactly 72 hours: %v", err)
	}
	testAttestWantTicketRefused(t, "past 72 hours", sign(start, start.Add(72*time.Hour+time.Millisecond)))
	last := batch.Expires.Add(-time.Hour)
	testAttestWantTicketRefused(t, "past its batch's expiry", sign(last, batch.Expires.Add(time.Millisecond)))
	testAttestWantTicketRefused(t, "empty", sign(start, start))
	testAttestWantTicketRefused(t, "before its sitting", sign(testAttestSitting.Add(-time.Millisecond), start))
}

// A batch whose expiry falls more than 14 days after its sitting is refused, every ticket of it.
func TestTicketBatchPastFourteenDaysRefused(t *testing.T) {
	keys := newTestAttestKeys(t)
	start := testAttestDay(testAttestSitting).AddDate(0, 0, 1)
	sign := func(expires time.Time) []byte {
		batch := ComputePolicyTicketBatch{Id: testAttestBatchId("long"), SignedAt: testAttestSitting, Expires: expires}
		return testAttestSignTicket(t, keys.policy, ComputePolicyNamespace, &ComputePolicyTicket{Batch: batch, PolicyVersion: 3, NotBefore: start, NotAfter: start.Add(24 * time.Hour)})
	}
	if _, err := keys.verifier(false).VerifyTicket(sign(testAttestSitting.Add(14*24*time.Hour)), testAttestSitting); err != nil {
		t.Fatalf("a batch of exactly 14 days: %v", err)
	}
	testAttestWantTicketRefused(t, "15 days", sign(testAttestSitting.Add(15*24*time.Hour)))
	testAttestWantTicketRefused(t, "a millisecond past 14 days", sign(testAttestSitting.Add(14*24*time.Hour+time.Millisecond)))
	testAttestWantTicketRefused(t, "expiring before its sitting", sign(testAttestSitting.Add(-time.Hour)))
}

// A ticket's bytes are one encoding: an unknown field, another order of the same fields, or a field missing is
// refused, as is a ticket the staging key signed in a production build.
func TestTicketParsesStrictly(t *testing.T) {
	keys := newTestAttestKeys(t)
	made := testAttestBatch(t, keys.policy, ComputePolicyNamespace, testAttestSitting, 3, false)[0]
	ticketBytes, err := made.ticket.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	sign := func(ticketBytes []byte) []byte {
		signature := testAttestSign(t, keys.policy, ComputePolicyNamespace, ticketBytes)
		file, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.ComputePolicyTicketFile{Ticket: ticketBytes, Signature: signature})
		if err != nil {
			t.Fatal(err)
		}
		return file
	}
	if _, err := keys.verifier(false).VerifyTicket(sign(ticketBytes), testAttestSitting); err != nil {
		t.Fatalf("the ticket signed again: %v", err)
	}
	unknown := protowire.AppendTag(append([]byte{}, ticketBytes...), 9, protowire.VarintType)
	unknown = protowire.AppendVarint(unknown, 1)
	testAttestWantTicketRefused(t, "an unknown field", sign(unknown))
	// field 5 (not_after_ms) moved before field 1: the same message in another encoding
	reordered := []byte{}
	var notAfterField []byte
	for rest := ticketBytes; 0 < len(rest); {
		number, kind, tagLength := protowire.ConsumeTag(rest)
		valueLength := protowire.ConsumeFieldValue(number, kind, rest[tagLength:])
		field := rest[:tagLength+valueLength]
		if number == 5 {
			notAfterField = field
		} else {
			reordered = append(reordered, field...)
		}
		rest = rest[tagLength+valueLength:]
	}
	testAttestWantTicketRefused(t, "another order", sign(append(append([]byte{}, notAfterField...), reordered...)))
	missing := &ComputePolicyTicket{Batch: made.ticket.Batch, NotBefore: made.ticket.NotBefore, NotAfter: made.ticket.NotAfter}
	testAttestWantTicketRefused(t, "no policy version", testAttestSignTicket(t, keys.policy, ComputePolicyNamespace, missing))
	stagingSigned := testAttestSignTicket(t, keys.staging, ComputePolicyStagingNamespace, made.ticket)
	ticket, err := keys.verifier(false).VerifyTicket(stagingSigned, testAttestSitting)
	testAttestWantRefused(t, nil, err, errComputePolicyNamespace)
	if ticket != nil {
		t.Error("a staging ticket in a production build")
	}
}

// Strict parsing keeps a ticket from passing for a policy and a policy for a ticket, though both are signed by the
// same key under the same namespace.
func TestTicketAndPolicyNeverPassForEachOther(t *testing.T) {
	keys := newTestAttestKeys(t)
	verifier := keys.verifier(false)
	document, err := os.ReadFile(filepath.Join(testAttestVectorDirectory, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	policySignature := testAttestVector(t, "policy.json.sig")
	asTicket, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.ComputePolicyTicketFile{Ticket: document, Signature: policySignature})
	if err != nil {
		t.Fatal(err)
	}
	if ticket, err := verifier.VerifyTicket(asTicket, testAttestNow); ticket != nil || !errors.Is(err, errComputePolicyTicketFormat) {
		t.Errorf("a policy as a ticket: %v, %v", ticket, err)
	}
	made := testAttestBatch(t, keys.policy, ComputePolicyNamespace, testAttestSitting, 3, false)[0]
	envelope := &protocol.ComputePolicyTicketFile{}
	if err := proto.Unmarshal(made.file, envelope); err != nil {
		t.Fatal(err)
	}
	if policy, err := verifier.Verify(envelope.GetTicket(), envelope.GetSignature(), testAttestNow); policy != nil || !errors.Is(err, errComputePolicyFormat) {
		t.Errorf("a ticket as a policy: %v, %v", policy, err)
	}
}

// The ticket vectors, beside the policy's (testdata/attest/ticket/): the batch's ticket of 2026-12-03, its last, and a
// revocation's first at 15:00 that day naming version 4, each a <day>.bin file as ur.io serves it, signed by the test
// compute-policy key. SIDECAR_WRITE_ATTEST_VECTORS=1 rewrites them.
const testAttestTicketVectorDirectory = "testdata/attest/ticket"

// Every ticket vector, by file name, as the test keys make them.
func testAttestTicketVectors(t testing.TB) map[string][]byte {
	t.Helper()
	keys := newTestAttestKeys(t)
	batch := testAttestBatch(t, keys.policy, ComputePolicyNamespace, testAttestSitting, 3, false)
	revocationAt := time.Date(2026, time.December, 3, 15, 0, 0, 0, time.UTC)
	revocation := testAttestBatch(t, keys.policy, ComputePolicyNamespace, revocationAt, 4, true)
	return map[string][]byte{
		"2026-12-03.bin":            testAttestTicketAt(t, batch, time.Date(2026, time.December, 3, 0, 0, 0, 0, time.UTC)).file,
		"2026-12-15.last.bin":       batch[len(batch)-1].file,
		"2026-12-03.revocation.bin": revocation[0].file,
	}
}

// The committed ticket vectors are what the keys make, and each verifies.
func TestTicketVectorsAreCurrent(t *testing.T) {
	files := testAttestTicketVectors(t)
	if os.Getenv(testAttestWriteVectorsEnvironment) != "" {
		if err := os.MkdirAll(testAttestTicketVectorDirectory, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, data := range files {
			if err := os.WriteFile(filepath.Join(testAttestTicketVectorDirectory, name), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	verifier := newTestAttestKeys(t).verifier(false)
	for name, data := range files {
		committed, err := os.ReadFile(filepath.Join(testAttestTicketVectorDirectory, name))
		if err != nil {
			t.Errorf("%s: %v (rewrite with %s=1)", name, err, testAttestWriteVectorsEnvironment)
			continue
		}
		if string(committed) != string(data) {
			t.Errorf("%s differs from what the test keys make (rewrite with %s=1)", name, testAttestWriteVectorsEnvironment)
		}
		if _, err := verifier.VerifyTicket(committed, testAttestSitting); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
