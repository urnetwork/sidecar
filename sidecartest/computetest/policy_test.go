package computetest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A fake on a fresh FakeClock at sidecartest.DefaultClockStart, which must build.
func newTestFakeComputePolicy(t *testing.T, seed string) (*FakeComputePolicy, *sidecartest.FakeClock) {
	t.Helper()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	fake, err := NewFakeComputePolicy(&FakeComputePolicyArgs{Seed: seed, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	return fake, clock
}

// A sitting's batch over args, which must build.
func newTestFakeBatch(t *testing.T, fake *FakeComputePolicy, args *FakeTicketBatchArgs) *FakeTicketBatch {
	t.Helper()
	batch, err := fake.NewBatch(args)
	if err != nil {
		t.Fatal(err)
	}
	return batch
}

// A sitting's tickets cover every instant from the first one's start to the batch's expiry, 14 days after the sitting
// and no later: one ticket for each UTC day from the day after the sitting, each starting at 00:00 UTC and current for
// 72 hours cut to the expiry, none at or after it; a revocation's batch starts its first ticket at the sitting itself.
func TestFakeTicketsCoverFourteenDays(t *testing.T) {
	fake, clock := newTestFakeComputePolicy(t, "")
	attest := fake.Settings().Attest
	sitting := clock.Now()
	cases := []struct {
		args *FakeTicketBatchArgs
		// the first ticket's start, and how many tickets
		first time.Time
		count int
	}{
		// a sitting at 03:04:05: days 1 to 14, the last cut at the expiry that day
		{args: &FakeTicketBatchArgs{PolicyVersion: 1}, first: fakeUtcDay(sitting).AddDate(0, 0, 1), count: 14},
		// a sitting at midnight: days 1 to 13, the expiry falling at day 14's start
		{args: &FakeTicketBatchArgs{PolicyVersion: 1, SignedAt: fakeUtcDay(sitting)}, first: fakeUtcDay(sitting).AddDate(0, 0, 1), count: 13},
		// a revocation's batch at 15:04:05 the next day: the sitting itself, then days 1 to 14 after it
		{args: &FakeTicketBatchArgs{PolicyVersion: 2, Revocation: true, SignedAt: sitting.Add(36 * time.Hour)}, first: sitting.Add(36 * time.Hour), count: 15},
	}
	for i, c := range cases {
		batch := newTestFakeBatch(t, fake, c.args)
		signedAt := c.args.SignedAt
		if signedAt.IsZero() {
			signedAt = sitting
		}
		if !batch.SignedAt.Equal(signedAt) || !batch.Expires.Equal(signedAt.Add(attest.TicketBatchMaxLifetime)) {
			t.Fatalf("case %d: signed %s, expires %s", i, batch.SignedAt, batch.Expires)
		}
		if len(batch.Tickets) != c.count || !batch.Tickets[0].NotBefore().Equal(c.first) {
			t.Fatalf("case %d: %d tickets from %s, not %d from %s", i, len(batch.Tickets), batch.Tickets[0].NotBefore(), c.count, c.first)
		}
		files := [][]byte{}
		for j, ticket := range batch.Tickets {
			if ticket.Ticket.Batch.Id != batch.Id || !ticket.Ticket.Batch.SignedAt.Equal(batch.SignedAt) ||
				!ticket.Ticket.Batch.Expires.Equal(batch.Expires) || ticket.Ticket.PolicyVersion != c.args.PolicyVersion {
				t.Fatalf("case %d ticket %d names another batch or version", i, j)
			}
			window := ticket.NotAfter().Sub(ticket.NotBefore())
			if window <= 0 || attest.TicketMaxWindow < window || batch.Expires.Before(ticket.NotAfter()) ||
				!batch.Expires.After(ticket.NotBefore()) {
				t.Fatalf("case %d ticket %d: %s to %s past the bounds", i, j, ticket.NotBefore(), ticket.NotAfter())
			}
			if want := ticket.NotBefore().Add(attest.TicketMaxWindow); want.Before(batch.Expires) && !ticket.NotAfter().Equal(want) {
				t.Fatalf("case %d ticket %d ends at %s, not 72 hours on", i, j, ticket.NotAfter())
			}
			if 0 < j || !c.args.Revocation {
				if !ticket.NotBefore().Equal(fakeUtcDay(ticket.NotBefore())) {
					t.Fatalf("case %d ticket %d starts at %s, not 00:00 UTC", i, j, ticket.NotBefore())
				}
			}
			if 0 < j {
				previous := batch.Tickets[j-1]
				if previous.NotAfter().Before(ticket.NotBefore()) || !ticket.Day().After(previous.Day()) {
					t.Fatalf("case %d: a gap or a repeated day before ticket %d", i, j)
				}
			}
			if len(ticket.File) == 0 || slices.ContainsFunc(files, func(file []byte) bool { return bytes.Equal(file, ticket.File) }) {
				t.Fatalf("case %d ticket %d's file is empty or another's", i, j)
			}
			files = append(files, ticket.File)
		}
		if last := batch.Tickets[len(batch.Tickets)-1]; !last.NotAfter().Equal(batch.Expires) {
			t.Fatalf("case %d: the last ticket ends at %s, not the expiry %s", i, last.NotAfter(), batch.Expires)
		}
	}
	if _, err := fake.NewBatch(&FakeTicketBatchArgs{}); !errors.Is(err, ErrFakePolicyInvalid) {
		t.Fatalf("a batch naming no version answered %v", err)
	}
}

// The host releases each ticket at its start, one a day on the clock the test steps, from the newest batch: every
// ticket still ahead is kept back and served to no one, and a later sitting's batch deletes the earlier batch's
// unreleased tickets at once, the host releasing from the newer batch after.
func TestFakeTicketHostReleasesOneADay(t *testing.T) {
	fake, clock := newTestFakeComputePolicy(t, "")
	host := fake.NewTicketHost()
	first := newTestFakeBatch(t, fake, &FakeTicketBatchArgs{PolicyVersion: 1})
	host.Sit(first)
	day := func(n int) time.Time {
		return fakeUtcDay(first.SignedAt).AddDate(0, 0, n)
	}
	served := func(at time.Time) []byte {
		file, err := host.Ticket(context.Background(), at)
		if errors.Is(err, sidecar.ErrComputePolicySourceAbsent) {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		return file
	}
	if len(host.Released()) != 0 || len(host.Unreleased()) != len(first.Tickets) || served(day(1)) != nil {
		t.Fatal("a ticket was released before its start")
	}
	clock.AdvanceTo(day(1).Add(-time.Millisecond))
	if len(host.Released()) != 0 || served(day(1)) != nil {
		t.Fatal("a ticket was released a millisecond early")
	}
	for n := 1; n <= 7; n += 1 {
		clock.AdvanceTo(day(n))
		released := host.Released()
		if len(released) != n || len(host.Unreleased()) != len(first.Tickets)-n || released[n-1] != first.Tickets[n-1] {
			t.Fatalf("day %d: %d released, %d kept back", n, len(released), len(host.Unreleased()))
		}
		if !bytes.Equal(served(day(n)), first.Tickets[n-1].File) || served(day(n+1)) != nil {
			t.Fatalf("day %d: the serving path does not hold that day's ticket alone", n)
		}
	}
	// the next sitting, at day 7's noon: the first batch's days 8 to 14 are deleted, never to be released
	clock.Advance(12 * time.Hour)
	second := newTestFakeBatch(t, fake, &FakeTicketBatchArgs{PolicyVersion: 1})
	host.Sit(second)
	for _, kept := range host.Unreleased() {
		if !slices.Contains(second.Tickets, kept) {
			t.Fatalf("the first batch's ticket of %s survived the next sitting", kept.Day())
		}
	}
	if len(host.Unreleased()) != len(second.Tickets) {
		t.Fatalf("%d tickets kept back, not the second batch's %d", len(host.Unreleased()), len(second.Tickets))
	}
	for n := 8; n <= 14; n += 1 {
		clock.AdvanceTo(day(n))
		released := host.Released()
		if newest := released[len(released)-1]; newest != second.Tickets[n-8] || len(released) != 7+(n-7) {
			t.Fatalf("day %d released %d tickets, the newest of %s", n, len(released), newest.Day())
		}
		if !bytes.Equal(served(day(n)), second.Tickets[n-8].File) {
			t.Fatalf("day %d: the serving path holds another batch's ticket", n)
		}
	}
	// a day already past keeps the ticket released for it
	if !bytes.Equal(served(day(3)), first.Tickets[2].File) {
		t.Fatal("the serving path lost a released ticket")
	}
}

// The serving path serves each published policy at its version, and nothing it withholds: a withheld version's policy
// and every ticket naming it are absent while the released tickets of other versions stay served; Serve undoes it.
func TestFakeTicketHostServesPoliciesItHolds(t *testing.T) {
	fake, clock := newTestFakeComputePolicy(t, "")
	host := fake.NewTicketHost()
	policy, err := fake.Sign(fake.NewPolicy(1), FakePolicySignerPolicy)
	if err != nil {
		t.Fatal(err)
	}
	host.Publish(policy)
	batch := newTestFakeBatch(t, fake, &FakeTicketBatchArgs{PolicyVersion: 1})
	host.Sit(batch)
	clock.AdvanceTo(batch.Tickets[0].NotBefore())
	document, signature, err := host.Policy(context.Background(), 1)
	if err != nil || !bytes.Equal(document, policy.Document) || !bytes.Equal(signature, policy.Signature) {
		t.Fatalf("policy 1: %v", err)
	}
	if _, _, err := host.Policy(context.Background(), 2); !errors.Is(err, sidecar.ErrComputePolicySourceAbsent) {
		t.Fatalf("an unpublished policy answered %v", err)
	}
	host.Withhold(1)
	if _, _, err := host.Policy(context.Background(), 1); !errors.Is(err, sidecar.ErrComputePolicySourceAbsent) {
		t.Fatalf("a withheld policy answered %v", err)
	}
	if _, err := host.Ticket(context.Background(), batch.Tickets[0].Day()); !errors.Is(err, sidecar.ErrComputePolicySourceAbsent) {
		t.Fatalf("a ticket naming a withheld version answered %v", err)
	}
	if len(host.Released()) != 1 {
		t.Fatal("withholding at the serving path took a ticket back from the host")
	}
	host.Serve(1)
	if file, err := host.Ticket(context.Background(), batch.Tickets[0].Day()); err != nil || !bytes.Equal(file, batch.Tickets[0].File) {
		t.Fatalf("a served ticket: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := host.Policy(ctx, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("an ended context answered %v", err)
	}
}

// Every key, certificate, document, signature and ticket is drawn from the seed, so two fakes of one seed and one clock
// make the same bytes, and another seed other keys and signatures.
func TestFakePolicyKeysAreStable(t *testing.T) {
	// the release key, each certificate, a policy's document and signatures, and a batch's ticket files
	made := func(seed string) [][]byte {
		fake, _ := newTestFakeComputePolicy(t, seed)
		keys := fake.Keys()
		out := [][]byte{
			keys.Release.PublicKey().Marshal(),
			keys.OtherRelease.PublicKey().Marshal(),
			keys.Policy.PublicKey().Marshal(),
			keys.Staging.PublicKey().Marshal(),
			keys.Uncertified.PublicKey().Marshal(),
			keys.ReleaseLine(),
		}
		policy, err := fake.Sign(fake.NewPolicy(1), FakePolicySignerPolicy)
		if err != nil {
			t.Fatal(err)
		}
		staging, err := fake.Sign(fake.NewPolicy(1), FakePolicySignerStaging)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, policy.Document, policy.Signature, staging.Signature)
		for _, ticket := range newTestFakeBatch(t, fake, &FakeTicketBatchArgs{PolicyVersion: 1}).Tickets {
			out = append(out, ticket.File)
		}
		return out
	}
	first := made("stable")
	if !slices.EqualFunc(first, made("stable"), bytes.Equal) {
		t.Fatal("two fakes of one seed made different bytes")
	}
	other := made("another")
	for i := range first {
		// a document's hashes, hotkeys and ids are drawn from the seed too, a ticket's batch id with them
		if bytes.Equal(first[i], other[i]) {
			t.Fatalf("another seed made the same bytes at %d", i)
		}
	}
	// the uncertified key is the compute-policy key itself, its certificate by another authority
	fake, _ := newTestFakeComputePolicy(t, "stable")
	keys := fake.Keys()
	policyCertificate, policyOk := keys.Policy.PublicKey().(*ssh.Certificate)
	uncertifiedCertificate, uncertifiedOk := keys.Uncertified.PublicKey().(*ssh.Certificate)
	if !policyOk || !uncertifiedOk || !bytes.Equal(policyCertificate.Key.Marshal(), uncertifiedCertificate.Key.Marshal()) ||
		!bytes.Equal(policyCertificate.SignatureKey.Marshal(), keys.Release.PublicKey().Marshal()) ||
		!bytes.Equal(uncertifiedCertificate.SignatureKey.Marshal(), keys.OtherRelease.PublicKey().Marshal()) {
		t.Fatal("the certificates do not name the keys the file header says")
	}
}

// A document is ATTEST's format as JSON with no null anywhere: every list the policy left nil is written [], the
// gated search and services lines are left out until set, and a raw line set is carried as given.
func TestFakePolicyDocumentWritesNoNull(t *testing.T) {
	fake, _ := newTestFakeComputePolicy(t, "")
	policy := &sidecar.ComputePolicy{Version: 1, NotAfterMs: 1}
	policy.Direct.Providers = []*sidecar.ComputePolicyDirect{{Slug: "engy", Models: []*sidecar.ComputePolicyDirectModel{{Model: "x"}}}}
	document, err := fake.Document(policy)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(document, []byte("null")) || bytes.Contains(document, []byte(`"search"`)) ||
		bytes.Contains(document, []byte(`"services"`)) || !bytes.Contains(document, []byte(`"aliases":[]`)) ||
		!bytes.Contains(document, []byte(`"targets":[]`)) || !bytes.Contains(document, []byte(`"providers":[]`)) {
		t.Fatalf("the document: %s", document)
	}
	if policy.Direct.Providers[0].Targets != nil || policy.Direct.Providers[0].Models[0].Aliases != nil || policy.Providers != nil {
		t.Fatal("writing the document changed the policy")
	}
	full := fake.NewPolicy(2)
	full.Search = json.RawMessage(`{"host": "search.example", "ceiling": 15}`)
	document, err = fake.Document(full)
	if err != nil {
		t.Fatal(err)
	}
	decoded := &sidecar.ComputePolicy{}
	if err := json.Unmarshal(document, decoded); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(decoded.Search), `"search.example"`) || decoded.Services != nil || bytes.Contains(document, []byte("null")) {
		t.Fatalf("the search line: %s", decoded.Search)
	}
	if _, err := fake.Document(nil); !errors.Is(err, ErrFakePolicyInvalid) {
		t.Fatalf("no policy answered %v", err)
	}
	if _, err := fake.SignBytes(document, FakePolicySigner("nobody")); !errors.Is(err, ErrFakePolicySigner) {
		t.Fatalf("an unknown signer answered %v", err)
	}
}
