//go:build sidecar_testhooks

package computetest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// The lapse reason a gate's refusal carries, empty for another error or none.
func testLapseReason(err error) sidecar.ComputeRemoteLapseReason {
	lapsed := &sidecar.ComputeRemoteLapsedError{}
	if errors.As(err, &lapsed) {
		return lapsed.Reason
	}
	return ""
}

// A signed policy, which must sign.
func testSignedPolicy(t *testing.T, fake *FakeComputePolicy, policy *sidecar.ComputePolicy, signer FakePolicySigner) *FakeSignedPolicy {
	t.Helper()
	signed, err := fake.Sign(policy, signer)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// A device over args, which must build.
func testFakeDevice(t *testing.T, fake *FakeComputePolicy, args *FakePolicyDeviceArgs) *FakePolicyDevice {
	t.Helper()
	device, err := fake.NewDevice(args)
	if err != nil {
		t.Fatal(err)
	}
	return device
}

// ATTEST's verifier, with the test release key pinned in a test build, takes the fake's policy, every line as the fake
// wrote it, the search and services lines verbatim, and each ticket of its batch within §5.4's bounds; the staging
// verifier takes the staging key's; a window past 72 hours and a batch past 14 days, the edges the fake can be asked
// past, are refused; and a device's store and gate run remote work on the policy and a current ticket.
func TestFakePolicyVerifiesUnderItsTestKeys(t *testing.T) {
	fake, clock := newTestFakeComputePolicy(t, "")
	production, err := fake.Verifier(false)
	if err != nil {
		t.Fatal(err)
	}
	staging, err := fake.Verifier(true)
	if err != nil {
		t.Fatal(err)
	}
	policy := fake.NewPolicy(3)
	policy.Search = json.RawMessage(`{"host": "search.example", "ceiling_nano_usd": 15000000}`)
	policy.Services = json.RawMessage(`[{"id": "connect:google", "hosts": ["oauth.example"]}]`)
	policy.Revoked.Profiles = []string{"chutes-tdx-computetest-0"}
	policy.Direct.LimitedUse = []string{"chutes-testmodel", "engy-testmodel"}
	signed := testSignedPolicy(t, fake, policy, FakePolicySignerPolicy)
	verified, err := production.Verify(signed.Document, signed.Signature, clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if verified.Version != 3 || !verified.Current(clock.Now()) || !verified.NotAfter().Equal(time.UnixMilli(policy.NotAfterMs).UTC()) ||
		verified.Signer().Namespace != sidecar.ComputePolicyNamespace || !bytes.Equal(verified.Document(), signed.Document) {
		t.Fatalf("the verified policy: version %d, signer %+v", verified.Version, verified.Signer())
	}
	for _, id := range FakePolicyDisclosureIds {
		disclosure := verified.Disclosure(id)
		if disclosure == nil || disclosure.Version != 1 || disclosure.GraceDays != 14 || disclosure.English() == nil ||
			disclosure.English().Summary != fake.Disclosure(id, 1, clock.Now()).Locales[0].Summary {
			t.Fatalf("disclosure %s: %+v", id, disclosure)
		}
	}
	chutes := verified.Provider("chutes")
	if chutes == nil || chutes.Label != sidecar.ComputeLabelAp || chutes.ProviderModelId("testmodel") != signed.Policy.Providers[0].Models[0].ProviderModelId ||
		chutes.Profile("chutes-tdx-computetest-1") == nil || chutes.Profile("chutes-tdx-computetest-1").GpuCount != 1 {
		t.Fatalf("chutes: %+v", chutes)
	}
	hippius := verified.Provider("hippius")
	if hippius == nil || hippius.Profile("hippius-tdx-computetest-1").Replayed[0].Register != "rtmr3" ||
		hippius.Profile("hippius-snp-computetest-1").Cpu != sidecar.ComputePolicyCpuSnp {
		t.Fatalf("hippius: %+v", hippius)
	}
	engy := verified.DirectProvider("engy")
	if engy == nil || engy.ApiHost != "api.engy.example" || !engy.Model("testmodel").ZeroRetention ||
		verified.DirectProvider("saygm").Model("testmodel").Upstreams[0] != "computetest-upstream" {
		t.Fatalf("the direct line: %+v", engy)
	}
	if !verified.LimitedUse("chutes", "testmodel") || !verified.LimitedUse("engy", "testmodel") || verified.LimitedUse("saygm", "testmodel") ||
		!verified.ProfileRevoked("chutes-tdx-computetest-0") {
		t.Fatal("the limited_use or revoked line")
	}
	// a raw line is written compact, as JSON writes a raw value, and verifies byte for byte as the document holds it
	for _, line := range []struct {
		given    json.RawMessage
		verified json.RawMessage
	}{
		{given: policy.Search, verified: verified.Search},
		{given: policy.Services, verified: verified.Services},
	} {
		compacted := &bytes.Buffer{}
		if err := json.Compact(compacted, line.given); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(line.verified, compacted.Bytes()) || !bytes.Contains(signed.Document, line.verified) {
			t.Fatalf("a raw line verified as %s, not %s", line.verified, compacted.Bytes())
		}
	}
	stagingSigned := testSignedPolicy(t, fake, fake.NewPolicy(3), FakePolicySignerStaging)
	if stagingVerified, err := staging.Verify(stagingSigned.Document, stagingSigned.Signature, clock.Now()); err != nil ||
		stagingVerified.Signer().Namespace != sidecar.ComputePolicyStagingNamespace {
		t.Fatalf("the staging verifier refused the staging key's policy: %v", err)
	}

	batch := newTestFakeBatch(t, fake, &FakeTicketBatchArgs{PolicyVersion: 3})
	for i, ticket := range batch.Tickets {
		taken, err := production.VerifyTicket(ticket.File, clock.Now())
		if err != nil {
			t.Fatalf("ticket %d: %v", i, err)
		}
		if taken.Batch.Id != batch.Id || !taken.Batch.SignedAt.Equal(batch.SignedAt) || !taken.Batch.Expires.Equal(batch.Expires) ||
			taken.PolicyVersion != 3 || !taken.NotBefore.Equal(ticket.NotBefore()) || !taken.NotAfter.Equal(ticket.NotAfter()) ||
			!bytes.Equal(taken.File(), ticket.File) {
			t.Fatalf("ticket %d verified as %+v", i, taken)
		}
	}
	for _, args := range []*FakeTicketBatchArgs{
		{PolicyVersion: 3, Window: 72*time.Hour + time.Second},
		{PolicyVersion: 3, Expires: clock.Now().Add(14*24*time.Hour + time.Second)},
	} {
		past := newTestFakeBatch(t, fake, args)
		if _, err := production.VerifyTicket(past.Tickets[0].File, clock.Now()); !errors.Is(err, sidecar.ErrComputePolicyRefused) {
			t.Fatalf("a ticket past §5.4's bounds (window %s, expiry %s) answered %v", args.Window, args.Expires, err)
		}
	}

	device := testFakeDevice(t, fake, &FakePolicyDeviceArgs{Release: signed})
	if newest := device.Store.Newest(); newest == nil || newest.Version != 3 {
		t.Fatal("the device holds no release copy")
	}
	clock.AdvanceTo(batch.Tickets[0].NotBefore())
	if _, err := device.Gate.OfferTicket(batch.Tickets[0].File); err != nil {
		t.Fatal(err)
	}
	for _, operation := range sidecar.ComputeRemoteOperations {
		if err := device.Gate.RemoteWork(context.Background(), operation); err != nil {
			t.Fatalf("%s: %v", operation, err)
		}
	}
}

// A sitting's batch on the ticket host carries a device fetching from it each day through to the batch's expiry, 14
// days after the sitting: remote work runs a second before the expiry and is refused at it.
func TestFakeBatchCarriesADeviceToItsExpiry(t *testing.T) {
	fake, clock := newTestFakeComputePolicy(t, "")
	ctx := context.Background()
	host := fake.NewTicketHost()
	host.Publish(testSignedPolicy(t, fake, fake.NewPolicy(1), FakePolicySignerPolicy))
	batch := newTestFakeBatch(t, fake, &FakeTicketBatchArgs{PolicyVersion: 1})
	host.Sit(batch)
	device := testFakeDevice(t, fake, &FakePolicyDeviceArgs{Sources: []sidecar.ComputePolicySource{host}})
	for _, ticket := range batch.Tickets {
		clock.AdvanceTo(ticket.NotBefore())
		if err := device.Fetcher.Fetch(ctx); err != nil {
			t.Fatalf("the fetch of %s: %v", ticket.Day(), err)
		}
		if !bytes.Equal(device.Gate.Ticket(), ticket.File) {
			t.Fatalf("%s: the device holds another ticket", ticket.Day())
		}
		if err := device.Gate.RemoteWork(ctx, sidecar.ComputeRemoteSearch); err != nil {
			t.Fatalf("%s: %v", ticket.Day(), err)
		}
	}
	clock.AdvanceTo(batch.Expires.Add(-time.Second))
	if err := device.Gate.RemoteWork(ctx, sidecar.ComputeRemoteEnclaveCreate); err != nil {
		t.Fatalf("a second before the expiry: %v", err)
	}
	clock.Advance(time.Second)
	if err := device.Gate.RemoteWork(ctx, sidecar.ComputeRemoteEnclaveCreate); testLapseReason(err) != sidecar.ComputeRemoteLapseTicketExpired {
		t.Fatalf("at the expiry: %v", err)
	}
}

// With a fixed clock: a revocation at once, its new policy withheld by the serving path with every ticket naming it,
// and the old batch's unreleased tickets deleted at the ticket host. A device fed by the serving path honors the last
// old ticket released until 72 hours after its start and is refused at that instant, never seeing the newer version
// named; a ticket the host still keeps back, leaked early, is refused, kept by no one, and alarms; and once the serving
// path serves the revocation the device takes policy 2 and works under it.
func TestFakeTicketHostWithholdsARevokedPolicy(t *testing.T) {
	fake, clock := newTestFakeComputePolicy(t, "")
	ctx := context.Background()
	host := fake.NewTicketHost()
	host.Publish(testSignedPolicy(t, fake, fake.NewPolicy(1), FakePolicySignerPolicy))
	batch := newTestFakeBatch(t, fake, &FakeTicketBatchArgs{PolicyVersion: 1})
	host.Sit(batch)
	device := testFakeDevice(t, fake, &FakePolicyDeviceArgs{Sources: []sidecar.ComputePolicySource{host}})
	remote := func() error {
		return device.Gate.RemoteWork(ctx, sidecar.ComputeRemoteModelCallTee)
	}

	// the sitting's day: the policy comes with the first fetch, and no ticket has been released
	if err := remote(); testLapseReason(err) != sidecar.ComputeRemoteLapseTicketUnavailable {
		t.Fatalf("before the first ticket: %v", err)
	}
	if newest := device.Store.Newest(); newest == nil || newest.Version != 1 {
		t.Fatal("the device fetched no policy")
	}
	clock.AdvanceTo(batch.Tickets[0].NotBefore())
	if err := remote(); err != nil {
		t.Fatalf("on the first ticket's day: %v", err)
	}
	last := batch.Tickets[1]
	clock.AdvanceTo(last.NotBefore())
	if err := device.Fetcher.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(device.Gate.Ticket(), last.File) {
		t.Fatal("the device did not take the second day's ticket")
	}

	// the revocation, at the second day's noon
	clock.Advance(12 * time.Hour)
	revoked := fake.NewPolicy(2)
	revoked.Revoked.Profiles = []string{"chutes-tdx-computetest-1"}
	host.Publish(testSignedPolicy(t, fake, revoked, FakePolicySignerPolicy))
	host.Withhold(2)
	revocation := newTestFakeBatch(t, fake, &FakeTicketBatchArgs{PolicyVersion: 2, Revocation: true})
	host.Sit(revocation)
	if !revocation.Tickets[0].NotBefore().Equal(clock.Now()) {
		t.Fatal("the revocation's first ticket does not start at its sitting")
	}
	for _, kept := range host.Unreleased() {
		if !slices.Contains(revocation.Tickets, kept) {
			t.Fatalf("the old batch's ticket of %s survived the revocation", kept.Day())
		}
	}
	if released := host.Released(); !slices.Equal(released, []*FakeTicket{batch.Tickets[0], batch.Tickets[1], revocation.Tickets[0]}) {
		t.Fatalf("%d tickets released", len(released))
	}
	if _, _, err := host.Policy(ctx, 2); !errors.Is(err, sidecar.ErrComputePolicySourceAbsent) {
		t.Fatalf("the withheld policy answered %v", err)
	}

	clock.AdvanceTo(last.NotAfter().Add(-time.Second))
	if err := remote(); err != nil {
		t.Fatalf("a second before the last old ticket's 72 hours: %v", err)
	}
	clock.Advance(time.Second)
	if !last.NotAfter().Equal(last.NotBefore().Add(72 * time.Hour)) {
		t.Fatalf("the last old ticket runs %s", last.NotAfter().Sub(last.NotBefore()))
	}
	if err := remote(); testLapseReason(err) != sidecar.ComputeRemoteLapseTicketExpired {
		t.Fatalf("at the last old ticket's 72 hours: %v", err)
	}
	if seen := device.Store.HighestSeen(); seen != 1 {
		t.Fatalf("the withheld revocation reached the device: version %d seen", seen)
	}
	for at := revocation.SignedAt; at.Before(revocation.Expires); at = at.AddDate(0, 0, 1) {
		file, err := host.Ticket(ctx, at)
		if err == nil && slices.ContainsFunc(revocation.Tickets, func(ticket *FakeTicket) bool { return bytes.Equal(ticket.File, file) }) {
			t.Fatalf("the serving path served the withheld revocation's ticket of %s", fakeUtcDay(at))
		}
	}

	early := host.Unreleased()[0]
	if _, err := device.Gate.OfferTicket(early.File); !errors.Is(err, sidecar.ErrComputePolicyTicketEarly) {
		t.Fatalf("a ticket leaked before its start answered %v", err)
	}
	if alarms := device.Alarms(); len(alarms) != 1 || alarms[0].BatchId != revocation.Id || !alarms[0].NotBefore.Equal(early.NotBefore()) {
		t.Fatalf("the early ticket's alarms: %+v", alarms)
	}
	if device.Gate.Ticket() != nil || device.Store.HighestSeen() != 1 {
		t.Fatal("the early ticket was kept or named its version")
	}

	host.Serve(2)
	if err := device.Fetcher.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	if newest := device.Store.Newest(); newest == nil || newest.Version != 2 || !newest.ProfileRevoked("chutes-tdx-computetest-1") {
		t.Fatal("the served revocation did not reach the device")
	}
	if err := remote(); err != nil {
		t.Fatalf("under the revocation's policy: %v", err)
	}
}

// A production build refuses a policy the staging key signed, and one by a compute-policy key the release key did not
// certify, by the bare key or by the release key itself; a staging build refuses all but the staging key's; this build's
// own verifier, which pins no test key, refuses every one the fake signs, its good one included; and a production
// device's store takes none of them.
func TestStagingSignedPolicyIsRefusedByAProductionBuild(t *testing.T) {
	fake, clock := newTestFakeComputePolicy(t, "")
	production, err := fake.Verifier(false)
	if err != nil {
		t.Fatal(err)
	}
	staging, err := fake.Verifier(true)
	if err != nil {
		t.Fatal(err)
	}
	own := sidecar.NewComputePolicyVerifier(fake.Settings().Attest)
	policy := fake.NewPolicy(1)
	signers := []FakePolicySigner{FakePolicySignerPolicy, FakePolicySignerStaging, FakePolicySignerUncertified, FakePolicySignerBare, FakePolicySignerRelease}
	device := testFakeDevice(t, fake, &FakePolicyDeviceArgs{})
	for _, signer := range signers {
		signed := testSignedPolicy(t, fake, policy, signer)
		_, productionErr := production.Verify(signed.Document, signed.Signature, clock.Now())
		_, stagingErr := staging.Verify(signed.Document, signed.Signature, clock.Now())
		_, ownErr := own.Verify(signed.Document, signed.Signature, clock.Now())
		if (productionErr == nil) != (signer == FakePolicySignerPolicy) || (stagingErr == nil) != (signer == FakePolicySignerStaging) {
			t.Fatalf("%s's policy: production %v, staging %v", signer, productionErr, stagingErr)
		}
		for _, refusal := range []error{productionErr, stagingErr, ownErr} {
			if refusal != nil && !errors.Is(refusal, sidecar.ErrComputePolicyRefused) {
				t.Fatalf("%s's policy refused with %v", signer, refusal)
			}
		}
		if !errors.Is(ownErr, sidecar.ErrComputePolicyRefused) {
			t.Fatalf("this build's own verifier took %s's policy: %v", signer, ownErr)
		}
		if signer != FakePolicySignerPolicy {
			if _, err := device.Store.Offer(signed.Document, signed.Signature); !errors.Is(err, sidecar.ErrComputePolicyRefused) {
				t.Fatalf("a production device's store took %s's policy: %v", signer, err)
			}
		}
	}
	if device.Store.Newest() != nil {
		t.Fatal("a production device holds a policy no good key signed")
	}
	stagingBatch := newTestFakeBatch(t, fake, &FakeTicketBatchArgs{PolicyVersion: 1, Signer: FakePolicySignerStaging})
	if _, err := production.VerifyTicket(stagingBatch.Tickets[0].File, clock.Now()); !errors.Is(err, sidecar.ErrComputePolicyRefused) {
		t.Fatalf("a production build took the staging key's ticket: %v", err)
	}
	if _, err := staging.VerifyTicket(stagingBatch.Tickets[0].File, clock.Now()); err != nil {
		t.Fatalf("a staging build refused the staging key's ticket: %v", err)
	}
}
