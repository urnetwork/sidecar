//go:build !sidecar_http && !js

// MAIL-M7-08's DKIM inside FS-121's bounds, on the kit's corpus: of 64 signatures at most 8 keys are looked up; an
// aligned valid signature after 3 invalid ones passes DKIM and DMARC; a spoofed From with 9 aligned bogus signatures
// is a DMARC fail, never a pass; 8 selectors answering at 4.9 s all verify inside 30 s; rsa-sha1 and a 9,000-bit key
// are permerror; and a cut aligned check gives DMARC temperror where a cut unaligned one does not. Every name and key
// is synthetic.

package sidecar_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The queries the zone saw for a DKIM key.
func testMailKeyQueryCount(zone *sidecartest.FakeMailZone) int {
	count := 0
	for _, query := range zone.Queries() {
		if strings.Contains(query.Name, "._domainkey.") {
			count += 1
		}
	}
	return count
}

// 64 signatures with distinct maximal d= and s=: 8 are selected, bottom of the header up, and only their keys are
// looked up; each passes; limits counts 64 seen and 8 checked, with the count bit.
func TestMailAuthLooksUpAtMost8KeysOf64(t *testing.T) {
	world := newMailAuthCheckWorld(t)
	message, err := world.corpus.MaximalSignatures(64)
	if err != nil {
		t.Fatal(err)
	}
	outcome := world.check(t, testMailAuthInput(message.Bytes, "sender.example"))
	if queries := testMailKeyQueryCount(world.zone); queries != 8 {
		t.Errorf("%d key lookups", queries)
	}
	if len(outcome.Dkim) != 8 || outcome.DkimVerifiedCount != 8 {
		t.Fatalf("%d entries, %d verified", len(outcome.Dkim), outcome.DkimVerifiedCount)
	}
	for index, result := range outcome.Dkim {
		// the corpus lists signatures top first; the selection runs from the bottom up
		want := message.Signatures[len(message.Signatures)-1-index]
		if result.GetResult() != protocol.DkimVerdict_DKIM_PASS || result.GetDomain() != want.Domain || result.GetSelector() != want.Selector {
			t.Errorf("entry %d: %v", index, result)
		}
	}
	limits := outcome.Limits
	if limits.GetDkimSeen() != 64 || limits.GetDkimChecked() != 8 || limits.GetReason() != sidecar.MailAuthLimitCount {
		t.Errorf("limits %v", limits)
	}
}

// An aligned signature that verifies, after 3 aligned ones that do not: the selection takes all four, DKIM passes
// on the valid one, and DMARC passes on it.
func TestMailAuthAlignedPassAfterThreeInvalid(t *testing.T) {
	world := newMailAuthCheckWorld(t)
	message, err := world.corpus.AlignedAfterInvalid(3)
	if err != nil {
		t.Fatal(err)
	}
	outcome := world.check(t, testMailAuthInput(message.Bytes, ""))
	verdicts := []protocol.DkimVerdict{}
	for _, result := range outcome.Dkim {
		verdicts = append(verdicts, result.GetResult())
	}
	want := []protocol.DkimVerdict{protocol.DkimVerdict_DKIM_FAIL, protocol.DkimVerdict_DKIM_FAIL, protocol.DkimVerdict_DKIM_FAIL, protocol.DkimVerdict_DKIM_PASS}
	if len(verdicts) != len(want) {
		t.Fatalf("verdicts %v", verdicts)
	}
	for index := range want {
		if verdicts[index] != want[index] {
			t.Fatalf("verdicts %v", verdicts)
		}
	}
	if outcome.Dmarc.GetResult() != protocol.DmarcVerdict_DMARC_PASS || outcome.Dmarc.GetAlignment() != sidecar.MailDmarcAlignedDkim {
		t.Errorf("dmarc %v", outcome.Dmarc)
	}
}

// A From domain publishing p=reject, with 9 aligned signatures none of which verifies: 8 are checked and fail, one
// is only counted, and DMARC fails, never passes.
func TestMailAuthSpoofedFromNeverPasses(t *testing.T) {
	world := newMailAuthCheckWorld(t)
	message, err := world.corpus.SpoofedFrom(9)
	if err != nil {
		t.Fatal(err)
	}
	outcome := world.check(t, testMailAuthInput(message.Bytes, ""))
	if len(outcome.Dkim) != 8 {
		t.Fatalf("%d entries", len(outcome.Dkim))
	}
	for _, result := range outcome.Dkim {
		if result.GetResult() != protocol.DkimVerdict_DKIM_FAIL {
			t.Errorf("an entry %v", result)
		}
	}
	if outcome.Dmarc.GetResult() != protocol.DmarcVerdict_DMARC_FAIL || outcome.Dmarc.GetP() != "reject" {
		t.Errorf("dmarc %v", outcome.Dmarc)
	}
	if outcome.Limits.GetReason()&sidecar.MailAuthLimitCount == 0 || outcome.Limits.GetDkimSeen() != 9 {
		t.Errorf("limits %v", outcome.Limits)
	}
}

// 8 selectors each answering at 4.9 s: the keys are fetched at once, so all 8 verify 4.9 s in, well inside the 30 s,
// where looking them up one at a time would take 39.2 s. Everything else the message needs is already in the stub.
func TestMailAuthEightSlowSelectorsVerifyWithin30s(t *testing.T) {
	world := newMailAuthCheckWorld(t)
	world.publishSender("sender.example")
	// a first message warms the stub with everything but the keys
	world.check(t, testMailAuthInput(testMailAuthMessage("sender.example", "warm"), "sender.example"))
	message, err := world.corpus.MaximalSignatures(8)
	if err != nil {
		t.Fatal(err)
	}
	for _, signature := range message.Signatures {
		world.zone.SetDelay(sidecartest.MailDkimKeyName(signature.Selector, signature.Domain), 4900*time.Millisecond)
	}
	start := world.clock.Now()
	done := make(chan *sidecar.MailAuthOutcome, 1)
	go func() {
		outcome, err := world.checker.Check(context.Background(), testMailAuthInput(message.Bytes, "sender.example"))
		if err != nil {
			t.Error(err)
		}
		done <- outcome
	}()
	awaitMailZoneDelays(t, world.clock, 8, 4900*time.Millisecond)
	world.clock.Advance(4900 * time.Millisecond)
	outcome := <-done
	if elapsed := world.clock.Now().Sub(start); 30*time.Second <= elapsed {
		t.Errorf("%s", elapsed)
	}
	for _, result := range outcome.Dkim {
		if result.GetResult() != protocol.DkimVerdict_DKIM_PASS {
			t.Errorf("an entry %v", result)
		}
	}
	if len(outcome.Dkim) != 8 || outcome.Limits.GetReason()&sidecar.MailAuthLimitDeadline != 0 {
		t.Errorf("%d entries, limits %v", len(outcome.Dkim), outcome.Limits)
	}
}

// rsa-sha1 is permerror with no lookup, since mox's algHash accepts it, and a 9,000-bit key is permerror once
// fetched, never verified under, since mox sets no ceiling.
func TestMailAuthRefusesRsaSha1AndKeysPast8192Bits(t *testing.T) {
	world := newMailAuthCheckWorld(t)
	sha1Signer, err := sidecartest.NewMailDkimSigner("sender.example", "old", sidecartest.MailDkimRsaSha1, sidecartest.MailDkimRsaKey(1024))
	if err != nil {
		t.Fatal(err)
	}
	world.zone.AddTxt(sidecartest.MailDkimKeyName("old", "sender.example"), sha1Signer.KeyRecord())
	bigSigner, err := sidecartest.NewMailDkimSigner("sender.example", "big", sidecartest.MailDkimRsaSha256, sidecartest.MailDkimRsaKey(9000))
	if err != nil {
		t.Fatal(err)
	}
	world.zone.AddTxt(sidecartest.MailDkimKeyName("big", "sender.example"), bigSigner.KeyRecord())
	message, err := sha1Signer.Sign(testMailAuthMessage("sender.example", "weak"))
	if err != nil {
		t.Fatal(err)
	}
	if message, err = bigSigner.Sign(message); err != nil {
		t.Fatal(err)
	}
	outcome := world.check(t, testMailAuthInput(message, ""))
	if len(outcome.Dkim) != 2 || outcome.DkimVerifiedCount != 0 {
		t.Fatalf("%d entries, %d verified", len(outcome.Dkim), outcome.DkimVerifiedCount)
	}
	for _, result := range outcome.Dkim {
		if result.GetResult() != protocol.DkimVerdict_DKIM_PERMERROR {
			t.Errorf("%s: %v", result.GetSelector(), result.GetResult())
		}
	}
	for _, query := range world.zone.Queries() {
		if strings.HasPrefix(query.Name, "old._domainkey.") {
			t.Error("rsa-sha1's key was looked up")
		}
	}
}

// A bound that cuts the only aligned signature's lookup leaves DMARC temperror, since nothing aligned passed; one
// that cuts an unaligned signature's lookup leaves an aligned pass a DMARC pass.
func TestMailAuthCutAlignedCheckIsTemperror(t *testing.T) {
	// the aligned key past the 30 s deadline
	world := newMailAuthCheckWorld(t)
	world.settings.QueryTimeout = time.Minute
	world.zone.AddTxt("_dmarc.sender.example", "v=DMARC1; p=quarantine")
	aligned, err := sidecartest.NewMailDkimSigner("sender.example", "slow", sidecartest.MailDkimRsaSha256, sidecartest.MailDkimRsaKey(1024))
	if err != nil {
		t.Fatal(err)
	}
	world.zone.AddTxt(sidecartest.MailDkimKeyName("slow", "sender.example"), aligned.KeyRecord())
	world.zone.SetDelay(sidecartest.MailDkimKeyName("slow", "sender.example"), 40*time.Second)
	message, err := aligned.Sign(testMailAuthMessage("sender.example", "cut-aligned"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *sidecar.MailAuthOutcome, 1)
	go func() {
		outcome, err := world.checker.Check(context.Background(), testMailAuthInput(message, ""))
		if err != nil {
			t.Error(err)
		}
		done <- outcome
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := world.zone.AwaitInFlight(ctx, 1); err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(30 * time.Second)
	outcome := <-done
	if len(outcome.Dkim) != 1 || outcome.Dkim[0].GetResult() != protocol.DkimVerdict_DKIM_INCOMPLETE {
		t.Errorf("dkim %v", outcome.Dkim)
	}
	if outcome.Dmarc.GetResult() != protocol.DmarcVerdict_DMARC_TEMPERROR || outcome.Limits.GetReason()&sidecar.MailAuthLimitDeadline == 0 {
		t.Errorf("dmarc %v, limits %v", outcome.Dmarc, outcome.Limits)
	}
	world.clock.Advance(20 * time.Second)

	// an unaligned key cut by the query count, beside an aligned pass
	world = newMailAuthCheckWorld(t)
	world.settings.QueryMaxCount = 3
	world.zone.AddTxt("_dmarc.sender.example", "v=DMARC1; p=quarantine")
	good, err := sidecartest.NewMailDkimSigner("sender.example", "good", sidecartest.MailDkimRsaSha256, sidecartest.MailDkimRsaKey(1024))
	if err != nil {
		t.Fatal(err)
	}
	world.zone.AddTxt(sidecartest.MailDkimKeyName("good", "sender.example"), good.KeyRecord())
	other, err := sidecartest.NewMailDkimSigner("other.example", "s1", sidecartest.MailDkimRsaSha256, sidecartest.MailDkimRsaKey(1024))
	if err != nil {
		t.Fatal(err)
	}
	world.zone.AddTxt(sidecartest.MailDkimKeyName("s1", "other.example"), other.KeyRecord())
	message, err = good.Sign(testMailAuthMessage("sender.example", "cut-unaligned"))
	if err != nil {
		t.Fatal(err)
	}
	if message, err = other.Sign(message); err != nil {
		t.Fatal(err)
	}
	// a null reverse path and an EHLO that is an address literal leave SPF nothing to look up
	input := testMailAuthInput(message, "")
	input.EhloName = "[192.0.2.25]"
	input.SenderIp = netip.MustParseAddr(testMailAuthSender)
	outcome = world.check(t, input)
	verdicts := map[string]protocol.DkimVerdict{}
	for _, result := range outcome.Dkim {
		verdicts[result.GetDomain()] = result.GetResult()
	}
	if verdicts["sender.example"] != protocol.DkimVerdict_DKIM_PASS || verdicts["other.example"] != protocol.DkimVerdict_DKIM_INCOMPLETE {
		t.Errorf("dkim %v", verdicts)
	}
	if outcome.Dmarc.GetResult() != protocol.DmarcVerdict_DMARC_PASS || outcome.Limits.GetReason()&sidecar.MailAuthLimitCount == 0 {
		t.Errorf("dmarc %v, limits %v", outcome.Dmarc, outcome.Limits)
	}
}
