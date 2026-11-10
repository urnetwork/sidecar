//go:build !sidecar_http && !js

// MAIL-M7-09's ARC inside FS-121's bounds, on the kit's sealer (written from RFC 8617 apart from this code), its
// corpus, FakeMailZone and a fake clock: a chain of 8 sets verifies its newest AMS and every seal; 12 sets are
// incomplete and 51 sets, a gap at instance 3, a repeated instance or a newest cv=fail are fail, each with no
// lookup; a tampered body or an older set fails; a missing key fails; a cut key or a cut header section is
// incomplete; and a message at every bound makes 9 body hashes and 17 signature checks. RFC 6376 §3.4.6's own example
// holds the canonicalization. Every name and key is synthetic.

package sidecar_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The corpus's forwarder, whose key every corpus chain is sealed by.
const testMailArcSealerKeyName = "arc._domainkey.forwarder.example"

// The queries the zone saw for name.
func testMailZoneQueryCountFor(zone *sidecartest.FakeMailZone, name string) int {
	count := 0
	for _, query := range zone.Queries() {
		if query.Name == name {
			count += 1
		}
	}
	return count
}

// RFC 6376 §3.4.6's example, byte for byte: its header relaxed, and its body relaxed and simple.
func TestMailCanonMatchesRfc6376Example(t *testing.T) {
	if got := sidecar.MailCanonHeaderRelaxedForTest([]byte("A: X\r\n")); string(got) != "a:X\r\n" {
		t.Errorf("%q", got)
	}
	if got := sidecar.MailCanonHeaderRelaxedForTest([]byte("B : Y\t\r\n\tZ  \r\n")); string(got) != "b:Y Z\r\n" {
		t.Errorf("%q", got)
	}
	body := []byte(" C \r\nD \t E\r\n\r\n\r\n")
	if got := sidecar.MailCanonBodyForTest(body, true); string(got) != " C\r\nD E\r\n" {
		t.Errorf("relaxed %q", got)
	}
	if got := sidecar.MailCanonBodyForTest(body, false); string(got) != " C \r\nD \t E\r\n" {
		t.Errorf("simple %q", got)
	}
}

// RFC 6376 §3.4.3 and §3.4.4's edges: an empty body is one CRLF simple and nothing relaxed, a last line without CRLF
// gets one, empty lines inside stay and only those at the end go, a bare CR or LF is content, and the hash read in
// chunks is the hash of the canonical form.
func TestMailCanonBodyEdges(t *testing.T) {
	for _, c := range []struct {
		body    string
		relaxed bool
		want    string
	}{
		{body: "", relaxed: false, want: "\r\n"},
		{body: "", relaxed: true, want: ""},
		{body: "\r\n\r\n", relaxed: false, want: "\r\n"},
		{body: "\r\n\r\n", relaxed: true, want: ""},
		{body: "abc", relaxed: false, want: "abc\r\n"},
		{body: "abc", relaxed: true, want: "abc\r\n"},
		{body: "a\r\n\r\nb\r\n\r\n", relaxed: false, want: "a\r\n\r\nb\r\n"},
		{body: "a\r\n \t\r\nb  \r\n  \r\n", relaxed: true, want: "a\r\n\r\nb\r\n"},
		{body: "a\rb\nc\r\n", relaxed: false, want: "a\rb\nc\r\n"},
		{body: "  lead\r\n", relaxed: true, want: " lead\r\n"},
		{body: "end\r", relaxed: true, want: "end\r\r\n"},
	} {
		if got := sidecar.MailCanonBodyForTest([]byte(c.body), c.relaxed); string(got) != c.want {
			t.Errorf("%q relaxed %t: %q", c.body, c.relaxed, got)
		}
	}
	long := bytes.Repeat([]byte("line \t with  spaces\r\n\r\n"), 20000)
	for _, relaxed := range []bool{false, true} {
		hash, err := sidecar.MailCanonBodyHashForTest(long, relaxed)
		want := sha256.Sum256(sidecar.MailCanonBodyForTest(long, relaxed))
		if err != nil || !bytes.Equal(hash, want[:]) {
			t.Errorf("relaxed %t: %x, %v", relaxed, hash, err)
		}
	}
}

// A field's own signature covers it with its b= value gone, folds around it included; another tag starting with b
// stays.
func TestMailFieldWithoutSignature(t *testing.T) {
	field := []byte("ARC-Seal: i=1; a=rsa-sha256; cv=none; bh=x;\r\n b=AAAA\r\n BBBB; d=forwarder.example\r\n")
	got, ok := sidecar.MailFieldWithoutSignatureForTest(field)
	if !ok || string(got) != "ARC-Seal: i=1; a=rsa-sha256; cv=none; bh=x;\r\n b=; d=forwarder.example" {
		t.Errorf("%q %t", got, ok)
	}
	if _, ok := sidecar.MailFieldWithoutSignatureForTest([]byte("ARC-Seal: i=1; bh=x\r\n")); ok {
		t.Error("a field with no b= gave a signature")
	}
}

// Ed25519 verifies over the data's SHA-256 (RFC 8463 §3), and a signature over other data does not.
func TestMailVerifiesEd25519OverTheHash(t *testing.T) {
	key := sidecartest.MailDkimEd25519Key(bytes.Repeat([]byte{0x07}, 32))
	data := []byte("a:X\r\nb:Y Z\r\n")
	digest := sha256.Sum256(data)
	signature := ed25519.Sign(key, digest[:])
	if !sidecar.MailVerifySignatureDataForTest(key.Public(), data, signature) {
		t.Error("a good signature failed")
	}
	if sidecar.MailVerifySignatureDataForTest(key.Public(), append(data, 'x'), signature) {
		t.Error("a signature over other data held")
	}
}

// A chain of 8 sets: its newest AMS and all 8 seals verify, each set listed newest first with its seal's d=, s= and
// key, one key lookup for the one forwarder, and nothing cut.
func TestMailArcVerifiesAnEightSetChain(t *testing.T) {
	world := newMailAuthCheckWorld(t)
	message, err := world.corpus.ArcChain(8, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	outcome := world.check(t, testMailAuthInput(message.Bytes, ""))
	if outcome.Arc.GetCv() != protocol.ArcVerdict_ARC_PASS || len(outcome.Arc.GetSets()) != 8 {
		t.Fatalf("arc %v", outcome.Arc)
	}
	for _, set := range outcome.Arc.GetSets() {
		if set.GetDomain() != "forwarder.example" || set.GetSelector() != "arc" || len(set.GetPublicKey()) == 0 {
			t.Errorf("set %v", set)
		}
	}
	if outcome.ArcBodyHashCount != 1 || outcome.ArcSignatureCheckCount != 9 {
		t.Errorf("%d body hashes, %d signature checks", outcome.ArcBodyHashCount, outcome.ArcSignatureCheckCount)
	}
	if queries := testMailZoneQueryCountFor(world.zone, testMailArcSealerKeyName); queries != 1 {
		t.Errorf("%d key lookups", queries)
	}
	if outcome.Limits != nil || outcome.Counts.GetArcSets() != 8 {
		t.Errorf("limits %v, counts %v", outcome.Limits, outcome.Counts)
	}
	// the corpus's own DKIM signature still passes beside it
	if len(outcome.Dkim) != 1 || outcome.Dkim[0].GetResult() != protocol.DkimVerdict_DKIM_PASS {
		t.Errorf("dkim %v", outcome.Dkim)
	}
}

// No ARC field is cv=none, with no lookup and no limits.
func TestMailArcNoneWithoutFields(t *testing.T) {
	world := newMailAuthCheckWorld(t)
	outcome := world.check(t, testMailAuthInput(testMailAuthMessage("sender.example", "no-arc"), ""))
	if outcome.Arc.GetCv() != protocol.ArcVerdict_ARC_NONE || outcome.Counts.GetArcSets() != 0 || outcome.ArcSignatureCheckCount != 0 {
		t.Errorf("arc %v, counts %v", outcome.Arc, outcome.Counts)
	}
}

// 12 sets are incomplete with no lookup, a count bound in limits; 51 sets and a chain lacking instance 3 are fail with
// no lookup; the highest instance is counted in each.
func TestMailArcStructureDecidesWithNoLookup(t *testing.T) {
	for _, c := range []struct {
		setCount  int
		gapAt     int
		want      protocol.ArcVerdict
		wantLimit bool
		highest   uint32
	}{
		{setCount: 12, want: protocol.ArcVerdict_ARC_INCOMPLETE, wantLimit: true, highest: 12},
		{setCount: 51, want: protocol.ArcVerdict_ARC_FAIL, highest: 51},
		{setCount: 8, gapAt: 3, want: protocol.ArcVerdict_ARC_FAIL, highest: 9},
		{setCount: 50, want: protocol.ArcVerdict_ARC_INCOMPLETE, wantLimit: true, highest: 50},
	} {
		world := newMailAuthCheckWorld(t)
		message, err := world.corpus.ArcChain(c.setCount, c.gapAt, false)
		if err != nil {
			t.Fatal(err)
		}
		outcome := world.check(t, testMailAuthInput(message.Bytes, ""))
		if outcome.Arc.GetCv() != c.want || len(outcome.Arc.GetSets()) != 0 {
			t.Errorf("%s: arc %v", message.Name, outcome.Arc)
		}
		if queries := testMailZoneQueryCountFor(world.zone, testMailArcSealerKeyName); queries != 0 {
			t.Errorf("%s: %d key lookups", message.Name, queries)
		}
		if limited := outcome.Limits.GetReason()&sidecar.MailAuthLimitCount != 0; limited != c.wantLimit {
			t.Errorf("%s: limits %v", message.Name, outcome.Limits)
		}
		if outcome.Counts.GetArcSets() != c.highest || outcome.ArcSignatureCheckCount != 0 || outcome.ArcBodyHashCount != 0 {
			t.Errorf("%s: counts %v, %d checks", message.Name, outcome.Counts, outcome.ArcSignatureCheckCount)
		}
	}
}

// A newest set marked cv=fail, and a set repeated at one instance, are fail with no lookup.
func TestMailArcNewestFailAndRepeatsFail(t *testing.T) {
	world := newMailAuthCheckWorld(t)
	failNewest, err := world.corpus.ArcChain(3, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	chained, err := world.corpus.ArcChain(2, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	// the newest AMS again, so instance 2 has two
	fields := strings.SplitAfter(string(chained.Bytes), "\r\n")
	amsEnd := 0
	for index, line := range fields {
		if strings.HasPrefix(line, "ARC-Message-Signature:") {
			amsEnd = index + 1
			for amsEnd < len(fields) && (strings.HasPrefix(fields[amsEnd], " ") || strings.HasPrefix(fields[amsEnd], "\t")) {
				amsEnd += 1
			}
			repeated := strings.Join(fields[index:amsEnd], "")
			fields = append(fields[:amsEnd], append([]string{repeated}, fields[amsEnd:]...)...)
			break
		}
	}
	repeated := []byte(strings.Join(fields, ""))
	for name, message := range map[string][]byte{"newest-fail": failNewest.Bytes, "repeated": repeated} {
		before := testMailZoneQueryCountFor(world.zone, testMailArcSealerKeyName)
		outcome := world.check(t, testMailAuthInput(message, ""))
		if outcome.Arc.GetCv() != protocol.ArcVerdict_ARC_FAIL {
			t.Errorf("%s: arc %v", name, outcome.Arc)
		}
		if after := testMailZoneQueryCountFor(world.zone, testMailArcSealerKeyName); after != before {
			t.Errorf("%s: %d key lookups", name, after-before)
		}
	}
}

// A body changed after sealing fails the newest AMS's body hash, and a changed older set fails the seals that cover
// it, while the newest AMS, which covers no ARC field, still holds: each is fail, no set listed.
func TestMailArcTamperingFails(t *testing.T) {
	world := newMailAuthCheckWorld(t)
	message, err := world.corpus.ArcChain(2, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	tamperedBody := bytes.Replace(message.Bytes, []byte("A synthetic body"), []byte("A different body"), 1)
	tamperedSet := bytes.Replace(message.Bytes, []byte("mx.forwarder.example; arc=none"), []byte("mx.forwarder.example; arc=pass"), 1)
	if bytes.Equal(tamperedBody, message.Bytes) || bytes.Equal(tamperedSet, message.Bytes) {
		t.Fatal("nothing tampered")
	}
	for name, tampered := range map[string][]byte{"body": tamperedBody, "older set": tamperedSet} {
		outcome := world.check(t, testMailAuthInput(tampered, ""))
		if outcome.Arc.GetCv() != protocol.ArcVerdict_ARC_FAIL || len(outcome.Arc.GetSets()) != 0 {
			t.Errorf("%s: arc %v", name, outcome.Arc)
		}
	}
	// the untouched message still passes
	if outcome := world.check(t, testMailAuthInput(message.Bytes, "")); outcome.Arc.GetCv() != protocol.ArcVerdict_ARC_PASS {
		t.Errorf("untouched: arc %v", outcome.Arc)
	}
}

// A seal key that is not published, or fails to look up, is fail: ARC has no temperror.
func TestMailArcMissingOrFailedKeyFails(t *testing.T) {
	for _, failure := range []sidecartest.FakeMailZoneFailure{sidecartest.FakeMailZoneNxDomain, sidecartest.FakeMailZoneServFail} {
		world := newMailAuthCheckWorld(t)
		message, err := world.corpus.ArcChain(3, 0, false)
		if err != nil {
			t.Fatal(err)
		}
		world.zone.Fail(testMailArcSealerKeyName, dnsmessage.TypeTXT, failure)
		outcome := world.check(t, testMailAuthInput(message.Bytes, ""))
		if outcome.Arc.GetCv() != protocol.ArcVerdict_ARC_FAIL || outcome.Limits != nil {
			t.Errorf("%s: arc %v, limits %v", failure, outcome.Arc, outcome.Limits)
		}
	}
}

// A seal key the 30 s cut is incomplete with the deadline bit, and one the query count refused is incomplete with
// the count bit; neither is fail.
func TestMailArcCutKeyIsIncomplete(t *testing.T) {
	world := newMailAuthCheckWorld(t)
	world.settings.QueryTimeout = time.Minute
	message, err := world.corpus.ArcChain(2, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	world.zone.SetDelay(testMailArcSealerKeyName, 40*time.Second)
	done := make(chan *sidecar.MailAuthOutcome, 1)
	go func() {
		outcome, err := world.checker.Check(context.Background(), testMailAuthInput(message.Bytes, ""))
		if err != nil {
			t.Error(err)
		}
		done <- outcome
	}()
	awaitMailZoneDelays(t, world.clock, 1, 40*time.Second)
	world.clock.Advance(30 * time.Second)
	outcome := <-done
	if outcome.Arc.GetCv() != protocol.ArcVerdict_ARC_INCOMPLETE || outcome.Limits.GetReason()&sidecar.MailAuthLimitDeadline == 0 {
		t.Errorf("arc %v, limits %v", outcome.Arc, outcome.Limits)
	}
	world.clock.Advance(20 * time.Second)

	// the count spent before ARC's key, the last in the budget's order: DMARC's record, the DKIM key and the PTR take
	// all three, a null reverse path with an address literal for EHLO leaving SPF nothing to ask
	world = newMailAuthCheckWorld(t)
	world.settings.QueryMaxCount = 3
	message, err = world.corpus.ArcChain(2, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	input := testMailAuthInput(message.Bytes, "")
	input.EhloName = "[192.0.2.25]"
	outcome = world.check(t, input)
	if outcome.Arc.GetCv() != protocol.ArcVerdict_ARC_INCOMPLETE || outcome.Limits.GetReason()&sidecar.MailAuthLimitCount == 0 {
		t.Errorf("arc %v, limits %v", outcome.Arc, outcome.Limits)
	}
}

// A header section cut at 256 KiB leaves a chain incomplete with no lookup, since a field past the cut may be a
// newer set, and leaves a message showing no ARC field incomplete too, not none; a seal marked cv=fail within the
// view still fails it.
func TestMailArcUnderACutHeaderIsIncomplete(t *testing.T) {
	world := newMailAuthCheckWorld(t)
	filler := strings.Repeat("X-Filler: "+strings.Repeat("f", 980)+"\r\n", 300)
	plain := testMailAuthMessage("sender.example", "no-arc-in-view")
	plainHeader, plainBody, _ := bytes.Cut(plain, []byte("\r\n\r\n"))
	plainCut := append(append(append([]byte{}, plainHeader...), []byte("\r\n"+filler)...), append([]byte("\r\n"), plainBody...)...)
	if outcome := world.check(t, testMailAuthInput(plainCut, "")); !outcome.View.Cut || outcome.Arc.GetCv() != protocol.ArcVerdict_ARC_INCOMPLETE {
		t.Errorf("no ARC in a cut view: arc %v", outcome.Arc)
	}
	for _, failNewest := range []bool{false, true} {
		message, err := world.corpus.ArcChain(2, 0, failNewest)
		if err != nil {
			t.Fatal(err)
		}
		// the filler below the ARC sets, so they stay in view and the cut falls past them
		header, body, _ := bytes.Cut(message.Bytes, []byte("\r\n\r\n"))
		cut := append(append(append([]byte{}, header...), []byte("\r\n"+filler)...), append([]byte("\r\n"), body...)...)
		before := testMailZoneQueryCountFor(world.zone, testMailArcSealerKeyName)
		outcome := world.check(t, testMailAuthInput(cut, ""))
		want := protocol.ArcVerdict_ARC_INCOMPLETE
		if failNewest {
			want = protocol.ArcVerdict_ARC_FAIL
		}
		if !outcome.View.Cut || outcome.Arc.GetCv() != want {
			t.Errorf("fail newest %t: cut %t, arc %v", failNewest, outcome.View.Cut, outcome.Arc)
		}
		if after := testMailZoneQueryCountFor(world.zone, testMailArcSealerKeyName); after != before {
			t.Errorf("fail newest %t: %d key lookups", failNewest, after-before)
		}
	}
}

// Seals count = sealers: a chain whose 8 sets are each sealed by a forwarder of its own, published apart.
func testMailArcDistinctChain(t *testing.T, zone *sidecartest.FakeMailZone, message []byte, setCount int, signTime time.Time) []byte {
	t.Helper()
	for instance := 1; instance <= setCount; instance += 1 {
		sealer := &sidecartest.MailArcSealer{
			Domain:     fmt.Sprintf("forwarder%d.example", instance),
			Selector:   "arc",
			Key:        sidecartest.MailDkimRsaKey(1024),
			AuthServId: fmt.Sprintf("mx.forwarder%d.example", instance),
			SignTime:   signTime,
		}
		zone.AddTxt(sidecartest.MailDkimKeyName(sealer.Selector, sealer.Domain), sidecartest.MailDkimKeyRecord(sealer.Key))
		cv := "pass"
		if instance == 1 {
			cv = "none"
		}
		var err error
		if message, err = sealer.Seal(message, instance, cv); err != nil {
			t.Fatal(err)
		}
	}
	return message
}

// FS-121's per-message bounds at every one of them: 64 maximal DKIM signatures, all valid, and 8 ARC sets each by
// its own forwarder: 8 DKIM keys and 8 seal keys looked up, 9 body hashes (8 DKIM, the newest AMS) and 17 signature
// checks (8 DKIM, the AMS and 8 seals), at most 64 queries, at most 8 in flight, and well inside 30 s.
func TestMailAuthMessageCostsAtMostNineBodyHashesAndSeventeenChecks(t *testing.T) {
	world := newMailAuthCheckWorld(t)
	maximal, err := world.corpus.MaximalSignatures(64)
	if err != nil {
		t.Fatal(err)
	}
	message := testMailArcDistinctChain(t, world.zone, maximal.Bytes, 8, world.clock.Now())
	start := world.clock.Now()
	outcome := world.check(t, testMailAuthInput(message, "sender.example"))
	if outcome.Arc.GetCv() != protocol.ArcVerdict_ARC_PASS || len(outcome.Arc.GetSets()) != 8 {
		t.Fatalf("arc %v", outcome.Arc)
	}
	for index, set := range outcome.Arc.GetSets() {
		if want := fmt.Sprintf("forwarder%d.example", 8-index); set.GetDomain() != want {
			t.Errorf("set %d: %s", index, set.GetDomain())
		}
	}
	if bodyHashes := outcome.DkimVerifiedCount + outcome.ArcBodyHashCount; bodyHashes != 9 {
		t.Errorf("%d body hashes", bodyHashes)
	}
	if checks := outcome.DkimVerifiedCount + outcome.ArcSignatureCheckCount; checks != 17 {
		t.Errorf("%d signature checks", checks)
	}
	queries := world.zone.Queries()
	if 64 < len(queries) || 8 < world.zone.MaxInFlight() || 30*time.Second <= world.clock.Now().Sub(start) {
		t.Errorf("%d queries, %d in flight", len(queries), world.zone.MaxInFlight())
	}
	sealKeys := 0
	for _, query := range queries {
		if strings.HasPrefix(query.Name, "arc._domainkey.forwarder") {
			sealKeys += 1
		}
	}
	if sealKeys != 8 || outcome.Counts.GetDkimSeen() != 64 || outcome.Counts.GetDkimChecked() != 8 || outcome.Counts.GetArcSets() != 8 {
		t.Errorf("%d seal keys, counts %v", sealKeys, outcome.Counts)
	}
	// its evidence, every identifier at its bound, within 8,192 bytes, limits counting what the checks saw
	evidence := testMailEvidenceOf(t, outcome, message)
	if size := proto.Size(evidence); sidecar.MailAuthEvidenceMaxByteCount < size {
		t.Errorf("%d bytes of evidence", size)
	}
	if limits := evidence.GetLimits(); limits.GetReason()&sidecar.MailAuthLimitCount == 0 || limits.GetDkimSeen() != 64 ||
		limits.GetDkimChecked() != 8 || limits.GetArcSets() != 8 || limits.GetDnsQueries() != uint32(len(queries)) ||
		int(limits.GetDropped()) != 16-len(evidence.GetDkim())-len(evidence.GetArc().GetSets()) {
		t.Errorf("limits %v, %d dkim and %d arc entries kept", limits, len(evidence.GetDkim()), len(evidence.GetArc().GetSets()))
	}
}
