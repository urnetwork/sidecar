//go:build !sidecar_http && !js

// MAIL-M7-09's evidence builder (§15.5's evidence row, FS-121): a message's evidence names its hash, time and
// receiver and carries every result; maximal identifiers stay within 8,192 bytes, dropping keys and records first, the
// last selected first, then whole entries from the end of the selection order, as a reference written apart from the
// builder drops them, each entry counted in limits and any drop setting its count bit; limits stays unset where no
// bound cut; a string that is not UTF-8 is left out; and FuzzMailAuth (§22.6's go-message and mox target) holds the
// checks and the builder to their bounds on any bytes. Every name, key and address is synthetic.

package sidecar_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The receiver every test's evidence names.
var testMailEvidenceReceiver = sidecar.Id{0x01, 0x92, 0x5a, 0x7e, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a}

// A time the tests seal as received.
const testMailEvidenceReceiveMillis = 1793923200000

// The evidence a check of message builds.
func testMailEvidenceOf(t testing.TB, outcome *sidecar.MailAuthOutcome, message []byte) *protocol.MailAuthEvidence {
	t.Helper()
	hash := sha256.Sum256(message)
	evidence, err := sidecar.NewMailEvidenceBuilder(testMailEvidenceReceiver).Build(&sidecar.MailEvidenceInput{
		MessageSha256:     hash[:],
		ReceiveTimeMillis: testMailEvidenceReceiveMillis,
		Outcome:           outcome,
	})
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

// A message every check passes: its evidence names the hash of the bytes as received, the time and the receiver,
// carries every result as the checks found them, ARC's none included, has no limits, fits and marshals, and the
// outcome it came from is unchanged.
func TestMailEvidenceCarriesTheChecks(t *testing.T) {
	world := newMailAuthCheckWorld(t)
	world.publishSender("sender.example")
	signer, err := sidecartest.NewMailDkimSigner("sender.example", "s1", sidecartest.MailDkimRsaSha256, sidecartest.MailDkimRsaKey(2048))
	if err != nil {
		t.Fatal(err)
	}
	world.zone.AddTxt(sidecartest.MailDkimKeyName("s1", "sender.example"), signer.KeyRecord())
	message, err := signer.Sign(testMailAuthMessage("sender.example", "evidence"))
	if err != nil {
		t.Fatal(err)
	}
	outcome := world.check(t, testMailAuthInput(message, "sender.example"))
	spfBefore, dkimBefore := proto.CloneOf(outcome.Spf), proto.CloneOf(outcome.Dkim[0])
	evidence := testMailEvidenceOf(t, outcome, message)
	hash := sha256.Sum256(message)
	if evidence.GetVersion() != 1 || !bytes.Equal(evidence.GetMessageSha256(), hash[:]) || evidence.GetReceiveTimeMillis() != testMailEvidenceReceiveMillis ||
		!bytes.Equal(evidence.GetReceiverSidecarId(), testMailEvidenceReceiver.Bytes()) {
		t.Errorf("header %v", evidence)
	}
	if !proto.Equal(evidence.GetSpf(), outcome.Spf) || len(evidence.GetDkim()) != 1 || !proto.Equal(evidence.GetDkim()[0], outcome.Dkim[0]) ||
		!proto.Equal(evidence.GetDmarc(), outcome.Dmarc) || evidence.GetPtrName() != "mail.sender.example" || !evidence.GetSniTlsaLive() {
		t.Errorf("results %v", evidence)
	}
	if evidence.GetArc().GetCv() != protocol.ArcVerdict_ARC_NONE || evidence.GetLimits() != nil || evidence.GetStrictChain() {
		t.Errorf("arc %v, limits %v", evidence.GetArc(), evidence.GetLimits())
	}
	if !proto.Equal(outcome.Spf, spfBefore) || !proto.Equal(outcome.Dkim[0], dkimBefore) {
		t.Error("building changed the outcome")
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(evidence)
	if err != nil || sidecar.MailAuthEvidenceMaxByteCount < len(encoded) {
		t.Errorf("%d bytes, %v", len(encoded), err)
	}
}

// No checks or no hash builds nothing, so the receiver deposits without evidence, which only weakens a label.
func TestMailEvidenceRefusesWithoutHashOrChecks(t *testing.T) {
	builder := sidecar.NewMailEvidenceBuilder(testMailEvidenceReceiver)
	for _, input := range []*sidecar.MailEvidenceInput{
		nil,
		{MessageSha256: make([]byte, 32)},
		{Outcome: &sidecar.MailAuthOutcome{}},
		{MessageSha256: make([]byte, 31), Outcome: &sidecar.MailAuthOutcome{}},
	} {
		if _, err := builder.Build(input); !errors.Is(err, sidecar.ErrMailEvidenceInvalid) {
			t.Errorf("%v: %v", input, err)
		}
	}
}

// A name of byteCount bytes, synthetic.
func testMailEvidenceName(tag string, byteCount int) string {
	return sidecartest.MailCorpusName(tag, byteCount, "example")
}

// An outcome at every identifier's bound: 8 DKIM entries, the first alignedCount aligned, and 8 ARC sets, each with a
// 253-byte d= and s= and an 8,192-bit key's 1,062 bytes, an SPF record of 4 KiB, a 253-byte SPF domain and PTR name.
func testMailEvidenceMaximalOutcome(alignedCount int) *sidecar.MailAuthOutcome {
	key := bytes.Repeat([]byte{0x30}, 1062)
	outcome := &sidecar.MailAuthOutcome{
		Spf: &protocol.SpfResult{
			Result:  protocol.SpfVerdict_SPF_PASS,
			Domain:  testMailEvidenceName("spf", 253),
			Ip:      bytes.Repeat([]byte{0x20}, 16),
			Records: []string{"v=spf1 " + strings.Repeat("ip4:192.0.2.0/24 ", 240) + "-all"},
		},
		Dmarc:            &protocol.DmarcResult{P: "quarantine", Adkim: "r", Aspf: "r", Alignment: 3, Result: protocol.DmarcVerdict_DMARC_PASS},
		PtrName:          testMailEvidenceName("ptr", 253),
		SniTlsaLive:      true,
		Arc:              &protocol.ArcResult{Cv: protocol.ArcVerdict_ARC_PASS},
		Counts:           &protocol.AuthLimits{DkimSeen: 64, DkimChecked: 8, ArcSets: 8, DnsQueries: 22},
		DkimAlignedCount: alignedCount,
	}
	for index := range 8 {
		outcome.Dkim = append(outcome.Dkim, &protocol.DkimResult{
			Domain:    testMailEvidenceName("d"+string(rune('a'+index)), 253),
			Selector:  testMailEvidenceName("s"+string(rune('a'+index)), 253),
			Result:    protocol.DkimVerdict_DKIM_PASS,
			PublicKey: key,
		})
		outcome.Arc.Sets = append(outcome.Arc.Sets, &protocol.ArcSet{
			Domain:    testMailEvidenceName("a"+string(rune('a'+index)), 253),
			Selector:  testMailEvidenceName("z"+string(rune('a'+index)), 253),
			PublicKey: key,
		})
	}
	return outcome
}

// §15.5's drops as a reference, written apart from the builder: the outcome's evidence with drops applied one at a
// time in the evidence row's order until it fits, so the test can hold the builder to the same result and show that
// one drop fewer would not fit.
func testMailEvidenceReference(t *testing.T, outcome *sidecar.MailAuthOutcome, message []byte, dropCount int) *protocol.MailAuthEvidence {
	t.Helper()
	hash := sha256.Sum256(message)
	evidence := &protocol.MailAuthEvidence{
		Version:           1,
		MessageSha256:     hash[:],
		ReceiveTimeMillis: testMailEvidenceReceiveMillis,
		ReceiverSidecarId: testMailEvidenceReceiver.Bytes(),
		Spf:               proto.CloneOf(outcome.Spf),
		Dmarc:             proto.CloneOf(outcome.Dmarc),
		PtrName:           outcome.PtrName,
		SniTlsaLive:       outcome.SniTlsaLive,
		Arc:               proto.CloneOf(outcome.Arc),
	}
	for _, entry := range outcome.Dkim {
		evidence.Dkim = append(evidence.Dkim, proto.CloneOf(entry))
	}
	steps := []func(){}
	for index := len(evidence.Arc.Sets) - 1; 0 <= index; index -= 1 {
		steps = append(steps, func() { evidence.Arc.Sets[index].PublicKey = nil })
	}
	for index := len(evidence.Dkim) - 1; outcome.DkimAlignedCount <= index; index -= 1 {
		steps = append(steps, func() { evidence.Dkim[index].PublicKey = nil })
	}
	steps = append(steps, func() { evidence.Spf.Records = nil })
	for index := outcome.DkimAlignedCount - 1; 0 <= index; index -= 1 {
		steps = append(steps, func() { evidence.Dkim[index].PublicKey = nil })
	}
	for range evidence.Arc.Sets {
		steps = append(steps, func() {
			evidence.Arc.Sets = evidence.Arc.Sets[:len(evidence.Arc.Sets)-1]
			evidence.Limits.Dropped += 1
		})
	}
	for range evidence.Dkim {
		steps = append(steps, func() {
			evidence.Dkim = evidence.Dkim[:len(evidence.Dkim)-1]
			evidence.Limits.Dropped += 1
		})
	}
	if 0 < dropCount {
		evidence.Limits = proto.CloneOf(outcome.Counts)
		evidence.Limits.Reason |= sidecar.MailAuthLimitCount
	}
	for _, step := range steps[:dropCount] {
		step()
	}
	return evidence
}

// The reference's first evidence that fits, and how many drops it took.
func testMailEvidenceReferenceFit(t *testing.T, outcome *sidecar.MailAuthOutcome, message []byte) (*protocol.MailAuthEvidence, int) {
	t.Helper()
	for dropCount := 0; ; dropCount += 1 {
		evidence := testMailEvidenceReference(t, outcome, message, dropCount)
		if proto.Size(evidence) <= sidecar.MailAuthEvidenceMaxByteCount {
			return evidence, dropCount
		}
	}
}

// Maximal identifiers: the evidence fits, every key and record dropped before any entry, the ARC sets from the oldest
// and the DKIM entries from the last selected, each counted in limits.dropped with the count bit set and the checks'
// counts kept; it is exactly the reference's after as many drops, and one drop fewer would not fit.
func TestMailEvidenceHoldsMaximalIdentifiersWithin8192(t *testing.T) {
	for _, alignedCount := range []int{0, 3, 8} {
		message := []byte("synthetic message bytes")
		outcome := testMailEvidenceMaximalOutcome(alignedCount)
		evidence := testMailEvidenceOf(t, outcome, message)
		if size := proto.Size(evidence); sidecar.MailAuthEvidenceMaxByteCount < size {
			t.Fatalf("aligned %d: %d bytes", alignedCount, size)
		}
		limits := evidence.GetLimits()
		if limits.GetReason() != sidecar.MailAuthLimitCount || limits.GetDkimSeen() != 64 || limits.GetDkimChecked() != 8 || limits.GetArcSets() != 8 || limits.GetDnsQueries() != 22 {
			t.Errorf("aligned %d: limits %v", alignedCount, limits)
		}
		for _, entry := range evidence.GetDkim() {
			if len(entry.GetPublicKey()) != 0 {
				t.Errorf("aligned %d: an entry kept its key past a dropped entry", alignedCount)
			}
		}
		dropped := int(limits.GetDropped())
		if dropped != 16-len(evidence.GetDkim())-len(evidence.GetArc().GetSets()) || dropped == 0 {
			t.Errorf("aligned %d: %d dropped, %d dkim and %d arc kept", alignedCount, dropped, len(evidence.GetDkim()), len(evidence.GetArc().GetSets()))
		}
		// whole entries from the end of the selection order: ARC's first, then DKIM's from the last selected
		if 0 < len(evidence.GetDkim()) && len(evidence.GetDkim()) < 8 && len(evidence.GetArc().GetSets()) != 0 {
			t.Errorf("aligned %d: a DKIM entry went before every ARC set", alignedCount)
		}
		for index, entry := range evidence.GetDkim() {
			if entry.GetDomain() != outcome.Dkim[index].GetDomain() {
				t.Errorf("aligned %d: entry %d is %s", alignedCount, index, entry.GetDomain())
			}
		}
		if len(evidence.GetSpf().GetRecords()) != 0 {
			t.Errorf("aligned %d: SPF's record kept past a dropped entry", alignedCount)
		}
		// the reference's first evidence that fits, after every key, the record and as many entries
		reference, dropCount := testMailEvidenceReferenceFit(t, outcome, message)
		if !proto.Equal(evidence, reference) || dropCount != 8+8+1+dropped {
			t.Errorf("aligned %d: the builder parts from the reference's %d drops", alignedCount, dropCount)
		}
		if outcome.Dkim[7].GetPublicKey() == nil || outcome.Arc.Sets[7].GetPublicKey() == nil {
			t.Errorf("aligned %d: building changed the outcome", alignedCount)
		}
	}
}

// Keys alone past the bound: the unaligned signatures' keys go from the last selected, ARC's having none, then the
// SPF record, and the aligned keys and every entry stay, limits saying a size bound cut it with nothing dropped.
func TestMailEvidenceDropsKeysBeforeEntries(t *testing.T) {
	key := bytes.Repeat([]byte{0x30}, 1062)
	outcome := &sidecar.MailAuthOutcome{
		Spf:              &protocol.SpfResult{Result: protocol.SpfVerdict_SPF_NONE, Records: []string{strings.Repeat("v", 600)}},
		Arc:              &protocol.ArcResult{Cv: protocol.ArcVerdict_ARC_NONE},
		Counts:           &protocol.AuthLimits{DkimSeen: 8, DkimChecked: 8},
		DkimAlignedCount: 2,
	}
	for index := range 8 {
		outcome.Dkim = append(outcome.Dkim, &protocol.DkimResult{
			Domain:    "d" + string(rune('a'+index)) + ".sender.example",
			Selector:  "s1",
			Result:    protocol.DkimVerdict_DKIM_PASS,
			PublicKey: key,
		})
	}
	message := []byte("synthetic")
	evidence := testMailEvidenceOf(t, outcome, message)
	if len(evidence.GetDkim()) != 8 || evidence.GetLimits().GetDropped() != 0 || evidence.GetLimits().GetReason() != sidecar.MailAuthLimitCount {
		t.Fatalf("%d entries, limits %v", len(evidence.GetDkim()), evidence.GetLimits())
	}
	// the keys gone are the last unaligned ones, and the aligned keys and SPF's record stay
	keptCount := 0
	for index, entry := range evidence.GetDkim() {
		if len(entry.GetPublicKey()) == 0 {
			continue
		}
		keptCount += 1
		if 0 < index && len(evidence.GetDkim()[index-1].GetPublicKey()) == 0 {
			t.Errorf("entry %d kept its key after an earlier one lost its", index)
		}
	}
	if keptCount < 2 || keptCount == 8 || len(evidence.GetSpf().GetRecords()) != 1 {
		t.Errorf("%d keys kept, spf %v", keptCount, evidence.GetSpf())
	}
	reference, dropCount := testMailEvidenceReferenceFit(t, outcome, message)
	if !proto.Equal(evidence, reference) || dropCount != 8-keptCount {
		t.Errorf("the builder parts from the reference's %d drops", dropCount)
	}
}

// Under the bound nothing drops and limits stays as the checks left it: unset where no bound cut, kept where one did.
func TestMailEvidenceLimitsOnlyWhereABoundCut(t *testing.T) {
	outcome := &sidecar.MailAuthOutcome{
		Spf:    &protocol.SpfResult{Result: protocol.SpfVerdict_SPF_NONE},
		Arc:    &protocol.ArcResult{Cv: protocol.ArcVerdict_ARC_NONE},
		Counts: &protocol.AuthLimits{DkimSeen: 1, DkimChecked: 1, DnsQueries: 4},
		Dkim:   []*protocol.DkimResult{{Domain: "sender.example", Selector: "s1", Result: protocol.DkimVerdict_DKIM_PASS}},
	}
	if evidence := testMailEvidenceOf(t, outcome, []byte("m")); evidence.GetLimits() != nil {
		t.Errorf("limits %v", evidence.GetLimits())
	}
	outcome.Limits = &protocol.AuthLimits{Reason: sidecar.MailAuthLimitDeadline, DkimSeen: 1, DkimChecked: 1, DnsQueries: 4}
	if evidence := testMailEvidenceOf(t, outcome, []byte("m")); !proto.Equal(evidence.GetLimits(), outcome.Limits) {
		t.Errorf("limits %v", evidence.GetLimits())
	}
}

// A string that is not UTF-8, which marshaling refuses, is left out, so the evidence still seals.
func TestMailEvidenceLeavesOutWhatIsNotUtf8(t *testing.T) {
	outcome := &sidecar.MailAuthOutcome{
		Spf:     &protocol.SpfResult{Result: protocol.SpfVerdict_SPF_FAIL, Domain: "bad\xff.example", Records: []string{"v=spf1 \xfe -all", "v=spf1 -all"}},
		Dkim:    []*protocol.DkimResult{{Domain: "\xc3", Selector: "s1", Result: protocol.DkimVerdict_DKIM_FAIL}},
		PtrName: "ptr\xff.example",
		Arc:     &protocol.ArcResult{Cv: protocol.ArcVerdict_ARC_PASS, Sets: []*protocol.ArcSet{{Domain: "fwd\xff.example", Selector: "arc"}}},
	}
	evidence := testMailEvidenceOf(t, outcome, []byte("m"))
	if _, err := proto.Marshal(evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.GetSpf().GetDomain() != "" || len(evidence.GetSpf().GetRecords()) != 1 || evidence.GetDkim()[0].GetDomain() != "" ||
		evidence.GetPtrName() != "" || evidence.GetArc().GetSets()[0].GetDomain() != "" || evidence.GetDkim()[0].GetResult() != protocol.DkimVerdict_DKIM_FAIL {
		t.Errorf("evidence %v", evidence)
	}
}

// §22.6's go-message and mox target for the checks: any bytes as a message on an empty zone, every lookup answered at
// once, give no error and no panic, at most 8 DKIM entries and 8 ARC sets, at most 9 body hashes and 17 signature
// checks, and evidence within 8,192 bytes that marshals: expansion bounded whatever the message.
func FuzzMailAuth(f *testing.F) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	corpus := sidecartest.NewMailCorpus(sidecartest.NewFakeMailZone(clock), clock.Now())
	seeds := [][]byte{
		testMailAuthMessage("sender.example", "seed"),
		[]byte("ARC-Seal: i=1; cv=none\r\nARC-Seal: i=1; cv=none\r\n\r\nbody"),
		[]byte("ARC-Authentication-Results: (c) i = 2 ; x\r\nARC-Message-Signature: i=2; h=from; b=;\r\n\r\n"),
		[]byte("no header at all"),
		{},
	}
	for _, build := range []func() (*sidecartest.MailCorpusMessage, error){
		func() (*sidecartest.MailCorpusMessage, error) { return corpus.MaximalSignatures(64) },
		func() (*sidecartest.MailCorpusMessage, error) { return corpus.ArcChain(8, 0, false) },
		func() (*sidecartest.MailCorpusMessage, error) { return corpus.ArcChain(12, 0, false) },
		func() (*sidecartest.MailCorpusMessage, error) { return corpus.ArcChain(8, 3, false) },
		func() (*sidecartest.MailCorpusMessage, error) { return corpus.SpoofedFrom(9) },
	} {
		message, err := build()
		if err != nil {
			f.Fatal(err)
		}
		seeds = append(seeds, message.Bytes)
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, message []byte) {
		world := newMailAuthCheckWorld(t)
		outcome, err := world.checker.Check(context.Background(), testMailAuthInput(message, "sender.example"))
		if err != nil {
			t.Fatal(err)
		}
		if 8 < len(outcome.Dkim) || 8 < len(outcome.Arc.GetSets()) || 8 < outcome.DkimVerifiedCount ||
			1 < outcome.ArcBodyHashCount || 9 < outcome.ArcSignatureCheckCount {
			t.Fatalf("%d dkim, %d arc sets, %d verified, %d and %d arc work", len(outcome.Dkim), len(outcome.Arc.GetSets()),
				outcome.DkimVerifiedCount, outcome.ArcBodyHashCount, outcome.ArcSignatureCheckCount)
		}
		if 64 < outcome.Counts.GetDkimSeen() || 8 < outcome.Counts.GetDkimChecked() || 64 < outcome.Counts.GetDnsQueries() {
			t.Fatalf("counts %v", outcome.Counts)
		}
		evidence := testMailEvidenceOf(t, outcome, message)
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(evidence)
		if err != nil || sidecar.MailAuthEvidenceMaxByteCount < len(encoded) {
			t.Fatalf("%d bytes, %v", len(encoded), err)
		}
	})
}
