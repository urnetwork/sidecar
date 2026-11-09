// MAIL-M7-12's scoring: a DMARC reject files as spam, the rules weigh the sealed results and nothing else, verdicts
// move the score once the filter is trained, s/model's bytes survive a restart and stay under their bound however
// much is taught, another device's teach is read again rather than lost, and a model that cannot be used is
// refused. Every name and word is synthetic.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"math"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A receiver's deposit sealing results: dmarc's verdict under policy p, SPF's, and DKIM's.
func testMailSpamDeposit(dmarc protocol.DmarcVerdict, p string, spf protocol.SpfVerdict, dkim ...protocol.DkimVerdict) *protocol.MailDeposit {
	evidence := &protocol.MailAuthEvidence{
		Version:           1,
		ReceiveTimeMillis: 1793923200000,
		ReceiverSidecarId: testMailId(0x5e).Bytes(),
		Spf:               &protocol.SpfResult{Result: spf},
		Dmarc:             &protocol.DmarcResult{P: p, Result: dmarc},
	}
	for _, result := range dkim {
		evidence.Dkim = append(evidence.Dkim, &protocol.DkimResult{Domain: "sender.example", Selector: "s1", Result: result})
	}
	return &protocol.MailDeposit{Version: 1, Evidence: evidence, Recipients: []string{"id@k3j4h5g6f7.root.example"}, ReceiverSidecarId: testMailId(0x5e).Bytes()}
}

// The score log odds L give.
func testMailSpamScoreOf(logOdds float64) uint32 {
	return uint32(math.Round(1000 / (1 + math.Exp(-logOdds))))
}

// A DMARC fail under p=reject files the message as spam, whatever the filter or the other results say; under
// p=none it is only one more result.
func TestMailSpamDmarcRejectFilesAsSpam(t *testing.T) {
	settings := DefaultMailSpamSettings()
	parsed := &MailParsed{Subject: "meeting agenda", FromDomain: "sender.example"}
	reject := MailSpamScore(nil, parsed, testMailSpamDeposit(protocol.DmarcVerdict_DMARC_FAIL, "reject", protocol.SpfVerdict_SPF_PASS, protocol.DkimVerdict_DKIM_PASS), settings)
	if !reject.Spam || !reject.DmarcReject || reject.Score != 1000 {
		t.Errorf("p=reject: %+v", reject)
	}
	none := MailSpamScore(nil, parsed, testMailSpamDeposit(protocol.DmarcVerdict_DMARC_FAIL, "none", protocol.SpfVerdict_SPF_NONE), settings)
	if none.Spam || none.DmarcReject || none.Score != testMailSpamScoreOf(settings.PriorLogOdds) {
		t.Errorf("p=none: %+v", none)
	}
}

// An untrained filter scores by the prior and the rules alone, each a sealed result: a quarantine fail, an SPF fail
// and a DKIM fail with no pass push toward spam, a DMARC pass away from it, and a cut, temporary or missing result
// moves nothing. A same-network deposit and one sealing no evidence have no results to weigh.
func TestMailSpamRulesWeighOnlySealedResults(t *testing.T) {
	settings := DefaultMailSpamSettings()
	parsed := &MailParsed{Subject: "hello"}
	cases := []struct {
		name    string
		deposit *protocol.MailDeposit
		logOdds float64
	}{
		{name: "quarantine", deposit: testMailSpamDeposit(protocol.DmarcVerdict_DMARC_FAIL, "quarantine", protocol.SpfVerdict_SPF_NONE), logOdds: settings.PriorLogOdds + settings.DmarcQuarantineLogOdds},
		{name: "dmarc pass", deposit: testMailSpamDeposit(protocol.DmarcVerdict_DMARC_PASS, "reject", protocol.SpfVerdict_SPF_PASS, protocol.DkimVerdict_DKIM_PASS), logOdds: settings.PriorLogOdds + settings.DmarcPassLogOdds},
		{name: "spf and dkim fail", deposit: testMailSpamDeposit(protocol.DmarcVerdict_DMARC_NONE, "", protocol.SpfVerdict_SPF_FAIL, protocol.DkimVerdict_DKIM_FAIL), logOdds: settings.PriorLogOdds + 2*settings.AuthFailLogOdds},
		{name: "a dkim fail beside a pass", deposit: testMailSpamDeposit(protocol.DmarcVerdict_DMARC_NONE, "", protocol.SpfVerdict_SPF_NONE, protocol.DkimVerdict_DKIM_FAIL, protocol.DkimVerdict_DKIM_PASS), logOdds: settings.PriorLogOdds},
		{name: "cut and temporary", deposit: testMailSpamDeposit(protocol.DmarcVerdict_DMARC_TEMPERROR, "reject", protocol.SpfVerdict_SPF_INCOMPLETE, protocol.DkimVerdict_DKIM_INCOMPLETE), logOdds: settings.PriorLogOdds},
		{name: "same network", deposit: &protocol.MailDeposit{Version: 1, MailFrom: []byte("ada@k3j4h5g6f7.root.example"), Recipients: []string{"grace@k3j4h5g6f7.root.example"}}, logOdds: settings.PriorLogOdds},
		{name: "no evidence", deposit: &protocol.MailDeposit{Version: 1, Recipients: []string{"id@k3j4h5g6f7.root.example"}, ReceiverSidecarId: testMailId(0x5e).Bytes()}, logOdds: settings.PriorLogOdds},
		{name: "no deposit", logOdds: settings.PriorLogOdds},
	}
	for _, c := range cases {
		verdict := MailSpamScore(nil, parsed, c.deposit, settings)
		if want := testMailSpamScoreOf(c.logOdds); verdict.Score != want || verdict.Spam != (settings.ScoreThreshold <= want) || verdict.Trained {
			t.Errorf("%s: %+v, want %d", c.name, verdict, want)
		}
	}
}

// Messages of two kinds, each from its own domain with its own words.
func testMailSpamMessage(spam bool, n int) *MailParsed {
	if spam {
		return &MailParsed{
			Subject:    fmt.Sprintf("cheap pills discount offer %d", n),
			Text:       "Limited offer: cheap pills, huge discount, click now to claim your prize.",
			FromDomain: "bulk.example",
		}
	}
	return &MailParsed{
		Subject:    fmt.Sprintf("project meeting agenda %d", n),
		Text:       "Hello team, the agenda for the project meeting is attached; please review the draft before Tuesday.",
		FromDomain: "colleague.example",
	}
}

// Verdicts move the score: once each class has been taught enough, a message like the spam taught scores past the
// threshold and one like the rest well under it; before then the filter does not speak; and a verdict changed back
// is unlearned.
func TestMailSpamVerdictsMoveTheScore(t *testing.T) {
	ctx := context.Background()
	settings := DefaultMailSpamSettings()
	scorer := NewMailSpamScorer(newMailTestStore(), settings)
	spammy, hammy := testMailSpamMessage(true, 900), testMailSpamMessage(false, 900)
	untrained, err := scorer.Score(ctx, spammy, nil)
	if err != nil || untrained.Trained || untrained.Score != testMailSpamScoreOf(settings.PriorLogOdds) {
		t.Fatalf("%+v, %v", untrained, err)
	}
	for n := range int(settings.MinTrainedCount) {
		if err := scorer.Teach(ctx, testMailSpamMessage(true, n), MailSpamClassNone, MailSpamClassSpam); err != nil {
			t.Fatal(err)
		}
		if err := scorer.Teach(ctx, testMailSpamMessage(false, n), MailSpamClassNone, MailSpamClassNotSpam); err != nil {
			t.Fatal(err)
		}
	}
	spamVerdict, _ := scorer.Score(ctx, spammy, nil)
	hamVerdict, _ := scorer.Score(ctx, hammy, nil)
	if !spamVerdict.Trained || !spamVerdict.Spam || spamVerdict.Score < 900 || hamVerdict.Spam || 100 < hamVerdict.Score {
		t.Fatalf("spam %+v, not spam %+v", spamVerdict, hamVerdict)
	}
	// a person says the spammy message is not spam after all: it was taught as spam, and is now taught the other way
	for n := range 3 * int(settings.MinTrainedCount) {
		if err := scorer.Teach(ctx, testMailSpamMessage(true, n), MailSpamClassSpam, MailSpamClassNotSpam); err != nil {
			t.Fatal(err)
		}
	}
	moved, _ := scorer.Score(ctx, spammy, nil)
	if spamVerdict.Score <= moved.Score || moved.Spam {
		t.Errorf("after the verdicts changed: %d, before %d", moved.Score, spamVerdict.Score)
	}
	spamCount, hamCount := scorer.model.MessageCounts()
	if spamCount != 0 || hamCount != 4*settings.MinTrainedCount {
		t.Errorf("counts %d spam, %d not spam", spamCount, hamCount)
	}
	// the same verdict again teaches nothing
	before := scorer.store.(*mailTestStore).writeCount
	if err := scorer.Teach(ctx, hammy, MailSpamClassNotSpam, MailSpamClassNotSpam); err != nil || scorer.store.(*mailTestStore).writeCount != before {
		t.Errorf("a repeated verdict wrote: %v", err)
	}
}

// s/model's bytes survive a restart: a new scorer over the same store reads them and scores alike, and they parse
// back to the same bytes.
func TestMailSpamModelSurvivesARestart(t *testing.T) {
	ctx := context.Background()
	settings := DefaultMailSpamSettings()
	store := newMailTestStore()
	scorer := NewMailSpamScorer(store, settings)
	for n := range int(settings.MinTrainedCount) + 2 {
		scorer.Teach(ctx, testMailSpamMessage(true, n), MailSpamClassNone, MailSpamClassSpam)
		scorer.Teach(ctx, testMailSpamMessage(false, n), MailSpamClassNone, MailSpamClassNotSpam)
	}
	before, _ := scorer.Score(ctx, testMailSpamMessage(true, 77), nil)
	restarted := NewMailSpamScorer(store, settings)
	after, err := restarted.Score(ctx, testMailSpamMessage(true, 77), nil)
	if err != nil || *before != *after {
		t.Fatalf("before %+v, after %+v, %v", before, after, err)
	}
	content := store.file(MailSpamModelPath).content
	model, err := ParseMailSpamModel(content)
	if err != nil {
		t.Fatal(err)
	}
	again, err := model.Marshal()
	if err != nil || string(again) != string(content) {
		t.Error("the bytes do not round-trip")
	}
}

// However much is taught, s/model stays under its bound: counts halve past TrainedMaxCount and every count stays
// below its limit, and the bytes never pass MailSpamModelMaxByteCount.
func TestMailSpamModelStaysUnderItsBound(t *testing.T) {
	settings := DefaultMailSpamSettings()
	settings.TrainedMaxCount = 1000
	model := NewMailSpamModel()
	for n := range 5000 {
		parsed := &MailParsed{Subject: fmt.Sprintf("w%dx w%dy w%dz", n, n*7, n*13), Text: fmt.Sprintf("body%d word%d text%d", n%97, n%89, n%83)}
		model.learn(mailSpamFeatures(parsed, settings), n%3 == 0, false, settings.TrainedMaxCount)
	}
	spamCount, hamCount := model.MessageCounts()
	if settings.TrainedMaxCount < spamCount+hamCount || spamCount == 0 || hamCount == 0 {
		t.Errorf("counts %d and %d", spamCount, hamCount)
	}
	content, err := model.Marshal()
	if err != nil || MailSpamModelMaxByteCount < len(content) {
		t.Fatalf("%d bytes, %v", len(content), err)
	}
	if _, err := ParseMailSpamModel(content); err != nil {
		t.Error(err)
	}
	// the widest a model can be: every count at its limit
	widest := NewMailSpamModel()
	widest.spamMessageCount, widest.hamMessageCount = mailSpamCountLimit-1, mailSpamCountLimit-1
	for bucket := range MailSpamModelBucketCount {
		widest.spamBuckets[bucket], widest.hamBuckets[bucket] = mailSpamCountLimit-1, mailSpamCountLimit-1
	}
	if content, err := widest.Marshal(); err != nil || MailSpamModelMaxByteCount < len(content) {
		t.Errorf("the widest model takes %d bytes", len(content))
	}
}

// A model a reader cannot use is refused: past the bound, another version, counts of another length, a bucket
// counting more messages than its class, and a count at its limit. A scorer scores past it as untrained, and a teach
// will not write over it.
func TestMailSpamModelRefusesWhatItCannotUse(t *testing.T) {
	ctx := context.Background()
	counts := make([]uint32, mailSpamModelCountCount)
	encode := func(version uint32, counts []uint32) []byte {
		content, err := proto.Marshal(&protocol.MailSpamModel{Version: version, Counts: counts})
		if err != nil {
			t.Fatal(err)
		}
		return content
	}
	overBucket := append([]uint32{}, counts...)
	overBucket[0], overBucket[2] = 1, 2
	atLimit := append([]uint32{}, counts...)
	atLimit[1] = mailSpamCountLimit
	for name, content := range map[string][]byte{
		"too large":      make([]byte, MailSpamModelMaxByteCount+1),
		"version 2":      encode(2, counts),
		"version 0":      encode(0, counts),
		"short counts":   encode(1, counts[:10]),
		"over its class": encode(1, overBucket),
		"count at limit": encode(1, atLimit),
		"not a message":  {0xff, 0xff},
	} {
		if _, err := ParseMailSpamModel(content); !errors.Is(err, ErrMailSpamModelInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	store := newMailTestStore()
	store.put(MailSpamModelPath, encode(2, counts))
	scorer := NewMailSpamScorer(store, DefaultMailSpamSettings())
	if verdict, err := scorer.Score(ctx, testMailSpamMessage(true, 1), nil); err != nil || verdict.Trained {
		t.Errorf("%+v, %v", verdict, err)
	}
	if err := scorer.Teach(ctx, testMailSpamMessage(true, 1), MailSpamClassNone, MailSpamClassSpam); !errors.Is(err, ErrMailSpamModelInvalid) {
		t.Errorf("a teach over a broken model: %v", err)
	}
}

// Another device's teach landing between this one's read and write: the write conflicts, this device reads again and
// teaches on top, so both verdicts count.
func TestMailSpamTeachReadsAgainAfterAnotherDevicesWrite(t *testing.T) {
	ctx := context.Background()
	store := newMailTestStore()
	scorer := NewMailSpamScorer(store, DefaultMailSpamSettings())
	other := NewMailSpamScorer(store, DefaultMailSpamSettings())
	store.beforeWrite = func() {
		if err := other.Teach(ctx, testMailSpamMessage(false, 1), MailSpamClassNone, MailSpamClassNotSpam); err != nil {
			t.Error(err)
		}
	}
	if err := scorer.Teach(ctx, testMailSpamMessage(true, 1), MailSpamClassNone, MailSpamClassSpam); err != nil {
		t.Fatal(err)
	}
	model, err := ParseMailSpamModel(store.file(MailSpamModelPath).content)
	if err != nil {
		t.Fatal(err)
	}
	if spamCount, hamCount := model.MessageCounts(); spamCount != 1 || hamCount != 1 || store.writeCount != 3 {
		t.Errorf("%d spam, %d not spam after %d writes", spamCount, hamCount, store.writeCount)
	}
}

// The flags a list shows give the verdict a teach starts from.
func TestMailSpamClassOfFlags(t *testing.T) {
	if MailSpamClassOf(&MailFlags{VerdictSpam: true}) != MailSpamClassSpam || MailSpamClassOf(&MailFlags{VerdictNotSpam: true}) != MailSpamClassNotSpam || MailSpamClassOf(&MailFlags{}) != MailSpamClassNone {
		t.Error("classes")
	}
}
