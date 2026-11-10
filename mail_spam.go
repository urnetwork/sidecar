// §15.9's spam scoring (R-MAIL-6, R-MAIL-10; MAIL-M7-12): what a reader files as spam at ingest, from the sealed SPF,
// DKIM and DMARC results, a few rules over them, and the mailbox's own naive Bayes filter in s/model, which its
// people's verdicts train. The score is spam_score in the message's IndexEntry, parts per thousand. Nothing here
// refuses mail, greylists or waits, since one-time codes cannot wait, and nothing looks anything up: every input is
// what the receiver sealed or what the message says (D-MAIL-14), so a DNS change after reception moves no score.
//
// A DMARC fail under p=reject files the message as spam whatever else it shows (§15.9). Otherwise the score is
// 1,000 / (1 + e^-L) for log odds L: the filter's prior and its most telling features once each class has been
// trained MinTrainedCount times, else PriorLogOdds, plus a rule's weight for a DMARC fail under p=quarantine, for an
// SPF or DKIM fail with no DKIM pass, and against spam for a DMARC pass. A check that was cut or failed to look up
// is no result and moves nothing. Each term is rounded to 1/1024 before the sum, so legs that differ in a log's last
// bit still agree on the score. A person's own verdict on the message outranks the score where a list shows it
// (MailView, MAIL-FORMAT.md), and teaches the filter through MailSpamScorer.Teach.
//
// On every leg. Package-level functions are safe for concurrent use, and so is MailSpamScorer.

package sidecar

import (
	"cmp"
	"context"
	"errors"
	"math"
	"slices"
	"sync"

	"github.com/urnetwork/sidecar/protocol"
)

// The units a term is rounded to before the sum.
const mailSpamLogOddsScale = 1024

// What the scorer and the filter are tuned by.
type MailSpamSettings struct {
	// spam_score, parts per thousand, from which a message with no person's verdict files as spam.
	ScoreThreshold uint32
	// The messages each class must have been trained on before the filter speaks: below it one verdict would swing
	// every score. Non-positive lets it speak from the first verdict.
	MinTrainedCount uint32
	// Once more messages than this are trained, every count halves, so the filter follows a mailbox's mail as it
	// changes. Non-positive never halves, the counts then held below their limit.
	TrainedMaxCount uint32
	// The distinct features one message gives, the first met kept: enough for a long message's vocabulary, little
	// enough that one cannot weigh like many.
	FeatureMaxCount int
	// The bytes of the first text part read for features, from its start.
	TextMaxByteCount int
	// A word's bytes: shorter ones and longer ones, mostly encodings and hashes, are passed over.
	TokenMinByteCount int
	TokenMaxByteCount int
	// The features that pull hardest either way, which alone count toward a trained score, as Graham's filter does:
	// a long message's many weak words would otherwise drown what tells.
	InformativeFeatureCount int
	// The log odds of an untrained filter: most mail a person receives is not spam.
	PriorLogOdds float64
	// A DMARC fail under p=quarantine: its domain asks that such mail be treated as suspicious.
	DmarcQuarantineLogOdds float64
	// An SPF fail, or a DKIM fail with no DKIM pass, each once.
	AuthFailLogOdds float64
	// A DMARC pass, against spam.
	DmarcPassLogOdds float64
	// How many times a teach reads s/model again after another device's write before it gives up. Non-positive
	// tries once.
	WriteRetryCount int
}

// The one default.
func DefaultMailSpamSettings() *MailSpamSettings {
	return &MailSpamSettings{
		ScoreThreshold:          500,
		MinTrainedCount:         10,
		TrainedMaxCount:         4000,
		FeatureMaxCount:         512,
		TextMaxByteCount:        16 * 1024,
		TokenMinByteCount:       2,
		TokenMaxByteCount:       32,
		InformativeFeatureCount: 32,
		PriorLogOdds:            -2,
		DmarcQuarantineLogOdds:  2.5,
		AuthFailLogOdds:         1,
		DmarcPassLogOdds:        -1,
		WriteRetryCount:         8,
	}
}

// What scoring found.
type MailSpamVerdict struct {
	// spam_score, parts per thousand.
	Score uint32
	// Files as spam: a DMARC reject, or Score at or past ScoreThreshold.
	Spam bool
	// The From domain's DMARC failed under p=reject, which files the message as spam whatever else it shows.
	DmarcReject bool
	// The filter had been trained on both classes enough to take part.
	Trained bool
}

// A person's verdict on one message, as the spam and not-spam labels give it.
type MailSpamClass int

const (
	MailSpamClassNone MailSpamClass = iota
	MailSpamClassSpam
	MailSpamClassNotSpam
)

// The verdict a message's flags hold.
func MailSpamClassOf(flags *MailFlags) MailSpamClass {
	switch {
	case flags.VerdictSpam:
		return MailSpamClassSpam
	case flags.VerdictNotSpam:
		return MailSpamClassNotSpam
	}
	return MailSpamClassNone
}

// A term rounded to the sum's units.
func mailSpamTerm(logOdds float64) int64 {
	return int64(math.Round(logOdds * mailSpamLogOddsScale))
}

// The score of one message: see the file header. model may be nil, an untrained filter. deposit is the message's
// sealed trailer, nil or a same-network deposit with no evidence to weigh.
func MailSpamScore(model *MailSpamModel, parsed *MailParsed, deposit *protocol.MailDeposit, settings *MailSpamSettings) *MailSpamVerdict {
	verdict := &MailSpamVerdict{}
	terms := []int64{}
	evidence := deposit.GetEvidence()
	if mailReceiverDeposit(deposit) && evidence != nil {
		dmarc := evidence.GetDmarc()
		switch dmarc.GetResult() {
		case protocol.DmarcVerdict_DMARC_FAIL:
			switch dmarc.GetP() {
			case "reject":
				verdict.DmarcReject = true
			case "quarantine":
				terms = append(terms, mailSpamTerm(settings.DmarcQuarantineLogOdds))
			}
		case protocol.DmarcVerdict_DMARC_PASS:
			terms = append(terms, mailSpamTerm(settings.DmarcPassLogOdds))
		}
		if evidence.GetSpf().GetResult() == protocol.SpfVerdict_SPF_FAIL {
			terms = append(terms, mailSpamTerm(settings.AuthFailLogOdds))
		}
		dkimFail, dkimPass := false, false
		for _, dkim := range evidence.GetDkim() {
			dkimFail = dkimFail || dkim.GetResult() == protocol.DkimVerdict_DKIM_FAIL
			dkimPass = dkimPass || dkim.GetResult() == protocol.DkimVerdict_DKIM_PASS
		}
		if dkimFail && !dkimPass {
			terms = append(terms, mailSpamTerm(settings.AuthFailLogOdds))
		}
	}
	if verdict.DmarcReject {
		verdict.Score, verdict.Spam = mailSpamScoreMax, true
		return verdict
	}
	if model != nil && parsed != nil && settings.MinTrainedCount <= model.spamMessageCount && settings.MinTrainedCount <= model.hamMessageCount {
		verdict.Trained = true
		spamCount, hamCount := float64(model.spamMessageCount), float64(model.hamMessageCount)
		terms = append(terms, mailSpamTerm(math.Log((spamCount+1)/(hamCount+1))))
		pulls := []int64{}
		for _, bucket := range mailSpamFeatures(parsed, settings) {
			// Laplace's rule: a feature neither class has met pulls neither way
			spamRate := (float64(model.spamBuckets[bucket]) + 1) / (spamCount + 2)
			hamRate := (float64(model.hamBuckets[bucket]) + 1) / (hamCount + 2)
			pulls = append(pulls, mailSpamTerm(math.Log(spamRate/hamRate)))
		}
		// the strongest pulls either way, ties broken by the larger, so every leg sums the same terms
		slices.SortFunc(pulls, func(a int64, b int64) int {
			absolute := func(value int64) int64 { return max(value, -value) }
			return cmp.Or(cmp.Compare(absolute(b), absolute(a)), cmp.Compare(b, a))
		})
		terms = append(terms, pulls[:min(len(pulls), max(0, settings.InformativeFeatureCount))]...)
	} else {
		terms = append(terms, mailSpamTerm(settings.PriorLogOdds))
	}
	sum := int64(0)
	for _, term := range terms {
		sum += term
	}
	probability := 1 / (1 + math.Exp(-float64(sum)/mailSpamLogOddsScale))
	verdict.Score = uint32(min(mailSpamScoreMax, max(0, math.Round(probability*mailSpamScoreMax))))
	verdict.Spam = settings.ScoreThreshold <= verdict.Score
	return verdict
}

// Scores a mailbox's messages with its s/model and teaches the model its people's verdicts. Safe for concurrent use.
type MailSpamScorer struct {
	store    mailStore
	settings *MailSpamSettings

	stateLock sync.Mutex
	// s/model as last read or written, nil until then, and whether it stood at all.
	model   *MailSpamModel
	version uint64
	loaded  bool
}

// A scorer over the mailbox's store.
func NewMailSpamScorer(store mailStore, settings *MailSpamSettings) *MailSpamScorer {
	return &MailSpamScorer{store: store, settings: settings}
}

// Drops the model kept, so the next score reads s/model again, as after another device's teach.
func (self *MailSpamScorer) Refresh() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.loaded = false
	self.model = nil
}

// s/model and its version, read now; a model that learned nothing where none stands. A model that does not parse is
// ErrMailSpamModelInvalid, which a score takes as an untrained filter and a teach refuses to write over.
func (self *MailSpamScorer) read(ctx context.Context) (*MailSpamModel, uint64, error) {
	content, version, err := self.store.Read(ctx, MailSpamModelPath, MailSpamModelMaxByteCount)
	if errors.Is(err, ErrEvsPathAbsent) {
		return NewMailSpamModel(), 0, nil
	}
	if errors.Is(err, ErrMailStoreTooLarge) {
		return nil, version, ErrMailSpamModelInvalid
	}
	if err != nil {
		return nil, 0, err
	}
	model, err := ParseMailSpamModel(content)
	if err != nil {
		return nil, version, err
	}
	return model, version, nil
}

// One message's verdict by the mailbox's model, read once and kept until Refresh or a teach. A model that does not
// parse scores as an untrained one, so a broken s/model costs only the filter's part.
func (self *MailSpamScorer) Score(ctx context.Context, parsed *MailParsed, deposit *protocol.MailDeposit) (*MailSpamVerdict, error) {
	self.stateLock.Lock()
	model, loaded := self.model, self.loaded
	self.stateLock.Unlock()
	if !loaded {
		read, version, err := self.read(ctx)
		if err != nil && !errors.Is(err, ErrMailSpamModelInvalid) {
			return nil, err
		}
		model = read
		self.stateLock.Lock()
		self.model, self.version, self.loaded = read, version, true
		self.stateLock.Unlock()
	}
	return MailSpamScore(model, parsed, deposit, self.settings), nil
}

// Teaches s/model that a person's verdict on one message went from before to after: it unlearns the old verdict and
// learns the new, in one write by a path CAS, reading again on another device's write. The device that wrote the
// verdict's op teaches it, once, so each act counts once. Teaching the same verdict again changes nothing.
func (self *MailSpamScorer) Teach(ctx context.Context, parsed *MailParsed, before MailSpamClass, after MailSpamClass) error {
	if before == after {
		return nil
	}
	buckets := mailSpamFeatures(parsed, self.settings)
	for attempt := 0; ; attempt += 1 {
		if err := ctx.Err(); err != nil {
			return err
		}
		model, version, err := self.read(ctx)
		if err != nil {
			return err
		}
		if before != MailSpamClassNone {
			model.learn(buckets, before == MailSpamClassSpam, true, self.settings.TrainedMaxCount)
		}
		if after != MailSpamClassNone {
			model.learn(buckets, after == MailSpamClassSpam, false, self.settings.TrainedMaxCount)
		}
		content, err := model.Marshal()
		if err != nil {
			return err
		}
		testHookBarrier("mail.spam.teach.before", "")
		versions, err := self.store.Write(ctx, []*mailStoreWrite{{Path: MailSpamModelPath, Content: content, IfVersion: version}})
		testHookBarrier("mail.spam.teach.after", "")
		if err == nil {
			self.stateLock.Lock()
			self.model, self.version, self.loaded = model, versions[0], true
			self.stateLock.Unlock()
			return nil
		}
		if !errors.Is(err, ErrMailStoreConflict) || self.settings.WriteRetryCount <= attempt {
			return err
		}
	}
}
