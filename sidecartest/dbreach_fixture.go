//go:build sidecar_testhooks && !ios_extension && !js

// §22.7's DBREACH fixture (R-TEST-3, D-TEST-5, I-2, I-19; TEST-M10-03): a mailbox's search index under a server that
// reads every padded size while a sender injects messages, and an attacker that ranks guesses for a fixture one-time
// code from those sizes alone. The run reports its per-guess advantage over chance on every run, pass or fail, since a
// shrinking margin is the signal (§22.16 fails the build on a recovered code).
//
// What leaks without the defences is the shard's dictionary, the one structure documents share (§11.14's codes row): a
// probe whose trigrams the code's message already holds adds no dictionary entries, so its shard is some 36 B smaller
// than another probe's. The defences are §11.14's keyed pad on every shard, pseudo-random in each shard's own bytes,
// beside evs's Padmé on what it stores, and no compression across documents.
//
//	index      shards as the index's own builder writes them (SearchTestWorld.WriteShards, SEARCH-M10-05's keyed pad),
//	           each sealed as evs stores a segment: Padmé of its record's length
//	mutants    DbreachModeNoKeyedPad seals each shard without its keyed pad, and DbreachModeCompressed compresses its
//	           bytes (DEFLATE) and seals that, again with no keyed pad: the designs §11.14 rejects, on which the attacker
//	           recovers the code, which shows it works
//	server     sees only sizes, as a PrivacyCapture's request log holds them (RequestLog's lines), and the attacker reads
//	           those lines and nothing else: never the index, a shard or a key
//	attacker   stronger than §22.7's, so its failure on the index binds the weaker one: it sees each probe against a
//	           fresh copy of the bucket, never against its earlier probes. It calibrates a decoy's probe to the next
//	           Padmé boundary by its filler's length, then reads, for each candidate code, at how many filler lengths
//	           past that its probe's shard stays below the boundary; the code's own probe stays below longest. It spends
//	           exactly its budget, 1,000 injections a bucket's worth (InjectionCount), the last of them re-reading its
//	           leading candidates, and claims a code only where its lead is RecoveryMargin readings or more
//
// Readings, in TEST-M10-03's report: an injected message is a document of the mailbox's index, as a deposit's
// indexing makes one, without MAIL's deposit path, whose own sealed size names nothing of the index; the probe's
// trigrams are what the attacker controls, so its documents are a file's row and body text as the search world
// prepares them; one shard holds the bucket, which keeps the boundary the attacker probes a shard's.
//
// Deterministic: every draw comes from Seed. Only the sidecar_testhooks build has it (§22.4).

package sidecartest

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// What the server is shown of each shard.
type DbreachMode int

const (
	// The index: each shard as its builder writes it, keyed pad and all, sealed at Padmé.
	DbreachModeIndex DbreachMode = 0
	// A mutant: each shard sealed without its keyed pad.
	DbreachModeNoKeyedPad DbreachMode = 1
	// A mutant: each shard's bytes before its pad compressed, then sealed, with no keyed pad.
	DbreachModeCompressed DbreachMode = 2
)

func (self DbreachMode) String() string {
	switch self {
	case DbreachModeNoKeyedPad:
		return "no keyed pad"
	case DbreachModeCompressed:
		return "compressed"
	}
	return "the index"
}

type DbreachSettings struct {
	// Every draw: codes, candidates, background and filler.
	Seed uint64
	// Codes attacked, each its own mailbox.
	TrialCount int
	// The digits of a one-time code.
	CodeDigitCount int
	// The mailbox's other messages, and the words in each.
	BackgroundCount     int
	BackgroundWordCount int
	// The attacker's injections into a bucket, which it spends whole, and the fewest a run may take: §22.7's 1,000,
	// since a run with fewer passes trivially. They fix how many candidates it ranks: what calibration leaves, a
	// candidate to each threshold search.
	InjectionCount         int
	RequiredInjectionCount int
	// The longest filler the calibration tries, in letters.
	FillerMaxCount int
	// How far past the calibrated boundary, in letters, the attacker reads each candidate's own threshold, the first
	// filler length at which its probe's shard crosses: one reading a length, since a sequential attacker's probe adds
	// its trigrams once and a re-read would average what it cannot. It reaches past what the code's probe saves, some
	// 10 letters' worth (40 B; 24 B compressed, a letter adding some 4 B, 2 B compressed).
	ThresholdMaxCount int
	// How many letters the leading candidate's threshold must pass the next's for the attacker to claim it: below
	// this, its top guess is a guess, which the advantage counts.
	RecoveryMargin int
}

func DefaultDbreachSettings() *DbreachSettings {
	return &DbreachSettings{
		Seed:                   20261118,
		TrialCount:             3,
		CodeDigitCount:         6,
		BackgroundCount:        24,
		BackgroundWordCount:    12,
		InjectionCount:         1000,
		RequiredInjectionCount: 1000,
		FillerMaxCount:         512,
		ThresholdMaxCount:      32,
		RecoveryMargin:         2,
	}
}

// One code attacked.
type DbreachTrial struct {
	Code string
	// The attacker's top candidate, the code's rank among its candidates (1 is first), and its lead over the next.
	Guess  string
	Rank   int
	Margin int
	// The attacker claimed the code, and was right.
	Recovered bool
	// The messages it injected, and the candidates it ranked, the code among them.
	InjectionCount int
	CandidateCount int
}

// What a run found.
type DbreachReport struct {
	Mode           DbreachMode
	CandidateCount int
	Trials         []*DbreachTrial
	// Trials whose code the attacker recovered.
	RecoveredCount int
	// The attacker's top guess's hit rate less chance's, 1 / CandidateCount: its per-guess advantage.
	Advantage float64
}

func (self *DbreachReport) String() string {
	ranks := []string{}
	for _, trial := range self.Trials {
		ranks = append(ranks, fmt.Sprintf("rank %d, lead %d", trial.Rank, trial.Margin))
	}
	return fmt.Sprintf("%s: %d of %d codes recovered among %d candidates, per-guess advantage %+.4f (%s)",
		self.Mode, self.RecoveredCount, len(self.Trials), self.CandidateCount, self.Advantage, strings.Join(ranks, "; "))
}

// The fixture: see the file header. Not safe for concurrent use.
type DbreachFixture struct {
	settings *DbreachSettings
	mode     DbreachMode
	random   *rand.Rand
}

func NewDbreachFixture(settings *DbreachSettings, mode DbreachMode) *DbreachFixture {
	return &DbreachFixture{settings: settings, mode: mode, random: rand.New(rand.NewPCG(settings.Seed, uint64(mode)+1))}
}

// A word of letters alone, so no filler or background trigram is a code's.
func (self *DbreachFixture) word(length int) string {
	letters := make([]byte, length)
	for index := range letters {
		letters[index] = byte('a' + self.random.IntN(26))
	}
	return string(letters)
}

func (self *DbreachFixture) code() string {
	digits := make([]byte, self.settings.CodeDigitCount)
	for index := range digits {
		digits[index] = byte('0' + self.random.IntN(10))
	}
	return string(digits)
}

// Runs every trial and reports. A run of fewer injections than §22.7's is refused, not passed.
func (self *DbreachFixture) Run(ctx context.Context) (*DbreachReport, error) {
	if self.settings.InjectionCount < self.settings.RequiredInjectionCount {
		return nil, fmt.Errorf("dbreach: %d injections a bucket, fewer than §22.7's %d", self.settings.InjectionCount, self.settings.RequiredInjectionCount)
	}
	if self.settings.ThresholdMaxCount < 1 || self.settings.FillerMaxCount < 1 {
		return nil, errors.New("dbreach: a threshold and a filler at least")
	}
	report := &DbreachReport{Mode: self.mode}
	for trialIndex := range self.settings.TrialCount {
		trial, err := self.trial(ctx, trialIndex)
		if err != nil {
			return nil, err
		}
		if trial.InjectionCount != self.settings.InjectionCount {
			return nil, fmt.Errorf("dbreach: the attacker injected %d messages, not its %d", trial.InjectionCount, self.settings.InjectionCount)
		}
		report.Trials = append(report.Trials, trial)
		report.CandidateCount = trial.CandidateCount
		if trial.Recovered {
			report.RecoveredCount += 1
		}
	}
	hits := 0
	for _, trial := range report.Trials {
		if trial.Rank == 1 {
			hits += 1
		}
	}
	report.Advantage = float64(hits)/float64(len(report.Trials)) - 1/float64(report.CandidateCount)
	return report, nil
}

// One mailbox: its background, the code's message, and the attacker's run against it.
type dbreachMailbox struct {
	fixture    *DbreachFixture
	code       string
	candidates []string
	decoy      string
	world      *sidecar.SearchTestWorld
	clock      *FakeClock
	base       []*sidecar.SearchTestDocument
	filler     string
	capture    *PrivacyCapture
	server     http.Handler
	bucket     uint32
	injected   int
	// the world's history read so far
	refVersion uint64
}

func (self *DbreachFixture) trial(ctx context.Context, trialIndex int) (*DbreachTrial, error) {
	mailbox, err := self.newMailbox(trialIndex)
	if err != nil {
		return nil, err
	}
	scores, ranked, err := mailbox.attack(ctx)
	if err != nil {
		return nil, err
	}
	trial := &DbreachTrial{
		Code: mailbox.code, Guess: ranked[0], Rank: slices.Index(ranked, mailbox.code) + 1, InjectionCount: mailbox.injected, CandidateCount: len(ranked),
	}
	if trial.Rank == 0 {
		return nil, errors.New("dbreach: the attacker's budget ended before the code's candidate")
	}
	trial.Margin = scores[ranked[0]] - scores[ranked[1]]
	trial.Recovered = trial.Guess == mailbox.code && self.settings.RecoveryMargin <= trial.Margin
	return trial, nil
}

// The calibration's most probes: the low reading and a binary search over the filler's lengths.
func (self *DbreachFixture) calibrationMaxCount() int {
	return 1 + bits.Len(uint(self.settings.FillerMaxCount)) + 1
}

// A threshold search's most probes, a letter at a time from 0 to ThresholdMaxCount.
func (self *DbreachFixture) thresholdMaxCount() int {
	return self.settings.ThresholdMaxCount + 1
}

// A trial's mailbox: its background, the code's message, the candidates and the decoy, its server and capture.
func (self *DbreachFixture) newMailbox(trialIndex int) (*dbreachMailbox, error) {
	clock := NewFakeClock(DefaultClockStart())
	world, err := sidecar.NewSearchTestWorld(&sidecar.SearchTestWorldArgs{
		RepoId: dbreachId(fmt.Sprintf("mailbox %d", trialIndex)), RefId: dbreachId(fmt.Sprintf("inbox %d", trialIndex)), Clock: clock,
	})
	if err != nil {
		return nil, err
	}
	code := self.code()
	mailbox := &dbreachMailbox{fixture: self, world: world, clock: clock, code: code, capture: NewPrivacyCapture(), bucket: sidecar.SearchTestBucketStartDay(clock.Now())}
	for index := range self.settings.BackgroundCount {
		words := []string{}
		for range self.settings.BackgroundWordCount {
			words = append(words, self.word(3+self.random.IntN(6)))
		}
		mailbox.base = append(mailbox.base, &sidecar.SearchTestDocument{
			Path: fmt.Sprintf("m/%d.eml", index), Version: 1, Title: "re " + words[0], Text: strings.Join(words, " "), Time: clock.Now(),
		})
	}
	// a one-time code's mail names it in its subject and its body
	mailbox.base = append(mailbox.base, &sidecar.SearchTestDocument{
		Path: "m/code.eml", Version: 1, Title: "your sign-in code " + code, Text: "your sign in code is " + code + " and it expires soon", Time: clock.Now(),
	})
	mailbox.filler = self.word(self.settings.FillerMaxCount)
	// the server stores each sealed shard; the capture keeps what it learns, a request's size
	mailbox.server = mailbox.capture.WrapHandler("evs1", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		// the store reads the whole upload, which is what the capture counts
		if _, err := io.Copy(io.Discard, request.Body); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.WriteHeader(http.StatusOK)
	}))
	// candidates as many as the budget could rank were each to cross at once, which most do; the code among those it
	// reaches even were each to take its longest search
	reached := (self.settings.InjectionCount - self.calibrationMaxCount()) / self.thresholdMaxCount()
	if reached < 2 {
		return nil, errors.New("dbreach: a budget that ranks fewer than two candidates")
	}
	mailbox.candidates = []string{code}
	seen := map[string]bool{code: true}
	for len(mailbox.candidates) < self.settings.InjectionCount {
		candidate := self.code()
		if !seen[candidate] {
			seen[candidate] = true
			mailbox.candidates = append(mailbox.candidates, candidate)
		}
	}
	at := self.random.IntN(reached)
	mailbox.candidates[0], mailbox.candidates[at] = mailbox.candidates[at], mailbox.candidates[0]
	mailbox.decoy = self.code()
	for seen[mailbox.decoy] {
		mailbox.decoy = self.code()
	}
	return mailbox, nil
}

// The attacker: what it learns comes from the capture's request log alone (sizeOf). It returns each candidate's
// readings below the boundary and the candidates it ranked, best first.
func (self *dbreachMailbox) attack(ctx context.Context) (map[string]int, []string, error) {
	settings := self.fixture.settings
	low, err := self.probe(ctx, self.decoy, 0)
	if err != nil {
		return nil, nil, err
	}
	// the first filler length at which the decoy's shard passes the boundary above it
	lo, hi := 0, settings.FillerMaxCount
	for lo < hi {
		middle := (lo + hi) / 2
		size, err := self.probe(ctx, self.decoy, middle)
		if err != nil {
			return nil, nil, err
		}
		if size <= low {
			lo = middle + 1
		} else {
			hi = middle
		}
	}
	boundary := lo
	// a probe whose own text holds fewer distinct trigrams than the decoy's grows its shard less whatever the mailbox
	// holds, so the attacker, who wrote it, lengthens its filler a letter for each, a filler letter adding one trigram
	decoyKeys := dbreachProbeKeyCount(self.decoy)
	below := func(candidate string, offset int) (bool, error) {
		filler := boundary + offset + decoyKeys - dbreachProbeKeyCount(candidate)
		size, err := self.probe(ctx, candidate, max(0, min(settings.FillerMaxCount, filler)))
		return size <= low, err
	}
	// each candidate's threshold: the first offset past the boundary at which its probe crosses it, read letter by
	// letter from the boundary, since a compressed shard's size need not rise with every letter
	scores := map[string]int{}
	ranked := []string{}
	for _, candidate := range self.candidates {
		if settings.InjectionCount-self.injected < settings.ThresholdMaxCount+1 {
			break
		}
		threshold := 0
		for ; threshold < settings.ThresholdMaxCount; threshold += 1 {
			stays, err := below(candidate, threshold)
			if err != nil {
				return nil, nil, err
			}
			if !stays {
				break
			}
		}
		scores[candidate] = threshold
		ranked = append(ranked, candidate)
	}
	slices.SortStableFunc(ranked, func(a string, b string) int { return scores[b] - scores[a] })
	// what the budget has left, fewer than a search, checks the leader's threshold: below one letter short of it, and
	// over at it, else the attacker trusts it a letter less
	for check := 0; self.injected < settings.InjectionCount; check += 1 {
		offset := scores[ranked[0]] - 1 + check%2
		stays, err := below(ranked[0], max(0, offset))
		if err != nil {
			return nil, nil, err
		}
		if stays != (check%2 == 0) {
			scores[ranked[0]] -= 1
		}
	}
	slices.SortStableFunc(ranked, func(a string, b string) int { return scores[b] - scores[a] })
	return scores, ranked, nil
}

// The probe's title and path, and its body before the filler: what the attacker writes.
func dbreachProbeTitle(candidate string) string {
	return "your sign-in code " + candidate
}

func dbreachProbeBody(candidate string) string {
	return "code " + candidate + " "
}

// The distinct trigrams of a probe's own text but its filler, as the attacker reckons them: letters and digits kept,
// anything else a space, each field between spaces, as normalizer 1 leaves ASCII.
func dbreachProbeKeyCount(candidate string) int {
	keys := map[string]bool{}
	for _, field := range []string{dbreachProbeTitle(candidate) + " m/probe.eml", dbreachProbeBody(candidate)} {
		text := []byte(" ")
		for _, b := range []byte(strings.ToLower(field)) {
			if ('a' <= b && b <= 'z') || ('0' <= b && b <= '9') {
				text = append(text, b)
			} else if text[len(text)-1] != ' ' {
				text = append(text, ' ')
			}
		}
		if text[len(text)-1] != ' ' {
			text = append(text, ' ')
		}
		for index := 0; index+3 <= len(text); index += 1 {
			keys[string(text[index:index+3])] = true
		}
	}
	return len(keys)
}

// Injects one probe, the candidate code beside fillerCount letters of filler, into a fresh copy of the bucket, and
// returns the size the server saw of the bucket's shard.
func (self *dbreachMailbox) probe(ctx context.Context, candidate string, fillerCount int) (int, error) {
	if self.fixture.settings.InjectionCount <= self.injected {
		return 0, errors.New("dbreach: the attacker's injections are spent")
	}
	self.injected += 1
	documents := append(slices.Clone(self.base), &sidecar.SearchTestDocument{
		Path: "m/probe.eml", Version: 1, Title: dbreachProbeTitle(candidate), Text: dbreachProbeBody(candidate) + self.filler[:fillerCount], Time: self.clock.Now(),
	})
	// each probe its own bucket: a fresh copy of the mailbox's, so no probe meets another
	self.bucket += 30
	partition := &sidecar.SearchTestPartition{StartDay: self.bucket, ShardDocumentCount: len(documents)}
	if err := self.world.WriteShards(ctx, dbreachId("device"), self.clock.Now(), partition, documents, nil); err != nil {
		return 0, err
	}
	shardPath := fmt.Sprintf(".ur-index/i1/b/%d/s/0", self.bucket)
	var shard []byte
	for _, push := range self.world.IndexHistory(self.refVersion) {
		self.refVersion = push.RefVersion
		for _, file := range push.Written {
			if file.Path == shardPath {
				shard = file.Plaintext
			}
		}
	}
	if shard == nil {
		return 0, fmt.Errorf("dbreach: no shard at %s", shardPath)
	}
	stored, err := self.fixture.sealedLength(shard)
	if err != nil {
		return 0, err
	}
	request := httptest.NewRequest(http.MethodPost, "/evs/segment", bytes.NewReader(make([]byte, stored)))
	self.server.ServeHTTP(httptest.NewRecorder(), request)
	return self.sizeOf()
}

// The size of the server's last stored object, read from the capture's request log: what the attacker sees.
func (self *dbreachMailbox) sizeOf() (int, error) {
	log := self.capture.RequestLog("")
	if len(log) == 0 {
		return 0, errors.New("dbreach: the server saw nothing")
	}
	fields := strings.Fields(log[len(log)-1])
	return strconv.Atoi(fields[len(fields)-1])
}

// The length evs stores for a shard, as the mode shows it: Padmé of its sealed record's length.
func (self *DbreachFixture) sealedLength(shard []byte) (uint64, error) {
	length := uint64(len(shard))
	if self.mode != DbreachModeIndex {
		unpadded, err := dbreachUnpadded(shard)
		if err != nil {
			return 0, err
		}
		length = uint64(len(unpadded))
		if self.mode == DbreachModeCompressed {
			compressed := &bytes.Buffer{}
			writer, err := flate.NewWriter(compressed, flate.BestCompression)
			if err != nil {
				return 0, err
			}
			if _, err := writer.Write(unpadded); err != nil {
				return 0, err
			}
			if err := writer.Close(); err != nil {
				return 0, err
			}
			length = uint64(compressed.Len())
		}
	}
	return sidecar.EvsPadme(sidecar.EvsRecordByteCount(length)), nil
}

// A shard's bytes before its pad: "URix", the header's VByte length, the header, and body_length bytes.
func dbreachUnpadded(shard []byte) ([]byte, error) {
	if !bytes.HasPrefix(shard, []byte("URix")) {
		return nil, errors.New("dbreach: a shard with no magic")
	}
	headerLength, n := binary.Uvarint(shard[4:])
	if n <= 0 || uint64(len(shard)-4-n) < headerLength {
		return nil, errors.New("dbreach: a shard's header past its bytes")
	}
	header := &protocol.IndexFileHeader{}
	if err := proto.Unmarshal(shard[4+n:4+n+int(headerLength)], header); err != nil {
		return nil, err
	}
	end := 4 + n + int(headerLength) + int(header.BodyLength)
	if len(shard) < end {
		return nil, errors.New("dbreach: a shard's body past its bytes")
	}
	return shard[:end], nil
}

// A 16 B id from a label.
func dbreachId(label string) sidecar.Id {
	digest := sha256.Sum256([]byte("dbreach " + label))
	return sidecar.Id(digest[:16])
}
