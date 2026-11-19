//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind && !sidecar_http

// §22.8's search row as a harness (SEARCH-M10-40; R-EVS-24, D-SDK-25, D-TEST-14; §16.10's targets and cold contract,
// §18.4's targets row): a generated mailbox of Days days at each of MessagesPerDays messages a day, written as one
// ref's index on a search world (the root's SearchTestWorld, under sidecar_testhooks), its two latest buckets and all,
// and on it, with production's settings and every feature on (CODESTYLE's benchmark rule):
//
//	warm      a desktop that keeps all and holds every message's text, so a search verifies its candidates as a desktop
//	          holding a mirror does: each query's first page over the buckets (scope latest) and over all (scope all,
//	          all held), timed on the wall clock from the call to the first page, p50 and p99 with failed attempts
//	          beside them, against §16.10's and §18.4's desktop targets
//	cold      §16.10's cold contract: a fresh desktop that holds the buckets and not all, all read at ReadByteRate on the
//	          world's fake clock a shard at a time, each query's "search more" timed on that clock: its first progress,
//	          each landed shard's delay to the page carrying its hits, its completion against B / R + 1 s, and the
//	          median and p90 first all hit over the query set, each a delivery time (owner decision 572)
//	quality   ranking and typo quality over the warm desktop: rare-word precision at 5, the top hit holding the word and
//	          verified or confirmed (top-1 with confirmation), and a one-edit typo, searched fuzzy, finding a message
//	          that holds the word in its top 5, against §22.8's 0.40, 0.6 and 0.9 (a phone's 0.8 is phone_bench.go's)
//	roll-up   one roll-up's wall time: the clock moved a window on, the expired bucket rolled into all by the index's
//	          own roller
//
// The corpus is generated (the row's trap): pseudo-words drawn by a Zipf law, each rare word planted in one message's
// subject and a few bodies, and every text from one seed, so a run repeats. 20 Newsgroups, the Japanese and Chinese
// corpora and an HTML-heavy mailbox are external inputs and are not read here; neither are the surrogates, the iOS
// simulator or Safari's wasm, nor a roll-up in wasm. A run below §22.8's scale is a smoke, and says so.
//
// Not safe for concurrent use: one run at a time.

package bench

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest/load"
)

// A generated mailbox: its shape. DefaultBenchCorpusSettings is §22.8's five years at 100 a day.
type BenchCorpusSettings struct {
	Seed int64
	// Days of mail ending at the clock's now, and messages a day.
	Days           int
	MessagesPerDay int
	// The common words, and the Zipf law's exponent they are drawn by.
	VocabularyCount int
	ZipfExponent    float64
	// A pseudo-word's letters: at least WordMinLength, and up to WordLengthSpread more.
	WordMinLength    int
	WordLengthSpread int
	// Words in a subject and in a body.
	SubjectWordCount int
	BodyWordCount    int
	// Rare words, each in one message's subject and body and in RareBodyCount other bodies.
	RareWordCount int
	RareBodyCount int
	// Documents a shard holds before the next opens: about a merge's 1 MB of rows.
	ShardDocumentCount int
}

// §22.8's mailbox: five years at 100 a day.
func DefaultBenchCorpusSettings() *BenchCorpusSettings {
	return &BenchCorpusSettings{
		Seed:               1,
		Days:               5 * 365,
		MessagesPerDay:     100,
		VocabularyCount:    20000,
		ZipfExponent:       1.1,
		WordMinLength:      5,
		WordLengthSpread:   5,
		SubjectWordCount:   5,
		BodyWordCount:      60,
		RareWordCount:      200,
		RareBodyCount:      4,
		ShardDocumentCount: 1400,
	}
}

// One generated message.
type BenchMessage struct {
	Path    string
	Subject string
	Body    string
	Time    time.Time
}

// A rare word's query and its truth.
type BenchRareQuery struct {
	Word string
	// One edit from Word: what a typo search types.
	Typo string
	// The message whose subject holds Word, and every message that holds it.
	IntendedPath string
	Paths        []string
}

// A generated mailbox and what its queries should find.
type BenchCorpus struct {
	Settings *BenchCorpusSettings
	Messages []*BenchMessage
	Rare     []*BenchRareQuery
	// Messages by path.
	byPath map[string]*BenchMessage
}

// A corpus of settings ending at now.
func NewBenchCorpus(settings *BenchCorpusSettings, now time.Time) (*BenchCorpus, error) {
	if settings.Days <= 0 || settings.MessagesPerDay <= 0 || settings.VocabularyCount <= 1 || settings.ShardDocumentCount <= 0 ||
		settings.SubjectWordCount <= 0 || settings.BodyWordCount <= 0 || settings.ZipfExponent <= 1 || settings.WordMinLength < 3 ||
		settings.WordLengthSpread <= 0 {
		return nil, errors.New("bench corpus: days, messages, a vocabulary, words of 3 letters or more, a shard size and an exponent past 1")
	}
	random := rand.New(rand.NewPCG(uint64(settings.Seed), 0x5eed5eed))
	words := map[string]bool{}
	pseudoWord := func() string {
		for {
			const consonants, vowels = "bcdfghjklmnprstvwz", "aeiou"
			length := settings.WordMinLength + random.IntN(settings.WordLengthSpread)
			word := make([]byte, length)
			for index := range word {
				if index%2 == 0 {
					word[index] = consonants[random.IntN(len(consonants))]
				} else {
					word[index] = vowels[random.IntN(len(vowels))]
				}
			}
			if !words[string(word)] {
				words[string(word)] = true
				return string(word)
			}
		}
	}
	vocabulary := make([]string, settings.VocabularyCount)
	for index := range vocabulary {
		vocabulary[index] = pseudoWord()
	}
	zipf := rand.NewZipf(random, settings.ZipfExponent, 1, uint64(settings.VocabularyCount-1))
	draw := func(count int) []string {
		drawn := make([]string, count)
		for index := range drawn {
			drawn[index] = vocabulary[zipf.Uint64()]
		}
		return drawn
	}
	corpus := &BenchCorpus{Settings: settings, byPath: map[string]*BenchMessage{}}
	total := settings.Days * settings.MessagesPerDay
	start := now.Add(-time.Duration(settings.Days) * 24 * time.Hour)
	for index := range total {
		at := start.Add(time.Duration(index) * time.Duration(settings.Days) * 24 * time.Hour / time.Duration(total))
		message := &BenchMessage{
			Path:    fmt.Sprintf("m/%s/%06d.eml", at.UTC().Format("2006-01-02"), index),
			Subject: strings.Join(draw(settings.SubjectWordCount), " "),
			Body:    strings.Join(draw(settings.BodyWordCount), " "),
			Time:    at,
		}
		corpus.Messages = append(corpus.Messages, message)
		corpus.byPath[message.Path] = message
	}
	for range min(settings.RareWordCount, total) {
		word := pseudoWord()
		typo := []byte(word)
		for {
			position := 1 + random.IntN(len(typo)-2)
			typo[position] = "aeiouy"[random.IntN(6)]
			if string(typo) != word && !words[string(typo)] {
				break
			}
			typo = []byte(word)
		}
		words[string(typo)] = true
		// a word among others, as text holds it, never at a text's end, where its last trigram's space is not
		plant := func(text string) string {
			words := strings.Fields(text)
			at := random.IntN(len(words))
			return strings.Join(slices.Insert(words, at, word), " ")
		}
		intended := corpus.Messages[random.IntN(total)]
		intended.Subject = plant(intended.Subject)
		intended.Body = plant(intended.Body)
		query := &BenchRareQuery{Word: word, Typo: string(typo), IntendedPath: intended.Path, Paths: []string{intended.Path}}
		for range settings.RareBodyCount {
			other := corpus.Messages[random.IntN(total)]
			if slices.Contains(query.Paths, other.Path) {
				continue
			}
			other.Body = plant(other.Body)
			query.Paths = append(query.Paths, other.Path)
		}
		corpus.Rare = append(corpus.Rare, query)
	}
	return corpus, nil
}

// The message at path, nil where there is none.
func (self *BenchCorpus) Message(path string) *BenchMessage {
	return self.byPath[path]
}

// The corpus's index on a fresh world at clock: all through the bucket before the previous one, then the previous and
// the current buckets, each as a merge leaves it. The world's repo is a general repo, as a mailbox's m/ files index in
// a file-mode ref. Its writer is writerId.
func (self *BenchCorpus) Index(ctx context.Context, clock sidecar.SearchTestClock, writerId sidecar.Id) (*sidecar.SearchTestWorld, error) {
	world, err := sidecar.NewSearchTestWorld(&sidecar.SearchTestWorldArgs{
		RepoId: benchId("bench repo"), RefId: benchId("bench ref"), Clock: clock, Kind: protocol.RepoKind_REPO_KIND_GENERAL,
	})
	if err != nil {
		return nil, err
	}
	now := clock.Now()
	current := sidecar.SearchTestBucketStartDay(now)
	window := benchWindowDaysAt(now)
	previous := current - window
	partitions := map[uint32][]*sidecar.SearchTestDocument{}
	all := []*sidecar.SearchTestDocument{}
	for _, message := range self.Messages {
		document := &sidecar.SearchTestDocument{Path: message.Path, Version: 1, Title: message.Subject, Text: message.Body, Time: message.Time}
		switch day := sidecar.SearchTestBucketStartDay(message.Time); {
		case day == current || day == previous:
			partitions[day] = append(partitions[day], document)
		case day < previous:
			all = append(all, document)
		default:
			return nil, fmt.Errorf("bench corpus: a message past the clock's bucket at %s", message.Time)
		}
	}
	if 0 < len(all) {
		partition := &sidecar.SearchTestPartition{All: true, RolledThroughDay: previous - window, ShardDocumentCount: self.Settings.ShardDocumentCount}
		if err := world.WriteShards(ctx, writerId, all[len(all)-1].Time, partition, all, nil); err != nil {
			return nil, fmt.Errorf("all: %w", err)
		}
	}
	for _, day := range []uint32{previous, current} {
		documents := partitions[day]
		if len(documents) == 0 {
			continue
		}
		partition := &sidecar.SearchTestPartition{StartDay: day, ShardDocumentCount: self.Settings.ShardDocumentCount}
		if err := world.WriteShards(ctx, writerId, documents[len(documents)-1].Time, partition, documents, nil); err != nil {
			return nil, fmt.Errorf("bucket %d: %w", day, err)
		}
	}
	return world, nil
}

// The days of a general repo's window (§11.14's settings row) as the world lays its buckets out at at: the current
// bucket's start less the previous one's.
func benchWindowDaysAt(at time.Time) uint32 {
	current := sidecar.SearchTestBucketStartDay(at)
	currentStart := time.UnixMilli(0).UTC().Add(time.Duration(current) * 24 * time.Hour)
	return current - sidecar.SearchTestBucketStartDay(currentStart.Add(-time.Millisecond))
}

// A 16 B id from a label.
func benchId(label string) sidecar.Id {
	digest := sha256.Sum256([]byte("bench id " + label))
	return sidecar.Id(digest[:16])
}

// The corpus's text as a desktop holding a mirror reads it: each message's subject as its title and its body, at the
// version the index names, never fetched.
type benchTextSource struct {
	corpus *BenchCorpus
}

// See sidecar.SearchTextSource: the message at the version the index names, never fetched.
func (self *benchTextSource) SearchDocuments(ctx context.Context, request *sidecar.SearchTextRequest) ([]*sidecar.IndexDocument, bool, error) {
	message := self.corpus.Message(string(request.Name))
	if message == nil || request.Version != 1 {
		return nil, false, nil
	}
	document := &sidecar.IndexDocument{
		Kind: sidecar.IndexDocFile, Name: []byte(message.Path), Version: 1, ByteCount: uint64(len(message.Subject) + len(message.Body)),
	}
	// §11.14's field numbers: 4 the title, 5 the body
	document.Fields[4] = []byte(message.Subject)
	document.Fields[5] = []byte(message.Body)
	return []*sidecar.IndexDocument{document}, true, nil
}

// What a search row runs. DefaultSearchBenchSettings is §22.8's.
type SearchBenchSettings struct {
	Corpus *BenchCorpusSettings
	// §22.8's rates: 100 and 300 messages a day.
	MessagesPerDays []int
	// Queries a warm figure is taken over, of the rare words; at most the corpus's.
	WarmQueryCount int
	// Queries the cold contract runs, each on a fresh device in one sync state.
	ColdQueryCount int
	// §16.10's cold contract: all read at 10 MB/s, a read a shard at a time.
	ColdReadByteRate  int64
	ColdReadByteCount int64
	// §16.10's and §18.4's desktop targets, which the report compares: buckets p50 10 ms and p95 50 ms (§18.4's desktop,
	// inside §16.10's 15 ms and 60 ms), a verified page over all p95 500 ms; the cold contract's first report within
	// 500 ms, the desktop's 100 ms arrival bound, the completion's 1 s beside B / R, and §16.10's typical first all hit,
	// median 3 s.
	BucketsP50       time.Duration
	BucketsP95       time.Duration
	AllP95           time.Duration
	ColdFirstReport  time.Duration
	ColdArrival      time.Duration
	ColdSlack        time.Duration
	ColdFirstHitP50  time.Duration
	PrecisionAtFive  float64
	TopOneConfirmed  float64
	TypoTopFive      float64
	QualityHitsCount int
	// A run below these is a smoke: §22.8's five years.
	EvidenceDays int
}

// §22.8's run: both rates over five years, production's settings.
func DefaultSearchBenchSettings() *SearchBenchSettings {
	return &SearchBenchSettings{
		Corpus:            DefaultBenchCorpusSettings(),
		MessagesPerDays:   []int{100, 300},
		WarmQueryCount:    200,
		ColdQueryCount:    20,
		ColdReadByteRate:  10 * 1000 * 1000,
		ColdReadByteCount: 1100 * 1000,
		BucketsP50:        10 * time.Millisecond,
		BucketsP95:        50 * time.Millisecond,
		AllP95:            500 * time.Millisecond,
		ColdFirstReport:   500 * time.Millisecond,
		ColdArrival:       100 * time.Millisecond,
		ColdSlack:         time.Second,
		ColdFirstHitP50:   3 * time.Second,
		PrecisionAtFive:   0.40,
		TopOneConfirmed:   0.6,
		TypoTopFive:       0.9,
		QualityHitsCount:  5,
		EvidenceDays:      5 * 365,
	}
}

// One warm figure: the first page's wall time over a query set, failed attempts beside it (connect/CODESTYLE.md:215).
type BenchLatency struct {
	Queries             int              `json:"queries"`
	LatencyMillis       load.Percentiles `json:"latency_ms"`
	Failed              int64            `json:"failed"`
	FailedLatencyMillis load.Percentiles `json:"failed_latency_ms"`
	FailureKinds        map[string]int64 `json:"failure_kinds"`
	// The target the row compares, 0 where it names none, and whether the figure meets it.
	TargetP50Millis float64 `json:"target_p50_ms"`
	TargetP95Millis float64 `json:"target_p95_ms"`
	Met             bool    `json:"met"`
}

// The latencies of attempts, each its duration and its error, into a figure against p50 and p95 targets.
func benchLatencyOf(durations []time.Duration, errs []error, targetP50 time.Duration, targetP95 time.Duration) *BenchLatency {
	figure := &BenchLatency{Queries: len(durations), FailureKinds: map[string]int64{}}
	successes, failures := []time.Duration{}, []time.Duration{}
	for index, duration := range durations {
		if errs[index] != nil {
			figure.Failed += 1
			figure.FailureKinds[errs[index].Error()] += 1
			failures = append(failures, duration)
			continue
		}
		successes = append(successes, duration)
	}
	figure.LatencyMillis = load.PercentilesOf(successes)
	figure.FailedLatencyMillis = load.PercentilesOf(failures)
	figure.TargetP50Millis = benchMillis(targetP50)
	figure.TargetP95Millis = benchMillis(targetP95)
	figure.Met = figure.Failed == 0 && 0 < len(successes) &&
		(targetP50 <= 0 || figure.LatencyMillis.P50 <= figure.TargetP50Millis) &&
		(targetP95 <= 0 || figure.LatencyMillis.P95 <= figure.TargetP95Millis)
	return figure
}

// A duration in milliseconds, as the reports give them.
func benchMillis(duration time.Duration) float64 {
	return float64(duration) / float64(time.Millisecond)
}

// One query's cold "search more", on the world's clock.
type BenchColdQuery struct {
	// The first progress report's delay from the call, and the longest gap between two reports.
	FirstReportMillis float64 `json:"first_report_ms"`
	LongestGapMillis  float64 `json:"longest_gap_ms"`
	// The longest delay from a shard's landing to the page carrying hits after it.
	ShardDelayMillis float64 `json:"shard_delay_ms"`
	// When the search said complete, against B / R + the slack.
	CompletionMillis float64 `json:"completion_ms"`
	BoundMillis      float64 `json:"bound_ms"`
	// When the first hit from all reached the caller, -1 for none.
	FirstAllHitMillis float64 `json:"first_all_hit_ms"`
	Failure           string  `json:"failure"`
}

// §16.10's cold contract over a query set.
type BenchCold struct {
	AllByteCount int64 `json:"all_byte_count"`
	ReadByteRate int64 `json:"read_byte_rate"`
	Queries      []*BenchColdQuery
	// The first all hit's delivery time over the queries with one: median and p90 among them.
	FirstAllHitMillis load.Percentiles `json:"first_all_hit_ms"`
	Failed            int64            `json:"failed"`
	// Each clause held for every query: the first report and its cadence, the arrival bound, the completion bound; and
	// the typical first all hit's median.
	FirstReportMet bool `json:"first_report_met"`
	ArrivalMet     bool `json:"arrival_met"`
	CompletionMet  bool `json:"completion_met"`
	FirstAllHitMet bool `json:"first_all_hit_met"`
}

// Ranking and typo quality.
type BenchQuality struct {
	Queries          int     `json:"queries"`
	PrecisionAtFive  float64 `json:"precision_at_5"`
	TopOneConfirmed  float64 `json:"top_1_confirmed"`
	TypoTopFive      float64 `json:"typo_top_5"`
	TargetPrecision  float64 `json:"target_precision_at_5"`
	TargetTopOne     float64 `json:"target_top_1"`
	TargetTypo       float64 `json:"target_typo_top_5"`
	Met              bool    `json:"met"`
	Failed           int64   `json:"failed"`
	FailureKinds     map[string]int64
	VerifiedHitCount int `json:"verified_hit_count"`
}

// One rate's figures.
type SearchBenchRate struct {
	MessagesPerDay  int           `json:"messages_per_day"`
	Days            int           `json:"days"`
	MessageCount    int           `json:"message_count"`
	AllByteCount    int64         `json:"all_byte_count"`
	Buckets         *BenchLatency `json:"buckets"`
	All             *BenchLatency `json:"all"`
	Cold            *BenchCold    `json:"cold"`
	Quality         *BenchQuality `json:"quality"`
	RollUpMillis    float64       `json:"roll_up_ms"`
	RollUpCommitted bool          `json:"roll_up_committed"`
}

// The search row's report.
type SearchBenchReport struct {
	Row   string             `json:"row"`
	Rates []*SearchBenchRate `json:"rates"`
	// A run below §22.8's scale, which proves nothing about a target.
	Smoke bool `json:"smoke"`
	// The effective settings, features on (R-TEST-2).
	Settings map[string]string `json:"settings"`
	Notes    []string          `json:"notes"`
}

// A desktop's search settings: production's, every feature on.
func benchDesktopSettings() *sidecar.SidecarSearchSettings {
	return sidecar.DefaultSidecarSettings().Search
}

// A daemon host reports no conditions and reads unmetered.
func benchDesktopConditions() sidecar.SearchConditions {
	return sidecar.SearchConditions{DaemonHost: true}
}

// Runs §22.8's search row at settings on clock, which must stand still but where the row moves it.
func RunSearchBench(ctx context.Context, settings *SearchBenchSettings, clock sidecar.SearchTestClock) (*SearchBenchReport, error) {
	report := &SearchBenchReport{Row: "search", Settings: map[string]string{}}
	desktop := benchDesktopSettings()
	report.Settings["search.page_cpu"] = desktop.PageCpu.String()
	report.Settings["search.page_candidate_count"] = fmt.Sprint(desktop.PageCandidateCount)
	report.Settings["search.daemon_search_count"] = fmt.Sprint(desktop.DaemonSearchCount)
	report.Settings["search.memory_byte_count"] = fmt.Sprint(desktop.MemoryByteCount)
	report.Settings["corpus.days"] = fmt.Sprint(settings.Corpus.Days)
	if settings.Corpus.Days < settings.EvidenceDays {
		report.Smoke = true
		report.Notes = append(report.Notes, fmt.Sprintf("%d days of mail, under §22.8's %d: a smoke", settings.Corpus.Days, settings.EvidenceDays))
	}
	report.Notes = append(report.Notes,
		"generated corpora only: 20 Newsgroups, the CJK corpora and an HTML-heavy mailbox are external inputs",
		"the phone p50 and p99 on the surrogates, an iOS simulator and Safari's wasm, and a roll-up in wasm, are external")
	for _, rate := range settings.MessagesPerDays {
		corpusSettings := *settings.Corpus
		corpusSettings.MessagesPerDay = rate
		figures, err := runSearchBenchRate(ctx, settings, &corpusSettings, clock)
		if err != nil {
			return report, fmt.Errorf("%d a day: %w", rate, err)
		}
		report.Rates = append(report.Rates, figures)
	}
	return report, nil
}

// One rate's figures.
func runSearchBenchRate(ctx context.Context, settings *SearchBenchSettings, corpusSettings *BenchCorpusSettings, clock sidecar.SearchTestClock) (*SearchBenchRate, error) {
	corpus, err := NewBenchCorpus(corpusSettings, clock.Now())
	if err != nil {
		return nil, err
	}
	writerId := benchId("bench writer")
	world, err := corpus.Index(ctx, clock, writerId)
	if err != nil {
		return nil, err
	}
	figures := &SearchBenchRate{
		MessagesPerDay: corpusSettings.MessagesPerDay, Days: corpusSettings.Days, MessageCount: len(corpus.Messages),
		AllByteCount: world.AllByteCount(),
	}
	// warm: a desktop that keeps all and holds the text
	text := &benchTextSource{corpus: corpus}
	desktop, err := sidecar.NewSearchTestNetworkDevice(ctx, &sidecar.SearchTestNetworkDeviceArgs{
		Settings: benchDesktopSettings(), Conditions: benchDesktopConditions, ReadByteCount: 32 * 1024 * 1024,
		Refs: []*sidecar.SearchTestNetworkRef{{World: world}},
		Text: func(repoId sidecar.Id, refId sidecar.Id) sidecar.SearchTextSource { return text },
	})
	if err != nil {
		return nil, err
	}
	defer desktop.Close()
	if err := desktop.Sync(ctx); err != nil {
		return nil, fmt.Errorf("the desktop's sync: %w", err)
	}
	queries := corpus.Rare[:min(settings.WarmQueryCount, len(corpus.Rare))]
	firstPage := func(scope sidecar.SearchScope, text string, fuzzy bool) ([]sidecar.SearchHit, time.Duration, error) {
		started := time.Now()
		stream, err := desktop.Engine().Search(ctx, &sidecar.SearchRequest{Text: text, Scope: scope, Fuzzy: fuzzy})
		if err != nil {
			return nil, time.Since(started), err
		}
		defer stream.Close()
		hits, _, _, err := stream.Next()
		return hits, time.Since(started), err
	}
	for _, scope := range []sidecar.SearchScope{sidecar.SearchLatest, sidecar.SearchAll} {
		durations, errs := []time.Duration{}, []error{}
		for _, query := range queries {
			_, duration, err := firstPage(scope, query.Word, false)
			durations, errs = append(durations, duration), append(errs, err)
		}
		if scope == sidecar.SearchLatest {
			figures.Buckets = benchLatencyOf(durations, errs, settings.BucketsP50, settings.BucketsP95)
		} else {
			figures.All = benchLatencyOf(durations, errs, 0, settings.AllP95)
		}
	}
	figures.Quality = benchQualityOf(settings, queries, func(text string, fuzzy bool) ([]sidecar.SearchHit, error) {
		hits, _, err := firstPage(sidecar.SearchAll, text, fuzzy)
		return hits, err
	})
	figures.Quality.TargetTypo = settings.TypoTopFive
	figures.Quality.Met = figures.Quality.Failed == 0 && settings.PrecisionAtFive <= figures.Quality.PrecisionAtFive &&
		settings.TopOneConfirmed <= figures.Quality.TopOneConfirmed && settings.TypoTopFive <= figures.Quality.TypoTopFive

	if figures.Cold, err = runBenchCold(ctx, settings, corpus, world, clock); err != nil {
		return nil, err
	}

	// one roll-up: the clock a window on, so the previous bucket expires and the roller folds it into all
	clock.Advance(time.Duration(benchWindowDaysAt(clock.Now())) * 24 * time.Hour)
	started := time.Now()
	version, err := world.RollUp(ctx, writerId)
	figures.RollUpMillis = benchMillis(time.Since(started))
	if err != nil {
		return nil, fmt.Errorf("the roll-up: %w", err)
	}
	figures.RollUpCommitted = 0 < version
	return figures, nil
}

// Rare-word precision at 5, the top hit's holding the word with confirmation, and a typo's top 5 holding a message
// that holds the word, over queries searched by search.
func benchQualityOf(settings *SearchBenchSettings, queries []*BenchRareQuery, search func(text string, fuzzy bool) ([]sidecar.SearchHit, error)) *BenchQuality {
	quality := &BenchQuality{
		Queries: len(queries), TargetPrecision: settings.PrecisionAtFive, TargetTopOne: settings.TopOneConfirmed, FailureKinds: map[string]int64{},
	}
	if len(queries) == 0 {
		return quality
	}
	precision, topOne, typo := 0.0, 0, 0
	fail := func(err error) {
		quality.Failed += 1
		quality.FailureKinds[err.Error()] += 1
	}
	for _, query := range queries {
		hits, err := search(query.Word, false)
		if err != nil {
			fail(err)
			continue
		}
		relevant := 0
		top := hits[:min(settings.QualityHitsCount, len(hits))]
		for _, hit := range top {
			if slices.Contains(query.Paths, hit.Path) {
				relevant += 1
			}
			if hit.State == sidecar.SearchVerified {
				quality.VerifiedHitCount += 1
			}
		}
		precision += float64(relevant) / float64(settings.QualityHitsCount)
		if 0 < len(hits) && slices.Contains(query.Paths, hits[0].Path) && (hits[0].State == sidecar.SearchVerified || hits[0].State == sidecar.SearchConfirmed) {
			topOne += 1
		}
		typoHits, err := search(query.Typo, true)
		if err != nil {
			fail(err)
			continue
		}
		if slices.ContainsFunc(typoHits[:min(settings.QualityHitsCount, len(typoHits))], func(hit sidecar.SearchHit) bool {
			return slices.Contains(query.Paths, hit.Path)
		}) {
			typo += 1
		}
	}
	quality.PrecisionAtFive = precision / float64(len(queries))
	quality.TopOneConfirmed = float64(topOne) / float64(len(queries))
	quality.TypoTopFive = float64(typo) / float64(len(queries))
	return quality
}

// §16.10's cold contract over the rare words whose messages all holds: each query a fresh desktop holding the buckets
// and not all, its "search more" read at ColdReadByteRate a shard at a time on the world's clock.
func runBenchCold(ctx context.Context, settings *SearchBenchSettings, corpus *BenchCorpus, world *sidecar.SearchTestWorld, clock sidecar.SearchTestClock) (*BenchCold, error) {
	cold := &BenchCold{AllByteCount: world.AllByteCount(), ReadByteRate: settings.ColdReadByteRate, FirstReportMet: true, ArrivalMet: true, CompletionMet: true}
	if cold.AllByteCount == 0 || settings.ColdReadByteRate <= 0 {
		return cold, nil
	}
	bound := time.Duration(cold.AllByteCount*int64(time.Second)/settings.ColdReadByteRate) + settings.ColdSlack
	firstHits := []time.Duration{}
	for _, query := range corpus.Rare[:min(settings.ColdQueryCount, len(corpus.Rare))] {
		figure := &BenchColdQuery{BoundMillis: benchMillis(bound), FirstAllHitMillis: -1}
		cold.Queries = append(cold.Queries, figure)
		failed := func(err error) {
			cold.Failed += 1
			figure.Failure = err.Error()
		}
		// a desktop before its first round of all: all on demand, as FS-110 reads it
		deviceSettings := benchDesktopSettings()
		deviceSettings.AllPolicy = sidecar.SearchPolicyOnDemand
		device, err := world.NewDevice(ctx, &sidecar.SearchTestDeviceArgs{
			Settings: deviceSettings, Conditions: benchDesktopConditions, ReadByteRate: settings.ColdReadByteRate,
			ReadByteCount: settings.ColdReadByteCount,
		})
		if err != nil {
			return nil, err
		}
		search, err := func() (*sidecar.SearchTestSearch, error) {
			defer device.Close()
			if err := device.Sync(ctx); err != nil {
				return nil, err
			}
			synced := len(device.Fetches())
			search, err := device.Search(ctx, &sidecar.SearchRequest{Text: query.Word, Scope: sidecar.SearchAll}, 1024, nil)
			if err != nil {
				return search, err
			}
			figure.ShardDelayMillis = benchMillis(benchShardDelay(device.Fetches()[synced:], search))
			return search, nil
		}()
		if err != nil {
			failed(err)
			continue
		}
		started := search.Started
		reportTimes := []time.Time{}
		for _, report := range search.Reports {
			reportTimes = append(reportTimes, report.At)
		}
		if 0 < len(reportTimes) {
			figure.FirstReportMillis = benchMillis(reportTimes[0].Sub(started))
			for index := 1; index < len(reportTimes); index += 1 {
				figure.LongestGapMillis = max(figure.LongestGapMillis, benchMillis(reportTimes[index].Sub(reportTimes[index-1])))
			}
		}
		for _, page := range search.Pages {
			if page.Done {
				figure.CompletionMillis = benchMillis(page.At.Sub(started))
			}
			if figure.FirstAllHitMillis < 0 && slices.ContainsFunc(page.Hits, func(hit sidecar.SearchHit) bool { return hit.Partition == sidecar.SearchPartitionAll }) {
				figure.FirstAllHitMillis = benchMillis(page.At.Sub(started))
				firstHits = append(firstHits, page.At.Sub(started))
			}
		}
		if len(reportTimes) == 0 || settings.ColdFirstReport < reportTimes[0].Sub(started) || benchMillis(time.Second) < figure.LongestGapMillis {
			cold.FirstReportMet = false
		}
		if benchMillis(settings.ColdArrival) < figure.ShardDelayMillis {
			cold.ArrivalMet = false
		}
		if figure.CompletionMillis == 0 || figure.BoundMillis < figure.CompletionMillis {
			cold.CompletionMet = false
		}
	}
	cold.FirstAllHitMillis = load.PercentilesOf(firstHits)
	cold.FirstAllHitMet = 0 < len(firstHits) && cold.FirstAllHitMillis.P50 <= benchMillis(settings.ColdFirstHitP50)
	return cold, nil
}

// The longest delay from an all shard's landing to the first page after it carrying a hit from all, among the shards
// a hit followed.
func benchShardDelay(fetches []sidecar.SearchTestFetch, search *sidecar.SearchTestSearch) time.Duration {
	longest := time.Duration(0)
	for _, page := range search.Pages {
		if !slices.ContainsFunc(page.Hits, func(hit sidecar.SearchHit) bool { return hit.Partition == sidecar.SearchPartitionAll }) {
			continue
		}
		var landed time.Time
		for _, fetch := range fetches {
			if strings.Contains(fetch.Path, "/a/") && !strings.HasSuffix(fetch.Path, "/a/m") && !fetch.At.After(page.At) {
				landed = fetch.At
			}
		}
		if !landed.IsZero() {
			longest = max(longest, page.At.Sub(landed))
		}
	}
	return longest
}
