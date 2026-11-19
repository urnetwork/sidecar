//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind && !sidecar_http

// §22.8's phone row as a harness (SEARCH-M10-40; D-SDK-25, D-SDK-21; §18.4's targets and caps rows): for each phone
// host class, on the search world search_bench.go writes, with the host's settings as sdk's host classes set them:
//
//	decrypt   all's shards decrypted in 64 KiB frames, as a phone opens a kept record a frame at a time: DecryptByteCount
//	          sealed as evs seals a record, read back through EvsRecordReader frame by frame, in MB/s on the wall clock
//	memory    the heap a search holds over the buckets, sampled after a forced collection at each record it opens and
//	          each page (sidecartest's SearchHeapSampler), its peak less its start against §18.4's working set: 4 MiB
//	          a search on the phones and 8 MiB on the page Worker, beside the 256 KiB of version-table pages
//	more      a "search more" over the whole mailbox with all not held: on first fetch, its completion on the world's
//	          fake clock at ReadByteRate, and cached, the same search again on the wall clock
//	quality   rare-word precision at 5, top-1 with confirmation and a one-edit typo in the top 5 from a phone, which
//	          holds no text, against §22.8's phone typo bar of 0.8
//
// These run in this process on this host: §22.8's figures are the T4 surrogates' (the ios32 and Android cells), wasm in
// Node and Safari's through Playwright, which are external, as is a peak that CheckWithin can answer for, which only a
// search heap process can (search_heap_process.go): a peak here is reported with whether it was taken in one.
//
// Not safe for concurrent use: one run at a time.

package bench

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/load"
)

// One phone host class, as sdk's host classes and §18.4 set it.
type PhoneBenchHost struct {
	Name string
	// The host's search settings.
	Settings func() *sidecar.SidecarSearchSettings
	// §18.4's working set of one search, beside the version-table pages.
	WorkingSetByteCount int64
	// §22.8's typo bar on this host.
	TypoTopFive float64
}

// The phones' settings over the core's defaults (sdk's phone host class; sidecartest/fault's searchPhoneSettings).
func benchPhoneSettings() *sidecar.SidecarSearchSettings {
	settings := sidecar.DefaultSidecarSettings().Search
	settings.AllPolicy = sidecar.SearchPolicyWifiCharging
	settings.MemoryByteCount = 4*1024*1024 + 256*1024
	settings.DaemonSearchCount = 1
	settings.AllCacheByteCount = 256 * 1024 * 1024
	settings.UnusedAllAge = 30 * 24 * time.Hour
	settings.DirectoryBuckets = false
	settings.SyncRoundCount = 1
	settings.RemoteServe = false
	settings.RemoteAsk = true
	return settings
}

// The page Worker's (§18.4's caps and targets rows).
func benchWorkerSettings() *sidecar.SidecarSearchSettings {
	settings := benchPhoneSettings()
	settings.MemoryByteCount = 8*1024*1024 + 256*1024
	settings.AllCacheByteCount = 128 * 1024 * 1024
	settings.RemoteAsk = false
	return settings
}

// A phone on Wi-Fi while charging, in the foreground, as a "search more" runs.
func benchPhoneConditions() sidecar.SearchConditions {
	return sidecar.SearchConditions{Unmetered: true, Charging: true, Reported: true, Foreground: true}
}

// What a phone row runs. DefaultPhoneBenchSettings is §22.8's.
type PhoneBenchSettings struct {
	Corpus *BenchCorpusSettings
	Hosts  []*PhoneBenchHost
	// Bytes the decrypt figure seals and reads back: 64 MiB, all's youngest few shards' worth.
	DecryptByteCount int64
	// Searches over the buckets the memory figure samples, of the corpus's rare words.
	MemoryQueryCount int
	// The "search more"'s read rate on the world's clock, and a read's most: 10 MB/s and a shard, as the cold contract's.
	MoreReadByteRate  int64
	MoreReadByteCount int64
	// Quality queries, of the rare words.
	QualityQueryCount int
	PrecisionAtFive   float64
	TopOneConfirmed   float64
	QualityHitsCount  int
	// A run below this is a smoke: §22.8's five years.
	EvidenceDays int
}

func DefaultPhoneBenchSettings() *PhoneBenchSettings {
	return &PhoneBenchSettings{
		Corpus: DefaultBenchCorpusSettings(),
		Hosts: []*PhoneBenchHost{
			{Name: "ios32", Settings: benchPhoneSettings, WorkingSetByteCount: 4 * 1024 * 1024, TypoTopFive: 0.8},
			{Name: "android", Settings: benchPhoneSettings, WorkingSetByteCount: 4 * 1024 * 1024, TypoTopFive: 0.8},
			{Name: "worker", Settings: benchWorkerSettings, WorkingSetByteCount: 8 * 1024 * 1024, TypoTopFive: 0.8},
		},
		DecryptByteCount:  64 * 1024 * 1024,
		MemoryQueryCount:  50,
		MoreReadByteRate:  10 * 1000 * 1000,
		MoreReadByteCount: 1100 * 1000,
		QualityQueryCount: 200,
		PrecisionAtFive:   0.40,
		TopOneConfirmed:   0.6,
		QualityHitsCount:  5,
		EvidenceDays:      5 * 365,
	}
}

// A "search more" over the whole mailbox.
type PhoneBenchMore struct {
	// all's bytes, and those the first call fetched.
	AllByteCount     int64 `json:"all_byte_count"`
	FetchedByteCount int64 `json:"fetched_byte_count"`
	// The first call's completion on the world's clock, at ReadByteRate; the cached call's on the wall clock.
	FirstFetchMillis float64 `json:"first_fetch_ms"`
	CachedMillis     float64 `json:"cached_ms"`
	// Hits each call gave, which agree.
	FirstHitCount  int    `json:"first_hit_count"`
	CachedHitCount int    `json:"cached_hit_count"`
	Failure        string `json:"failure"`
}

// One host's figures.
type PhoneBenchHostFigures struct {
	Host string `json:"host"`
	// Decryption in 64 KiB frames.
	DecryptByteCount          int64   `json:"decrypt_byte_count"`
	DecryptFrameCount         int     `json:"decrypt_frame_count"`
	DecryptMegabytesPerSecond float64 `json:"decrypt_mb_per_s"`
	// The heap's peak over the memory figure's searches, less its start, and the budget it is held to: the working set
	// beside the version-table pages.
	PeakHeapGrowthByteCount int64            `json:"peak_heap_growth_byte_count"`
	PeakLabel               string           `json:"peak_label"`
	BudgetByteCount         int64            `json:"budget_byte_count"`
	WithinBudget            bool             `json:"within_budget"`
	HeapProcess             bool             `json:"heap_process"`
	MemorySearches          int              `json:"memory_searches"`
	MemoryLatencyMillis     load.Percentiles `json:"memory_latency_ms"`
	MemoryFailed            int64            `json:"memory_failed"`
	More                    *PhoneBenchMore  `json:"more"`
	Quality                 *BenchQuality    `json:"quality"`
}

// The phone row's report.
type PhoneBenchReport struct {
	Row      string                   `json:"row"`
	Hosts    []*PhoneBenchHostFigures `json:"hosts"`
	Smoke    bool                     `json:"smoke"`
	Settings map[string]string        `json:"settings"`
	Notes    []string                 `json:"notes"`
}

// Runs §22.8's phone row at settings on clock, which must stand still but where the row moves it.
func RunPhoneBench(ctx context.Context, settings *PhoneBenchSettings, clock sidecar.SearchTestClock) (*PhoneBenchReport, error) {
	report := &PhoneBenchReport{Row: "phone", Settings: map[string]string{
		"corpus.days": fmt.Sprint(settings.Corpus.Days), "corpus.messages_per_day": fmt.Sprint(settings.Corpus.MessagesPerDay),
		"decrypt_byte_count": fmt.Sprint(settings.DecryptByteCount), "frame_byte_count": fmt.Sprint(sidecar.EvsRecordFrameByteCount),
	}}
	if settings.Corpus.Days < settings.EvidenceDays {
		report.Smoke = true
		report.Notes = append(report.Notes, fmt.Sprintf("%d days of mail, under §22.8's %d: a smoke", settings.Corpus.Days, settings.EvidenceDays))
	}
	if !sidecartest.InSearchHeapProcess() {
		report.Notes = append(report.Notes, "the heap was sampled outside a search heap process, so no peak here is CheckWithin's answer")
	}
	report.Notes = append(report.Notes, "run in this process: the T4 surrogates, wasm in Node and Safari's wasm are external")
	corpus, err := NewBenchCorpus(settings.Corpus, clock.Now())
	if err != nil {
		return nil, err
	}
	world, err := corpus.Index(ctx, clock, benchId("bench writer"))
	if err != nil {
		return nil, err
	}
	for _, host := range settings.Hosts {
		figures, err := runPhoneBenchHost(ctx, settings, host, corpus, world)
		if err != nil {
			return report, fmt.Errorf("%s: %w", host.Name, err)
		}
		report.Hosts = append(report.Hosts, figures)
	}
	return report, nil
}

// One host's figures.
func runPhoneBenchHost(ctx context.Context, settings *PhoneBenchSettings, host *PhoneBenchHost, corpus *BenchCorpus, world *sidecar.SearchTestWorld) (*PhoneBenchHostFigures, error) {
	figures := &PhoneBenchHostFigures{Host: host.Name, HeapProcess: sidecartest.InSearchHeapProcess()}
	if err := benchDecrypt(world, settings.DecryptByteCount, figures); err != nil {
		return nil, err
	}

	// memory over the buckets: the sampler fed at each record the search opens and each page
	var sampler *sidecartest.SearchHeapSampler
	device, err := world.NewDevice(ctx, &sidecar.SearchTestDeviceArgs{
		Settings: host.Settings(), Conditions: benchPhoneConditions, ReadByteCount: 32 * 1024 * 1024,
		OnRecord: func() {
			if sampler != nil {
				sampler.SampleHoldingSlot("record")
			}
		},
	})
	if err != nil {
		return nil, err
	}
	defer device.Close()
	if err := device.Sync(ctx); err != nil {
		return nil, fmt.Errorf("the phone's sync: %w", err)
	}
	figures.BudgetByteCount = host.WorkingSetByteCount + 256*1024
	sampler = sidecartest.NewSearchHeapSamplerLeavingOut(device.CacheByteCount)
	durations, errs := []time.Duration{}, []error{}
	for _, query := range corpus.Rare[:min(settings.MemoryQueryCount, len(corpus.Rare))] {
		started := time.Now()
		_, err := device.Search(ctx, &sidecar.SearchRequest{Text: query.Word, Scope: sidecar.SearchLatest}, 64, func(page *sidecar.SearchTestPage) {
			sampler.Sample("page")
		})
		durations, errs = append(durations, time.Since(started)), append(errs, err)
	}
	peak := sampler.Peak()
	figures.PeakHeapGrowthByteCount, figures.PeakLabel = peak.GrowthByteCount, peak.Label
	figures.WithinBudget = figures.PeakHeapGrowthByteCount <= figures.BudgetByteCount
	latency := benchLatencyOf(durations, errs, 0, 0)
	figures.MemorySearches, figures.MemoryLatencyMillis, figures.MemoryFailed = latency.Queries, latency.LatencyMillis, latency.Failed

	// quality from the phone, which holds no text
	queries := corpus.Rare[:min(settings.QualityQueryCount, len(corpus.Rare))]
	qualitySettings := &SearchBenchSettings{PrecisionAtFive: settings.PrecisionAtFive, TopOneConfirmed: settings.TopOneConfirmed, TypoTopFive: host.TypoTopFive, QualityHitsCount: settings.QualityHitsCount}
	figures.Quality = benchQualityOf(qualitySettings, queries, func(text string, fuzzy bool) ([]sidecar.SearchHit, error) {
		search, err := device.Search(ctx, &sidecar.SearchRequest{Text: text, Scope: sidecar.SearchLatest, Fuzzy: fuzzy}, 64, nil)
		if err != nil {
			return nil, err
		}
		return search.Hits(), nil
	})
	figures.Quality.TargetTypo = host.TypoTopFive
	figures.Quality.Met = figures.Quality.Failed == 0 && settings.PrecisionAtFive <= figures.Quality.PrecisionAtFive &&
		settings.TopOneConfirmed <= figures.Quality.TopOneConfirmed && host.TypoTopFive <= figures.Quality.TypoTopFive

	figures.More = benchSearchMore(ctx, settings, host, corpus, world)
	return figures, nil
}

// all's bytes sealed as evs seals a kept record and read back in 64 KiB frames: the decrypt figure.
func benchDecrypt(world *sidecar.SearchTestWorld, byteCount int64, figures *PhoneBenchHostFigures) error {
	if byteCount <= 0 {
		return nil
	}
	repoKey := world.RepoKey()
	manifestKey, err := sidecar.NewEvsManifestKey(repoKey)
	if err != nil {
		return err
	}
	objectKey := sidecar.NewEvsObjectKey()
	fileId := sidecar.NewId()
	header := &sidecar.EvsRecordHeader{
		RecordId: sidecar.NewId(), Generation: 1, BodyLength: uint64(byteCount), Kind: protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT,
		KeyRefKind: protocol.EvsKeyRefKind_EVS_KEY_REF_CONTAINER, OidKind: protocol.EvsOidKind_EVS_OID_SHA1,
	}
	sealed := &bytes.Buffer{}
	writer := sidecar.NewEvsRecordWriter()
	if err := writer.Begin(sealed, manifestKey, objectKey, fileId, header); err != nil {
		return err
	}
	chunk := bytes.Repeat([]byte("shard row bytes "), sidecar.EvsRecordFrameByteCount/16)
	for written := int64(0); written < byteCount; {
		part := chunk[:min(int64(len(chunk)), byteCount-written)]
		if _, err := writer.Write(part); err != nil {
			return err
		}
		written += int64(len(part))
	}
	if err := writer.Close(); err != nil {
		return err
	}
	opened := writer.Header()
	reader := sidecar.NewEvsRecordReader()
	body := bytes.NewReader(sealed.Bytes()[sidecar.EvsRecordHeaderByteCount:])
	started := time.Now()
	if err := reader.Begin(body, &opened, objectKey, world.RepoId(), fileId); err != nil {
		return err
	}
	frame := make([]byte, sidecar.EvsRecordFrameByteCount)
	read, frames := int64(0), 0
	for {
		count, err := io.ReadFull(reader, frame)
		read += int64(count)
		if 0 < count {
			frames += 1
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return err
		}
	}
	elapsed := time.Since(started)
	if read != byteCount {
		return fmt.Errorf("decrypted %d B of %d", read, byteCount)
	}
	figures.DecryptByteCount, figures.DecryptFrameCount = read, frames
	figures.DecryptMegabytesPerSecond = float64(read) / 1000 / 1000 / max(elapsed.Seconds(), 1e-9)
	return nil
}

// A "search more" over the mailbox with all not held, then again from the cache.
func benchSearchMore(ctx context.Context, settings *PhoneBenchSettings, host *PhoneBenchHost, corpus *BenchCorpus, world *sidecar.SearchTestWorld) *PhoneBenchMore {
	more := &PhoneBenchMore{AllByteCount: world.AllByteCount()}
	if len(corpus.Rare) == 0 {
		more.Failure = "no query"
		return more
	}
	hostSettings := host.Settings()
	hostSettings.AllPolicy = sidecar.SearchPolicyOnDemand
	device, err := world.NewDevice(ctx, &sidecar.SearchTestDeviceArgs{
		Settings: hostSettings, Conditions: benchPhoneConditions, ReadByteRate: settings.MoreReadByteRate, ReadByteCount: settings.MoreReadByteCount,
	})
	if err != nil {
		more.Failure = err.Error()
		return more
	}
	defer device.Close()
	if err := device.Sync(ctx); err != nil {
		more.Failure = err.Error()
		return more
	}
	synced := int64(0)
	for _, fetch := range device.Fetches() {
		synced += int64(fetch.ByteCount)
	}
	query := corpus.Rare[0].Word
	first, err := device.Search(ctx, &sidecar.SearchRequest{Text: query, Scope: sidecar.SearchAll}, 1024, nil)
	if err != nil {
		more.Failure = err.Error()
		return more
	}
	for _, fetch := range device.Fetches() {
		more.FetchedByteCount += int64(fetch.ByteCount)
	}
	more.FetchedByteCount -= synced
	if 0 < len(first.Pages) {
		more.FirstFetchMillis = benchMillis(first.Pages[len(first.Pages)-1].At.Sub(first.Started))
	}
	more.FirstHitCount = len(first.Hits())
	started := time.Now()
	cached, err := device.Search(ctx, &sidecar.SearchRequest{Text: query, Scope: sidecar.SearchAll}, 1024, nil)
	more.CachedMillis = benchMillis(time.Since(started))
	if err != nil {
		more.Failure = err.Error()
		return more
	}
	more.CachedHitCount = len(cached.Hits())
	return more
}
