//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind && !sidecar_http

// §22.8's remote row as a harness (SEARCH-M10-40; R-CORE-19, D-SDK-25; §18.4's remote targets, §16.10's targets;
// DESIGN-DETAILS 7.2.8): on sidecartest's remote team (search_remote_world.go), its m's vault holding the generated
// mailbox search_bench.go writes, m's indexers serving it from their text, and RequesterCount more phones of m beside
// the team's own, with production's settings and every feature on (CODESTYLE's benchmark rule):
//
//	tap       m's phone's "search more" for a rare word, from the call to its first page and to its next, p50 and p95
//	          with failed attempts beside them: cold, each extra phone's first search, its pair's first exchange; and
//	          pre-warmed, the phone's later ones; each split into the indexer's compute for the page (its handler's own
//	          time) and the rest, the exchange and the phone's own work, which T3's real relays and netem add their round
//	          trip to (7.2.8: about 100 ms outside the network)
//	service   every page the indexers computed, their handlers' time: the indexer's service time on this host
//	load      the extra phones searching at once, as simulated requesters, while the indexer runs its own searches of
//	          its cache: those local first pages against §16.10's targets (p50 15 ms, p95 60 ms), and the refusals the
//	          remote budget answered
//
// On T2 there is no relay, so a tap here is compute and in-process work: §22.8's figures are T3's, with real relays and
// netem (Wi-Fi 30 ms RTT, LTE 75 ms and 300 ms at p50 and p95), on desktop amd64 and arm64 and a NAS-class host, at 100
// and 1,000 requesters, and on T4's surrogates from the later of M10's and M8's exits, all external; as are the
// 50-runs-a-day vault, which waits on the record's documents, and failover within a phone's timeout, which FS-83 holds.
// A run below the row's scale is a smoke, and says so. Not safe for concurrent use.

package bench

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/load"
)

// What a remote row runs. DefaultRemoteBenchSettings is §22.8's.
type RemoteBenchSettings struct {
	Corpus *BenchCorpusSettings
	// Pre-warmed searches the phone runs, of the rare words; each asks its first page and its next, PageSize hits a page.
	TapCount int
	PageSize int
	// Simulated requesters: phones of m beside the team's own; each one's first search is a cold tap.
	RequesterCount int
	// Searches each requester runs while the load runs, and the indexer's own searches beside them.
	RequesterSearchCount int
	LocalSearchCount     int
	// §18.4's Wi-Fi remote targets, pre-warmed: first page p50 300 ms and p95 1 s, a later page 250 ms and 800 ms; cold
	// adds 500 ms and 1.5 s. §16.10's local targets: p50 15 ms, p95 60 ms.
	FirstP50, FirstP95, NextP50, NextP95, ColdAddP50, ColdAddP95, LocalP50, LocalP95 time.Duration
	// A run below these is a smoke: five years of mail and §22.8's 100 requesters.
	EvidenceDays           int
	EvidenceRequesterCount int
}

// §22.8's run: five years of mail, 100 requesters.
func DefaultRemoteBenchSettings() *RemoteBenchSettings {
	return &RemoteBenchSettings{
		Corpus:                 DefaultBenchCorpusSettings(),
		TapCount:               100,
		PageSize:               10,
		RequesterCount:         100,
		RequesterSearchCount:   4,
		LocalSearchCount:       200,
		FirstP50:               300 * time.Millisecond,
		FirstP95:               time.Second,
		NextP50:                250 * time.Millisecond,
		NextP95:                800 * time.Millisecond,
		ColdAddP50:             500 * time.Millisecond,
		ColdAddP95:             1500 * time.Millisecond,
		LocalP50:               15 * time.Millisecond,
		LocalP95:               60 * time.Millisecond,
		EvidenceDays:           5 * 365,
		EvidenceRequesterCount: 100,
	}
}

// One tap figure, and its two parts.
type RemoteBenchTap struct {
	// From the call to the page.
	Tap *BenchLatency `json:"tap"`
	// The indexers' handlers' time for the page's request, and the rest.
	ComputeMillis load.Percentiles `json:"compute_ms"`
	RestMillis    load.Percentiles `json:"rest_ms"`
}

// The remote row's report.
type RemoteBenchReport struct {
	Row          string `json:"row"`
	MessageCount int    `json:"message_count"`
	// Pre-warmed first and next pages, and cold first pages.
	First *RemoteBenchTap `json:"first"`
	Next  *RemoteBenchTap `json:"next"`
	Cold  *RemoteBenchTap `json:"cold"`
	// Every page the indexers computed.
	ServiceMillis load.Percentiles `json:"service_ms"`
	// The load: the requesters, their searches and the budget's refusals among their pages, and the indexer's own first
	// pages meanwhile.
	Requesters     int           `json:"requesters"`
	LoadSearches   int64         `json:"load_searches"`
	LoadFailed     int64         `json:"load_failed"`
	BudgetRefusals int64         `json:"budget_refusals"`
	Local          *BenchLatency `json:"local"`
	Smoke          bool          `json:"smoke"`
	Settings       map[string]string
	Notes          []string `json:"notes"`
}

// Runs §22.8's remote row at settings on tier's network, which the team's clock (the tier's) stands still on.
func RunRemoteBench(ctx context.Context, settings *RemoteBenchSettings, tier *sidecartest.AdmissionTier) (*RemoteBenchReport, error) {
	report := &RemoteBenchReport{Row: "remote", Requesters: settings.RequesterCount, Settings: map[string]string{
		"corpus.days": fmt.Sprint(settings.Corpus.Days), "corpus.messages_per_day": fmt.Sprint(settings.Corpus.MessagesPerDay),
		"requesters": fmt.Sprint(settings.RequesterCount),
	}}
	if settings.Corpus.Days < settings.EvidenceDays || settings.RequesterCount < settings.EvidenceRequesterCount {
		report.Smoke = true
		report.Notes = append(report.Notes, fmt.Sprintf("%d days and %d requesters, under §22.8's %d and %d: a smoke",
			settings.Corpus.Days, settings.RequesterCount, settings.EvidenceDays, settings.EvidenceRequesterCount))
	}
	report.Notes = append(report.Notes, "no relay on T2: a tap is the indexer's compute and in-process work, T3's relays and netem add the round trip")
	corpus, err := NewBenchCorpus(settings.Corpus, tier.Clock.Now())
	if err != nil {
		return nil, err
	}
	report.MessageCount = len(corpus.Messages)
	text := &benchTextSource{corpus: corpus}
	team, err := sidecartest.NewSearchRemoteTeam(ctx, &sidecartest.SearchRemoteTeamArgs{
		Tier: tier, Requesters: settings.RequesterCount,
		Documents: func(repo string) []*sidecar.SearchTestDocument {
			if repo != "m vault" {
				return nil
			}
			documents := []*sidecar.SearchTestDocument{}
			for _, message := range corpus.Messages {
				documents = append(documents, &sidecar.SearchTestDocument{Path: message.Path, Version: 1, Title: message.Subject, Text: message.Body, Time: message.Time})
			}
			return documents
		},
		Text: func(indexer string, repo string) sidecar.SearchTextSource {
			if repo != "m vault" {
				return nil
			}
			return text
		},
	})
	if err != nil {
		return nil, err
	}
	defer team.Close()
	vault := []sidecar.Id{team.RepoId("m vault")}
	queries := corpus.Rare
	if len(queries) == 0 {
		return nil, errors.New("remote bench: a corpus with no rare word")
	}
	// one search's taps: its first page and its next, each with its compute
	type tap struct {
		durations []time.Duration
		computes  []time.Duration
		// whether an indexer was asked the page, which a page merged from what earlier pages held needs not
		asked []bool
		err   error
	}
	search := func(requester *sidecartest.SearchRemoteRequester, query string) tap {
		pages, err := requester.Search(ctx, &sidecar.SearchRequest{Text: query, Repos: vault, PageSize: settings.PageSize}, 2)
		if err != nil {
			return tap{err: err}
		}
		found := tap{durations: pages.PageTimes}
		for index := range pages.PageTimes {
			compute, asked := time.Duration(0), false
			for _, call := range pages.Calls {
				if call.Request != nil && int(call.Request.GetPage()) == index {
					compute, asked = max(compute, call.HandleDuration), true
				}
			}
			found.computes = append(found.computes, compute)
			found.asked = append(found.asked, asked)
		}
		return found
	}
	figures := func(taps []tap, page int, targetP50 time.Duration, targetP95 time.Duration) *RemoteBenchTap {
		durations, errs, computes, rests := []time.Duration{}, []error{}, []time.Duration{}, []time.Duration{}
		for _, found := range taps {
			if found.err != nil {
				durations, errs = append(durations, 0), append(errs, found.err)
				continue
			}
			if len(found.durations) <= page || !found.asked[page] {
				// no such page, or none an indexer was asked: not a remote page's tap
				continue
			}
			durations, errs = append(durations, found.durations[page]), append(errs, nil)
			computes = append(computes, found.computes[page])
			rests = append(rests, max(0, found.durations[page]-found.computes[page]))
		}
		return &RemoteBenchTap{Tap: benchLatencyOf(durations, errs, targetP50, targetP95), ComputeMillis: load.PercentilesOf(computes), RestMillis: load.PercentilesOf(rests)}
	}
	cold := []tap{}
	for index, requester := range team.Requesters {
		cold = append(cold, search(requester, queries[index%len(queries)].Word))
	}
	warm := []tap{}
	for index := range settings.TapCount {
		warm = append(warm, search(team.Phone, queries[index%len(queries)].Word))
	}
	report.First = figures(warm, 0, settings.FirstP50, settings.FirstP95)
	report.Next = figures(warm, 1, settings.NextP50, settings.NextP95)
	if report.Next.Tap.Queries == 0 {
		report.Notes = append(report.Notes, "no search asked an indexer a second page: each query's matches fit its first, so the next-page figure holds none")
	}
	report.Cold = figures(cold, 0, settings.FirstP50+settings.ColdAddP50, settings.FirstP95+settings.ColdAddP95)

	// the load: every requester at once, the indexer's own searches beside them
	before, _ := team.Remote.Calls()
	var wait sync.WaitGroup
	var stateLock sync.Mutex
	for index, requester := range team.Requesters {
		wait.Go(func() {
			for n := range settings.RequesterSearchCount {
				found := search(requester, queries[(index+n)%len(queries)].Word)
				stateLock.Lock()
				report.LoadSearches += 1
				if found.err != nil {
					report.LoadFailed += 1
				}
				stateLock.Unlock()
			}
		})
	}
	indexer := team.Indexers["m nas"].Device.Engine()
	durations, errs := []time.Duration{}, []error{}
	for index := range settings.LocalSearchCount {
		started := time.Now()
		stream, err := indexer.Search(ctx, &sidecar.SearchRequest{Text: queries[index%len(queries)].Word, Scope: sidecar.SearchLatest})
		if err == nil {
			_, _, _, err = stream.Next()
			stream.Close()
		}
		durations, errs = append(durations, time.Since(started)), append(errs, err)
	}
	wait.Wait()
	report.Local = benchLatencyOf(durations, errs, settings.LocalP50, settings.LocalP95)
	calls, _ := team.Remote.Calls()
	services := []time.Duration{}
	for index, call := range calls {
		if call.Err == nil && 0 < call.ReplyByteCount {
			services = append(services, call.HandleDuration)
		}
		var refusal *sidecar.SidecarRemoteRefusal
		if len(before) <= index && errors.As(call.Err, &refusal) {
			report.BudgetRefusals += 1
		}
	}
	report.ServiceMillis = load.PercentilesOf(services)
	return report, nil
}
