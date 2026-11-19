//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind && !sidecar_http

package sidecartest

// S11 on T2 (§22.7's S11, F11; FS-77, FS-80; owner decision 172; SEARCH-M10-39), under the scenario harness and its
// guard, its query and its entry's words canaries: a writer's push of an entry lands in another device's next search
// once that device's sync takes its index entry; a device reading a repo by an EvsShare deposits its read receipt
// before it reads the repo's first index object; an erasure's CUT, once the device's round takes it and the repo's
// searches end as CORE-M10-04's ApplyCut ends them (no composition wires that hint here), ends an open cursor, the next
// page answering cursor_expired, and a new search misses the document; and two searches with different queries from
// one sync state send evs the same requests.
//
// Not here, each S11's and SEARCH-M10-39's report's: a claim filed through the record and its card push in a team
// network, or a vault's companion push, with owner decision 172's minute and five minutes (the record's documents and
// the companion's composition are not built over evs); hits grouped by agent, active first; an untrusted hit's stub
// and include's taint first; a parked device's search omitting its member's vault as consent pending; the caches'
// postings emptied before the erasure's hint is acknowledged; and T3.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

func TestScenarioS11(t *testing.T) {
	RunScenario(t, &Scenario{Id: "S11", Run: s11Run}, nil)
}

func s11Run(ctx context.Context, run *ScenarioRun) error {
	clock := run.Net.Clock()
	query, entry := run.CanaryText("search query"), run.CanaryText("entry text")
	worlds := map[string]*sidecar.SearchTestWorld{}
	for _, name := range []string{"notes", "shared"} {
		world, err := sidecar.NewSearchTestWorld(&sidecar.SearchTestWorldArgs{
			RepoId: searchWorldId("s11 repo " + name), RefId: searchWorldId("s11 ref " + name), Clock: clock, Kind: protocol.RepoKind_REPO_KIND_GENERAL,
		})
		if err != nil {
			return err
		}
		worlds[name] = world
	}
	writer := searchWorldId("s11 writer")
	documents := []*sidecar.SearchTestDocument{
		{Path: "notes/a.md", Version: 1, Title: "a note", Text: "the " + query + " is here", Time: clock.Now()},
		{Path: "notes/b.md", Version: 1, Title: "another", Text: "nothing searched", Time: clock.Now()},
	}
	for _, world := range worlds {
		if err := world.PushDocuments(ctx, writer, clock.Now(), documents); err != nil {
			return err
		}
	}
	// the reader: the notes repo its own, the shared one by an EvsShare, its receipts counted against its reads
	receipts := []int{}
	var reader *sidecar.SearchTestNetworkDevice
	reader, err := sidecar.NewSearchTestNetworkDevice(ctx, &sidecar.SearchTestNetworkDeviceArgs{
		Settings: sidecar.DefaultSidecarSettings().Search, Conditions: func() sidecar.SearchConditions { return sidecar.SearchConditions{DaemonHost: true} },
		ReadByteCount: 32 * 1024 * 1024,
		Refs: []*sidecar.SearchTestNetworkRef{{World: worlds["notes"]}, {World: worlds["shared"], NonWriter: true, Receipt: func(ctx context.Context, paths []string) error {
			receipts = append(receipts, len(reader.Fetches(worlds["shared"].RepoId())))
			return nil
		}}},
	})
	if err != nil {
		return err
	}
	defer reader.Close()
	if err := reader.Sync(ctx); err != nil {
		return err
	}
	if len(receipts) == 0 || receipts[0] != 0 || len(reader.Fetches(worlds["shared"].RepoId())) == 0 {
		return fmt.Errorf("the shared repo's receipts came at %v of its reads", receipts)
	}
	search := func(text string, pageSize int) (*sidecar.SearchStream, error) {
		return reader.Engine().Search(ctx, &sidecar.SearchRequest{Text: text, Scope: sidecar.SearchAll, PageSize: pageSize})
	}
	collect := func(text string) ([]sidecar.SearchHit, []string, error) {
		before := map[sidecar.Id]int{}
		for _, world := range worlds {
			before[world.RepoId()] = len(reader.Fetches(world.RepoId()))
		}
		stream, err := search(text, 0)
		if err != nil {
			return nil, nil, err
		}
		defer stream.Close()
		hits := []sidecar.SearchHit{}
		for range 16 {
			page, _, done, err := stream.Next()
			if err != nil {
				return nil, nil, err
			}
			hits = append(hits, page...)
			if done {
				break
			}
		}
		requests := []string{}
		for _, world := range worlds {
			for _, fetch := range reader.Fetches(world.RepoId())[before[world.RepoId()]:] {
				requests = append(requests, "evs read "+fetch.Path)
			}
		}
		return hits, requests, nil
	}

	// an entry pushed by the writer is in the reader's next search once its sync takes it
	if err := worlds["notes"].PushDocuments(ctx, writer, clock.Now(), []*sidecar.SearchTestDocument{
		{Path: "notes/entry.md", Version: 1, Title: "entry", Text: "a claim: " + entry, Time: clock.Now()},
	}); err != nil {
		return err
	}
	if err := reader.Sync(ctx); err != nil {
		return err
	}
	hits, entryRequests, err := collect(entry)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(hits, func(hit sidecar.SearchHit) bool { return hit.Path == "notes/entry.md" }) {
		return fmt.Errorf("the entry is not in the reader's next search: %v", hits)
	}
	// two queries from one sync state send evs the same requests
	_, queryRequests, err := collect(query)
	if err != nil {
		return err
	}
	if err := RequestTraceEqual(
		&RequestTrace{Label: "the entry's query", SyncState: "synced past the entry", Requests: entryRequests},
		&RequestTrace{Label: "the other query", SyncState: "synced past the entry", Requests: queryRequests},
	); err != nil {
		return err
	}
	// an erasure's CUT ends an open cursor, and a new search misses the document
	stream, err := search(query, 1)
	if err != nil {
		return err
	}
	defer stream.Close()
	if _, _, _, err := stream.Next(); err != nil {
		return err
	}
	if _, err := worlds["notes"].Cut(ctx, searchWorldId("s11 erasure"), documents[:1]); err != nil {
		return err
	}
	if err := reader.Sync(ctx); err != nil {
		return err
	}
	// the CUT applied, as CORE-M10-04's ApplyCut ends the repo's searches once its round took it
	reader.EndRepo(worlds["notes"].RepoId())
	if _, _, _, err := stream.Next(); !errors.Is(err, sidecar.ErrSearchCursorExpired) {
		return fmt.Errorf("the open cursor after the CUT answered %v", err)
	}
	hits, _, err = collect(query)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(hits, func(hit sidecar.SearchHit) bool {
		return hit.Repo == worlds["notes"].RepoId() && hit.Path == documents[0].Path
	}) {
		return errors.New("a new search found the erased document")
	}
	return nil
}
