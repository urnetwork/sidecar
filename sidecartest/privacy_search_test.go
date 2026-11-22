//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind && !sidecar_http

package sidecartest

// §22.7's search rows in the privacy harness (SEARCH-M10-39; FI-21, FI-23, FI-24, I-13, I-19): on the remote team
// (search_remote_world.go), ten queries, each a canary, whose matches number 0 to 20, asked by m's phone's "search
// more" of its own indexers, which serve them from their text:
//
//	frames     each pair's request and reply sizes, as the relay carries them, are one sequence per kind across the ten
//	           and every post-parse failure the indexer answers (UNSUPPORTED_VERSION, CURSOR_EXPIRED, INVALID): one
//	           request of 4,016 B and one reply of 16,384 B a step
//	stored     no query canary in either device's state directory, the indexers' served records included, after the
//	           first search and after them all (CC4's state files); the capture holds them, so a stored query is found
//	requests   two searches with different queries from one sync state send evs the same requests: none
//
// The transport here carries each body unsealed, standing for the pair's sealed frames, so no body is the capture's
// CC2: on T3 and the surrogates, CC2's frames are the relays' own TransferFrames, which this does not reach. Nothing
// here captures a device's logs, metrics, traces or crash reports, which these devices write none of (their loggers
// are the no-op logger); that clause waits on a composition that logs through the Net's capture.
//
// The indexers' budgets spend compute on a meter of the test's own (SearchRemoteTeamArgs.CpuClock), not the Net's
// clock, which moves a minute for the phone's rate. A search's first page needs one own indexer's answer, so the other
// leg may still hold one of its indexer's slots when the clock moves, longer the busier the host; on the one clock that
// minute counted as compute past RemoteCpuPerMinute's 30 s, and the failures were refused for CPU. One slot is held
// across the move here every time, as such a leg's would be.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// §22.7's search rows: see the file header.
func TestPrivacySearchQueryCanaries(t *testing.T) {
	ctx := t.Context()
	capture := NewPrivacyCapture()
	hitCounts := []int{0, 1, 2, 3, 4, 5, 8, 12, 16, 20}
	queries := []string{}
	for index := range hitCounts {
		queries = append(queries, capture.CanaryText(fmt.Sprintf("search query %d", index)))
	}
	documents := func(repo string) []*sidecar.SearchTestDocument {
		if repo != "m vault" {
			return []*sidecar.SearchTestDocument{{Path: "notes/other.md", Version: 1, Title: "other", Text: "nothing searched"}}
		}
		found := []*sidecar.SearchTestDocument{}
		for index, count := range hitCounts {
			for n := range count {
				found = append(found, &sidecar.SearchTestDocument{
					Path: fmt.Sprintf("notes/q%d-%d.md", index, n), Version: 1, Title: queries[index], Text: "a note",
				})
			}
		}
		return found
	}
	directories := map[string]string{}
	for _, name := range []string{"m phone", "m desktop", "m nas", "b nas", "owner"} {
		directories[name] = t.TempDir()
	}
	net := NewNet(ctx, nil)
	defer net.Close()
	tier, err := net.AdmissionTier()
	if err != nil {
		t.Fatal(err)
	}
	cpuClock := NewFakeClock(DefaultClockStart())
	team, err := NewSearchRemoteTeam(ctx, &SearchRemoteTeamArgs{
		Tier: tier, Documents: documents, CpuClock: cpuClock,
		StateDirectory: func(device string) string { return directories[device] },
		Text: func(indexer string, repo string) sidecar.SearchTextSource {
			return &searchRemoteDocumentText{documents: documents(repo)}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer team.Close()
	capture.AddSource(func() []*PrivacyItem {
		items := []*PrivacyItem{}
		for name, directory := range directories {
			filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
				if err != nil || entry.IsDir() {
					return nil
				}
				body, err := os.ReadFile(path)
				if err == nil {
					items = append(items, &PrivacyItem{Class: PrivacyClass("CC4/state"), Name: name + " " + filepath.Base(path), Body: body})
				}
				return nil
			})
		}
		for name, indexer := range team.Indexers {
			if records, err := indexer.Device.State().ServedRecords(); err == nil {
				items = append(items, &PrivacyItem{Class: PrivacyClass("CC4/served"), Name: name + " served record", Body: []byte(fmt.Sprint(records))})
			}
		}
		return items
	})

	phoneId := team.Id("m phone")
	traces := []*FrameSizeTrace{}
	requestTraces := []*RequestTrace{}
	for index, query := range queries {
		// each query's first page alone, as a phone shows one until its person asks for more: one exchange a leg
		pages, err := team.Phone.Search(ctx, &sidecar.SearchRequest{Text: query, Repos: []sidecar.Id{team.RepoId("m vault")}}, 1)
		if err != nil {
			t.Fatalf("query %d: %v", index, err)
		}
		if len(pages.Hits) < hitCounts[index] {
			t.Errorf("query %d found %d of its %d documents", index, len(pages.Hits), hitCounts[index])
		}
		for _, indexer := range []string{"m desktop", "m nas"} {
			requests, replies := pages.FrameSizes(phoneId, team.Id(indexer))
			if 0 < len(replies) {
				traces = append(traces, &FrameSizeTrace{Label: fmt.Sprintf("query %d to %s", index, indexer), Kind: "1 step", Requests: requests, Replies: replies})
			}
		}
		requestTraces = append(requestTraces, &RequestTrace{Label: fmt.Sprintf("query %d", index), SyncState: "synced at setup", Requests: pages.Requests[phoneId]})
		if index == 0 {
			if findings := capture.Scan(); len(findings) != 0 {
				t.Fatalf("after query %d: %v", index, findings)
			}
		}
	}
	// every post-parse failure answers in its step's one size: the phone's rate refilled first, since its twenty legs
	// spent its burst, while one of the desktop's slots is held across the clock's move as a leg the phone stopped
	// waiting for may hold one (the file header)
	searchSettings := sidecar.DefaultSidecarSettings().Search
	indexer := team.Indexers["m desktop"]
	straggler, err := indexer.Budget.Admit(ctx, team.Net.Id("a leg the phone stopped waiting for"))
	if err != nil {
		t.Fatal(err)
	}
	team.Net.Clock().Advance(searchSettings.RemoteRequesterRate.Interval)
	wire := sidecar.DefaultSearchWireSettings()
	vault := &protocol.SearchRepo{RepoId: team.RepoId("m vault").Bytes()}
	// UNSUPPORTED_VERSION; CURSOR_EXPIRED for a page of no cursor; and INVALID for a page past a live cursor's next,
	// after the page 0 that opens it, which answers as any page does
	failures := []*protocol.SearchRequest{
		{SearchVersion: sidecar.SearchTestRemoteVersion + 1, SearchId: 7001, Page: 0, Steps: 1, Scope: 2, Query: queries[1], Repos: []*protocol.SearchRepo{vault}},
		{SearchVersion: sidecar.SearchTestRemoteVersion, SearchId: 7002, Page: 3, Steps: 1},
		{SearchVersion: sidecar.SearchTestRemoteVersion, SearchId: 7003, Page: 0, Steps: 1, Scope: 2, Query: queries[2], Repos: []*protocol.SearchRepo{vault}},
		{SearchVersion: sidecar.SearchTestRemoteVersion, SearchId: 7003, Page: 5, Steps: 1},
	}
	for index, request := range failures {
		body, err := sidecar.SearchTestRemoteRequestBody(wire, request)
		if err != nil {
			t.Fatalf("failure %d: %v", index, err)
		}
		reply, err := indexer.Server.Handle(ctx, &sidecar.SubprotocolRequest{
			SourceId: phoneId, Peer: &sidecar.SubprotocolPeerIdentity{SidecarId: phoneId}, MessageType: protocol.MessageType_SEARCH, Body: body,
		})
		if err != nil {
			t.Fatalf("failure %d: %v", index, err)
		}
		parsed := &protocol.SearchReply{}
		opens := request.GetSearchId() == 7003 && request.GetPage() == 0
		if err := proto.Unmarshal(reply, parsed); err != nil || (protocol.SearchStatus(parsed.GetStatus()) == protocol.SearchStatus_SEARCH_OK) != opens {
			t.Errorf("request %d answered %v: %v", index, protocol.SearchStatus(parsed.GetStatus()), err)
		}
		traces = append(traces, &FrameSizeTrace{Label: fmt.Sprintf("failure %d", index), Kind: "1 step", Requests: []int{len(body)}, Replies: []int{len(reply)}})
	}
	// the budget still spends what its meter measures: past RemoteCpuPerMinute there the next request is refused, from
	// a requester of its own so no leg's rate is spent, and the held slot counted the meter's time and none of the
	// clock's minute
	cpuClock.Advance(searchSettings.RemoteCpuPerMinute)
	var refusal *sidecar.SidecarRemoteRefusal
	if _, err := indexer.Budget.Admit(ctx, team.Net.Id("a request past the meter's cap")); !errors.As(err, &refusal) || refusal.Reason != sidecar.SidecarRemoteRefusedCpu {
		t.Errorf("past RemoteCpuPerMinute on the meter the desktop's budget answered %v", err)
	}
	if held := straggler.Release(); held != searchSettings.RemoteCpuPerMinute {
		t.Errorf("the held slot counted %s of compute, not the meter's %s", held, searchSettings.RemoteCpuPerMinute)
	}
	if err := FrameSizesEqual(traces...); err != nil {
		t.Error(err)
	}
	if err := RequestTraceEqual(requestTraces...); err != nil {
		t.Error(err)
	}
	if findings := capture.Scan(); len(findings) != 0 {
		t.Errorf("the scan: %v", findings)
	}
	if count := capture.ItemCount(PrivacyClass("CC4")); count == 0 {
		t.Error("the capture held nothing of the devices' state")
	}

	// the capture reads the state directories: a query written there is found
	planted := filepath.Join(directories["m phone"], "planted-query")
	if err := os.WriteFile(planted, []byte(queries[3]), 0o600); err != nil {
		t.Fatal(err)
	}
	if findings := capture.Scan(); !slices.ContainsFunc(findings, func(finding *PrivacyFinding) bool { return finding.Needle == "search query 3" }) {
		t.Errorf("a query written to the phone's state directory was not found: %v", findings)
	}
}
