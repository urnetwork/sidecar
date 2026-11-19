//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind && !sidecar_http

package sidecartest

// S12 on T2 (§22.7's S12, F12; FS-83; owner decisions 175, 177, 178, 609; SEARCH-M10-39), under the scenario harness and
// its guard: on the remote team (search_remote_world.go), whose network designates search indexers (none is by
// default, owner decision 177), m's phone's "search more" asks its own indexers and shows their verified hits merged
// with its own; with one killed the other answers, and with both the vault falls back to the phone's own download; the
// team repo reaches the Owner's network-scope indexer only once its notice is answered, and m's vault never does;
// neither device reads evs while a remote search runs; and every exchange of one kind shows the relay one size each
// way. The query is a canary, so the harness's scan finds it nowhere the Net captures.
//
// Not here: "a false possible match collapsed", which needs a local possible match inside an indexer's checked span
// (FS-83's merge cases, not built); the pair's close reports carrying its bytes as any peer's (owner decision 609),
// which are connect's and no transport here carries; and T3, with real relays.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

func TestScenarioS12(t *testing.T) {
	RunScenario(t, &Scenario{Id: "S12", Run: s12Run}, nil)
}

// A world's documents as text a desktop holding a mirror reads: each document's title and body at its version.
type searchRemoteDocumentText struct {
	documents []*sidecar.SearchTestDocument
}

func (self *searchRemoteDocumentText) SearchDocuments(ctx context.Context, request *sidecar.SearchTextRequest) ([]*sidecar.IndexDocument, bool, error) {
	for _, document := range self.documents {
		if document.Path != string(request.Name) || document.Version != request.Version {
			continue
		}
		found := &sidecar.IndexDocument{Kind: sidecar.IndexDocFile, Name: []byte(document.Path), Version: document.Version, ByteCount: uint64(len(document.Title) + len(document.Text))}
		// §11.14's field numbers: 4 the title, 5 the body
		found.Fields[4] = []byte(document.Title)
		found.Fields[5] = []byte(document.Text)
		return []*sidecar.IndexDocument{found}, true, nil
	}
	return nil, false, nil
}

func s12Run(ctx context.Context, run *ScenarioRun) error {
	tier, err := run.Net.AdmissionTier()
	if err != nil {
		return err
	}
	query := run.CanaryText("search query")
	documents := func(repo string) []*sidecar.SearchTestDocument {
		slug := strings.ReplaceAll(repo, " ", "-")
		return []*sidecar.SearchTestDocument{
			{Path: "notes/" + slug + "/a.md", Version: 1, Title: query, Text: "the first of them"},
			{Path: "notes/" + slug + "/b.md", Version: 1, Title: "second", Text: "and here " + query + " again"},
			{Path: "notes/" + slug + "/c.md", Version: 1, Title: "third", Text: "nothing of it"},
		}
	}
	team, err := NewSearchRemoteTeam(ctx, &SearchRemoteTeamArgs{
		Tier: tier, Documents: documents,
		Text: func(indexer string, repo string) sidecar.SearchTextSource {
			return &searchRemoteDocumentText{documents: documents(repo)}
		},
	})
	if err != nil {
		return err
	}
	defer team.Close()
	traces := []*FrameSizeTrace{}
	search := func(label string, repos ...string) (*SearchRemotePages, error) {
		repoIds := []sidecar.Id{}
		for _, repo := range repos {
			repoIds = append(repoIds, team.RepoId(repo))
		}
		pages, err := team.Phone.Search(ctx, &sidecar.SearchRequest{Text: query, Repos: repoIds}, 16)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		// neither device reads evs while a remote search runs
		for id, requests := range pages.Requests {
			if 0 < len(requests) && !slices.ContainsFunc(pages.Calls, func(call *SearchRemoteCall) bool { return call.Err != nil }) {
				return nil, fmt.Errorf("%s: %s read %v while the remote search ran", label, team.NameOf(id), requests)
			}
		}
		for _, indexer := range searchRemoteTeamIndexers {
			requests, replies := pages.FrameSizes(team.Id("m phone"), team.Id(indexer))
			if 0 < len(replies) {
				traces = append(traces, &FrameSizeTrace{Label: label + " to " + indexer, Kind: "1 step", Requests: requests, Replies: replies})
			}
		}
		return pages, nil
	}
	askedOf := func(pages *SearchRemotePages, indexer string) []string {
		names := []string{}
		for _, call := range pages.Calls {
			if call.IndexerId == team.Id(indexer) {
				for _, repoId := range call.RepoIds() {
					names = append(names, team.RepoNameOf(repoId))
				}
			}
		}
		slices.Sort(names)
		return slices.Compact(names)
	}

	// the phone's own indexers answer its vault, with verified hits merged beside its own
	pages, err := search("own", "m vault", "m mailbox")
	if err != nil {
		return err
	}
	verified := 0
	for _, hit := range pages.Hits {
		if hit.State == sidecar.SearchVerified && hit.By != "" {
			verified += 1
		}
	}
	if verified == 0 {
		return fmt.Errorf("no verified hit came from an own indexer: %+v", pages.Hits)
	}
	// with one killed the next answers
	team.Indexers["m desktop"].Kill()
	pages, err = search("one killed", "m vault")
	if err != nil {
		return err
	}
	if asked := askedOf(pages, "m nas"); !slices.Equal(asked, []string{"m vault"}) {
		return fmt.Errorf("with the desktop killed the NAS was asked of %v", asked)
	}
	// with none the vault falls back to the download, and the team repo waits on the Owner's notice
	team.Indexers["m nas"].Kill()
	if pages, err = search("none", "m vault", "team"); err != nil {
		return err
	}
	if asked := askedOf(pages, "owner"); len(asked) != 0 {
		return fmt.Errorf("the Owner's indexer was asked of %v before its notice", asked)
	}
	if pages.Progress.FallbackReason == "" {
		return errors.New("nothing fell back with no own indexer")
	}
	ownerMember := team.Devices["owner"].MemberId
	if err := team.Phone.Device.State().SetAnswer(&ownerMember, true); err != nil {
		return err
	}
	if pages, err = search("notice answered", "m vault", "team"); err != nil {
		return err
	}
	if asked := askedOf(pages, "owner"); !slices.Equal(asked, []string{"team"}) {
		return fmt.Errorf("with its notice answered the Owner's indexer was asked of %v, not the team repo alone", asked)
	}
	// every exchange of one kind shows the relay one size each way
	if err := FrameSizesEqual(traces...); err != nil {
		return err
	}
	return nil
}
