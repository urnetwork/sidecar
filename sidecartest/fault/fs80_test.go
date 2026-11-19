//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind && !sidecar_http

package fault

// FS-80 on T2, its engine part (§22.8; §16.10's scope, excluded, coverage, limits, pages and trust rows, §16.6; FI-21,
// FI-23; SEARCH-M10-39): a desktop of one network holding the text of a vault, a mailbox, a notes repo and a vault it
// reads by an EvsShare, beside a secret and a config repo it reads too, each a search world (the root's
// SearchTestWorld) and a repo of SearchOracle's ledger, the two vaults general repos since the oracle does not judge
// a vault's record documents yet (SEARCH-M10-07); its engine's searches recorded for FI-21 and FI-23, which hold
// after every step:
//
//	scopes    repo breadth over the vault and network breadth over every repo return exactly the oracle's matching
//	          documents at their newest versions, and every hit carries its source, its repo and partition
//	excluded  no secret, config or mailcfg repo is searched; the config repo is named excluded with its reason, and
//	          the secret repo is not named at all (§16.6)
//	receipts  the shared vault's read receipt is deposited before its first index object is read, and a device whose
//	          deposit fails reads nothing of it and names it excluded for its receipt
//	erasure   an ERASE's CUT while a cursor is open, the desktop's round taking it and the repo's searches ended as
//	          CORE-M10-04's ApplyCut ends them (no composition wires that hint here): the next page answers
//	          cursor_expired, and a new search misses the document
//	limits    a page holds at most Search.PageByteCount, and a query past TooBroadCandidateCount candidates answers
//	          too_broad
//	traces    two searches with different queries from one sync state send evs the same requests (FI-23)
//
// Not here, each FS-80's and SEARCH-M10-39's report's: the team directory instead of a coordination log, the team
// record and its run cards, agents claiming and handing off, ur agents and search_agents' groups, another member's
// announced run and an opt-out (RECORD-M10-04's documents are not on sidecar); ur search and the MCP search tool
// themselves, their filters by agent, time, kind, path prefix and field, and more adding all; a parked device's member
// vault as consent pending; a repo with its index off in repo scope searched by §11.14's no-index rule; D-MCP-18's
// budget over 300 searches a day; untrusted stubs, include's fsynced taint and a failed fsync, and the harness shell's
// taint by process ancestry; an ERASE's caches and local-layer postings gone before its hint is acknowledged, and a
// read loss's cache deletion; a third search in a session busy after wait_ms; more's downloads stopping at
// MoreByteCount (FS-110's); each hit's trust, which the engine judges only where a composition gives it the reader's
// state (none does yet); the team-record case (M6-out); and T3.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs80 = Register("FS-80", "", []Tier{TierT2}, Fs80SearchScopes)

// A repo of FS-80's network.
type fs80Repo struct {
	name  string
	kind  protocol.RepoKind
	world *sidecar.SearchTestWorld
	// its documents, which the ledger records and the desktop holds the text of
	documents []*sidecar.SearchTestDocument
	// the ledger's next ref version
	refVersion uint64
}

// What FS-80's steps share.
type fs80State struct {
	readerId  sidecar.Id
	networkId sidecar.Id
	writerId  sidecar.Id
	repos     map[string]*fs80Repo
	ledger    *sidecartest.SearchLedger
	oracle    *sidecartest.SearchOracle
	desktop   *sidecar.SearchTestNetworkDevice
	// the shared vault's receipts: the count of its index objects the desktop had read at each
	receipts []int
}

// The repos, in the order the desktop follows them.
var fs80RepoNames = []string{"vault", "mailbox", "notes", "shared", "secret", "config"}

// A repo's documents: two that hold harbor, one of them in its title, and one that does not; the notes repo also holds
// a document of every word the limits step asks.
func fs80Documents(repo string, at time.Time) []*sidecar.SearchTestDocument {
	place := func(name string) string {
		if repo == "mailbox" {
			// a mailbox's documents are its m/ messages
			return "m/" + name + ".eml"
		}
		return "notes/" + repo + "/" + name + ".md"
	}
	return []*sidecar.SearchTestDocument{
		{Path: place("harbor"), Version: 1, Title: "harbor at noon", Text: "the boats leave early", Time: at},
		{Path: place("tides"), Version: 1, Title: "tides", Text: "the harbor floods at spring tide", Time: at},
		{Path: place("garden"), Version: 1, Title: "garden", Text: "tomatoes and lighthouse beans", Time: at},
	}
}

// A document's bytes as its repo holds them, which the oracle extracts with its own reading: a mailbox's a message
// whose subject is the title, every other repo's a file whose first line is.
func fs80Content(kind protocol.RepoKind, document *sidecar.SearchTestDocument) []byte {
	if kind == protocol.RepoKind_REPO_KIND_MAILBOX {
		return []byte("From: writer@example.com\r\nSubject: " + document.Title + "\r\n\r\n" + document.Text + "\r\n")
	}
	return []byte(document.Title + "\n" + document.Text)
}

// The text of every repo's documents, as a desktop holding mirrors reads it.
type fs80Text struct {
	state *fs80State
}

func (self *fs80Text) SearchDocuments(ctx context.Context, request *sidecar.SearchTextRequest) ([]*sidecar.IndexDocument, bool, error) {
	for _, repo := range self.state.repos {
		if repo.world.RepoId() != request.RepoId {
			continue
		}
		for _, document := range repo.documents {
			if document.Path == string(request.Name) && document.Version == request.Version {
				found := &sidecar.IndexDocument{Kind: sidecar.IndexDocFile, Name: []byte(document.Path), Version: document.Version, ByteCount: uint64(len(document.Title) + len(document.Text))}
				// §11.14's field numbers: 4 the title, 5 the body
				found.Fields[4] = []byte(document.Title)
				found.Fields[5] = []byte(document.Text)
				return []*sidecar.IndexDocument{found}, true, nil
			}
		}
	}
	return nil, false, nil
}

// The network: every repo a world with its documents, the ledger beside it, and the desktop over all of it, its
// shared vault read by receipt (receipt nil: the desktop's own).
func (self *fs80State) setup(ctx context.Context, net *Net) error {
	self.readerId, self.networkId, self.writerId = searchId("fs80 reader"), searchId("fs80 network"), searchId("fs80 writer")
	self.repos = map[string]*fs80Repo{}
	self.ledger = sidecartest.NewSearchLedger()
	// the vaults are general repos here: a vault's documents are the record's, which SearchOracle refuses until it
	// judges them (SEARCH-M10-07's note), so the shared one stands for an EvsShare'd vault by its non-writer's receipts
	kinds := map[string]protocol.RepoKind{
		"vault": protocol.RepoKind_REPO_KIND_GENERAL, "mailbox": protocol.RepoKind_REPO_KIND_MAILBOX, "notes": protocol.RepoKind_REPO_KIND_GENERAL,
		"shared": protocol.RepoKind_REPO_KIND_GENERAL, "secret": protocol.RepoKind_REPO_KIND_SECRET, "config": protocol.RepoKind_REPO_KIND_CONFIG,
	}
	now := net.Clock().Now()
	for _, name := range fs80RepoNames {
		world, err := sidecar.NewSearchTestWorld(&sidecar.SearchTestWorldArgs{
			RepoId: searchId("fs80 repo " + name), RefId: searchId("fs80 ref " + name), Clock: net.Clock(), Kind: kinds[name],
		})
		if err != nil {
			return err
		}
		repo := &fs80Repo{name: name, kind: kinds[name], world: world}
		self.repos[name] = repo
		if err := self.ledger.AddRepo(&sidecartest.SearchLedgerRepo{
			RepoId: world.RepoId(), NetworkId: self.networkId, Kind: kinds[name], DefaultRefId: world.RefId(), Key: world.RepoKey(),
			ReaderIds: []sidecar.Id{self.readerId},
		}); err != nil {
			return err
		}
		switch name {
		case "secret", "config":
			// §11.14's never row: no honest writer writes an index there
			continue
		}
		if err := self.write(ctx, repo, now, fs80Documents(name, now)...); err != nil {
			return err
		}
	}
	self.oracle = sidecartest.NewSearchOracle(self.ledger)
	device, err := self.device(ctx, func(ctx context.Context, paths []string) error {
		self.receipts = append(self.receipts, len(self.desktop.Fetches(self.repos["shared"].world.RepoId())))
		return nil
	})
	if err != nil {
		return err
	}
	self.desktop = device
	return self.desktop.Sync(ctx)
}

// documents pushed by the writer at at, and recorded in the ledger as one indexed commit.
func (self *fs80State) write(ctx context.Context, repo *fs80Repo, at time.Time, documents ...*sidecar.SearchTestDocument) error {
	if err := repo.world.PushDocuments(ctx, self.writerId, at, documents); err != nil {
		return err
	}
	repo.documents = append(repo.documents, documents...)
	repo.refVersion += 1
	commit := &sidecartest.SearchCommit{
		RepoId: repo.world.RepoId(), RefId: repo.world.RefId(), RefVersion: repo.refVersion, Time: at, WriterId: self.writerId, Indexed: true,
	}
	for _, document := range documents {
		commit.Changes = append(commit.Changes, &sidecartest.SearchChange{
			Path: document.Path, Version: document.Version, Content: fs80Content(repo.kind, document),
		})
	}
	return self.ledger.Commit(commit)
}

// A desktop over every repo, holding their text, its shared vault read as a non-writer depositing receipt.
func (self *fs80State) device(ctx context.Context, receipt func(ctx context.Context, paths []string) error) (*sidecar.SearchTestNetworkDevice, error) {
	refs := []*sidecar.SearchTestNetworkRef{}
	for _, name := range fs80RepoNames {
		ref := &sidecar.SearchTestNetworkRef{World: self.repos[name].world}
		if name == "shared" {
			ref.NonWriter, ref.Receipt = true, receipt
		}
		refs = append(refs, ref)
	}
	text := &fs80Text{state: self}
	return sidecar.NewSearchTestNetworkDevice(ctx, &sidecar.SearchTestNetworkDeviceArgs{
		Settings: sidecar.DefaultSidecarSettings().Search, Conditions: func() sidecar.SearchConditions { return sidecar.SearchConditions{DaemonHost: true} },
		ReadByteCount: 32 * 1024 * 1024, Refs: refs,
		Text: func(repoId sidecar.Id, refId sidecar.Id) sidecar.SearchTextSource { return text },
	})
}

// The oracle's scope for a search of repos (nil: network breadth).
func (self *fs80State) scope(repos ...string) *sidecartest.SearchScope {
	scope := &sidecartest.SearchScope{
		Partitions: sidecartest.SearchScopeAll, Breadth: sidecartest.SearchBreadthNetwork,
		NetworkIds: []sidecar.Id{self.networkId}, ReaderId: self.readerId,
	}
	if 0 < len(repos) {
		scope.Breadth = sidecartest.SearchBreadthRepo
		for _, name := range repos {
			scope.Repos = append(scope.Repos, &sidecartest.SearchScopeRepo{RepoId: self.repos[name].world.RepoId()})
		}
	}
	return scope
}

// The desktop's search, every page, recorded for FI-21 and FI-23; its hits and last progress.
func (self *fs80State) search(ctx context.Context, net *Net, label string, query string, repos ...string) ([]sidecar.SearchHit, sidecar.SearchProgress, error) {
	request := &sidecar.SearchRequest{Text: query, Scope: sidecar.SearchAll}
	for _, name := range repos {
		request.Repos = append(request.Repos, self.repos[name].world.RepoId())
	}
	before := map[sidecar.Id]int{}
	for _, name := range fs80RepoNames {
		before[self.repos[name].world.RepoId()] = len(self.desktop.Fetches(self.repos[name].world.RepoId()))
	}
	stream, err := self.desktop.Engine().Search(ctx, request)
	if err != nil {
		return nil, sidecar.SearchProgress{}, fmt.Errorf("%s: %w", label, err)
	}
	defer stream.Close()
	hits := []sidecar.SearchHit{}
	var progress sidecar.SearchProgress
	for range 64 {
		page, pageProgress, done, err := stream.Next()
		if err != nil {
			return hits, progress, fmt.Errorf("%s: %w", label, err)
		}
		hits, progress = append(hits, page...), pageProgress
		if done {
			break
		}
	}
	requests := []string{}
	for _, name := range fs80RepoNames {
		repoId := self.repos[name].world.RepoId()
		for _, fetch := range self.desktop.Fetches(repoId)[before[repoId]:] {
			requests = append(requests, fmt.Sprintf("evs read %s@%d", fetch.Path, fetch.Version))
		}
	}
	shared := self.repos["shared"].world.RepoId()
	SearchRecordOf(net).RecordSearch(&SearchRun{
		Label: label, Query: query, Scope: self.scope(repos...), Oracle: self.oracle, Hits: hits, Uncovered: progress.Uncovered,
		SyncState: fmt.Sprintf("desktop synced, %d receipts", len(self.receipts)), Fetches: requests, Requests: requests,
		ReceiptRepoIds: []sidecar.Id{shared}, AcknowledgedRepoIds: []sidecar.Id{shared},
	})
	return hits, progress, nil
}

// The hits as names at versions, sorted, and the oracle's matches for query in scope.
func (self *fs80State) agree(label string, query string, hits []sidecar.SearchHit, scope *sidecartest.SearchScope) error {
	found := searchHitNames(hits)
	want := []string{}
	for _, key := range self.oracle.Matches(query, scope) {
		want = append(want, fmt.Sprintf("%s@%d", key.Name, key.Version))
	}
	slices.Sort(want)
	if !slices.Equal(found, want) {
		return fmt.Errorf("%s: the search found %v, the oracle %v", label, found, want)
	}
	for _, hit := range hits {
		// its source; its trust is judged only where the engine knows the reader's state, which no composition gives it
		// yet, so every hit here reads "", untrusted (search_trust.go)
		if hit.PartitionName == "" || hit.Repo == (sidecar.Id{}) {
			return fmt.Errorf("%s: a hit on %s carries no source: partition %q", label, hit.Path, hit.PartitionName)
		}
	}
	return nil
}

// See the file header.
func Fs80SearchScopes(net *Net) *Schedule {
	state := &fs80State{}
	steps := []*Step{
		{Actor: "setup", Action: state.setup},
		{Actor: "desktop", Action: func(ctx context.Context, net *Net) error {
			hits, _, err := state.search(ctx, net, "repo breadth", "harbor", "vault")
			if err != nil {
				return err
			}
			return state.agree("repo breadth", "harbor", hits, state.scope("vault"))
		}},
		{Actor: "desktop", Action: func(ctx context.Context, net *Net) error {
			hits, progress, err := state.search(ctx, net, "network breadth", "harbor")
			if err != nil {
				return err
			}
			if err := state.agree("network breadth", "harbor", hits, state.scope()); err != nil {
				return err
			}
			// a different query from the same sync state: FI-23 holds the two to one trace
			if _, _, err := state.search(ctx, net, "network breadth, another query", "lighthouse"); err != nil {
				return err
			}
			for _, hit := range hits {
				if name := state.repoName(hit.Repo); name == "secret" || name == "config" {
					return fmt.Errorf("a hit from the %s repo", name)
				}
			}
			excluded := map[string]string{}
			for _, exclusion := range progress.Excluded {
				excluded[state.repoName(exclusion.RepoId)] = exclusion.Reason
			}
			if _, ok := excluded["secret"]; ok {
				return errors.New("the secret repo is named among the exclusions")
			}
			if excluded["config"] == "" {
				return fmt.Errorf("the config repo is not named excluded: %v", excluded)
			}
			return nil
		}},
		{Actor: "desktop", Action: func(ctx context.Context, net *Net) error {
			shared := state.repos["shared"].world.RepoId()
			if len(state.receipts) == 0 || state.receipts[0] != 0 || len(state.desktop.Fetches(shared)) == 0 {
				return fmt.Errorf("the shared vault's receipts came at %v of its reads, %d reads in all", state.receipts, len(state.desktop.Fetches(shared)))
			}
			// a device whose deposit fails reads nothing of the shared vault, and names it excluded for its receipt
			refused, err := state.device(ctx, func(ctx context.Context, paths []string) error { return errors.New("the deposit failed") })
			if err != nil {
				return err
			}
			defer refused.Close()
			// its round of the shared vault fails on the deposit, which the search below names
			refused.Sync(ctx)
			if fetched := refused.Fetches(shared); len(fetched) != 0 {
				return fmt.Errorf("a device whose receipt failed read %d of the shared vault's objects", len(fetched))
			}
			stream, err := refused.Engine().Search(ctx, &sidecar.SearchRequest{Text: "harbor", Repos: []sidecar.Id{shared}, Scope: sidecar.SearchAll})
			if err != nil {
				return err
			}
			defer stream.Close()
			hits, progress, _, err := stream.Next()
			if err != nil {
				return err
			}
			if 0 < len(hits) || !slices.ContainsFunc(progress.Excluded, func(exclusion sidecar.SearchExclusion) bool {
				return exclusion.RepoId == shared && exclusion.Reason == sidecar.SearchExcludedReceipt
			}) {
				return fmt.Errorf("with its receipt refused the shared vault gave %d hits and the exclusions %+v", len(hits), progress.Excluded)
			}
			return nil
		}},
		{Actor: "desktop", Action: func(ctx context.Context, net *Net) error {
			vault := state.repos["vault"]
			stream, err := state.desktop.Engine().Search(ctx, &sidecar.SearchRequest{Text: "harbor", Repos: []sidecar.Id{vault.world.RepoId()}, Scope: sidecar.SearchAll, PageSize: 1})
			if err != nil {
				return err
			}
			defer stream.Close()
			if _, _, done, err := stream.Next(); err != nil || done {
				return fmt.Errorf("the first page of two: done %v, %v", done, err)
			}
			erased := vault.documents[0]
			if _, err := vault.world.Cut(ctx, searchId("fs80 erasure"), []*sidecar.SearchTestDocument{erased}); err != nil {
				return err
			}
			if err := state.ledger.Erase(vault.world.RepoId(), vault.world.RefId(), erased.Path, erased.Version); err != nil {
				return err
			}
			if err := state.desktop.Sync(ctx); err != nil {
				return err
			}
			// the CUT applied, as CORE-M10-04's ApplyCut ends the repo's searches once its round took it
			state.desktop.EndRepo(vault.world.RepoId())
			if _, _, _, err := stream.Next(); !errors.Is(err, sidecar.ErrSearchCursorExpired) {
				return fmt.Errorf("the open cursor's next page after the CUT answered %v", err)
			}
			hits, _, err := state.search(ctx, net, "after the erasure", "harbor", "vault")
			if err != nil {
				return err
			}
			if slices.ContainsFunc(hits, func(hit sidecar.SearchHit) bool { return hit.Path == erased.Path }) {
				return errors.New("a new search found the erased document")
			}
			return state.agree("after the erasure", "harbor", hits, state.scope("vault"))
		}},
		{Actor: "desktop", Action: func(ctx context.Context, net *Net) error {
			// past TooBroadCandidateCount candidates, as one bulk of the notes repo's shards
			notes := state.repos["notes"]
			count := sidecar.DefaultSidecarSettings().Search.TooBroadCandidateCount + 1
			prefix := "bulk/everywhere-"
			err := notes.world.WriteShards(ctx, state.writerId, net.Clock().Now(), &sidecar.SearchTestPartition{
				StartDay: sidecar.SearchTestBucketStartDay(net.Clock().Now().Add(-30 * 24 * time.Hour)), ShardDocumentCount: 4096,
			}, nil, []*sidecar.SearchTestBulk{{Prefix: prefix, Count: count, Version: 1, Document: &sidecar.SearchTestDocument{
				Path: prefix + "template", Version: 1, Title: "everywhere", Text: "the everywhere note", Time: net.Clock().Now().Add(-30 * 24 * time.Hour),
			}}})
			if err != nil {
				return err
			}
			if err := state.desktop.Sync(ctx); err != nil {
				return err
			}
			stream, err := state.desktop.Engine().Search(ctx, &sidecar.SearchRequest{Text: "everywhere", Repos: []sidecar.Id{notes.world.RepoId()}, Scope: sidecar.SearchLatest})
			if err != nil {
				return err
			}
			defer stream.Close()
			pageByteCount := sidecar.DefaultSidecarSettings().Search.PageByteCount
			for range 8 {
				page, progress, done, err := stream.Next()
				if err != nil {
					return err
				}
				byteCount := 0
				for _, hit := range page {
					byteCount += len(hit.Path) + len(hit.Snippet)
					for _, field := range hit.Fields {
						byteCount += len(field.Text)
					}
				}
				if pageByteCount < byteCount {
					return fmt.Errorf("a page of %d B past Search.PageByteCount", byteCount)
				}
				if progress.TooBroad {
					return nil
				}
				if done {
					break
				}
			}
			return fmt.Errorf("%d candidates of one word never answered too_broad", count)
		}},
		{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
			state.desktop.Close()
			return nil
		}},
	}
	return &Schedule{Id: "FS-80", Steps: steps, Check: []Invariant{FI(21), FI(23)}, Tiers: []Tier{TierT2}}
}

// The repo's name by its id, "" for none.
func (self *fs80State) repoName(repoId sidecar.Id) string {
	for name, repo := range self.repos {
		if repo.world.RepoId() == repoId {
			return name
		}
	}
	return ""
}

// FS-80 on T2, one explorer seed: its steps hold no barrier.
func TestFs80(t *testing.T) {
	settings := DefaultRuleSettings()
	settings.Seeds = settings.Seeds[:1]
	RunRow(t, "FS-80", "", settings)
}
