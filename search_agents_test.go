//go:build !ios_extension

// SEARCH-M10-27's search_agents tests (§16.10's agents row; FS-88's search cases; FS-80): through the engine over a
// synced index of a vault's record rows, a task's agents grouped by (network, sidecar, agent label), the active ones
// first, a file holding the task left out by the kind filter; with no task only the active agents; a tainted run's
// claim a stub, counted untrusted_withheld, until include taints the run first; a credential in an entry withheld
// whatever its trust (I-7); kind[] read as one of its kinds.

package sidecar

import (
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A record row of label index, as a log's entry of kind gives one: its title indexed, and its writer, agent label and
// run in its registered fields; a claim's expiry and state where given.
func testAgentsDocument(t *testing.T, label string, index int, kind string, writer Id, agent string, title string, claimExpires time.Time, tainted bool) *indexPendingDocument {
	t.Helper()
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		t.Fatal(err)
	}
	document := &IndexDocument{Kind: IndexDocRecord, Name: []byte("r/" + label), Version: 1, Tainted: tainted}
	document.Fields[indexFieldTitle] = []byte(title)
	document.Fields[indexFieldBody] = []byte(title)
	document.Fields[searchFieldKind] = []byte(kind)
	document.Fields[searchFieldWriter] = []byte(hex.EncodeToString(writer.Bytes()))
	document.Fields[searchFieldAgentLabel] = []byte(agent)
	document.Fields[searchFieldRunId] = []byte(hex.EncodeToString(evsTestId("run of " + agent).Bytes()))
	if !claimExpires.IsZero() {
		document.Fields[searchFieldClaimExpires] = []byte(claimExpires.UTC().Format(searchClaimTimeLayout))
		document.Fields[searchFieldClaimState] = []byte(searchStateActive)
	}
	prepared, err := document.prepare(normalizer, false, evsTestId("view ref"), DefaultIndexFormatSettings())
	if err != nil {
		t.Fatal(err)
	}
	return &indexPendingDocument{kind: indexEntryFull, key: testIndexId(label, index), version: 1, keys: prepared.keys, row: prepared.row}
}

// An engine world over a vault holding Dana's limiter claim, my note on it, a tainted run's claim, a note holding a
// credential and a file on the same task.
func newTestAgentsWorld(t *testing.T) *testEngineWorld {
	t.Helper()
	future := time.Date(2099, 6, 1, 0, 0, 0, 0, time.UTC)
	world := newTestEngineWorld(t, nil,
		testAgentsDocument(t, "claim", 1, "claim", evsTestId("dana laptop"), "limiter-fix", "the rate limiter middleware", future, false),
		testAgentsDocument(t, "note", 2, "note", evsTestId("my laptop"), "api-refactor", "notes on the rate limiter", time.Time{}, false),
		testAgentsDocument(t, "tainted", 3, "claim", evsTestId("dana laptop"), "scraper", "rate limiter from a pasted page", future, true),
		testAgentsDocument(t, "secret", 4, "note", evsTestId("my laptop"), "api-refactor", "rate limiter token ur_test_secret_canary", time.Time{}, false),
		testEngineDocument(t, "file", 5, 1, "docs/limiter.md", "the rate limiter design"),
	)
	world.scope.repos[0].Kind = protocol.RepoKind_REPO_KIND_VAULT
	return world
}

func TestSearchAgentsExpiresDuringGrouping(t *testing.T) {
	world := newTestAgentsWorld(t)
	result, err := world.engine.Agents(t.Context(), NewId(), evsTestId("network"), &SearchAgentsRequest{
		Task: "limiter", Since: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), Reader: testTrustReader(),
		Fold: func(hits []SearchHit) []SearchHit {
			if len(hits) == 0 {
				t.Fatal("expected indexed task entries")
			}
			if err := world.sync.cache.cache.ApplyCut(t.Context(), world.sync.repoId, world.sync.refId, &protocol.IndexErasureSet{}); err != nil {
				t.Fatal(err)
			}
			return hits
		},
	})
	if !errors.Is(err, ErrSearchCursorExpired) || result != nil {
		t.Fatalf("after CUT during grouping, got %+v, %v", result, err)
	}
}

func TestSearchEngineAgentsGroupsWhoWorksOnATask(t *testing.T) {
	world := newTestAgentsWorld(t)
	since := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	tainted := 0
	agents := func(task string, include bool) *SearchAgentsResult {
		result, err := world.engine.Agents(context.Background(), NewId(), evsTestId("network"), &SearchAgentsRequest{
			Task: task, Since: since, Reader: testTrustReader(), Include: include, Secret: testSearchSecret,
			Taint: func(ctx context.Context) error {
				tainted += 1
				return nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	result := agents("limiter", false)
	if len(result.Groups) != 3 || !result.Complete {
		t.Fatalf("%d groups, complete %v", len(result.Groups), result.Complete)
	}
	if result.UntrustedWithheld != 1 || result.SecretWithheld != 1 || result.Untrusted || tainted != 0 || result.Trust != SearchTrustMember {
		t.Fatalf("withheld %d untrusted and %d secret, untrusted text %v, tainted %d, trust %s", result.UntrustedWithheld, result.SecretWithheld, result.Untrusted, tainted, result.Trust)
	}
	for _, group := range result.Groups {
		for _, hit := range group.Top {
			if hit.Path == "docs/limiter.md" {
				t.Fatal("a file reached search_agents")
			}
			if strings.Contains(testHitText(&hit), "ur_test_secret_canary") {
				t.Fatal("a credential reached a group")
			}
		}
	}
	// the two active claims' groups first (the tainted one a stub naming no agent), then the notes'
	if !result.Groups[0].Active || !result.Groups[1].Active || result.Groups[2].Active || result.Groups[2].AgentLabel != "api-refactor" {
		t.Fatalf("active %v %v %v, the last %q", result.Groups[0].Active, result.Groups[1].Active, result.Groups[2].Active, result.Groups[2].AgentLabel)
	}
	stubs := 0
	for _, group := range result.Groups[:2] {
		if group.Stub {
			stubs += 1
			if group.AgentLabel != "" || group.Claims[0].Text != "" || strings.Contains(group.Key, "scraper") {
				t.Fatalf("the tainted claim's group shows text: %+v", group)
			}
		} else if group.AgentLabel != "limiter-fix" || group.Trust != SearchTrustMember || group.Claims[0].Text == "" ||
			group.MemberId == nil || *group.MemberId != evsTestId("dana") {
			t.Fatalf("Dana's group: %+v", group)
		}
	}
	if stubs != 1 {
		t.Fatalf("%d stub groups", stubs)
	}

	// with no task: only the agents active in the window
	idle := agents("", false)
	if len(idle.Groups) != 2 {
		t.Fatalf("%d active agents", len(idle.Groups))
	}
	for _, group := range idle.Groups {
		if !group.Active {
			t.Fatal("an idle agent listed with no task")
		}
	}

	// include: the tainted claim's text comes back, the run tainted first; the credential still does not
	included := agents("limiter", true)
	if !included.Untrusted || included.UntrustedWithheld != 0 || included.SecretWithheld != 1 || tainted != 1 || included.Trust != SearchTrustUntrusted {
		t.Fatalf("include: untrusted %v, %d and %d withheld, tainted %d", included.Untrusted, included.UntrustedWithheld, included.SecretWithheld, tainted)
	}

	// the window: a since after every row finds nothing
	if late, err := world.engine.Agents(context.Background(), NewId(), evsTestId("network"), &SearchAgentsRequest{
		Task: "limiter", Since: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC), Reader: testTrustReader(),
	}); err != nil || len(late.Groups) != 0 {
		t.Fatalf("a window past every row: %+v %v", late, err)
	}
	// include with nothing to taint the run is refused
	if _, err := world.engine.Agents(context.Background(), NewId(), evsTestId("network"), &SearchAgentsRequest{Task: "limiter", Include: true}); err != ErrSearchToolInclude {
		t.Fatalf("include with no taint: %v", err)
	}
}

// §16.10's kind[]: a search naming two kinds finds the rows of either, and one naming a kind no row has finds none.
func TestSearchEngineKindFilterIsOneOfItsKinds(t *testing.T) {
	world := newTestAgentsWorld(t)
	kinds := func(names ...string) []SearchFieldFilter {
		filters := []SearchFieldFilter{}
		for _, name := range names {
			filters = append(filters, SearchFieldFilter{Name: "kind", Value: name})
		}
		return filters
	}
	hits, _ := world.all(t, &SearchRequest{Text: "limiter", Filters: kinds("claim", "note")})
	if paths := testHitPaths(hits); len(paths) != 4 {
		t.Fatalf("claims and notes: %v", paths)
	}
	hits, _ = world.all(t, &SearchRequest{Text: "limiter", Filters: kinds("note")})
	if paths := testHitPaths(hits); len(paths) != 2 {
		t.Fatalf("notes: %v", paths)
	}
	if hits, _ = world.all(t, &SearchRequest{Text: "limiter", Filters: kinds("handoff")}); len(hits) != 0 {
		t.Fatalf("handoffs: %v", testHitPaths(hits))
	}
	// a hit carries its row's kind, writer and provenance
	hits, _ = world.all(t, &SearchRequest{Text: "pasted"})
	if len(hits) != 1 || searchHitField(&hits[0], searchFieldKind) != "claim" || hits[0].Signer != evsTestId("dana laptop") || !hits[0].Tainted ||
		hits[0].DocKind != int(indexDocRecord) || hits[0].DocKey != testIndexId("tainted", 3) || hits[0].PartitionName == "" {
		t.Fatalf("a record hit: %+v", hits)
	}
}

// §16.10's member and sidecar filters: a member's filter keeps the rows one of its sidecars wrote, as the engine's
// Members names them, a member it names none of keeps nothing, and an engine with no Members keeps nothing either; a
// sidecar's keeps its own rows; neither keeps a file, whose row names no writer.
func TestSearchEngineMemberAndSidecarFilters(t *testing.T) {
	world := newTestAgentsWorld(t)
	engine, err := NewSearchEngine(&SearchEngineArgs{
		Settings: world.sync.cache.settings, Cache: world.sync.cache.cache, Sync: world.sync.sync, Policy: world.policy, Scope: world.scope,
		Gkm: &evsTestReadGkm{newest: 1}, Clock: world.sync.cache.clock, Log: NewNoopLogger(),
		Members: func(memberId Id) []Id {
			if memberId == evsTestId("dana") {
				return []Id{evsTestId("dana laptop"), evsTestId("dana phone")}
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	search := func(engine *SearchEngine, name string, value string) []string {
		stream, err := engine.Search(context.Background(), &SearchRequest{Text: "limiter", Filters: []SearchFieldFilter{{Name: name, Value: value}}})
		if err != nil {
			t.Fatal(err)
		}
		defer stream.Close()
		hits := []SearchHit{}
		for {
			page, _, done, err := stream.Next()
			if err != nil {
				t.Fatal(err)
			}
			hits = append(hits, page...)
			if done {
				return testHitPaths(hits)
			}
		}
	}
	if paths := search(engine, "member", evsTestId("dana").String()); !slices.Equal(paths, []string{"r/claim", "r/tainted"}) {
		t.Fatalf("Dana's rows: %v", paths)
	}
	if paths := search(engine, "member", evsTestId("nobody").String()); len(paths) != 0 {
		t.Fatalf("a member with no sidecar: %v", paths)
	}
	if paths := search(world.engine, "member", evsTestId("dana").String()); len(paths) != 0 {
		t.Fatalf("an engine with no members: %v", paths)
	}
	if paths := search(engine, "sidecar", evsTestId("my laptop").String()); !slices.Equal(paths, []string{"r/note", "r/secret"}) {
		t.Fatalf("my laptop's rows: %v", paths)
	}
	if _, err := engine.Search(context.Background(), &SearchRequest{Text: "limiter", Filters: []SearchFieldFilter{{Name: "member", Value: "not an id"}}}); !errors.Is(err, ErrSearchRequest) {
		t.Fatalf("a member that is no id: %v", err)
	}
}
