//go:build !js && !ios && !android && !sdk_mobile_bind && !ios_extension

package sidecar

// search.sync (SEARCH-M10-30's control method): a round now on every followed ref, all's too with more, a repo it names
// alone; evict drops the cache and keeps the search state; a policy is one of §18.4's, "default" the host's, and an
// unknown one or a repo that is no id is refused with constant text; and --explain's terms read the query as normalizer
// 1 does.

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestSearchSyncRunsRoundsEvictsAndSetsThePolicy(t *testing.T) {
	world := newTestEngineWorld(t, nil, testLive("doc", 0, 1, testHeadKeys(0, 0)))
	states := newSearchStateTestWorld(t)
	state := func() (*SidecarSearchState, error) { return states.state, nil }
	reply, err := searchSyncNow(context.Background(), world.engine, state, nil, "", &DaemonSearchSyncParams{More: true})
	if err != nil {
		t.Fatal(err)
	}
	if reply.Synced != 1 || len(reply.Failed) != 0 || reply.Evicted || reply.Policy != "" {
		t.Fatalf("a sync of every followed ref: %+v", reply)
	}
	repoId := world.sync.repoId
	reply, err = searchSyncNow(context.Background(), world.engine, state, &repoId, SearchPolicyNever, &DaemonSearchSyncParams{Evict: true, Policy: SearchPolicyNever})
	if err != nil {
		t.Fatal(err)
	}
	if reply.Synced != 1 || !reply.Evicted || reply.Policy != SearchPolicyNever {
		t.Fatalf("a sync that evicts and sets the policy: %+v", reply)
	}
	if mode, err := states.state.Policy(repoId); err != nil || mode != SearchPolicyNever {
		t.Fatalf("the repo's policy %q, %v", mode, err)
	}
	other := NewId()
	reply, err = searchSyncNow(context.Background(), world.engine, state, &other, "", &DaemonSearchSyncParams{})
	if err != nil || reply.Synced != 0 {
		t.Fatalf("a repo nothing follows: %+v, %v", reply, err)
	}
	for _, params := range []*DaemonSearchSyncParams{{Policy: "sometimes"}, {Repo: "not an id"}} {
		if _, err := daemonSearchSync(context.Background(), nil, params); !errors.Is(err, ErrSearchSyncArguments) {
			t.Errorf("%+v: %v", params, err)
		}
	}
}

func TestExplainSearchQuery(t *testing.T) {
	terms, err := ExplainSearchQuery(`rotate "the keys" subject:invoice -draft`)
	if err != nil {
		t.Fatal(err)
	}
	if len(terms) != 4 {
		t.Fatalf("%d terms", len(terms))
	}
	byText := map[string]*SearchTermExplain{}
	for _, term := range terms {
		byText[term.Text] = term
	}
	rotate, phrase, subject, draft := byText["rotate"], byText["the keys"], byText["invoice"], byText["draft"]
	if rotate == nil || phrase == nil || subject == nil || draft == nil {
		t.Fatalf("the terms %+v", terms)
	}
	if !slices.Equal(rotate.Trigrams, []string{"ate", "ota", "rot", "tat"}) || rotate.Field != "" || rotate.Excluded {
		t.Fatalf("rotate as %+v", rotate)
	}
	if !phrase.Phrase || !strings.Contains(strings.Join(phrase.Trigrams, ","), "e k") {
		t.Fatalf("the phrase as %+v", phrase)
	}
	if subject.Field != "subject" || !draft.Excluded || draft.Group != 0 {
		t.Fatalf("subject as %+v, draft as %+v", subject, draft)
	}
}
