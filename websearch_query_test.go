//go:build !ios_extension && !sidecar_http && !js

package sidecar

// The query check (SRCH-M13-10; D-SRCH-4): secrets refused, personal data confirmed by an attached person and refused
// otherwise, and a tainted run's URL or host refused unless its fetches may reach it.

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// Synthetic values the record's rules match: a GitHub token's shape, an example address and a reserved number.
const (
	testWebSearchSecret = "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
	testWebSearchEmail  = "someone@mail.example"
	testWebSearchPhone  = "+15555550123"
)

// The check's corpus at the check itself: each kind found in the field it was in, by its rule, the text never kept.
func TestWebSearchQueryCheckFindings(t *testing.T) {
	check := CheckWebSearchQuery("find "+testWebSearchSecret, []string{"plain words", "mail " + testWebSearchEmail, "call " + testWebSearchPhone,
		"read https://docs.search.example/page and docs.other.example"})
	if len(check.Secrets) != 1 || check.Secrets[0].Field != "objective" || check.Secrets[0].Rule != "github-pat" {
		t.Fatalf("secrets %+v", check.Secrets)
	}
	rules := []string{}
	for _, finding := range check.Personal {
		rules = append(rules, finding.Field+" "+finding.Rule)
	}
	if !slices.Equal(rules, []string{"queries[1] pii-email", "queries[2] pii-phone"}) {
		t.Fatalf("personal %v", rules)
	}
	if !slices.Equal(check.Urls, []string{"https://docs.search.example/page"}) || !slices.Contains(check.Hosts, "docs.other.example") {
		t.Fatalf("urls %v, hosts %v", check.Urls, check.Hosts)
	}
	clean := CheckWebSearchQuery("an objective about synthetic tests", []string{"three word query", "version 1.2 release"})
	if len(clean.Secrets) != 0 || len(clean.Personal) != 0 || len(clean.Urls) != 0 || len(clean.Hosts) != 0 {
		t.Fatalf("a clean query found %+v", clean)
	}
}

// The corpus through the tool: a secret refused and nothing searched; personal data confirmed by an attached person,
// refused when they say no and when no one is attached; a tainted run's unlisted URL or host refused
// unlisted_url_in_query, a listed one let through, and an untainted run's URL let through.
func TestWebSearchQueryCheckCorpus(t *testing.T) {
	confirm := func(world *testWebSearchToolWorld, yes bool) {
		world.attached = true
		world.answer = func(request *HarnessUiRequest) (*HarnessUiResponse, error) {
			return &HarnessUiResponse{Id: request.Id, Confirmed: &yes}, nil
		}
	}
	world := newTestWebSearchToolWorld(t)
	if _, err := world.execute(`{"queries":["token ` + testWebSearchSecret + `"]}`); WebSearchErrorCode(err) != WebSearchCodeQueryRefused ||
		!strings.Contains(err.Error(), "github-pat") || strings.Contains(err.Error(), testWebSearchSecret) || world.searcher.count() != 0 {
		t.Fatalf("a secret: %v", err)
	}
	for _, personal := range []string{testWebSearchEmail, testWebSearchPhone} {
		args := `{"objective":"look up ` + personal + `","queries":["synthetic"]}`
		world = newTestWebSearchToolWorld(t)
		if _, err := world.execute(args); WebSearchErrorCode(err) != WebSearchCodeQueryRefused || world.searcher.count() != 0 {
			t.Fatalf("%s unattended: %v", personal, err)
		}
		world = newTestWebSearchToolWorld(t)
		confirm(world, false)
		if _, err := world.execute(args); WebSearchErrorCode(err) != WebSearchCodeQueryRefused || world.searcher.count() != 0 {
			t.Fatalf("%s declined: %v", personal, err)
		}
		world = newTestWebSearchToolWorld(t)
		confirm(world, true)
		if _, err := world.execute(args); err != nil || world.searcher.count() != 1 {
			t.Fatalf("%s confirmed: %v", personal, err)
		}
		if len(world.asked) != 1 || world.asked[0].Method != HarnessUiConfirm || !strings.Contains(world.asked[0].Message, personal) {
			t.Fatalf("%s: the confirm %+v", personal, world.asked)
		}
	}
	urlArgs := `{"queries":["read https://docs.search.example/page"]}`
	hostArgs := `{"queries":["read docs.search.example"]}`
	world = newTestWebSearchToolWorld(t)
	if _, err := world.execute(urlArgs); err != nil {
		t.Fatalf("an untainted run's URL: %v", err)
	}
	world = newTestWebSearchToolWorld(t)
	if err := world.run.Taint(context.Background(), RunTaintUntrustedData); err != nil {
		t.Fatal(err)
	}
	for _, args := range []string{urlArgs, hostArgs} {
		if _, err := world.execute(args); WebSearchErrorCode(err) != WebSearchCodeUnlistedUrl || strings.Contains(err.Error(), "docs.search.example") {
			t.Fatalf("a tainted run's unlisted %s: %v", args, err)
		}
	}
	if world.searcher.count() != 0 {
		t.Fatal("a tainted run's unlisted URL was searched")
	}
	world.runUrls.urls["https://docs.search.example/page"] = true
	world.runUrls.hosts["docs.search.example"] = true
	for _, args := range []string{urlArgs, hostArgs} {
		if _, err := world.execute(args); err != nil {
			t.Fatalf("a tainted run's listed %s: %v", args, err)
		}
	}
	// with no fetch list at all, every URL or host in a tainted run's query is refused
	world.tool.runUrls = nil
	if _, err := world.execute(urlArgs); WebSearchErrorCode(err) != WebSearchCodeUnlistedUrl {
		t.Fatalf("no fetch list: %v", err)
	}
}
