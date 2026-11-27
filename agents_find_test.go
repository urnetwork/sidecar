//go:build !ios_extension && !sidecar_http

// agent_find (§20.8's second question, §20.10, D-SKILL-6): agents ranked for a task by their status and summary
// words, each match saying whether it rests on trusted text; a match resting on an untrusted writer's words is shown
// by its stub for the person to confirm, never called clear, so no agent's own words draw the person's message to it;
// the search index's hits add to the agents they name; scope team is refused.

package sidecar

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// The match of name, nil for none.
func testAgentFindMatch(found *AgentFindResult, name string) *AgentFindMatch {
	for _, match := range found.Matches {
		if match.Name == name {
			return match
		}
	}
	return nil
}

func TestAgentFindMarksUntrustedMatch(t *testing.T) {
	env := newTestAgentToolsEnv(t)
	ctx := env.world.ctx
	session := &testAgentsCaller{}
	// scraper's status and summary repeat the task's words to draw the message: it ranks close behind fix, on
	// untrusted text, so neither is clear
	answer, err := env.tools.Find(ctx, session.caller("helper"), &AgentFindToolArgs{Task: "rate limiter"}, HarnessUntrustedText)
	if err != nil {
		t.Fatal(err)
	}
	found := answer.Data.(*AgentFindResult)
	scraper, fix := testAgentFindMatch(found, "scraper"), testAgentFindMatch(found, "fix")
	if scraper == nil || fix == nil || len(found.Matches) != 2 {
		t.Fatalf("the matches: %+v", found.Matches)
	}
	if scraper.Trusted || scraper.Agent.Stub == nil || scraper.Agent.Activity != "" || !slices.Contains(scraper.Matched, AgentFindMatchedTask) {
		t.Fatalf("the untrusted match: %+v, %+v", scraper, scraper.Agent)
	}
	if !fix.Trusted || fix.Agent.Stub != nil || fix.Agent.Task != "fix the token bucket rate limiter" || !slices.Contains(fix.Matched, AgentFindMatchedTask) {
		t.Fatalf("the trusted match: %+v", fix)
	}
	if found.Clear != "" || !found.Confirm || answer.Untrusted || session.taintCount() != 0 {
		t.Fatalf("an answer whose best match is untrusted: clear %q, confirm %t, untrusted %t, %d taints", found.Clear, found.Confirm, answer.Untrusted, session.taintCount())
	}
	if strings.Contains(answer.Text, testAgentToolsInjection) || !strings.Contains(answer.Text, "confirm with your person") {
		t.Fatalf("the model's text: %s", answer.Text)
	}
	// on trusted text alone, one clear match may be messaged at once
	answer, err = env.tools.Find(ctx, session.caller("helper"), &AgentFindToolArgs{Task: "install docs"}, HarnessUntrustedText)
	if err != nil {
		t.Fatal(err)
	}
	found = answer.Data.(*AgentFindResult)
	if found.Clear != "docs" || found.Confirm || len(found.Matches) != 1 {
		t.Fatalf("a clear match: %+v", found)
	}
	// two trusted matches close together are the person's to choose
	if err := env.laptop.WriteStatus(ctx, &AgentStatusWrite{Name: "helper", Status: &AgentStatus{
		State: AgentStateWorking, Activity: "reading the docs", Task: "review the install docs", Updated: env.world.now(),
	}}); err != nil {
		t.Fatal(err)
	}
	answer, err = env.tools.Find(ctx, session.caller("fix"), &AgentFindToolArgs{Task: "install docs"}, HarnessUntrustedText)
	if err != nil {
		t.Fatal(err)
	}
	if found := answer.Data.(*AgentFindResult); found.Clear != "" || !found.Confirm || len(found.Matches) != 2 {
		t.Fatalf("a near tie: %+v", found)
	}
	// untrusted: include returns scraper's words once the run is tainted
	answer, err = env.tools.Find(ctx, session.caller("helper"), &AgentFindToolArgs{Task: "rate limiter", Untrusted: "include"}, HarnessUntrustedText)
	if err != nil {
		t.Fatal(err)
	}
	if session.taintCount() != 1 || !answer.Untrusted || testAgentFindMatch(answer.Data.(*AgentFindResult), "scraper").Agent.Activity != testAgentToolsInjection {
		t.Fatalf("include: %d taints, %+v", session.taintCount(), answer)
	}
	if _, err := env.tools.Find(ctx, session.caller("helper"), &AgentFindToolArgs{Task: "rate limiter", Scope: AgentFindScopeTeam}, nil); !errors.Is(err, ErrAgentFindScope) {
		t.Fatalf("scope team: %v", err)
	}
	if _, err := env.tools.Find(ctx, session.caller("helper"), &AgentFindToolArgs{Task: "- a -"}, nil); !errors.Is(err, ErrAgentFindTask) {
		t.Fatalf("a task with no word: %v", err)
	}
}

// The index's hits count for the agents whose status or summary they name, on that text's trust: a near match the
// scan's words miss ranks, and the scan alone ranks when the index answers nothing.
func TestAgentFindIndexAddsNearMatches(t *testing.T) {
	env := newTestAgentToolsEnv(t)
	ctx := env.world.ctx
	asked := []string{}
	index := func(ctx context.Context, repoId Id, task string) ([]string, error) {
		asked = append(asked, task)
		return []string{"summary/fix.md", "status/docs.json", "cards/helper.json", "status/nobody.json"}, nil
	}
	// a typo the scan's words miss
	found, err := env.laptop.Find(ctx, &AgentFindArgs{Task: "refll", ForModel: true, Index: index})
	if err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0] != "refll" || !found.Indexed {
		t.Fatalf("the index asked %v, indexed %t", asked, found.Indexed)
	}
	fix, docs := testAgentFindMatch(found, "fix"), testAgentFindMatch(found, "docs")
	if fix == nil || docs == nil || len(found.Matches) != 2 || !fix.Trusted || !slices.Contains(fix.Matched, AgentFindMatchedIndex) {
		t.Fatalf("the index's matches: %+v", found.Matches)
	}
	// an index that fails leaves the scan to rank alone
	found, err = env.laptop.Find(ctx, &AgentFindArgs{Task: "limiter", ForModel: true, Index: func(ctx context.Context, repoId Id, task string) ([]string, error) {
		return nil, ErrSidecarSearchUnavailable
	}})
	if err != nil {
		t.Fatal(err)
	}
	if found.Indexed || testAgentFindMatch(found, "fix") == nil {
		t.Fatalf("with no index: %+v", found)
	}
}
