//go:build !ios_extension

// search_agents (§16.10's agents row; §16.11's tools row; R-MCP-13, D-MCP-23, D-MCP-24, I-20, FS-88; SEARCH-M10-27):
// who is working on a task. search_agents(task) is search(task, kind [claim, handoff, ask, note, run], group_by agent),
// since SearchGroupSettings.AgentsSince unless the caller sets it; with no task it lists the agents active in the
// window. Its repos are a search's: the repos named, else every repo of the network this sidecar reads, which in a
// team network is the directory, whose run announcements it groups, the caller's own vault, for its run cards, and,
// for admins and auditors, the team record, each as §8.6's local evaluation lets this sidecar read it. A run reaches
// the directory only as its announcement (I-20), and a member who opted out announces nothing (owner decision 170), so
// nothing of theirs is found there. Each hit's trust is judged for the reader, and untrusted text is withheld unless
// the caller asks for it and its taint lands first (search_trust.go).
//
// The search tools are R: Agents files no request, signs nothing and is never evidence (§16.10's approvals row).
// Nothing here holds a task past the call or logs one (I-13). Safe for concurrent use as the engine is.

package sidecar

import (
	"context"
	"errors"
	"slices"
	"time"
)

// The record kinds search_agents reads (§16.10's agents row). Identifiers.
var searchAgentsKinds = []string{"claim", "handoff", "ask", "note", "run"}

// search_agents' request.
type SearchAgentsRequest struct {
	// The task, a query as search's; empty lists the agents active in the window.
	Task string
	// Zero: now less SearchGroupSettings.AgentsSince, and no end.
	Since time.Time
	Until time.Time
	// The repos read; empty reads the network's breadth, whose kind filter keeps only those logs' rows.
	Repos []Id
	// The groups returned at most; zero returns every one.
	GroupCount int
	// Untrusted text is returned, Taint called first.
	Include bool
	// Taints the caller's run, fsynced, before untrusted text is kept (D-MCP-16); nil refuses Include.
	Taint func(ctx context.Context) error
	// The reader each hit's trust is judged for; nil reads every hit untrusted.
	Reader *SearchTrustReader
	// The daemon's credentials and token forms, whose matches are withheld (I-7); nil matches nothing.
	Secret func(text []byte) bool
	// Whether a hit may be named at all, by its repo and whole path (MCP's guard); nil admits every hit.
	Admit func(repoId Id, path string) bool
	// The team directory's folded view (§16.11's tools row; DirectoryClient.SearchAgentsFold): reads each run
	// announcement hit at its item's current state and expiry, which a renewal moves and no index entry follows, and
	// answers the hits that stand. Nil leaves every hit as its row reads.
	Fold func(hits []SearchHit) []SearchHit
	// How long pages after the first may take, on the engine's clock; non-positive pages only the first. What landed
	// by then answers, incomplete.
	Wait time.Duration
}

// What search_agents answers.
type SearchAgentsResult struct {
	Groups []*SearchGroup
	// The search's running counts.
	Counts SearchHitCounts
	// Untrusted hits returned as stubs, and hits withheld for holding a credential.
	UntrustedWithheld int
	SecretWithheld    int
	// Every hit was read: no page left, and no more than SearchGroupSettings.AgentsHitCount.
	Complete bool
	// Untrusted text is in the groups: Taint ran first.
	Untrusted bool
	// The lowest trust of what the groups show: a stub's is never untrusted (searchShownTrust).
	Trust SearchTrust
	// The hits grouped, whole, and the cursor token that gave them, whose session their hit ids open in.
	hits   []SearchHit
	cursor string
}

// search_agents in session on networkId's engine: see the file header. ctx bounds the call: what landed by its end
// answers, incomplete.
func (self *SearchEngine) Agents(ctx context.Context, session Id, networkId Id, request *SearchAgentsRequest) (*SearchAgentsResult, error) {
	if request == nil || request.GroupCount < 0 {
		return nil, ErrSearchRequest
	}
	if request.Include && request.Taint == nil {
		return nil, ErrSearchToolInclude
	}
	settings := self.groups
	now := self.clock.Now()
	search := &SearchRequest{Text: request.Task, Repos: request.Repos, Since: request.Since, Until: request.Until}
	if search.Since.IsZero() {
		search.Since = now.Add(-settings.AgentsSince)
	}
	for _, kind := range searchAgentsKinds {
		search.Filters = append(search.Filters, SearchFieldFilter{Name: "kind", Value: kind})
	}
	stream, cursor, err := self.open(ctx, session, search)
	if err != nil {
		return nil, err
	}
	// its pages end with the call; the cursor stays, so its hits' ids open until it idles out
	defer self.cursors.finish(session, cursor)
	hits, progress, done, err := searchCollect(ctx, stream, self.clock, settings.AgentsHitCount, request.Wait, nil)
	if err != nil {
		return nil, err
	}
	if request.Admit != nil {
		hits = slices.DeleteFunc(hits, func(hit SearchHit) bool { return !request.Admit(hit.Repo, hit.Path) })
	}
	if request.Fold != nil {
		hits = request.Fold(hits)
	}
	result := &SearchAgentsResult{Counts: progress.Counts, Complete: done, hits: hits, cursor: cursor}
	searchJudgeTrust(hits, request.Reader)
	withheld, err := searchWithhold(ctx, hits, &searchWithholdArgs{
		reader: request.Reader, include: request.Include, taint: request.Taint, secret: request.Secret,
	})
	if err != nil {
		return nil, err
	}
	result.UntrustedWithheld, result.SecretWithheld, result.Untrusted = withheld.untrustedCount, withheld.secretCount, withheld.untrusted
	result.Trust = withheld.trust
	groups := searchGroup(hits, withheld.hits, SearchGroupByAgent, networkId, now, request.Reader, settings)
	if request.Task == "" {
		// no task: the agents active in the window
		active := []*SearchGroup{}
		for _, group := range groups {
			if group.Active {
				active = append(active, group)
			}
		}
		groups = active
	}
	if 0 < request.GroupCount && request.GroupCount < len(groups) {
		groups = groups[:request.GroupCount]
	}
	if stream.scopeEnded() {
		return nil, ErrSearchCursorExpired
	}
	result.Groups = groups
	return result, nil
}

// Pages of stream until it holds count hits, the search is done or wait passes on clock, the first page computed
// whatever the wait; hits past count go back to the stream, first on its next page, so a page is never revised. report
// gets the search's progress as pages and "search more" land, never after this returns; nil reports nothing. The
// progress answered is the last page's.
func searchCollect(ctx context.Context, stream *searchEngineStream, clock Clock, count int, wait time.Duration, report func(progress SearchProgress)) ([]SearchHit, SearchProgress, bool, error) {
	waitCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if 0 < wait {
		stop := clock.AfterFunc(wait, cancel)
		defer stop()
	}
	hits := []SearchHit{}
	progress := stream.currentProgress()
	done := false
	for first := true; len(hits) < count && !done; first = false {
		pageCtx := waitCtx
		if first {
			pageCtx = ctx
		}
		page, pageProgress, pageDone, err := stream.nextReporting(pageCtx, report)
		if err != nil {
			if !errors.Is(err, ErrSearchCursorExpired) && !first && waitCtx.Err() != nil && ctx.Err() == nil {
				// the wait ended mid-page: what landed answers
				break
			}
			return nil, progress, false, err
		}
		hits = append(hits, page...)
		progress, done = pageProgress, pageDone
		if report != nil && !done {
			report(progress)
		}
		if wait <= 0 || waitCtx.Err() != nil {
			// no wait: the first page alone; or the wait ended
			break
		}
	}
	if count < len(hits) {
		stream.holdBack(hits[count:])
		hits = hits[:count]
		done = false
	}
	return hits, progress, done, nil
}
