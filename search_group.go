//go:build !ios_extension

// Groups (§16.10's group row; R-MCP-13, D-MCP-23, D-MCP-24, FS-80, FS-88; SEARCH-M10-27): a search's hits by agent,
// by run or by repo, as search's group_by and search_agents give them.
//
//	agent   key (network, sidecar_id, agent label, else agent_id), from a record entry's or run card's registered
//	        fields (the writer as the hit's signer, 8 agent_id, 9 the label) or a directory announcement's (the
//	        sidecar_id as its signer, 8, 9); a hit with no signer, label or agent_id is in no agent's group
//	run     key run_id (field 10)
//	repo    key repo_id
//	shows   the label, the sidecar, its member or sponsor, last_activity (its newest hit), active, runs (run_id,
//	        title, started, last activity, ended), claims (the claim's name, text, expires, state), hit_count and its
//	        newest TopHitCount hits; active groups first, then the newest, then by key
//	active  an unexpired claim not handed off or released; an unexpired run announcement in state active; or a run
//	        card whose run has no Coverage entry (its row's expires unset) that moved within ActiveWindow
//	trust   a group's trust is the lowest of what its hits show as returned, and it is a stub when any of them is
//	        withheld: a group of stubs holds no untrusted text, so returning it taints nothing (§16.10's example)
//	shown   groups are keyed on the whole hits, but everything a group shows comes from its hits as they are
//	        returned (searchWithhold): a stub's text, label, run or claim name stays withheld in its group too, and a
//	        group no hit of which shows who it is keys on a hash of its key and names no agent, run or sidecar
//
// Active reads a claim's expiry and state and a run's state and times, which no stub shows, so an untrusted agent's
// group still says whether it is active. Nothing here holds a query or logs a hit (I-13). Safe for concurrent use:
// every function reads only its arguments.

package sidecar

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"time"
)

// §16.10's group_by.
type SearchGroupBy string

const (
	SearchGroupByNone  SearchGroupBy = ""
	SearchGroupByAgent SearchGroupBy = "agent"
	SearchGroupByRun   SearchGroupBy = "run"
	SearchGroupByRepo  SearchGroupBy = "repo"
)

// The record kinds and states grouping reads, as their registries name them (RECORD.md 6.3 and 7.3; §16.11's
// states). Identifiers.
const (
	searchKindClaim      = "claim"
	searchKindRun        = "run"
	searchStateActive    = "active"
	searchStateHandedOff = "handed_off"
	searchStateReleased  = "released"
)

// A claim's expiry as a record row writes it (indexRecordTime's RFC 3339 to the second). An identifier of the format.
const searchClaimTimeLayout = "2006-01-02T15:04:05Z"

// What grouping and search_agents hold to.
type SearchGroupSettings struct {
	// Hits a group shows: 3 (§16.10's result row). Positive.
	TopHitCount int
	// A run card's run is active while the card moved this recently and no Coverage entry ended it: 10 min (§16.10's
	// group row). Positive.
	ActiveWindow time.Duration
	// search_agents' window where the caller sets none: 30 days (§16.10's agents row). Positive.
	AgentsSince time.Duration
	// Hits search_agents reads before it groups: 1,000, so a broad task stays within a few pages' work; past it the
	// result reads incomplete. Positive.
	AgentsHitCount int
}

// The defaults, the only source of their values. A fresh value each call.
func DefaultSearchGroupSettings() *SearchGroupSettings {
	return &SearchGroupSettings{TopHitCount: 3, ActiveWindow: 10 * time.Minute, AgentsSince: 30 * 24 * time.Hour, AgentsHitCount: 1000}
}

// Refuses values no grouping can run on.
func (self *SearchGroupSettings) check() error {
	if self.TopHitCount <= 0 || self.ActiveWindow <= 0 || self.AgentsSince <= 0 || self.AgentsHitCount <= 0 {
		return fmt.Errorf("%w: search grouping's bounds", errInvalidSettings)
	}
	return nil
}

// One run a group holds.
type SearchGroupRun struct {
	// Empty where every hit of the run is a stub that withholds it.
	RunId string
	// Empty in a stub.
	Title        string
	Started      time.Time
	LastActivity time.Time
	// Zero while the run has no Coverage entry.
	Ended time.Time
}

// One claim a group holds.
type SearchGroupClaim struct {
	// The claim entry's name in its log, or the doc key in hex where the hit is a stub.
	ClaimId string
	// Empty in a stub.
	Text string
	// Zero and empty in a stub.
	Expires time.Time
	State   string
}

// One group of hits (§16.10's search out row's groups).
type SearchGroup struct {
	Key string
	// The agent's label and id, empty where no hit of the group shows them.
	AgentLabel string
	AgentId    string
	// The sidecar the agent runs on, and its member or sponsor, where a hit shows the sidecar and the reader's state
	// names its member.
	SidecarId *Id
	MemberId  *Id
	// The lowest trust of its hits, and whether any of them is a stub.
	Trust        SearchTrust
	Stub         bool
	Active       bool
	LastActivity time.Time
	Runs         []*SearchGroupRun
	Claims       []*SearchGroupClaim
	HitCount     int
	// Its newest hits as returned, at most TopHitCount.
	Top []SearchHit
}

// The key a hit groups under by, and whether it groups at all.
func searchGroupKey(hit *SearchHit, by SearchGroupBy, networkId Id) (string, bool) {
	switch by {
	case SearchGroupByRepo:
		return hit.Repo.String(), true
	case SearchGroupByRun:
		runId := searchHitField(hit, searchFieldRunId)
		return runId, runId != ""
	case SearchGroupByAgent:
		agent := searchHitField(hit, searchFieldAgentLabel)
		if agent == "" {
			if agentId := searchHitField(hit, searchFieldAgentId); agentId != "" {
				agent = "id:" + agentId
			}
		}
		if hit.Signer == (Id{}) && agent == "" {
			return "", false
		}
		return networkId.String() + "/" + hit.Signer.String() + "/" + agent, true
	}
	return "", false
}

// Whether view, hit as returned, shows the agent the key names: its label, else its agent_id, else its sidecar, each
// with the sidecar the key took.
func searchGroupShowsAgent(hit *SearchHit, view *SearchHit) bool {
	if view.Signer != hit.Signer {
		return false
	}
	if label := searchHitField(hit, searchFieldAgentLabel); label != "" {
		return searchHitField(view, searchFieldAgentLabel) == label
	}
	if agentId := searchHitField(hit, searchFieldAgentId); agentId != "" {
		return searchHitField(view, searchFieldAgentId) == agentId
	}
	return hit.Signer != (Id{})
}

// Whether hit keeps its group active at now.
func searchHitActive(hit *SearchHit, now time.Time, settings *SearchGroupSettings) bool {
	switch searchHitField(hit, searchFieldKind) {
	case searchKindClaim:
		state := searchHitField(hit, searchFieldClaimState)
		if state == searchStateHandedOff || state == searchStateReleased {
			return false
		}
		expires, err := time.Parse(searchClaimTimeLayout, searchHitField(hit, searchFieldClaimExpires))
		return err == nil && now.Before(expires)
	case searchKindRun:
		// a directory announcement carries its state in field 15, which a run card leaves empty
		if state := searchHitField(hit, searchFieldState); state != "" {
			return state == searchStateActive && now.Before(hit.Expires)
		}
		// a run card: no Coverage entry ended it, and it moved within the window
		return hit.Expires.IsZero() && now.Sub(hit.Time) <= settings.ActiveWindow
	}
	return false
}

// Groups hits by by at now, in §16.10's order: see the file header. hits are judged for reader (searchJudgeTrust),
// which names each sidecar's member or sponsor, and shown[i] is hits[i] as the call returns it (searchWithhold's hits).
// A group's trust is the lowest of what its hits show (searchShownTrust). Nil for SearchGroupByNone.
func searchGroup(hits []SearchHit, shown []SearchHit, by SearchGroupBy, networkId Id, now time.Time, reader *SearchTrustReader, settings *SearchGroupSettings) []*SearchGroup {
	if by == SearchGroupByNone || len(hits) != len(shown) {
		return nil
	}
	groups := map[string]*SearchGroup{}
	// whether any hit of a group shows who the group is
	named := map[*SearchGroup]bool{}
	for index := range hits {
		hit, view := &hits[index], &shown[index]
		key, ok := searchGroupKey(hit, by, networkId)
		if !ok {
			continue
		}
		group := groups[key]
		if group == nil {
			group = &SearchGroup{Key: key, Trust: SearchTrustOwn}
			groups[key] = group
		}
		switch by {
		case SearchGroupByAgent:
			if !named[group] && searchGroupShowsAgent(hit, view) {
				named[group] = true
				group.AgentLabel = searchHitField(view, searchFieldAgentLabel)
				group.AgentId = searchHitField(view, searchFieldAgentId)
				if view.Signer != (Id{}) {
					sidecarId := view.Signer
					group.SidecarId = &sidecarId
					if memberId, ok := reader.memberOf(sidecarId); ok {
						group.MemberId = &memberId
					}
				}
			}
		case SearchGroupByRun:
			named[group] = named[group] || searchHitField(view, searchFieldRunId) != ""
		case SearchGroupByRepo:
			named[group] = true
		}
		group.HitCount += 1
		group.Trust = searchTrustMin(group.Trust, searchShownTrust(view, reader))
		group.Stub = group.Stub || view.Withheld
		if group.LastActivity.Before(hit.Time) {
			group.LastActivity = hit.Time
		}
		group.Active = group.Active || searchHitActive(hit, now, settings)
		group.Top = append(group.Top, *view)
		switch searchHitField(hit, searchFieldKind) {
		case searchKindRun:
			run := &SearchGroupRun{
				RunId: searchHitField(view, searchFieldRunId), Title: searchHitField(view, indexFieldTitle),
				Started: hit.Started, LastActivity: hit.Time, Ended: hit.Expires,
			}
			if searchHitField(hit, searchFieldState) != "" {
				// an announcement's expires is its item's, not an end: the run ended only once handed off
				run.Ended = time.Time{}
			}
			held := slices.IndexFunc(group.Runs, func(held *SearchGroupRun) bool { return held.RunId != "" && held.RunId == run.RunId })
			switch {
			case held < 0:
				group.Runs = append(group.Runs, run)
			case group.Runs[held].LastActivity.Before(run.LastActivity):
				group.Runs[held] = run
			}
		case searchKindClaim:
			claim := &SearchGroupClaim{ClaimId: view.Path, Text: searchHitField(view, indexFieldTitle)}
			if view.Withheld {
				claim.ClaimId = hex.EncodeToString(hit.DocKey[:])
			} else {
				claim.State = searchHitField(view, searchFieldClaimState)
				if expires, err := time.Parse(searchClaimTimeLayout, searchHitField(view, searchFieldClaimExpires)); err == nil {
					claim.Expires = expires
				}
			}
			group.Claims = append(group.Claims, claim)
		}
	}
	ordered := make([]*SearchGroup, 0, len(groups))
	for _, group := range groups {
		if !named[group] {
			// no hit shows who the group is: its key is opaque, and it names no agent, run or sidecar
			sum := sha256.Sum256([]byte(group.Key))
			group.Key = hex.EncodeToString(sum[:16])
			group.AgentLabel, group.AgentId, group.SidecarId, group.MemberId = "", "", nil, nil
		}
		slices.SortStableFunc(group.Top, func(a SearchHit, b SearchHit) int {
			return b.Time.Compare(a.Time)
		})
		group.Top = group.Top[:min(len(group.Top), settings.TopHitCount)]
		slices.SortStableFunc(group.Runs, func(a *SearchGroupRun, b *SearchGroupRun) int {
			return cmp.Or(b.LastActivity.Compare(a.LastActivity), cmp.Compare(a.RunId, b.RunId))
		})
		ordered = append(ordered, group)
	}
	slices.SortFunc(ordered, func(a *SearchGroup, b *SearchGroup) int {
		if a.Active != b.Active {
			if a.Active {
				return -1
			}
			return 1
		}
		return cmp.Or(b.LastActivity.Compare(a.LastActivity), cmp.Compare(a.Key, b.Key))
	})
	return ordered
}
