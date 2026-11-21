//go:build !js && !ios && !android && !sdk_mobile_bind && !ios_extension

package sidecar

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"time"
)

const daemonSearchAllPrefix = "all."

func daemonSearchAllScope(raw json.RawMessage) bool {
	var selector struct{ Scope, Cursor string }
	return json.Unmarshal(raw, &selector) == nil && (selector.Scope == "all" || strings.HasPrefix(selector.Cursor, daemonSearchAllPrefix))
}

type daemonSearchLeg struct {
	tools  *SearchTools
	env    *SearchToolEnv
	stream *searchEngineStream
	done   bool
}

func daemonSearchAll(ctx context.Context, call *DaemonCall, params *daemonSearchParams,
	envOf func(*DaemonCall) (*SearchTools, *SearchToolEnv, error), matcherOf func(*DaemonCall, *SearchToolEnv) error) (*SearchToolResult, error) {
	if params.Network != "" || len(params.Repos) != 0 || params.Ref != "" || !slices.Contains([]string{"", "network", "all"}, params.Scope) {
		return nil, ErrSearchToolArguments
	}
	if len(call.Networks) == 0 {
		return nil, ErrSidecarSearchUnavailable
	}
	args := params.SearchToolArgs
	args.Scope = "network"
	networkIds, legs, err := daemonSearchLegs(ctx, call, envOf, matcherOf)
	if err != nil {
		return nil, err
	}
	first := legs[0]
	wait, err := first.tools.wait(args.WaitMs)
	if err != nil {
		return nil, err
	}
	grouped := args.GroupBy != "" && args.GroupBy != "none"
	defaultCount, maxCount := first.tools.settings.HitCount, first.tools.settings.HitMaxCount
	if grouped {
		defaultCount, maxCount = first.tools.settings.GroupCount, first.tools.settings.GroupMaxCount
	}
	limit, err := searchToolCount(args.Limit, defaultCount, maxCount)
	if err != nil {
		return nil, err
	}
	hosted, err := daemonHostedCursor(ctx, networkIds, legs, &args, limit)
	if err != nil {
		return nil, err
	}
	return hosted.page(ctx, call, params.Progress, &args, legs, limit, first.tools.engine.clock.Now().Add(wait))
}

// Opens each network through its normal search tools and binds each result to the host's full credential filter.
func daemonSearchLegs(ctx context.Context, call *DaemonCall,
	envOf func(*DaemonCall) (*SearchTools, *SearchToolEnv, error), matcherOf func(*DaemonCall, *SearchToolEnv) error) ([]Id, []daemonSearchLeg, error) {
	networkIds := make([]Id, 0, len(call.Networks))
	legs := make([]daemonSearchLeg, 0, len(call.Networks))
	matchers := []func([]byte) bool{}
	tainters := []func(context.Context) error{}
	for _, network := range call.Networks {
		child := *call
		child.NetworkId, child.Sidecar = network.NetworkId, network.Sidecar
		tools, env, err := envOf(&child)
		if err != nil {
			return nil, nil, err
		}
		if err := matcherOf(&child, env); err != nil {
			return nil, nil, err
		}
		networkIds = append(networkIds, network.NetworkId)
		legs = append(legs, daemonSearchLeg{tools: tools, env: env})
		matchers = append(matchers, env.Secret)
		tainters = append(tainters, env.Taint)
	}
	// A result from any network passes the daemon's credential filters. If it contains untrusted text, the
	// querying harness can have its run in any of these networks.
	taint := sync.OnceValue(func() error {
		for _, mark := range tainters {
			if err := mark(ctx); err != nil {
				return err
			}
		}
		return nil
	})
	for _, leg := range legs {
		leg.env.Secret = func(text []byte) bool {
			return slices.ContainsFunc(matchers, func(matches func([]byte) bool) bool { return matches != nil && matches(text) })
		}
		leg.env.Taint = func(context.Context) error { return taint() }
	}
	return networkIds, legs, nil
}

func daemonHostedCursor(ctx context.Context, networkIds []Id, legs []daemonSearchLeg, args *SearchToolArgs, limit int) (*daemonHostedSearch, error) {
	var err error
	first := legs[0]
	var hosted *daemonHostedSearch
	if args.Cursor == "" {
		hosted = &daemonHostedSearch{networkIds: networkIds}
		for i := range legs {
			leg := &legs[i]
			stream, token, err := leg.tools.stream(ctx, leg.env.Session, args, leg.tools.reader(), limit)
			if err != nil {
				for _, previous := range legs[:i] {
					previous.stream.Close()
				}
				return nil, err
			}
			leg.stream = stream
			hosted.tokens = append(hosted.tokens, token)
		}
		err = first.tools.engine.cursors.visit(first.env.Session, hosted.tokens[0], func(cursor *searchCursor) { cursor.hosted = hosted })
	} else {
		token, ok := strings.CutPrefix(args.Cursor, daemonSearchAllPrefix)
		if !ok {
			return nil, ErrSearchCursorInvalid
		}
		err = first.tools.engine.cursors.visit(first.env.Session, token, func(cursor *searchCursor) { hosted = cursor.hosted })
	}
	if err != nil {
		return nil, err
	}
	if hosted == nil {
		return nil, ErrSearchCursorInvalid
	}
	if !slices.Equal(hosted.networkIds, networkIds) {
		return nil, ErrSearchCursorExpired
	}
	return hosted, nil
}

func (hosted *daemonHostedSearch) page(ctx context.Context, call *DaemonCall, report bool, args *SearchToolArgs, legs []daemonSearchLeg, limit int, deadline time.Time) (*SearchToolResult, error) {
	hosted.pageLock.Lock()
	defer hosted.pageLock.Unlock()
	if hosted.closed {
		return nil, ErrSearchCursorExpired
	}
	for i := range legs {
		leg := &legs[i]
		err := leg.tools.engine.cursors.visit(leg.env.Session, hosted.tokens[i], func(cursor *searchCursor) {
			leg.stream, leg.done = cursor.stream, cursor.finished
		})
		if err != nil {
			hosted.closed = true
			return nil, err
		}
	}
	// Start each requested download independently of which network's hits fill this page.
	for _, leg := range legs {
		if !leg.done && leg.stream.request.Scope == SearchAll && leg.stream.engine.args.Policy != nil {
			leg.stream.beginWindow()
		}
	}
	result := &SearchToolResult{Hits: []*SearchToolHit{}, Coverage: []*SearchToolCoverage{}, Status: SearchToolStatus{Trust: string(SearchTrustOwn)}}
	clock := legs[0].tools.engine.clock
	start := hosted.next
	remaining := limit
	for offset := range legs {
		i := (start + offset) % len(legs)
		leg := &legs[i]
		if leg.done {
			continue
		}
		child := *args
		child.Cursor = hosted.tokens[i]
		child.Limit = remaining
		leftMs := int(max(time.Duration(0), deadline.Sub(clock.Now())).Milliseconds())
		child.WaitMs = &leftMs
		if report && call.Notify != nil {
			leg.env.Report = func(progress *SearchToolProgress) {
				total := *progress
				for j, other := range legs {
					if i != j {
						p := other.stream.currentProgress()
						total.Searched += p.Searched
						total.Total += p.Total
						total.FetchBytes += p.FetchBytes
						total.FetchedBytes += p.FetchedBytes
						total.Uncovered += p.Uncovered
						total.Counts.add(searchToolCountsOf(&p))
					}
				}
				call.Notify(DaemonMethodSearchProgress, &total)
			}
		}
		part, err := leg.tools.Search(ctx, leg.env, &child)
		if err != nil {
			// Earlier legs of this page may have advanced. A retry must begin with a fresh set of cursors.
			hosted.closed = true
			for _, leg := range legs {
				leg.stream.Close()
			}
			return nil, err
		}
		leg.done = part.Status.Complete
		result.Status.Tainted = result.Status.Tainted || part.Status.Tainted
		result.Status.Trust = string(searchTrustMin(SearchTrust(result.Status.Trust), SearchTrust(part.Status.Trust)))
		result.Counts.UntrustedWithheld += part.Counts.UntrustedWithheld
		result.Hits = append(result.Hits, part.Hits...)
		for _, group := range part.Groups {
			group.Network = hosted.networkIds[i].String()
		}
		result.Groups = append(result.Groups, part.Groups...)
		remaining -= len(part.Hits) + len(part.Groups)
		hosted.next = (i + 1) % len(legs)
		if remaining == 0 || !clock.Now().Before(deadline) {
			break
		}
	}
	result.Status.Complete = true
	for i, leg := range legs {
		if leg.stream.scopeEnded() {
			return nil, ErrSearchCursorExpired
		}
		progress := leg.stream.currentProgress()
		result.Status.Complete = result.Status.Complete && leg.done
		result.Status.TooBroad = result.Status.TooBroad || progress.TooBroad
		result.Status.MeteredBytes += progress.FetchedBytes
		result.Counts.add(searchToolCountsOf(&progress))
		for _, row := range searchToolCoverageOf(&progress) {
			row.Network = hosted.networkIds[i].String()
			result.Coverage = append(result.Coverage, row)
		}
		if leg.stream.isClosed() && !leg.done {
			return nil, ErrSearchCursorExpired
		}
	}
	switch args.Sort {
	case "time":
		slices.SortStableFunc(result.Hits, func(a, b *SearchToolHit) int { return strings.Compare(b.Time, a.Time) })
	case "path":
		path := func(hit *SearchToolHit) string {
			if hit.Open != nil {
				if path, ok := hit.Open.Arguments["path"].(string); ok {
					return path
				}
			}
			return ""
		}
		slices.SortStableFunc(result.Hits, func(a, b *SearchToolHit) int { return strings.Compare(path(a), path(b)) })
	}
	if !result.Status.Complete {
		result.Status.NextCursor = daemonSearchAllPrefix + hosted.tokens[0]
	} else {
		hosted.closed = true
	}
	return result, nil
}

func (self *SearchToolCounts) add(counts SearchToolCounts) {
	self.Confirmed += counts.Confirmed
	self.Possible += counts.Possible
	self.Near += counts.Near
	self.Masked += counts.Masked
	self.Repos += counts.Repos
	self.Excluded += counts.Excluded
}
