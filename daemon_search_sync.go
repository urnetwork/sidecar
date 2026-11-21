//go:build !js && !ios && !android && !sdk_mobile_bind && !ios_extension

// `ur search sync`'s control method (§16.10's CLI block; §18.4's modes; §5.9's state row; SEARCH-M10-30): search.sync
// on the call's network.
//
//	sync    a round now for each followed index ref of the named repo, or of every followed repo, as a hint would
//	        start one but at once (SearchSync.RunRound); more asks for the all set too, kept or not, as "search more"
//	        does (SearchSyncMore); a ref whose round fails is named, the others go on
//	evict   drops the network's cache, or the repo's, through SearchEngine.DropCache, which ends the searches reading
//	        it and keeps §5.9's non-derived state (search.state); the next rounds fetch what it dropped
//	policy  sets this device's all policy (§18.4's background, wifi_charging, on_demand or never) for the repo, or for
//	        every repo, through SidecarSearchState.SetPolicy; "default" restores the host's
//
// A person's command at a terminal: it signs nothing, files no request and sets no remote mode or index settings, and no
// MCP tool reaches it (D-MCP-17). An evict comes first, then the policy, then the rounds. Safe for concurrent use as the
// engine is.

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
)

// The control method `ur search sync` calls.
const DaemonMethodSearchSync = "search.sync"

var (
	// search.sync's arguments outside what it takes. Constant text: it never echoes an argument.
	ErrSearchSyncArguments = errors.New("search sync: a repo by id, and a policy of background, wifi_charging, on_demand, never or default")
)

// search.sync's params.
type DaemonSearchSyncParams struct {
	Network string `json:"network,omitempty"`
	// A repo by id ("id:" may lead it); empty for every followed repo.
	Repo   string `json:"repo,omitempty"`
	More   bool   `json:"more,omitempty"`
	Evict  bool   `json:"evict,omitempty"`
	Policy string `json:"policy,omitempty"`
}

// One ref whose round failed.
type DaemonSearchSyncFailure struct {
	RepoId string `json:"repo_id"`
	RefId  string `json:"ref_id"`
	Error  string `json:"error"`
}

// search.sync's reply.
type DaemonSearchSyncReply struct {
	// Refs a round ran on and finished.
	Synced int                        `json:"synced"`
	Failed []*DaemonSearchSyncFailure `json:"failed,omitempty"`
	// The cache was dropped.
	Evicted bool `json:"evicted,omitempty"`
	// The policy now set, "default" for the host's.
	Policy string `json:"policy,omitempty"`
}

// The followed refs of repoId, or of every repo, as [repo, ref] pairs.
func (self *SearchSync) followedRefs(repoId *Id) [][2]Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	keys := [][2]Id{}
	for key := range self.refs {
		if repoId == nil || key[0] == *repoId {
			keys = append(keys, key)
		}
	}
	return keys
}

// The daemon's search.sync method: see the file header.
func DaemonSearchSyncMethods() []*DaemonMethod {
	return []*DaemonMethod{{
		Name:    DaemonMethodSearchSync,
		Network: true,
		Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
			params := &DaemonSearchSyncParams{}
			if 0 < len(call.Params) {
				decoder := json.NewDecoder(bytes.NewReader(call.Params))
				decoder.DisallowUnknownFields()
				if err := decoder.Decode(params); err != nil {
					return nil, ErrSearchSyncArguments
				}
			}
			if call.Sidecar == nil {
				return nil, ErrSidecarSearchUnavailable
			}
			return daemonSearchSync(ctx, call.Sidecar, params)
		},
	}}
}

// What search.sync does on one Sidecar.
func daemonSearchSync(ctx context.Context, sidecar *Sidecar, params *DaemonSearchSyncParams) (*DaemonSearchSyncReply, error) {
	var repoId *Id
	if params.Repo != "" {
		parsed, err := ParseId(strings.TrimPrefix(params.Repo, "id:"))
		if err != nil {
			return nil, ErrSearchSyncArguments
		}
		repoId = &parsed
	}
	policy := params.Policy
	if policy == "default" {
		policy = ""
	}
	if policy != "" && !isSearchPolicy(policy) {
		return nil, ErrSearchSyncArguments
	}
	installed, err := sidecar.searchEngine()
	if err != nil {
		return nil, err
	}
	engine, ok := installed.(*SearchEngine)
	if !ok {
		return nil, ErrSidecarSearchUnavailable
	}
	return searchSyncNow(ctx, engine, sidecar.SearchState, repoId, policy, params)
}

// search.sync's work on engine, state giving this device's search state where a policy is set: evict, then the
// policy, then the rounds.
func searchSyncNow(ctx context.Context, engine *SearchEngine, state func() (*SidecarSearchState, error), repoId *Id, policy string, params *DaemonSearchSyncParams) (*DaemonSearchSyncReply, error) {
	reply := &DaemonSearchSyncReply{}
	if params.Evict {
		if err := engine.DropCache(repoId); err != nil {
			return nil, err
		}
		reply.Evicted = true
	}
	if params.Policy != "" {
		searchState, err := state()
		if err != nil {
			return nil, err
		}
		if err := searchState.SetPolicy(repoId, policy); err != nil {
			return nil, err
		}
		reply.Policy = params.Policy
	}
	if _, err := engine.args.Scope.Repos(ctx); err != nil {
		return nil, err
	}
	for _, key := range engine.args.Sync.followedRefs(repoId) {
		if err := engine.args.Sync.RunRound(ctx, key[0], key[1], params.More); err != nil {
			reply.Failed = append(reply.Failed, &DaemonSearchSyncFailure{RepoId: key[0].String(), RefId: key[1].String(), Error: err.Error()})
			continue
		}
		reply.Synced += 1
	}
	return reply, nil
}
