//go:build !sidecar_http && !ios_extension

// Remote search's warm pairs and bit 1 (SEARCH-M10-33; §6.10's mark, window and keepalive rows; §6.11's bit 1; §18.4's
// remote row; §18.7's foreground row; D-PROTO-22, D-SDK-27, C19, R-CTX-37, X9; DESIGN-DETAILS 7.2.3 as amended for
// QD-707, QD-158): what the asker tells each generation's dispatcher, which owns the marking, the windows and the Ping
// grid (rpc_marked_pair.go, PROTO-M10-04 and PROTO-M10-06), and C19 beneath it in connect (PROTO-M10-02 to 05).
//
//	bit 1       asksSearch(d): the mode is not off, and d is an indexer E1 to E6 let answer this device for some repo it
//	            reads, own or with its notice member's answer allowing; recomputed from the state at each call, so a
//	            revoked indexer loses the bit at once, and none is set in mode off
//	warm pairs  at each foreground, and when the mode, an answer or the config's indexers move in it, the asker names at
//	            most three: the warm own set W, the first RemoteOwnAskCount (2) by ownKey of the own indexers E1 to E6
//	            let answer it for some repo, which are the two a search asks at once (QD-707), so no contract opens at a
//	            search on either; and, in mode on with its notice answered, the first other member's indexer by otherKey
//	            where some repo has no own indexer (RemoteOtherWarmCount, 1), whose contract then opens at the
//	            foreground and not at the search (owner decision 188). W is kept with the time it was named, and a search
//	            asks at once only its members, so it never asks two own indexers of which one is cold
//	foreground  Sidecar.SetSearchForeground (QD-158) feeds Subprotocol.SetForeground; a host that never calls it is in the
//	            background, where no keepalive runs
//
// Each warm pair costs C19's floor a window while the app is in the foreground (DESIGN-DETAILS 7.4).

package sidecar

import (
	"context"
	"slices"
	"time"
)

// Whether this device asks indexerId for remote search now: bit 1 toward it (the file header).
func (self *SearchRemoteClient) asksSearch(indexerId Id) bool {
	mode := self.mode()
	if mode == SearchRemoteOff {
		return false
	}
	state, err := self.args.Config()
	if err != nil || state == nil {
		return false
	}
	selfId, ok := self.args.SelfId()
	if !ok || !slices.Contains(self.eligibleAnywhere(state, selfId), indexerId) {
		return false
	}
	if searchRemoteOwn(state, indexerId, selfId) {
		return true
	}
	if mode != SearchRemoteOn {
		return false
	}
	memberId, ok := searchRemoteNoticeMember(state, indexerId)
	if !ok {
		return false
	}
	allow, answered := self.answer(memberId)
	return answered && allow
}

// The warm pairs now: the warm own set and the other member's beside it (the file header).
func (self *SearchRemoteClient) warmPairs() (own []Id, other []Id) {
	mode := self.mode()
	if mode == SearchRemoteOff {
		return nil, nil
	}
	state, err := self.args.Config()
	if err != nil || state == nil {
		return nil, nil
	}
	selfId, ok := self.args.SelfId()
	if !ok {
		return nil, nil
	}
	scope := self.scopeOf(state, selfId, &SearchRequest{})
	view, err := self.orderView(scope)
	if err != nil {
		return nil, nil
	}
	ownSet := map[Id]bool{}
	otherForUnowned := map[Id]bool{}
	for _, repoId := range scope {
		eligible := self.eligibleFor(view, repoId)
		hasOwn := false
		for _, indexerId := range eligible {
			if searchRemoteOwn(state, indexerId, selfId) {
				ownSet[indexerId] = true
				hasOwn = true
			}
		}
		if hasOwn {
			continue
		}
		for _, indexerId := range eligible {
			otherForUnowned[indexerId] = true
		}
	}
	for indexerId := range ownSet {
		own = append(own, indexerId)
	}
	searchRemoteSortBy(own, view.ownKey)
	own = own[:min(len(own), self.settings.RemoteOwnAskCount)]
	if mode != SearchRemoteOn {
		return own, nil
	}
	candidates := []Id{}
	for indexerId := range otherForUnowned {
		memberId, ok := searchRemoteNoticeMember(state, indexerId)
		if !ok {
			continue
		}
		if allow, answered := self.answer(memberId); answered && allow {
			candidates = append(candidates, indexerId)
		}
	}
	searchRemoteSortBy(candidates, view.otherKey)
	return own, candidates[:min(len(candidates), self.settings.RemoteOtherWarmCount)]
}

// Names the warm pairs to transport's dispatcher, the own ones first, and keeps the warm own set a search asks at once.
func (self *SearchRemoteClient) nameWarm(ctx context.Context, transport searchRemoteTransport) {
	own, other := self.warmPairs()
	named := append(slices.Clone(own), other...)
	if err := transport.MarkSearchPeers(ctx, named); err != nil && self.log.V(1).Enabled() {
		self.log.Infof("[search]the warm pairs were not all named: %s", err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.warmOwn, self.warmOther, self.warmAt = own, other, self.clock.Now()
}

// The warm own set and the other member's pair last named.
func (self *SearchRemoteClient) warm() (own []Id, other []Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.warmOwn), slices.Clone(self.warmOther)
}

// The foreground as the host last reported it, and a channel closed at its next change; background with no report.
func (self *SearchRemoteClient) foreground() (bool, chan struct{}) {
	if self.args.Foreground == nil {
		return false, nil
	}
	return self.args.Foreground()
}

// Follows one generation until ctx ends: bit 1 by asksSearch, the foreground to the dispatcher, and the warm pairs named
// at each foreground and each move of the mode, the answers or the config while in it.
func (self *SearchRemoteClient) follow(ctx context.Context, transport searchRemoteTransport) {
	if err := transport.SetAsksSearch(self.asksSearch); err != nil {
		self.log.Warningf("[search]remote search could not set bit 1: %s", err)
	}
	configMoved := make(chan struct{}, 1)
	if self.args.ConfigWatch != nil {
		stop := self.args.ConfigWatch(func() {
			select {
			case configMoved <- struct{}{}:
			default:
			}
		})
		defer stop()
	}
	for {
		foreground, foregroundChanged := self.foreground()
		_, stateChanged := self.args.State.Changes()
		transport.SetForeground(foreground)
		if foreground {
			self.nameWarm(ctx, transport)
		}
		select {
		case <-ctx.Done():
			return
		case <-foregroundChanged:
		case <-stateChanged:
		case <-configMoved:
		case <-self.clock.After(self.settings.ServeRecheckInterval):
		}
	}
}

// When the warm own set was last named.
func (self *SearchRemoteClient) warmNamedAt() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.warmAt
}
