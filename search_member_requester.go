//go:build !sidecar_http && !ios_extension

package sidecar

import (
	"context"
	"errors"
	"slices"
)

// The app opens its local engine after its follower verifies enrollment. SEARCH uses the same engine and state.
type memberRequesterLocal struct {
	member *memberSearchHost
}

// Runs the requester's local search on the enrolled member's engine.
func (self memberRequesterLocal) Search(ctx context.Context, request *SearchRequest) (*SearchStream, error) {
	engine, err := self.member.open()
	if err != nil {
		return nil, err
	}
	return engine.Search(ctx, request)
}

// Reports local coverage for the requested repo, or for every repo when repo is nil.
func (self memberRequesterLocal) Status(repo *Id) (*SearchStatus, error) {
	engine, err := self.member.open()
	if err != nil {
		return nil, err
	}
	return engine.Status(repo)
}

// Drops the member engine's local search data for the requested scope.
func (self memberRequesterLocal) DropCache(repo *Id) error {
	engine, err := self.member.open()
	if err != nil {
		return err
	}
	return engine.DropCache(repo)
}

// Registers once per enrolled app replica. A new connect generation reattaches the same network's client and
// retains its served memory and open cursors. Ending the replica removes the component and closes those cursors.
func (self *MemberReplica) bindSearchRequester() error {
	running := self.running
	if !running.settings.Search.RemoteAsk {
		return nil
	}
	state, err := running.SearchState()
	if err != nil {
		return err
	}
	search := running.searchOf()
	search.stateLock.Lock()
	member := search.member
	search.stateLock.Unlock()
	if member == nil || member.ctx != self.ctx {
		return ErrSidecarSearchUnavailable
	}
	local := memberRequesterLocal{member: member}
	authority := newSearchRemoteHostAuthority(running, self.identity.NetworkId)
	client, err := NewSearchRemoteClient(&SearchRemoteClientArgs{
		Settings: running.settings.Search, Wire: &running.settings.ProtocolSettings.Search, State: state, Local: local,
		Config: authority.config, Services: authority.services, SelfId: func() (Id, bool) {
			if self.activeIdentity() == nil || !running.Admitted() {
				return Id{}, false
			}
			return self.identity.SidecarId, true
		},
		Foreground: running.SearchForeground, Conditions: func() SearchConditions {
			reported, _ := running.SearchConditions()
			foreground, _ := running.SearchForeground()
			return searchConditionsOf(reported, foreground, false)
		},
		ConfigWatch: self.watchRequesterConfig, DeviceName: self.searchDeviceName,
		OwnIndex: local.ownIndex, Masked: local.masked, Events: running.emitEvent, Clock: running.clock, Log: running.log,
	})
	if err != nil {
		return err
	}
	remove, err := running.AddComponent(client)
	if err != nil {
		client.Close()
		return err
	}
	search.stateLock.Lock()
	if search.member != member || search.networkId != self.identity.NetworkId {
		search.stateLock.Unlock()
		remove()
		return ErrSidecarSearchUnavailable
	}
	search.requester = client
	search.stateLock.Unlock()
	self.removeSearchRequester = func() {
		search.stateLock.Lock()
		if search.requester == client {
			search.requester = nil
		}
		search.stateLock.Unlock()
		remove()
	}
	return nil
}

// The generation may attach while the follower is still verifying its first head.
func (self *MemberReplica) watchRequesterConfig(notify func()) func() {
	ctx, cancel := context.WithCancel(self.ctx)
	go func() {
		client, err := self.follower.WaitStanding(ctx)
		if err != nil {
			return
		}
		remove := client.AddEntryCallback(func(*SidecarAuthorityEntry) { notify() })
		defer remove()
		notify()
		<-ctx.Done()
	}()
	return cancel
}

// Read the device label at the exact verified config head, without fetching it for a search.
func (self *MemberReplica) searchDeviceName(id Id) string {
	client := self.Config()
	if client == nil || client.Fork() != nil {
		return ""
	}
	state := client.State()
	if state == nil || state.Base() == nil {
		return ""
	}
	self.headsLock.Lock()
	heads := self.heads
	self.headsLock.Unlock()
	if heads == nil {
		return ""
	}
	base := state.Base()
	head := heads.CachedConfigHead(base.GetConfigVersion(), base.GetConfigHeadSha256())
	if head == nil {
		return ""
	}
	table, err := head.Names()
	if err != nil {
		return ""
	}
	names, err := ConfigNames(table, state.Rows().GetSidecars(), state.TeamScopeLabels())
	if err != nil {
		return ""
	}
	return names[id]
}

// Returns the local index pin and its recent chain values for judging an indexer's coverage.
func (self memberRequesterLocal) ownIndex(repo, ref Id) (SearchSyncPin, bool, []SearchSyncPinPair, bool) {
	engine, err := self.member.open()
	if err != nil {
		return SearchSyncPin{}, false, nil, false
	}
	indexId := engine.args.Scope.(*memberSearchSource).indexId(repo, ref)
	if indexId == (Id{}) {
		return SearchSyncPin{}, false, nil, false
	}
	syncer := engine.args.Sync
	syncer.stateLock.Lock()
	defer syncer.stateLock.Unlock()
	held := syncer.refs[[2]Id{repo, indexId}]
	if held == nil || held.manifest == nil || syncer.closed {
		return SearchSyncPin{}, false, nil, false
	}
	return held.manifest.Pin, searchRootCompanion(held.manifest.Root), slices.Clone(held.manifest.Pins), true
}

// An indexer's claim must survive our own ERASE, CUT and ref tombstones even if the remote cursor predates them.
// A missing local index is normal on a phone. Its independent sealed erasure masks still apply.
func (self memberRequesterLocal) masked(repo, ref Id, key [16]byte, version uint64) bool {
	engine, err := self.member.open()
	if err != nil {
		return true
	}
	indexId := engine.args.Scope.(*memberSearchSource).indexId(repo, ref)
	if indexId == (Id{}) {
		return true
	}
	snapshot, err := engine.args.Sync.Snapshot(repo, indexId)
	switch {
	case err == nil:
		defer snapshot.Release()
		probe, err := snapshot.Versions().Probe(key, &ref)
		return err != nil || version <= probe.ErasedThrough || version < probe.RefTombstoneVersion ||
			(probe.Tombstone && version <= probe.Version)
	case errors.Is(err, ErrSearchSyncUnfollowed), errors.Is(err, ErrSidecarStoreAbsent):
		mask, err := engine.args.Cache.erasedMask(repo, indexId, key)
		return err != nil || mask.Erase || version <= mask.Through
	default:
		return true
	}
}
