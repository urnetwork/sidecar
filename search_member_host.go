//go:build !ios_extension

// A member's local search uses the same EVS client, verified config and sealed key store as its file reads.
package sidecar

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"

	"github.com/urnetwork/sidecar/protocol"
)

// One live per-network search binding. The daemon may bind it before its clients have opened.
type memberSearchHost struct {
	running   *Sidecar
	ctx       context.Context
	clients   func() (*EvsClient, *GkmGroupClient, error)
	buildLock sync.Mutex
	engine    *SearchEngine
	syncer    *SearchSync
}

// Binds the hosted network's existing clients. The cache and queries open on first use, after enrollment.
func (self *Sidecar) BindMemberSearch(ctx context.Context, clients func() (*EvsClient, *GkmGroupClient, error)) {
	if clients == nil {
		return
	}
	host := &memberSearchHost{running: self, ctx: ctx, clients: clients}
	search := self.searchOf()
	search.stateLock.Lock()
	search.member = host
	search.stateLock.Unlock()
	context.AfterFunc(ctx, func() {
		host.buildLock.Lock()
		defer host.buildLock.Unlock()
		if host.engine != nil {
			host.engine.Close()
			host.syncer.Close()
		}
		search.stateLock.Lock()
		defer search.stateLock.Unlock()
		if search.member == host {
			search.member = nil
		}
	})
}

// The exact generation already opened in the local sealed keychain. A search never causes a key delivery or fetch.
func (self *GkmGroupClient) localRepoKey(repo Id, generation uint64) (*EvsRepoKey, error) {
	if !self.holdsState() {
		return nil, ErrGkmUnavailable
	}
	held, err := self.heldGeneration(repo, generation)
	if err != nil {
		return nil, err
	}
	if held.key == nil {
		return nil, ErrGkmKeyMissing
	}
	return held.key, nil
}

// Opens this network's engine once its published config and its bound clients agree.
func (self *memberSearchHost) open() (*SearchEngine, error) {
	self.buildLock.Lock()
	defer self.buildLock.Unlock()
	if self.ctx.Err() != nil {
		return nil, ErrSidecarSearchUnavailable
	}
	if self.engine != nil {
		return self.engine, nil
	}
	running := self.running
	follower := running.ConfigFollower()
	if follower == nil || follower.Client() == nil || !running.Admitted() {
		return nil, ErrSidecarSearchUnavailable
	}
	evs, group, err := self.clients()
	if err != nil {
		return nil, err
	}
	if evs == nil || group == nil {
		return nil, ErrSidecarSearchUnavailable
	}
	record, err := running.Record()
	if err != nil {
		return nil, err
	}
	source := &memberSearchSource{host: self, evs: evs, group: group, record: record}
	if source.state() == nil {
		return nil, ErrSidecarSearchUnavailable
	}
	cache, err := running.SearchCache()
	if err != nil {
		return nil, err
	}
	state, err := running.SearchState()
	if err != nil {
		return nil, err
	}
	settings := running.settings.Search
	policy, err := NewSearchPolicy(&SearchPolicyArgs{Settings: settings, State: state, Clock: running.clock, Conditions: func() SearchConditions {
		conditions, _ := running.SearchConditions()
		foreground, _ := running.SearchForeground()
		return searchConditionsOf(conditions, foreground, settings.RemoteServe)
	}})
	if err != nil {
		return nil, err
	}
	limits := DefaultEvsFormatSettings()
	format := DefaultIndexFormatSettings()
	syncer, err := newSearchSync(&searchSyncArgs{cache: cache, settings: settings, format: format, clock: running.clock, log: running.log,
		events: running.searchEvents(), readPathCount: limits.ReadMaxPathCount, readByteCount: limits.ReadStreamMaxByteCount, budget: policy})
	if err != nil {
		return nil, err
	}
	engine, err := NewSearchEngine(&SearchEngineArgs{Settings: settings, Cache: cache, Sync: syncer, Policy: policy, Format: format, Scope: source, Gkm: evs.args.Gkm,
		Scan: source.scan, Events: running.searchEvents(), Clock: running.clock, Log: running.log})
	if err != nil {
		syncer.Close()
		return nil, err
	}
	self.engine, self.syncer = engine, syncer
	return engine, nil
}

// The record retention and the file view belong to the same authorized member.
type memberSearchSource struct {
	host   *memberSearchHost
	evs    *EvsClient
	group  *GkmGroupClient
	record *SidecarRecord
}

// Refuses pending, closed, locked, replaced or freshly revoked identities.
func (self *memberSearchSource) state() *ConfigState {
	running := self.host.running
	if self.host.ctx.Err() != nil || !running.Admitted() {
		return nil
	}
	if state, _ := running.instance.State(); state != SidecarInstanceOpen {
		return nil
	}
	follower := running.ConfigFollower()
	if follower == nil {
		return nil
	}
	client := follower.Client()
	if client == nil {
		return nil
	}
	state := client.State()
	id := running.Identity()
	if state == nil || id == nil || id.NetworkId != self.evs.NetworkId() || state.NetworkId() != id.NetworkId ||
		id.SidecarId != self.record.writer.sidecarId || !bytes.Equal(state.IdentityKey(id.SidecarId), id.IdentityPublicKey) {
		return nil
	}
	return state
}

// Every ref is named by local verified evidence and scoped to the reader that holds it.
func (self *memberSearchSource) Repos(ctx context.Context) ([]*SearchScopeRepo, error) {
	state := self.state()
	if state == nil {
		return nil, ErrSidecarSearchUnavailable
	}
	acl, err := state.Acl()
	if err != nil {
		return nil, err
	}
	subject := AclSidecarSubject(self.record.writer.sidecarId)
	now := self.host.running.clock.Now()
	var repos []*SearchScopeRepo
	for _, id := range acl.RepoIds() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		row := acl.Repo(id)
		if row == nil || row.Kind == protocol.RepoKind_REPO_KIND_SECRET {
			continue
		}
		rights := acl.EvsAccess(subject, id, AclTokenAudienceEvs, now).Rights
		repo := &SearchScopeRepo{RepoId: id, Kind: row.Kind, GroupInbox: AclRepoIsInbox(row), Readable: rights.Has(AclEvsRead), DepositOnly: !rights.Has(AclEvsRead) && rights.Has(AclEvsDeposit)}
		if !repo.Readable && !repo.DepositOnly {
			continue
		}
		repos = append(repos, repo)
		if !repo.Readable || indexRepoExcluded(repo.Kind) {
			continue
		}
		repo.ReceiptRequired = aclRepoKindOwnerBound(repo.Kind) && !rights.Has(AclEvsWrite)
		repo.valid = func() bool {
			current := self.state()
			return current != nil && bytes.Equal(current.Pin().Chain, state.Pin().Chain) && acl.EvsAccess(subject, id, AclTokenAudienceEvs, self.host.running.clock.Now()).Rights.Has(AclEvsRead)
		}
		if repo.Kind == protocol.RepoKind_REPO_KIND_DIRECTORY {
			r := self.record.Retention()
			repo.SearchableAge = memberSearchAge(r.SearchableDays(id, RecordClassCoordination), r.settings.Day)
		}
		repo.Refs, err = self.refs(repo)
		if err != nil {
			return nil, err
		}
	}
	return repos, nil
}

// Held generation one derives K_ref directly, without testing or authenticating any remote endpoint.
func (self *memberSearchSource) refKey(repo Id) (*EvsRefKey, error) {
	key, err := self.group.localRepoKey(repo, 1)
	if errors.Is(err, ErrGkmKeyMissing) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return NewEvsRefKey(key)
}

// The signed record reader knows each stream's name. The pins and sealed observations name ordinary file refs.
func (self *memberSearchSource) refs(repo *SearchScopeRepo) ([]*SearchScopeRef, error) {
	key, err := self.refKey(repo.RepoId)
	if err != nil || key == nil {
		return nil, err
	}
	refs := map[Id]*SearchScopeRef{}
	add := func(id Id, name string, def bool) {
		if id == (Id{}) || name == "" || name == string(EvsIndexRefName) {
			return
		}
		verified, err := EvsRefId(key, []byte(name))
		if err != nil || verified != id {
			return
		}
		refs[id] = &SearchScopeRef{RefId: id, Name: name, Default: def, Unbuilt: true}
	}
	if memberSearchRecordKind(repo.Kind) {
		reader := self.record.Reader()
		reader.stateLock.Lock()
		if log := reader.logs[repo.RepoId]; log != nil && log.complete {
			for writer, ref := range log.streamRefIds {
				add(ref, string(RecordStreamRefName(writer)), writer == self.record.writer.sidecarId)
			}
		}
		reader.stateLock.Unlock()
	}
	if repo.Kind == protocol.RepoKind_REPO_KIND_GENERAL && !repo.GroupInbox {
		pins, err := self.evs.pins.Pins(&repo.RepoId)
		if err != nil {
			return nil, err
		}
		for _, p := range pins {
			add(p.RefId, string(EvsMainRefName), true)
		}
		self.evs.pins.stateLock.Lock()
		if state := self.evs.pins.repoIdRepos[repo.RepoId]; state != nil {
			for _, r := range state.reads {
				if r.search != nil {
					add(r.RefId, r.search.RefName, r.search.RefName == string(EvsMainRefName))
				}
			}
		}
		self.evs.pins.stateLock.Unlock()
	}
	out := make([]*SearchScopeRef, 0, len(refs))
	for _, r := range refs {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b *SearchScopeRef) int {
		if a.Default != b.Default {
			if a.Default {
				return -1
			}
			return 1
		}
		return a.RefId.Cmp(b.RefId)
	})
	return out, nil
}
