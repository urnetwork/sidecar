//go:build !ios_extension

// A member's local search uses the same EVS client, verified config and sealed key store as its file reads.
package sidecar

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// One live per-network search binding. The daemon may bind it before its clients have opened.
type memberSearchHost struct {
	running   *Sidecar
	ctx       context.Context
	clients   func() (*EvsClient, error)
	buildLock sync.Mutex
	engine    *SearchEngine
	syncer    *SearchSync
}

// Binds the hosted network's existing clients. The cache and queries open on first use, after enrollment.
func (self *Sidecar) BindMemberSearch(ctx context.Context, clients func() (*EvsClient, error)) {
	if clients == nil {
		return
	}
	host := &memberSearchHost{running: self, ctx: ctx, clients: clients}
	search := self.searchOf()
	search.stateLock.Lock()
	search.member = host
	search.stateLock.Unlock()
	go host.run()
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

// Query-time record opening only reads an already-held generation. Other key operations refuse.
type memberSearchKeys struct {
	gkmRefusingClient
	running *Sidecar
}

func (self memberSearchKeys) RepoKey(ctx context.Context, repo Id, generation uint64) (*EvsRepoKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if key := self.running.GkmHeldKey(repo, generation); key != nil {
		return key, nil
	}
	return nil, ErrGkmKeyMissing
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
	evs, err := self.clients()
	if err != nil {
		return nil, err
	}
	if evs == nil {
		return nil, ErrSidecarSearchUnavailable
	}
	record, err := running.Record()
	if err != nil {
		return nil, err
	}
	source := &memberSearchSource{host: self, evs: evs, record: record}
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
	source.syncer, source.policy = syncer, policy
	engine, err := NewSearchEngine(&SearchEngineArgs{Settings: settings, Cache: cache, Sync: syncer, Policy: policy, Format: format, Scope: source, Gkm: memberSearchKeys{running: running},
		Scan: source.scan, Members: source.memberSidecars, Join: source, Events: running.searchEvents(), Clock: running.clock, Log: running.log})
	if err != nil {
		syncer.Close()
		return nil, err
	}
	syncer.Start(self.ctx)
	self.engine, self.syncer = engine, syncer
	return engine, nil
}

// The record retention and the file view belong to the same authorized member.
type memberSearchSource struct {
	host       *memberSearchHost
	evs        *EvsClient
	syncer     *SearchSync
	policy     *SearchPolicy
	followLock sync.Mutex
	followed   map[[2]Id]bool
	record     *SidecarRecord
}

// Refuses pending, closed, locked, replaced or freshly revoked identities.
func (self *memberSearchSource) state() *ConfigState {
	running := self.host.running
	search := running.searchOf()
	search.stateLock.Lock()
	current := search.member == self.host
	search.stateLock.Unlock()
	if !current || self.host.ctx.Err() != nil || !running.Admitted() {
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

// Resolves a historical writer to the member its verified admission names, including retired devices.
func (self *memberSearchSource) memberSidecars(member Id) []Id {
	state := self.state()
	if state == nil || member == (Id{}) {
		return nil
	}
	var ids []Id
	for _, id := range state.SidecarIds() {
		if row := state.SidecarRow(id); row != nil && bytes.Equal(row.GetMemberId(), member[:]) {
			ids = append(ids, id)
		}
	}
	return ids
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
	live := map[[2]Id]bool{}
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
		repo.acceptRow = func(row *indexRow) bool { return memberSearchIndexRow(repo, row) }
		if !repo.Readable && !repo.DepositOnly {
			continue
		}
		repos = append(repos, repo)
		repo.valid = func() bool {
			current := self.state()
			if current == nil || !bytes.Equal(current.Pin().Chain, state.Pin().Chain) {
				return false
			}
			live := acl.EvsAccess(subject, id, AclTokenAudienceEvs, self.host.running.clock.Now()).Rights
			if repo.Readable {
				return live.Has(AclEvsRead)
			}
			return live.Has(AclEvsDeposit)
		}
		if !repo.Readable || indexRepoExcluded(repo.Kind) {
			continue
		}
		repo.ReceiptRequired = aclRepoKindOwnerBound(repo.Kind) && !rights.Has(AclEvsWrite)
		repo.Refs, err = self.refs(repo, len(row.GetPrefixRules()) == 0, live)
		if err != nil {
			return nil, err
		}
		if repo.GroupInbox || repo.Kind == protocol.RepoKind_REPO_KIND_MAILBOX {
			mail := self.heldMail(id)
			if mail == nil {
				for _, ref := range repo.Refs {
					ref.Unbuilt = true
				}
			} else {
				authorized := repo.valid
				repo.valid = func() bool { return authorized() && mail() }
			}
		}
		if repo.Kind == protocol.RepoKind_REPO_KIND_DIRECTORY {
			age, policy := self.directoryAge(id)
			repo.SearchableAge = age
			for _, ref := range repo.Refs {
				if policy == nil {
					ref.Unbuilt = true
				}
			}
			if policy != nil {
				authorized := repo.valid
				repo.valid = func() bool { return authorized() && policy() }
			}
		}
	}
	// A revoked grant or withdrawn ref cannot remain a scheduled or control-visible sync target.
	self.followLock.Lock()
	if self.state() == state {
		for key := range self.followed {
			if !live[key] {
				self.syncer.Unfollow(key[0], key[1])
				delete(self.followed, key)
			}
		}
	}
	self.followLock.Unlock()
	return repos, nil
}

// Checks row shape against this verified repo's document class before ranking or opening its text.
func memberSearchIndexRow(repo *SearchScopeRepo, row *indexRow) bool {
	if row == nil || row.locator == "" || indexExcluded(indexPlace{repoKind: repo.Kind, groupInbox: repo.GroupInbox, path: row.locator}) {
		return false
	}
	if repo.GroupInbox || repo.Kind == protocol.RepoKind_REPO_KIND_MAILBOX {
		_, _, ok := searchJoinMailPath(row.locator)
		return ok && row.docKind == IndexDocMail
	}
	switch repo.Kind {
	case protocol.RepoKind_REPO_KIND_GENERAL:
		return row.docKind == IndexDocFile
	case protocol.RepoKind_REPO_KIND_DIRECTORY:
		// Cards and repo files produce announcement documents named a/<announcement> or a/<writer><announcement>.
		ids, ok := strings.CutPrefix(row.locator, directoryIndexAnnouncementPrefix)
		return row.docKind == IndexDocDerived && ok && (len(ids) == 2*len(Id{}) || len(ids) == 4*len(Id{})) &&
			strings.Trim(ids, "0123456789abcdef") == ""
	}
	return false
}

// QD-1138 uses the directory's signed coordination policy for every indexed card. Only a complete local read
// establishes which policy stands. A new reader revision expires every page opened at the preceding cut.
func (self *memberSearchSource) directoryAge(repo Id) (time.Duration, func() bool) {
	_, directory := recordTeamLogs(self.record.writer.auth())
	if directory == nil || *directory != repo {
		return 0, nil
	}
	reader := self.record.Reader()
	reader.stateLock.Lock()
	log := reader.logs[repo]
	if log == nil || !log.complete {
		reader.stateLock.Unlock()
		return 0, nil
	}
	revision := log.searchRevision
	reader.stateLock.Unlock()
	retention := self.record.Retention()
	age := memberSearchAge(retention.SearchableDays(repo, RecordClassCoordination), retention.settings.Day)
	valid := func() bool {
		reader.stateLock.Lock()
		defer reader.stateLock.Unlock()
		return log.complete && log.searchRevision == revision
	}
	if !valid() {
		return 0, nil
	}
	return age, valid
}

// Held generation one derives K_ref directly, without testing or authenticating any remote endpoint.
func (self *memberSearchSource) refKey(repo Id) (*EvsRefKey, error) {
	key := self.host.running.GkmHeldKey(repo, 1)
	if key == nil {
		return nil, nil
	}
	return NewEvsRefKey(key)
}

// The signed record reader knows each stream's name. The pins and sealed observations name ordinary file refs.
func (self *memberSearchSource) refs(repo *SearchScopeRepo, unrestricted bool, live map[[2]Id]bool) ([]*SearchScopeRef, error) {
	key, err := self.refKey(repo.RepoId)
	if err != nil || key == nil {
		return nil, err
	}
	refs := map[Id]*SearchScopeRef{}
	add := func(id Id, name string, def bool) {
		if id == (Id{}) || name == "" || (name == string(EvsIndexRefName) || name == string(EvsLfsRefName)) {
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
	fileIndex := repo.Kind == protocol.RepoKind_REPO_KIND_DIRECTORY || repo.Kind == protocol.RepoKind_REPO_KIND_GENERAL || repo.Kind == protocol.RepoKind_REPO_KIND_MAILBOX
	if fileIndex {
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
		if unrestricted && fileIndex && !repo.ReceiptRequired && (!memberSearchRecordKind(repo.Kind) || r.Name == string(EvsMainRefName)) {
			live[[2]Id{repo.RepoId, r.RefId}] = true
			if err := self.follow(repo, r); err != nil {
				return nil, err
			}
		}
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

// Follow starts no network work. Rounds run only on a sync trigger. A verified cache manifest chooses index or scan.
func (self *memberSearchSource) follow(repo *SearchScopeRepo, ref *SearchScopeRef) error {
	key := [2]Id{repo.RepoId, ref.RefId}
	self.followLock.Lock()
	if !self.followed[key] {
		source := &memberIndexSource{member: self, store: newIndexEvsStore(self.evs.Repo(repo.RepoId), []byte(ref.Name), ref.Companion), contentRef: ref.RefId, kind: repo.Kind}
		err := self.syncer.Follow(&searchSyncRefArgs{repoId: repo.RepoId, refId: ref.RefId, repoKind: repo.Kind, companion: ref.Companion, source: source,
			keepLatest: func() bool { return self.policy.KeepsLatest(repo.Kind) }, keepAll: func() bool { return self.policy.KeepsAll(repo.RepoId, 0) },
			mayErase: func(signer Id, when int64) bool {
				state := self.state()
				if state == nil {
					return false
				}
				acl, err := state.Acl()
				return err == nil && indexAclAdmins(acl, repo.RepoId)(&indexFileVersion{signerSidecarId: signer, signedTimeMs: when})
			}})
		if err != nil {
			self.followLock.Unlock()
			return err
		}
		if self.followed == nil {
			self.followed = make(map[[2]Id]bool)
		}
		self.followed[key] = true
	}
	self.followLock.Unlock()
	snapshot, err := self.syncer.Snapshot(repo.RepoId, ref.RefId)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil
	}
	if err != nil {
		return err
	}
	if snapshot == nil {
		return nil
	}
	defer snapshot.Release()
	held := snapshot.Pin()
	current := func() bool {
		pin, found, err := self.evs.pins.Pin(repo.RepoId, ref.RefId)
		return err == nil && found && pin.Version == held.Version && pin.Chain == held.Chain
	}
	if !current() {
		return nil
	}
	ref.valid = current
	for _, f := range snapshot.manifest.Files {
		if f.State != SearchManifestHeld {
			continue
		}
		parsed, ok := indexParsePath(f.Path, ref.Companion)
		if !ok {
			continue
		}
		switch parsed.kind {
		case indexPathSettings:
			settings, err := indexDecodeSettings(f.Small)
			if err == nil {
				ref.IndexOff = settings.Off
			}
		case indexPathSlot, indexPathLargeEntry, indexPathBucketShard, indexPathAllShard:
			ref.Unbuilt = false
		}
	}
	return nil
}

// Enrollment and scheduled refreshes discover newly pinned refs independently of queries.
func (self *memberSearchHost) run() {
	wake := make(chan struct{}, 1)
	stop := self.running.AddEventCallback(func(event SidecarEvent) {
		if event.Kind == SidecarEventState {
			select {
			case wake <- struct{}{}:
			default:
			}
		}
	})
	defer stop()
	timer := self.running.clock.After(self.running.settings.Search.ResyncInterval)
	_, foregroundChange := self.running.SearchForeground()
	for {
		reason := SearchSyncResync
		select {
		case <-self.ctx.Done():
			return
		case <-wake:
		case <-foregroundChange:
			foreground, changed := self.running.SearchForeground()
			foregroundChange = changed
			if !foreground {
				continue
			}
			reason = SearchSyncForeground
		case <-timer:
			timer = self.running.clock.After(self.running.settings.Search.ResyncInterval)
		}
		if engine, err := self.open(); err == nil {
			if err := engine.refreshScope(self.ctx, nil); err == nil {
				engine.args.Sync.triggerAll(reason)
			}
		}
	}
}
