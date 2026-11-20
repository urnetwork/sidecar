//go:build sidecar_testhooks && !ios_extension && !js

// A search device following one ref's index on a real evs engine, for the directory's search cases (FS-88's searches
// case, S13's search_agents step and FS-87's index case's roll-up leg; RECORD-M10-06): the cards ref's index as the
// directory's writers pushed it beside their cards, read by the search cache, sync engine, policy and engine a
// composition will run, the scope carrying the searchable_days a case gives it, as a composition's scope source will
// read it from the policy that governs the log. No composition gives
// the sync engine its adapter over EvsRepo yet (search_sync.go's searchSyncSource names it), so this hook stands in
// for that adapter alone, and in the plainest way one may answer: the head by listing, as a device past its catch-up
// budget takes it, each file read through EvsRepo's verifying reader (evs_index_store_evs.go) and sealed again for
// the cache under the repo's key as the device's gkm answers it. Replay by statements, read receipts and a slot key's
// reopening are that adapter's, and nothing here stands for them. Only the sidecar_testhooks build has it (§22.4).

package sidecar

import (
	"context"
	"errors"
	"time"
)

// What a search device over an evs ref is made of.
type SearchTestEvsDeviceArgs struct {
	// The repo as the device's evs client holds it, and its file-mode ref's name; nil is main.
	Repo    *EvsRepo
	RefName []byte
	// The host class's search settings and reports.
	Settings   *SidecarSearchSettings
	Conditions func() SearchConditions
	// Whether a signer could erase the repo's documents: its admins, the directory's too. Required.
	IsAdmin func(signer Id) bool
	// The most one read asks for, §11.9's read limit. Required.
	ReadByteCount int64
	// The engine's events; nil drops them.
	Events func(event SidecarEvent)
	// The repo's searchable_days as an age (SearchScopeRepo.SearchableAge), asked at each search as a composition's
	// scope source reads the policy that governs the log then, so a rise takes effect at the next search with nothing
	// fetched or built; nil masks none.
	SearchableAge func() time.Duration
}

// One device following an evs ref for search.
type SearchTestEvsDevice struct {
	repoId   Id
	refId    Id
	instance *SidecarInstance
	cache    *SearchCache
	sync     *SearchSync
	policy   *SearchPolicy
	engine   *SearchEngine
}

// A fresh device: its own state, cache, sync engine, policy and engine, following the ref on the clock of the repo's
// client and opening what it keeps with that client's gkm.
func NewSearchTestEvsDevice(ctx context.Context, args *SearchTestEvsDeviceArgs) (*SearchTestEvsDevice, error) {
	if args == nil || args.Repo == nil || args.Settings == nil || args.Conditions == nil || args.IsAdmin == nil || args.ReadByteCount <= 0 {
		return nil, errors.New("search test evs device: a repo, settings, conditions, an admin judge and a read limit")
	}
	repo := args.Repo
	client := repo.client
	store := newIndexEvsStore(repo, args.RefName, false)
	refId, err := store.refId(ctx)
	if err != nil {
		return nil, err
	}
	kind, err := repo.repoKind()
	if err != nil {
		return nil, err
	}
	settings := DefaultSidecarSettings()
	settings.Log = NewNoopLogger()
	settings.KeychainSettings.PassMemoryByteCount = 64 * 1024
	settings.KeychainSettings.PassIterationCount = 1
	settings.KeychainSettings.PassThreadCount = 1
	settings.KeychainSettings.AutoLockTimeout = 0
	instance, err := NewSidecarInstance(ctx, &SidecarInstanceArgs{Backend: NewSidecarMemoryBackend(), KeyStore: NewSidecarMemoryKeyStore(), Settings: settings})
	if err != nil {
		return nil, err
	}
	device := &SearchTestEvsDevice{repoId: repo.repoId, refId: refId, instance: instance}
	fail := func(err error) (*SearchTestEvsDevice, error) {
		device.Close()
		return nil, err
	}
	if err := instance.Unlock(nil); err != nil {
		return fail(err)
	}
	networkId := NewId()
	if _, err := instance.createKeychain(networkId); err != nil {
		return fail(err)
	}
	format := DefaultIndexFormatSettings()
	if device.cache, err = NewSearchCache(ctx, instance.Store(&networkId), args.Settings, client.clock, NewNoopLogger()); err != nil {
		return fail(err)
	}
	if device.policy, err = NewSearchPolicy(&SearchPolicyArgs{Settings: args.Settings, Conditions: args.Conditions, Clock: client.clock}); err != nil {
		return fail(err)
	}
	device.sync, err = newSearchSync(&searchSyncArgs{
		cache: device.cache, settings: args.Settings, format: format, clock: client.clock, log: NewNoopLogger(),
		readPathCount: DefaultEvsFormatSettings().ReadMaxPathCount, readByteCount: args.ReadByteCount, budget: device.policy,
		events: args.Events,
	})
	if err != nil {
		return fail(err)
	}
	err = device.sync.Follow(&searchSyncRefArgs{
		repoId: repo.repoId, refId: refId, repoKind: kind,
		source:   &searchTestEvsSource{repo: repo, refId: refId, store: store},
		mayErase: func(signer Id, signedTimeMs int64) bool { return args.IsAdmin(signer) },
	})
	if err != nil {
		return fail(err)
	}
	device.engine, err = NewSearchEngine(&SearchEngineArgs{
		Settings: args.Settings, Format: format, Cache: device.cache, Sync: device.sync, Policy: device.policy, Gkm: client.args.Gkm,
		Clock: client.clock, Log: NewNoopLogger(),
		Scope:  &searchTestScope{repoId: repo.repoId, refId: refId, kind: kind, searchableAge: args.SearchableAge},
		Events: args.Events,
	})
	if err != nil {
		return fail(err)
	}
	return device, nil
}

// Ends the device and its state.
func (self *SearchTestEvsDevice) Close() {
	if self.engine != nil {
		self.engine.Close()
	}
	if self.sync != nil {
		self.sync.Close()
	}
	if self.cache != nil {
		self.cache.Close()
	}
	if self.instance != nil {
		self.instance.Close()
	}
}

// The device's engine.
func (self *SearchTestEvsDevice) Engine() *SearchEngine {
	return self.engine
}

// The ref the device follows.
func (self *SearchTestEvsDevice) RefId() Id {
	return self.refId
}

// One round of the ref now.
func (self *SearchTestEvsDevice) Sync(ctx context.Context) error {
	return self.sync.RunRound(ctx, self.repoId, self.refId, false)
}

// The ref's index through EvsRepo, answered as a catch-up each round.
type searchTestEvsSource struct {
	repo  *EvsRepo
	refId Id
	store *indexEvsStore
}

// See searchSyncSource: the head, with a catch-up wherever it is past pin.
func (self *searchTestEvsSource) Replay(ctx context.Context, pin SearchSyncPin) (*searchSyncReplay, error) {
	head, err := self.store.Head(ctx)
	if err != nil {
		return nil, err
	}
	if head.version < pin.Version {
		return nil, errors.New("search test evs source: a pin past the head")
	}
	return &searchSyncReplay{head: head, catchUp: head.version != pin.Version}, nil
}

// See searchSyncSource.
func (self *searchTestEvsSource) List(ctx context.Context) (*indexListing, error) {
	return self.store.List(ctx, 0)
}

// See searchSyncSource: each file as evs's reader verifies it, sealed again under the repo's newest key.
func (self *searchTestEvsSource) Fetch(ctx context.Context, files []*indexFileVersion) ([]*searchSyncFetched, error) {
	repoKey, err := self.repo.client.args.Gkm.CurrentRepoKey(ctx, self.repo.repoId)
	if err != nil {
		return nil, err
	}
	fetched := []*searchSyncFetched{}
	for _, file := range files {
		plaintext, err := self.store.Read(ctx, file)
		if errors.Is(err, errIndexCollected) {
			fetched = append(fetched, &searchSyncFetched{file: file, collected: true})
			continue
		}
		if err != nil {
			return nil, err
		}
		record, err := searchTestSeal(repoKey, self.repo.repoId, self.refId, file, plaintext)
		if err != nil {
			return nil, err
		}
		fetched = append(fetched, &searchSyncFetched{file: file, record: record})
	}
	return fetched, nil
}

// The plaintext of every index file repo's file-mode ref refName (nil: main) holds at its head, by path, each read
// through EvsRepo's verifying reader: what a schedule scans for text that must not be there.
func ReadSearchTestEvsIndexFiles(ctx context.Context, repo *EvsRepo, refName []byte) (map[string][]byte, error) {
	store := newIndexEvsStore(repo, refName, false)
	listing, err := store.List(ctx, 0)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	for _, file := range listing.files {
		plaintext, err := store.Read(ctx, file)
		if err != nil {
			return nil, err
		}
		files[file.path] = plaintext
	}
	return files, nil
}
