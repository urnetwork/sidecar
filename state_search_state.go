//go:build !ios_extension

// §5.9's search state (CORE-M10-03; R-CORE-18, R-CORE-19, D-CORE-16, D-CORE-17, I-13, I-19; DESIGN-DETAILS 7.2.3): the
// part of search that is not derived, so `ur search sync --evict`, DropSearchCache and the cache's eviction all keep it.
// One sealed file a network, search.state in the network's directory under file class search, beside the cache's
// search/ directory and not in it, so nothing that clears the cache reaches it; it goes with the network's local state
// (Logout's wipe). It holds:
//
//	mode      this network's remote mode (§18.4): on, own or off; none set reads Search.RemoteMode
//	answers   the notice's answers by member (§18.4): allowed or refused
//	policies  this device's policy overrides (§18.4's modes), by repo and one for every repo
//	served    the asker's memory of which repos each indexer served, kept Search.RemoteServedTimeout
//	distrust  an indexer's distrust deadline (DESIGN-DETAILS 7.2.6)
//	records   on an owner's indexer, the served record (owner decision 294, QD-961): one row per (requester, repo,
//	          UTC day) of the remote searches an EvsShare reader made in an owner-bound repo that day, with their
//	          count and the first and last of their times; a row is kept until its day ended
//	          Search.ServedRecordTimeout ago, and Search.ServedRecordCount bounds the number of these rows, one per
//	          (requester, repo, day), beneath that, the oldest days going first and a day's by requester then repo
//
// None of it names a query, hit, snippet, cursor, result count or verdict (§5.9's never row): no call here takes one,
// and the encoding has no field that could hold one; a row's count is of searches, never of results. The mismatch
// counts and the refused and skip memories are in RAM only (DESIGN-DETAILS 7.2.3), the asker's.
//
// Each change is written through, whole and atomically, before its call returns, and what has expired is pruned as it
// is. A read loads the file once and keeps it in memory while the instance is open; a lock drops that copy, and while
// locked every call answers the store's ErrSidecarStoreLocked and changes nothing. A file that fails AEAD or decoding is
// not derived data, so unlike the cache's files it is never dropped or written over: every call answers
// ErrSidecarStoreFailed, which callers read as fail-closed (no remote search, no other member's indexer asked), and the
// first such read alarms through onFailed (a reading of D-CORE-15 for non-derived state).
//
// On every leg but the forwarding one, which runs no search: root Id, no connect type. Safe for concurrent use.

package sidecar

import (
	"cmp"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"
)

const (
	// The search state's file, in the network's directory under file class search.
	sidecarSearchStateName = "search.state"
	// Its encoding's version.
	searchStateVersion = 1
)

// §18.4's remote modes.
const (
	SearchRemoteOn  = "on"
	SearchRemoteOwn = "own"
	SearchRemoteOff = "off"
)

// §18.4's policies for all, which a per-device override may name.
const (
	SearchPolicyBackground   = "background"
	SearchPolicyWifiCharging = "wifi_charging"
	SearchPolicyOnDemand     = "on_demand"
	SearchPolicyNever        = "never"
)

var (
	// What a search state call asks is not well formed: a mode, a policy or an id.
	ErrSearchStateArgs = errors.New("search state: invalid arguments")
)

// Whether mode is one of §18.4's remote modes.
func isSearchRemoteMode(mode string) bool {
	return mode == SearchRemoteOn || mode == SearchRemoteOwn || mode == SearchRemoteOff
}

// Whether policy is one of §18.4's policies for all.
func isSearchPolicy(policy string) bool {
	switch policy {
	case SearchPolicyBackground, SearchPolicyWifiCharging, SearchPolicyOnDemand, SearchPolicyNever:
		return true
	}
	return false
}

// The served record (§5.9's state row, D-CORE-17; owner decision 294, QD-961): the remote searches one EvsShare reader
// made in one owner-bound repo on one UTC day, as the owner's indexer keeps them, one row a requester, repo and day. It
// names no query.
type SidecarServedRecord struct {
	RequesterId Id
	RepoId      Id
	// the UTC day, as its first instant
	Day time.Time
	// the searches made that day, each counted once, at its page 0
	Count int64
	// the first and the last of them
	First time.Time
	Last  time.Time
}

// One network's search state. Construct with newSidecarSearchState.
type SidecarSearchState struct {
	// the network's directory under file class search
	store    SidecarStore
	instance *SidecarInstance
	settings *SidecarSearchSettings
	clock    Clock
	log      Logger
	// called once each time the file is found failed, outside every lock
	onFailed func()
	// raised at each change, for the asker and the policy to follow (Changes)
	changes *MonitorValue[uint64]

	// one change at a time, held across its read and write, so never stateLock
	writeLock sync.Mutex

	stateLock sync.Mutex
	// the file as last read or written, nil until loaded and after a lock
	wire *searchStateWire
	// the file was found failed and the alarm went: it is read again at each call, so a medium that recovers is
	// read again, and alarms once more only after it has read well
	failed bool
}

// The file's encoding. Every list is sorted, so one state is one set of bytes.
type searchStateWire struct {
	Version  int                       `json:"version"`
	Mode     string                    `json:"mode,omitempty"`
	Answers  []searchStateAnswerWire   `json:"answers,omitempty"`
	Policies []searchStatePolicyWire   `json:"policies,omitempty"`
	Served   []searchStateServedWire   `json:"served,omitempty"`
	Distrust []searchStateDistrustWire `json:"distrust,omitempty"`
	Records  []searchStateRecordWire   `json:"records,omitempty"`
}

// A notice's answer for one member.
type searchStateAnswerWire struct {
	Member string `json:"member"`
	Allow  bool   `json:"allow"`
}

// A policy override: Repo empty for every repo.
type searchStatePolicyWire struct {
	Repo string `json:"repo,omitempty"`
	Mode string `json:"mode"`
}

// When an indexer last served a repo.
type searchStateServedWire struct {
	Indexer string `json:"indexer"`
	Repo    string `json:"repo"`
	AtMs    int64  `json:"at_ms"`
}

// An indexer's distrust deadline.
type searchStateDistrustWire struct {
	Indexer string `json:"indexer"`
	UntilMs int64  `json:"until_ms"`
}

// One served row: the searches a requester made in a repo on one UTC day. A record of the old one-search form carries
// at_ms alone; it reads as a row of count 1 on its time's day (foldRecords) and is never written.
type searchStateRecordWire struct {
	Requester string `json:"requester"`
	Repo      string `json:"repo"`
	// the UTC day, counted from 1970-01-01
	Day     int64 `json:"day"`
	Count   int64 `json:"count"`
	FirstMs int64 `json:"first_ms"`
	LastMs  int64 `json:"last_ms"`
	// the old form's one search
	AtMs int64 `json:"at_ms,omitempty"`
}

// Whether a record is a row of at least one search whose times fall on its day, in order, or one of the old form.
func (self searchStateRecordWire) wellFormed() bool {
	if self.Count == 0 {
		return self.Day == 0 && self.FirstMs == 0 && self.LastMs == 0
	}
	return 0 < self.Count && self.AtMs == 0 && self.FirstMs <= self.LastMs &&
		servedRowDayOf(self.FirstMs) == self.Day && servedRowDayOf(self.LastMs) == self.Day
}

// The served rows' order: the oldest day first, a day's by requester then repo. It is the order the bound drops them
// in and ServedRecords answers them in.
func compareServedRows(a searchStateRecordWire, b searchStateRecordWire) int {
	return cmp.Or(cmp.Compare(a.Day, b.Day), cmp.Compare(a.Requester, b.Requester), cmp.Compare(a.Repo, b.Repo))
}

// A served row's day: the UTC day timeMs falls on, counted from 1970-01-01. The day is the calendar's, the 86,400 s
// Unix time counts, so no setting moves it.
func servedRowDayOf(timeMs int64) int64 {
	dayMs := (24 * time.Hour).Milliseconds()
	// floored, so a time before 1970 falls on its own day as well
	day := timeMs / dayMs
	if timeMs%dayMs < 0 {
		day -= 1
	}
	return day
}

// The first instant of a served row's day, in ms; the next day's is when it ends.
func servedRowDayStartMs(day int64) int64 {
	return day * (24 * time.Hour).Milliseconds()
}

// The search state of the network store is of: store must be a SidecarInstance's for one network, so a lock is seen.
// onFailed, nil for none, is called once each time the file is found failed.
func newSidecarSearchState(store SidecarStore, settings *SidecarSearchSettings, clock Clock, log Logger, onFailed func()) (*SidecarSearchState, error) {
	if store == nil || settings == nil {
		return nil, fmt.Errorf("%w: a search state needs its store and settings", ErrSearchStateArgs)
	}
	instance, networkId, ok := sidecarInstanceOfStore(store)
	if !ok || networkId == nil {
		return nil, fmt.Errorf("%w: a search state is one network's", ErrSearchStateArgs)
	}
	classStore, err := store.Directory("", SidecarSearchFileClass)
	if err != nil {
		return nil, err
	}
	return &SidecarSearchState{
		store:    classStore,
		instance: instance,
		settings: settings,
		clock:    clockOrReal(clock),
		log:      loggerOrDefault(log),
		onFailed: onFailed,
		changes:  NewMonitorValue[uint64](0),
	}, nil
}

// A count raised at each change, and a channel closed at the next: what the asker and the policy follow, subscribing
// before they read.
func (self *SidecarSearchState) Changes() (uint64, chan struct{}) {
	return self.changes.Get()
}

// The state as the file holds it, loaded on first use: an empty one where there is no file. A lock drops the copy and
// answers the store's error; a failed file answers ErrSidecarStoreFailed, alarming the first time.
func (self *SidecarSearchState) current() (*searchStateWire, error) {
	if err := self.instance.stateError(); err != nil {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.wire = nil
		}()
		return nil, err
	}
	wire := func() *searchStateWire {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.wire
	}()
	if wire != nil {
		return wire, nil
	}
	wire, err := self.read()
	if errors.Is(err, ErrSidecarStoreFailed) {
		alarm := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			first := !self.failed
			self.failed = true
			return first
		}()
		if alarm {
			self.log.Warningf("[search]the network's search state failed: no change is written over it")
			if self.onFailed != nil {
				self.onFailed()
			}
		}
		return nil, ErrSidecarStoreFailed
	}
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.wire = wire
	self.failed = false
	return wire, nil
}

// Reads the file: an empty state where there is none, ErrSidecarStoreFailed for one that does not decode.
func (self *SidecarSearchState) read() (*searchStateWire, error) {
	reader, err := self.store.Open(sidecarSearchStateName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return &searchStateWire{Version: searchStateVersion}, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	content, err := io.ReadAll(io.LimitReader(reader, self.settings.StateByteCount+1))
	if err != nil {
		return nil, err
	}
	if self.settings.StateByteCount < int64(len(content)) {
		return nil, fmt.Errorf("%w: the search state is past its bound", ErrSidecarStoreFailed)
	}
	wire := &searchStateWire{}
	if json.Unmarshal(content, wire) != nil || wire.Version != searchStateVersion || !wire.wellFormed() {
		return nil, fmt.Errorf("%w: the search state does not decode", ErrSidecarStoreFailed)
	}
	wire.foldRecords()
	return wire, nil
}

// Whether every id is one and every mode a mode: what read refuses otherwise.
func (self *searchStateWire) wellFormed() bool {
	isId := func(text string) bool {
		_, err := searchCacheIdOfHex(text)
		return err == nil
	}
	if self.Mode != "" && !isSearchRemoteMode(self.Mode) {
		return false
	}
	for _, answer := range self.Answers {
		if !isId(answer.Member) {
			return false
		}
	}
	for _, policy := range self.Policies {
		if (policy.Repo != "" && !isId(policy.Repo)) || !isSearchPolicy(policy.Mode) {
			return false
		}
	}
	for _, served := range self.Served {
		if !isId(served.Indexer) || !isId(served.Repo) {
			return false
		}
	}
	for _, distrust := range self.Distrust {
		if !isId(distrust.Indexer) {
			return false
		}
	}
	for _, record := range self.Records {
		if !isId(record.Requester) || !isId(record.Repo) || !record.wellFormed() {
			return false
		}
	}
	return true
}

// Reads each record as a row, one of the old form as a row of count 1 on its time's day, and folds the rows of one
// requester, repo and day into one, their counts summed and their times spanned, in the rows' order. A file written in
// the old one-search form so reads as rows, and the next write leaves only rows.
func (self *searchStateWire) foldRecords() {
	type servedRowKey struct {
		requester string
		repo      string
		day       int64
	}
	keyIndexes := map[servedRowKey]int{}
	rows := []searchStateRecordWire{}
	for _, record := range self.Records {
		if record.Count == 0 {
			record = searchStateRecordWire{
				Requester: record.Requester,
				Repo:      record.Repo,
				Day:       servedRowDayOf(record.AtMs),
				Count:     1,
				FirstMs:   record.AtMs,
				LastMs:    record.AtMs,
			}
		}
		key := servedRowKey{requester: record.Requester, repo: record.Repo, day: record.Day}
		if index, ok := keyIndexes[key]; ok {
			rows[index].Count += record.Count
			rows[index].FirstMs = min(rows[index].FirstMs, record.FirstMs)
			rows[index].LastMs = max(rows[index].LastMs, record.LastMs)
			continue
		}
		keyIndexes[key] = len(rows)
		rows = append(rows, record)
	}
	slices.SortFunc(rows, compareServedRows)
	self.Records = rows
}

// A deep copy, for a change to edit while readers hold the old one.
func (self *searchStateWire) clone() *searchStateWire {
	return &searchStateWire{
		Version:  self.Version,
		Mode:     self.Mode,
		Answers:  slices.Clone(self.Answers),
		Policies: slices.Clone(self.Policies),
		Served:   slices.Clone(self.Served),
		Distrust: slices.Clone(self.Distrust),
		Records:  slices.Clone(self.Records),
	}
}

// Drops what has expired at now and the served rows past their bound, the oldest days first, and sorts every list. A
// row goes once its day ended more than Search.ServedRecordTimeout ago.
func (self *SidecarSearchState) prune(wire *searchStateWire, now time.Time) {
	servedSince := now.Add(-self.settings.RemoteServedTimeout).UnixMilli()
	wire.Served = slices.DeleteFunc(wire.Served, func(served searchStateServedWire) bool { return served.AtMs < servedSince })
	wire.Distrust = slices.DeleteFunc(wire.Distrust, func(distrust searchStateDistrustWire) bool { return distrust.UntilMs <= now.UnixMilli() })
	recordsSince := now.Add(-self.settings.ServedRecordTimeout).UnixMilli()
	wire.Records = slices.DeleteFunc(wire.Records, func(record searchStateRecordWire) bool {
		return servedRowDayStartMs(record.Day+1) < recordsSince
	})
	slices.SortFunc(wire.Records, compareServedRows)
	// a bound of zero or less keeps no row
	if excess := len(wire.Records) - max(self.settings.ServedRecordCount, 0); 0 < excess {
		wire.Records = slices.Delete(wire.Records, 0, excess)
	}
	slices.SortFunc(wire.Answers, func(a searchStateAnswerWire, b searchStateAnswerWire) int { return cmp.Compare(a.Member, b.Member) })
	slices.SortFunc(wire.Policies, func(a searchStatePolicyWire, b searchStatePolicyWire) int { return cmp.Compare(a.Repo, b.Repo) })
	slices.SortFunc(wire.Served, func(a searchStateServedWire, b searchStateServedWire) int {
		return cmp.Or(cmp.Compare(a.Indexer, b.Indexer), cmp.Compare(a.Repo, b.Repo))
	})
	slices.SortFunc(wire.Distrust, func(a searchStateDistrustWire, b searchStateDistrustWire) int {
		return cmp.Compare(a.Indexer, b.Indexer)
	})
}

// One change: edit a copy of the state, prune it and write it whole, then keep it and raise Changes. Nothing is written
// while locked, over a failed file, or where kept, nil for none, refuses the pruned copy.
func (self *SidecarSearchState) change(edit func(wire *searchStateWire), kept func(wire *searchStateWire) error) error {
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	current, err := self.current()
	if err != nil {
		return err
	}
	next := current.clone()
	edit(next)
	self.prune(next, self.clock.Now())
	if kept != nil {
		if err := kept(next); err != nil {
			return err
		}
	}
	encoded, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if int64(len(encoded)) > self.settings.StateByteCount {
		return fmt.Errorf("%w: the search state would pass its bound", ErrSearchStateArgs)
	}
	writer, err := self.store.Create(sidecarSearchStateName)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(encoded); err != nil {
		return err
	}
	if err := writer.Commit(); err != nil {
		return err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.wire = next
	}()
	self.changes.Update(func(count uint64) uint64 { return count + 1 })
	return nil
}

// This network's remote mode: the person's choice, else Search.RemoteMode.
func (self *SidecarSearchState) Mode() (string, error) {
	wire, err := self.current()
	if err != nil {
		return "", err
	}
	if wire.Mode == "" {
		return self.settings.RemoteMode, nil
	}
	return wire.Mode, nil
}

// Sets this network's remote mode: on, own or off.
func (self *SidecarSearchState) SetMode(mode string) error {
	if !isSearchRemoteMode(mode) {
		return fmt.Errorf("%w: a remote mode is on, own or off", ErrSearchStateArgs)
	}
	return self.change(func(wire *searchStateWire) {
		wire.Mode = mode
	}, nil)
}

// The notice's answer for memberId: whether it was answered, and whether it allowed.
func (self *SidecarSearchState) Answer(memberId Id) (allow bool, answered bool, err error) {
	wire, err := self.current()
	if err != nil {
		return false, false, err
	}
	member := hex.EncodeToString(memberId[:])
	for _, answer := range wire.Answers {
		if answer.Member == member {
			return answer.Allow, true, nil
		}
	}
	return false, false, nil
}

// Records the notice's answer for memberId (§18.4): an allow lets that member's indexer be asked; a refusal also sets
// the mode to own, in the same write, as "Only my devices" does. A nil memberId clears every answer, the mode staying.
func (self *SidecarSearchState) SetAnswer(memberId *Id, allow bool) error {
	return self.change(func(wire *searchStateWire) {
		if memberId == nil {
			wire.Answers = nil
			return
		}
		member := hex.EncodeToString(memberId[:])
		wire.Answers = slices.DeleteFunc(wire.Answers, func(answer searchStateAnswerWire) bool { return answer.Member == member })
		wire.Answers = append(wire.Answers, searchStateAnswerWire{Member: member, Allow: allow})
		if !allow {
			wire.Mode = SearchRemoteOwn
		}
	}, nil)
}

// This device's policy override for repoId: its own, else the one for every repo, else "", the host's default.
func (self *SidecarSearchState) Policy(repoId Id) (string, error) {
	wire, err := self.current()
	if err != nil {
		return "", err
	}
	repo := hex.EncodeToString(repoId[:])
	every := ""
	for _, policy := range wire.Policies {
		switch policy.Repo {
		case repo:
			return policy.Mode, nil
		case "":
			every = policy.Mode
		}
	}
	return every, nil
}

// Sets this device's policy override (§18.4): for repoId, or with a nil repoId for every repo, which clears each repo's
// own; a policy of "" restores the host's default there, for every repo clearing them all.
func (self *SidecarSearchState) SetPolicy(repoId *Id, policy string) error {
	if policy != "" && !isSearchPolicy(policy) {
		return fmt.Errorf("%w: a policy is one of §18.4's", ErrSearchStateArgs)
	}
	return self.change(func(wire *searchStateWire) {
		if repoId == nil {
			wire.Policies = nil
			if policy != "" {
				wire.Policies = []searchStatePolicyWire{{Mode: policy}}
			}
			return
		}
		repo := hex.EncodeToString(repoId[:])
		wire.Policies = slices.DeleteFunc(wire.Policies, func(kept searchStatePolicyWire) bool { return kept.Repo == repo })
		if policy != "" {
			wire.Policies = append(wire.Policies, searchStatePolicyWire{Repo: repo, Mode: policy})
		}
	}, nil)
}

// Notes that indexerId served repoId now: the asker's served memory, kept Search.RemoteServedTimeout.
func (self *SidecarSearchState) NoteServed(indexerId Id, repoId Id) error {
	now := self.clock.Now()
	return self.change(func(wire *searchStateWire) {
		indexer, repo := hex.EncodeToString(indexerId[:]), hex.EncodeToString(repoId[:])
		wire.Served = slices.DeleteFunc(wire.Served, func(served searchStateServedWire) bool {
			return served.Indexer == indexer && served.Repo == repo
		})
		wire.Served = append(wire.Served, searchStateServedWire{Indexer: indexer, Repo: repo, AtMs: now.UnixMilli()})
	}, nil)
}

// The repos indexerId served within Search.RemoteServedTimeout, each with when it last did, by repo id.
func (self *SidecarSearchState) Served(indexerId Id) (map[Id]time.Time, error) {
	wire, err := self.current()
	if err != nil {
		return nil, err
	}
	since := self.clock.Now().Add(-self.settings.RemoteServedTimeout).UnixMilli()
	indexer := hex.EncodeToString(indexerId[:])
	repoIdTimes := map[Id]time.Time{}
	for _, served := range wire.Served {
		if served.Indexer != indexer || served.AtMs < since {
			continue
		}
		if repoId, err := searchCacheIdOfHex(served.Repo); err == nil {
			repoIdTimes[repoId] = time.UnixMilli(served.AtMs)
		}
	}
	return repoIdTimes, nil
}

// indexerId's distrust deadline, zero for none in force.
func (self *SidecarSearchState) DistrustUntil(indexerId Id) (time.Time, error) {
	wire, err := self.current()
	if err != nil {
		return time.Time{}, err
	}
	indexer := hex.EncodeToString(indexerId[:])
	now := self.clock.Now().UnixMilli()
	for _, distrust := range wire.Distrust {
		if distrust.Indexer == indexer && now < distrust.UntilMs {
			return time.UnixMilli(distrust.UntilMs), nil
		}
	}
	return time.Time{}, nil
}

// Sets indexerId's distrust deadline (DESIGN-DETAILS 7.2.6); one at or before now clears it.
func (self *SidecarSearchState) SetDistrustUntil(indexerId Id, until time.Time) error {
	return self.change(func(wire *searchStateWire) {
		indexer := hex.EncodeToString(indexerId[:])
		wire.Distrust = slices.DeleteFunc(wire.Distrust, func(distrust searchStateDistrustWire) bool { return distrust.Indexer == indexer })
		wire.Distrust = append(wire.Distrust, searchStateDistrustWire{Indexer: indexer, UntilMs: until.UnixMilli()})
	}, nil)
}

// Writes the served record of one remote search requesterId made in owner-bound repoId by an EvsShare, now: what an
// owner's indexer keeps at page 0, once a search (DESIGN-DETAILS 7.2.5). The row of requesterId, repoId and now's UTC
// day takes it, its count raised and its times spanned to now, or a row of count 1 is added (owner decision 294,
// QD-961). It takes no query, and returns once the row is on the medium; an error means nothing was written, which the
// server answers fail-closed, as it is for a row Search.ServedRecordCount would drop at once.
func (self *SidecarSearchState) RecordServed(requesterId Id, repoId Id) error {
	if requesterId == (Id{}) || repoId == (Id{}) {
		return fmt.Errorf("%w: a served record names its requester and repo", ErrSearchStateArgs)
	}
	nowMs := self.clock.Now().UnixMilli()
	requester, repo, day := hex.EncodeToString(requesterId[:]), hex.EncodeToString(repoId[:]), servedRowDayOf(nowMs)
	isRow := func(record searchStateRecordWire) bool {
		return record.Requester == requester && record.Repo == repo && record.Day == day
	}
	return self.change(func(wire *searchStateWire) {
		if index := slices.IndexFunc(wire.Records, isRow); 0 <= index {
			row := &wire.Records[index]
			row.Count += 1
			row.FirstMs = min(row.FirstMs, nowMs)
			row.LastMs = max(row.LastMs, nowMs)
			return
		}
		wire.Records = append(wire.Records, searchStateRecordWire{
			Requester: requester,
			Repo:      repo,
			Day:       day,
			Count:     1,
			FirstMs:   nowMs,
			LastMs:    nowMs,
		})
	}, func(wire *searchStateWire) error {
		if !slices.ContainsFunc(wire.Records, isRow) {
			return fmt.Errorf("%w: the served rows' bound keeps no row for this search", ErrSearchStateArgs)
		}
		return nil
	})
}

// The served rows kept, the oldest day first and a day's by requester then repo: those whose day ended within
// Search.ServedRecordTimeout.
func (self *SidecarSearchState) ServedRecords() ([]SidecarServedRecord, error) {
	wire, err := self.current()
	if err != nil {
		return nil, err
	}
	since := self.clock.Now().Add(-self.settings.ServedRecordTimeout).UnixMilli()
	records := []SidecarServedRecord{}
	for _, record := range wire.Records {
		if servedRowDayStartMs(record.Day+1) < since {
			continue
		}
		requesterId, requesterErr := searchCacheIdOfHex(record.Requester)
		repoId, repoErr := searchCacheIdOfHex(record.Repo)
		if requesterErr != nil || repoErr != nil {
			continue
		}
		records = append(records, SidecarServedRecord{
			RequesterId: requesterId,
			RepoId:      repoId,
			Day:         time.UnixMilli(servedRowDayStartMs(record.Day)).UTC(),
			Count:       record.Count,
			First:       time.UnixMilli(record.FirstMs).UTC(),
			Last:        time.UnixMilli(record.LastMs).UTC(),
		})
	}
	return records, nil
}
