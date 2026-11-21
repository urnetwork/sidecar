//go:build !ios_extension

// A repo-scoped fallback pages only effective files and signed entries already verified on this device.
package sidecar

import (
	"bytes"
	"context"
	"errors"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// Saturates large signed lifetimes without wrapping an age to zero.
func memberSearchAge(days uint32, day time.Duration) time.Duration {
	if day <= 0 || days == 0 {
		return 0
	}
	if int64(days) > int64(math.MaxInt64)/int64(day) {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(days) * day
}

// The kinds whose documents may come from the local signed record reader.
func memberSearchRecordKind(kind protocol.RepoKind) bool {
	return EvsRepoKindRecordClass(kind)
}

// Opens the verified scope again after resolution. Receipt-gated data needs evidence covering this search itself.
func (self *memberSearchSource) scan(ctx context.Context, repo, ref Id) (*SearchScanView, error) {
	state := self.state()
	if state == nil {
		return nil, ErrSidecarSearchUnavailable
	}
	acl, err := state.Acl()
	if err != nil {
		return nil, err
	}
	row := acl.Repo(repo)
	rights := acl.EvsAccess(AclSidecarSubject(self.record.writer.sidecarId), repo, AclTokenAudienceEvs, self.host.running.clock.Now()).Rights
	if row == nil || !rights.Has(AclEvsRead) || indexRepoExcluded(row.Kind) {
		return nil, nil
	}
	if aclRepoKindOwnerBound(row.Kind) && !rights.Has(AclEvsWrite) {
		return nil, errSearchSyncReceipt
	}
	key, err := self.refKey(repo)
	if err != nil || key == nil {
		return nil, err
	}
	if memberSearchRecordKind(row.Kind) {
		return self.recordScan(repo, ref, row.Kind, key), nil
	}
	if row.Kind != protocol.RepoKind_REPO_KIND_GENERAL || AclRepoIsInbox(row) {
		return nil, nil
	}
	pins := self.evs.pins
	pin, found, err := pins.Pin(repo, ref)
	if err != nil || !found {
		return nil, err
	}
	var rows []*SearchScanDocument
	ruleSet := len(row.GetPrefixRules()) > 0
	func() {
		pins.stateLock.Lock()
		defer pins.stateLock.Unlock()
		held := pins.repoIdRepos[repo]
		if held == nil {
			return
		}
		for _, row := range held.reads {
			if indexExcluded(indexPlace{repoKind: protocol.RepoKind_REPO_KIND_GENERAL, path: row.Path}) {
				continue
			}
			observed := row.search
			if row.RefId != ref || observed == nil || observed.Head != pin.Version || observed.Chain != pin.Chain || (ruleSet && !bytes.Equal(observed.AuthChain, state.Pin().GetChain())) {
				continue
			}
			if observed.Signer == (Id{}) || observed.Version == 0 || observed.TimeMs <= 0 {
				continue
			}
			rows = append(rows, &SearchScanDocument{RefId: ref, Kind: IndexDocFile, Name: []byte(row.Path), Version: observed.Version, TimeMs: observed.TimeMs, Signer: observed.Signer,
				Tainted: observed.Tainted, Outside: observed.Outside, Display: &SearchScanDisplay{}})
		}
	}()
	if len(rows) == 0 {
		return nil, nil
	}
	slices.SortFunc(rows, func(a, b *SearchScanDocument) int { return bytes.Compare(a.Name, b.Name) })
	valid := func() bool {
		current, found, err := pins.Pin(repo, ref)
		return err == nil && found && current.Version == pin.Version && current.Chain == pin.Chain
	}
	return &SearchScanView{Source: memberFileSearchScan(rows), RefKey: key, valid: valid}, nil
}

// A verified reader supplies the per-class searchable lifetime and the current liveness of each stream's
// documents. A card requires every contributing copy to stand under its own class's policy.
func (self *memberSearchSource) recordIndexRows(repo *SearchScopeRepo) (func(*indexRow) bool, func() bool) {
	reader := self.record.Reader()
	reader.stateLock.Lock()
	log := reader.logs[repo.RepoId]
	if log == nil || !log.complete {
		reader.stateLock.Unlock()
		return nil, nil
	}
	revision := log.searchRevision
	reader.stateLock.Unlock()
	valid := func() bool {
		reader.stateLock.Lock()
		defer reader.stateLock.Unlock()
		return log.complete && log.searchRevision == revision
	}
	type name struct {
		ref  Id
		path string
	}
	// A listing, status request or query without a candidate never walks the log or opens a body.
	membership := sync.OnceValue(func() map[name]RecordKind {
		now := self.host.running.clock.Now()
		retention := self.record.Retention()
		policy := retention.governing(repo.RepoId)
		cardSources := indexRunCardSources(repo.Kind)
		members := map[name]RecordKind{}
		reader.stateLock.Lock()
		defer reader.stateLock.Unlock()
		if !log.complete || log.searchRevision != revision {
			return members
		}
		for _, entry := range log.ordered {
			if entry == nil || entry.Header == nil {
				continue
			}
			kind := entry.Kind()
			run, err := IdFromBytes(entry.Header.Header.GetRunId())
			card := err == nil && run != (Id{}) && slices.Contains(cardSources, kind)
			counts := indexRecordIndexesEntry(repo.Kind, kind)
			if !card && !counts {
				continue
			}
			for _, copy := range entry.Copies {
				ref := log.streamRefIds[copy.StreamSidecarId]
				live := entry.State == RecordEntryLive && !entry.BodyInvalid && !entry.BodyGeneric &&
					memberSearchCopyVisible(now, retention.settings.Day, policy[kind.Class()], copy)
				if counts && live {
					members[name{ref: ref, path: copy.Path}] = kind
				}
				if card {
					key := name{ref: ref, path: string(indexRunCardName(run))}
					previous, seen := members[key]
					if !live || seen && previous == 0 {
						members[key] = 0
					} else {
						members[key] = RecordKindRun
					}
				}
			}
		}
		return members
	})
	return func(row *indexRow) bool {
		ref, err := IdFromBytes(row.refId)
		if err != nil {
			return false
		}
		kind, ok := membership()[name{ref: ref, path: row.locator}]
		return ok && kind != 0 && kind.String() == row.fields[indexFieldFirstRegistered]
	}, valid
}

// A verified copy's push time is the signed time to which its class's policy applies.
func memberSearchCopyVisible(now time.Time, day time.Duration, policy *RecordRetentionPolicy, copy *RecordEntryCopy) bool {
	return copy != nil && copy.TimeMillis > 0 &&
		(policy == nil || uint64(copy.TimeMillis/1000) >= searchSearchableSinceSeconds(now.UnixMilli(), memberSearchAge(policy.SearchableDays, day)))
}

// A bounded snapshot of names; pin changes invalidate every page that retained it.
type memberFileSearchScan []*SearchScanDocument

// Visits held names in their stable order until the requested page fills.
func (self memberFileSearchScan) SearchScan(ctx context.Context, after uint64, visit func(uint64, *SearchScanDocument) (bool, error)) error {
	for i := after; i < uint64(len(self)); i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		more, err := visit(i+1, self[i])
		if err != nil || !more {
			return err
		}
	}
	return nil
}

// The record scan retains the local reader's positions and revisions. Plaintext is cloned one entry at a time.
type memberRecordSearchScan struct {
	record      *SidecarRecord
	log         *recordReadLog
	writer, ref Id
	kind        protocol.RepoKind
	revision    uint64
	length      int
	now         time.Time
	policy      map[RecordClass]*RecordRetentionPolicy
	// Only positions are held for the scan. A single run's signed source bodies are folded on demand.
	cards []memberScanCard
	epoch uint64
	day   time.Duration
}

// One run's entries in this stream, in record-reader insertion order.
type memberScanCard struct {
	run       Id
	positions []int
}

// Captures the reader revision and its stream positions before opening any result page.
func (self *memberSearchSource) recordScan(repo, ref Id, kind protocol.RepoKind, key *EvsRefKey) *SearchScanView {
	record := self.record
	reader := record.Reader()
	retention := record.Retention()
	scan := &memberRecordSearchScan{record: record, ref: ref, kind: kind, day: retention.settings.Day, now: self.host.running.clock.Now()}
	reader.stateLock.Lock()
	log := reader.logs[repo]
	var erased bool
	if log != nil && log.complete {
		for writer, held := range log.streamRefIds {
			if ref == held {
				verified, err := EvsRefId(key, RecordStreamRefName(writer))
				if err == nil && verified == ref {
					scan.log, scan.writer, scan.revision, scan.length = log, writer, log.searchRevision, len(log.ordered)
					if indexRunCardLog(kind) {
						erased = log.erasureVersion != 0
						scan.collectCardsWithLock()
					}
				}
				break
			}
		}
	}
	reader.stateLock.Unlock()
	if scan.log == nil {
		return nil
	}
	if len(scan.cards) != 0 {
		index, err := EvsRefId(key, EvsIndexRefName)
		if err != nil {
			return nil
		}
		snap, err := self.syncer.Snapshot(repo, index)
		switch {
		case err == nil:
			scan.epoch = snap.manifest.IndexEpoch
			snap.Release()
		case errors.Is(err, ErrSidecarStoreAbsent), errors.Is(err, ErrSearchSyncUnfollowed):
			if erased {
				// With erasures and no verified index epoch, the card version cannot be established.
				scan.cards = nil
			}
		default:
			scan.cards = nil
		}
	}
	scan.policy = retention.governing(repo)
	return &SearchScanView{Source: scan, RefKey: key, valid: scan.valid}
}

// A changed read or erasure invalidates every page of this scan.
func (self *memberRecordSearchScan) valid() bool {
	reader := self.record.Reader()
	reader.stateLock.Lock()
	defer reader.stateLock.Unlock()
	return self.log.complete && self.log.searchRevision == self.revision
}

// Collects the positions of each run's sources on this stream, without retaining another copy of their bodies.
func (self *memberRecordSearchScan) collectCardsWithLock() {
	sources := indexRunCardSources(self.kind)
	runs := map[Id]int{}
	for i, entry := range self.log.ordered {
		if entry == nil || entry.Header == nil || !slices.Contains(sources, entry.Kind()) {
			continue
		}
		run, err := IdFromBytes(entry.Header.Header.GetRunId())
		if err != nil || run == (Id{}) || !slices.ContainsFunc(entry.Copies, func(c *RecordEntryCopy) bool { return c.StreamSidecarId == self.writer }) {
			continue
		}
		pos, ok := runs[run]
		if !ok {
			pos = len(self.cards)
			runs[run] = pos
			self.cards = append(self.cards, memberScanCard{run: run})
		}
		self.cards[pos].positions = append(self.cards[pos].positions, i)
	}
}

// Folds the same stream and log kind as its companion writer, from the verified held reader only.
func (self *memberRecordSearchScan) card(card *memberScanCard) (*SearchScanDocument, error) {
	reader := self.record.Reader()
	reader.stateLock.Lock()
	if !self.log.complete || self.log.searchRevision != self.revision {
		reader.stateLock.Unlock()
		return nil, ErrSearchCursorExpired
	}
	var entries []*indexRecordEntry
	var latest int64
	var tainted bool
	for _, pos := range card.positions {
		entry := self.log.ordered[pos]
		if entry.State != RecordEntryLive || entry.BodyInvalid || entry.BodyGeneric {
			reader.stateLock.Unlock()
			return nil, nil
		}
		for _, c := range entry.Copies {
			if c.StreamSidecarId != self.writer {
				continue
			}
			if self.expired(entry, c) {
				reader.stateLock.Unlock()
				return nil, nil
			}
			entries = append(entries, &indexRecordEntry{entryId: entry.EntryId, header: entry.Header.Header, path: c.Path, version: c.Version, body: bytes.Clone(entry.Body)})
			latest = max(latest, c.TimeMillis)
			tainted = tainted || entry.Flagged
		}
	}
	reader.stateLock.Unlock()
	doc, _, err := searchRunCardOf(&indexRunCardArgs{logKind: self.kind, entries: entries, runId: card.run, epoch: self.epoch,
		erasedAtEpoch: func(*indexRecordEntry) bool { return false }, settings: DefaultIndexRecordSettings(), format: DefaultIndexFormatSettings()})
	if errors.Is(err, errIndexCardVersionSpace) || doc == nil && err == nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &SearchScanDocument{RefId: self.ref, Kind: doc.Kind, Name: doc.Name, Version: doc.Version, TimeMs: latest, Signer: self.writer, Tainted: tainted || doc.Tainted, Documents: []*IndexDocument{doc}}, nil
}

// Reads only the next page of verified entries and run cards from the held reader.
func (self *memberRecordSearchScan) SearchScan(ctx context.Context, after uint64, visit func(uint64, *SearchScanDocument) (bool, error)) error {
	reader := self.record.Reader()
	for i := after; i < uint64(self.length+len(self.cards)); i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if i >= uint64(self.length) {
			doc, err := self.card(&self.cards[i-uint64(self.length)])
			if err != nil {
				return err
			}
			more, err := visit(i+1, doc)
			if err != nil || !more {
				return err
			}
			continue
		}
		reader.stateLock.Lock()
		if !self.log.complete || self.log.searchRevision != self.revision {
			reader.stateLock.Unlock()
			return ErrSearchCursorExpired
		}
		entry := self.log.ordered[i]
		var copied *RecordReadEntry
		if entry != nil && entry.State == RecordEntryLive && entry.Header != nil && !entry.BodyInvalid && !entry.BodyGeneric && indexRecordIndexesEntry(self.kind, entry.Kind()) {
			copied = entry.clone()
		}
		reader.stateLock.Unlock()
		doc, err := self.document(copied)
		if err != nil {
			return err
		}
		more, err := visit(i+1, doc)
		if err != nil || !more {
			return err
		}
	}
	return nil
}

// Uses the index's registry and the signed stream copy's version, signer and commit time.
func (self *memberRecordSearchScan) document(entry *RecordReadEntry) (*SearchScanDocument, error) {
	if entry == nil {
		return nil, nil
	}
	var newest *RecordEntryCopy
	for _, copy := range entry.Copies {
		if copy.StreamSidecarId == self.writer && (newest == nil || newest.Version < copy.Version) {
			newest = copy
		}
	}
	if newest == nil || newest.Path == "" || newest.Version == 0 || newest.TimeMillis <= 0 {
		return nil, nil
	}
	if self.expired(entry, newest) {
		return nil, nil
	}
	signer, err := IdFromBytes(entry.Header.Header.GetWriterSidecarId())
	if err != nil || signer == (Id{}) {
		return nil, nil
	}
	raw := &indexRecordEntry{entryId: entry.EntryId, header: entry.Header.Header, path: newest.Path, version: newest.Version, body: entry.Body}
	d, err := indexRecordEntryDocument(raw, nil, DefaultIndexRecordSettings())
	if err != nil {
		return nil, err
	}
	return &SearchScanDocument{RefId: self.ref, Kind: d.Kind, Name: d.Name, Version: d.Version, TimeMs: newest.TimeMillis, Signer: signer, Tainted: entry.Flagged, Documents: []*IndexDocument{d}}, nil
}

// A card and a standalone entry use the same signed retention clock for each underlying copy.
func (self *memberRecordSearchScan) expired(entry *RecordReadEntry, copy *RecordEntryCopy) bool {
	return !memberSearchCopyVisible(self.now, self.day, self.policy[entry.Kind().Class()], copy)
}

// Installs the repo's own versionless index writer beside the ordinary content commit on supported hosts.
func (self *Sidecar) BindSearchWrites(evs *EvsClient) error {
	if evs == nil || evs.args == nil || evs.args.Identity == nil {
		return ErrSidecarSearchUnavailable
	}
	format := DefaultIndexFormatSettings()
	writer, err := newIndexWriter(&indexWriterArgs{client: evs, settings: format, clock: self.clock, log: self.log,
		store:   func(repo *EvsRepo, name []byte) indexRefStore { return newIndexEvsStore(repo, name, false) },
		isAdmin: func(repo Id) func(*indexFileVersion) bool { judge, _ := evs.Repo(repo).indexAdmins(); return judge },
		mayMerge: func() bool {
			conditions, _ := self.SearchConditions()
			fg, _ := self.SearchForeground()
			current := searchConditionsOf(conditions, fg, self.settings.Search.RemoteServe)
			return current.DaemonHost || current.OnCharge() && !current.Metered() && !current.Paused()
		},
	})
	if err != nil {
		return err
	}
	writer.Install()
	evs.searchNames.Store(true)
	return nil
}
