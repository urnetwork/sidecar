//go:build !ios_extension

// A repo-scoped fallback pages only effective files and signed entries already verified on this device.
package sidecar

import (
	"bytes"
	"context"
	"math"
	"slices"
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

// A bounded snapshot of names; pin changes invalidate every page that retained it.
type memberFileSearchScan []*SearchScanDocument

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
	day         time.Duration
}

func (self *memberSearchSource) recordScan(repo, ref Id, kind protocol.RepoKind, key *EvsRefKey) *SearchScanView {
	record := self.record
	reader := record.Reader()
	retention := record.Retention()
	scan := &memberRecordSearchScan{record: record, ref: ref, kind: kind, day: retention.settings.Day, now: self.host.running.clock.Now()}
	reader.stateLock.Lock()
	log := reader.logs[repo]
	if log != nil && log.complete {
		for writer, held := range log.streamRefIds {
			if ref == held {
				verified, err := EvsRefId(key, RecordStreamRefName(writer))
				if err == nil && verified == ref {
					scan.log, scan.writer, scan.revision, scan.length = log, writer, log.searchRevision, len(log.ordered)
				}
				break
			}
		}
	}
	reader.stateLock.Unlock()
	if scan.log == nil {
		return nil
	}
	scan.policy = retention.governing(repo)
	return &SearchScanView{Source: scan, RefKey: key, valid: scan.valid}
}

func (self *memberRecordSearchScan) valid() bool {
	reader := self.record.Reader()
	reader.stateLock.Lock()
	defer reader.stateLock.Unlock()
	return self.log.complete && self.log.searchRevision == self.revision
}

func (self *memberRecordSearchScan) SearchScan(ctx context.Context, after uint64, visit func(uint64, *SearchScanDocument) (bool, error)) error {
	reader := self.record.Reader()
	for i := after; i < uint64(self.length); i++ {
		if err := ctx.Err(); err != nil {
			return err
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
	if policy := self.policy[entry.Kind().Class()]; policy != nil && policy.SearchableDays != 0 && !self.now.Before(time.UnixMilli(entry.PushTimeMillis).Add(memberSearchAge(policy.SearchableDays, self.day))) {
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
