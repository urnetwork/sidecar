//go:build !ios_extension && !sidecar_http

// §16.11's retention row as the directory keeps it (RECORD-M6-21; RECORD-M6-03's RetentionPolicy, D-MCP-33, FS-87):
//
//	defaults   request, decision, erasure request and coordination entries keep_days 400, announce entries 30
//	           (RecordRetentionSettings' DirectoryKeepDays and DirectoryAnnounceKeepDays, the defaults the record's
//	           retention reads for the directory); and past its keep_days an announce entry is still held until
//	           AnnounceHold after a newer entry or file for its item, or its item's expiry, so a live repo item keeps
//	           its newest copy, its last M6 entry until format 2's r/ file supersedes it, since repo items carry no
//	           expiry (directoryAnnounceHold)
//	expiry     the directory's erasure runner (directory_erasure.go) runs RecordRetention.Expire with that hold, on the
//	           runner's daemon alone; with no runner online it waits, and every directory admin's device names the
//	           oldest entry waiting (RetentionStatusLines, in ur status)
//	base       an admin BASE re-lists the live set once a BaseInterval, on the runner's daemon: RecordRetention.Base,
//	           which removes from each stream the files of entries whose erasure is complete (DirectoryBase)
//	set        ur admin directory --keep and --searchable file a RetentionPolicy for the coordination and request
//	           classes, a directory admin's confirmed act (SetDirectoryRetention); announce entries keep §16.11's rule
//
// Safe for concurrent use.

package sidecar

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
)

// The classes ur admin directory's --keep and --searchable set: coordination entries (ask, answer, check, note) and
// requests (request, decision, erasure request). Announce entries keep §16.11's rule.
var directoryRetentionSetClasses = []RecordClass{RecordClassCoordination, RecordClassRequest}

// An announce copy as the hold sorts it.
type directoryAnnounceCopy struct {
	// the entry's id; zero for a card's or repo file's version
	entryId       Id
	version       uint64
	pushMillis    int64
	expiresMillis int64
}

// Whether expiry holds an entry (§16.11's retention row): an announce entry until window after a newer entry or file
// for its item, or its item's expiry; a repo item's newest copy, which has neither, for as long as it is the newest.
// files are the card and repo file versions the fold accepted, from format 2 (DirectoryFold's file versions).
func directoryAnnounceHold(entries []*RecordReadEntry, files []*directoryVersion, nowMillis int64, window time.Duration) func(entry *RecordReadEntry) bool {
	byItem := map[DirectoryItemKey][]*directoryAnnounceCopy{}
	for _, entry := range entries {
		if entry.Header == nil || entry.Header.Kind() != RecordKindAnnounce || entry.Body == nil || entry.BodyInvalid {
			continue
		}
		version, ok := directoryVersionOf(entry)
		if !ok {
			continue
		}
		byItem[version.key] = append(byItem[version.key], &directoryAnnounceCopy{
			entryId: entry.EntryId, version: version.item.GetVersion(), pushMillis: entry.PushTimeMillis, expiresMillis: version.item.GetExpiresMillis(),
		})
	}
	for _, file := range files {
		if _, ok := byItem[file.key]; !ok {
			// an item no entry carries holds nothing
			continue
		}
		byItem[file.key] = append(byItem[file.key], &directoryAnnounceCopy{
			version: file.item.GetVersion(), pushMillis: file.pushTimeMillis, expiresMillis: file.item.GetExpiresMillis(),
		})
	}
	endedMillis := map[Id]int64{}
	held := map[Id]bool{}
	for _, copies := range byItem {
		slices.SortStableFunc(copies, func(a *directoryAnnounceCopy, b *directoryAnnounceCopy) int {
			return cmp.Or(cmp.Compare(a.version, b.version), cmp.Compare(a.pushMillis, b.pushMillis), a.entryId.Cmp(b.entryId))
		})
		for i, copied := range copies {
			if copied.entryId == (Id{}) {
				continue
			}
			held[copied.entryId] = true
			switch {
			case i+1 < len(copies):
				endedMillis[copied.entryId] = copies[i+1].pushMillis
			case copied.expiresMillis != 0:
				endedMillis[copied.entryId] = copied.expiresMillis
			}
		}
	}
	return func(entry *RecordReadEntry) bool {
		if !held[entry.EntryId] {
			// no announce entry this copy reads: the policy's own rule
			return false
		}
		ended, ok := endedMillis[entry.EntryId]
		return !ok || nowMillis < ended+window.Milliseconds()
	}
}

// The card and repo file versions the client's fold accepted at its last update, for the hold.
func (self *DirectoryClient) foldFileVersions() []*directoryVersion {
	fold := self.currentFold()
	fold.stateLock.Lock()
	defer fold.stateLock.Unlock()
	files := []*directoryVersion{}
	for _, version := range fold.leafVersions {
		if version.entryId == (Id{}) {
			files = append(files, version)
		}
	}
	return files
}

// One entry past its class's keep_days that no erasure has taken, as a directory admin's device names it.
type DirectoryRetentionWaiting struct {
	EntryId Id
	Kind    RecordKind
	// When its keep_days ran out, and how long it has waited since.
	DueMillis int64
	Age       time.Duration
}

// The entries of this copy past their class's keep_days by their push time, not archived, not held by
// directoryAnnounceHold and with a key left, oldest due first: what the runner's next expiry pass erases.
func (self *DirectoryClient) RetentionWaiting(settings *DirectoryErasureSettings) []*DirectoryRetentionWaiting {
	if settings == nil {
		settings = DefaultDirectoryErasureSettings()
	}
	directoryId, ok := self.DirectoryId()
	if !ok {
		return nil
	}
	entries := self.allEntries()
	retention := DefaultRecordRetentionSettings()
	policies, _ := RecordRetentionGoverning(self.recordAuth(), directoryId, entries, self.recordSet, retention)
	nowMillis := self.clock.Now().UnixMilli()
	hold := directoryAnnounceHold(entries, self.foldFileVersions(), nowMillis, settings.AnnounceHold)
	waiting := []*DirectoryRetentionWaiting{}
	for _, entry := range entries {
		if entry.Header == nil || entry.State.KeyGone() || entry.State == RecordEntryLost || entry.State == RecordEntryArchived {
			continue
		}
		class := entry.Kind().Class()
		policy := policies[class]
		if class == RecordClassLog || policy == nil || policy.KeepDays == 0 || policy.Archive {
			continue
		}
		dueMillis := entry.PushTimeMillis + (time.Duration(policy.KeepDays) * retention.Day).Milliseconds()
		if nowMillis < dueMillis || hold(entry) {
			continue
		}
		waiting = append(waiting, &DirectoryRetentionWaiting{
			EntryId: entry.EntryId, Kind: entry.Kind(), DueMillis: dueMillis, Age: time.Duration(nowMillis-dueMillis) * time.Millisecond,
		})
	}
	slices.SortStableFunc(waiting, func(a *DirectoryRetentionWaiting, b *DirectoryRetentionWaiting) int {
		return cmp.Or(cmp.Compare(a.DueMillis, b.DueMillis), a.EntryId.Cmp(b.EntryId))
	})
	return waiting
}

// `ur status`'s retention line on a directory admin's device: how many entries wait for the runner's expiry and the
// oldest one, while no runner has erased them (§16.11's readers row, FS-87). None on any other device, and none when
// nothing waits.
func (self *DirectoryClient) RetentionStatusLines(settings *DirectoryErasureSettings) []string {
	admin, _, err := self.directoryAdmin(self.auth())
	if err != nil || !admin {
		return nil
	}
	waiting := self.RetentionWaiting(settings)
	if len(waiting) == 0 {
		return nil
	}
	oldest := waiting[0]
	return []string{fmt.Sprintf("directory: %d entries past retention wait for the erasure runner, the oldest a %s entry %s past its keep_days (entry %s): expiry waits for a directory admin's daemon",
		len(waiting), oldest.Kind, directoryAgeText(oldest.Age), oldest.EntryId)}
}

// The directory's admin BASE on the runner's daemon: RecordRetention.Base once BaseInterval has passed since the last
// one it marked, as the record's own tick runs it for the logs it administers. Answers how many files went, and false
// when none was due. ErrRecordRetentionBaseUnbound, nothing marked, while no BASE is bound.
func (self *RecordRetention) DirectoryBase(ctx context.Context, directoryId Id) (int, bool, error) {
	self.passLock.Lock()
	defer self.passLock.Unlock()
	writer := self.record.writer
	interval := writer.settings.BaseInterval
	if interval <= 0 {
		return 0, false, nil
	}
	mark, err := self.readMark(directoryId)
	if err != nil {
		return 0, false, err
	}
	now := writer.clock.Now().UTC()
	if now.Sub(time.UnixMilli(mark.BaseMillis)) < interval {
		return 0, false, nil
	}
	removed, err := self.rebase(ctx, directoryId)
	if err != nil {
		return removed, true, err
	}
	mark.BaseMillis = now.UnixMilli()
	return removed, true, self.writeMark(mark)
}

// Runs the runner's BASE once due, after its expiry. The caller holds passLock.
func (self *DirectoryErasureRunner) rebase(ctx context.Context, directoryId Id) error {
	if self.base == nil {
		return nil
	}
	_, _, err := self.base(ctx, directoryId)
	if errors.Is(err, ErrRecordRetentionBaseUnbound) {
		return nil
	}
	return err
}

// What ur admin directory's --keep and --searchable ask (§16.11's admins row; plan-RECORD-small-readings #14): one
// RetentionPolicy for each of the coordination and request classes.
type DirectoryRetentionArgs struct {
	KeepDays       uint32
	SearchableDays uint32
	// A person confirmed the command on /dev/tty or in an app's UI (§5.8).
	Confirmed bool
	// The caller has a harness process among its ancestors: refused.
	HarnessAncestor bool
}

// Files the directory's RetentionPolicy for the coordination and request classes through the record's retention, a
// directory admin's confirmed act: see the file's header's set row. Answers the entries written, one a class. A
// searchable_days outside the directory's 7 to 400 days refuses with nothing written; one past keep_days, or a class's
// policy the record refuses, stops at that class.
func (self *Sidecar) SetDirectoryRetention(ctx context.Context, args *DirectoryRetentionArgs) ([]*RecordEntryRef, error) {
	if args == nil || !args.Confirmed || args.HarnessAncestor {
		return nil, ErrRecordRetentionUnconfirmed
	}
	client := self.Directory()
	if client == nil {
		return nil, fmt.Errorf("%w: this network is personal, or its team directory does not exist yet", ErrDirectoryNone)
	}
	directoryId, _ := client.DirectoryId()
	admin, _, err := client.directoryAdmin(client.auth())
	if err != nil {
		return nil, err
	}
	if !admin {
		return nil, ErrDirectoryEraseNotAdmin
	}
	if args.SearchableDays != 0 {
		// §16.11's settings row: a searchable_days an admin names is within the directory's days
		if err := client.indexSettings().CheckSearchableDays(args.SearchableDays); err != nil {
			return nil, err
		}
	}
	record, err := self.Record()
	if err != nil {
		return nil, err
	}
	refs := []*RecordEntryRef{}
	for _, class := range directoryRetentionSetClasses {
		ref, err := record.Retention().Set(ctx, &RecordRetentionSetArgs{
			LogId: directoryId, Class: class, KeepDays: args.KeepDays, SearchableDays: args.SearchableDays, Confirmed: true,
		})
		if err != nil {
			return refs, err
		}
		refs = append(refs, ref)
	}
	return refs, nil
}
