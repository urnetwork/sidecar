// §11.7's newest row, the one rule head reads, listings and step 5g's path-level CAS all use (D-EVS-31, I-EVS-6,
// I-EVS-8): a path's newest committed version at a head H is the newer of
//
//   - its entry's newest folded version, a marker's removal included, and
//   - the newest version after h that changes the path or a prefix holding it, the window entry's digest first and
//     then the statement's change list,
//
// h being the folded_through of a head evs read before the entry. A fold's PUTs precede the commit that raises
// folded_through over them, so the entry holds every version through h; H's window must hold every version after h,
// else evs reads the entry again after H (ErrEvsEntryBehindWindow); and a folded version committed after H's v sends
// evs to a newer head (ErrEvsEntryAheadOfHead). The digest is only a filter: the change list decides, inline in the
// statement or under changes_root in the payload or its parts. A prefix's removal ends every path below it, whose
// removal version is then one past its last.
//
// Statements come from the process's record cache or batch ranges (RecordPushSource); older ones are never needed
// here, since every version after h is in H's window. Readers check what evs serves against its statements either
// way (§11.9's reader row).
//
// Pure over its inputs but for the push source's reads. Safe for concurrent use.

package evsservice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

var (
	// H's window does not hold every version after the entry's h: read the entry again after H.
	ErrEvsEntryBehindWindow = errors.New("evs window does not reach the entry's horizon")
	// The entry holds a version committed past H's v: read a newer head.
	ErrEvsEntryAheadOfHead = errors.New("evs entry holds a version past the head")
	// The record at a window entry's place is not the push it names: a wrong place, hash or digest, which only
	// breaks the chain a reader checks (§11.8's trust row), and alarms.
	ErrEvsStatementMismatch = errors.New("evs record is not the statement its window entry names")
	// An entry combined with a head older than the one it was read after: the caller's bug.
	ErrEvsHorizonAhead = errors.New("evs entry read after a head newer than the one served")
)

// One change of a committed push, as the newest rule reads it.
type EvsCommittedChange struct {
	TokenPath        sidecar.EvsTokenPath
	BaseEntryVersion uint64
	EntrySha256      []byte
	// The EvsEntryVersion bytes the change writes, as received; nil for a removal.
	EntryVersion []byte
	// While the head lists sources: the EvsSourcePath encodings naming the path in each source that may hold it
	// (§11.6's read row), which a fold carries from (§11.7's epochs row). Empty otherwise.
	SourcePaths [][]byte
}

// Whether the change removes its path.
func (self *EvsCommittedChange) Removes() bool {
	return len(self.EntrySha256) == 0
}

// Where the newest rule reads a window version's changes: the push committed at version, whose window entry is
// entry, and of its changes those on tokenPath or on a prefix holding it, each writing one with its entry version.
type EvsPushSource interface {
	ChangesAt(ctx context.Context, version uint64, entry *sidecar.EvsWindowEntry, tokenPath sidecar.EvsTokenPath) ([]*EvsCommittedChange, error)
}

// A path's newest committed version at a head, by §11.7's rule.
type EvsNewest struct {
	// Whether the path stands at the head: written, and not removed since.
	Exists bool
	// The ref version that committed its newest version or removal; 0 when it was never written.
	CommitVersion uint64
	// A file's newest version while it stands: what a change's base_entry_version must equal. 0 when absent, never
	// written or removed. A directory's folded table keeps no version, so a directory reads its newest delta's when
	// the window holds it and 0 otherwise, with Exists set.
	Version uint64
	// While its newest is a removal, its own or a prefix's: that removal's version, one past the path's last, which
	// a creation's version must exceed (§11.7's versions row's m). 0 when it never stood.
	RemovalVersion uint64
	// The push that wrote its newest version or removal.
	PushId sidecar.Id
	// Its newest is a directory.
	Directory bool
	// Its newest came from a window statement after h, not from its entry.
	FromWindow bool
	// From the entry: the folded version or the marker that is its newest.
	IndexVersion *protocol.EvsIndexVersion
	Marker       *protocol.EvsRemovalMarker
	// From the window: the change that wrote or removed it. nil when a prefix's removal ended it.
	Change *EvsCommittedChange
	// A prefix's removal ended it at CommitVersion.
	RemovedByPrefix bool
}

// The window and entry one rule combines.
type newestScan struct {
	ctx          context.Context
	read         *EvsEntryRead
	pushes       EvsPushSource
	window       []*sidecar.EvsWindowEntry
	firstVersion uint64
}

// The path's newest committed version at head, combining read, the entry read after a head whose folded_through was
// read.FoldedThrough, with head's window. ErrEvsEntryBehindWindow and ErrEvsEntryAheadOfHead tell the caller which
// read to repeat.
func Newest(ctx context.Context, read *EvsEntryRead, head *protocol.EvsHead, pushes EvsPushSource) (*EvsNewest, error) {
	scan, err := newNewestScan(ctx, read, head, pushes)
	if err != nil {
		return nil, err
	}
	return scan.below(head.GetVersion() + 1)
}

// The scan of read against head, once its rule's preconditions hold.
func newNewestScan(ctx context.Context, read *EvsEntryRead, head *protocol.EvsHead, pushes EvsPushSource) (*newestScan, error) {
	version := head.GetVersion()
	foldedThrough := read.FoldedThrough
	if version < foldedThrough {
		return nil, fmt.Errorf("%w: folded through %d past version %d", ErrEvsHorizonAhead, foldedThrough, version)
	}
	firstVersion := EvsHeadWindowFirstVersion(head)
	if foldedThrough+1 < firstVersion {
		return nil, fmt.Errorf("%w: the window starts at %d, past %d", ErrEvsEntryBehindWindow, firstVersion, foldedThrough+1)
	}
	if newest := entryNewestBelow(read.Entry, ^uint64(0)); newest != nil && version < newest.CommitVersion {
		return nil, fmt.Errorf("%w: a version committed at %d past %d", ErrEvsEntryAheadOfHead, newest.CommitVersion, version)
	}
	window, err := EvsHeadWindow(head)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEvsHeadInvalid, err)
	}
	return &newestScan{ctx: ctx, read: read, pushes: pushes, window: window, firstVersion: firstVersion}, nil
}

// The newest the entry holds committed below limit: its newest folded version below it, or its marker when that is
// newer, or a directory's table.
func entryNewestBelow(entry *protocol.EvsIndexEntry, limit uint64) *EvsNewest {
	if entry == nil {
		return nil
	}
	var newest *EvsNewest
	for _, version := range entry.GetVersions() {
		if limit <= version.GetCommitVersion() {
			continue
		}
		entryVersion, err := parseEvsEntryVersion(version.GetEntryVersion())
		if err != nil {
			// ParseEvsIndexEntry has held every version to parse
			continue
		}
		newest = &EvsNewest{
			Exists:        true,
			CommitVersion: version.GetCommitVersion(),
			Version:       entryVersion.GetVersion(),
			PushId:        sidecar.Id(version.GetPushId()),
			IndexVersion:  version,
		}
		break
	}
	if names := entry.GetNames(); names != nil && newest == nil && entry.GetNamesThrough() < limit {
		newest = &EvsNewest{Exists: true, Directory: true, CommitVersion: entry.GetNamesThrough()}
	}
	if marker := entry.GetMarker(); marker != nil && marker.GetRemovalVersion() < limit &&
		(newest == nil || newest.CommitVersion < marker.GetRemovalVersion()) {
		newest = &EvsNewest{
			CommitVersion:  marker.GetRemovalVersion(),
			RemovalVersion: marker.GetPathVersion(),
			PushId:         sidecar.Id(marker.GetPushId()),
			Marker:         marker,
		}
	}
	return newest
}

// The path's newest committed below limit: the entry's below limit, unless a window version after both h and that
// one changes the path or removes a prefix holding it.
func (self *newestScan) below(limit uint64) (*EvsNewest, error) {
	entryNewest := entryNewestBelow(self.read.Entry, limit)
	floor := self.read.FoldedThrough
	if entryNewest != nil && floor < entryNewest.CommitVersion {
		// window versions at or below the entry's newest are older than it, or are it
		floor = entryNewest.CommitVersion
	}
	path := self.read.TokenPath
	for version := limit - 1; floor < version; version -= 1 {
		windowEntry := self.window[version-self.firstVersion]
		if !windowEntry.PathsDigest.MayChange(path) {
			continue
		}
		changes, err := self.pushes.ChangesAt(self.ctx, version, windowEntry, path)
		if err != nil {
			return nil, err
		}
		var own *EvsCommittedChange
		prefixRemoved := false
		for _, change := range changes {
			switch {
			case change.TokenPath.Equal(path):
				own = change
			case path.HasPrefix(change.TokenPath) && change.Removes():
				prefixRemoved = true
			}
		}
		switch {
		case own != nil:
			return newestOfChange(version, windowEntry.PushId, own)
		case prefixRemoved:
			last, err := self.below(version)
			if err != nil {
				return nil, err
			}
			if !last.Exists {
				// already absent: the prefix's removal adds no removal of its own (§11.7's removal row)
				return last, nil
			}
			return &EvsNewest{
				CommitVersion:   version,
				RemovalVersion:  last.Version + 1,
				PushId:          windowEntry.PushId,
				Directory:       last.Directory,
				FromWindow:      true,
				RemovedByPrefix: true,
			}, nil
		}
	}
	if entryNewest != nil {
		return entryNewest, nil
	}
	return &EvsNewest{}, nil
}

// The newest a window change on the path itself makes: a removal one past the version it removes, or the version
// its entry version writes.
func newestOfChange(version uint64, pushId sidecar.Id, change *EvsCommittedChange) (*EvsNewest, error) {
	if change.Removes() {
		return &EvsNewest{
			CommitVersion:  version,
			RemovalVersion: change.BaseEntryVersion + 1,
			PushId:         pushId,
			FromWindow:     true,
			Change:         change,
		}, nil
	}
	entryVersion, err := parseEvsEntryVersion(change.EntryVersion)
	if err != nil {
		return nil, fmt.Errorf("%w: version %d: %v", ErrEvsStatementMismatch, version, err)
	}
	return &EvsNewest{
		Exists:        true,
		CommitVersion: version,
		Version:       entryVersion.GetVersion(),
		PushId:        pushId,
		Directory:     entryVersion.GetKind() == uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY),
		FromWindow:    true,
		Change:        change,
	}, nil
}

// A directory's listing at a head (§11.9's newest row): its folded table plus, in version order, the deltas after h
// past the version the table holds.
type EvsListing struct {
	// Whether the directory stands at the head.
	Exists bool
	// Its rows, by token.
	Names []*protocol.EvsName
	// The ref version its folded table was folded through, 0 when the window re-created it.
	TableThrough uint64
	// The window versions whose deltas it applied, ascending.
	DeltaVersions []uint64
}

// The directory's listing at head: Newest's rule for whether it stands, then its table and the window's deltas.
func Listing(ctx context.Context, read *EvsEntryRead, head *protocol.EvsHead, pushes EvsPushSource) (*EvsListing, error) {
	scan, err := newNewestScan(ctx, read, head, pushes)
	if err != nil {
		return nil, err
	}
	newest, err := scan.below(head.GetVersion() + 1)
	if err != nil {
		return nil, err
	}
	if !newest.Exists {
		return &EvsListing{}, nil
	}
	path := read.TokenPath
	tokenNames := map[sidecar.EvsToken]*protocol.EvsName{}
	tableThrough := uint64(0)
	if entry := read.Entry; entry != nil && entry.GetNames() != nil && entry.GetMarker() == nil {
		tableThrough = entry.GetNamesThrough()
		for _, name := range entry.GetNames().GetNames() {
			tokenNames[sidecar.EvsToken(name.GetToken())] = name
		}
	}
	from := max(read.FoldedThrough, tableThrough)
	listing := &EvsListing{Exists: true, TableThrough: tableThrough}
	for version := from + 1; version <= head.GetVersion(); version += 1 {
		windowEntry := scan.window[version-scan.firstVersion]
		if !windowEntry.PathsDigest.MayChange(path) {
			continue
		}
		changes, err := pushes.ChangesAt(ctx, version, windowEntry, path)
		if err != nil {
			return nil, err
		}
		for _, change := range changes {
			switch {
			case change.TokenPath.Equal(path) && change.Removes(), !change.TokenPath.Equal(path) && change.Removes():
				// the directory, or a prefix holding it, removed: what was listed is gone
				clear(tokenNames)
				listing.TableThrough = 0
			case change.TokenPath.Equal(path):
				entryVersion, err := parseEvsEntryVersion(change.EntryVersion)
				if err != nil {
					return nil, fmt.Errorf("%w: version %d: %v", ErrEvsStatementMismatch, version, err)
				}
				if change.BaseEntryVersion == 0 {
					// a creation replaces what was held, carrying nothing
					clear(tokenNames)
					listing.TableThrough = 0
				}
				for _, removed := range entryVersion.GetNames().GetRemovedTokens() {
					if len(removed) == sidecar.EvsTokenByteCount {
						delete(tokenNames, sidecar.EvsToken(removed))
					}
				}
				for _, name := range entryVersion.GetNames().GetNames() {
					if len(name.GetToken()) == sidecar.EvsTokenByteCount {
						tokenNames[sidecar.EvsToken(name.GetToken())] = name
					}
				}
				listing.DeltaVersions = append(listing.DeltaVersions, version)
			}
		}
	}
	tokens := make([]sidecar.EvsToken, 0, len(tokenNames))
	for token := range tokenNames {
		tokens = append(tokens, token)
	}
	sort.Slice(tokens, func(i int, j int) bool { return bytes.Compare(tokens[i][:], tokens[j][:]) < 0 })
	for _, token := range tokens {
		listing.Names = append(listing.Names, tokenNames[token])
	}
	return listing, nil
}

// The push source over the ref's batch records: the process's cache, else a range read at each window entry's place
// (§11.8's read row). A push record's changes come checked from its statement and payload; a seal's from the parts
// whose runs may hold the path or a prefix of it, each matched to the seal's changes_root. A record that is not the
// statement its entry names is ErrEvsStatementMismatch. Not safe for concurrent use: one request's.
type RecordPushSource struct {
	cache   *RecordCache
	cluster sidecar.BlobCluster
	repoId  sidecar.Id
	refId   sidecar.Id
	// the pushes read so far, by version, so several paths of one request share a read
	versionPushes map[uint64]*recordPush
}

// A push as one record read gave it: its statement, and its changes so far, by part.
type recordPush struct {
	statement *sidecar.EvsStatement
	// a one-part push's changes, all of them
	changes []*EvsCommittedChange
	// a sealed push's parts, and the changes of those read
	sealParts   []*sidecar.EvsSealPart
	partChanges map[int][]*EvsCommittedChange
	sealed      bool
	// a sealed push's every change, checked whole as its seal, once a fold read them all (fold.go)
	allChanges []*EvsCommittedChange
	// a DROP's body as checked (format 2): a one-part push's from its record, a sealed push's with allChanges; nil
	// for any other push (fold_format2.go)
	drop *sidecar.EvsCheckedDrop
}

// A source for one ref of one repo on its cluster.
func NewRecordPushSource(cache *RecordCache, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id) *RecordPushSource {
	return &RecordPushSource{cache: cache, cluster: cluster, repoId: repoId, refId: refId, versionPushes: map[uint64]*recordPush{}}
}

// See EvsPushSource.
func (self *RecordPushSource) ChangesAt(ctx context.Context, version uint64, entry *sidecar.EvsWindowEntry, tokenPath sidecar.EvsTokenPath) ([]*EvsCommittedChange, error) {
	push, ok := self.versionPushes[version]
	if !ok {
		var err error
		push, err = self.readPush(ctx, entry)
		if err != nil {
			return nil, err
		}
		self.versionPushes[version] = push
	}
	if !push.sealed {
		return touching(push.changes, tokenPath), nil
	}
	// the parts whose runs may hold the path or a prefix of it: each prefix sorts before the path
	partIndexes := []int{}
	for length := 1; length <= len(tokenPath); length += 1 {
		index := sealPartHolding(push.sealParts, tokenPath[:length])
		if 0 <= index && !slices.Contains(partIndexes, index) {
			partIndexes = append(partIndexes, index)
		}
	}
	changes := []*EvsCommittedChange{}
	for _, index := range partIndexes {
		partChanges, err := self.readPart(ctx, push, index)
		if err != nil {
			return nil, err
		}
		changes = append(changes, touching(partChanges, tokenPath)...)
	}
	return changes, nil
}

// The changes on tokenPath or on a prefix holding it.
func touching(changes []*EvsCommittedChange, tokenPath sidecar.EvsTokenPath) []*EvsCommittedChange {
	touched := []*EvsCommittedChange{}
	for _, change := range changes {
		if tokenPath.HasPrefix(change.TokenPath) {
			touched = append(touched, change)
		}
	}
	return touched
}

// The part whose run would hold tokenPath: the last whose first token path sorts at or before it, -1 for none.
func sealPartHolding(parts []*sidecar.EvsSealPart, tokenPath sidecar.EvsTokenPath) int {
	index := -1
	for i, part := range parts {
		// a changeless part holds no change, and comes after every part that does
		if part.Changeless {
			break
		}
		if part.FirstTokenPath.Compare(tokenPath) <= 0 {
			index = i
		}
	}
	return index
}

// The window entry's record, checked to be the push the entry names and of this repo and ref.
func (self *RecordPushSource) readPush(ctx context.Context, entry *sidecar.EvsWindowEntry) (*recordPush, error) {
	record, err := ReadRecord(ctx, self.cache, self.cluster, entry.Place)
	if err != nil {
		return nil, err
	}
	if record.PushId != entry.PushId || record.RepoId != self.repoId || record.RefId != self.refId {
		return nil, fmt.Errorf("%w: another push's record", ErrEvsStatementMismatch)
	}
	switch record.Type {
	case protocol.EvsBatchRecordType_EVS_BATCH_PUSH, protocol.EvsBatchRecordType_EVS_BATCH_RESEED:
		statementBytes, payloadBytes, err := sidecar.ParseEvsPushRecordBody(record.Body)
		if err != nil {
			return nil, err
		}
		statement, err := self.statementOf(entry, statementBytes)
		if err != nil {
			return nil, err
		}
		checked, err := sidecar.EvsCheckStoredPayload(statement, payloadBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrEvsStatementMismatch, err)
		}
		return &recordPush{statement: statement, changes: committedChanges(checked.Changes), drop: checked.Drop}, nil
	case protocol.EvsBatchRecordType_EVS_BATCH_SEAL:
		statementBytes, parts, err := sidecar.ParseEvsSealRecordBody(record.Body)
		if err != nil {
			return nil, err
		}
		statement, err := self.statementOf(entry, statementBytes)
		if err != nil {
			return nil, err
		}
		return &recordPush{statement: statement, sealParts: parts, partChanges: map[int][]*EvsCommittedChange{}, sealed: true}, nil
	}
	return nil, fmt.Errorf("%w: a record of type %d at a version's place", ErrEvsStatementMismatch, record.Type)
}

// The statement's bytes parsed and held to the window entry's push id and hash prefix. A committed statement is
// read as stored, of either format (format1_guard.go).
func (self *RecordPushSource) statementOf(entry *sidecar.EvsWindowEntry, statementBytes []byte) (*sidecar.EvsStatement, error) {
	statement, err := sidecar.ParseEvsStatementFormat2(statementBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEvsStatementMismatch, err)
	}
	if !entry.Names(sidecar.Id(statement.Push.GetPushId()), statement.Sha256) {
		return nil, fmt.Errorf("%w: the statement's hash", ErrEvsStatementMismatch)
	}
	return statement, nil
}

// One part of a sealed push, read once and matched to the seal's changes_root for it.
func (self *RecordPushSource) readPart(ctx context.Context, push *recordPush, index int) ([]*EvsCommittedChange, error) {
	if changes, ok := push.partChanges[index]; ok {
		return changes, nil
	}
	sealPart := push.sealParts[index]
	record, err := ReadRecord(ctx, self.cache, self.cluster, sealPart.Place)
	if err != nil {
		return nil, err
	}
	if record.Type != protocol.EvsBatchRecordType_EVS_BATCH_PART || record.PushId != sidecar.Id(push.statement.Push.GetPushId()) {
		return nil, fmt.Errorf("%w: a seal's part place holds another record", ErrEvsStatementMismatch)
	}
	statementBytes, partBytes, _, _, err := sidecar.ParseEvsPartRecordBody(record.Body)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(statementBytes, push.statement.Bytes) {
		return nil, fmt.Errorf("%w: a part of another statement", ErrEvsStatementMismatch)
	}
	checked, err := sidecar.EvsCheckStoredPart(push.statement, partBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEvsStatementMismatch, err)
	}
	if checked.Root != sealPart.ChangesRoot {
		return nil, fmt.Errorf("%w: a part whose changes_root the seal does not name", ErrEvsStatementMismatch)
	}
	changes := committedChanges(checked.Changes)
	push.partChanges[index] = changes
	return changes, nil
}

// Checked changes as the newest rule reads them.
func committedChanges(checkedChanges []*sidecar.EvsCheckedChange) []*EvsCommittedChange {
	changes := make([]*EvsCommittedChange, len(checkedChanges))
	for i, checked := range checkedChanges {
		changes[i] = &EvsCommittedChange{
			TokenPath:        checked.TokenPath,
			BaseEntryVersion: checked.Change.GetBaseEntryVersion(),
			EntrySha256:      checked.Change.GetEntrySha256(),
			EntryVersion:     checked.EntryVersion,
			SourcePaths:      checked.SourcePaths,
		}
	}
	return changes
}
