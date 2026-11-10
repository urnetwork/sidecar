// §16.11's desktops row: how a daemon keeps its copy of the team directory, on format 1's streams at M6 (D-PHASE-11),
// and DirectoryCards, the seam to evs that the sync and every later directory task build on (RECORD-M6-13). It adds to
// RecordStreams what the directory needs: the shared cards ref's versioned files with path CAS, a read of up to 64
// streams in one request, the moved listing and leases on notice prefixes (§11.9, §11.10). RECORD-M3-12 and EVS1-M6-01
// bind it to EvsRepo's ReadStreams and GET .../refs?moved_after; sidecartest's FakeDirectoryCards stands in until then,
// and DirectoryCardsUnavailable refuses everything while nothing is bound.
//
// One sync, in this order:
//
//	cards     the cards ref's statements after its pin, log pages past the window, applying each file they write or
//	          remove: at M6 only notices, q/<h>/<tgt>/<rid>; from format 2 cards and repo files too
//	listing   GET .../refs?moved_after=<the sequence the last sync ended at>; at the first sync of each UTC day no
//	          moved_after, since a commit whose raise a crash lost shows only at its ref's next commit; a sequence
//	          restart, or a ref the head cache lost, answers every ref; a stream listed below what the copy holds
//	          was wound back, and alarms chain_fork while the copy keeps what it verified (I-16)
//	streams   the moved streams past what this daemon holds, 64 to a request, following more and paging the log for
//	          behind, each version kept in the store before the stream's position moves, so ceil(n/64) requests read
//	          n moved streams and a kill re-reads at most what was not kept
//	verify    RECORD-M3-03's reader over what the store holds: headers, rights, chains and bodies, as for any log
//	          (RECORD.md section 5.5), with no request of its own but the erasure ref's when it moved
//
// What a sync never does: lease the cards ref (D-MCP-31; readers poll it and lease only notice prefixes), read a
// stream that did not move, or send evs anything of a view or a search (I-19). Barriers: directory.sync.before and
// .after around a sync, keyed by the directory's repo id, with no lock held.

package sidecar

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §11.9's streams row: refs one POST .../read {refs} carries, a format value.
const DirectoryStreamReadCount = 64

var (
	// No DirectoryCards is bound yet: nothing was read or written.
	ErrDirectoryCardsUnavailable = errors.New("directory cards unavailable")
	// The network has no directory: a personal network, or a team whose directory does not exist yet
	// (plan-RECORD-small-readings #8). Tools answer FAILED_PRECONDITION naming which.
	ErrDirectoryNone = errors.New("network has no team directory")
	// This sidecar no longer reads the directory: its copy is deleted (§5.9).
	ErrDirectoryReadLost = errors.New("directory read lost")
	// This client writes nothing: the page Worker is read_only (§16.11's console row).
	ErrDirectoryReadOnly = errors.New("directory client is read_only")
	// A lease on anything but a notice prefix or path: readers poll the cards ref and never lease it (D-MCP-31).
	ErrDirectoryLeaseRefused = errors.New("directory lease refused")
)

// What a ref of the directory's repo is.
type DirectoryRefKind int

const (
	// A writer's own record-class stream (§11.8).
	DirectoryRefStream DirectoryRefKind = iota + 1
	// The shared cards ref, file mode (§16.11).
	DirectoryRefCards
	// The erasure ref (§11.12).
	DirectoryRefErasure
	// Any other: ur/index, a deposit ref.
	DirectoryRefOther
)

// One ref as GET .../refs lists it.
type DirectoryRef struct {
	Kind DirectoryRefKind
	// A stream's writer; zero for any other ref.
	WriterSidecarId Id
	// Its newest committed version.
	Version uint64
	// The push sequence value its last commit raised (§11.10), which moved_after compares.
	Sequence uint64
}

// GET .../refs[?moved_after=]'s answer.
type DirectoryRefListing struct {
	// The repo's push sequence now: the next sync's moved_after.
	Sequence uint64
	// Every ref is listed: no moved_after, a value from before the sequence's restart, or a ref the cache lacks.
	All  bool
	Refs []*DirectoryRef
}

// One stream of a POST .../read {refs}: its writer and the version this reader holds.
type DirectoryStreamRead struct {
	WriterSidecarId Id
	PinVersion      uint64
}

// One committed push of a stream with its slot's live rows, as the read carries them (§11.9's streams row).
type DirectoryStreamVersion struct {
	Version *RecordStreamVersion
	Slot    *RecordSlot
}

// What a read answered for one stream.
type DirectoryStreamVersions struct {
	WriterSidecarId Id
	// The stream's head.
	HeadVersion uint64
	// After the pin, oldest first, within the read's frame.
	Versions []*DirectoryStreamVersion
	// The stream holds more past the frame: read again after the last version given.
	More bool
	// The pin is older than the window: the first version the read could not give, which GET .../log pages.
	Behind uint64
}

// One file of the cards ref as a statement left it.
type DirectoryCardFile struct {
	// q/<h>/<tgt>/<rid> at M6 (directory_format.go); d/ and r/ from format 2.
	Path string
	// The path's version.
	Version uint64
	// The statement removed it: no content.
	Removed bool
	// The file's plaintext, which the binding opened.
	Content []byte
	// The cards ref's version that wrote or removed it, its signer, the auth pin its push declared and evs's time for
	// it, which the path rules judge (§16.11).
	PushVersion     uint64
	SignerSidecarId Id
	AuthPin         *bridge.AuthPin
	TimeMillis      int64
}

// The cards ref's statements after a pin: the files they changed, in commit order.
type DirectoryCardsChanges struct {
	// The cards ref's head.
	HeadVersion uint64
	// Changes up to ThroughVersion.
	Files          []*DirectoryCardFile
	ThroughVersion uint64
	// More statements past ThroughVersion: page again from there.
	More bool
}

// A path CAS write or removal on the cards ref (§11.7).
type DirectoryCardWrite struct {
	PushId Id
	Path   string
	// The path's version the writer read, 0 for a path it read as absent; another answers PATH_CONFLICT.
	IfVersion uint64
	// The plaintext the binding seals; nil for a removal.
	Content []byte
	// §7.9's pin the push declares.
	AuthPin *bridge.AuthPin
}

// One sidecar's reach into its network's directory beyond RecordStreams (§11.9, §11.10): evs's part of the directory.
// Calls carry this sidecar's token, so evs says what it may do: reads at r, card writes at rw, never above. A refusal
// is a RecordStreamRefusal by §11.8's code. Safe for concurrent use.
type DirectoryCards interface {
	// GET .../refs?moved_after=: the refs whose last commit raised the push sequence past movedAfter; 0 lists every
	// ref, as GET .../refs does.
	Refs(ctx context.Context, repoId Id, movedAfter uint64) (*DirectoryRefListing, error)
	// POST .../read {refs}: up to DirectoryStreamReadCount streams after their pins, each answering its versions,
	// more or behind, in the order asked.
	ReadStreams(ctx context.Context, repoId Id, reads []*DirectoryStreamRead) ([]*DirectoryStreamVersions, error)
	// GET .../log?ref=&since=: one page of a stream's versions after afterVersion, for a pin older than the window.
	ReadStreamLog(ctx context.Context, repoId Id, writerSidecarId Id, afterVersion uint64) (*DirectoryStreamVersions, error)
	// The cards ref's statements after afterVersion, one page: the files they changed.
	ReadCards(ctx context.Context, repoId Id, afterVersion uint64) (*DirectoryCardsChanges, error)
	// Writes a file of the cards ref by path CAS, answering its new version.
	PutCard(ctx context.Context, repoId Id, write *DirectoryCardWrite) (uint64, error)
	// Removes a file of the cards ref by path CAS.
	RemoveCard(ctx context.Context, repoId Id, write *DirectoryCardWrite) error
	// Leases a notice prefix q/<h>/<tgt>/ or a notice's own path (§11.10): callback, with no lock held, at each
	// commit changing a file under it, a hint carrying nothing, until release. Refuses any other path.
	Lease(repoId Id, prefix string, callback func(repoId Id)) (func(), error)
}

// The directory's evs until RECORD-M3-12 and EVS1-M6-01 bind one: every call refuses, so nothing reads as synced.
type DirectoryCardsUnavailable struct{}

// Refuses.
func (self DirectoryCardsUnavailable) Refs(ctx context.Context, repoId Id, movedAfter uint64) (*DirectoryRefListing, error) {
	return nil, ErrDirectoryCardsUnavailable
}

// Refuses.
func (self DirectoryCardsUnavailable) ReadStreams(ctx context.Context, repoId Id, reads []*DirectoryStreamRead) ([]*DirectoryStreamVersions, error) {
	return nil, ErrDirectoryCardsUnavailable
}

// Refuses.
func (self DirectoryCardsUnavailable) ReadStreamLog(ctx context.Context, repoId Id, writerSidecarId Id, afterVersion uint64) (*DirectoryStreamVersions, error) {
	return nil, ErrDirectoryCardsUnavailable
}

// Refuses.
func (self DirectoryCardsUnavailable) ReadCards(ctx context.Context, repoId Id, afterVersion uint64) (*DirectoryCardsChanges, error) {
	return nil, ErrDirectoryCardsUnavailable
}

// Refuses: nothing may read as written.
func (self DirectoryCardsUnavailable) PutCard(ctx context.Context, repoId Id, write *DirectoryCardWrite) (uint64, error) {
	return 0, ErrDirectoryCardsUnavailable
}

// Refuses.
func (self DirectoryCardsUnavailable) RemoveCard(ctx context.Context, repoId Id, write *DirectoryCardWrite) error {
	return ErrDirectoryCardsUnavailable
}

// Refuses.
func (self DirectoryCardsUnavailable) Lease(repoId Id, prefix string, callback func(repoId Id)) (func(), error) {
	return nil, ErrDirectoryCardsUnavailable
}

// Whether a cards ref path may be leased: a notice prefix q/<h>/<tgt>/ or a notice's path q/<h>/<tgt>/<rid>, never the
// ref's root, d/ or r/ (D-MCP-31).
func DirectoryLeasePathAllowed(prefix string) bool {
	parts := strings.Split(prefix, "/")
	if len(parts) != 4 || parts[0] != "q" || len(parts[1]) != 2 || len(parts[2]) != 2*len(Id{}) {
		return false
	}
	return parts[3] == "" || len(parts[3]) == 2*len(Id{})
}

// Whether the cards ref path is one a sync keeps: a notice, a card or a repo file, as directory_format.go builds them.
// Anything else is no file of the directory's (§16.11's path rules' last row) and is not kept.
func directoryCardPathKept(path string) bool {
	parts := strings.Split(path, "/")
	switch {
	case len(parts) == 4 && parts[0] == "q":
		return DirectoryLeasePathAllowed(path) && parts[3] != ""
	case len(parts) == 3 && (parts[0] == "d" || parts[0] == "r"):
		return len(parts[1]) == 2 && len(parts[2]) == 2*len(Id{})
	}
	return false
}

// A refusal that ends this sidecar's read: evs no longer lets it read the directory.
func directoryReadRefused(err error) bool {
	code, ok := RecordStreamRefusalCode(err)
	return ok && (code == protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE || code == protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND)
}

// One sync of the directory: see the file's header.
func (self *DirectoryClient) Sync(ctx context.Context) error {
	self.syncLock.Lock()
	defer self.syncLock.Unlock()
	directoryId, err := self.readableDirectory()
	if err != nil {
		return err
	}
	if err := self.store.Load(directoryId); err != nil {
		return err
	}
	hookKey := recordChainIdText(directoryId)
	testHookBarrier("directory.sync.before", hookKey)
	defer testHookBarrier("directory.sync.after", hookKey)
	cards := self.boundCards()
	err = self.syncFrom(ctx, cards, directoryId)
	if directoryReadRefused(err) {
		return self.loseRead(directoryId, err)
	}
	return err
}

// The cards ref, the listing and the moved streams, then the reader's verification over the store.
func (self *DirectoryClient) syncFrom(ctx context.Context, cards DirectoryCards, directoryId Id) error {
	// cards: the ref's statements after its pin, page by page, each page kept before the next is asked
	for {
		held := self.store.State().CardsVersion
		changes, err := cards.ReadCards(ctx, directoryId, held)
		if err != nil {
			return err
		}
		if err := self.store.ApplyCards(changes); err != nil {
			return err
		}
		if !changes.More || self.store.State().CardsVersion <= held {
			break
		}
	}
	state := self.store.State()

	// listing: moved since the last sync, or every ref at the day's first sync
	day := directoryUtcDay(self.clock.Now().UnixMilli())
	movedAfter := state.Sequence
	full := state.FullListingDay != day || !state.SequenceKnown
	if full {
		movedAfter = 0
	}
	listing, err := cards.Refs(ctx, directoryId, movedAfter)
	if err != nil {
		return err
	}
	reads := []*DirectoryStreamRead{}
	erasureMoved := false
	for _, ref := range listing.Refs {
		switch ref.Kind {
		case DirectoryRefStream:
			held := state.StreamVersions[ref.WriterSidecarId]
			switch {
			case held < ref.Version:
				reads = append(reads, &DirectoryStreamRead{WriterSidecarId: ref.WriterSidecarId, PinVersion: held})
			case ref.Version < held:
				// evs lists less of the stream than this copy holds: wound back (I-16), so the copy keeps what it
				// verified and alarms, as the reader does for any log (record_reader.go)
				writerId := ref.WriterSidecarId
				self.raise(SidecarRecordAlarmChainFork, directoryId, &writerId)
			}
		case DirectoryRefErasure:
			erasureMoved = erasureMoved || state.ErasureVersion < ref.Version
		}
	}
	slices.SortFunc(reads, func(a *DirectoryStreamRead, b *DirectoryStreamRead) int {
		return a.WriterSidecarId.Cmp(b.WriterSidecarId)
	})

	// streams: 64 to a request; a stream past the frame joins the next request, one behind the window pages the log
	for 0 < len(reads) {
		batch := reads[:min(len(reads), DirectoryStreamReadCount)]
		reads = reads[len(batch):]
		results, err := cards.ReadStreams(ctx, directoryId, batch)
		if err != nil {
			return err
		}
		for _, result := range results {
			if result == nil {
				continue
			}
			if 0 < result.Behind {
				if err := self.pageStreamLog(ctx, cards, directoryId, result.WriterSidecarId); err != nil {
					return err
				}
				continue
			}
			if err := self.store.AppendStream(result.WriterSidecarId, result.Versions); err != nil {
				return err
			}
			if result.More {
				reads = append(reads, &DirectoryStreamRead{WriterSidecarId: result.WriterSidecarId, PinVersion: self.store.State().StreamVersions[result.WriterSidecarId]})
			}
		}
	}

	// verify what the store holds, with no request but the erasure ref's when it moved
	self.adapter.setErasureMoved(erasureMoved)
	if err := self.reader.Sync(ctx, directoryId); err != nil {
		return err
	}
	return self.store.FinishSync(listing.Sequence, full, day)
}

// GET .../log for a stream whose pin is older than the window, page by page until it reaches the head.
func (self *DirectoryClient) pageStreamLog(ctx context.Context, cards DirectoryCards, directoryId Id, writerSidecarId Id) error {
	for {
		held := self.store.State().StreamVersions[writerSidecarId]
		page, err := cards.ReadStreamLog(ctx, directoryId, writerSidecarId, held)
		if err != nil {
			return err
		}
		if err := self.store.AppendStream(writerSidecarId, page.Versions); err != nil {
			return err
		}
		reached := self.store.State().StreamVersions[writerSidecarId]
		if !page.More || reached <= held || page.HeadVersion <= reached {
			return nil
		}
	}
}

// Days since 1970-01-01 in UTC, the daily listing's clock.
func directoryUtcDay(millis int64) int64 {
	return millis / (24 * 60 * 60 * 1000)
}

// RecordStreams over the directory's store, for its reader: the streams a sync kept, their slots as the reads carried
// them, and the erasure ref through the bound RecordStreams, read only when the listing showed it moved. It writes
// nothing and asks evs nothing else, so verifying costs no request (§16.11's sync row). Safe for concurrent use.
type directoryStreams struct {
	store   *DirectoryStore
	streams func() RecordStreams

	stateLock    sync.Mutex
	erasureMoved bool
}

// Whether the next reader sync reads the erasure ref.
func (self *directoryStreams) setErasureMoved(moved bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.erasureMoved = moved
}

// Refuses: the reader writes nothing.
func (self *directoryStreams) Append(ctx context.Context, repoId Id, push *RecordStreamPush) (*RecordStreamCommit, error) {
	return nil, ErrDirectoryReadOnly
}

// The streams the store holds.
func (self *directoryStreams) Streams(ctx context.Context, repoId Id) ([]*RecordStreamHead, error) {
	heads := []*RecordStreamHead{}
	for writerId, version := range self.store.State().StreamVersions {
		heads = append(heads, &RecordStreamHead{SidecarId: writerId, Version: version})
	}
	slices.SortFunc(heads, func(a *RecordStreamHead, b *RecordStreamHead) int { return a.SidecarId.Cmp(b.SidecarId) })
	return heads, nil
}

// The kept versions after afterVersion.
func (self *directoryStreams) ReadStream(ctx context.Context, repoId Id, writerSidecarId Id, afterVersion uint64) ([]*RecordStreamVersion, error) {
	versions, err := self.store.StreamVersions(writerSidecarId, afterVersion)
	if err != nil {
		return nil, err
	}
	recordVersions := make([]*RecordStreamVersion, 0, len(versions))
	for _, version := range versions {
		recordVersions = append(recordVersions, version.Version)
	}
	return recordVersions, nil
}

// The slot as the read that carried its push kept it.
func (self *directoryStreams) ReadSlot(ctx context.Context, repoId Id, slotId Id) (*RecordSlot, error) {
	slot, err := self.store.Slot(slotId)
	if err != nil {
		return nil, err
	}
	if slot == nil {
		return nil, &RecordStreamRefusal{Code: protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND}
	}
	return slot, nil
}

// Refuses.
func (self *directoryStreams) Deposit(ctx context.Context, repoId Id, deposit *RecordStreamDeposit) (*RecordStreamCommit, error) {
	return nil, ErrDirectoryReadOnly
}

// None: the directory takes no deposit.
func (self *directoryStreams) DepositRefs(ctx context.Context, repoId Id) ([]*RecordStreamHead, error) {
	return []*RecordStreamHead{}, nil
}

// None.
func (self *directoryStreams) ReadDeposits(ctx context.Context, repoId Id, depositorSidecarId Id) ([]*RecordStreamDepositVersion, error) {
	return []*RecordStreamDepositVersion{}, nil
}

// Refuses.
func (self *directoryStreams) Consume(ctx context.Context, repoId Id, consume *RecordStreamConsume) (*RecordStreamCommit, error) {
	return nil, ErrDirectoryReadOnly
}

// Refuses: an erasure is the erasure runner's (RECORD-M6-20), never the sync's.
func (self *directoryStreams) Erase(ctx context.Context, repoId Id, erase *RecordStreamErase) (*RecordStreamCommit, error) {
	return nil, ErrDirectoryReadOnly
}

// The erasure ref past afterVersion through the bound streams, only when the listing showed it moved.
func (self *directoryStreams) ReadErasures(ctx context.Context, repoId Id, afterVersion uint64) ([]*RecordStreamErasure, error) {
	moved := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.erasureMoved
	}()
	if !moved {
		return []*RecordStreamErasure{}, nil
	}
	erasures, err := self.streams().ReadErasures(ctx, repoId, afterVersion)
	if err != nil {
		return nil, err
	}
	for _, erasure := range erasures {
		if err := self.store.NoteErasureVersion(erasure.Version); err != nil {
			return nil, err
		}
	}
	return erasures, nil
}

// Never fires: the directory's hints are its leases' (DirectoryClient.Lease).
func (self *directoryStreams) Subscribe(repoId Id, callback func(repoId Id)) func() {
	return func() {}
}
