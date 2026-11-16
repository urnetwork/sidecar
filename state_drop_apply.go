//go:build !ios_extension

// Executed drops on a device (CORE-M10-04; D-CORE-19, FI-27, FS-89; §5.9's dropped row, §11.7's rule and states rows,
// §11.11's Drops; owner decisions 173, 183, 184): applying a drop whose window passed with no cancel, evs not reporting
// it refused, deletes what only its listed versions name wherever this device holds it.
//
//	window   ApplyExecutedDrop applies nothing before the DROP's not_before_ms by this device's clock, nor a drop a
//	         committed cancel names or evs reports refused (ErrSidecarDropNotExecuted); a drop whose deletions a hold
//	         defers on evs is executed here all the same, and reads done (owner decision 184)
//	mirror   the repo's sealed mirror loses the segment and slot copies listed versions name
//	cache    the index cache: the repo's open searches and remote cursors end (DESIGN-DETAILS 7.2.5, 7.2.7), its
//	         retained buckets go, as at an ERASE, since no rewrite reaches a file the ref no longer lists, the index file
//	         versions the DROP's rewrites replaced go with their derived data, and the local layer's entries of listed
//	         versions go, its sealed copy written again
//	holders  every decrypted copy kept elsewhere, through the holders registered with AddDropHolder: §16.7's restore
//	         points (MCP-M10-01's restore_drop.go, since the root cannot import mcp/), mail and record caches
//	keep     statements and served entry versions are never among what a drop names here, and an id or content a version
//	         no executed drop lists also names stays, whatever a listed version names: the kept head's re-cited chunk
//	         set, renames, copies on other refs, reverts (§11.7's rule row). Live answers that, and what it cannot
//	         answer for stays, so a doubt keeps content rather than deleting it (FI-27)
//	offline  a device offline at the drop applies it when it syncs: its reader calls this then (EVS2-M10-22), and a
//	         second call for a drop applied deletes nothing more
//
// history_drop's plumbing is here too: SidecarHistoryDrop, its event, and the raise a Sidecar and its EvsClient give the
// drop reader (EVS2-M10-22), which raises one at each state it reads: pending, cancelled, executing, done, refused,
// invalid.
//
// Not here: the inline records of the mirror's push records that only listed versions name, which the mirror's
// statement-only rule elides (EVS2-M10-13): until a holder elides them they stay, counted in the result. Barrier
// sidecar.drop.applied, keyed <repo>/<drop>, once every deletion ran. Nothing of a path is logged (I-13). Safe for
// concurrent use.

package sidecar

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// The drop is not executed by this device's clock and evs's word: its window has not passed, a committed cancel
	// names it, or evs reports it refused. Nothing was deleted.
	ErrSidecarDropNotExecuted = errors.New("drop: not executed, so nothing was deleted")
	// A drop, or a drop's state, that is not well formed.
	ErrSidecarDropArgs = errors.New("drop: invalid arguments")
)

// What a listed version names that this device may hold a copy of.
type SidecarDropObjectKind int

const (
	// A segment, by its id, its SHA-256.
	SidecarDropSegment SidecarDropObjectKind = 1
	// A slot object, by its id.
	SidecarDropSlot SidecarDropObjectKind = 2
	// A version's plaintext, by its SHA-256, its entry version's content_sha256: a decrypted copy holding those bytes.
	SidecarDropContent SidecarDropObjectKind = 3
)

// One thing a listed version names, as Live is asked about it.
type SidecarDropObject struct {
	Kind SidecarDropObjectKind
	Id   []byte
}

// One listed version this device holds anything of, and what it names, as the drop's reader found it (EVS2-M10-22).
type SidecarDroppedVersion struct {
	// The path as this device names it. Never logged (I-13).
	Path    string
	Version uint64
	// Its entry version's content_sha256: a decrypted copy holding bytes of this hash is a copy of it.
	ContentSha256 [sha256.Size]byte
	// The segments its chain names, by id, and the slots it names.
	SegmentIds [][]byte
	SlotIds    []Id
	// Its chain's inline records, in push records of the mirror.
	InlineRecords []SidecarDroppedInline
	// The index ref holding its documents (its own ref's .ur-index/), and their doc keys, one a chunk, whose local-layer
	// entries go. Zero where it was never indexed.
	IndexRefId Id
	DocKeys    [][indexIdByteCount]byte
}

// An inline record of a listed version: the push record holding it and its place there.
type SidecarDroppedInline struct {
	PushId Id
	// The record's part.
	Part uint32
	// The record's index among its part's inline records.
	Index uint32
}

// One executed drop as this device applies it (§11.7's rule row, §11.11's Drops; D-CORE-19): what its reader's Covers
// found over what this device holds (EVS2-M10-22).
type SidecarExecutedDrop struct {
	RepoId Id
	// The ref the DROP is on.
	RefId  Id
	DropId Id
	// The DROP's not_before_ms: nothing applies before it by this device's clock.
	NotBefore time.Time
	// A committed cancel names the drop, or evs reports it refused: nothing applies (§11.7's states row).
	Cancelled bool
	Refused   bool
	// The listed versions this device holds anything of.
	Versions []*SidecarDroppedVersion
	// The index file versions the DROP's index rewrites, or the backfill that made them, replaced, which held listed
	// versions' postings (§11.14's drop row): any copy in the index cache goes with its derived data.
	IndexReplaced []SearchCacheKey
	// The repo's sealed mirror on this device (EvsClient.Mirror), nil where it mirrors none.
	Mirror *EvsMirrorStore
	// Whether a version no executed drop lists names object, so it stays (§11.7's rule row): the kept head's chunk set, a
	// rename, a copy on another ref, a revert. Required: a drop with no way to keep what is live deletes nothing. An
	// error keeps the object.
	Live func(ctx context.Context, object SidecarDropObject) (bool, error)
}

// Whether the drop is executed at now on this device: its window passed, by this device's clock, with no cancel, and
// evs does not report it refused. A drop a hold defers on evs is executed (owner decision 184).
func (self *SidecarExecutedDrop) Executed(now time.Time) bool {
	return !self.Cancelled && !self.Refused && !now.Before(self.NotBefore)
}

// Whether a decrypted copy holding bytes of SHA-256 sum is a copy of a listed version whose content no live version
// shares: what a holder deletes. An error is Live's, and the holder keeps the copy.
func (self *SidecarExecutedDrop) DroppedContent(ctx context.Context, sum [sha256.Size]byte) (bool, error) {
	listed := slices.ContainsFunc(self.Versions, func(version *SidecarDroppedVersion) bool {
		return version.ContentSha256 == sum
	})
	if !listed {
		return false, nil
	}
	live, err := self.Live(ctx, SidecarDropObject{Kind: SidecarDropContent, Id: sum[:]})
	if err != nil {
		return false, err
	}
	return !live, nil
}

// The well-formed part of the drop.
func (self *SidecarExecutedDrop) check() error {
	switch {
	case self.RepoId == (Id{}) || self.RefId == (Id{}) || self.DropId == (Id{}):
		return fmt.Errorf("%w: a drop of no repo, ref or id", ErrSidecarDropArgs)
	case self.Live == nil:
		return fmt.Errorf("%w: a drop with no liveness check deletes nothing", ErrSidecarDropArgs)
	case self.Mirror != nil && self.Mirror.RepoId() != self.RepoId:
		return fmt.Errorf("%w: another repo's mirror", ErrSidecarDropArgs)
	}
	for _, version := range self.Versions {
		if version == nil || version.Version == 0 {
			return fmt.Errorf("%w: a listed version of no version", ErrSidecarDropArgs)
		}
	}
	for _, key := range self.IndexReplaced {
		if key.RepoId != self.RepoId || key.check() != nil {
			return fmt.Errorf("%w: a replaced index file of another repo", ErrSidecarDropArgs)
		}
	}
	return nil
}

// What applying a drop deleted and kept.
type SidecarDropApplied struct {
	// Copies the mirror held that went.
	SegmentCount int
	SlotCount    int
	// Index file versions the cache held that went, with their derived data.
	CacheFileCount int
	// Ids and contents kept because a live version names them too, or Live could not answer.
	KeptCount int
	// Inline records left in the mirror's push records for its statement-only rule (EVS2-M10-13).
	InlineCount int
}

// What keeps copies of a repo's content on this device beside its mirror and its index cache, and deletes a dropped
// version's (D-CORE-19): §16.7's restore points (MCP-M10-01's restore_drop.go, since the root cannot import mcp/), mail
// and record caches. Registered with Sidecar.AddDropHolder. Safe for concurrent use.
type SidecarDropHolder interface {
	// Deletes every copy it keeps of the drop's listed versions whose content no live version shares
	// (SidecarExecutedDrop.DroppedContent). Called again at a later sync for a drop it applied, so idempotent.
	ApplyExecutedDrop(ctx context.Context, drop *SidecarExecutedDrop) error
}

// A Sidecar's drop holders, in the order they were added.
type sidecarDrops struct {
	stateLock sync.Mutex
	holders   map[uint64]SidecarDropHolder
	nextId    uint64
}

// The Sidecar's drop holders, made on first use.
func (self *Sidecar) dropsOf() *sidecarDrops {
	if drops, ok := self.drops.Load().(*sidecarDrops); ok {
		return drops
	}
	self.drops.CompareAndSwap(nil, &sidecarDrops{holders: map[uint64]SidecarDropHolder{}})
	return self.drops.Load().(*sidecarDrops)
}

// Adds holder, which every drop applied from now on reaches; the answer removes it.
func (self *Sidecar) AddDropHolder(holder SidecarDropHolder) (func(), error) {
	if holder == nil {
		return nil, fmt.Errorf("%w: no holder", ErrSidecarDropArgs)
	}
	drops := self.dropsOf()
	drops.stateLock.Lock()
	defer drops.stateLock.Unlock()
	drops.nextId += 1
	holderId := drops.nextId
	drops.holders[holderId] = holder
	var once sync.Once
	return func() {
		once.Do(func() {
			drops.stateLock.Lock()
			defer drops.stateLock.Unlock()
			delete(drops.holders, holderId)
		})
	}, nil
}

// The holders added, oldest first.
func (self *sidecarDrops) list() []SidecarDropHolder {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	holderIds := make([]uint64, 0, len(self.holders))
	for holderId := range self.holders {
		holderIds = append(holderIds, holderId)
	}
	slices.Sort(holderIds)
	holders := make([]SidecarDropHolder, 0, len(holderIds))
	for _, holderId := range holderIds {
		holders = append(holders, self.holders[holderId])
	}
	return holders
}

// Applies an executed drop on this device (D-CORE-19): deletes what only its listed versions name from the repo's
// sealed mirror, from the index cache, and through every holder, keeping whatever Live says a live version names. A
// drop that is not executed by this device's clock and evs's word deletes nothing: ErrSidecarDropNotExecuted. Every
// part runs whatever another answered, the answer joining their errors, and the caller applies it again at its next
// sync, which deletes only what is left.
func (self *Sidecar) ApplyExecutedDrop(ctx context.Context, drop *SidecarExecutedDrop) (*SidecarDropApplied, error) {
	if drop == nil {
		return nil, fmt.Errorf("%w: no drop", ErrSidecarDropArgs)
	}
	if err := drop.check(); err != nil {
		return nil, err
	}
	if !drop.Executed(self.clock.Now()) {
		return nil, ErrSidecarDropNotExecuted
	}
	applied := &SidecarDropApplied{}
	errs := []error{}
	if cache, err := self.SearchCache(); err != nil {
		errs = append(errs, err)
	} else {
		errs = append(errs, cache.applyDrop(ctx, drop, applied))
	}
	if drop.Mirror != nil {
		errs = append(errs, applyDropToMirror(ctx, drop, applied))
	} else {
		for _, version := range drop.Versions {
			applied.InlineCount += len(version.InlineRecords)
		}
	}
	for _, holder := range self.dropsOf().list() {
		errs = append(errs, holder.ApplyExecutedDrop(ctx, drop))
	}
	testHookBarrier("sidecar.drop.applied", drop.RepoId.String()+"/"+drop.DropId.String())
	return applied, errors.Join(errs...)
}

// Whether Live keeps object, an error keeping it too: counted kept either way.
func (self *SidecarExecutedDrop) keeps(ctx context.Context, object SidecarDropObject, applied *SidecarDropApplied) (bool, error) {
	live, err := self.Live(ctx, object)
	if err != nil || live {
		applied.KeptCount += 1
		return true, err
	}
	return false, nil
}

// Deletes from the repo's sealed mirror each segment and slot copy listed versions name that no live version names.
// Inline records stay, counted, for the mirror's statement-only rule (EVS2-M10-13).
func applyDropToMirror(ctx context.Context, drop *SidecarExecutedDrop, applied *SidecarDropApplied) error {
	errs := []error{}
	seen := map[string]bool{}
	remove := func(object SidecarDropObject, key EvsMirrorKey, count *int) {
		name := fmt.Sprintf("%d/%x", object.Kind, object.Id)
		if seen[name] {
			return
		}
		seen[name] = true
		held, err := drop.Mirror.Has(key)
		if err != nil {
			errs = append(errs, err)
			return
		}
		if !held {
			return
		}
		if kept, err := drop.keeps(ctx, object, applied); kept {
			errs = append(errs, err)
			return
		}
		if err := drop.Mirror.Remove(key); err != nil {
			errs = append(errs, err)
			return
		}
		*count += 1
	}
	for _, version := range drop.Versions {
		for _, segmentId := range version.SegmentIds {
			remove(SidecarDropObject{Kind: SidecarDropSegment, Id: segmentId}, EvsMirrorSegmentKey(segmentId), &applied.SegmentCount)
		}
		for _, slotId := range version.SlotIds {
			remove(SidecarDropObject{Kind: SidecarDropSlot, Id: slotId.Bytes()}, EvsMirrorSlotKey(slotId.Bytes()), &applied.SlotCount)
		}
		applied.InlineCount += len(version.InlineRecords)
	}
	return errors.Join(errs...)
}

// An executed drop's part in the index cache (§5.9's dropped row; DESIGN-DETAILS 7.2.5, 7.2.7): the repo's searches and
// remote cursors end, its retained buckets go, each held index file version the DROP's rewrites replaced goes with its
// derived data, and the local layer's entries of listed versions go, its sealed copy written again.
func (self *SearchCache) applyDrop(ctx context.Context, drop *SidecarExecutedDrop, applied *SidecarDropApplied) error {
	self.endRepo(drop.RepoId)
	defer self.endRepo(drop.RepoId)
	errs := []error{}
	if err := self.DropRetained(drop.RepoId); err != nil {
		errs = append(errs, err)
	}
	for _, key := range drop.IndexReplaced {
		_, held, err := self.heldFile(key)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !held {
			continue
		}
		if err := self.Remove(key); err != nil {
			errs = append(errs, err)
			continue
		}
		applied.CacheFileCount += 1
	}
	listed := map[Id]map[[indexIdByteCount]byte]uint64{}
	refIds := []Id{}
	for _, version := range drop.Versions {
		if version.IndexRefId == (Id{}) {
			continue
		}
		keys, ok := listed[version.IndexRefId]
		if !ok {
			keys = map[[indexIdByteCount]byte]uint64{}
			listed[version.IndexRefId] = keys
			refIds = append(refIds, version.IndexRefId)
		}
		for _, key := range version.DocKeys {
			keys[key] = max(keys[key], version.Version)
		}
	}
	for _, refId := range refIds {
		errs = append(errs, self.eraseLayers(ctx, drop.RepoId, refId, func(layer *SearchLocalLayer) bool {
			erased := false
			for key, through := range listed[refId] {
				erased = layer.Erase(key, through) || erased
			}
			return erased
		}))
	}
	return errors.Join(errs...)
}

// One drop's state as this device reads it (§11.7's states row), raised as history_drop (§18.5's Drops listing).
type SidecarHistoryDrop struct {
	RepoId Id
	RefId  Id
	DropId Id
	State  SidecarDropState
	// The DROP's signer: required in state invalid, which names it, and given where known.
	SignerSidecarId *Id
	// Its first listed path, as this device names it. Never logged (I-13).
	Path string
	// Its window's end (owner decision 183): required while pending.
	NotBefore time.Time
}

// The history_drop event of drop: ErrSidecarDropArgs for one of no repo, ref or drop, of a state §11.7 does not name,
// invalid with no signer, or pending with no window's end.
func newSidecarHistoryDropEvent(drop *SidecarHistoryDrop) (SidecarEvent, error) {
	if drop == nil || drop.RepoId == (Id{}) || drop.RefId == (Id{}) || drop.DropId == (Id{}) {
		return SidecarEvent{}, fmt.Errorf("%w: a drop event of no repo, ref or drop", ErrSidecarDropArgs)
	}
	switch drop.State {
	case SidecarDropPending, SidecarDropCancelled, SidecarDropExecuting, SidecarDropDone, SidecarDropRefused,
		SidecarDropInvalid:
	default:
		return SidecarEvent{}, fmt.Errorf("%w: a drop state %q", ErrSidecarDropArgs, drop.State)
	}
	if drop.State == SidecarDropInvalid && (drop.SignerSidecarId == nil || *drop.SignerSidecarId == (Id{})) {
		return SidecarEvent{}, fmt.Errorf("%w: an invalid drop names its signer", ErrSidecarDropArgs)
	}
	if drop.State == SidecarDropPending && drop.NotBefore.IsZero() {
		return SidecarEvent{}, fmt.Errorf("%w: a pending drop names its window's end", ErrSidecarDropArgs)
	}
	repoId, refId, dropId := drop.RepoId, drop.RefId, drop.DropId
	event := SidecarEvent{
		Kind: SidecarEventHistoryDrop, RepoId: &repoId, RefId: &refId, DropId: &dropId, DropState: drop.State,
		Path: drop.Path, NotBefore: drop.NotBefore,
	}
	if drop.SignerSidecarId != nil {
		signerId := *drop.SignerSidecarId
		event.SidecarId = &signerId
	}
	return event, nil
}

// evs's report of a drop (EvsDropStatus.state) as the state a device shows (§11.7's states row): a drop whose
// deletions a hold defers is reported done already (owner decision 184), and observe mode's, verified with nothing
// deleted on the server, reads done too, since D-TEST-18's mode changes only whether the server deletes. False for a
// state evs does not name.
func SidecarDropStateOf(state protocol.EvsDropState) (SidecarDropState, bool) {
	switch state {
	case protocol.EvsDropState_EVS_DROP_PENDING:
		return SidecarDropPending, true
	case protocol.EvsDropState_EVS_DROP_CANCELLED:
		return SidecarDropCancelled, true
	case protocol.EvsDropState_EVS_DROP_EXECUTING:
		return SidecarDropExecuting, true
	case protocol.EvsDropState_EVS_DROP_DONE, protocol.EvsDropState_EVS_DROP_OBSERVED:
		return SidecarDropDone, true
	case protocol.EvsDropState_EVS_DROP_REFUSED:
		return SidecarDropRefused, true
	}
	return "", false
}

// Raises history_drop for a drop whose state this device read changed.
func (self *Sidecar) raiseHistoryDrop(drop *SidecarHistoryDrop) error {
	event, err := newSidecarHistoryDropEvent(drop)
	if err != nil {
		return err
	}
	self.emitEvent(event)
	return nil
}

// Raises history_drop through the client's sink, for the drop reader, which holds the client and not its Sidecar.
func (self *EvsClient) raiseHistoryDrop(drop *SidecarHistoryDrop) error {
	event, err := newSidecarHistoryDropEvent(drop)
	if err != nil {
		return err
	}
	self.emit(event)
	return nil
}
