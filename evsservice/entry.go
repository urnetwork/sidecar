// Index entries (§11.7's index entries row, evs-11): idx/<repo>/<ref>/<p>/<t1>/.../<tn>.e, a cache of each path's
// committed versions in path epoch p, folded from committed pushes, whose push records hold every one. An entry holds
// a file's up to four folded EvsEntryVersions, newest first, all but the newest with inline records elided; or a
// directory's folded name table as of the newest delta applied (names_through); and a removed path's marker, which a
// fold sets only over an older version, and a dropped path's drop mark (format 2, which format 1 keeps). idx/ decides
// no outcome: the head and its window do, by §11.7's newest rule (newest.go).
//
// While the head lists source epochs, an entry's state rides in object metadata (plan-EVS1-entry-state-metadata,
// decided): the key entry-state, its value carried:<source epoch>, fresh or removed, read by HEAD; every other
// family and every entry written while the head lists no source carries none.
//
// ParseEvsIndexEntry is the decode evs runs before it uses an entry it read, so bytes a fault or an attacker with the
// bucket left there fail before use: §22.6's index-entry fuzz target. A reader checks what evs serves against its
// statements regardless (§11.9).

package evsservice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// §11.8's bound on an entry.
const EvsIndexEntryMaxByteCount = 512 * 1024

// The most folded versions an entry keeps (§11.7's holds row).
const evsIndexEntryMaxVersionCount = 4

// The object metadata key an entry's state rides under (plan-EVS1-entry-state-metadata).
const EvsEntryStateMetadataKey = "entry-state"

// The state values, and carried's prefix.
const (
	evsEntryStateCarriedPrefix = "carried:"
	evsEntryStateFreshValue    = "fresh"
	evsEntryStateRemovedValue  = "removed"
)

// An entry's state while its head lists sources (§11.7's epochs row).
type EvsEntryState int

const (
	// No state: written while the head listed no source, or no entry at all.
	EvsEntryStateNone EvsEntryState = iota
	// Carried from a source epoch, keeping that source's folded versions and drop mark.
	EvsEntryStateCarried
	// New to the current epoch, a re-creation replacing a marker and carrying nothing.
	EvsEntryStateFresh
	// Removed: its marker stands.
	EvsEntryStateRemoved
)

// An entry's state and, when carried, its source epoch.
type EvsEntryStateValue struct {
	State EvsEntryState
	Epoch uint64
}

// An entry whose bytes or state break their shape: a fault that alarms, never an entry to use.
var ErrEvsIndexEntryInvalid = errors.New("evs index entry invalid")

// The state an entry's metadata holds: none for no entry-state key; ErrEvsIndexEntryInvalid for a value that is not
// carried:<decimal>, fresh or removed.
func ParseEvsEntryState(metadata map[string]string) (EvsEntryStateValue, error) {
	value, ok := metadata[EvsEntryStateMetadataKey]
	if !ok {
		return EvsEntryStateValue{}, nil
	}
	switch {
	case value == evsEntryStateFreshValue:
		return EvsEntryStateValue{State: EvsEntryStateFresh}, nil
	case value == evsEntryStateRemovedValue:
		return EvsEntryStateValue{State: EvsEntryStateRemoved}, nil
	}
	epochText, ok := strings.CutPrefix(value, evsEntryStateCarriedPrefix)
	if ok {
		epoch, err := strconv.ParseUint(epochText, 10, 64)
		if err == nil && strconv.FormatUint(epoch, 10) == epochText && 0 < epoch {
			return EvsEntryStateValue{State: EvsEntryStateCarried, Epoch: epoch}, nil
		}
	}
	return EvsEntryStateValue{}, fmt.Errorf("%w: entry-state %q", ErrEvsIndexEntryInvalid, value)
}

// The metadata a write carries for the state: nil for none.
func (self EvsEntryStateValue) Metadata() map[string]string {
	switch self.State {
	case EvsEntryStateCarried:
		return map[string]string{EvsEntryStateMetadataKey: evsEntryStateCarriedPrefix + strconv.FormatUint(self.Epoch, 10)}
	case EvsEntryStateFresh:
		return map[string]string{EvsEntryStateMetadataKey: evsEntryStateFreshValue}
	case EvsEntryStateRemoved:
		return map[string]string{EvsEntryStateMetadataKey: evsEntryStateRemovedValue}
	}
	return nil
}

// An entry's bytes held to its shape: its bound; a file's at most four versions, newest first by commit version and
// path version, each of its push, the newest whole and its entry version parsing as one; or a directory's table of
// rows with a token, a kind and a sealed name, removing none; never both; a marker above every folded version; a
// drop mark kept as read.
func ParseEvsIndexEntry(entryBytes []byte) (*protocol.EvsIndexEntry, error) {
	if EvsIndexEntryMaxByteCount < len(entryBytes) {
		return nil, fmt.Errorf("%w: %d bytes", ErrEvsIndexEntryInvalid, len(entryBytes))
	}
	entry := &protocol.EvsIndexEntry{}
	if err := proto.Unmarshal(entryBytes, entry); err != nil {
		return nil, fmt.Errorf("%w: does not parse", ErrEvsIndexEntryInvalid)
	}
	refuse := func(format string, args ...any) (*protocol.EvsIndexEntry, error) {
		return nil, fmt.Errorf("%w: %s", ErrEvsIndexEntryInvalid, fmt.Sprintf(format, args...))
	}
	versions := entry.GetVersions()
	if evsIndexEntryMaxVersionCount < len(versions) {
		return refuse("%d versions", len(versions))
	}
	if 0 < len(versions) && entry.GetNames() != nil {
		return refuse("a file's versions beside a directory's table")
	}
	var newerCommit, newerPath uint64
	for i, version := range versions {
		if len(version.GetPushId()) != 16 || version.GetCommitVersion() == 0 {
			return refuse("version %d names no push or commit", i)
		}
		if 0 < i && newerCommit <= version.GetCommitVersion() {
			return refuse("versions not newest first")
		}
		if i == 0 && version.GetElided() {
			return refuse("the newest version elided")
		}
		entryVersion, err := parseEvsEntryVersion(version.GetEntryVersion())
		if err != nil {
			return refuse("version %d: %v", i, err)
		}
		if !bytes.Equal(entryVersion.GetPushId(), version.GetPushId()) {
			return refuse("version %d's entry version names another push", i)
		}
		if 0 < i && newerPath <= entryVersion.GetVersion() {
			return refuse("path versions not newest first")
		}
		newerCommit, newerPath = version.GetCommitVersion(), entryVersion.GetVersion()
	}
	if names := entry.GetNames(); names != nil {
		if len(names.GetRemovedTokens()) != 0 {
			return refuse("a folded table removing names")
		}
		for i, name := range names.GetNames() {
			if len(name.GetToken()) != sidecar.EvsTokenByteCount || len(name.GetSealedName()) == 0 {
				return refuse("name %d", i)
			}
			if name.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE) && name.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY) {
				return refuse("name %d of kind %d", i, name.GetKind())
			}
		}
	}
	if marker := entry.GetMarker(); marker != nil {
		if len(marker.GetPushId()) != 16 || marker.GetRemovalVersion() == 0 || marker.GetPathVersion() == 0 {
			return refuse("a marker naming no push, removal or version")
		}
		if 0 < len(versions) && marker.GetRemovalVersion() <= versions[0].GetCommitVersion() {
			return refuse("a marker below its folded versions")
		}
		if 0 < len(versions) && marker.GetPathVersion() <= newestPathVersion(versions) {
			return refuse("a marker's version not past the path's last")
		}
	}
	return entry, nil
}

// An entry version's bytes parsed, a version and a push id present.
func parseEvsEntryVersion(entryVersionBytes []byte) (*protocol.EvsEntryVersion, error) {
	entryVersion := &protocol.EvsEntryVersion{}
	if err := proto.Unmarshal(entryVersionBytes, entryVersion); err != nil {
		return nil, fmt.Errorf("an entry version that does not parse")
	}
	if entryVersion.GetVersion() == 0 || len(entryVersion.GetPushId()) != 16 {
		return nil, fmt.Errorf("an entry version with no version or push")
	}
	return entryVersion, nil
}

// The path version of an entry's newest folded version, which ParseEvsIndexEntry has held to parse.
func newestPathVersion(versions []*protocol.EvsIndexVersion) uint64 {
	if len(versions) == 0 {
		return 0
	}
	entryVersion, err := parseEvsEntryVersion(versions[0].GetEntryVersion())
	if err != nil {
		return 0
	}
	return entryVersion.GetVersion()
}

// One path's entry as a read found it.
type EvsEntryRead struct {
	// The path in the head's current epoch, which the newest rule scans the window by.
	TokenPath sidecar.EvsTokenPath
	// The path epoch whose idx/ it was read in: the current one, or a source's (sources.go).
	Epoch uint64
	// nil when the key 404s.
	Entry *protocol.EvsIndexEntry
	// What the next write's If-Match names, empty when absent.
	Etag  string
	State EvsEntryStateValue
	// h: the folded_through of the head read before this entry, which the newest rule combines it with and only
	// with (§11.7's newest row). A rerun keeps it.
	FoldedThrough uint64
}

// Whether the read found no entry.
func (self *EvsEntryRead) Absent() bool {
	return self.Entry == nil
}

// One GET of a path's entry in epoch, after a head whose folded_through was foldedThrough. A 404 is an absent
// entry. Bytes or a state that break their shape are ErrEvsIndexEntryInvalid.
func ReadEntry(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, epoch uint64, tokenPath sidecar.EvsTokenPath, foldedThrough uint64) (*EvsEntryRead, error) {
	read := &EvsEntryRead{TokenPath: tokenPath, Epoch: epoch, FoldedThrough: foldedThrough}
	barrierKey := barrierRefKey(repoId, refId)
	testHookBarrier(BarrierEntryReadBefore, barrierKey)
	object, err := cluster.Get(ctx, IndexEntryKey(repoId, refId, epoch, tokenPath))
	testHookBarrier(BarrierEntryReadAfter, barrierKey)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return read, nil
	}
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	entryBytes, err := io.ReadAll(io.LimitReader(object.Body, EvsIndexEntryMaxByteCount+1))
	if err != nil {
		return nil, err
	}
	entry, err := ParseEvsIndexEntry(entryBytes)
	if err != nil {
		return nil, err
	}
	state, err := ParseEvsEntryState(object.Metadata)
	if err != nil {
		return nil, err
	}
	read.Entry = entry
	read.Etag = object.Etag
	read.State = state
	return read, nil
}

// One HEAD of a path's entry in epoch: its state, and whether it exists (§11.6's read row: a prefix check stays a
// HEAD).
func HeadEntryState(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, epoch uint64, tokenPath sidecar.EvsTokenPath) (EvsEntryStateValue, bool, error) {
	info, err := cluster.Head(ctx, IndexEntryKey(repoId, refId, epoch, tokenPath))
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return EvsEntryStateValue{}, false, nil
	}
	if err != nil {
		return EvsEntryStateValue{}, false, err
	}
	state, err := ParseEvsEntryState(info.Metadata)
	if err != nil {
		return EvsEntryStateValue{}, true, err
	}
	return state, true, nil
}

// Writes entry for a path in epoch: If-Match prior's ETag, or If-None-Match when prior found none, with state in its
// metadata (none while the head lists no source). Folds and copies call this (§11.7's fold row); ctx carries their
// class and §11.7's stale deadline. ErrBlobPrecondition means another write came first, and the caller reads again
// and merges.
func PutEntry(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, epoch uint64, tokenPath sidecar.EvsTokenPath, prior *EvsEntryRead, entry *protocol.EvsIndexEntry, state EvsEntryStateValue) (string, error) {
	entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
	if err != nil {
		return "", err
	}
	if _, err := ParseEvsIndexEntry(entryBytes); err != nil {
		return "", err
	}
	if len(tokenPath) == 0 || sidecar.EvsTokenPathMaxLength < len(tokenPath) {
		return "", fmt.Errorf("%w: a path of %d components", ErrEvsIndexEntryInvalid, len(tokenPath))
	}
	var options *sidecar.BlobPutOptions
	if metadata := state.Metadata(); metadata != nil {
		options = &sidecar.BlobPutOptions{Metadata: metadata}
	}
	key := IndexEntryKey(repoId, refId, epoch, tokenPath)
	if prior == nil || prior.Absent() {
		return cluster.PutIfNoneMatch(ctx, key, entryBytes, options)
	}
	return cluster.PutIfMatch(ctx, key, prior.Etag, entryBytes, options)
}
