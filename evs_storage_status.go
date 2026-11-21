//go:build !ios_extension

// A ref's storage as `ur status` shows it (§11.7's cli row; R-EVS-26, I-13; EVS2-M10-23): its versionless files' bytes,
// its search index's bytes apart from content, and the versioned paths whose history holds most of its storage, each
// from the padded sizes its verified pushes' entry versions state: a versionless or index file's newest version's, a
// versioned file's every version's summed, so nothing is read but statements and records.
//
// The ref's whole history is walked from version 1 and verified as export walks it; the paths named are the ones this
// device can name on the head (KnownPaths), and any other is counted under an unnamed line (I-13). On every leg but
// ios_extension; only a desktop host runs it.

package sidecar

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// One ref's storage.
type EvsStorageStatus struct {
	RefId Id
	// The newest versions' record bytes of versionless files, and of the search index's files.
	VersionlessByteCount uint64
	IndexByteCount       uint64
	// The versioned paths whose history holds most, most first, at most EvsSettings.StatusPathCount.
	Paths []*EvsStoragePath
	// Versioned bytes of paths this device cannot name.
	UnnamedByteCount uint64
}

// One versioned path's history bytes.
type EvsStoragePath struct {
	// As this device names it. Never logged (I-13).
	Path      string
	ByteCount uint64
}

// The storage of refName, nil main: see the file header.
func (self *EvsRepo) StorageStatus(ctx context.Context, refName []byte) (*EvsStorageStatus, error) {
	refId, err := self.resolveRefId(ctx, refName, nil)
	if err != nil {
		return nil, err
	}
	// the read in flight from the head's ask to its pin, so a raise meanwhile keeps the chains that place it
	done := self.client.pins.beginRead(self.repoId, refId)
	defer done()
	pinned, err := self.pinnedHead(ctx, refId)
	if err != nil {
		return nil, err
	}
	head, err := self.verifiedHistory(ctx, pinned)
	if err != nil {
		return nil, err
	}
	status := &EvsStorageStatus{RefId: refId}
	type pathBytes struct {
		// the padded sizes of its versions, summed, and its newest version
		history    uint64
		newest     *protocol.EvsEntryVersion
		versioning uint32
	}
	paths := map[string]*pathBytes{}
	for _, statement := range head.Statements {
		push := statement.Statement.Push
		if push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE) != 0 {
			paths = map[string]*pathBytes{}
			continue
		}
		payload, err := self.pushContent(ctx, head, statement)
		if err != nil {
			return nil, err
		}
		for _, change := range payload.Changes {
			key := fmt.Sprint(max(1, push.GetPathEpoch()), "/", string(change.TokenPath.Bytes()))
			if !change.WritesEntry() {
				delete(paths, key)
				continue
			}
			entry := &protocol.EvsEntryVersion{}
			if err := proto.Unmarshal(change.EntryVersion, entry); err != nil || entry.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE) {
				continue
			}
			held := paths[key]
			if held == nil {
				held = &pathBytes{}
				paths[key] = held
			}
			held.newest, held.versioning = entry, entry.GetVersioning()
			held.history += entry.GetPaddedSize()
		}
	}
	known, err := self.KnownPaths(ctx, refName)
	if err != nil {
		return nil, err
	}
	keys := newEvsReadKeys(self)
	named := map[string]string{}
	for _, path := range known {
		names, err := evsPathNames(path)
		if err != nil {
			continue
		}
		epoch := evsCurrentEpoch(head.Head.GetPathEpoch())
		tokenPath, err := keys.tokenPathIn(ctx, names, epoch)
		if err != nil {
			return nil, err
		}
		named[fmt.Sprint(epoch, "/", string(tokenPath.Bytes()))] = path
	}
	versioned := []*EvsStoragePath{}
	for key, held := range paths {
		switch held.versioning {
		case uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS):
			status.VersionlessByteCount += held.newest.GetPaddedSize()
		case uint32(protocol.EvsVersioning_EVS_VERSIONING_INDEX):
			status.IndexByteCount += held.newest.GetPaddedSize()
		default:
			total := held.history
			if path, ok := named[key]; ok {
				versioned = append(versioned, &EvsStoragePath{Path: path, ByteCount: total})
			} else {
				status.UnnamedByteCount += total
			}
		}
	}
	slices.SortFunc(versioned, func(a *EvsStoragePath, b *EvsStoragePath) int {
		switch {
		case a.ByteCount != b.ByteCount && a.ByteCount < b.ByteCount:
			return 1
		case a.ByteCount != b.ByteCount:
			return -1
		}
		return strings.Compare(a.Path, b.Path)
	})
	status.Paths = versioned[:min(len(versioned), max(0, self.client.settings.StatusPathCount))]
	return status, nil
}

// `ur status`'s lines of a ref's storage, ids and the person's own path names only.
func EvsStorageStatusLines(repoId Id, status *EvsStorageStatus) []string {
	lines := []string{
		fmt.Sprintf("repo %s ref %s: %d bytes of versionless files, %d bytes of search index", repoId, status.RefId,
			status.VersionlessByteCount, status.IndexByteCount),
	}
	for _, path := range status.Paths {
		lines = append(lines, fmt.Sprintf("  %d bytes of history: %s", path.ByteCount, path.Path))
	}
	if status.UnnamedByteCount != 0 {
		lines = append(lines, fmt.Sprintf("  %d bytes of history in paths this device cannot name", status.UnnamedByteCount))
	}
	return lines
}
