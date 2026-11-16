//go:build !ios_extension

// A drop's version walk (DESIGN-DETAILS 10.2.4's versions row; EVS2-M10-20): a path's versions on a ref, newest first,
// from History's verified walk, page by page within the working set, so the list is the signer's own enumeration and
// never a count or a hash evs supplied (QD-705).
//
//	pages    History answers at most HistoryVersionCount versions a call; the walk asks again below the last one
//	         until a creation's earlier life, or version 1
//	lives    a creation's version is one past the removal below it (versions never restart, I-EVS-8), so the version
//	         below a creation is the removal of the path's earlier life. That life shares the lineage's token path
//	         when its removal committed in the creation's epoch, and its versions are walked and listed too; one whose
//	         removal is in an older epoch was removed before a cut-over, another lineage, and the walk stops
//	budget   a head-mode device (one holding no local tier) walks at most HeadDropFetchByteCount, counted at
//	         StatementMaxByteCount a version, past which it answers ErrEvsDropTooLarge naming `ur history drop` on a
//	         device that mirrors the repo; a device with a local tier walks as far as History goes
//
// On every leg but ios_extension.

package sidecar

import (
	"context"
	"fmt"
)

// One path's walked versions, newest first.
type evsDropWalk struct {
	versions []*EvsHistoryVersion
}

// Walks path on refName: see the file header.
func (self *EvsRepo) dropWalk(ctx context.Context, refName []byte, path string) (*evsDropWalk, error) {
	walk := &evsDropWalk{}
	headMode := func() bool {
		self.client.stateLock.Lock()
		defer self.client.stateLock.Unlock()
		return self.client.localTier == nil
	}()
	budget := self.client.settings.HeadDropFetchByteCount
	versionCost := int64(DefaultEvsFormatSettings().StatementMaxByteCount)
	spent := int64(0)
	version := uint64(0)
	for {
		history, err := self.History(ctx, &EvsReadArgs{RefName: refName, Path: path, Version: version, Fresh: version == 0})
		if err != nil {
			return nil, err
		}
		if len(history.Versions) == 0 {
			break
		}
		first := history.Versions[0]
		if 0 < len(walk.versions) {
			last := walk.versions[len(walk.versions)-1]
			// below a creation: the earlier life's removal, which joins the lineage only in the creation's epoch
			if first.Removed && first.Epoch != last.Epoch {
				break
			}
		}
		walk.versions = append(walk.versions, history.Versions...)
		if headMode {
			spent += int64(len(history.Versions)) * versionCost
			if budget < spent {
				return nil, fmt.Errorf("%w: past %d bytes of history on this device; run ur history drop on a device that mirrors the repo", ErrEvsDropTooLarge, budget)
			}
		}
		oldest := walk.versions[len(walk.versions)-1]
		if oldest.Version <= 1 {
			break
		}
		version = oldest.Version - 1
	}
	return walk, nil
}
