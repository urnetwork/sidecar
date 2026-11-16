//go:build !ios_extension

// A drop's version walk (DESIGN-DETAILS 10.2.4's versions row; EVS2-M10-20): a path's versions on a ref, newest first,
// from History's verified walk, page by page within the working set, so the list is the signer's own enumeration and
// never a count or a hash evs supplied (QD-705).
//
//	pages    History answers at most HistoryVersionCount versions a call; the walk asks again below the last one
//	         until version 1, or until nothing stands at the number below it
//	lives    History follows each version's prev pointers, so a creation over a standing removal walks on into the
//	         life that removal ended. That life shares the lineage's token path when its removal committed in the
//	         creation's epoch, and its versions are walked and listed too; one whose removal is in an older epoch was
//	         removed before a cut-over, another lineage, and the walk stops. A creation with no removal standing
//	         under it took max(b, m) + 1 (§11.6's version, I-EVS-8), which may be past 1 with nothing below it: evs
//	         answers the number below absent, and the walk ends there. A walk that misses a version evs holds, as
//	         one cut at a page's end between a creation and the removal it names, leaves a list the dry run answers
//	         list_match false, which stops the command (10.2.4's head-mode signer)
//	budget   a head-mode device (one holding no local tier) walks at most HeadDropFetchByteCount, counted at
//	         StatementMaxByteCount a version, past which it answers ErrEvsDropTooLarge naming `ur history drop` on a
//	         device that mirrors the repo; a device with a local tier walks as far as History goes
//
// On every leg but ios_extension.

package sidecar

import (
	"context"
	"errors"
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
		if 0 < version && errors.Is(err, ErrEvsPathAbsent) {
			// nothing at the number below the oldest version walked: the path's first creation (see the file header)
			break
		}
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
