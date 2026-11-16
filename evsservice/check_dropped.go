// 5h's fence on a DROP's listed versions (§11.7's fence row, §11.8's 5h; I-EVS-15, FI-27, FS-91; DESIGN-DETAILS 10.2.7;
// EVS2-M10-09), for every push from a DROP's commit on, at a format-2 instance. It tests each version the push leans
// on, W, a committed version of a ref R' that step 4 read with R''s head: each changed path's base (a write's or a
// removal's, so each path the push deletes) on the push's own ref, and each reuse source on its ref:
//
//	window   for each DROP of action 1 in the window of that head, cancelled, refused or not: its body covers W, by
//	         Covers(body, e(W), t(W), k(W)) (sidecar.EvsDropLists.Lists), 409 DROPPED
//	mark     W was read from an idx/ entry whose drop mark has k(W) < through_version: 409 DROPPED
//	seal     a seal reruns both for every part's bases and sources against heads it rereads from the cluster
//	recorded DROPPED is recorded before it is answered, on heads read from the cluster: one that rests on a head
//	         from the cache sends the attempt to step 4 again from the cluster (push.go), so a cache that shows the
//	         DROP never refuses alone
//
// e(W) and t(W) are the epoch and token path of the entry step 4 read W from, the head's current ones for a window
// version, which is all the current epoch's (9.3's W1). A folded version that a path-epoch copy carried from an older
// epoch sits in the current epoch's entry, and an honest lineage holds every epoch from the path's oldest to its
// newest (10.2.4), so it holds the entry's epoch whenever it holds W's own; the job's resolve and every reader judge
// by W's own (10.2.3, 10.2.8).
//
// A cancel lifts no fence: a later copy re-uploads. A listed version that is no longer in its ref's window and whose
// entry holds no version of it (a written boundary's replaced entry, a collected marker, a drained epoch) is not found
// by step 4 at all, which 5h's unknown segment and source rules already refuse.
//
// Package-level functions are safe for concurrent use; a PushView is read only.

package evsservice

import (
	"fmt"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// One ref's DROPs as the fence reads them: the bodies of action 1 among the bit-5 entries of the window of the head
// step 4 read of it, and whether that head came from the cache.
type EvsDropFence struct {
	Drops  []*DropBody
	Cached bool
}

// Whether a DROP of the fence covers the version of a path committed in epoch at tokenPath at path version version.
func (self *EvsDropFence) covers(epoch uint64, tokenPath sidecar.EvsTokenPath, version uint64) *DropBody {
	if self == nil || tokenPath == nil {
		return nil
	}
	for _, drop := range self.Drops {
		if _, listed := drop.Lists.Lists(epoch, tokenPath, version, false); listed {
			return drop
		}
	}
	return nil
}

// Whether an entry's drop mark covers path version version.
func evsDropMarkCovers(mark *protocol.EvsDropMark, version uint64) bool {
	return mark != nil && version < mark.GetThroughVersion()
}

// 5h's fence: see the file header. A view with no fences, a format-1 instance's or a test's, passes.
func CheckDropped(view *PushView) *EvsCheckRefusal {
	if view.Fences == nil || view.Payload == nil {
		return nil
	}
	refId := sidecar.Id(view.Statement.Push.GetRefId())
	dropped := func(tokenPath sidecar.EvsTokenPath, detail string) *EvsCheckRefusal {
		refusal := newEvsCheckRefusal(EvsCheckReasonDropped, detail)
		if tokenPath != nil {
			refusal.Paths = []sidecar.EvsTokenPath{tokenPath}
		}
		return refusal
	}
	for _, change := range view.Payload.Changes {
		base := change.Change.GetBaseEntryVersion()
		if base == 0 {
			continue
		}
		read := view.Paths[change.TokenPath.KeyString()]
		epoch, tokenPath := view.Statement.Push.GetPathEpoch(), change.TokenPath
		var mark *protocol.EvsDropMark
		if read != nil {
			if read.Epoch != 0 && read.TokenPath != nil {
				epoch, tokenPath = read.Epoch, read.TokenPath
			}
			mark = read.DropMark
		}
		if drop := view.Fences[refId].covers(epoch, tokenPath, base); drop != nil {
			return dropped(change.TokenPath, fmt.Sprintf("a base a DROP at version %d lists", drop.Version))
		}
		if evsDropMarkCovers(mark, base) {
			return dropped(change.TokenPath, "a base below its entry's drop mark")
		}
	}
	for _, reuse := range view.Reuses {
		if reuse == nil || reuse.Reuse == nil || reuse.EntryVersion == nil {
			// a source step 4 found none of is 5h's unknown source
			continue
		}
		version := reuse.EntryVersion.GetVersion()
		if drop := view.Fences[reuse.Reuse.RefId].covers(reuse.Epoch, reuse.Reuse.TokenPath, version); drop != nil {
			return dropped(nil, fmt.Sprintf("a reuse source a DROP at version %d lists", drop.Version))
		}
		if evsDropMarkCovers(reuse.DropMark, version) {
			return dropped(nil, "a reuse source below its entry's drop mark")
		}
	}
	return nil
}

// Whether a DROPPED refusal of the view rests on a head step 4 read from the cache: its own ref's or a reuse source's,
// which the refuse row never records on (push.go reads them again from the cluster).
func evsDroppedOnCachedHead(view *PushView) bool {
	if view == nil {
		return false
	}
	for _, fence := range view.Fences {
		if fence.Cached {
			return true
		}
	}
	for _, reuse := range view.Reuses {
		if reuse != nil && reuse.HeadCached {
			return true
		}
	}
	return false
}
