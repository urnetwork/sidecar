//go:build !ios_extension

// Status's index share (D-QUOTA-10; §11.14's status row, §20.7's stored row; QUOTA-M10-01): the search index's files
// count toward the network's storage like any evs bytes, so `ur status` shows them apart from content. ReadIndexShare
// reads each repo's EvsRepo.IndexStatus, sums the files and bytes of every root it read, and keeps the result as what
// Status shows until the next read. Status never reads evs itself, so it stays a read of memory on every leg, the
// forwarding leg included, which reads no index and so never shows a share.
//
//	excluded  a repo of a kind that holds no index (config, mailcfg, secret: ErrEvsIndexExcluded) is left out
//	unread    a repo whose status this build cannot read, by an error or a root in a newer format
//	          (EvsIndexStateUpdate), counts as unread and adds nothing, so a partial read never passes as the whole
//	floor     the share is what each index ref's head lists; replaced index versions still in their batch count toward
//	          storage for up to 26 h (owner decision 165) and no head lists them, so it never passes what the index
//	          stores
//
// Which repos a share covers is its caller's to say: the daemon's composition, once it holds an evs client for the
// network's repos (CORE's, as for `ur status`'s versionless lines). Until a host calls it, Status shows no share.

package sidecar

import (
	"context"
	"errors"
)

// What a share reads of one repo. EvsRepo meets it.
type SidecarIndexStatusReader interface {
	IndexStatus(ctx context.Context, args *EvsIndexStatusArgs) (*EvsIndexStatus, error)
}

// Reads the index status of each repo, every index ref of each (EvsIndexStatusArgs' defaults: main's own index and
// ur/index where the repo holds it), and keeps their share as what Status shows, answering it. A ctx that ends leaves
// the repos not yet read unread, so the share says how much it covered.
func (self *Sidecar) ReadIndexShare(ctx context.Context, repos []SidecarIndexStatusReader) *SidecarIndexShare {
	share := &SidecarIndexShare{}
	for _, repo := range repos {
		if repo == nil {
			continue
		}
		if ctx.Err() != nil {
			share.RepoCount += 1
			share.UnreadRepoCount += 1
			continue
		}
		status, err := repo.IndexStatus(ctx, &EvsIndexStatusArgs{})
		addSidecarIndexShare(share, status, err)
	}
	share.ReadAt = self.clock.Now()
	self.indexShares.set(share)
	return share
}

// Adds one repo's index status, or the error that answered for it, to share (see the file header).
func addSidecarIndexShare(share *SidecarIndexShare, status *EvsIndexStatus, err error) {
	if errors.Is(err, ErrEvsIndexExcluded) {
		return
	}
	share.RepoCount += 1
	if err != nil || status == nil {
		share.UnreadRepoCount += 1
		return
	}
	fileCount := int64(0)
	byteCount := int64(0)
	for _, root := range status.Roots {
		if root == nil {
			continue
		}
		if root.State == EvsIndexStateUpdate {
			// a newer format this build does not read: its files and bytes are unknown here
			share.UnreadRepoCount += 1
			return
		}
		fileCount += int64(root.FileCount)
		byteCount += root.ByteCount
	}
	share.FileCount += fileCount
	share.ByteCount += byteCount
}
