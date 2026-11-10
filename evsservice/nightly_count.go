// The nightly pass's count (§11.13's bytes row, §20.7's count row; EVSB-M2-12): a repo's stored bytes are the sizes
// of its seg/, pack/ and hp/ objects as LIST returns them, plus the record lengths its head windows give for
// versions still in batches, with no payload read. They are summed by the network its repo/ names (the answer to
// plan-EVSB-repo-network): a repo whose repo/ names none is counted to no one.
//
// A version counts from its head's window while its batch may stand, and from the parcel or pack that holds it
// afterwards, so a record mid-evacuation counts twice only until its minute's batches are deleted, and the next
// pass corrects it (§20.7). A batch may stand while its minute starts at or after the cluster's horizon; with no
// horizon read, while it is under 26 h old.

package evsservice

import (
	"context"
	"errors"

	"github.com/urnetwork/sidecar"
)

// Adds one repo's stored bytes to its network's in result: what it listed, less the containers the pass deleted.
func (self *NightlyPass) countRepo(ctx context.Context, cluster sidecar.BlobCluster, listing *nightlyListing, result *NightlyResult) error {
	repoId := listing.repoId
	read, err := self.repos.Read(ctx, cluster, repoId)
	if errors.Is(err, sidecar.ErrEvsRepoNotFound) {
		// deleted between the LIST and this read: nothing of it is counted
		return nil
	}
	if err != nil {
		return err
	}
	networkId, err := sidecar.IdFromBytes(read.Object.GetNetworkId())
	if err != nil {
		result.UnknownNetworkRepoCount += 1
		return nil
	}
	batchRecordByteCount, err := self.batchRecordByteCount(ctx, cluster, repoId, result)
	if err != nil {
		return err
	}
	networkBytes, ok := result.NetworkBytes[networkId]
	if !ok {
		networkBytes = &NightlyBytes{}
		result.NetworkBytes[networkId] = networkBytes
	}
	networkBytes.RepoCount += 1
	for _, segment := range listing.segments {
		networkBytes.SegmentByteCount += segment.ByteCount
	}
	for _, pack := range listing.packs {
		if !listing.deletedKeys[pack.Key] {
			networkBytes.PackByteCount += pack.ByteCount
		}
	}
	for _, parcel := range listing.parcels {
		if !listing.deletedKeys[parcel.Key] {
			networkBytes.ParcelByteCount += parcel.ByteCount
		}
	}
	networkBytes.BatchRecordByteCount += batchRecordByteCount
	return nil
}

// The record lengths the head windows of the repo's refs give for versions whose batch may still stand: one head
// GET per ref written within HeadWindowAge, and no payload read (§11.13's cost row).
func (self *NightlyPass) batchRecordByteCount(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, result *NightlyResult) (int64, error) {
	heads, err := self.listAll(ctx, cluster, HeadRepoPrefix(repoId))
	if err != nil {
		return 0, err
	}
	now := self.clock.Now()
	standing := now.Add(-self.settings.HeadWindowAge)
	if result.HasHorizon {
		standing = result.Horizon
	}
	byteCount := int64(0)
	for _, listed := range heads {
		if listed.LastModified.Before(now.Add(-self.settings.HeadWindowAge)) {
			continue
		}
		headBytes, err := readBlob(ctx, cluster, listed.Key)
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			continue
		}
		if err != nil {
			return 0, err
		}
		head, err := ParseEvsHead(headBytes)
		if err != nil {
			return 0, err
		}
		window, err := EvsHeadWindow(head)
		if err != nil {
			return 0, err
		}
		for _, entry := range window {
			if place := entry.Place; place != nil && !batchMinuteTime(place.GetMinute()).Before(standing) {
				byteCount += int64(place.GetLength())
			}
		}
	}
	return byteCount, nil
}
