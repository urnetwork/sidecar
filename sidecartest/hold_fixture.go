// §21.9's holds as a test places them: the hold/<network_id>/<case_id>/_ object api writes from
// abuse_legal_hold (ABUSE-M5-14), written through sidecar.EncodeHoldRecord, the codec api uses, so a
// fixture cannot drift from what readers parse. evs's, gkm's and taskworker's hold cases (EVSB-M2-11,
// KEYS-M2-16, EVS1-M2-19, FS-66, FS-69, FS-76, FS-78, FS-92) place holds here long before api writes
// one.

package sidecartest

import (
	"context"
	"errors"

	"github.com/urnetwork/sidecar"
)

// Writes record's object on the first metadata cluster, as api places a hold, or rewrites it If-Match
// when it exists, as api renews one. blobs is any BlobStore that holds the first cluster, a FakeBlobs
// among them.
func PlaceHold(ctx context.Context, blobs sidecar.BlobStore, record *sidecar.HoldRecord) error {
	body, err := sidecar.EncodeHoldRecord(record)
	if err != nil {
		return err
	}
	return PlaceHoldBytes(ctx, blobs, sidecar.HoldObjectKey(record.NetworkId, record.CaseId), body)
}

// Writes body at key on the first metadata cluster, created or rewritten If-Match: how a test plants
// an object no codec would write, such as a malformed body or a newer version.
func PlaceHoldBytes(ctx context.Context, blobs sidecar.BlobStore, key string, body []byte) error {
	cluster, err := blobs.FirstCluster()
	if err != nil {
		return err
	}
	_, err = cluster.PutIfNoneMatch(ctx, key, body, nil)
	if !errors.Is(err, sidecar.ErrBlobPrecondition) {
		return err
	}
	info, err := cluster.Head(ctx, key)
	if err != nil {
		return err
	}
	_, err = cluster.PutIfMatch(ctx, key, info.Etag, body, nil)
	return err
}

// Deletes a hold's object, as api's sweep does once the hold has ended.
func RemoveHold(ctx context.Context, blobs sidecar.BlobStore, networkId sidecar.Id, caseId sidecar.Id) error {
	cluster, err := blobs.FirstCluster()
	if err != nil {
		return err
	}
	return cluster.Delete(ctx, sidecar.HoldObjectKey(networkId, caseId))
}
