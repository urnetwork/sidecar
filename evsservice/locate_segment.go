// §11.13's address row (EVSB-M2-10): a segment is addressed only by its id. SegmentLocator GETs seg/<repo>/<id> on
// the segment cluster, and on 404 looks the id up in spidx/<repo>/ on the repo's metadata cluster. spidx/ is
// reserved and empty in v0, so a page there is one this build has no format for, and the locator refuses it rather
// than guess; with none, the segment is gone (ErrBlobNotFound). A 404 is rare, a segment GC or a drop deleted, so
// each one lists spidx/ afresh, which the negative rule asks of a miss anyway (§11.13). Safe for concurrent use.

package evsservice

import (
	"context"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar"
)

// spidx/ holds a page, which format 1 never writes.
var ErrEvsSpidxUnsupported = errors.New("evs spidx page this build cannot read")

// See the file header.
type SegmentLocator struct {
	blobs sidecar.BlobStore
}

func NewSegmentLocator(blobs sidecar.BlobStore) *SegmentLocator {
	return &SegmentLocator{blobs: blobs}
}

// Opens byteCount bytes from offset of the segment, the whole of it when byteCount is not positive. The caller
// closes the body.
func (self *SegmentLocator) OpenSegment(ctx context.Context, metadataCluster sidecar.BlobCluster, repoId sidecar.Id, segmentId [32]byte, offset int64, byteCount int64) (*sidecar.BlobObject, error) {
	segmentCluster, err := self.blobs.SegmentCluster()
	if err != nil {
		return nil, err
	}
	key := SegmentKey(repoId, segmentId)
	var object *sidecar.BlobObject
	if 0 < byteCount {
		object, err = segmentCluster.GetRange(ctx, key, offset, byteCount)
	} else {
		object, err = segmentCluster.Get(ctx, key)
	}
	if !errors.Is(err, sidecar.ErrBlobNotFound) {
		return object, err
	}
	pages, _, listErr := metadataCluster.List(ctx, spidxKeyPrefix+sidecar.EvsKeyId(repoId)+"/", "", 1)
	if listErr != nil {
		return nil, listErr
	}
	if 0 < len(pages) {
		return nil, fmt.Errorf("%w: %s", ErrEvsSpidxUnsupported, pages[0].Key)
	}
	return nil, err
}
