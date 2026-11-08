// ServiceHost.Blobs with every metadata cluster's writes held to the write budget (§11.13: every
// metadata write spends its cluster's budget). A PUT or DELETE on a metadata cluster whose ctx no
// WriteBudget passed fails with ErrWriteUnbudgeted before anything is sent, so a write that forgot its
// budget fails in its first test rather than wearing the drives unpriced. Reads, and every call on the
// segment cluster, which spends no NVMe budget, pass through.
//
// A host wraps its Blobs in this once it holds a WriteBudget, and engines see only the wrapped store.
// Safe for concurrent use.

package evsservice

import (
	"context"
	"fmt"
	"io"

	"github.com/urnetwork/sidecar"
)

// A metadata write whose ctx carries no class: nothing was sent, so the outcome is definite, as
// ErrBlobPutOptions's is.
var ErrWriteUnbudgeted = fmt.Errorf("%w: a metadata write that no write budget passed", sidecar.ErrBlobPutOptions)

// See the file header.
type BudgetedBlobs struct {
	store              sidecar.BlobStore
	metadataClusterIds map[string]bool
}

// store with its metadata clusters' writes held to the budget.
func NewBudgetedBlobs(store sidecar.BlobStore) *BudgetedBlobs {
	metadataClusterIds := map[string]bool{}
	for _, clusterId := range store.MetadataClusterIds() {
		metadataClusterIds[clusterId] = true
	}
	return &BudgetedBlobs{store: store, metadataClusterIds: metadataClusterIds}
}

// The cluster, wrapped when it is a metadata cluster.
func (self *BudgetedBlobs) wrap(cluster sidecar.BlobCluster, err error) (sidecar.BlobCluster, error) {
	if err != nil {
		return nil, err
	}
	if !self.metadataClusterIds[cluster.ClusterId()] {
		return cluster, nil
	}
	return &budgetedBlobCluster{BlobCluster: cluster}, nil
}

// The store's cluster, wrapped when it is a metadata cluster.
func (self *BudgetedBlobs) Cluster(clusterId string) (sidecar.BlobCluster, error) {
	return self.wrap(self.store.Cluster(clusterId))
}

// The store's first cluster, a metadata cluster, wrapped.
func (self *BudgetedBlobs) FirstCluster() (sidecar.BlobCluster, error) {
	return self.wrap(self.store.FirstCluster())
}

// The segment cluster as it is: segment PUTs queue on §11.13's hdd row, not this budget.
func (self *BudgetedBlobs) SegmentCluster() (sidecar.BlobCluster, error) {
	return self.store.SegmentCluster()
}

// The store's.
func (self *BudgetedBlobs) MetadataClusterIds() []string {
	return self.store.MetadataClusterIds()
}

// The store's.
func (self *BudgetedBlobs) NewRepoClusterId() string {
	return self.store.NewRepoClusterId()
}

// A metadata cluster whose writes need a class on their ctx.
type budgetedBlobCluster struct {
	sidecar.BlobCluster
}

// ErrWriteUnbudgeted unless a budget passed ctx.
func checkWriteClass(ctx context.Context) error {
	if _, ok := sidecar.WriteClassOf(ctx); !ok {
		return ErrWriteUnbudgeted
	}
	return nil
}

// The cluster's, once a budget passed ctx.
func (self *budgetedBlobCluster) PutIfNoneMatch(ctx context.Context, key string, body []byte, options *sidecar.BlobPutOptions) (string, error) {
	if err := checkWriteClass(ctx); err != nil {
		return "", err
	}
	return self.BlobCluster.PutIfNoneMatch(ctx, key, body, options)
}

// The cluster's, once a budget passed ctx.
func (self *budgetedBlobCluster) PutIfMatch(ctx context.Context, key string, etag string, body []byte, options *sidecar.BlobPutOptions) (string, error) {
	if err := checkWriteClass(ctx); err != nil {
		return "", err
	}
	return self.BlobCluster.PutIfMatch(ctx, key, etag, body, options)
}

// The cluster's, once a budget passed ctx.
func (self *budgetedBlobCluster) PutStream(ctx context.Context, key string, body io.Reader, byteCount int64, checksumSha256 []byte) (string, error) {
	if err := checkWriteClass(ctx); err != nil {
		return "", err
	}
	return self.BlobCluster.PutStream(ctx, key, body, byteCount, checksumSha256)
}

// The cluster's, once a budget passed ctx.
func (self *budgetedBlobCluster) Delete(ctx context.Context, key string) error {
	if err := checkWriteClass(ctx); err != nil {
		return err
	}
	return self.BlobCluster.Delete(ctx, key)
}

var _ sidecar.BlobStore = (*BudgetedBlobs)(nil)
var _ sidecar.BlobCluster = (*budgetedBlobCluster)(nil)
