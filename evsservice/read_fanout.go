// §11.15's fan-out (owner decision 780; QD-1394): the store reads one push attempt, one read request or one GET
// .../refs has in flight, at most EvsSettings.EntryReadConcurrency. Step 4 issues its round together, a read for each
// changed entry (with its source copies and its prefixes' states while the head lists sources, sources.go), each
// window place and each reuse, and a read's first round one for each path it names; a seal reads its parts together,
// a read's second round the statements after its pin, and GET .../refs a page of heads. With no bound, a part's 1,024
// entries, four parts posted at once, put about 4,000 GETs in flight at one block, each dialing a connection of its
// own, and a store that reset them under load turned each part into a 503 whose retry repeated the burst.
//
// Each such attempt reads through its cluster wrapped here, with a pool of that many slots of its own. A read takes
// a slot just before it is sent and gives it back once it is over: a HEAD or a LIST when it returns, a GET when its
// body reaches its end, fails or is closed, whichever comes first, and any read when it fails. A read that finds
// every slot taken waits for one under its own ctx, the attempt's, and fails with that ctx's error, sending nothing,
// if the ctx ends first. Writes pass through: the write budget holds them (budget_blobs.go).
//
// A slot is held only while its read is at the store or its body is being read, and every caller reads a body to
// its end before it reads anything else (readBlob, ReadRecord, the entry, head and repo/ reads), so a read waiting
// for a slot waits only on reads that need nothing more to finish, and the pool cannot deadlock. A read that streams
// an object to its client (read_frame.go) holds one slot until the object is sent, and reads nothing meanwhile.
//
// The pool is the attempt's own, so attempts never wait on one another's reads here (CODESTYLE's budgets owned by
// instances); the file clusters' cap on the connections a block opens to one host (server's
// FileClusterSettings.MaxConnsPerHost) is each block's backstop over all of them. Safe for concurrent use.

package evsservice

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/urnetwork/sidecar"
)

// A cluster whose reads each hold one of its attempt's slots while in flight. See the file header.
type attemptReadCluster struct {
	sidecar.BlobCluster
	// one value for each read in flight
	slots chan struct{}
	// BarrierReadSlotWait's key: the repo's
	barrierKey string
	// called as a read starts to wait for a slot; nil but in this package's tests
	waiting func()
}

// cluster with its reads held to concurrency in flight, for one attempt on repoId; nil for a nil cluster.
// EvsSettings.Validate holds concurrency positive.
func newAttemptReadCluster(cluster sidecar.BlobCluster, concurrency int, repoId sidecar.Id) sidecar.BlobCluster {
	if cluster == nil {
		return nil
	}
	return &attemptReadCluster{
		BlobCluster: cluster,
		slots:       make(chan struct{}, max(1, concurrency)),
		barrierKey:  sidecar.EvsKeyId(repoId),
	}
}

// request's cluster for one attempt: its reads held to EntryReadConcurrency in flight.
func (self *EvsEngine) attemptCluster(request *EvsRequest) sidecar.BlobCluster {
	return newAttemptReadCluster(request.Cluster, self.settings.EntryReadConcurrency, request.RepoId)
}

// Takes a slot, waiting under ctx while every slot is taken.
func (self *attemptReadCluster) take(ctx context.Context) error {
	select {
	case self.slots <- struct{}{}:
		return nil
	default:
	}
	testHookBarrier(BarrierReadSlotWait, self.barrierKey)
	if self.waiting != nil {
		self.waiting()
	}
	select {
	case self.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("a store read waiting for one of its attempt's %d slots: %w", cap(self.slots), ctx.Err())
	}
}

// Gives a slot back.
func (self *attemptReadCluster) give() {
	<-self.slots
}

func (self *attemptReadCluster) Get(ctx context.Context, key string) (*sidecar.BlobObject, error) {
	if err := self.take(ctx); err != nil {
		return nil, err
	}
	object, err := self.BlobCluster.Get(ctx, key)
	return self.held(object, err)
}

func (self *attemptReadCluster) GetRange(ctx context.Context, key string, offset int64, byteCount int64) (*sidecar.BlobObject, error) {
	if err := self.take(ctx); err != nil {
		return nil, err
	}
	object, err := self.BlobCluster.GetRange(ctx, key, offset, byteCount)
	return self.held(object, err)
}

// A GET's answer: its slot back at once when it failed, else held by the body until the body ends or is closed.
func (self *attemptReadCluster) held(object *sidecar.BlobObject, err error) (*sidecar.BlobObject, error) {
	if err != nil {
		self.give()
		return nil, err
	}
	return &sidecar.BlobObject{
		BlobInfo: object.BlobInfo,
		Body:     &attemptReadBody{ReadCloser: object.Body, give: self.give},
	}, nil
}

func (self *attemptReadCluster) Head(ctx context.Context, key string) (*sidecar.BlobInfo, error) {
	if err := self.take(ctx); err != nil {
		return nil, err
	}
	defer self.give()
	return self.BlobCluster.Head(ctx, key)
}

func (self *attemptReadCluster) List(ctx context.Context, keyPrefix string, startAfter string, limit int) ([]*sidecar.BlobInfo, bool, error) {
	if err := self.take(ctx); err != nil {
		return nil, false, err
	}
	defer self.give()
	return self.BlobCluster.List(ctx, keyPrefix, startAfter, limit)
}

// A GET's body, which gives its slot back at its end, at a read that fails or at its close, whichever comes first.
type attemptReadBody struct {
	io.ReadCloser
	give     func()
	giveOnce sync.Once
}

func (self *attemptReadBody) Read(buffer []byte) (int, error) {
	count, err := self.ReadCloser.Read(buffer)
	if err != nil {
		self.giveOnce.Do(self.give)
	}
	return count, err
}

func (self *attemptReadBody) Close() error {
	err := self.ReadCloser.Close()
	self.giveOnce.Do(self.give)
	return err
}
