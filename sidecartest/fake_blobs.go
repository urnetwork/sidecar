// T2's ServiceHost.Blobs (§22.4): the file clusters in memory. It keeps host_blobs.go's promises the
// way the real store does, so a test on it sees what evs would see:
//
//   - each cluster holds its own keys, and a conditional PUT is decided under one lock;
//   - an ETag is the MD5 of the bytes, as MinIO's is, so equal bytes give an equal ETag and a blind
//     rewrite of a head shows up here, where §11.8's etag row forbids it, and not first on T3;
//   - LastModified comes from the injected clock;
//   - a request is refused once its deadline has passed, by the sender's clock, so an actor with an
//     offset clock has that offset here;
//   - a parked write lands before the next request on its key or never (D-OPS-20), unless it has not
//     reached the store (DelayInNetwork);
//   - no key may prefix another (§11.8's keys row): a write that breaks this is recorded and, through
//     settings.Report, fails the test. A real store takes it, so only this fake can catch it early.
//
// Faults come from the shared FaultQueue. Safe for concurrent use.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// What a client sees of a dropped connection: never a definite answer.
var errBlobTransport = errors.New("connection reset by the fault plan")

// The store refused a request past its deadline, which a client also cannot tell from a lost one
// (host_blobs.go), so a PUT or DELETE reports it as unknown.
var errBlobDeadline = errors.New("store refused a request past its deadline")

// A client's own timeout: no response came.
var errBlobClientTimeout = errors.New("no response before the request timeout")

type FakeBlobsSettings struct {
	// Every metadata cluster, the first first.
	MetadataClusterIds []string
	// Where seg/, pack/ and dropscan/ live.
	SegmentClusterId string
	// §19.6's store request deadline: 10 s on both clusters. What RequestTimeout reports, and how long
	// a parked request's caller waits.
	RequestTimeout time.Duration
	// §19.6: the store bounds a streamed PUT this long after its last byte.
	StreamTimeout time.Duration
	// What SettlePassed answers until SetSettlePassed changes it. True: this fake keeps the settle
	// rule, and a test of a build that has not passed sets it false.
	SettlePassed bool
	// Told each rule a caller broke, as it happens. A test passes t.Errorf's shape here so the failure
	// lands on the test. nil: Violations alone holds them.
	Report func(violation string)
}

func DefaultFakeBlobsSettings() *FakeBlobsSettings {
	return &FakeBlobsSettings{
		MetadataClusterIds: []string{"meta-1"},
		SegmentClusterId:   "seg-1",
		RequestTimeout:     10 * time.Second,
		StreamTimeout:      40 * time.Second,
		SettlePassed:       true,
	}
}

type FakeBlobs struct {
	clock    Clock
	faults   *FaultQueue
	barriers *BarrierDriver
	settings *FakeBlobsSettings
	clusters map[string]*fakeBlobCluster

	stateLock        sync.Mutex
	newRepoClusterId string
	violations       []string
}

// clock and settings may be nil, for a fresh clock and the defaults. faults may be nil, for a queue of
// the fake's own. barriers may be nil outside a schedule.
func NewFakeBlobs(clock Clock, faults *FaultQueue, barriers *BarrierDriver, settings *FakeBlobsSettings) *FakeBlobs {
	if clock == nil {
		clock = NewFakeClock(DefaultClockStart())
	}
	if faults == nil {
		faults = NewFaultQueue()
	}
	if settings == nil {
		settings = DefaultFakeBlobsSettings()
	}
	self := &FakeBlobs{
		clock:            clock,
		faults:           faults,
		barriers:         barriers,
		settings:         settings,
		clusters:         map[string]*fakeBlobCluster{},
		newRepoClusterId: settings.MetadataClusterIds[0],
	}
	for _, clusterId := range append(slices.Clone(settings.MetadataClusterIds), settings.SegmentClusterId) {
		self.clusters[clusterId] = &fakeBlobCluster{
			store:         self,
			clusterId:     clusterId,
			settlePassed:  settings.SettlePassed,
			objects:       map[string]*fakeBlob{},
			requestCounts: map[string]int{},
		}
	}
	return self
}

func (self *FakeBlobs) Faults() *FaultQueue {
	return self.faults
}

func (self *FakeBlobs) Cluster(clusterId string) (sidecar.BlobCluster, error) {
	cluster, ok := self.clusters[clusterId]
	if !ok {
		return nil, sidecar.ErrBlobClusterUnknown
	}
	return cluster, nil
}

func (self *FakeBlobs) FirstCluster() (sidecar.BlobCluster, error) {
	return self.Cluster(self.settings.MetadataClusterIds[0])
}

func (self *FakeBlobs) SegmentCluster() (sidecar.BlobCluster, error) {
	return self.Cluster(self.settings.SegmentClusterId)
}

func (self *FakeBlobs) MetadataClusterIds() []string {
	return slices.Clone(self.settings.MetadataClusterIds)
}

func (self *FakeBlobs) NewRepoClusterId() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.newRepoClusterId
}

// Moves place_new. It may name a cluster Cluster refuses, as a host's config may (§19.9).
func (self *FakeBlobs) SetNewRepoClusterId(clusterId string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.newRepoClusterId = clusterId
}

// What SettlePassed answers for one cluster (FS-114's gate).
func (self *FakeBlobs) SetSettlePassed(clusterId string, settlePassed bool) {
	cluster := self.clusters[clusterId]
	cluster.stateLock.Lock()
	defer cluster.stateLock.Unlock()
	cluster.settlePassed = settlePassed
}

// This store as a process that holds credentials for clusterIds alone sees it (§19.4): gkm has no
// segment cluster, and api only the first.
func (self *FakeBlobs) View(clusterIds ...string) sidecar.BlobStore {
	return &fakeBlobsView{store: self, clusterIds: clusterIds}
}

type fakeBlobsView struct {
	store      *FakeBlobs
	clusterIds []string
}

func (self *fakeBlobsView) Cluster(clusterId string) (sidecar.BlobCluster, error) {
	if !slices.Contains(self.clusterIds, clusterId) {
		return nil, sidecar.ErrBlobClusterUnknown
	}
	return self.store.Cluster(clusterId)
}

func (self *fakeBlobsView) FirstCluster() (sidecar.BlobCluster, error) {
	return self.Cluster(self.store.settings.MetadataClusterIds[0])
}

func (self *fakeBlobsView) SegmentCluster() (sidecar.BlobCluster, error) {
	return self.Cluster(self.store.settings.SegmentClusterId)
}

func (self *fakeBlobsView) MetadataClusterIds() []string {
	return self.store.MetadataClusterIds()
}

func (self *fakeBlobsView) NewRepoClusterId() string {
	return self.store.NewRepoClusterId()
}

func (self *FakeBlobs) violate(violation string) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.violations = append(self.violations, violation)
	}()
	if self.settings.Report != nil {
		self.settings.Report(violation)
	}
}

// Every rule a caller broke.
func (self *FakeBlobs) Violations() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.violations)
}

// Delivers parked requests under keyPrefix on clusterId, in the order they were parked, each to its
// fate: one in the network reaches the store now and is judged now, one the store took lands, and one
// armed never to land is lost. Returns how many arrived, so a schedule can tell a request it means to
// deliver from one that never parked.
func (self *FakeBlobs) DeliverDelayed(clusterId string, keyPrefix string) int {
	cluster := self.clusters[clusterId]
	cluster.stateLock.Lock()
	defer cluster.stateLock.Unlock()
	delivered := 0
	for _, request := range slices.Clone(cluster.delayed) {
		if strings.HasPrefix(request.key, keyPrefix) {
			cluster.settleRequestWithLock(request)
			delivered += 1
		}
	}
	return delivered
}

// Parked requests not yet landed or lost, across clusters.
func (self *FakeBlobs) DelayedCount() int {
	count := 0
	for _, cluster := range self.clusters {
		func() {
			cluster.stateLock.Lock()
			defer cluster.stateLock.Unlock()
			count += len(cluster.delayed)
		}()
	}
	return count
}

// Every object, by <cluster>/<key>, each as its key, metadata and body, for CC3's scan.
func (self *FakeBlobs) Dump() map[string][]byte {
	dump := map[string][]byte{}
	for clusterId, cluster := range self.clusters {
		func() {
			cluster.stateLock.Lock()
			defer cluster.stateLock.Unlock()
			for key, blob := range cluster.objects {
				var serialized bytes.Buffer
				serialized.WriteString(key)
				serialized.WriteByte(0)
				for _, name := range slices.Sorted(maps.Keys(blob.metadata)) {
					serialized.WriteString(name)
					serialized.WriteByte(0)
					serialized.WriteString(blob.metadata[name])
					serialized.WriteByte(0)
				}
				serialized.Write(blob.body)
				dump[clusterId+"/"+key] = serialized.Bytes()
			}
		}()
	}
	return dump
}

// Requests one cluster has served by operation, so a test can hold a cost to what §11.13 prices.
func (self *FakeBlobs) RequestCount(clusterId string, op string) int {
	cluster := self.clusters[clusterId]
	cluster.stateLock.Lock()
	defer cluster.stateLock.Unlock()
	return cluster.requestCounts[op]
}

func (self *FakeBlobs) blocking(wait func()) {
	if self.barriers != nil {
		self.barriers.Blocking(wait)
		return
	}
	wait()
}

type fakeBlob struct {
	body         []byte
	etag         string
	lastModified time.Time
	metadata     map[string]string
}

func (self *fakeBlob) info(key string) sidecar.BlobInfo {
	return sidecar.BlobInfo{
		Key:          key,
		ByteCount:    int64(len(self.body)),
		Etag:         self.etag,
		LastModified: self.lastModified,
		Metadata:     maps.Clone(self.metadata),
	}
}

// A request parked by Delay.
type delayedBlobRequest struct {
	key      string
	delay    FaultDelay
	deadline time.Time
	// Runs under the cluster's lock at landing, and keeps its result where its caller reads it.
	serve func() error
	// closes when it landed or was lost
	landed chan struct{}
	err    error
}

type fakeBlobCluster struct {
	store     *FakeBlobs
	clusterId string

	stateLock     sync.Mutex
	settlePassed  bool
	objects       map[string]*fakeBlob
	sortedKeys    []string
	delayed       []*delayedBlobRequest
	requestCounts map[string]int
}

func (self *fakeBlobCluster) ClusterId() string {
	return self.clusterId
}

func (self *fakeBlobCluster) RequestTimeout() time.Duration {
	return self.store.settings.RequestTimeout
}

func (self *fakeBlobCluster) SettlePassed() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.settlePassed
}

func (self *fakeBlobCluster) now() time.Time {
	return self.store.clock.Now()
}

// Settles every parked request on key, or under it for a LIST, before a later request is served
// (D-OPS-20). One still in the network has not reached the store, so it stays.
func (self *fakeBlobCluster) settleWithLock(matches func(key string) bool) {
	for _, request := range slices.Clone(self.delayed) {
		if request.delay == DelayInNetwork || !matches(request.key) {
			continue
		}
		self.settleRequestWithLock(request)
	}
}

// Settles one parked request to its fate, unless something settled it first: one armed never to land
// is lost, and any other lands.
func (self *fakeBlobCluster) settleRequestWithLock(request *delayedBlobRequest) {
	if !slices.Contains(self.delayed, request) {
		return
	}
	if request.delay == DelayNeverLands {
		self.loseWithLock(request)
		return
	}
	self.landWithLock(request)
}

func (self *fakeBlobCluster) removeDelayedWithLock(request *delayedBlobRequest) {
	self.delayed = slices.DeleteFunc(self.delayed, func(delayed *delayedBlobRequest) bool { return delayed == request })
}

func (self *fakeBlobCluster) loseWithLock(request *delayedBlobRequest) {
	self.removeDelayedWithLock(request)
	request.err = errBlobTransport
	close(request.landed)
}

// The parked request reaches the store: judged on arrival, its deadline first.
func (self *fakeBlobCluster) landWithLock(request *delayedBlobRequest) {
	if !slices.Contains(self.delayed, request) {
		// settled already, by a request that reached the store before this delivery got to it
		return
	}
	self.removeDelayedWithLock(request)
	if request.delay == DelayInNetwork {
		// other parked writes on this key settle first, as for any request
		self.settleWithLock(func(key string) bool { return key == request.key })
	}
	if self.pastDeadline(request.deadline) {
		request.err = errBlobDeadline
	} else {
		request.err = request.serve()
	}
	close(request.landed)
}

func (self *fakeBlobCluster) pastDeadline(deadline time.Time) bool {
	return !deadline.IsZero() && !self.now().Before(deadline)
}

// How a definite result leaves the store: a condition, a checksum, a hold, or a missing key stay what
// they are; anything else a client cannot tell from a lost response, so a write's is unknown.
func blobClientError(err error, isWrite bool) error {
	switch {
	case err == nil,
		errors.Is(err, sidecar.ErrBlobPrecondition),
		errors.Is(err, sidecar.ErrBlobChecksum),
		errors.Is(err, sidecar.ErrBlobHeld),
		errors.Is(err, sidecar.ErrBlobNotFound),
		errors.Is(err, sidecar.ErrBlobRange):
		return err
	}
	if isWrite {
		return &sidecar.BlobUnknownError{Err: err}
	}
	return fmt.Errorf("blob request failed: %w", err)
}

// One request through the store: its fault, then serve under the lock. deadline zero means none.
// matches says which keys this request must see settled; for all but a LIST that is its own key.
func (self *fakeBlobCluster) request(
	ctx context.Context,
	op string,
	key string,
	isWrite bool,
	deadline time.Time,
	matches func(key string) bool,
	serve func() error,
) error {
	stopIfDead(ctx)
	if isInspecting(ctx) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return serve()
	}
	if err := ctx.Err(); err != nil {
		return blobClientError(err, isWrite)
	}

	plan := self.store.faults.take(ctx, op, self.clusterId, key, isWrite)
	result := FaultResult(0)
	if plan != nil {
		result = plan.Result
	}
	switch result {
	case FailBeforeApply:
		return blobClientError(errBlobTransport, isWrite)
	case Precondition:
		return sidecar.ErrBlobPrecondition
	case Held:
		return sidecar.ErrBlobHeld
	case CrashBeforeApply:
		crashCaller(ctx)
	case Delay:
		return self.requestDelayed(ctx, plan, key, isWrite, deadline, serve)
	}

	err := func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.requestCounts[op] += 1
		self.settleWithLock(matches)
		if self.pastDeadline(deadline) {
			return errBlobDeadline
		}
		return serve()
	}()

	switch result {
	case ApplyThenDrop:
		return blobClientError(errBlobTransport, isWrite)
	case CrashAfterApply:
		crashCaller(ctx)
	}
	return blobClientError(err, isWrite)
}

// Parks a request and waits as a client does: for its answer, its ctx, or its timeout. A client that
// gives up leaves the request where it is, since a cancel tells the store nothing.
func (self *fakeBlobCluster) requestDelayed(
	ctx context.Context,
	plan *FaultPlan,
	key string,
	isWrite bool,
	deadline time.Time,
	serve func() error,
) error {
	request := &delayedBlobRequest{
		key:      key,
		delay:    plan.Delay,
		deadline: deadline,
		serve:    serve,
		landed:   make(chan struct{}),
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.delayed = append(self.delayed, request)
	}()

	timedOut := self.store.clock.After(self.RequestTimeout())
	var err error
	self.store.blocking(func() {
		select {
		case <-request.landed:
			err = request.err
		case <-ctx.Done():
			err = ctx.Err()
		case <-timedOut:
			err = errBlobClientTimeout
		}
	})
	stopIfDead(ctx)
	return blobClientError(err, isWrite)
}

func (self *fakeBlobCluster) deadline(ctx context.Context) time.Time {
	return sidecar.BlobRequestDeadline(ctx, clockOf(ctx, self.store.clock).Now(), self.RequestTimeout())
}

func (self *fakeBlobCluster) writeWithLock(key string, body []byte, options *sidecar.BlobPutOptions) string {
	sum := md5.Sum(body)
	blob := &fakeBlob{
		body:         bytes.Clone(body),
		etag:         hex.EncodeToString(sum[:]),
		lastModified: self.now(),
	}
	if options != nil {
		blob.metadata = maps.Clone(options.Metadata)
	}
	if _, exists := self.objects[key]; !exists {
		self.checkPrefixWithLock(key)
		index := sort.SearchStrings(self.sortedKeys, key)
		self.sortedKeys = slices.Insert(self.sortedKeys, index, key)
	}
	self.objects[key] = blob
	return blob.etag
}

// §11.8's keys row. Any key prefixing this one is one of its own prefixes, and a key this one prefixes
// sorts right after it, so neither check walks the bucket.
func (self *fakeBlobCluster) checkPrefixWithLock(key string) {
	for length := 1; length < len(key); length += 1 {
		if _, exists := self.objects[key[:length]]; exists {
			self.store.violate(fmt.Sprintf("key %q prefixes key %q", key[:length], key))
		}
	}
	index := sort.SearchStrings(self.sortedKeys, key)
	if index < len(self.sortedKeys) && strings.HasPrefix(self.sortedKeys[index], key) {
		self.store.violate(fmt.Sprintf("key %q prefixes key %q", key, self.sortedKeys[index]))
	}
}

func blobChecksumOk(body []byte, options *sidecar.BlobPutOptions) bool {
	if options == nil || len(options.Sha256) == 0 {
		return true
	}
	sum := sha256.Sum256(body)
	return bytes.Equal(sum[:], options.Sha256)
}

func (self *fakeBlobCluster) keyEquals(key string) func(string) bool {
	return func(other string) bool { return other == key }
}

func (self *fakeBlobCluster) PutIfNoneMatch(ctx context.Context, key string, body []byte, options *sidecar.BlobPutOptions) (string, error) {
	if err := options.Validate(); err != nil {
		return "", err
	}
	var newEtag string
	err := self.request(ctx, FaultOpPut, key, true, self.deadline(ctx), self.keyEquals(key), func() error {
		if _, exists := self.objects[key]; exists {
			return sidecar.ErrBlobPrecondition
		}
		if !blobChecksumOk(body, options) {
			return sidecar.ErrBlobChecksum
		}
		newEtag = self.writeWithLock(key, body, options)
		return nil
	})
	if err != nil {
		return "", err
	}
	return newEtag, nil
}

func (self *fakeBlobCluster) PutIfMatch(ctx context.Context, key string, etag string, body []byte, options *sidecar.BlobPutOptions) (string, error) {
	if etag == "" {
		return "", fmt.Errorf("%w: an If-Match with no etag", sidecar.ErrBlobPutOptions)
	}
	if err := options.Validate(); err != nil {
		return "", err
	}
	var newEtag string
	err := self.request(ctx, FaultOpPut, key, true, self.deadline(ctx), self.keyEquals(key), func() error {
		blob, exists := self.objects[key]
		if !exists || blob.etag != etag {
			return sidecar.ErrBlobPrecondition
		}
		if !blobChecksumOk(body, options) {
			return sidecar.ErrBlobChecksum
		}
		newEtag = self.writeWithLock(key, body, options)
		return nil
	})
	if err != nil {
		return "", err
	}
	return newEtag, nil
}

func (self *fakeBlobCluster) PutStream(ctx context.Context, key string, body io.Reader, byteCount int64, checksumSha256 []byte) (string, error) {
	if len(checksumSha256) != 32 {
		return "", fmt.Errorf("%w: a segment names its 32 byte checksum", sidecar.ErrBlobPutOptions)
	}
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return "", &sidecar.BlobUnknownError{Err: err}
	}
	if int64(len(bodyBytes)) != byteCount {
		return "", &sidecar.BlobUnknownError{Err: fmt.Errorf("%d bytes where %d were declared", len(bodyBytes), byteCount)}
	}
	options := &sidecar.BlobPutOptions{Sha256: checksumSha256}
	// no request deadline: the store's bound runs from the last byte, which has just gone
	deadline := self.now().Add(self.store.settings.StreamTimeout)
	var newEtag string
	err = self.request(ctx, FaultOpPut, key, true, deadline, self.keyEquals(key), func() error {
		if _, exists := self.objects[key]; exists {
			return sidecar.ErrBlobPrecondition
		}
		if !blobChecksumOk(bodyBytes, options) {
			return sidecar.ErrBlobChecksum
		}
		newEtag = self.writeWithLock(key, bodyBytes, options)
		return nil
	})
	if err != nil {
		return "", err
	}
	return newEtag, nil
}

func (self *fakeBlobCluster) Get(ctx context.Context, key string) (*sidecar.BlobObject, error) {
	var object *sidecar.BlobObject
	err := self.request(ctx, FaultOpGet, key, false, self.deadline(ctx), self.keyEquals(key), func() error {
		blob, exists := self.objects[key]
		if !exists {
			return sidecar.ErrBlobNotFound
		}
		object = &sidecar.BlobObject{
			BlobInfo: blob.info(key),
			Body:     io.NopCloser(bytes.NewReader(bytes.Clone(blob.body))),
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return object, nil
}

func (self *fakeBlobCluster) GetRange(ctx context.Context, key string, offset int64, byteCount int64) (*sidecar.BlobObject, error) {
	var object *sidecar.BlobObject
	err := self.request(ctx, FaultOpGet, key, false, self.deadline(ctx), self.keyEquals(key), func() error {
		blob, exists := self.objects[key]
		if !exists {
			return sidecar.ErrBlobNotFound
		}
		length := int64(len(blob.body))
		if offset < 0 || byteCount <= 0 || length <= offset {
			return sidecar.ErrBlobRange
		}
		object = &sidecar.BlobObject{
			BlobInfo: blob.info(key),
			Body:     io.NopCloser(bytes.NewReader(bytes.Clone(blob.body[offset:min(length, offset+byteCount)]))),
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return object, nil
}

func (self *fakeBlobCluster) Head(ctx context.Context, key string) (*sidecar.BlobInfo, error) {
	var info *sidecar.BlobInfo
	err := self.request(ctx, FaultOpGet, key, false, self.deadline(ctx), self.keyEquals(key), func() error {
		blob, exists := self.objects[key]
		if !exists {
			return sidecar.ErrBlobNotFound
		}
		blobInfo := blob.info(key)
		info = &blobInfo
		return nil
	})
	if err != nil {
		return nil, err
	}
	return info, nil
}

func (self *fakeBlobCluster) List(ctx context.Context, keyPrefix string, startAfter string, limit int) ([]*sidecar.BlobInfo, bool, error) {
	if limit <= 0 {
		return nil, false, fmt.Errorf("a list limit of %d", limit)
	}
	underPrefix := func(key string) bool { return strings.HasPrefix(key, keyPrefix) }
	var objects []*sidecar.BlobInfo
	var more bool
	err := self.request(ctx, FaultOpList, keyPrefix, false, self.deadline(ctx), underPrefix, func() error {
		objects = []*sidecar.BlobInfo{}
		more = false
		start := sort.SearchStrings(self.sortedKeys, keyPrefix)
		for _, key := range self.sortedKeys[start:] {
			if !strings.HasPrefix(key, keyPrefix) {
				break
			}
			if key <= startAfter {
				continue
			}
			if len(objects) == limit {
				more = true
				break
			}
			info := self.objects[key].info(key)
			// a listing carries no metadata (host_blobs.go)
			info.Metadata = nil
			objects = append(objects, &info)
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return objects, more, nil
}

func (self *fakeBlobCluster) Delete(ctx context.Context, key string) error {
	return self.request(ctx, FaultOpDelete, key, true, self.deadline(ctx), self.keyEquals(key), func() error {
		if _, exists := self.objects[key]; exists {
			delete(self.objects, key)
			index := sort.SearchStrings(self.sortedKeys, key)
			self.sortedKeys = slices.Delete(self.sortedKeys, index, index+1)
		}
		return nil
	})
}
