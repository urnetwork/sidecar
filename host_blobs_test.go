//go:build !sidecar_http

// Walks §11.8's and §11.13's store flows through BlobCluster, on a small in-memory cluster local to
// this file, to prove the signatures carry them. sidecartest's fake and store suite are what check a
// real implementation (§22.9).

package sidecar

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type memoryBlob struct {
	body         []byte
	etag         string
	lastModified time.Time
	metadata     map[string]string
}

// The file header's promises for one bucket. Safe for concurrent use.
type memoryBlobCluster struct {
	stateLock  sync.Mutex
	writeCount int
	keyBlobs   map[string]*memoryBlob
}

func newMemoryBlobCluster() *memoryBlobCluster {
	return &memoryBlobCluster{keyBlobs: map[string]*memoryBlob{}}
}

func (self *memoryBlobCluster) ClusterId() string {
	return "meta-1"
}

func (self *memoryBlobCluster) RequestTimeout() time.Duration {
	return 10 * time.Second
}

func (self *memoryBlobCluster) SettlePassed() bool {
	return false
}

func (self *memoryBlobCluster) writeWithLock(key string, body []byte, options *BlobPutOptions) string {
	self.writeCount += 1
	etag := fmt.Sprintf("etag-%d", self.writeCount)
	blob := &memoryBlob{body: bytes.Clone(body), etag: etag, lastModified: time.Unix(int64(self.writeCount), 0)}
	if options != nil {
		blob.metadata = options.Metadata
	}
	self.keyBlobs[key] = blob
	return etag
}

func (self *memoryBlobCluster) checkBody(body []byte, options *BlobPutOptions) error {
	if err := options.Validate(); err != nil {
		return err
	}
	if options != nil && len(options.Sha256) != 0 {
		if sum := sha256.Sum256(body); !bytes.Equal(sum[:], options.Sha256) {
			return ErrBlobChecksum
		}
	}
	return nil
}

func (self *memoryBlobCluster) PutIfNoneMatch(ctx context.Context, key string, body []byte, options *BlobPutOptions) (string, error) {
	if err := self.checkBody(body, options); err != nil {
		return "", err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, exists := self.keyBlobs[key]; exists {
		return "", ErrBlobPrecondition
	}
	return self.writeWithLock(key, body, options), nil
}

func (self *memoryBlobCluster) PutIfMatch(ctx context.Context, key string, etag string, body []byte, options *BlobPutOptions) (string, error) {
	if etag == "" {
		return "", fmt.Errorf("%w: no etag", ErrBlobPutOptions)
	}
	if err := self.checkBody(body, options); err != nil {
		return "", err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	blob, exists := self.keyBlobs[key]
	if !exists || blob.etag != etag {
		return "", ErrBlobPrecondition
	}
	return self.writeWithLock(key, body, options), nil
}

func (self *memoryBlobCluster) PutStream(ctx context.Context, key string, body io.Reader, byteCount int64, checksumSha256 []byte) (string, error) {
	if len(checksumSha256) != 32 {
		return "", fmt.Errorf("%w: a segment names its checksum", ErrBlobPutOptions)
	}
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return "", err
	}
	if int64(len(bodyBytes)) != byteCount {
		return "", fmt.Errorf("%d bytes, %d declared", len(bodyBytes), byteCount)
	}
	return self.PutIfNoneMatch(ctx, key, bodyBytes, &BlobPutOptions{Sha256: checksumSha256})
}

func (self *memoryBlobCluster) Get(ctx context.Context, key string) (*BlobObject, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	blob, exists := self.keyBlobs[key]
	if !exists {
		return nil, ErrBlobNotFound
	}
	return &BlobObject{BlobInfo: blob.info(key), Body: io.NopCloser(bytes.NewReader(blob.body))}, nil
}

func (self *memoryBlobCluster) GetRange(ctx context.Context, key string, offset int64, byteCount int64) (*BlobObject, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	blob, exists := self.keyBlobs[key]
	if !exists {
		return nil, ErrBlobNotFound
	}
	if int64(len(blob.body)) <= offset {
		return nil, ErrBlobRange
	}
	body := blob.body[offset:min(int64(len(blob.body)), offset+byteCount)]
	return &BlobObject{BlobInfo: blob.info(key), Body: io.NopCloser(bytes.NewReader(body))}, nil
}

func (self *memoryBlobCluster) Head(ctx context.Context, key string) (*BlobInfo, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	blob, exists := self.keyBlobs[key]
	if !exists {
		return nil, ErrBlobNotFound
	}
	info := blob.info(key)
	return &info, nil
}

func (self *memoryBlobCluster) List(ctx context.Context, keyPrefix string, startAfter string, limit int) ([]*BlobInfo, bool, error) {
	if limit <= 0 {
		return nil, false, errors.New("limit")
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	keys := []string{}
	for key := range self.keyBlobs {
		if strings.HasPrefix(key, keyPrefix) && startAfter < key {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	objects := []*BlobInfo{}
	for _, key := range keys[:min(limit, len(keys))] {
		info := self.keyBlobs[key].info(key)
		info.Metadata = nil
		objects = append(objects, &info)
	}
	return objects, limit < len(keys), nil
}

func (self *memoryBlobCluster) Delete(ctx context.Context, key string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.keyBlobs, key)
	return nil
}

func (self *memoryBlob) info(key string) BlobInfo {
	return BlobInfo{
		Key:          key,
		ByteCount:    int64(len(self.body)),
		Etag:         self.etag,
		LastModified: self.lastModified,
		Metadata:     self.metadata,
	}
}

var _ BlobCluster = (*memoryBlobCluster)(nil)

func readBlobObject(t *testing.T, object *BlobObject, err error) []byte {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	defer object.Body.Close()
	body, err := io.ReadAll(object.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestBlobPutOptionsNilAndPlainAreValid(t *testing.T) {
	for _, options := range []*BlobPutOptions{
		nil,
		{},
		{Sha256: make([]byte, 32)},
		{Metadata: map[string]string{"entry-state": "carried", "e2": "a value, of printable ascii"}},
	} {
		if err := options.Validate(); err != nil {
			t.Errorf("%+v: %v", options, err)
		}
	}
}

func TestBlobPutOptionsRefuseAPartialChecksum(t *testing.T) {
	for _, byteCount := range []int{1, 16, 31, 33, 64} {
		options := &BlobPutOptions{Sha256: make([]byte, byteCount)}
		if err := options.Validate(); !errors.Is(err, ErrBlobPutOptions) {
			t.Errorf("%d bytes: %v", byteCount, err)
		}
	}
}

func TestBlobPutOptionsKeepMetadataToWhatHeadersCarry(t *testing.T) {
	for _, metadata := range []map[string]string{
		{"": "value"},
		// a store folds case, so a fake must not keep it
		{"Entry-State": "carried"},
		{"entry_state": "carried"},
		{"entry state": "carried"},
		{"entry-state": "new\nline"},
		{"entry-state": "café"},
		// an HTTP header drops these, so the fake would keep what the store lost
		{"entry-state": " carried"},
		{"entry-state": "carried "},
		{"entry-state": "  carried  "},
		{"entry-state": " "},
	} {
		options := &BlobPutOptions{Metadata: metadata}
		if err := options.Validate(); !errors.Is(err, ErrBlobPutOptions) {
			t.Errorf("%q: %v", metadata, err)
		}
	}
}

// The value a store reads, by the header it would receive: written and read back by net/http, with no
// socket involved.
func blobMetadataThroughHeader(t *testing.T, value string) string {
	t.Helper()
	request, err := http.NewRequest("PUT", "http://store.example/key", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Amz-Meta-Entry-State", value)
	var wire bytes.Buffer
	if err := request.Write(&wire); err != nil {
		t.Fatal(err)
	}
	received, err := http.ReadRequest(bufio.NewReader(&wire))
	if err != nil {
		t.Fatal(err)
	}
	return received.Header.Get("X-Amz-Meta-Entry-State")
}

// The rule against the thing it describes: every printable byte at the start, middle and end of a
// value, kept by Validate exactly when a header carries the value unchanged. Interior runs of spaces
// survive, so nothing broader than the ends is refused.
func TestBlobMetadataValidatesExactlyWhatAHeaderCarries(t *testing.T) {
	values := []string{"", "carried", "two  spaces", "a, b", `"quoted"`}
	for c := byte(' '); c <= '~'; c += 1 {
		values = append(values, string(c)+"a", "a"+string(c)+"b", "a"+string(c))
	}
	for _, value := range values {
		options := &BlobPutOptions{Metadata: map[string]string{"entry-state": value}}
		valid := options.Validate() == nil
		unchanged := blobMetadataThroughHeader(t, value) == value
		if valid != unchanged {
			t.Errorf("%q: valid %v, unchanged by a header %v", value, valid, unchanged)
		}
	}
}

// The store refuses past 2 KiB with the header prefix counted, so a fake must refuse there too.
func TestBlobMetadataStaysInsideTheStoresLimit(t *testing.T) {
	prefixByteCount := len("x-amz-meta-") + len("entry-state")
	valueByteCount := 2*1024 - prefixByteCount

	atLimit := &BlobPutOptions{Metadata: map[string]string{"entry-state": strings.Repeat("a", valueByteCount)}}
	if err := atLimit.Validate(); err != nil {
		t.Errorf("at the limit: %v", err)
	}
	pastLimit := &BlobPutOptions{Metadata: map[string]string{"entry-state": strings.Repeat("a", valueByteCount+1)}}
	if err := pastLimit.Validate(); !errors.Is(err, ErrBlobPutOptions) {
		t.Errorf("past the limit: %v", err)
	}
	// the limit is on the whole set, not one value
	spread := &BlobPutOptions{Metadata: map[string]string{
		"a": strings.Repeat("a", 1024),
		"b": strings.Repeat("a", 1024),
	}}
	if err := spread.Validate(); !errors.Is(err, ErrBlobPutOptions) {
		t.Errorf("spread past the limit: %v", err)
	}
}

func TestBlobRequestDeadlineDefaultsToTheStoresTimeout(t *testing.T) {
	issued := time.Unix(1000, 0)
	got := BlobRequestDeadline(context.Background(), issued, 10*time.Second)
	if !got.Equal(issued.Add(10 * time.Second)) {
		t.Errorf("deadline %v", got)
	}
}

// §19.6's two cases: a marker's DELETE, whose own deadline comes first, and a fold's write, 15 s after a
// head read just issued, whose own deadline shortens a request and never lengthens one.
func TestBlobRequestDeadlineTakesTheEarlier(t *testing.T) {
	issued := time.Unix(1000, 0)
	timeout := 10 * time.Second

	earlier := issued.Add(3 * time.Second)
	ctx := WithBlobDeadline(context.Background(), earlier)
	if got := BlobRequestDeadline(ctx, issued, timeout); !got.Equal(earlier) {
		t.Errorf("own deadline first: %v", got)
	}

	later := issued.Add(15 * time.Second)
	ctx = WithBlobDeadline(context.Background(), later)
	if got := BlobRequestDeadline(ctx, issued, timeout); !got.Equal(issued.Add(timeout)) {
		t.Errorf("store's deadline first: %v", got)
	}
}

func TestWithBlobDeadlineNeverLengthens(t *testing.T) {
	issued := time.Unix(1000, 0)
	earlier := issued.Add(2 * time.Second)

	ctx := WithBlobDeadline(context.Background(), earlier)
	ctx = WithBlobDeadline(ctx, issued.Add(5*time.Second))
	if got := BlobRequestDeadline(ctx, issued, 10*time.Second); !got.Equal(earlier) {
		t.Errorf("a later deadline replaced an earlier one: %v", got)
	}

	even := issued.Add(1 * time.Second)
	ctx = WithBlobDeadline(ctx, even)
	if got := BlobRequestDeadline(ctx, issued, 10*time.Second); !got.Equal(even) {
		t.Errorf("an earlier deadline did not shorten: %v", got)
	}
}

// A fake clock runs ahead of real time. A test's real-time ctx deadline must not read as already passed
// there, or every request in an advanced schedule would be refused (§22.8's fake clocks).
func TestBlobRequestDeadlineIgnoresARealTimeContext(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(1000, 0))
	defer cancel()

	fakeIssued := time.Unix(1000000, 0)
	got := BlobRequestDeadline(ctx, fakeIssued, 10*time.Second)
	if !got.Equal(fakeIssued.Add(10 * time.Second)) {
		t.Errorf("deadline %v", got)
	}
}

func TestBlobUnknownErrorKeepsItsCause(t *testing.T) {
	var err error = &BlobUnknownError{Err: io.ErrUnexpectedEOF}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("cause lost: %v", err)
	}
	var unknown *BlobUnknownError
	if !errors.As(fmt.Errorf("step 7: %w", err), &unknown) {
		t.Error("a wrapped unknown outcome reads as known")
	}
	// the outcomes §11.8 acts on stay apart, or a retry could take an unknown outcome for a refusal
	for _, known := range []error{ErrBlobPrecondition, ErrBlobHeld, ErrBlobNotFound, ErrBlobChecksum} {
		if errors.Is(err, known) {
			t.Errorf("an unknown outcome reads as %v", known)
		}
	}
}

// §11.8's place row: of two racing creates exactly one places the repo.
func TestBlobPlaceRaceHasOneWinner(t *testing.T) {
	ctx := context.Background()
	cluster := newMemoryBlobCluster()
	const racerCount = 16
	results := make([]error, racerCount)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, results[i] = cluster.PutIfNoneMatch(ctx, "place/repo-1", []byte{byte(i)}, nil)
		}()
	}
	wg.Wait()

	winner := -1
	for i, err := range results {
		switch {
		case err == nil:
			if 0 <= winner {
				t.Fatalf("racers %d and %d both won", winner, i)
			}
			winner = i
		case !errors.Is(err, ErrBlobPrecondition):
			t.Fatalf("racer %d: %v", i, err)
		}
	}
	if winner < 0 {
		t.Fatal("no racer won")
	}
	// a loser reads the object, as the row says, and learns who placed it
	object, err := cluster.Get(ctx, "place/repo-1")
	if body := readBlobObject(t, object, err); !bytes.Equal(body, []byte{byte(winner)}) {
		t.Errorf("place holds %v, the winner was %d", body, winner)
	}
}

// §11.8 step 7: a push commits only on the ETag its checks read.
func TestBlobHeadCasRefusesAStaleEtag(t *testing.T) {
	ctx := context.Background()
	cluster := newMemoryBlobCluster()

	etag, err := cluster.PutIfNoneMatch(ctx, "head/repo-1/ref-1", []byte("v1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	newEtag, err := cluster.PutIfMatch(ctx, "head/repo-1/ref-1", etag, []byte("v2"), nil)
	if err != nil {
		t.Fatal(err)
	}

	// the slower writer still holds the first ETag
	if _, err := cluster.PutIfMatch(ctx, "head/repo-1/ref-1", etag, []byte("v2-other"), nil); !errors.Is(err, ErrBlobPrecondition) {
		t.Fatalf("stale If-Match: %v", err)
	}
	object, err := cluster.Get(ctx, "head/repo-1/ref-1")
	if body := readBlobObject(t, object, err); string(body) != "v2" {
		t.Errorf("head holds %q", body)
	}

	// §11.8's 412 row: reread, then CAS on the reread ETag, which a Get gives in its one round trip
	if object.Etag != newEtag {
		t.Errorf("reread etag %q, want %q", object.Etag, newEtag)
	}
	if _, err := cluster.PutIfMatch(ctx, "head/repo-1/ref-1", object.Etag, []byte("v3"), nil); err != nil {
		t.Error(err)
	}
}

func TestBlobIfMatchOnAMissingKeyFails(t *testing.T) {
	cluster := newMemoryBlobCluster()
	_, err := cluster.PutIfMatch(context.Background(), "head/repo-1/ref-1", "etag", []byte("v1"), nil)
	if !errors.Is(err, ErrBlobPrecondition) {
		t.Errorf("err %v", err)
	}
}

// An ETag read as empty must not become an If-Match left off, which a store would take as an
// overwrite of the commit point.
func TestBlobEmptyEtagIsNoBlindOverwrite(t *testing.T) {
	ctx := context.Background()
	cluster := newMemoryBlobCluster()
	if _, err := cluster.PutIfNoneMatch(ctx, "head/repo-1/ref-1", []byte("v1"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.PutIfMatch(ctx, "head/repo-1/ref-1", "", []byte("v2"), nil); !errors.Is(err, ErrBlobPutOptions) {
		t.Fatalf("err %v", err)
	}
	object, err := cluster.Get(ctx, "head/repo-1/ref-1")
	if body := readBlobObject(t, object, err); string(body) != "v1" {
		t.Errorf("head holds %q", body)
	}
}

// §11.8's immutable row: a 412 on equal bytes is success, which a read tells from a fault.
func TestBlobImmutableRetryReadsEqualBytes(t *testing.T) {
	ctx := context.Background()
	cluster := newMemoryBlobCluster()
	body := []byte("a log page")

	if _, err := cluster.PutIfNoneMatch(ctx, "log/repo-1/ref-1/0", body, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.PutIfNoneMatch(ctx, "log/repo-1/ref-1/0", body, nil); !errors.Is(err, ErrBlobPrecondition) {
		t.Fatalf("second create: %v", err)
	}
	object, err := cluster.Get(ctx, "log/repo-1/ref-1/0")
	if !bytes.Equal(readBlobObject(t, object, err), body) {
		t.Error("the retry's bytes differ")
	}
}

// §11.8's write row: a batch goes up with its SHA-256 as its checksum.
func TestBlobChecksumRidesAPut(t *testing.T) {
	ctx := context.Background()
	cluster := newMemoryBlobCluster()
	batch := []byte("a batch")
	sum := sha256.Sum256(batch)
	if _, err := cluster.PutIfNoneMatch(ctx, "pb/2026110616/30/a-b", batch, &BlobPutOptions{Sha256: sum[:]}); err != nil {
		t.Fatal(err)
	}
	other := sha256.Sum256([]byte("other bytes"))
	if _, err := cluster.PutIfNoneMatch(ctx, "pb/2026110616/30/a-c", batch, &BlobPutOptions{Sha256: other[:]}); !errors.Is(err, ErrBlobChecksum) {
		t.Errorf("wrong checksum: %v", err)
	}
}

// §11.8 step 2: a segment streams through with its id as its checksum, and a client that lied about
// the id stores nothing.
func TestBlobSegmentStreamsUnderItsChecksum(t *testing.T) {
	ctx := context.Background()
	cluster := newMemoryBlobCluster()
	segment := []byte("sealed segment bytes")
	segmentId := sha256.Sum256(segment)

	if _, err := cluster.PutStream(ctx, "seg/repo-1/id", bytes.NewReader(segment), int64(len(segment)), segmentId[:]); err != nil {
		t.Fatal(err)
	}

	// §11.13's existing row: a re-upload meets the first, and a HEAD gives its age for the receipt
	if _, err := cluster.PutStream(ctx, "seg/repo-1/id", bytes.NewReader(segment), int64(len(segment)), segmentId[:]); !errors.Is(err, ErrBlobPrecondition) {
		t.Fatalf("re-upload: %v", err)
	}
	info, err := cluster.Head(ctx, "seg/repo-1/id")
	if err != nil {
		t.Fatal(err)
	}
	if info.LastModified.IsZero() || info.ByteCount != int64(len(segment)) {
		t.Errorf("info %+v", info)
	}

	otherId := sha256.Sum256([]byte("other bytes"))
	_, err = cluster.PutStream(ctx, "seg/repo-1/other", bytes.NewReader(segment), int64(len(segment)), otherId[:])
	if !errors.Is(err, ErrBlobChecksum) {
		t.Errorf("wrong id: %v", err)
	}
	if _, err := cluster.Head(ctx, "seg/repo-1/other"); !errors.Is(err, ErrBlobNotFound) {
		t.Errorf("the refused segment: %v", err)
	}
}

func TestBlobMissingKeyIsNotFound(t *testing.T) {
	ctx := context.Background()
	cluster := newMemoryBlobCluster()
	if _, err := cluster.Head(ctx, "seg/repo-1/id"); !errors.Is(err, ErrBlobNotFound) {
		t.Errorf("head: %v", err)
	}
	if _, err := cluster.Get(ctx, "seg/repo-1/id"); !errors.Is(err, ErrBlobNotFound) {
		t.Errorf("get: %v", err)
	}
	if _, err := cluster.GetRange(ctx, "seg/repo-1/id", 0, 1); !errors.Is(err, ErrBlobNotFound) {
		t.Errorf("get range: %v", err)
	}
}

// §11.8's read row: a record by its place in a batch, reporting the whole object's size.
func TestBlobGetRangeReadsARecordInPlace(t *testing.T) {
	ctx := context.Background()
	cluster := newMemoryBlobCluster()
	key := "pb/2026110616/30/a-b"
	if _, err := cluster.PutIfNoneMatch(ctx, key, []byte("0123456789"), nil); err != nil {
		t.Fatal(err)
	}

	object, err := cluster.GetRange(ctx, key, 2, 3)
	if body := readBlobObject(t, object, err); string(body) != "234" {
		t.Errorf("body %q", body)
	}
	if object.ByteCount != 10 {
		t.Errorf("byte count %d, want the whole object's", object.ByteCount)
	}

	// a span past the end stops there, and one starting past it is refused
	object, err = cluster.GetRange(ctx, key, 8, 5)
	if body := readBlobObject(t, object, err); string(body) != "89" {
		t.Errorf("body %q", body)
	}
	if _, err := cluster.GetRange(ctx, key, 10, 1); !errors.Is(err, ErrBlobRange) {
		t.Errorf("past the end: %v", err)
	}
}

// §11.13's nightly pass: bounded pages, resumed from the last key, under one prefix only.
func TestBlobListPagesInKeyOrder(t *testing.T) {
	ctx := context.Background()
	cluster := newMemoryBlobCluster()
	for _, key := range []string{"seg/repo-2/a", "seg/repo-1/c", "seg/repo-1/a", "seg/repo-1/b", "pack/repo-1/a"} {
		if _, err := cluster.PutIfNoneMatch(ctx, key, []byte(key), nil); err != nil {
			t.Fatal(err)
		}
	}

	keys := []string{}
	startAfter := ""
	for {
		objects, more, err := cluster.List(ctx, "seg/repo-1/", startAfter, 2)
		if err != nil {
			t.Fatal(err)
		}
		if 2 < len(objects) {
			t.Fatalf("page of %d", len(objects))
		}
		for _, object := range objects {
			keys = append(keys, object.Key)
			startAfter = object.Key
		}
		if !more {
			break
		}
	}
	if !slices.Equal(keys, []string{"seg/repo-1/a", "seg/repo-1/b", "seg/repo-1/c"}) {
		t.Errorf("keys %q", keys)
	}

	if _, _, err := cluster.List(ctx, "seg/", "", 0); err == nil {
		t.Error("an unbounded list was accepted")
	}
}

// §20.7's stored count reads sizes from LIST, and §11.13's orphan rule its LastModified.
func TestBlobListGivesSizeAndAge(t *testing.T) {
	ctx := context.Background()
	cluster := newMemoryBlobCluster()
	if _, err := cluster.PutIfNoneMatch(ctx, "seg/repo-1/a", []byte("four"), nil); err != nil {
		t.Fatal(err)
	}
	objects, _, err := cluster.List(ctx, "seg/", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 1 || objects[0].ByteCount != 4 || objects[0].LastModified.IsZero() {
		t.Errorf("objects %+v", objects)
	}
}

// §11.13: a DELETE answers alike whether or not the object was there, which is why the sweep HEADs.
func TestBlobDeleteOfAMissingKeySucceeds(t *testing.T) {
	ctx := context.Background()
	cluster := newMemoryBlobCluster()
	if _, err := cluster.PutIfNoneMatch(ctx, "slot/repo-1/s", []byte("slot"), nil); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i += 1 {
		if err := cluster.Delete(ctx, "slot/repo-1/s"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := cluster.Head(ctx, "slot/repo-1/s"); !errors.Is(err, ErrBlobNotFound) {
		t.Errorf("after delete: %v", err)
	}
}

// §11.7: an entry's state rides in object metadata, so a prefix check is a HEAD, not a GET of up to
// 512 KiB. A fold rewrites it If-Match, so both PUTs carry it.
func TestBlobMetadataRidesPutAndHead(t *testing.T) {
	ctx := context.Background()
	cluster := newMemoryBlobCluster()
	key := "idx/repo-1/ref-1/0/t1.e"
	etag, err := cluster.PutIfNoneMatch(ctx, key, []byte("entry"), &BlobPutOptions{Metadata: map[string]string{"entry-state": "fresh"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.PutIfMatch(ctx, key, etag, []byte("marker"), &BlobPutOptions{Metadata: map[string]string{"entry-state": "removed"}}); err != nil {
		t.Fatal(err)
	}
	info, err := cluster.Head(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if info.Metadata["entry-state"] != "removed" {
		t.Errorf("head's metadata %v", info.Metadata)
	}
	object, err := cluster.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	defer object.Body.Close()
	if object.Metadata["entry-state"] != "removed" {
		t.Errorf("get's metadata %v", object.Metadata)
	}
}

func TestBlobInvalidOptionsWriteNothing(t *testing.T) {
	ctx := context.Background()
	cluster := newMemoryBlobCluster()
	if _, err := cluster.PutIfNoneMatch(ctx, "pb/a", []byte("batch"), &BlobPutOptions{Sha256: []byte{1}}); !errors.Is(err, ErrBlobPutOptions) {
		t.Fatalf("err %v", err)
	}
	if _, err := cluster.Head(ctx, "pb/a"); !errors.Is(err, ErrBlobNotFound) {
		t.Errorf("head: %v", err)
	}
}

// What a lossyBlobCluster does to the next create.
type blobLoss int

const (
	// The create applies and its answer is lost.
	blobLossAfterApply blobLoss = iota + 1
	// The create never reaches the store, and the caller sees the same lost answer.
	blobLossBeforeApply
)

// memoryBlobCluster with lost answers: each create takes the next loss in creates, and each read the
// next in getErrs, so PutImmutable's paths run without a store that loses things. Counts every
// create it is asked for.
type lossyBlobCluster struct {
	*memoryBlobCluster
	creates     []blobLoss
	getErrs     []error
	createCount int
}

func (self *lossyBlobCluster) PutIfNoneMatch(ctx context.Context, key string, body []byte, options *BlobPutOptions) (string, error) {
	self.createCount += 1
	if len(self.creates) == 0 {
		return self.memoryBlobCluster.PutIfNoneMatch(ctx, key, body, options)
	}
	loss := self.creates[0]
	self.creates = self.creates[1:]
	if loss == blobLossAfterApply {
		if _, err := self.memoryBlobCluster.PutIfNoneMatch(ctx, key, body, options); err != nil {
			return "", err
		}
	}
	return "", &BlobUnknownError{Err: io.ErrUnexpectedEOF}
}

func (self *lossyBlobCluster) Get(ctx context.Context, key string) (*BlobObject, error) {
	if 0 < len(self.getErrs) {
		err := self.getErrs[0]
		self.getErrs = self.getErrs[1:]
		return nil, err
	}
	return self.memoryBlobCluster.Get(ctx, key)
}

func wantBlobBody(t *testing.T, cluster BlobCluster, key string, want []byte) {
	t.Helper()
	object, err := cluster.Get(context.Background(), key)
	if body := readBlobObject(t, object, err); !bytes.Equal(body, want) {
		t.Errorf("%s holds %q, want %q", key, body, want)
	}
}

func TestPutImmutableCreates(t *testing.T) {
	cluster := newMemoryBlobCluster()
	etag, err := PutImmutable(context.Background(), cluster, "log/repo-1/ref-1/0", []byte("a page"), nil)
	if err != nil {
		t.Fatal(err)
	}
	info, err := cluster.Head(context.Background(), "log/repo-1/ref-1/0")
	if err != nil {
		t.Fatal(err)
	}
	if info.Etag != etag {
		t.Errorf("etag %q, the key holds %q", etag, info.Etag)
	}
}

// §11.8's immutable row: a retry of one's own create finds its bytes, and that is success, with the
// ETag the key holds.
func TestPutImmutableEqualBytesOnA412AreSuccess(t *testing.T) {
	ctx := context.Background()
	cluster := newMemoryBlobCluster()
	first, err := PutImmutable(ctx, cluster, "pidx/repo-1/ref-1/x", []byte("entry"), nil)
	if err != nil {
		t.Fatal(err)
	}
	again, err := PutImmutable(ctx, cluster, "pidx/repo-1/ref-1/x", []byte("entry"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if again != first {
		t.Errorf("etag %q, the key holds %q", again, first)
	}
}

// Other bytes at an immutable key are a fault, never success, whichever is longer.
func TestPutImmutableOtherBytesOnA412Alarm(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		held    string
		written string
	}{
		{held: "entry", written: "other"},
		{held: "entry", written: "entr"},
		{held: "entr", written: "entry"},
		{held: "", written: "entry"},
		{held: "entry", written: ""},
	} {
		cluster := newMemoryBlobCluster()
		if _, err := cluster.PutIfNoneMatch(ctx, "hp/repo-1/p", []byte(c.held), nil); err != nil {
			t.Fatal(err)
		}
		if _, err := PutImmutable(ctx, cluster, "hp/repo-1/p", []byte(c.written), nil); !errors.Is(err, ErrBlobImmutableMismatch) {
			t.Errorf("%q over %q: %v", c.written, c.held, err)
		}
		wantBlobBody(t, cluster, "hp/repo-1/p", []byte(c.held))
	}
}

// §11.8's write row: an unknown outcome GETs the key, and equal bytes were written.
func TestPutImmutableLostAnswerThatLandedIsSuccess(t *testing.T) {
	cluster := &lossyBlobCluster{memoryBlobCluster: newMemoryBlobCluster(), creates: []blobLoss{blobLossAfterApply}}
	etag, err := PutImmutable(context.Background(), cluster, "pb/2026110616/30/a-b", []byte("batch"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if etag == "" {
		t.Error("success with no etag")
	}
	if cluster.createCount != 1 {
		t.Errorf("%d creates for one that landed", cluster.createCount)
	}
}

// A 404 after an unknown outcome means it never landed, so the same bytes go again.
func TestPutImmutableLostCreateIsWrittenAgain(t *testing.T) {
	cluster := &lossyBlobCluster{memoryBlobCluster: newMemoryBlobCluster(), creates: []blobLoss{blobLossBeforeApply}}
	if _, err := PutImmutable(context.Background(), cluster, "pb/2026110616/30/a-b", []byte("batch"), nil); err != nil {
		t.Fatal(err)
	}
	if cluster.createCount != 2 {
		t.Errorf("%d creates", cluster.createCount)
	}
	wantBlobBody(t, cluster, "pb/2026110616/30/a-b", []byte("batch"))
}

// Written again once, and no more: a second lost create leaves the outcome the caller's.
func TestPutImmutableGivesUpUnknownAfterTwoLostCreates(t *testing.T) {
	cluster := &lossyBlobCluster{
		memoryBlobCluster: newMemoryBlobCluster(),
		creates:           []blobLoss{blobLossBeforeApply, blobLossBeforeApply, blobLossBeforeApply},
	}
	_, err := PutImmutable(context.Background(), cluster, "pb/2026110616/30/a-b", []byte("batch"), nil)
	var unknown *BlobUnknownError
	if !errors.As(err, &unknown) {
		t.Fatalf("err %v", err)
	}
	if cluster.createCount != blobImmutableWriteCount {
		t.Errorf("%d creates", cluster.createCount)
	}
}

// A read that cannot answer leaves the create unknown, so the caller rereads rather than trusts it.
func TestPutImmutableUnreadableAfterALostAnswerStaysUnknown(t *testing.T) {
	for _, getErr := range []error{ErrBlobHeld, io.ErrUnexpectedEOF} {
		cluster := &lossyBlobCluster{
			memoryBlobCluster: newMemoryBlobCluster(),
			creates:           []blobLoss{blobLossAfterApply},
			getErrs:           []error{getErr},
		}
		_, err := PutImmutable(context.Background(), cluster, "log/repo-1/ref-1/0", []byte("a page"), nil)
		var unknown *BlobUnknownError
		if !errors.As(err, &unknown) {
			t.Errorf("read %v: err %v", getErr, err)
		}
		if cluster.createCount != 1 {
			t.Errorf("read %v: %d creates", getErr, cluster.createCount)
		}
	}
}

// Another writer's bytes found after a lost answer are the same fault as after a 412.
func TestPutImmutableOtherBytesAfterALostAnswerAlarm(t *testing.T) {
	ctx := context.Background()
	cluster := &lossyBlobCluster{memoryBlobCluster: newMemoryBlobCluster(), creates: []blobLoss{blobLossBeforeApply}}
	if _, err := cluster.memoryBlobCluster.PutIfNoneMatch(ctx, "log/repo-1/ref-1/0", []byte("theirs"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := PutImmutable(ctx, cluster, "log/repo-1/ref-1/0", []byte("mine"), nil); !errors.Is(err, ErrBlobImmutableMismatch) {
		t.Errorf("err %v", err)
	}
}

// A 412 whose key is gone before its read-back stands for nothing: deleted whole, by evacuation or GC.
func TestPutImmutableKeyGoneAfterA412IsNoSuccess(t *testing.T) {
	cluster := &lossyBlobCluster{memoryBlobCluster: newMemoryBlobCluster(), getErrs: []error{ErrBlobNotFound}}
	ctx := context.Background()
	if _, err := cluster.memoryBlobCluster.PutIfNoneMatch(ctx, "pb/2026110616/30/a-b", []byte("batch"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := PutImmutable(ctx, cluster, "pb/2026110616/30/a-b", []byte("batch"), nil); !errors.Is(err, ErrBlobPrecondition) {
		t.Errorf("err %v", err)
	}
}

// A definite refusal is passed through: nothing was written, and the outcome is known.
func TestPutImmutablePassesDefiniteRefusalsThrough(t *testing.T) {
	ctx := context.Background()
	cluster := newMemoryBlobCluster()
	if _, err := PutImmutable(ctx, cluster, "pb/a", []byte("batch"), &BlobPutOptions{Sha256: []byte{1}}); !errors.Is(err, ErrBlobPutOptions) {
		t.Errorf("options: %v", err)
	}
	other := sha256.Sum256([]byte("other"))
	if _, err := PutImmutable(ctx, cluster, "pb/a", []byte("batch"), &BlobPutOptions{Sha256: other[:]}); !errors.Is(err, ErrBlobChecksum) {
		t.Errorf("checksum: %v", err)
	}
	if _, err := cluster.Head(ctx, "pb/a"); !errors.Is(err, ErrBlobNotFound) {
		t.Errorf("head: %v", err)
	}
}

func TestWithBlobUnmodifiedNamesTheObject(t *testing.T) {
	if _, ok := BlobUnmodified(context.Background()); ok {
		t.Error("a plain context names an object")
	}
	listed := time.Unix(1000, 250_000_000)
	ctx := WithBlobUnmodified(context.Background(), listed)
	got, ok := BlobUnmodified(ctx)
	if !ok || !got.Equal(listed) {
		t.Errorf("named %v, %t", got, ok)
	}
	// a deadline and a name ride one context without touching each other
	ctx = WithBlobDeadline(ctx, time.Unix(2000, 0))
	if got, ok := BlobUnmodified(ctx); !ok || !got.Equal(listed) {
		t.Errorf("after a deadline: named %v, %t", got, ok)
	}
	if deadline := BlobRequestDeadline(ctx, time.Unix(1990, 0), time.Minute); !deadline.Equal(time.Unix(2000, 0)) {
		t.Errorf("deadline %v", deadline)
	}
}

// The store's rule (§19.6): an object stored a second or more after the time named is another object.
func TestBlobUnmodifiedRefusesAnObjectStoredASecondLater(t *testing.T) {
	named := time.UnixMilli(1_700_000_000_500)
	cases := []struct {
		stored  time.Duration
		refused bool
	}{
		{stored: 0, refused: false},
		{stored: -5 * time.Second, refused: false},
		{stored: 500 * time.Millisecond, refused: false},
		{stored: 999 * time.Millisecond, refused: false},
		{stored: 1 * time.Second, refused: true},
		{stored: 49 * time.Hour, refused: true},
	}
	for _, c := range cases {
		if refused := BlobUnmodifiedRefuses(named, named.Add(c.stored)); refused != c.refused {
			t.Errorf("an object stored %v after the time named: refused %t", c.stored, refused)
		}
	}
	// a time read from a HEAD has whole seconds, and still names its object
	stored := time.UnixMilli(1_700_000_000_999)
	if BlobUnmodifiedRefuses(stored.Truncate(time.Second), stored) {
		t.Error("a LastModified cut to the second no longer names its object")
	}
}
