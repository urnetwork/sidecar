//go:build !sidecar_http && !ios_extension

// ServiceHost.Blobs: the file clusters (§11.8, §11.13, §19.6). evs and gkm keep every durable thing
// here, each repo's metadata objects on the one metadata cluster its create-only place/<repo_id>
// names, and segments and packs on the segment cluster. Each cluster has its own endpoint, credentials
// and unversioned bucket, so a DELETE or overwrite keeps no prior version (owner decision 90).
//
// What every implementation declares, on every cluster, and §22.9's store suite checks per build,
// upgrade and cluster:
//
//   - One condition decides a race. A conditional PUT is evaluated under quorum, so of two racing
//     creates exactly one wins, and a head's history is its successful If-Match PUTs in order. There is
//     no unconditional PUT, so no call site can overwrite a commit point by leaving a condition out.
//   - Consistent reads. GET, HEAD and LIST see every write answered before they were issued.
//   - The settle rule (D-OPS-20): a PUT or DELETE takes effect before every later request on its key,
//     or never, even when its answer was lost, cancelled or timed out. So a read after an unknown
//     outcome tells what happened.
//   - The deadline rule: a request is refused once its deadline has passed, and no drive commit of it
//     begins past that. Each request but PutStream carries BlobRequestDeadline as x-ur-deadline-ms,
//     which covers the response's start: a body then streams under ctx alone. Cancelling ctx, or
//     reaching its deadline, abandons a request, whose outcome is then unknown, and tells the store
//     nothing: a caller whose margin needs the store to stop at a time says so with WithBlobDeadline.
//
// A PUT or DELETE that fails with anything but ErrBlobPrecondition, ErrBlobHeld, ErrBlobChecksum or
// ErrBlobPutOptions has an unknown outcome, however definite it reads: a timeout, EOF and a 5xx alike
// (§11.8's unknown row). Implementations say so with BlobUnknownError. Never retry past one on faith:
// reread, as the owning section says.
//
// No key prefixes another, since MinIO stores an object as a directory and lists it without descending
// (§11.3): §11.8's keys end in .e or /_ for this. Keys are opaque ids and tokens, never names (I-13).

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

var (
	// A Get, GetRange or Head of a key that does not exist. For a ranged read at a place, the batch has
	// gone, and §11.8's read row finds the record in pidx/.
	ErrBlobNotFound = errors.New("blob not found")
	// A PUT's condition failed and nothing was written: an If-None-Match on a key that exists, or an
	// If-Match on one that has moved or does not exist. Or a Delete that named its object with
	// WithBlobUnmodified found a newer one under its key, and deleted nothing.
	ErrBlobPrecondition = errors.New("blob precondition failed")
	// §19.6's settle holds the key, so the request waited and got a 503 and took no effect. A write
	// before it on the key is still settling: the caller retries later, and a key held past a minute
	// pages (§19.8).
	ErrBlobHeld = errors.New("blob key held")
	// A PUT's body does not hash to its checksum, and nothing was written. For a segment, the client
	// sent bytes other than the id it named.
	ErrBlobChecksum = errors.New("blob checksum mismatch")
	// A GetRange that starts at or past the object's end.
	ErrBlobRange = errors.New("blob range not satisfiable")
	// No cluster this process holds credentials for (§19.4): gkm has no segment cluster, and api only
	// the first.
	ErrBlobClusterUnknown = errors.New("blob cluster unknown")
	// A PUT's arguments fail their rules, so nothing was sent.
	ErrBlobPutOptions = errors.New("blob put options invalid")
	// An immutable key holds bytes other than the ones a create of it carried: two writers disagree on
	// what a key created once holds, a fault the caller alarms (§11.8's immutable and write rows).
	// Nothing was written.
	ErrBlobImmutableMismatch = errors.New("blob immutable key holds other bytes")
)

// How many times PutImmutable sends one create: once, and once more after a read shows an unknown
// outcome never landed (§11.8's write row, "404 written again with the same bytes"). A protocol step
// and not a tunable: past it the outcome stays the caller's to resolve, as its section says.
const blobImmutableWriteCount = 2

// The store's limits on a PUT's metadata (minio/cmd/generic-handlers.go, maxUserDataSize): 2 KiB,
// counting each key with the header prefix it travels under. Format values, not settings.
const (
	blobMetadataMaxByteCount = 2 * 1024
	blobMetadataKeyPrefix    = "x-amz-meta-"
)

// A PUT or DELETE that may have applied, or may yet apply before the next request on its key: a
// timeout, an EOF or a 5xx. The caller rereads (§11.8's unknown row), and deletes nothing on the
// strength of it (I-EVS-2). Err is what the transport said, for logs only.
type BlobUnknownError struct {
	Err error
}

// Names the cause, for logs only.
func (self *BlobUnknownError) Error() string {
	return fmt.Sprintf("blob outcome unknown: %v", self.Err)
}

// What the transport said.
func (self *BlobUnknownError) Unwrap() error {
	return self.Err
}

// The context key WithBlobDeadline stores under.
type blobDeadlineKey struct{}

// ctx with a request's own store deadline: a fold's or copy's write, 15 s after the head read it
// relies on (§11.7's stale row), or a marker's or drop's DELETE, 50 ms before until_ms (§11.7's collect
// row, §11.13). An earlier deadline already on ctx stands, since a caller may shorten a request, never
// lengthen one.
//
// This is a value and not context.WithDeadline because a margin is a time on the deadline's own clock:
// T2's fake holds it against an injected clock, which a context's real timer would fire past. A real
// implementation also cancels the request at it (§19.6).
func WithBlobDeadline(ctx context.Context, deadline time.Time) context.Context {
	if earlier, ok := ctx.Value(blobDeadlineKey{}).(time.Time); ok && earlier.Before(deadline) {
		return ctx
	}
	return context.WithValue(ctx, blobDeadlineKey{}, deadline)
}

// The context key WithBlobUnmodified stores under.
type blobUnmodifiedKey struct{}

// How far past the time a Delete names an object's LastModified may be and still be the object it
// means: under a second, since a caller may pass a time it read from a HEAD, whose Last-Modified has
// whole seconds (§19.6). The store's rule, so a format value and not a setting.
const BlobUnmodifiedSlack = 1 * time.Second

// ctx for a Delete that names its object: lastModified is the LastModified its caller read, from a
// LIST or a HEAD, of the object it means to delete. The store compares under the key's lock, and an
// object stored BlobUnmodifiedSlack or more after that time is another object, so the Delete answers
// ErrBlobPrecondition and deletes nothing (§19.6, x-ur-if-unmodified-ms). A key already gone is nil, as
// for any Delete.
//
// This is how a deletion decided on a listing takes only what was listed (§11.13): orphan GC, the
// nightly pass and the sweep send it, so a run that wakes late, or beside its successor, removes the
// object it judged or nothing, however a key was written since. A Delete on a ctx without it is
// unconditional, as a marker's collection and the versionless purge are.
func WithBlobUnmodified(ctx context.Context, lastModified time.Time) context.Context {
	return context.WithValue(ctx, blobUnmodifiedKey{}, lastModified)
}

// The LastModified a Delete on ctx names, and whether it names one: what an implementation sends as
// x-ur-if-unmodified-ms, in Unix ms.
func BlobUnmodified(ctx context.Context) (lastModified time.Time, ok bool) {
	lastModified, ok = ctx.Value(blobUnmodifiedKey{}).(time.Time)
	return lastModified, ok
}

// Whether a Delete naming named must refuse an object stored at lastModified: the store's rule, in
// whole ms, which every implementation and T2's fake keep alike.
func BlobUnmodifiedRefuses(named time.Time, lastModified time.Time) bool {
	return named.UnixMilli()+BlobUnmodifiedSlack.Milliseconds() <= lastModified.UnixMilli()
}

// What a request issued at issued carries as x-ur-deadline-ms (Unix ms by the sender's clock):
// requestTimeout after issued, or WithBlobDeadline's when that comes first (§19.6). ctx's own real-time
// deadline stays out of it, as it can name a later clock than a fake's, and the implementation cancels
// by it anyway.
func BlobRequestDeadline(ctx context.Context, issued time.Time, requestTimeout time.Duration) time.Time {
	deadline := issued.Add(requestTimeout)
	if own, ok := ctx.Value(blobDeadlineKey{}).(time.Time); ok && own.Before(deadline) {
		return own
	}
	return deadline
}

// §11.8's create of an immutable key (place/, log/, pb/, hp/, pmap/, pidx/, spidx/, dropscan/ and any
// other family its immutable row names): creates key holding body and returns the ETag it holds. The
// one helper every family's writer calls, so each answers a lost response alike (D-EVS-13):
//
//   - A 412 reads the key back. Equal bytes are success, as a retry of one's own create finds them;
//     other bytes are ErrBlobImmutableMismatch, which the caller alarms.
//   - An unknown outcome reads the key back too, since the settle rule makes that read tell what
//     happened (D-OPS-20): equal bytes were written, other bytes are ErrBlobImmutableMismatch, and a 404
//     means the create never landed and never will, so the same bytes go once more.
//   - When the read cannot tell, or the second create's outcome is unknown too, the BlobUnknownError
//     comes back: the key may yet hold body, and the caller rereads as its section says (§11.8's
//     unknown row).
//   - A 412 whose read-back finds no key is ErrBlobPrecondition: what stood there was deleted whole, as
//     only evacuation, packing and GC delete immutable keys, so neither its bytes nor these stand.
//
// Bytes alone are compared, since an immutable family carries no object metadata (§19.6). options
// rides each create, so a checksum is verified on the second as on the first. Segments and packs
// stream, and take PutStream's own 412 rule.
func PutImmutable(ctx context.Context, cluster BlobCluster, key string, body []byte, options *BlobPutOptions) (etag string, err error) {
	// what the key holds now: found false for none, and ErrBlobImmutableMismatch for other bytes
	readBack := func() (heldEtag string, found bool, err error) {
		object, err := cluster.Get(ctx, key)
		if errors.Is(err, ErrBlobNotFound) {
			return "", false, nil
		}
		if err != nil {
			return "", false, err
		}
		defer object.Body.Close()
		// one byte past body is enough to tell a longer object
		held, err := io.ReadAll(io.LimitReader(object.Body, int64(len(body))+1))
		if err != nil {
			return "", false, err
		}
		if !bytes.Equal(held, body) {
			return "", true, fmt.Errorf("%w: %s", ErrBlobImmutableMismatch, key)
		}
		return object.Etag, true, nil
	}

	for writeCount := 1; ; writeCount += 1 {
		newEtag, err := cluster.PutIfNoneMatch(ctx, key, body, options)
		var unknown *BlobUnknownError
		switch {
		case err == nil:
			return newEtag, nil
		case errors.Is(err, ErrBlobPrecondition):
			heldEtag, found, readErr := readBack()
			if readErr != nil {
				return "", readErr
			}
			if !found {
				return "", fmt.Errorf("%w: %s existed and is gone", ErrBlobPrecondition, key)
			}
			return heldEtag, nil
		case errors.As(err, &unknown):
			heldEtag, found, readErr := readBack()
			switch {
			case errors.Is(readErr, ErrBlobImmutableMismatch):
				return "", readErr
			case readErr != nil:
				// the read could not tell, so the create's outcome stays unknown
				return "", err
			case found:
				return heldEtag, nil
			case blobImmutableWriteCount <= writeCount:
				return "", err
			}
			// it never landed, and by the settle rule it never will: send the same bytes again
		default:
			return "", err
		}
	}
}

// The clusters of one deployment, by cluster id: the names sidecar.yml uses, such as place_new's
// meta-1, and place/<repo_id> records. Ids are stable, so a repo's place/ always resolves. A lookup
// dials nothing, so an engine may call these per request.
type BlobStore interface {
	// One cluster, or ErrBlobClusterUnknown.
	Cluster(clusterId string) (BlobCluster, error)
	// The first metadata cluster, the only one holding place/, proj/, projrows/, rev/, hold/ and
	// per-sidecar gkm/ objects (§11.8).
	FirstCluster() (BlobCluster, error)
	// Where seg/, pack/ and dropscan/ live.
	SegmentCluster() (BlobCluster, error)
	// Every metadata cluster, the first first: what a recovery fetch and evacuation walk (§10.6,
	// §11.13).
	MetadataClusterIds() []string
	// The metadata cluster that takes new repos: sidecar.yml's place_new, the first when absent
	// (§19.9). It changes as the host rereads its config, and it may name a cluster Cluster refuses,
	// which evs answers 503.
	NewRepoClusterId() string
}

// One cluster's bucket. See the file header for what every method promises.
type BlobCluster interface {
	// Its id in BlobStore.
	ClusterId() string
	// §19.6's store request deadline, 10 s on both clusters. What a waiter waits: §11.8's unknown row
	// and §11.13's orphan and GC rules wait this long, so it is read from here and kept nowhere else.
	RequestTimeout() time.Duration
	// Whether this cluster's build passed §22.9's settle cases (FS-114). False: taskworker opens no
	// collection window and v1's purge and drop jobs delete nothing, keeping markers and candidates
	// (§11.7, §19.6). A host that cannot tell answers false, and answers false after an upgrade until
	// the suite has passed on the new build.
	SettlePassed() bool

	// Creates key, returning its ETag, or ErrBlobPrecondition when it exists. One request. A 412 on an
	// immutable family reads the key back, and equal bytes are success (§11.8).
	PutIfNoneMatch(ctx context.Context, key string, body []byte, options *BlobPutOptions) (newEtag string, err error)
	// Replaces key while it still has etag, returning its new ETag: §11.8 step 7's commit. A missing key
	// is ErrBlobPrecondition too. An empty etag is ErrBlobPutOptions and sends nothing, since an
	// If-Match left off is the blind overwrite this interface exists to rule out.
	PutIfMatch(ctx context.Context, key string, etag string, body []byte, options *BlobPutOptions) (newEtag string, err error)
	// Creates key from a body streamed through, a segment from a client's upload (§11.8 step 2), with
	// its id as its checksum. byteCount is exact, and a body of any other length fails without writing.
	// The only call with no deadline, since the uploader sets the pace: the store bounds it 40 s after
	// its last byte, and this client cancels it RequestTimeout after that byte if no response came.
	PutStream(ctx context.Context, key string, body io.Reader, byteCount int64, checksumSha256 []byte) (newEtag string, err error)
	// Opens the whole object in one round trip: its bytes and BlobInfo. The caller closes the body.
	Get(ctx context.Context, key string) (*BlobObject, error)
	// Opens byteCount bytes from offset: a batch record by its place (§11.8), or a record in a pack
	// (§11.13). A span past the object's end stops there, and one starting at or past it is
	// ErrBlobRange. BlobInfo.ByteCount stays the whole object's.
	GetRange(ctx context.Context, key string, offset int64, byteCount int64) (*BlobObject, error)
	// What Get would describe, with no body: an object's age from LastModified (§11.13), an entry's
	// state from Metadata (§11.7).
	Head(ctx context.Context, key string) (*BlobInfo, error)
	// Keys under keyPrefix strictly after startAfter, ascending by byte, at most limit of them, and
	// whether more follow, so a night's pass pages through a repo and checkpoints between pages
	// (connect/CODESTYLE.md:135). Each has its Key, ByteCount, Etag and LastModified, never Metadata. A
	// limit that is not positive is an error.
	List(ctx context.Context, keyPrefix string, startAfter string, limit int) (objects []*BlobInfo, more bool, err error)
	// Unconditional, since upstream's store evaluates no precondition on a DELETE (§11.3), unless ctx
	// names the object with WithBlobUnmodified: §19.6's build then deletes only an object stored under
	// BlobUnmodifiedSlack after that time, and answers ErrBlobPrecondition, deleting nothing, for a
	// newer one. nil for a key already gone (§11.13), named or not, so a HEAD first is what tells the
	// two apart.
	Delete(ctx context.Context, key string) error
}

// What rides a PUT beyond its condition. nil means none of it.
type BlobPutOptions struct {
	// Sent as x-amz-checksum-sha256, which the store verifies before the object exists: pb/ and pack/
	// PUTs (§11.8). Empty: none. Otherwise 32 bytes.
	Sha256 []byte
	// Object metadata, read back by Head and Get: an idx/ entry's state while a head lists sources
	// (§11.7). Nil for every other family, which carries none (§19.6). Keys are lowercase letters,
	// digits and dashes, and values printable ASCII with no space at either end, which an HTTP header
	// drops: what a store's headers carry unchanged, so T2's fake and the store agree. The store takes
	// 2 KiB of them, keys included.
	Metadata map[string]string
}

// What every implementation checks before it sends anything, so a fake and the store refuse alike. A
// failure wraps ErrBlobPutOptions.
func (self *BlobPutOptions) Validate() error {
	if self == nil {
		return nil
	}
	if len(self.Sha256) != 0 && len(self.Sha256) != 32 {
		return fmt.Errorf("%w: a %d byte checksum", ErrBlobPutOptions, len(self.Sha256))
	}
	metadataByteCount := 0
	for key, value := range self.Metadata {
		if key == "" {
			return fmt.Errorf("%w: an empty metadata key", ErrBlobPutOptions)
		}
		metadataByteCount += len(blobMetadataKeyPrefix) + len(key) + len(value)
		for i := 0; i < len(key); i += 1 {
			c := key[i]
			if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
				return fmt.Errorf("%w: byte %d of a metadata key", ErrBlobPutOptions, i)
			}
		}
		for i := 0; i < len(value); i += 1 {
			if c := value[i]; c < ' ' || '~' < c {
				return fmt.Errorf("%w: byte %d of a metadata value", ErrBlobPutOptions, i)
			}
		}
		if strings.HasPrefix(value, " ") || strings.HasSuffix(value, " ") {
			return fmt.Errorf("%w: a space at the end of a metadata value", ErrBlobPutOptions)
		}
	}
	if blobMetadataMaxByteCount < metadataByteCount {
		return fmt.Errorf("%w: %d bytes of metadata", ErrBlobPutOptions, metadataByteCount)
	}
	return nil
}

// One object, as Head, Get and List see it.
type BlobInfo struct {
	// The key, as a call named it or List found it.
	Key string
	// The whole object's size, even for a GetRange.
	ByteCount int64
	// Opaque: compare it and hand it to PutIfMatch, never parse it. A head never repeats one, since
	// every write raises its version or fence (§11.8's etag row).
	Etag string
	// The store's clock: §11.13's 23 h and 25 h age rules read it.
	LastModified time.Time
	// What BlobPutOptions.Metadata set. Nil from List, and for an object with none.
	Metadata map[string]string
}

// An open Get. Body holds the bytes asked for, and the caller closes it.
type BlobObject struct {
	BlobInfo
	Body io.ReadCloser
}
