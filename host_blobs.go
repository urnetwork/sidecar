//go:build !sidecar_http && !ios_extension

// ServiceHost.Blobs: the file clusters (§11.8, §11.13, §19.6), whose interfaces, records and sentinel
// errors are operator-core's (owner decision 251); the context helpers and PutImmutable stay here. evs
// and gkm keep every durable thing here, each repo's metadata objects on the one metadata cluster its create-only place/<repo_id>
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
	"time"

	operator "github.com/urnetwork/operator-core"
)

// operator-core's sentinels, so errors.Is reads one value on both sides.
var (
	// A Get, GetRange or Head of a key that does not exist.
	ErrBlobNotFound = operator.ErrBlobNotFound
	// A PUT's condition failed and nothing was written, or a Delete that named its object found a newer
	// one under its key and deleted nothing.
	ErrBlobPrecondition = operator.ErrBlobPrecondition
	// §19.6's settle holds the key, so the request took no effect.
	ErrBlobHeld = operator.ErrBlobHeld
	// A PUT's body does not hash to its checksum, and nothing was written.
	ErrBlobChecksum = operator.ErrBlobChecksum
	// A GetRange that starts at or past the object's end.
	ErrBlobRange = operator.ErrBlobRange
	// No cluster this process holds credentials for (§19.4).
	ErrBlobClusterUnknown = operator.ErrBlobClusterUnknown
	// A PUT's arguments fail their rules, so nothing was sent.
	ErrBlobPutOptions = operator.ErrBlobPutOptions
	// An immutable key holds bytes other than the ones a create of it carried. Nothing was written.
	ErrBlobImmutableMismatch = operator.ErrBlobImmutableMismatch
)

// How many times PutImmutable sends one create: once, and once more after a read shows an unknown
// outcome never landed (§11.8's write row, "404 written again with the same bytes"). A protocol step
// and not a tunable: past it the outcome stays the caller's to resolve, as its section says.
const blobImmutableWriteCount = 2

// A PUT or DELETE that may have applied, or may yet apply before the next request on its key. The caller
// rereads (§11.8's unknown row), and deletes nothing on the strength of it (I-EVS-2).
type BlobUnknownError = operator.BlobUnknownError

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

// The clusters of one deployment, by cluster id.
type BlobStore = operator.BlobStore

// One cluster's bucket. See the file header for what every method promises.
type BlobCluster = operator.BlobCluster

// What rides a PUT beyond its condition, with the Validate every implementation runs before it sends.
type BlobPutOptions = operator.BlobPutOptions

// One object, as Head, Get and List see it.
type BlobInfo = operator.BlobInfo

// An open Get. Body holds the bytes asked for, and the caller closes it.
type BlobObject = operator.BlobObject
