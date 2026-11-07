// The store conformance suite for ServiceHost.Blobs (§22.9's file clusters, §11.13's needs row): what
// host_blobs.go declares, run against a fake here and against a real store by whoever hosts one, so
// the fake stays honest (D-TEST-2) and each build, upgrade and cluster proves itself. Every case runs
// through BlobCluster alone and uses keys of its own under a fresh prefix, so a run needs no empty
// bucket and leaves little behind.
//
// Two rule groups depend on the store. Deadlines and settle hold only on D-OPS-20's build, so a stock
// MinIO cannot run them, and Target.Settle says which it is: a target that leaves it nil reports them
// as waiting, by name, in t.Log, and they do not pass by silence. Host and quorum loss need more than
// one process, so they stay with FS-1 and FS-40 at T3.
//
// A case is a plain function returning its first failure, and Run loops over them, since one store's
// cases are homogeneous variations (connect/CODESTYLE.md:216). A failure in one does not stop the next.

package blobsuite

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// What a settle-capable store lets the suite do: read its clock, and reach it as a request the network
// held past its deadline does.
type Settle struct {
	// The store's clock, as the suite must read it to set a deadline in the past of it.
	Now func() time.Time
	// Target.Cluster through a client that sends each request's x-ur-deadline-ms and never cancels at
	// it, as a request the network held past its deadline reaches the store (FS-114). A client that
	// cancels at the deadline never lets a late request reach the store, so a settle case through it
	// passes whatever the store does. nil fails the settle cases. A fake judging deadlines in the store
	// itself, with no cancel of its own, is its own.
	Delayed sidecar.BlobCluster
}

type Target struct {
	// The cluster under test.
	Cluster sidecar.BlobCluster
	// The store's clock, for LastModified: time.Now on a real store, the fake's otherwise.
	Now func() time.Time
	// How far LastModified may sit from Now: real stores round it to the second.
	ClockTolerance time.Duration
	// Non-nil on a store that keeps D-OPS-20's deadline and settle rules. nil: those cases wait.
	Settle *Settle
}

type suiteCase struct {
	name string
	run  func(ctx context.Context, target *Target, keys *keySpace) error
}

// A case's own part of the bucket. Every key ends in /_ so none prefixes another (§11.8).
type keySpace struct {
	prefix string
}

func (self *keySpace) key(name string) string {
	return self.prefix + name + "/_"
}

func newRunId() string {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(random[:])
}

// Runs every case on target, each under a prefix of its own.
func Run(t *testing.T, target *Target) {
	t.Helper()
	ctx := t.Context()
	runId := newRunId()
	for _, c := range cases() {
		keys := &keySpace{prefix: fmt.Sprintf("blobsuite/%s/%s/", runId, c.name)}
		if err := c.run(ctx, target, keys); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		cleanup(ctx, target.Cluster, keys.prefix)
	}
	if target.Settle == nil {
		for _, c := range settleCases() {
			t.Logf("waits for D-OPS-20's build: %s", c.name)
		}
		return
	}
	for _, c := range settleCases() {
		keys := &keySpace{prefix: fmt.Sprintf("blobsuite/%s/%s/", runId, c.name)}
		if err := c.run(ctx, target, keys); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		cleanup(ctx, target.Cluster, keys.prefix)
	}
}

// Best effort: what a failure leaves stays under its run's prefix.
func cleanup(ctx context.Context, cluster sidecar.BlobCluster, prefix string) {
	for {
		objects, more, err := cluster.List(ctx, prefix, "", 1000)
		if err != nil {
			return
		}
		for _, object := range objects {
			if err := cluster.Delete(ctx, object.Key); err != nil {
				return
			}
		}
		if !more {
			return
		}
	}
}

func cases() []*suiteCase {
	return []*suiteCase{
		{name: "identity", run: caseIdentity},
		{name: "create-wins-once", run: caseCreateWinsOnce},
		{name: "racing-creates-have-one-winner", run: caseRacingCreates},
		{name: "if-match-replaces", run: caseIfMatchReplaces},
		{name: "stale-etag-writes-nothing", run: caseStaleEtag},
		{name: "if-match-on-a-missing-key", run: caseIfMatchMissingKey},
		{name: "if-match-after-a-delete", run: caseIfMatchAfterDelete},
		{name: "empty-etag-sends-nothing", run: caseEmptyEtag},
		{name: "racing-if-match-has-one-winner", run: caseRacingIfMatch},
		{name: "etag-follows-the-bytes", run: caseEtagFollowsBytes},
		{name: "read-after-write", run: caseReadAfterWrite},
		{name: "missing-key-is-not-found", run: caseMissingKey},
		{name: "ranged-get", run: caseRangedGet},
		{name: "ranged-get-of-an-empty-object", run: caseRangedGetEmpty},
		{name: "key-bytes-survive", run: caseKeyBytes},
		{name: "head-describes-without-a-body", run: caseHead},
		{name: "list-order-and-start-after", run: caseListOrder},
		{name: "list-pages", run: caseListPages},
		{name: "list-gives-size-and-age-not-metadata", run: caseListFields},
		{name: "list-sees-writes-and-deletes", run: caseListConsistency},
		{name: "list-refuses-a-bad-limit", run: caseListLimit},
		{name: "delete-of-a-missing-key", run: caseDeleteMissing},
		{name: "delete-then-create", run: caseDeleteThenCreate},
		{name: "metadata-rides-put", run: caseMetadata},
		{name: "metadata-at-its-limit", run: caseMetadataLimit},
		{name: "invalid-options-write-nothing", run: caseInvalidOptions},
		{name: "checksum-is-verified", run: caseChecksum},
		{name: "put-stream", run: casePutStream},
		{name: "put-stream-length-is-exact", run: casePutStreamLength},
		{name: "put-stream-checksum-is-verified", run: casePutStreamChecksum},
		{name: "put-stream-does-not-overwrite", run: casePutStreamExists},
		{name: "put-stream-names-its-checksum", run: casePutStreamNoChecksum},
		{name: "empty-and-large-bodies", run: caseBodySizes},
		{name: "last-modified-is-the-stores-clock", run: caseLastModified},
	}
}

func settleCases() []*suiteCase {
	return []*suiteCase{
		{name: "request-past-its-deadline-is-refused", run: caseDeadlineRefused},
		{name: "delete-past-its-deadline-deletes-nothing", run: caseDeadlineDelete},
	}
}

func readAll(object *sidecar.BlobObject) ([]byte, error) {
	defer object.Body.Close()
	return io.ReadAll(object.Body)
}

func wantBody(ctx context.Context, cluster sidecar.BlobCluster, key string, want []byte) error {
	object, err := cluster.Get(ctx, key)
	if err != nil {
		return fmt.Errorf("get %s: %w", key, err)
	}
	body, err := readAll(object)
	if err != nil {
		return fmt.Errorf("read %s: %w", key, err)
	}
	if !bytes.Equal(body, want) {
		return fmt.Errorf("%s holds %q, want %q", key, truncated(body), truncated(want))
	}
	return nil
}

func truncated(body []byte) []byte {
	return body[:min(len(body), 64)]
}

func wantError(what string, err error, want error) error {
	if !errors.Is(err, want) {
		return fmt.Errorf("%s: got %v, want %v", what, err, want)
	}
	return nil
}

func caseIdentity(ctx context.Context, target *Target, keys *keySpace) error {
	if target.Cluster.ClusterId() == "" {
		return errors.New("an empty cluster id")
	}
	if target.Cluster.RequestTimeout() <= 0 {
		return fmt.Errorf("a request timeout of %v", target.Cluster.RequestTimeout())
	}
	if target.Settle == nil && target.Cluster.SettlePassed() {
		return errors.New("a store that waits for the settle cases answers SettlePassed true")
	}
	return nil
}

func caseCreateWinsOnce(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	key := keys.key("place")
	if _, err := cluster.PutIfNoneMatch(ctx, key, []byte("first"), nil); err != nil {
		return err
	}
	_, err := cluster.PutIfNoneMatch(ctx, key, []byte("second"), nil)
	if err := wantError("second create", err, sidecar.ErrBlobPrecondition); err != nil {
		return err
	}
	return wantBody(ctx, cluster, key, []byte("first"))
}

// One condition decides a race: of many creates, exactly one wins and its bytes stand.
func caseRacingCreates(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	key := keys.key("place")
	const racers = 16
	winners := make(chan []byte, racers)
	failures := make(chan error, racers)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for racer := range racers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			body := fmt.Appendf(nil, "racer-%d", racer)
			_, err := cluster.PutIfNoneMatch(ctx, key, body, nil)
			switch {
			case err == nil:
				winners <- body
			case !errors.Is(err, sidecar.ErrBlobPrecondition):
				failures <- err
			}
		}()
	}
	close(start)
	wait.Wait()
	close(winners)
	close(failures)
	for err := range failures {
		return err
	}
	if len(winners) != 1 {
		return fmt.Errorf("%d winners", len(winners))
	}
	return wantBody(ctx, cluster, key, <-winners)
}

func caseIfMatchReplaces(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	key := keys.key("head")
	etag, err := cluster.PutIfNoneMatch(ctx, key, []byte("v1"), nil)
	if err != nil {
		return err
	}
	newEtag, err := cluster.PutIfMatch(ctx, key, etag, []byte("v2"), nil)
	if err != nil {
		return err
	}
	if newEtag == etag {
		return errors.New("new bytes kept the old etag")
	}
	return wantBody(ctx, cluster, key, []byte("v2"))
}

func caseStaleEtag(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	key := keys.key("head")
	staleEtag, err := cluster.PutIfNoneMatch(ctx, key, []byte("v1"), nil)
	if err != nil {
		return err
	}
	if _, err := cluster.PutIfMatch(ctx, key, staleEtag, []byte("v2"), nil); err != nil {
		return err
	}
	_, err = cluster.PutIfMatch(ctx, key, staleEtag, []byte("v3"), nil)
	if err := wantError("stale etag", err, sidecar.ErrBlobPrecondition); err != nil {
		return err
	}
	return wantBody(ctx, cluster, key, []byte("v2"))
}

func caseIfMatchMissingKey(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	key := keys.key("head")
	sum := "d41d8cd98f00b204e9800998ecf8427e"
	_, err := cluster.PutIfMatch(ctx, key, sum, []byte("v1"), nil)
	if err := wantError("missing key", err, sidecar.ErrBlobPrecondition); err != nil {
		return err
	}
	_, err = cluster.Head(ctx, key)
	return wantError("head after", err, sidecar.ErrBlobNotFound)
}

// The etag a key held says nothing once the key is gone.
func caseIfMatchAfterDelete(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	key := keys.key("head")
	etag, err := cluster.PutIfNoneMatch(ctx, key, []byte("v1"), nil)
	if err != nil {
		return err
	}
	if err := cluster.Delete(ctx, key); err != nil {
		return err
	}
	_, err = cluster.PutIfMatch(ctx, key, etag, []byte("v2"), nil)
	if err := wantError("after a delete", err, sidecar.ErrBlobPrecondition); err != nil {
		return err
	}
	_, err = cluster.Head(ctx, key)
	return wantError("head after", err, sidecar.ErrBlobNotFound)
}

func caseEmptyEtag(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	key := keys.key("head")
	if _, err := cluster.PutIfNoneMatch(ctx, key, []byte("v1"), nil); err != nil {
		return err
	}
	_, err := cluster.PutIfMatch(ctx, key, "", []byte("blind"), nil)
	if err := wantError("empty etag", err, sidecar.ErrBlobPutOptions); err != nil {
		return err
	}
	return wantBody(ctx, cluster, key, []byte("v1"))
}

// A head's history is its successful If-Match PUTs in order: from one etag, one PUT succeeds.
func caseRacingIfMatch(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	key := keys.key("head")
	etag, err := cluster.PutIfNoneMatch(ctx, key, []byte("v0"), nil)
	if err != nil {
		return err
	}
	const racers = 16
	winners := make(chan []byte, racers)
	failures := make(chan error, racers)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for racer := range racers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			body := fmt.Appendf(nil, "v1-racer-%d", racer)
			_, err := cluster.PutIfMatch(ctx, key, etag, body, nil)
			switch {
			case err == nil:
				winners <- body
			case !errors.Is(err, sidecar.ErrBlobPrecondition):
				failures <- err
			}
		}()
	}
	close(start)
	wait.Wait()
	close(winners)
	close(failures)
	for err := range failures {
		return err
	}
	if len(winners) != 1 {
		return fmt.Errorf("%d winners", len(winners))
	}
	return wantBody(ctx, cluster, key, <-winners)
}

// An ETag names bytes: every view agrees on it, new bytes change it, and equal bytes keep it, which is
// why §11.8's etag row raises a version or fence in every head write.
func caseEtagFollowsBytes(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	key := keys.key("head")
	etag, err := cluster.PutIfNoneMatch(ctx, key, []byte("v1"), nil)
	if err != nil {
		return err
	}
	if etag == "" {
		return errors.New("a create returned no etag")
	}
	info, err := cluster.Head(ctx, key)
	if err != nil {
		return err
	}
	object, err := cluster.Get(ctx, key)
	if err != nil {
		return err
	}
	object.Body.Close()
	objects, _, err := cluster.List(ctx, key, "", 10)
	if err != nil {
		return err
	}
	if len(objects) != 1 {
		return fmt.Errorf("listed %d objects", len(objects))
	}
	if info.Etag != etag || object.Etag != etag || objects[0].Etag != etag {
		return fmt.Errorf("put %q, head %q, get %q, list %q", etag, info.Etag, object.Etag, objects[0].Etag)
	}

	sameBytes, err := cluster.PutIfMatch(ctx, key, etag, []byte("v1"), nil)
	if err != nil {
		return err
	}
	if sameBytes != etag {
		return fmt.Errorf("equal bytes changed the etag: %q then %q", etag, sameBytes)
	}
	seen := map[string]bool{etag: true}
	for version := 2; version < 6; version += 1 {
		newEtag, err := cluster.PutIfMatch(ctx, key, etag, fmt.Appendf(nil, "v%d", version), nil)
		if err != nil {
			return err
		}
		if seen[newEtag] {
			return fmt.Errorf("etag %q repeated for new bytes", newEtag)
		}
		seen[newEtag] = true
		etag = newEtag
	}
	return nil
}

func caseReadAfterWrite(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	key := keys.key("head")
	etag, err := cluster.PutIfNoneMatch(ctx, key, []byte("v0"), nil)
	if err != nil {
		return err
	}
	for version := 1; version < 20; version += 1 {
		body := fmt.Appendf(nil, "v%d", version)
		if etag, err = cluster.PutIfMatch(ctx, key, etag, body, nil); err != nil {
			return err
		}
		if err := wantBody(ctx, cluster, key, body); err != nil {
			return err
		}
	}
	return nil
}

func caseMissingKey(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	key := keys.key("absent")
	_, err := cluster.Get(ctx, key)
	if err := wantError("get", err, sidecar.ErrBlobNotFound); err != nil {
		return err
	}
	_, err = cluster.GetRange(ctx, key, 0, 10)
	if err := wantError("get range", err, sidecar.ErrBlobNotFound); err != nil {
		return err
	}
	_, err = cluster.Head(ctx, key)
	return wantError("head", err, sidecar.ErrBlobNotFound)
}

func caseRangedGet(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	key := keys.key("batch")
	body := []byte("0123456789abcdef")
	if _, err := cluster.PutIfNoneMatch(ctx, key, body, nil); err != nil {
		return err
	}
	spans := []struct {
		offset    int64
		byteCount int64
		want      string
	}{
		{offset: 0, byteCount: 4, want: "0123"},
		{offset: 4, byteCount: 4, want: "4567"},
		{offset: 15, byteCount: 1, want: "f"},
		// a span past the end stops there
		{offset: 12, byteCount: 100, want: "cdef"},
	}
	for _, span := range spans {
		object, err := cluster.GetRange(ctx, key, span.offset, span.byteCount)
		if err != nil {
			return fmt.Errorf("range %d+%d: %w", span.offset, span.byteCount, err)
		}
		if object.ByteCount != int64(len(body)) {
			return fmt.Errorf("range %d+%d: ByteCount %d, want the whole object's", span.offset, span.byteCount, object.ByteCount)
		}
		got, err := readAll(object)
		if err != nil {
			return err
		}
		if string(got) != span.want {
			return fmt.Errorf("range %d+%d: %q, want %q", span.offset, span.byteCount, got, span.want)
		}
	}
	for _, offset := range []int64{16, 17, 1000} {
		_, err := cluster.GetRange(ctx, key, offset, 1)
		if err := wantError(fmt.Sprintf("range at %d", offset), err, sidecar.ErrBlobRange); err != nil {
			return err
		}
	}
	return nil
}

// Every offset of an empty object starts at or past its end.
func caseRangedGetEmpty(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	key := keys.key("empty")
	if _, err := cluster.PutIfNoneMatch(ctx, key, nil, nil); err != nil {
		return err
	}
	_, err := cluster.GetRange(ctx, key, 0, 1)
	return wantError("range of nothing", err, sidecar.ErrBlobRange)
}

// Keys are opaque ids and tokens, so whatever a token's alphabet holds comes back as it went in, and a
// listing finds it under that spelling.
func caseKeyBytes(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	for _, name := range []string{"a+b", "a=b", "a~b", "a_b", "a.b", "a%41b", "a b", "a:b"} {
		key := keys.key(name)
		if _, err := cluster.PutIfNoneMatch(ctx, key, []byte(name), nil); err != nil {
			return fmt.Errorf("%q: %w", name, err)
		}
		if err := wantBody(ctx, cluster, key, []byte(name)); err != nil {
			return fmt.Errorf("%q: %w", name, err)
		}
		objects, _, err := cluster.List(ctx, key, "", 2)
		if err != nil {
			return fmt.Errorf("%q: %w", name, err)
		}
		if got := listedKeys(objects); !slices.Equal(got, []string{key}) {
			return fmt.Errorf("%q: listed %q", name, got)
		}
	}
	return nil
}

func caseHead(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	key := keys.key("entry")
	etag, err := cluster.PutIfNoneMatch(ctx, key, []byte("twelve bytes"), nil)
	if err != nil {
		return err
	}
	info, err := cluster.Head(ctx, key)
	if err != nil {
		return err
	}
	if info.Key != key || info.ByteCount != 12 || info.Etag != etag || info.LastModified.IsZero() {
		return fmt.Errorf("info %+v", info)
	}
	return nil
}

func putAll(ctx context.Context, cluster sidecar.BlobCluster, keys []string) error {
	for _, key := range keys {
		if _, err := cluster.PutIfNoneMatch(ctx, key, []byte(key), nil); err != nil {
			return fmt.Errorf("put %s: %w", key, err)
		}
	}
	return nil
}

func listedKeys(objects []*sidecar.BlobInfo) []string {
	listed := make([]string, 0, len(objects))
	for _, object := range objects {
		listed = append(listed, object.Key)
	}
	return listed
}

// Ascending by byte, not by anything a locale says, and strictly after startAfter.
func caseListOrder(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	names := []string{"Z", "a", "a-b", "a.b", "a0", "aa", "b"}
	written := make([]string, 0, len(names))
	for _, name := range names {
		written = append(written, keys.key(name))
	}
	shuffled := slices.Clone(written)
	slices.Reverse(shuffled)
	if err := putAll(ctx, cluster, shuffled); err != nil {
		return err
	}
	want := slices.Clone(written)
	slices.Sort(want)

	objects, more, err := cluster.List(ctx, keys.prefix, "", 100)
	if err != nil {
		return err
	}
	if more {
		return errors.New("more followed the whole list")
	}
	if got := listedKeys(objects); !slices.Equal(got, want) {
		return fmt.Errorf("listed %q, want %q", got, want)
	}

	objects, _, err = cluster.List(ctx, keys.prefix, want[2], 100)
	if err != nil {
		return err
	}
	if got := listedKeys(objects); !slices.Equal(got, want[3:]) {
		return fmt.Errorf("after %q: %q, want %q", want[2], got, want[3:])
	}

	// a startAfter that is no key still splits the list
	objects, _, err = cluster.List(ctx, keys.prefix, want[2]+"x", 100)
	if err != nil {
		return err
	}
	if got := listedKeys(objects); !slices.Equal(got, want[3:]) {
		return fmt.Errorf("after a gap: %q, want %q", got, want[3:])
	}

	// another prefix sees none of these
	objects, _, err = cluster.List(ctx, keys.prefix+"no-such-part", "", 100)
	if err != nil {
		return err
	}
	if len(objects) != 0 {
		return fmt.Errorf("an empty prefix listed %q", listedKeys(objects))
	}
	return nil
}

func caseListPages(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	want := []string{}
	for index := range 7 {
		want = append(want, keys.key(fmt.Sprintf("%02d", index)))
	}
	if err := putAll(ctx, cluster, want); err != nil {
		return err
	}
	got := []string{}
	startAfter := ""
	pages := 0
	for {
		objects, more, err := cluster.List(ctx, keys.prefix, startAfter, 3)
		if err != nil {
			return err
		}
		pages += 1
		if 3 < len(objects) {
			return fmt.Errorf("a page of %d", len(objects))
		}
		got = append(got, listedKeys(objects)...)
		if !more {
			break
		}
		if len(objects) == 0 {
			return errors.New("an empty page said more follow")
		}
		startAfter = objects[len(objects)-1].Key
	}
	if pages != 3 {
		return fmt.Errorf("%d pages", pages)
	}
	if !slices.Equal(got, want) {
		return fmt.Errorf("paged %q, want %q", got, want)
	}
	return nil
}

func caseListFields(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	key := keys.key("entry")
	options := &sidecar.BlobPutOptions{Metadata: map[string]string{"entry-state": "live"}}
	etag, err := cluster.PutIfNoneMatch(ctx, key, []byte("twelve bytes"), options)
	if err != nil {
		return err
	}
	objects, _, err := cluster.List(ctx, keys.prefix, "", 10)
	if err != nil {
		return err
	}
	if len(objects) != 1 {
		return fmt.Errorf("listed %d", len(objects))
	}
	object := objects[0]
	if object.Key != key || object.ByteCount != 12 || object.Etag != etag || object.LastModified.IsZero() {
		return fmt.Errorf("listed %+v", object)
	}
	if len(object.Metadata) != 0 {
		return fmt.Errorf("a listing carried metadata %v", object.Metadata)
	}
	return nil
}

func caseListConsistency(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	key := keys.key("entry")
	if _, err := cluster.PutIfNoneMatch(ctx, key, []byte("x"), nil); err != nil {
		return err
	}
	objects, _, err := cluster.List(ctx, keys.prefix, "", 10)
	if err != nil {
		return err
	}
	if len(objects) != 1 {
		return fmt.Errorf("a written key listed %d times", len(objects))
	}
	if err := cluster.Delete(ctx, key); err != nil {
		return err
	}
	objects, _, err = cluster.List(ctx, keys.prefix, "", 10)
	if err != nil {
		return err
	}
	if len(objects) != 0 {
		return fmt.Errorf("a deleted key stayed: %q", listedKeys(objects))
	}
	return nil
}

func caseListLimit(ctx context.Context, target *Target, keys *keySpace) error {
	for _, limit := range []int{0, -1} {
		if _, _, err := target.Cluster.List(ctx, keys.prefix, "", limit); err == nil {
			return fmt.Errorf("a limit of %d passed", limit)
		}
	}
	return nil
}

func caseDeleteMissing(ctx context.Context, target *Target, keys *keySpace) error {
	return target.Cluster.Delete(ctx, keys.key("never-written"))
}

// A removal keeps no prior version (owner decision 90): the key is free again, and a create succeeds.
func caseDeleteThenCreate(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	key := keys.key("slot")
	if _, err := cluster.PutIfNoneMatch(ctx, key, []byte("first"), nil); err != nil {
		return err
	}
	if err := cluster.Delete(ctx, key); err != nil {
		return err
	}
	if err := cluster.Delete(ctx, key); err != nil {
		return fmt.Errorf("a second delete: %w", err)
	}
	_, err := cluster.Get(ctx, key)
	if err := wantError("get after delete", err, sidecar.ErrBlobNotFound); err != nil {
		return err
	}
	if _, err := cluster.PutIfNoneMatch(ctx, key, []byte("second"), nil); err != nil {
		return err
	}
	return wantBody(ctx, cluster, key, []byte("second"))
}

func caseMetadata(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	key := keys.key("entry")
	metadata := map[string]string{"entry-state": "sources-standing", "ur-v2": "printable ~ ascii"}
	etag, err := cluster.PutIfNoneMatch(ctx, key, []byte("x"), &sidecar.BlobPutOptions{Metadata: metadata})
	if err != nil {
		return err
	}
	info, err := cluster.Head(ctx, key)
	if err != nil {
		return err
	}
	for name, value := range metadata {
		if info.Metadata[name] != value {
			return fmt.Errorf("head: %s is %q, want %q (all: %v)", name, info.Metadata[name], value, info.Metadata)
		}
	}
	object, err := cluster.Get(ctx, key)
	if err != nil {
		return err
	}
	object.Body.Close()
	for name, value := range metadata {
		if object.Metadata[name] != value {
			return fmt.Errorf("get: %s is %q, want %q", name, object.Metadata[name], value)
		}
	}

	// a replacement without metadata carries none: nothing survives an overwrite
	if _, err := cluster.PutIfMatch(ctx, key, etag, []byte("y"), nil); err != nil {
		return err
	}
	info, err = cluster.Head(ctx, key)
	if err != nil {
		return err
	}
	if _, ok := info.Metadata["entry-state"]; ok {
		return fmt.Errorf("metadata survived an overwrite: %v", info.Metadata)
	}
	return nil
}

// The store takes 2 KiB of metadata, each key with the header prefix it travels under, and the two
// sides agree where that ends: a store refusing what Validate passed would fail only at T3.
func caseMetadataLimit(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	const limit = 2 * 1024
	name := "state"
	value := strings.Repeat("x", limit-len("x-amz-meta-")-len(name))
	key := keys.key("entry")
	if _, err := cluster.PutIfNoneMatch(ctx, key, []byte("x"), &sidecar.BlobPutOptions{Metadata: map[string]string{name: value}}); err != nil {
		return fmt.Errorf("at the limit: %w", err)
	}
	info, err := cluster.Head(ctx, key)
	if err != nil {
		return err
	}
	if info.Metadata[name] != value {
		return fmt.Errorf("a %d byte value came back as %d", len(value), len(info.Metadata[name]))
	}
	_, err = cluster.PutIfNoneMatch(ctx, keys.key("over"), []byte("x"), &sidecar.BlobPutOptions{Metadata: map[string]string{name: value + "x"}})
	return wantError("past the limit", err, sidecar.ErrBlobPutOptions)
}

func caseInvalidOptions(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	key := keys.key("entry")
	badOptions := []*sidecar.BlobPutOptions{
		{Sha256: make([]byte, 16)},
		{Metadata: map[string]string{"Upper": "x"}},
		{Metadata: map[string]string{"": "x"}},
		{Metadata: map[string]string{"ok": "line\nbreak"}},
	}
	for _, options := range badOptions {
		_, err := cluster.PutIfNoneMatch(ctx, key, []byte("x"), options)
		if err := wantError("options", err, sidecar.ErrBlobPutOptions); err != nil {
			return err
		}
	}
	_, err := cluster.Head(ctx, key)
	return wantError("head after", err, sidecar.ErrBlobNotFound)
}

func caseChecksum(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	key := keys.key("pack")
	body := []byte("sealed bytes")
	sum := sha256.Sum256(body)
	if _, err := cluster.PutIfNoneMatch(ctx, key, body, &sidecar.BlobPutOptions{Sha256: sum[:]}); err != nil {
		return err
	}
	if err := wantBody(ctx, cluster, key, body); err != nil {
		return err
	}

	badKey := keys.key("pack-bad")
	otherSum := sha256.Sum256([]byte("other bytes"))
	_, err := cluster.PutIfNoneMatch(ctx, badKey, body, &sidecar.BlobPutOptions{Sha256: otherSum[:]})
	if err := wantError("bad checksum", err, sidecar.ErrBlobChecksum); err != nil {
		return err
	}
	_, err = cluster.Head(ctx, badKey)
	return wantError("head after a bad checksum", err, sidecar.ErrBlobNotFound)
}

func casePutStream(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	key := keys.key("segment")
	body := bytes.Repeat([]byte("segment bytes "), 1024)
	sum := sha256.Sum256(body)
	etag, err := cluster.PutStream(ctx, key, bytes.NewReader(body), int64(len(body)), sum[:])
	if err != nil {
		return err
	}
	if etag == "" {
		return errors.New("no etag")
	}
	return wantBody(ctx, cluster, key, body)
}

func casePutStreamLength(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	key := keys.key("segment")
	body := []byte("exactly this")
	sum := sha256.Sum256(body)
	for _, byteCount := range []int64{int64(len(body)) - 1, int64(len(body)) + 1} {
		if _, err := cluster.PutStream(ctx, key, bytes.NewReader(body), byteCount, sum[:]); err == nil {
			return fmt.Errorf("a %d byte body passed as %d", len(body), byteCount)
		}
	}
	_, err := cluster.Head(ctx, key)
	return wantError("head after", err, sidecar.ErrBlobNotFound)
}

func casePutStreamChecksum(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	key := keys.key("segment")
	body := []byte("the bytes sent")
	sum := sha256.Sum256([]byte("the bytes named"))
	_, err := cluster.PutStream(ctx, key, bytes.NewReader(body), int64(len(body)), sum[:])
	if err := wantError("bad checksum", err, sidecar.ErrBlobChecksum); err != nil {
		return err
	}
	_, err = cluster.Head(ctx, key)
	return wantError("head after", err, sidecar.ErrBlobNotFound)
}

func casePutStreamExists(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	key := keys.key("segment")
	body := []byte("segment")
	sum := sha256.Sum256(body)
	if _, err := cluster.PutStream(ctx, key, bytes.NewReader(body), int64(len(body)), sum[:]); err != nil {
		return err
	}
	_, err := cluster.PutStream(ctx, key, bytes.NewReader(body), int64(len(body)), sum[:])
	return wantError("second stream", err, sidecar.ErrBlobPrecondition)
}

func casePutStreamNoChecksum(ctx context.Context, target *Target, keys *keySpace) error {
	key := keys.key("segment")
	_, err := target.Cluster.PutStream(ctx, key, strings.NewReader("x"), 1, nil)
	return wantError("no checksum", err, sidecar.ErrBlobPutOptions)
}

// Empty, one past MinIO's inline shard limit (§11.3) and well past it, in binary.
func caseBodySizes(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	for _, byteCount := range []int{0, 1, 128 * 1024, 128*1024 + 1, 1024 * 1024} {
		key := keys.key(fmt.Sprintf("size-%d", byteCount))
		body := make([]byte, byteCount)
		if _, err := rand.Read(body); err != nil {
			return err
		}
		if _, err := cluster.PutIfNoneMatch(ctx, key, body, nil); err != nil {
			return fmt.Errorf("%d bytes: %w", byteCount, err)
		}
		if err := wantBody(ctx, cluster, key, body); err != nil {
			return err
		}
	}
	return nil
}

// §11.13's age rules read LastModified, so it must be the store's clock.
func caseLastModified(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	key := keys.key("slot")
	before := target.Now()
	if _, err := cluster.PutIfNoneMatch(ctx, key, []byte("x"), nil); err != nil {
		return err
	}
	after := target.Now()
	info, err := cluster.Head(ctx, key)
	if err != nil {
		return err
	}
	if info.LastModified.Before(before.Add(-target.ClockTolerance)) || info.LastModified.After(after.Add(target.ClockTolerance)) {
		return fmt.Errorf("LastModified %v outside %v to %v", info.LastModified, before, after)
	}
	return nil
}

// The way to the store a late request takes: Settle.Delayed, on Target.Cluster's cluster.
func delayedCluster(target *Target) (sidecar.BlobCluster, error) {
	delayed := target.Settle.Delayed
	if delayed == nil {
		return nil, errors.New("no delayed path to the store: a late request cancelled before it arrives proves nothing of the store's deadline check")
	}
	if delayed.ClusterId() != target.Cluster.ClusterId() {
		return nil, fmt.Errorf("the delayed path reaches cluster %q, not %q", delayed.ClusterId(), target.Cluster.ClusterId())
	}
	return delayed, nil
}

// A request that reaches the store past its deadline takes no effect, and its caller cannot tell that
// from a lost response, so a write reports unknown and a read fails. Then the store reads as if it
// never came. Each late request goes the delayed way, so it reaches the store.
func caseDeadlineRefused(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	delayed, err := delayedCluster(target)
	if err != nil {
		return err
	}
	key := keys.key("marker")
	etag, err := cluster.PutIfNoneMatch(ctx, key, []byte("v1"), nil)
	if err != nil {
		return err
	}
	past := sidecar.WithBlobDeadline(ctx, target.Settle.Now().Add(-1*time.Millisecond))
	var unknown *sidecar.BlobUnknownError
	_, err = delayed.PutIfMatch(past, key, etag, []byte("v2"), nil)
	if !errors.As(err, &unknown) {
		return fmt.Errorf("a late PUT: got %v, want an unknown outcome", err)
	}
	if err := wantBody(ctx, cluster, key, []byte("v1")); err != nil {
		return err
	}
	if _, err := delayed.Get(past, key); err == nil {
		return errors.New("a late GET was served")
	}
	return nil
}

func caseDeadlineDelete(ctx context.Context, target *Target, keys *keySpace) error {
	cluster := target.Cluster
	delayed, err := delayedCluster(target)
	if err != nil {
		return err
	}
	key := keys.key("marker")
	if _, err := cluster.PutIfNoneMatch(ctx, key, []byte("v1"), nil); err != nil {
		return err
	}
	past := sidecar.WithBlobDeadline(ctx, target.Settle.Now().Add(-1*time.Millisecond))
	var unknown *sidecar.BlobUnknownError
	if err := delayed.Delete(past, key); !errors.As(err, &unknown) {
		return fmt.Errorf("a late DELETE: got %v, want an unknown outcome", err)
	}
	return wantBody(ctx, cluster, key, []byte("v1"))
}

// Runs BlobStore's own promises: which clusters exist and how they are found.
func RunStore(t *testing.T, store sidecar.BlobStore) {
	t.Helper()
	metadataClusterIds := store.MetadataClusterIds()
	if len(metadataClusterIds) == 0 {
		t.Fatal("no metadata cluster")
	}
	first, err := store.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	if first.ClusterId() != metadataClusterIds[0] {
		t.Errorf("first cluster %q, ids %v", first.ClusterId(), metadataClusterIds)
	}
	for _, clusterId := range metadataClusterIds {
		cluster, err := store.Cluster(clusterId)
		if err != nil {
			t.Errorf("%s: %v", clusterId, err)
			continue
		}
		if cluster.ClusterId() != clusterId {
			t.Errorf("cluster %q answers as %q", clusterId, cluster.ClusterId())
		}
	}
	if _, err := store.SegmentCluster(); err != nil {
		t.Errorf("segment cluster: %v", err)
	}
	if _, err := store.Cluster("no-such-cluster"); !errors.Is(err, sidecar.ErrBlobClusterUnknown) {
		t.Errorf("an unknown cluster: %v", err)
	}
	if store.NewRepoClusterId() == "" {
		t.Error("no cluster takes new repos")
	}
}
