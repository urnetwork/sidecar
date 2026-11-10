// gkm's store suite (KEYS-M2-17; §10.6, D-TEST-2): the conditional writes gkm's engine and reconciler rest on, run on
// a metadata cluster and Redis, so the store gkm's T2 tests ran on and the one production runs hold to one contract.
// T2 runs it on FakeBlobs and FakeRedis (gkmservice's store_test.go), and server's T3 on server.FileClusters over the
// local stack's MinIO and sidecarhost.Redis on the private test store (server/gkm's run_test.go).
//
// The cases are §10.6's rows as the store sees them:
//
//	one commit   racing If-None-Match creates of epoch/<n>: one wins, every other answers ErrBlobPrecondition and
//	             reads back the winner, and the winner's own retry reads back its bytes, which gkm answers as success
//	one claim    racing claimers of one KeyPackage, each creating <ref>.claim If-None-Match: one wins and deletes
//	             <ref>, which then reads 404, and a delete of a key already gone is no error
//	pointer      group-info rewritten If-Match on the etag a read found: a write on a stale etag is refused, and
//	             If-None-Match creates it when absent
//	ladder       gen/<g>'s 20-digit keys list in number order, page by page from any start-after
//	acks         {gka_<group_id>}: a leaf's field and since set, read back whole and one at a time, its ttl renewed,
//	             since kept when absent only, and the key deleted with its group
//	shred        every key under a group's prefix deleted a page at a time, twice, the second finding nothing
//
// It cannot import gkmservice, whose tests import this package, so the target carries gkm's own key builders. Every
// write carries a write class on its ctx, as a budget's grant would, since a server's clusters may refuse one that
// does not. Keys are fresh ids each run, so runs on a shared store do not meet.

package sidecartest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// What RunGkmStoreSuite runs on: one metadata cluster, Redis, and gkm's key builders.
type GkmStoreSuiteTarget struct {
	Cluster sidecar.BlobCluster
	Redis   sidecar.Redis
	// gkmservice's key builders: epoch/<n>, gen/<g>, group-info and the group's prefix on the repo's cluster,
	// kp/<sidecar_id>/<ref> and its claim on the first, and {gka_<group_id>}.
	EpochKey           func(groupId sidecar.Id, epoch uint64) string
	GenerationKey      func(groupId sidecar.Id, generation uint64) string
	GenerationPrefix   func(groupId sidecar.Id) string
	GroupInfoKey       func(groupId sidecar.Id) string
	GroupPrefix        func(groupId sidecar.Id) string
	KeyPackageKey      func(sidecarId sidecar.Id, ref []byte) (string, error)
	KeyPackageClaimKey func(sidecarId sidecar.Id, ref []byte) (string, error)
	AckRedisKey        func(groupId sidecar.Id) string
	// How many writers race in the race cases: 8 when not positive.
	RaceCount int
}

// Runs every case on target.
func RunGkmStoreSuite(t testing.TB, target *GkmStoreSuiteTarget) {
	t.Helper()
	if target == nil || target.Cluster == nil || target.Redis == nil || target.EpochKey == nil || target.GenerationKey == nil ||
		target.GenerationPrefix == nil || target.GroupInfoKey == nil || target.GroupPrefix == nil || target.KeyPackageKey == nil ||
		target.KeyPackageClaimKey == nil || target.AckRedisKey == nil {
		t.Fatal("gkm's store suite needs a cluster, Redis and every key builder")
	}
	raceCount := target.RaceCount
	if raceCount <= 0 {
		raceCount = 8
	}
	// every write as a budget's grant would carry it
	ctx := sidecar.WithWriteClass(t.Context(), sidecar.WriteClassP1)
	gkmStoreSuiteOneCommit(t, ctx, target, raceCount)
	gkmStoreSuiteOneClaim(t, ctx, target, raceCount)
	gkmStoreSuitePointer(t, ctx, target)
	gkmStoreSuiteLadder(t, ctx, target)
	gkmStoreSuiteAcks(t, ctx, target)
	gkmStoreSuiteShred(t, ctx, target)
}

// key's bytes, nil for none; a failure that is no 404 fails the test.
func gkmStoreSuiteRead(t testing.TB, ctx context.Context, cluster sidecar.BlobCluster, key string) []byte {
	t.Helper()
	object, err := cluster.Get(ctx, key)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil
	}
	if err != nil {
		t.Fatalf("read %s: %v", key, err)
	}
	defer object.Body.Close()
	body := bytes.Buffer{}
	if _, err := body.ReadFrom(object.Body); err != nil {
		t.Fatalf("read %s: %v", key, err)
	}
	return body.Bytes()
}

// Races count If-None-Match creates of key, each its own bytes, and answers which index won and every error.
func gkmStoreSuiteRace(ctx context.Context, cluster sidecar.BlobCluster, key string, count int, body func(i int) []byte) (winners []int, errs []error) {
	var waitGroup sync.WaitGroup
	start := make(chan struct{})
	results := make([]error, count)
	for i := range count {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			_, results[i] = cluster.PutIfNoneMatch(ctx, key, body(i), nil)
		}()
	}
	close(start)
	waitGroup.Wait()
	for i, err := range results {
		switch {
		case err == nil:
			winners = append(winners, i)
		case !errors.Is(err, sidecar.ErrBlobPrecondition):
			errs = append(errs, err)
		}
	}
	return winners, errs
}

// §10.6's one-commit duty on the store: one racing create of epoch/<n> wins, the losers read back the winner, and the
// winner's retry of its own bytes reads back equal bytes.
func gkmStoreSuiteOneCommit(t testing.TB, ctx context.Context, target *GkmStoreSuiteTarget, raceCount int) {
	t.Helper()
	groupId := sidecar.NewId()
	key := target.EpochKey(groupId, 1)
	commit := func(i int) []byte { return []byte(fmt.Sprintf("commit %d of epoch 1", i)) }
	winners, errs := gkmStoreSuiteRace(ctx, target.Cluster, key, raceCount, commit)
	if len(errs) != 0 {
		t.Fatalf("one commit: %v", errs)
	}
	if len(winners) != 1 {
		t.Fatalf("one commit: %d creates of epoch/1 won", len(winners))
	}
	held := gkmStoreSuiteRead(t, ctx, target.Cluster, key)
	if !bytes.Equal(held, commit(winners[0])) {
		t.Fatalf("one commit: epoch/1 does not hold the winner")
	}
	if _, err := target.Cluster.PutIfNoneMatch(ctx, key, commit(winners[0]), nil); !errors.Is(err, sidecar.ErrBlobPrecondition) {
		t.Errorf("one commit: the winner's retry: %v", err)
	}
	if !bytes.Equal(gkmStoreSuiteRead(t, ctx, target.Cluster, key), commit(winners[0])) {
		t.Errorf("one commit: a retry moved epoch/1")
	}
	gkmStoreSuiteCleanUp(t, ctx, target, groupId)
}

// §10.6's KeyPackages row on the store: racing claimers of one KeyPackage, one claim wins, the winner deletes <ref>,
// which then reads 404, and a delete of a key already gone answers no error.
func gkmStoreSuiteOneClaim(t testing.TB, ctx context.Context, target *GkmStoreSuiteTarget, raceCount int) {
	t.Helper()
	sidecarId := sidecar.NewId()
	ref := bytes.Repeat([]byte{0x5c}, 32)
	key, err := target.KeyPackageKey(sidecarId, ref)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Cluster.PutIfNoneMatch(ctx, key, []byte("a one-time KeyPackage"), nil); err != nil {
		t.Fatalf("one claim: the upload: %v", err)
	}
	claimKey, err := target.KeyPackageClaimKey(sidecarId, ref)
	if err != nil {
		t.Fatal(err)
	}
	claim := func(i int) []byte { return []byte(fmt.Sprintf("claimer %d", i)) }
	winners, errs := gkmStoreSuiteRace(ctx, target.Cluster, claimKey, raceCount, claim)
	if len(errs) != 0 {
		t.Fatalf("one claim: %v", errs)
	}
	if len(winners) != 1 {
		t.Fatalf("one claim: %d claims of one KeyPackage won", len(winners))
	}
	if err := target.Cluster.Delete(ctx, key); err != nil {
		t.Fatalf("one claim: the winner's delete: %v", err)
	}
	if held := gkmStoreSuiteRead(t, ctx, target.Cluster, key); held != nil {
		t.Errorf("one claim: a claimed KeyPackage still reads")
	}
	if err := target.Cluster.Delete(ctx, key); err != nil {
		t.Errorf("one claim: a delete of a key already gone: %v", err)
	}
	if !bytes.Equal(gkmStoreSuiteRead(t, ctx, target.Cluster, claimKey), claim(winners[0])) {
		t.Errorf("one claim: the claim does not hold its winner")
	}
	if err := target.Cluster.Delete(ctx, claimKey); err != nil {
		t.Fatal(err)
	}
}

// §10.6's group-info row on the store: created If-None-Match when absent, then rewritten If-Match rising, a write on
// a stale etag refused.
func gkmStoreSuitePointer(t testing.TB, ctx context.Context, target *GkmStoreSuiteTarget) {
	t.Helper()
	groupId := sidecar.NewId()
	key := target.GroupInfoKey(groupId)
	firstEtag, err := target.Cluster.PutIfNoneMatch(ctx, key, []byte("pointer to epoch 1"), nil)
	if err != nil {
		t.Fatalf("pointer: the first write: %v", err)
	}
	if _, err := target.Cluster.PutIfNoneMatch(ctx, key, []byte("pointer to epoch 1 again"), nil); !errors.Is(err, sidecar.ErrBlobPrecondition) {
		t.Errorf("pointer: a second create: %v", err)
	}
	secondEtag, err := target.Cluster.PutIfMatch(ctx, key, firstEtag, []byte("pointer to epoch 17"), nil)
	if err != nil {
		t.Fatalf("pointer: a rewrite on its etag: %v", err)
	}
	if secondEtag == firstEtag {
		t.Errorf("pointer: a rewrite kept its etag")
	}
	if _, err := target.Cluster.PutIfMatch(ctx, key, firstEtag, []byte("pointer to epoch 2"), nil); !errors.Is(err, sidecar.ErrBlobPrecondition) {
		t.Errorf("pointer: a rewrite on a stale etag: %v", err)
	}
	if !bytes.Equal(gkmStoreSuiteRead(t, ctx, target.Cluster, key), []byte("pointer to epoch 17")) {
		t.Errorf("pointer: a stale rewrite moved the pointer")
	}
	info, err := target.Cluster.Head(ctx, key)
	if err != nil || info.Etag != secondEtag {
		t.Errorf("pointer: the etag a read finds is not the newest write's: %v", err)
	}
	gkmStoreSuiteCleanUp(t, ctx, target, groupId)
}

// gen/'s ladder on the store: 20-digit keys list in number order, page by page, from any start-after.
func gkmStoreSuiteLadder(t testing.TB, ctx context.Context, target *GkmStoreSuiteTarget) {
	t.Helper()
	groupId := sidecar.NewId()
	const generationCount = 12
	// written out of order, as racing rotators of distant generations would not, but a listing must not care
	for _, generation := range []uint64{10, 2, 11, 1, 3, 12, 4, 9, 5, 8, 6, 7} {
		if _, err := target.Cluster.PutIfNoneMatch(ctx, target.GenerationKey(groupId, generation), []byte("gen "+strconv.FormatUint(generation, 10)), nil); err != nil {
			t.Fatalf("ladder: gen/%d: %v", generation, err)
		}
	}
	prefix := target.GenerationPrefix(groupId)
	listed := []string{}
	startAfter := ""
	for range generationCount {
		page, more, err := target.Cluster.List(ctx, prefix, startAfter, 5)
		if err != nil {
			t.Fatalf("ladder: list: %v", err)
		}
		for _, info := range page {
			listed = append(listed, info.Key)
		}
		if !more || len(page) == 0 {
			break
		}
		startAfter = page[len(page)-1].Key
	}
	if len(listed) != generationCount {
		t.Fatalf("ladder: listed %d generations of %d", len(listed), generationCount)
	}
	for i, key := range listed {
		if key != target.GenerationKey(groupId, uint64(i+1)) {
			t.Fatalf("ladder: listing %d is %s", i, key)
		}
	}
	page, _, err := target.Cluster.List(ctx, prefix, target.GenerationKey(groupId, 10), 5)
	if err != nil || len(page) != 2 || page[0].Key != target.GenerationKey(groupId, 11) {
		t.Errorf("ladder: a listing after gen/10: %v", err)
	}
	gkmStoreSuiteCleanUp(t, ctx, target, groupId)
}

// §10.6's acks on Redis: a leaf's field and since, read back, the ttl renewed by a write, since kept when present,
// and the family deleted whole.
func gkmStoreSuiteAcks(t testing.TB, ctx context.Context, target *GkmStoreSuiteTarget) {
	t.Helper()
	groupId := sidecar.NewId()
	key := target.AckRedisKey(groupId)
	leaf := sidecar.EvsKeyId(sidecar.NewId())
	since := []byte(strconv.FormatInt(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC).UnixMilli(), 10))
	if err := target.Redis.HashSet(ctx, key, map[string][]byte{leaf: []byte("7:1767323045000"), "since": since}); err != nil {
		t.Fatalf("acks: the first write: %v", err)
	}
	if found, err := target.Redis.Expire(ctx, key, 31*24*time.Hour); err != nil || !found {
		t.Fatalf("acks: the ttl: %t %v", found, err)
	}
	value, found, err := target.Redis.HashGet(ctx, key, leaf)
	if err != nil || !found || string(value) != "7:1767323045000" {
		t.Fatalf("acks: a leaf's field: %q %t %v", value, found, err)
	}
	// a later ack writes its own field, and since only where absent, which a reader checks first
	if _, found, err := target.Redis.HashGet(ctx, key, "since"); err != nil || !found {
		t.Fatalf("acks: since: %t %v", found, err)
	}
	if err := target.Redis.HashSet(ctx, key, map[string][]byte{leaf: []byte("9:1767409445000")}); err != nil {
		t.Fatal(err)
	}
	fieldValues, err := target.Redis.HashGetAll(ctx, key)
	if err != nil || len(fieldValues) != 2 || string(fieldValues[leaf]) != "9:1767409445000" || !bytes.Equal(fieldValues["since"], since) {
		t.Fatalf("acks: the family read whole: %v %v", fieldValues, err)
	}
	if err := target.Redis.Delete(ctx, []string{key}); err != nil {
		t.Fatalf("acks: the shred's delete: %v", err)
	}
	if fieldValues, err := target.Redis.HashGetAll(ctx, key); err != nil || len(fieldValues) != 0 {
		t.Errorf("acks: a deleted family reads %v %v", fieldValues, err)
	}
	if found, err := target.Redis.Expire(ctx, key, time.Hour); err != nil || found {
		t.Errorf("acks: a ttl on a deleted family: %t %v", found, err)
	}
}

// §11.12's shred on the store: every key under a group's prefix deleted a page at a time, and a repeat, ten minutes
// on, finds nothing and errs on nothing.
func gkmStoreSuiteShred(t testing.TB, ctx context.Context, target *GkmStoreSuiteTarget) {
	t.Helper()
	groupId := sidecar.NewId()
	keys := []string{target.EpochKey(groupId, 0), target.EpochKey(groupId, 1), target.GenerationKey(groupId, 1), target.GroupInfoKey(groupId)}
	for _, key := range keys {
		if _, err := target.Cluster.PutIfNoneMatch(ctx, key, []byte("an object of the group"), nil); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		gkmStoreSuiteDeletePrefix(t, ctx, target.Cluster, target.GroupPrefix(groupId))
	}
	page, _, err := target.Cluster.List(ctx, target.GroupPrefix(groupId), "", 10)
	if err != nil || len(page) != 0 {
		t.Errorf("shred: %d keys left: %v", len(page), err)
	}
}

// Deletes every key under prefix, two at a time.
func gkmStoreSuiteDeletePrefix(t testing.TB, ctx context.Context, cluster sidecar.BlobCluster, prefix string) {
	t.Helper()
	startAfter := ""
	for {
		page, more, err := cluster.List(ctx, prefix, startAfter, 2)
		if err != nil {
			t.Fatalf("delete %s: %v", prefix, err)
		}
		for _, info := range page {
			if err := cluster.Delete(ctx, info.Key); err != nil {
				t.Fatalf("delete %s: %v", info.Key, err)
			}
		}
		if !more || len(page) == 0 {
			return
		}
		startAfter = page[len(page)-1].Key
	}
}

// Deletes what a case left of a group, so a real store keeps nothing of a run.
func gkmStoreSuiteCleanUp(t testing.TB, ctx context.Context, target *GkmStoreSuiteTarget, groupId sidecar.Id) {
	t.Helper()
	gkmStoreSuiteDeletePrefix(t, ctx, target.Cluster, target.GroupPrefix(groupId))
}
