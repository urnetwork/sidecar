//go:build !ios_extension && !sidecar_http

// The store (ATTEST-M11-01): only higher versions, never one older than the release's copy, across restarts; the
// highest version seen, persisted; the release's copy alone while the file cannot be read; and the component on a
// Sidecar, which in a build from this tree pins no root.

package sidecar

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

// A clock a test sets, which never fires: the store and gate read it and wait on nothing.
type testAttestClock struct {
	stateLock sync.Mutex
	now       time.Time
}

func newTestAttestClock(at time.Time) *testAttestClock {
	return &testAttestClock{now: at}
}

func (self *testAttestClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

func (self *testAttestClock) Set(at time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.now = at
}

func (self *testAttestClock) After(timeout time.Duration) <-chan time.Time {
	return make(chan time.Time)
}

func (self *testAttestClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return func() bool { return true }
}

// A test's world for the store: the keys, a verifier over them, a clock and a sealed attest directory.
type testAttestStoreWorld struct {
	keys     *testAttestKeys
	verifier *ComputePolicyVerifier
	clock    *testAttestClock
	store    SidecarStore
}

func newTestAttestStoreWorld(t *testing.T) *testAttestStoreWorld {
	t.Helper()
	instance, _, _ := enrolledInstance(t)
	keys := newTestAttestKeys(t)
	return &testAttestStoreWorld{
		keys:     keys,
		verifier: keys.verifier(false),
		clock:    newTestAttestClock(testAttestNow),
		store:    storeOf(t, instance, testNetworkId, computePolicyStoreClass),
	}
}

// The vector at version, signed.
func (self *testAttestStoreWorld) policy(t *testing.T, version int) (document []byte, signature []byte) {
	t.Helper()
	document = testAttestPolicyVersion(t, version)
	return document, testAttestSign(t, self.keys.policy, ComputePolicyNamespace, document)
}

// A store over the world's directory, its release's copy the vector at releaseVersion, or none at 0.
func (self *testAttestStoreWorld) open(t *testing.T, releaseVersion int) *ComputePolicyStore {
	t.Helper()
	args := &ComputePolicyStoreArgs{
		Store:        self.store,
		Verifier:     self.verifier,
		Settings:     DefaultAttestSettings(),
		Clock:        self.clock,
		releaseGiven: true,
	}
	if 0 < releaseVersion {
		args.releaseDocument, args.releaseSignature = self.policy(t, releaseVersion)
	}
	store, err := NewComputePolicyStore(args)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// The newest's version, 0 for none.
func testAttestNewestVersion(store *ComputePolicyStore) uint64 {
	if newest := store.Newest(); newest != nil {
		return newest.Version
	}
	return 0
}

// A higher version is taken, an older one or one under the release's copy refused, the same document again is the
// newest, the same version with other bytes a conflict; a restart keeps what was taken, and a newer release's copy
// outranks it.
func TestComputePolicyStoreTakesOnlyHigher(t *testing.T) {
	world := newTestAttestStoreWorld(t)
	store := world.open(t, 3)
	if testAttestNewestVersion(store) != 3 || store.HighestSeen() != 3 || store.Release() == nil || store.Release().Version != 3 {
		t.Fatalf("from the release's copy: newest %d, highest %d", testAttestNewestVersion(store), store.HighestSeen())
	}
	if _, err := store.Offer(world.policy(t, 2)); !errors.Is(err, ErrComputePolicyStale) {
		t.Errorf("a policy older than the release's copy: %v", err)
	}
	taken, err := store.Offer(world.policy(t, 4))
	if err != nil || taken.Version != 4 || testAttestNewestVersion(store) != 4 || store.HighestSeen() != 4 {
		t.Fatalf("version 4: %v, %v, newest %d", taken, err, testAttestNewestVersion(store))
	}
	if _, err := store.Offer(world.policy(t, 3)); !errors.Is(err, ErrComputePolicyStale) {
		t.Errorf("an older version after a newer: %v", err)
	}
	again, err := store.Offer(world.policy(t, 4))
	if err != nil || again != store.Newest() {
		t.Errorf("the same document again: %v, %v", again, err)
	}
	other := testAttestPolicyEdit(t, `"version": 3,`, `"version": 4,`)
	other = []byte(string(other)[:len(other)-2] + " \n}\n")
	if _, err := store.Offer(other, testAttestSign(t, world.keys.policy, ComputePolicyNamespace, other)); !errors.Is(err, ErrComputePolicyConflict) {
		t.Errorf("version 4 with other bytes: %v", err)
	}
	if _, err := store.Offer(testAttestPolicyVersion(t, 5), testAttestVector(t, "policy.json.sig")); !errors.Is(err, ErrComputePolicyRefused) {
		t.Errorf("version 5 under another document's signature: %v", err)
	}
	if testAttestNewestVersion(store) != 4 {
		t.Errorf("a refusal moved the newest to %d", testAttestNewestVersion(store))
	}

	restarted := world.open(t, 3)
	if testAttestNewestVersion(restarted) != 4 || restarted.HighestSeen() != 4 {
		t.Errorf("after a restart: newest %d, highest %d", testAttestNewestVersion(restarted), restarted.HighestSeen())
	}
	if _, err := restarted.Offer(world.policy(t, 3)); !errors.Is(err, ErrComputePolicyStale) {
		t.Errorf("after a restart, an older version: %v", err)
	}

	upgraded := world.open(t, 6)
	if testAttestNewestVersion(upgraded) != 6 || upgraded.HighestSeen() != 6 {
		t.Errorf("a newer release's copy: newest %d, highest %d", testAttestNewestVersion(upgraded), upgraded.HighestSeen())
	}
	if _, err := upgraded.Offer(world.policy(t, 5)); !errors.Is(err, ErrComputePolicyStale) {
		t.Errorf("a version under the newer release's copy: %v", err)
	}
}

// The highest version anything verified named survives a restart, and only rises.
func TestComputePolicyHighestSeenPersists(t *testing.T) {
	world := newTestAttestStoreWorld(t)
	store := world.open(t, 0)
	if store.Newest() != nil || store.HighestSeen() != 0 {
		t.Fatalf("a store with no copy: %v, %d", store.Newest(), store.HighestSeen())
	}
	if _, err := store.Offer(world.policy(t, 4)); err != nil {
		t.Fatal(err)
	}
	if err := store.noteVersionSeen(7); err != nil || store.HighestSeen() != 7 {
		t.Fatalf("noting version 7: %v, %d", err, store.HighestSeen())
	}
	if err := store.noteVersionSeen(5); err != nil || store.HighestSeen() != 7 {
		t.Errorf("a lower version moved it: %v, %d", err, store.HighestSeen())
	}
	restarted := world.open(t, 0)
	if restarted.HighestSeen() != 7 || testAttestNewestVersion(restarted) != 4 {
		t.Errorf("after a restart: highest %d, newest %d", restarted.HighestSeen(), testAttestNewestVersion(restarted))
	}
	if _, err := restarted.Offer(world.policy(t, 7)); err != nil || restarted.HighestSeen() != 7 || testAttestNewestVersion(restarted) != 7 {
		t.Errorf("the version seen, taken: %v, highest %d", err, restarted.HighestSeen())
	}
}

// A policy past its not_after stays the newest and answers not current; the gate decides what that stops.
func TestComputePolicyStoreKeepsAPolicyPastItsNotAfter(t *testing.T) {
	world := newTestAttestStoreWorld(t)
	store := world.open(t, 3)
	past := time.Date(2027, time.March, 1, 0, 0, 0, 0, time.UTC)
	world.clock.Set(past)
	taken, err := store.Offer(world.policy(t, 4))
	if err != nil || store.Newest() != taken || taken.Current(past) || !taken.Current(testAttestNow) {
		t.Errorf("a policy past its not_after: %v, current %t", err, taken != nil && taken.Current(past))
	}
}

// A store that cannot read its file, before enrollment or while its keychain is locked: unlockable at will.
type testAttestLockedStore struct {
	stateLock sync.Mutex
	open      SidecarStore
}

func (self *testAttestLockedStore) unlock(store SidecarStore) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.open = store
}

func (self *testAttestLockedStore) current() (SidecarStore, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.open == nil {
		return nil, ErrSidecarStoreLocked
	}
	return self.open, nil
}

func (self *testAttestLockedStore) Open(name string) (io.ReadCloser, error) {
	store, err := self.current()
	if err != nil {
		return nil, err
	}
	return store.Open(name)
}

func (self *testAttestLockedStore) Create(name string) (SidecarStoreWriter, error) {
	store, err := self.current()
	if err != nil {
		return nil, err
	}
	return store.Create(name)
}

func (self *testAttestLockedStore) Remove(name string) error {
	store, err := self.current()
	if err != nil {
		return err
	}
	return store.Remove(name)
}

func (self *testAttestLockedStore) List(prefix string) ([]SidecarStoreEntry, error) {
	store, err := self.current()
	if err != nil {
		return nil, err
	}
	return store.List(prefix)
}

func (self *testAttestLockedStore) Directory(name string, class string) (SidecarStore, error) {
	store, err := self.current()
	if err != nil {
		return nil, err
	}
	return store.Directory(name, class)
}

// While the file cannot be read, the release's copy serves alone and nothing new is taken, though what an offer named
// raises the highest seen in memory; once it can, the file is read and offers are taken.
func TestComputePolicyStoreServesTheReleaseCopyWhileLocked(t *testing.T) {
	world := newTestAttestStoreWorld(t)
	locked := &testAttestLockedStore{}
	unlocked := world.store
	world.store = locked
	store := world.open(t, 3)
	if testAttestNewestVersion(store) != 3 {
		t.Fatalf("locked: newest %d", testAttestNewestVersion(store))
	}
	if _, err := store.Offer(world.policy(t, 4)); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Errorf("an offer while locked: %v", err)
	}
	if testAttestNewestVersion(store) != 3 || store.HighestSeen() != 4 {
		t.Errorf("after a locked offer: newest %d, highest %d", testAttestNewestVersion(store), store.HighestSeen())
	}
	locked.unlock(unlocked)
	if _, err := store.Offer(world.policy(t, 4)); err != nil || testAttestNewestVersion(store) != 4 {
		t.Errorf("unlocked: %v, newest %d", err, testAttestNewestVersion(store))
	}
}

// A state file whose policy this build refuses, its pins changed, is dropped as it is read, keeping what it named.
func TestComputePolicyStoreDropsWhatThisBuildRefuses(t *testing.T) {
	world := newTestAttestStoreWorld(t)
	if _, err := world.open(t, 0).Offer(world.policy(t, 4)); err != nil {
		t.Fatal(err)
	}
	world.verifier = newComputePolicyVerifier(DefaultAttestSettings(), nil, ComputePolicyNamespace, false)
	world.verifier.roots = append(world.verifier.roots, world.keys.otherRelease.PublicKey())
	reopened := world.open(t, 0)
	if reopened.Newest() != nil || reopened.HighestSeen() != 4 {
		t.Errorf("a refused state: newest %v, highest %d", reopened.Newest(), reopened.HighestSeen())
	}
}

// The release's copy is both files or none; half a copy is an error.
func TestComputePolicyReleaseCopyIsWholeOrAbsent(t *testing.T) {
	directory := "release"
	both := fstest.MapFS{
		directory + "/" + computePolicyReleaseDocumentName:  {Data: []byte("document")},
		directory + "/" + computePolicyReleaseSignatureName: {Data: []byte("signature")},
		directory + "/README.md":                            {Data: []byte("readme")},
	}
	document, signature, err := computePolicyReleaseCopyFrom(both, directory)
	if err != nil || string(document) != "document" || string(signature) != "signature" {
		t.Errorf("both: %q, %q, %v", document, signature, err)
	}
	none := fstest.MapFS{directory + "/README.md": {Data: []byte("readme")}}
	if document, signature, err := computePolicyReleaseCopyFrom(none, directory); document != nil || signature != nil || err != nil {
		t.Errorf("none: %q, %q, %v", document, signature, err)
	}
	half := fstest.MapFS{directory + "/" + computePolicyReleaseDocumentName: {Data: []byte("document")}}
	if _, _, err := computePolicyReleaseCopyFrom(half, directory); err == nil {
		t.Error("half a copy was taken")
	}
}

// A source build embeds no copy, only the directory's README.
func TestComputePolicySourceBuildCarriesNoReleaseCopy(t *testing.T) {
	document, signature, err := computePolicyReleaseCopy()
	if document != nil || signature != nil || err != nil {
		t.Errorf("a source build's copy: %d bytes, %d bytes, %v", len(document), len(signature), err)
	}
}

// On a Sidecar the component is constructed with it, serves no policy in a build from this tree, and refuses every
// offer, since the build pins no release key.
func TestSidecarComputePolicyStoreRefusesWithNoRoot(t *testing.T) {
	if computePolicyReleaseKeys != "" {
		t.Skip("this build pins a release key")
	}
	instance, enrollment := newTestEnrolledInstance(t)
	platform := newTestSidecarPlatform()
	sidecar, err := NewSidecar(context.Background(), &testSidecarHost{store: instance.Store(&enrollment.networkId)}, nil, testSidecarSettings(platform))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), sidecarTestTimeout)
		defer cancel()
		sidecar.CloseAndWait(ctx)
	})
	store, err := sidecar.ComputePolicyStore()
	if err != nil {
		t.Fatal(err)
	}
	if store.Newest() != nil || store.HighestSeen() != 0 {
		t.Errorf("a source build's store: %v, %d", store.Newest(), store.HighestSeen())
	}
	document := testAttestPolicyDocument(t)
	if _, err := store.Offer(document, testAttestVector(t, "policy.json.sig")); !errors.Is(err, errComputePolicyNoRoot) {
		t.Errorf("an offer to a build with no root: %v", err)
	}
}
