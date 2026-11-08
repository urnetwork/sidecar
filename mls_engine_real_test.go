// Fixtures for driving real engines in the root's tests: a store in memory that can fail its writes from some
// point on, a fixed clock, and sidecars admitted to one another. sidecartest/mlssuite runs the seam's suite on
// the same engine from outside the package.

package sidecar

import (
	"bytes"
	"errors"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// What a failing mlsTestStore write answers.
var errMlsTestStoreWrite = errors.New("test store: write failed")

// One network's files in memory, unsealed, shared by every directory taken from it.
type mlsTestStore struct {
	shared *mlsTestStoreFiles
	prefix string
}

type mlsTestStoreFiles struct {
	stateLock    sync.Mutex
	pathContents map[string][]byte
	// writes left before every write fails, negative for no limit
	writesLeft int
}

func newMlsTestStore() *mlsTestStore {
	return &mlsTestStore{shared: &mlsTestStoreFiles{pathContents: map[string][]byte{}, writesLeft: -1}}
}

// After count more writes, every write fails, as a process killed there leaves the store.
func (self *mlsTestStore) failWritesAfter(count int) {
	self.shared.stateLock.Lock()
	defer self.shared.stateLock.Unlock()
	self.shared.writesLeft = count
}

// Every path held, sorted.
func (self *mlsTestStore) paths() []string {
	self.shared.stateLock.Lock()
	defer self.shared.stateLock.Unlock()
	return slices.Sorted(maps.Keys(self.shared.pathContents))
}

func (self *mlsTestStoreFiles) takeWriteWithLock() error {
	if self.writesLeft == 0 {
		return errMlsTestStoreWrite
	}
	if 0 < self.writesLeft {
		self.writesLeft -= 1
	}
	return nil
}

func (self *mlsTestStore) Open(name string) (io.ReadCloser, error) {
	self.shared.stateLock.Lock()
	defer self.shared.stateLock.Unlock()
	content, ok := self.shared.pathContents[self.prefix+name]
	if !ok {
		return nil, ErrSidecarStoreAbsent
	}
	return io.NopCloser(bytes.NewReader(bytes.Clone(content))), nil
}

func (self *mlsTestStore) Create(name string) (SidecarStoreWriter, error) {
	if !isStoreName(name) {
		return nil, ErrSidecarStoreName
	}
	return &mlsTestStoreWriter{shared: self.shared, path: self.prefix + name}, nil
}

func (self *mlsTestStore) Remove(name string) error {
	self.shared.stateLock.Lock()
	defer self.shared.stateLock.Unlock()
	if _, ok := self.shared.pathContents[self.prefix+name]; !ok {
		return nil
	}
	if err := self.shared.takeWriteWithLock(); err != nil {
		return err
	}
	delete(self.shared.pathContents, self.prefix+name)
	return nil
}

func (self *mlsTestStore) List(prefix string) ([]SidecarStoreEntry, error) {
	self.shared.stateLock.Lock()
	defer self.shared.stateLock.Unlock()
	entries := []SidecarStoreEntry{}
	for path, content := range self.shared.pathContents {
		if name, ok := strings.CutPrefix(path, self.prefix); ok && strings.HasPrefix(name, prefix) {
			entries = append(entries, SidecarStoreEntry{Name: name, ByteCount: int64(len(content))})
		}
	}
	slices.SortFunc(entries, func(first SidecarStoreEntry, second SidecarStoreEntry) int { return strings.Compare(first.Name, second.Name) })
	return entries, nil
}

func (self *mlsTestStore) Directory(name string, class string) (SidecarStore, error) {
	if name == "" {
		return self, nil
	}
	return &mlsTestStore{shared: self.shared, prefix: self.prefix + name + "/"}, nil
}

type mlsTestStoreWriter struct {
	shared  *mlsTestStoreFiles
	path    string
	content bytes.Buffer
}

func (self *mlsTestStoreWriter) Write(data []byte) (int, error) {
	return self.content.Write(data)
}

func (self *mlsTestStoreWriter) Commit() error {
	self.shared.stateLock.Lock()
	defer self.shared.stateLock.Unlock()
	if err := self.shared.takeWriteWithLock(); err != nil {
		return err
	}
	self.shared.pathContents[self.path] = bytes.Clone(self.content.Bytes())
	return nil
}

func (self *mlsTestStoreWriter) Close() error {
	return nil
}

// A clock that stands where a test puts it.
type mlsTestClock struct {
	stateLock sync.Mutex
	at        time.Time
}

func (self *mlsTestClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.at
}

func (self *mlsTestClock) advance(by time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.at = self.at.Add(by)
}

func (self *mlsTestClock) After(timeout time.Duration) <-chan time.Time {
	return make(chan time.Time)
}

func (self *mlsTestClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return func() bool { return true }
}

// The identity keys a test admitted, which every engine of it checks credentials against, as KEYS-M2-19's check
// will through the log.
type mlsTestAdmissions struct {
	stateLock sync.Mutex
	signers   []*gkmTestSigner
}

func (self *mlsTestAdmissions) admit(signer *gkmTestSigner) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.signers = append(self.signers, signer)
}

func (self *mlsTestAdmissions) check(credential *protocol.UrMlsCredential) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return mlsTestAdmit(self.signers...)(credential)
}

// One sidecar of a test: its identity, its store, and its engine, which restart replaces as a crash would.
type mlsTestSidecar struct {
	signer     *gkmTestSigner
	store      SidecarStore
	clock      *mlsTestClock
	admissions *mlsTestAdmissions
	suite      *mlsCipherSuite
	engine     *mlsEngine
}

// A world of sidecars on one clock, each admitted.
type mlsTestWorld struct {
	t          *testing.T
	clock      *mlsTestClock
	admissions *mlsTestAdmissions
	suite      *mlsCipherSuite
	count      int
}

func newMlsTestWorld(t *testing.T) *mlsTestWorld {
	return &mlsTestWorld{t: t, clock: &mlsTestClock{at: mlsTestTime}, admissions: &mlsTestAdmissions{}, suite: mlsSuite}
}

// A new sidecar, admitted, on store, or on a store of its own when nil.
func (self *mlsTestWorld) sidecar(store SidecarStore) *mlsTestSidecar {
	self.t.Helper()
	self.count += 1
	signer := newGkmTestSigner("world sidecar " + string(rune('a'+self.count)))
	signer.sidecarId = NewId()
	self.admissions.admit(signer)
	if store == nil {
		store = newMlsTestStore()
	}
	sidecar := &mlsTestSidecar{signer: signer, store: store, clock: self.clock, admissions: self.admissions, suite: self.suite}
	sidecar.restart(self.t)
	return sidecar
}

// A new engine on the same store, as after a crash: nothing but the store carries over.
func (self *mlsTestSidecar) restart(t *testing.T) {
	t.Helper()
	engine, err := newMlsEngine(&MlsEngineArgs{
		SidecarId:         self.signer.sidecarId,
		IdentityPublicKey: self.signer.publicKey(),
		AdmissionSha256:   gkmTestBytes("admission "+self.signer.sidecarId.String(), gkmDigestByteCount),
		Sign:              self.signer.sign,
		Store:             self.store,
		CheckCredential:   self.admissions.check,
		Clock:             self.clock,
	}, self.suite, defaultMlsGroupSettings())
	if err != nil {
		t.Fatal(err)
	}
	self.engine = engine
}

// A group self creates, then joiners added by one Add-only commit and joined, every member at epoch 1, in the
// order given, the creator first.
func mlsTestGroupOf(t *testing.T, creator *mlsTestSidecar, joiners ...*mlsTestSidecar) []MlsGroup {
	t.Helper()
	group, err := creator.engine.CreateGroup(NewId(), mlsTestUrGroup())
	if err != nil {
		t.Fatal(err)
	}
	if len(joiners) == 0 {
		return []MlsGroup{group}
	}
	adds := [][]byte{}
	for _, joiner := range joiners {
		keyPackage, err := joiner.engine.CreateKeyPackage(false)
		if err != nil {
			t.Fatal(err)
		}
		adds = append(adds, keyPackage.Encoded)
	}
	staged, err := group.Commit(&MlsCommitArgs{Adds: adds, AuthenticatedData: []byte("add")})
	if err != nil {
		t.Fatal(err)
	}
	groupInfo, err := staged.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	adopted, err := staged.Adopt()
	if err != nil {
		t.Fatal(err)
	}
	groups := []MlsGroup{adopted}
	for _, joiner := range joiners {
		pending, err := joiner.engine.JoinWelcome(staged.Welcome())
		if err != nil {
			t.Fatal(err)
		}
		joined, err := pending.Complete(groupInfo)
		if err != nil {
			t.Fatal(err)
		}
		groups = append(groups, joined)
	}
	return groups
}

// Has every group but the committer's process and adopt message, and returns the groups at the new epoch, the
// committer's from adopted.
func mlsTestFollow(t *testing.T, groups []MlsGroup, committer int, adopted MlsGroup, message []byte) []MlsGroup {
	t.Helper()
	next := []MlsGroup{}
	for index, group := range groups {
		if index == committer {
			next = append(next, adopted)
			continue
		}
		processed, err := group.Process(message)
		if err != nil {
			t.Fatalf("member %d processing: %v", index, err)
		}
		followed, err := processed.Adopt()
		if err != nil {
			t.Fatalf("member %d adopting: %v", index, err)
		}
		next = append(next, followed)
	}
	return next
}

// Fails unless every group is at one epoch with one authenticator and one KEK.
func mlsTestAgree(t *testing.T, groups []MlsGroup) {
	t.Helper()
	var kek []byte
	for index, group := range groups {
		if group.Epoch() != groups[0].Epoch() || !bytes.Equal(group.EpochAuthenticator(), groups[0].EpochAuthenticator()) {
			t.Fatalf("member %d at epoch %d with another authenticator", index, group.Epoch())
		}
		memberKek, err := MlsKek(group, gkmTestId("repo"))
		if err != nil {
			t.Fatal(err)
		}
		if kek == nil {
			kek = memberKek
		} else if !bytes.Equal(kek, memberKek) {
			t.Fatalf("member %d derives another KEK", index)
		}
	}
}
