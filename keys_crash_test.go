// A machine that can lose power at any step (§22.8's kills mid-keychain write): every Sync, Rename,
// SyncDirectory, Remove and key store write is a numbered step, and a run dies at the one a test names.
// What the medium keeps after that is what a power cut keeps, in its worst case or its best: a rename
// not yet fsynced into its directory is lost or kept, by the choice given to reboot.

package sidecar

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"maps"
	"path"
	"strings"
	"sync"
	"testing"
)

var errKilled = errors.New("the power went out")

// One machine, its medium and its key store. Safe for concurrent use.
type crashWorld struct {
	t         *testing.T
	stateLock sync.Mutex
	// what a reader sees
	visible map[string][]byte
	// for each renamed or removed path whose directory has not been fsynced, what was there before
	unsynced map[string][]byte
	// the key store's items, which a store's own guarantee keeps
	keyStoreItems map[string][]byte
	steps         int
	dieAt         int
	dead          bool
	// names each step, for a failure's message
	trace []string
}

// A machine with nothing on it.
func newCrashWorld(t *testing.T) *crashWorld {
	t.Helper()
	return &crashWorld{
		t:             t,
		visible:       map[string][]byte{},
		unsynced:      map[string][]byte{},
		keyStoreItems: map[string][]byte{},
	}
}

// Counts a step. Past the chosen one, nothing happens at all: the machine is off.
func (self *crashWorld) step(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.dead {
		return errKilled
	}
	self.steps += 1
	self.trace = append(self.trace, name)
	if self.steps == self.dieAt {
		self.dead = true
		return errKilled
	}
	return nil
}

// The machine dies at the next step.
func (self *crashWorld) dieAtNextStep() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.dieAt = self.steps + 1
}

// Turns the machine back on. loseUnsynced is the worst case: every rename whose directory was not
// fsynced is undone, and every other survives.
func (self *crashWorld) reboot(loseUnsynced bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if loseUnsynced {
		for filePath, content := range self.unsynced {
			if content == nil {
				delete(self.visible, filePath)
			} else {
				self.visible[filePath] = content
			}
		}
	}
	self.unsynced = map[string][]byte{}
	self.dead = false
	self.dieAt = 0
	self.steps = 0
	self.trace = nil
}

// An independent copy of this machine as it stands, for a run that dies at another step.
func (self *crashWorld) clone() *crashWorld {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return &crashWorld{
		t:             self.t,
		visible:       maps.Clone(self.visible),
		unsynced:      maps.Clone(self.unsynced),
		keyStoreItems: maps.Clone(self.keyStoreItems),
	}
}

// An instance on this machine, at the least cost, with no auto-lock.
func (self *crashWorld) open(keyStore SidecarKeyStore) *SidecarInstance {
	self.t.Helper()
	settings := cheapKeychainSettings()
	settings.KeychainSettings.AutoLockTimeout = 0
	clock := newTestClock()
	instance, err := newSidecarInstance(
		context.Background(),
		&SidecarInstanceArgs{Backend: &crashBackend{world: self}, KeyStore: keyStore, Settings: settings},
		clock.now,
		clock.after,
		rand.Reader,
	)
	if err != nil {
		self.t.Fatal(err)
	}
	return instance
}

// This machine's key store.
func (self *crashWorld) keyStore() SidecarKeyStore {
	return &crashKeyStore{world: self}
}

// A SidecarStoreBackend on a crashWorld.
type crashBackend struct {
	world *crashWorld
}

// What a reader sees now, on a machine that is on.
func (self *crashBackend) Open(filePath string) (io.ReadCloser, error) {
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	if self.world.dead {
		return nil, errKilled
	}
	content, ok := self.world.visible[filePath]
	if !ok {
		return nil, ErrSidecarStoreAbsent
	}
	return io.NopCloser(bytes.NewReader(content)), nil
}

// A buffer until its Rename.
func (self *crashBackend) CreateTemp() (SidecarStoreBackendFile, error) {
	return &crashFile{world: self.world}, nil
}

// Makes durable every rename and remove in path's directory.
func (self *crashBackend) SyncDirectory(filePath string) error {
	if err := self.world.step("sync directory of " + filePath); err != nil {
		return err
	}
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	directory := path.Dir(filePath)
	for unsyncedPath := range self.world.unsynced {
		if path.Dir(unsyncedPath) == directory {
			delete(self.world.unsynced, unsyncedPath)
		}
	}
	return nil
}

// A step, undone by a power cut until its directory is synced.
func (self *crashBackend) Remove(filePath string) error {
	if err := self.world.step("remove " + filePath); err != nil {
		return err
	}
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	if _, ok := self.world.unsynced[filePath]; !ok {
		self.world.unsynced[filePath] = self.world.visible[filePath]
	}
	delete(self.world.visible, filePath)
	return nil
}

// What a reader sees now.
func (self *crashBackend) List(prefix string) ([]SidecarStoreEntry, error) {
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	if self.world.dead {
		return nil, errKilled
	}
	entries := []SidecarStoreEntry{}
	for filePath, content := range self.world.visible {
		if strings.HasPrefix(filePath, prefix) {
			entries = append(entries, SidecarStoreEntry{Name: filePath, ByteCount: int64(len(content))})
		}
	}
	return entries, nil
}

// Temp files here die with the machine.
func (self *crashBackend) RemoveTemp() error {
	return nil
}

// A temp file on a crashWorld. A rename before its Sync is the bug this exists to catch: a power cut
// could expose the name with no bytes behind it.
type crashFile struct {
	world  *crashWorld
	buffer bytes.Buffer
	synced bool
	done   bool
}

// Buffers p, which then needs a new fsync.
func (self *crashFile) Write(p []byte) (int, error) {
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	if self.world.dead {
		return 0, errKilled
	}
	self.synced = false
	return self.buffer.Write(p)
}

// A step, after which the bytes would survive.
func (self *crashFile) Sync() error {
	if err := self.world.step("fsync a temp file"); err != nil {
		return err
	}
	self.synced = true
	return nil
}

// A step, undone by a power cut until its directory is synced.
func (self *crashFile) Rename(filePath string) error {
	if !self.synced {
		self.world.t.Errorf("a rename to %s came before its fsync", filePath)
	}
	if err := self.world.step("rename to " + filePath); err != nil {
		return err
	}
	self.done = true
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	if _, ok := self.world.unsynced[filePath]; !ok {
		self.world.unsynced[filePath] = self.world.visible[filePath]
	}
	self.world.visible[filePath] = bytes.Clone(self.buffer.Bytes())
	return nil
}

// Drops the buffer.
func (self *crashFile) Discard() error {
	self.done = true
	return nil
}

// A SidecarKeyStore on a crashWorld.
type crashKeyStore struct {
	world *crashWorld
}

// A step, durable once it returns.
func (self *crashKeyStore) PutSecret(name string, value []byte) SidecarKeyStoreStatus {
	if err := self.world.step("key store put"); err != nil {
		return SidecarKeyStoreFailed
	}
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	self.world.keyStoreItems[name] = bytes.Clone(value)
	return SidecarKeyStoreOk
}

// What the store holds, on a machine that is on.
func (self *crashKeyStore) GetSecret(name string) ([]byte, SidecarKeyStoreStatus) {
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	if self.world.dead {
		return nil, SidecarKeyStoreFailed
	}
	value, ok := self.world.keyStoreItems[name]
	if !ok {
		return nil, SidecarKeyStoreAbsent
	}
	return bytes.Clone(value), SidecarKeyStorePresent
}

// A step, durable once it returns.
func (self *crashKeyStore) DeleteSecret(name string) SidecarKeyStoreStatus {
	if err := self.world.step("key store delete"); err != nil {
		return SidecarKeyStoreFailed
	}
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	delete(self.world.keyStoreItems, name)
	return SidecarKeyStoreOk
}

// Runs operation on a copy of world once to count its steps, then once for each step it died at, in the
// worst case and the best, handing each machine to check as it came back up. A step past the last runs
// the operation whole.
func forEachKill(t *testing.T, world *crashWorld, operation func(world *crashWorld) error,
	check func(world *crashWorld, trace []string, died bool)) {
	t.Helper()
	counted := world.clone()
	if err := operation(counted); err != nil {
		t.Fatalf("the unbroken run failed: %v", err)
	}
	stepCount := counted.steps
	if stepCount == 0 {
		t.Fatal("the operation took no step")
	}
	for dieAt := 1; dieAt <= stepCount+1; dieAt += 1 {
		for _, loseUnsynced := range []bool{true, false} {
			killed := world.clone()
			killed.dieAt = dieAt
			err := operation(killed)
			died := dieAt <= stepCount
			// a step whose failure the operation may ignore, such as restoring a store's wrap, dies
			// in silence, so a nil error says nothing: the machine being off is what counts
			if died && !killed.dead {
				t.Fatalf("no death at step %d of %d: %v", dieAt, stepCount, err)
			}
			trace := killed.trace
			killed.reboot(loseUnsynced)
			check(killed, trace, died)
		}
	}
}

// Comes up on world's key store, unlocked, as a restart would.
func restartOpen(t *testing.T, world *crashWorld, trace []string) *SidecarInstance {
	t.Helper()
	instance := world.open(world.keyStore())
	if err := instance.Unlock(nil); err != nil {
		t.Fatalf("after %q: %v", trace, err)
	}
	return instance
}

// A machine holding one enrolled network, a secret and a file, all durable.
func enrolledCrashWorld(t *testing.T) *crashWorld {
	t.Helper()
	world := newCrashWorld(t)
	instance := world.open(world.keyStore())
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	opened := enrollTestNetwork(t, instance, testNetworkId)
	if err := opened.secrets("evs").Put("key", []byte("old value")); err != nil {
		t.Fatal(err)
	}
	writeStoreFile(t, storeOf(t, instance, testNetworkId, "evs"), "file", []byte("old file"))
	instance.Close()
	world.reboot(false)
	return world
}

// §5.9's first run dies anywhere, and the next start still comes up, with one U.
func TestFirstRunSurvivesAKillAtEveryStep(t *testing.T) {
	world := newCrashWorld(t)
	operation := func(world *crashWorld) error {
		instance := world.open(world.keyStore())
		defer instance.Close()
		return instance.Unlock(nil)
	}
	forEachKill(t, world, operation, func(world *crashWorld, trace []string, died bool) {
		instance := restartOpen(t, world, trace)
		defer instance.Close()
		requireState(t, instance, SidecarInstanceOpen)
		unlockKey, err := instance.currentUnlockKey()
		if err != nil {
			t.Fatal(err)
		}
		instance.Close()

		again := restartOpen(t, world, trace)
		defer again.Close()
		reopenedKey, err := again.currentUnlockKey()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(unlockKey, reopenedKey) {
			t.Errorf("after %q: U changed on the second start", trace)
		}
	})
}

// §22.8: the keychain opens at its old or new state, never between, and never empty.
func TestKeychainWriteSurvivesAKillAtEveryStep(t *testing.T) {
	world := enrolledCrashWorld(t)
	operation := func(world *crashWorld) error {
		instance := world.open(world.keyStore())
		defer instance.Close()
		if err := instance.Unlock(nil); err != nil {
			return err
		}
		opened, err := instance.keychainFor(testNetworkId)
		if err != nil {
			return err
		}
		return opened.secrets("evs").Put("key", []byte("new value"))
	}
	forEachKill(t, world, operation, func(world *crashWorld, trace []string, died bool) {
		instance := restartOpen(t, world, trace)
		defer instance.Close()
		opened, err := instance.keychainFor(testNetworkId)
		if err != nil {
			t.Fatalf("after %q: %v", trace, err)
		}
		value, err := opened.secrets("evs").Get("key")
		if err != nil {
			t.Fatalf("after %q: %v", trace, err)
		}
		if string(value) != "old value" && string(value) != "new value" {
			t.Errorf("after %q: value %q", trace, value)
		}
		if !died && string(value) != "new value" {
			t.Errorf("a finished write was lost")
		}
		if _, err := opened.secrets("identity").Get("seed"); err != nil {
			t.Errorf("after %q: the identity is gone: %v", trace, err)
		}
	})
}

func TestFileWriteSurvivesAKillAtEveryStep(t *testing.T) {
	world := enrolledCrashWorld(t)
	operation := func(world *crashWorld) error {
		instance := world.open(world.keyStore())
		defer instance.Close()
		if err := instance.Unlock(nil); err != nil {
			return err
		}
		store, err := instance.Store(&testNetworkId).Directory("evs", "evs")
		if err != nil {
			return err
		}
		return putStoreFile(store, "file", []byte("new file"))
	}
	forEachKill(t, world, operation, func(world *crashWorld, trace []string, died bool) {
		instance := restartOpen(t, world, trace)
		defer instance.Close()
		content, err := readStoreFile(storeOf(t, instance, testNetworkId, "evs"), "file")
		if err != nil {
			t.Fatalf("after %q: %v", trace, err)
		}
		if string(content) != "old file" && string(content) != "new file" {
			t.Errorf("after %q: content %q", trace, content)
		}
		if !died && string(content) != "new file" {
			t.Errorf("a finished write was lost")
		}
	})
}

// A write whose Commit returned survives a power cut, which is what its fsyncs are for. Each step of
// the write is in its place, and the worst case keeps the file only because the directory was synced.
func TestACommittedFileSurvivesThePowerGoingOut(t *testing.T) {
	world := enrolledCrashWorld(t)
	instance := world.open(world.keyStore())
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	writeStoreFile(t, storeOf(t, instance, testNetworkId, "evs"), "file", []byte("new file"))
	instance.Close()

	world.reboot(true)
	reopened := world.open(world.keyStore())
	defer reopened.Close()
	if err := reopened.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	requireStoreFile(t, storeOf(t, reopened, testNetworkId, "evs"), "file", []byte("new file"))
}

// §5.9's pass change dies anywhere: the old pass or the new one opens the same U.
func TestChangePassSurvivesAKillAtEveryStep(t *testing.T) {
	world := enrolledCrashWorld(t)
	setup := world.open(world.keyStore())
	if err := setup.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	if err := setup.ChangePass(nil, testPass); err != nil {
		t.Fatal(err)
	}
	unlockKey, err := setup.currentUnlockKey()
	if err != nil {
		t.Fatal(err)
	}
	setup.Close()
	world.reboot(false)
	next := []byte("synthetic next pass")

	operation := func(world *crashWorld) error {
		instance := world.open(world.keyStore())
		defer instance.Close()
		if err := instance.Unlock(nil); err != nil {
			return err
		}
		return instance.ChangePass(testPass, next)
	}
	forEachKill(t, world, operation, func(world *crashWorld, trace []string, died bool) {
		instance := world.open(nil)
		defer instance.Close()
		// a kill may have used an attempt of the five, and this opens within them
		err := instance.Unlock(next)
		if errors.Is(err, ErrSidecarPassRefused) {
			if died {
				err = instance.Unlock(testPass)
			}
		}
		if err != nil {
			t.Fatalf("after %q: %v", trace, err)
		}
		opened, err := instance.currentUnlockKey()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(opened, unlockKey) {
			t.Errorf("after %q: another U", trace)
		}
	})
}

// A network's first keychain dies anywhere. The next enrollment finds what is there and goes on.
func TestEnrollmentSurvivesAKillAtEveryStep(t *testing.T) {
	world := newCrashWorld(t)
	setup := world.open(world.keyStore())
	if err := setup.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	setup.Close()
	world.reboot(false)

	enroll := func(instance *SidecarInstance) error {
		opened, err := instance.createKeychain(testNetworkId)
		if err != nil {
			return err
		}
		if err := opened.secrets("identity").Put("seed", []byte("synthetic seed")); err != nil {
			return err
		}
		return instance.RecordNetwork(SidecarNetworkRecord{
			NetworkId:         testNetworkId,
			ClientId:          Id{1},
			SidecarId:         Id{2},
			ConnectInstanceId: Id{3},
		})
	}
	operation := func(world *crashWorld) error {
		instance := world.open(world.keyStore())
		defer instance.Close()
		if err := instance.Unlock(nil); err != nil {
			return err
		}
		return enroll(instance)
	}
	forEachKill(t, world, operation, func(world *crashWorld, trace []string, died bool) {
		instance := restartOpen(t, world, trace)
		defer instance.Close()
		if err := enroll(instance); err != nil {
			t.Fatalf("after %q: %v", trace, err)
		}
		opened, err := instance.keychainFor(testNetworkId)
		if err != nil {
			t.Fatalf("after %q: %v", trace, err)
		}
		if seed, err := opened.secrets("identity").Get("seed"); err != nil || string(seed) != "synthetic seed" {
			t.Errorf("after %q: seed %q, err %v", trace, seed, err)
		}
	})
}

// Putting W back after a loss dies anywhere, and the pass still opens U.
func TestRestoringTheStoreWrapSurvivesAKillAtEveryStep(t *testing.T) {
	world := enrolledCrashWorld(t)
	setup := world.open(world.keyStore())
	if err := setup.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	if err := setup.ChangePass(nil, testPass); err != nil {
		t.Fatal(err)
	}
	unlockKey, err := setup.currentUnlockKey()
	if err != nil {
		t.Fatal(err)
	}
	setup.Close()
	world.reboot(false)
	clear(world.keyStoreItems)

	operation := func(world *crashWorld) error {
		instance := world.open(world.keyStore())
		defer instance.Close()
		return instance.Unlock(testPass)
	}
	forEachKill(t, world, operation, func(world *crashWorld, trace []string, died bool) {
		instance := world.open(world.keyStore())
		defer instance.Close()
		err := instance.Unlock(nil)
		if err != nil {
			if !died || !errors.Is(err, ErrSidecarKeystoreLost) {
				t.Fatalf("after %q: %v", trace, err)
			}
			if err := instance.Unlock(testPass); err != nil {
				t.Fatalf("after %q: %v", trace, err)
			}
		}
		opened, err := instance.currentUnlockKey()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(opened, unlockKey) {
			t.Errorf("after %q: another U", trace)
		}
	})
}
