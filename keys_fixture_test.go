// What the keychain's tests share: a key store and a clock a test steers, and the steps every test
// repeats. Each test owns its own medium.

package sidecar

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"maps"
	"sync"
	"testing"
	"time"
)

// The pass at its least cost, so a suite runs Argon2id many times. A test about the default cost says
// so, and §5.9's numbers are held in settings_test.go.
func cheapKeychainSettings() *SidecarSettings {
	settings := validSidecarSettings()
	settings.Log = NewNoopLogger()
	settings.KeychainSettings.PassMemoryByteCount = 64 * 1024
	settings.KeychainSettings.PassIterationCount = 1
	settings.KeychainSettings.PassThreadCount = 1
	return settings
}

// A key store a test steers: it answers readStatus and writeStatus while they are set, and works
// otherwise. Every call is counted, so a test can show nothing was asked of it.
type fakeKeyStore struct {
	stateLock   sync.Mutex
	nameValues  map[string][]byte
	readStatus  *SidecarKeyStoreStatus
	writeStatus *SidecarKeyStoreStatus
	writeCount  int
	deleteCount int
}

// A working store holding nothing.
func newFakeKeyStore() *fakeKeyStore {
	return &fakeKeyStore{nameValues: map[string][]byte{}}
}

// Keeps a copy, unless a status is set.
func (self *fakeKeyStore) PutSecret(name string, value []byte) SidecarKeyStoreStatus {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.writeStatus != nil {
		return *self.writeStatus
	}
	self.writeCount += 1
	self.nameValues[name] = bytes.Clone(value)
	return SidecarKeyStoreOk
}

// A copy, Absent, or the status set.
func (self *fakeKeyStore) GetSecret(name string) ([]byte, SidecarKeyStoreStatus) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.readStatus != nil {
		return nil, *self.readStatus
	}
	value, ok := self.nameValues[name]
	if !ok {
		return nil, SidecarKeyStoreAbsent
	}
	return bytes.Clone(value), SidecarKeyStorePresent
}

// Forgets name, unless a status is set.
func (self *fakeKeyStore) DeleteSecret(name string) SidecarKeyStoreStatus {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.writeStatus != nil {
		return *self.writeStatus
	}
	self.deleteCount += 1
	delete(self.nameValues, name)
	return SidecarKeyStoreOk
}

// Every read and write answers status from here on, as a store that locked or broke does.
func (self *fakeKeyStore) answer(status SidecarKeyStoreStatus) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.readStatus = &status
	self.writeStatus = &status
}

// Back to working, with what it held.
func (self *fakeKeyStore) recover() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.readStatus = nil
	self.writeStatus = nil
}

// Loses every item, as a wiped keychain does.
func (self *fakeKeyStore) lose() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.nameValues = map[string][]byte{}
}

// What it holds.
func (self *fakeKeyStore) snapshot() map[string][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return maps.Clone(self.nameValues)
}

// A clock a test moves, and a timer that fires when the test says.
type testClock struct {
	stateLock sync.Mutex
	current   time.Time
	// what the run loop last armed, which a test reads to see the timer is set
	timerArmed chan time.Duration
	// fires the armed timer
	timerFire chan time.Time
}

// A fixed date, so a test repeats.
func newTestClock() *testClock {
	return &testClock{
		current:    time.Date(2026, time.March, 4, 5, 6, 7, 0, time.UTC),
		timerArmed: make(chan time.Duration, 64),
		timerFire:  make(chan time.Time),
	}
}

// What a SidecarInstance reads as now.
func (self *testClock) now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.current
}

// Moves the clock, backward with a negative by.
func (self *testClock) advance(by time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.current = self.current.Add(by)
}

// Reports what was armed, and answers the channel a test fires.
func (self *testClock) after(timeout time.Duration) <-chan time.Time {
	self.timerArmed <- timeout
	return self.timerFire
}

// An instance on the given medium and clock, closed at the test's end. Its auto-lock is off unless
// settings turn it on.
func openTestInstance(t *testing.T, backend SidecarStoreBackend, keyStore SidecarKeyStore, settings *SidecarSettings,
	clock *testClock) *SidecarInstance {
	t.Helper()
	instance, err := newSidecarInstance(
		context.Background(),
		&SidecarInstanceArgs{Backend: backend, KeyStore: keyStore, Settings: settings},
		clock.now,
		clock.after,
		rand.Reader,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(instance.Close)
	return instance
}

// An instance with no auto-lock, for a test about something else.
func newInstanceOn(t *testing.T, backend SidecarStoreBackend, keyStore SidecarKeyStore) *SidecarInstance {
	t.Helper()
	settings := cheapKeychainSettings()
	settings.KeychainSettings.AutoLockTimeout = 0
	return openTestInstance(t, backend, keyStore, settings, newTestClock())
}

// Every file and its bytes, for proving nothing changed.
func backendSnapshot(t *testing.T, backend SidecarStoreBackend) map[string][]byte {
	t.Helper()
	entries, err := backend.List("")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := map[string][]byte{}
	for _, entry := range entries {
		reader, err := backend.Open(entry.Name)
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		snapshot[entry.Name] = content
	}
	return snapshot
}

// Fails on any file added, gone or changed since want.
func requireSameBackend(t *testing.T, want map[string][]byte, backend SidecarStoreBackend) {
	t.Helper()
	got := backendSnapshot(t, backend)
	if !maps.EqualFunc(want, got, bytes.Equal) {
		t.Errorf("the backend changed: had %d files, has %d", len(want), len(got))
		for path := range got {
			if !bytes.Equal(want[path], got[path]) {
				t.Errorf("%s differs", path)
			}
		}
		for path := range want {
			if _, ok := got[path]; !ok {
				t.Errorf("%s is gone", path)
			}
		}
	}
}

// Overwrites path with content, as damage on the medium would.
func putBackendFile(t *testing.T, backend SidecarStoreBackend, path string, content []byte) {
	t.Helper()
	if err := writeBackendFile(backend, path, content); err != nil {
		t.Fatal(err)
	}
}

// The bytes at path, which must be there.
func readBackend(t *testing.T, backend SidecarStoreBackend, path string) []byte {
	t.Helper()
	content, err := readBackendFile(backend, path, 16*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

// One enrolled network, as CORE-M1-09 leaves it.
func enrollTestNetwork(t *testing.T, instance *SidecarInstance, networkId Id) *keychain {
	t.Helper()
	opened, err := instance.createKeychain(networkId)
	if err != nil {
		t.Fatal(err)
	}
	if err := opened.secrets("identity").Put("seed", []byte("synthetic seed of "+networkId.String())); err != nil {
		t.Fatal(err)
	}
	err = instance.RecordNetwork(SidecarNetworkRecord{
		NetworkId:         networkId,
		ClientId:          NewId(),
		SidecarId:         NewId(),
		ConnectInstanceId: NewId(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return opened
}

// A class's store for a network.
func storeOf(t *testing.T, instance *SidecarInstance, networkId Id, class string) SidecarStore {
	t.Helper()
	store, err := instance.Store(&networkId).Directory(class, class)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// putStoreFile, which must work.
func writeStoreFile(t *testing.T, store SidecarStore, name string, content []byte) {
	t.Helper()
	if err := putStoreFile(store, name, content); err != nil {
		t.Fatal(err)
	}
}

// A whole file by a writer's steps.
func putStoreFile(store SidecarStore, name string, content []byte) error {
	writer, err := store.Create(name)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(content); err != nil {
		return err
	}
	return writer.Commit()
}

// A whole file, or what stopped the read.
func readStoreFile(store SidecarStore, name string) ([]byte, error) {
	reader, err := store.Open(name)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

// Fails unless name holds want.
func requireStoreFile(t *testing.T, store SidecarStore, name string, want []byte) {
	t.Helper()
	got, err := readStoreFile(store, name)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s: %d bytes, want %d", name, len(got), len(want))
	}
}

// Fails unless the instance reads want now.
func requireState(t *testing.T, instance *SidecarInstance, want SidecarInstanceState) {
	t.Helper()
	if state := instance.state.Value(); state != want {
		t.Errorf("state %s, want %s", state, want)
	}
}
