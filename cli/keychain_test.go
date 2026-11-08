package main

import (
	"context"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar"
)

// Each platform's mapping of its answers onto D-CORE-15's statuses, through fake call tables, so every platform's
// rules run on any host.

// A darwinKeychainCalls answering the statuses a test sets, and panicking when told to.
type fakeKeychainCalls struct {
	copyStatus   int32
	addStatus    int32
	updateStatus int32
	removeStatus int32
	value        []byte
	panics       bool
}

func (self *fakeKeychainCalls) copyData(account string) ([]byte, int32) {
	if self.panics {
		panic("synthetic")
	}
	return self.value, self.copyStatus
}

func (self *fakeKeychainCalls) add(account string, value []byte) int32 {
	if self.panics {
		panic("synthetic")
	}
	return self.addStatus
}

func (self *fakeKeychainCalls) update(account string, value []byte) int32 {
	return self.updateStatus
}

func (self *fakeKeychainCalls) remove(account string) int32 {
	return self.removeStatus
}

// macOS: errSecItemNotFound is Absent, errSecInteractionNotAllowed Locked, and anything else, a missing entitlement
// included, Failed; a duplicate add updates; a panic is Failed.
func TestKeychainDarwinStatusMapping(t *testing.T) {
	reads := []struct {
		status int32
		want   sidecar.SidecarKeyStoreStatus
	}{
		{status: errSecSuccess, want: sidecar.SidecarKeyStorePresent},
		{status: errSecItemNotFound, want: sidecar.SidecarKeyStoreAbsent},
		{status: errSecInteractionNotAllowed, want: sidecar.SidecarKeyStoreLocked},
		{status: errSecMissingEntitlement, want: sidecar.SidecarKeyStoreFailed},
		{status: -1, want: sidecar.SidecarKeyStoreFailed},
	}
	for _, c := range reads {
		store := &darwinKeychainStore{calls: &fakeKeychainCalls{copyStatus: c.status, value: []byte("synthetic")}}
		value, status := store.GetSecret("synthetic-item")
		if status != c.want || (status == sidecar.SidecarKeyStorePresent) != (value != nil) {
			t.Errorf("read %d: %d", c.status, status)
		}
	}
	writes := []struct {
		add    int32
		update int32
		want   sidecar.SidecarKeyStoreStatus
	}{
		{add: errSecSuccess, want: sidecar.SidecarKeyStoreOk},
		{add: errSecDuplicateItem, update: errSecSuccess, want: sidecar.SidecarKeyStoreOk},
		{add: errSecDuplicateItem, update: errSecInteractionNotAllowed, want: sidecar.SidecarKeyStoreLocked},
		{add: errSecInteractionNotAllowed, want: sidecar.SidecarKeyStoreLocked},
		{add: errSecMissingEntitlement, want: sidecar.SidecarKeyStoreFailed},
		{add: errSecItemNotFound, want: sidecar.SidecarKeyStoreFailed},
	}
	for _, c := range writes {
		store := &darwinKeychainStore{calls: &fakeKeychainCalls{addStatus: c.add, updateStatus: c.update}}
		if status := store.PutSecret("synthetic-item", []byte("synthetic")); status != c.want {
			t.Errorf("write %d then %d: %d", c.add, c.update, status)
		}
	}
	for status, want := range map[int32]sidecar.SidecarKeyStoreStatus{
		errSecSuccess:               sidecar.SidecarKeyStoreOk,
		errSecItemNotFound:          sidecar.SidecarKeyStoreOk,
		errSecInteractionNotAllowed: sidecar.SidecarKeyStoreLocked,
		-1:                          sidecar.SidecarKeyStoreFailed,
	} {
		store := &darwinKeychainStore{calls: &fakeKeychainCalls{removeStatus: status}}
		if got := store.DeleteSecret("synthetic-item"); got != want {
			t.Errorf("delete %d: %d", status, got)
		}
	}
	panicking := &darwinKeychainStore{calls: &fakeKeychainCalls{panics: true}}
	if _, status := panicking.GetSecret("synthetic-item"); status != sidecar.SidecarKeyStoreFailed {
		t.Errorf("a panicking read: %d", status)
	}
	if status := panicking.PutSecret("synthetic-item", nil); status != sidecar.SidecarKeyStoreFailed {
		t.Errorf("a panicking write: %d", status)
	}
}

// An osKeyStoreFiles a test steers: files in memory, or one error for every call.
type fakeKeyStoreFiles struct {
	files map[string][]byte
	err   error
}

func (self *fakeKeyStoreFiles) read(file string) ([]byte, error) {
	if self.err != nil {
		return nil, self.err
	}
	content, ok := self.files[file]
	if !ok {
		return nil, errOsKeyStoreFileAbsent
	}
	return content, nil
}

func (self *fakeKeyStoreFiles) write(file string, content []byte) error {
	if self.err != nil {
		return self.err
	}
	self.files[file] = content
	return nil
}

func (self *fakeKeyStoreFiles) remove(file string) error {
	if self.err != nil {
		return self.err
	}
	delete(self.files, file)
	return nil
}

// A dpapiCalls that marks what it protects, or fails.
type fakeDpapi struct {
	err error
}

func (self fakeDpapi) protect(plain []byte, entropy []byte) ([]byte, error) {
	if self.err != nil {
		return nil, self.err
	}
	return append(append([]byte("sealed:"), entropy...), plain...), nil
}

func (self fakeDpapi) unprotect(sealed []byte, entropy []byte) ([]byte, error) {
	if self.err != nil {
		return nil, self.err
	}
	prefix := append([]byte("sealed:"), entropy...)
	if len(sealed) < len(prefix) || string(sealed[:len(prefix)]) != string(prefix) {
		return nil, errors.New("not this item's blob")
	}
	return sealed[len(prefix):], nil
}

// Windows: a missing blob is Absent; a file or DPAPI error, or a blob of another item, is Failed, never Absent.
func TestKeychainDpapiStatusMapping(t *testing.T) {
	files := &fakeKeyStoreFiles{files: map[string][]byte{}}
	store := &dpapiStore{calls: fakeDpapi{}, files: files}
	if _, status := store.GetSecret("synthetic-item"); status != sidecar.SidecarKeyStoreAbsent {
		t.Fatalf("before: %d", status)
	}
	if status := store.PutSecret("synthetic-item", []byte("synthetic")); status != sidecar.SidecarKeyStoreOk {
		t.Fatalf("put: %d", status)
	}
	if value, status := store.GetSecret("synthetic-item"); status != sidecar.SidecarKeyStorePresent || string(value) != "synthetic" {
		t.Fatalf("get: %d %q", status, value)
	}
	// another item's blob under this item's file opens to nothing
	files.files[osKeyStoreItemFile("synthetic-item")] = files.files[osKeyStoreItemFile("synthetic-item")][:3]
	if _, status := store.GetSecret("synthetic-item"); status != sidecar.SidecarKeyStoreFailed {
		t.Fatalf("a damaged blob: %d", status)
	}
	failing := &dpapiStore{calls: fakeDpapi{err: errors.New("synthetic")}, files: &fakeKeyStoreFiles{files: map[string][]byte{osKeyStoreItemFile("x"): []byte("sealed:x")}}}
	if _, status := failing.GetSecret("x"); status != sidecar.SidecarKeyStoreFailed {
		t.Fatalf("a failed unprotect: %d", status)
	}
	if status := failing.PutSecret("x", []byte("v")); status != sidecar.SidecarKeyStoreFailed {
		t.Fatalf("a failed protect: %d", status)
	}
	brokenFiles := &dpapiStore{calls: fakeDpapi{}, files: &fakeKeyStoreFiles{err: errors.New("synthetic")}}
	if _, status := brokenFiles.GetSecret("x"); status != sidecar.SidecarKeyStoreFailed {
		t.Fatalf("a failed read: %d", status)
	}
	if status := brokenFiles.DeleteSecret("x"); status != sidecar.SidecarKeyStoreFailed {
		t.Fatalf("a failed delete: %d", status)
	}
}

// A secretServiceCalls answering what a test sets.
type fakeSecretService struct {
	value  []byte
	found  bool
	locked bool
	err    error
}

func (self *fakeSecretService) get(name string) ([]byte, bool, bool, error) {
	return self.value, self.found, self.locked, self.err
}

func (self *fakeSecretService) put(name string, value []byte) (bool, error) {
	return self.locked, self.err
}

func (self *fakeSecretService) remove(name string) (bool, error) {
	return self.locked, self.err
}

// Linux desktop: an error, a missing daemon included, is Failed and a locked collection Locked, whatever else the
// call says; only an unlocked search that finds nothing is Absent.
func TestKeychainSecretServiceStatusMapping(t *testing.T) {
	cases := []struct {
		calls *fakeSecretService
		read  sidecar.SidecarKeyStoreStatus
		write sidecar.SidecarKeyStoreStatus
	}{
		{calls: &fakeSecretService{value: []byte("v"), found: true}, read: sidecar.SidecarKeyStorePresent, write: sidecar.SidecarKeyStoreOk},
		{calls: &fakeSecretService{}, read: sidecar.SidecarKeyStoreAbsent, write: sidecar.SidecarKeyStoreOk},
		{calls: &fakeSecretService{locked: true}, read: sidecar.SidecarKeyStoreLocked, write: sidecar.SidecarKeyStoreLocked},
		{calls: &fakeSecretService{err: errors.New("no secret service")}, read: sidecar.SidecarKeyStoreFailed, write: sidecar.SidecarKeyStoreFailed},
		{calls: &fakeSecretService{found: true, err: errors.New("synthetic")}, read: sidecar.SidecarKeyStoreFailed, write: sidecar.SidecarKeyStoreFailed},
		{calls: &fakeSecretService{locked: true, err: errors.New("synthetic")}, read: sidecar.SidecarKeyStoreFailed, write: sidecar.SidecarKeyStoreFailed},
	}
	for i, c := range cases {
		store := &secretServiceStore{calls: c.calls}
		if _, status := store.GetSecret("synthetic-item"); status != c.read {
			t.Errorf("case %d read: %d, want %d", i, status, c.read)
		}
		if status := store.PutSecret("synthetic-item", []byte("v")); status != c.write {
			t.Errorf("case %d write: %d, want %d", i, status, c.write)
		}
		if status := store.DeleteSecret("synthetic-item"); status != c.write {
			t.Errorf("case %d delete: %d, want %d", i, status, c.write)
		}
	}
}

// Each adapter drives CORE-M1-02's store-state table through a real SidecarInstance, one terminal result an unlock:
// Absent with nothing recorded creates U, Locked creates nothing and reads Locked, Failed creates nothing and reads
// Failed.
func TestKeychainAdaptersDriveTheStoreStates(t *testing.T) {
	type adapter struct {
		name   string
		absent func() sidecar.SidecarKeyStore
		locked func() sidecar.SidecarKeyStore
		failed func() sidecar.SidecarKeyStore
	}
	adapters := []adapter{
		{
			name:   "keychain",
			absent: func() sidecar.SidecarKeyStore { return &darwinKeychainStore{calls: newMemoryKeychainCalls()} },
			locked: func() sidecar.SidecarKeyStore {
				return &darwinKeychainStore{calls: &fakeKeychainCalls{copyStatus: errSecInteractionNotAllowed, addStatus: errSecInteractionNotAllowed}}
			},
			failed: func() sidecar.SidecarKeyStore {
				return &darwinKeychainStore{calls: &fakeKeychainCalls{copyStatus: errSecMissingEntitlement, addStatus: errSecMissingEntitlement}}
			},
		},
		{
			name: "dpapi",
			absent: func() sidecar.SidecarKeyStore {
				return &dpapiStore{calls: fakeDpapi{}, files: &fakeKeyStoreFiles{files: map[string][]byte{}}}
			},
			// DPAPI reports no lock: a failed call is all it can say
			locked: nil,
			failed: func() sidecar.SidecarKeyStore {
				return &dpapiStore{calls: fakeDpapi{}, files: &fakeKeyStoreFiles{err: errors.New("synthetic")}}
			},
		},
		{
			name: "secret_service",
			absent: func() sidecar.SidecarKeyStore {
				return &secretServiceStore{calls: newMemorySecretService()}
			},
			locked: func() sidecar.SidecarKeyStore { return &secretServiceStore{calls: &fakeSecretService{locked: true}} },
			failed: func() sidecar.SidecarKeyStore {
				return &secretServiceStore{calls: &fakeSecretService{err: errors.New("no secret service")}}
			},
		},
		{
			name: "key_file",
			absent: func() sidecar.SidecarKeyStore {
				return &keyFileStore{files: &fakeKeyStoreFiles{files: map[string][]byte{}}}
			},
			locked: nil,
			failed: func() sidecar.SidecarKeyStore {
				return &keyFileStore{files: &fakeKeyStoreFiles{err: errOsKeyStoreLooseMode}}
			},
		},
	}
	unlock := func(store sidecar.SidecarKeyStore) (sidecar.SidecarInstanceState, error, sidecar.SidecarStoreBackend) {
		backend := sidecar.NewSidecarMemoryBackend()
		settings := sidecar.DefaultSidecarSettings()
		settings.Log = sidecar.NewNoopLogger()
		settings.KeychainSettings.AutoLockTimeout = 0
		instance, err := sidecar.NewSidecarInstance(context.Background(), &sidecar.SidecarInstanceArgs{Backend: backend, KeyStore: store, Settings: settings})
		if err != nil {
			t.Fatal(err)
		}
		defer instance.Close()
		err = instance.Unlock(nil)
		state, _ := instance.State()
		return state, err, backend
	}
	for _, adapter := range adapters {
		if state, err, _ := unlock(adapter.absent()); err != nil || state != sidecar.SidecarInstanceOpen {
			t.Errorf("%s absent: %s %v", adapter.name, state, err)
		}
		if adapter.locked != nil {
			state, err, backend := unlock(adapter.locked())
			entries, _ := backend.List("")
			if !errors.Is(err, sidecar.ErrSidecarStoreLocked) || state != sidecar.SidecarInstanceLocked || len(entries) != 0 {
				t.Errorf("%s locked: %s %v, %d files", adapter.name, state, err, len(entries))
			}
		}
		state, err, backend := unlock(adapter.failed())
		entries, _ := backend.List("")
		if !errors.Is(err, sidecar.ErrSidecarStoreFailed) || state != sidecar.SidecarInstanceFailed || len(entries) != 0 {
			t.Errorf("%s failed: %s %v, %d files", adapter.name, state, err, len(entries))
		}
	}
}

// A keychain in memory, answering as Security.framework does.
type memoryKeychainCalls struct {
	items map[string][]byte
}

func newMemoryKeychainCalls() *memoryKeychainCalls {
	return &memoryKeychainCalls{items: map[string][]byte{}}
}

func (self *memoryKeychainCalls) copyData(account string) ([]byte, int32) {
	value, ok := self.items[account]
	if !ok {
		return nil, errSecItemNotFound
	}
	return value, errSecSuccess
}

func (self *memoryKeychainCalls) add(account string, value []byte) int32 {
	if _, ok := self.items[account]; ok {
		return errSecDuplicateItem
	}
	self.items[account] = append([]byte{}, value...)
	return errSecSuccess
}

func (self *memoryKeychainCalls) update(account string, value []byte) int32 {
	if _, ok := self.items[account]; !ok {
		return errSecItemNotFound
	}
	self.items[account] = append([]byte{}, value...)
	return errSecSuccess
}

func (self *memoryKeychainCalls) remove(account string) int32 {
	if _, ok := self.items[account]; !ok {
		return errSecItemNotFound
	}
	delete(self.items, account)
	return errSecSuccess
}

// A Secret Service in memory.
type memorySecretService struct {
	items map[string][]byte
}

func newMemorySecretService() *memorySecretService {
	return &memorySecretService{items: map[string][]byte{}}
}

func (self *memorySecretService) get(name string) ([]byte, bool, bool, error) {
	value, ok := self.items[name]
	return value, ok, false, nil
}

func (self *memorySecretService) put(name string, value []byte) (bool, error) {
	self.items[name] = append([]byte{}, value...)
	return false, nil
}

func (self *memorySecretService) remove(name string) (bool, error) {
	delete(self.items, name)
	return false, nil
}
