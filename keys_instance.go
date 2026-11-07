// SidecarInstance: one instance's <state>, its sidecar.json and unlock.wrap, U in memory, and auto-lock
// (§5.9). It is shared by every Sidecar of the instance, so one Argon2id run opens every network, and it
// holds each network's keychain. A process has one per instance: §5.8's flock on <state>/lock keeps a
// second daemon out, and nothing here takes that lock.
//
// operationLock orders what changes the wraps: Unlock, Lock, a pass change, a rotation and a network's
// first keychain. It is held across a backend's and a key store's calls, which is why it is not
// stateLock. Order: operationLock, then a keychain's locks, then stateLock.

package sidecar

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// The key store's item, unlock.wrap, or a network's keychain.wrap is lost with an identity recorded
	// (D-CORE-15). The pass, or that network's recovery code, may still open it. Otherwise this is
	// Unenrolled(keystore_lost), and nothing is created until the person confirms a new device.
	ErrSidecarKeystoreLost = errors.New("keystore lost")
	// A pass that opens nothing. The pass approves nothing: it only opens U (§5.9).
	ErrSidecarPassRefused = errors.New("pass refused")
	// Past §5.4's attempts in its interval, whether or not this pass was right.
	ErrSidecarPassLimited = errors.New("too many pass attempts")
)

// A confirmation of a new device with no loss to confirm, which changes nothing: only a loss may go
// past D-CORE-15's table, never a lock or a fault.
var errNothingLost = errors.New("nothing is lost")

// What SidecarInstance.State reads, which a Sidecar turns into its own state: Open is what lets one
// leave Locked, and Lost is Unenrolled(keystore_lost).
type SidecarInstanceState string

const (
	// U is not in memory: the store has not unlocked, or the pass has not been given.
	SidecarInstanceLocked SidecarInstanceState = "locked"
	// A fault or a value failing decoding or AEAD. As Locked, and it alarms (§5.9).
	SidecarInstanceFailed SidecarInstanceState = "failed"
	// §5.9's Absent with an identity recorded. Unlock with the pass may still open it.
	SidecarInstanceLost SidecarInstanceState = "lost"
	// U is in memory, and each network's keychain opens on demand.
	SidecarInstanceOpen SidecarInstanceState = "open"
)

// What a host opens an instance with.
type SidecarInstanceArgs struct {
	// Where <state> lives: NewSidecarOsBackend, a page Worker's IndexedDB, or
	// NewSidecarMemoryBackend for an ephemeral sidecar.
	Backend SidecarStoreBackend
	// The store holding W. Nil: pass only.
	KeyStore SidecarKeyStore
	// This machine's id, which sidecar.json keeps only as a hash salted by the instance id. Empty on
	// a host with none, where restored or copied state cannot be told.
	MachineId []byte
	// Read for its KeychainSettings, its service urls and its Log.
	Settings *SidecarSettings
}

// One instance's state. Safe for concurrent use.
type SidecarInstance struct {
	ctx       context.Context
	cancel    context.CancelFunc
	backend   SidecarStoreBackend
	keyStore  SidecarKeyStore
	machineId []byte
	urls      sidecarStateUrls
	settings  *SidecarKeychainSettings
	log       Logger
	// seams, so a test runs on its own clock and bytes
	now    func() time.Time
	after  func(timeout time.Duration) <-chan time.Time
	random io.Reader

	state *MonitorValue[SidecarInstanceState]

	operationLock sync.Mutex

	lastUseMillis atomic.Int64
	holdCount     atomic.Int64

	stateLock sync.Mutex
	// Nil once sidecar.json fails to decode, which holds this instance at Failed.
	document *sidecarStateDocument
	// U by generation. Holds more than one only during a rotation.
	unlockKeys       map[uint64][]byte
	unlockGeneration uint64
	keychains        map[Id]*keychain
	// sidecar.json's hash is another machine's, or another instance's, and nothing has accepted it
	restored bool
}

// Reads sidecar.json and sweeps a kill's temp files. An instance that cannot read its state comes back
// Failed rather than as an error, so a host can say so, and nothing reads it as a first run. Runs until
// ctx ends or Close.
func NewSidecarInstance(ctx context.Context, args *SidecarInstanceArgs) (*SidecarInstance, error) {
	return newSidecarInstance(ctx, args, time.Now, time.After, rand.Reader)
}

// NewSidecarInstance with its seams.
func newSidecarInstance(ctx context.Context, args *SidecarInstanceArgs, now func() time.Time,
	after func(timeout time.Duration) <-chan time.Time, random io.Reader) (*SidecarInstance, error) {
	if args == nil || args.Backend == nil || args.Settings == nil || args.Settings.KeychainSettings == nil {
		return nil, fmt.Errorf("%w: an instance needs a backend and keychain settings", errInvalidSettings)
	}
	err := checkSettingsNumbers("KeychainSettings", reflect.ValueOf(args.Settings.KeychainSettings), false)
	if err != nil {
		return nil, err
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &SidecarInstance{
		ctx:       cancelCtx,
		cancel:    cancel,
		backend:   args.Backend,
		keyStore:  args.KeyStore,
		machineId: args.MachineId,
		urls:      stateUrlsFromSettings(args.Settings),
		settings:  args.Settings.KeychainSettings,
		log:       loggerOrDefault(args.Settings.Log),
		now:       now,
		after:     after,
		random:    random,
		state:     NewMonitorValue(SidecarInstanceLocked),
		keychains: map[Id]*keychain{},
	}
	self.touch()
	if err := self.loadDocument(); err != nil {
		self.state.Set(SidecarInstanceFailed)
	}
	if err := self.backend.RemoveTemp(); err != nil {
		self.log.Warningf("[keys]a killed write's temp files were not removed")
	}
	if 0 < self.settings.AutoLockTimeout {
		go self.run()
	}
	return self, nil
}

// Reads sidecar.json, or starts a document that reaches the disk with U, so a first run in front of a
// locked store writes nothing.
func (self *SidecarInstance) loadDocument() error {
	encoded, err := readBackendFile(self.backend, stateJsonPath, stateJsonMaxByteCount)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		instanceId := NewId()
		self.setDocument(&sidecarStateDocument{
			Version:       stateJsonVersion,
			InstanceId:    instanceId,
			MachineIdHash: stateMachineIdHash(instanceId, self.machineId),
			Urls:          self.urls,
			Networks:      []SidecarNetworkRecord{},
		})
		return nil
	}
	if err != nil {
		return err
	}
	document, err := decodeStateDocument(encoded)
	if err != nil {
		return err
	}
	machineIdHash := stateMachineIdHash(document.InstanceId, self.machineId)
	self.setDocument(document)
	if document.MachineIdHash != "" && machineIdHash != "" && document.MachineIdHash != machineIdHash {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.restored = true
	}
	return nil
}

// What sidecar.json holds now. Read it, never change it: editDocumentWithLock does that.
func (self *SidecarInstance) currentDocument() *sidecarStateDocument {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.document
}

// Replaces the document in memory.
func (self *SidecarInstance) setDocument(document *sidecarStateDocument) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.document = document
}

// Applies edit to a copy of the document and writes it. Memory takes the copy only once it is durable.
func (self *SidecarInstance) editDocumentWithLock(edit func(document *sidecarStateDocument) error) error {
	document := self.currentDocument()
	if document == nil {
		return ErrSidecarStoreFailed
	}
	next := document.clone()
	if err := edit(next); err != nil {
		return err
	}
	encoded, err := next.encode()
	if err != nil {
		return storeFault(err)
	}
	if err := writeBackendFile(self.backend, stateJsonPath, encoded); err != nil {
		return err
	}
	self.setDocument(next)
	return nil
}

// What the instance reads as now, and the channel that closes on its next change.
func (self *SidecarInstance) State() (SidecarInstanceState, chan struct{}) {
	return self.state.Get()
}

// Whether sidecar.json's machine-id hash is not this machine's: restored or copied state (§5.9). This
// instance's keys open as ever, and an identity here may not act until `--replace` has revoked the old
// client and called AcceptRestored, since two copies of one sidecar must not both run.
func (self *SidecarInstance) Restored() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.restored
}

// Takes this machine as the instance's own, after `--replace`.
func (self *SidecarInstance) AcceptRestored() error {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	err := self.editDocumentWithLock(func(document *sidecarStateDocument) error {
		document.MachineIdHash = stateMachineIdHash(document.InstanceId, self.machineId)
		return nil
	})
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.restored = false
	return nil
}

// The networks enrolled here.
func (self *SidecarInstance) Networks() []SidecarNetworkRecord {
	document := self.currentDocument()
	if document == nil {
		return nil
	}
	return slices.Clone(document.Networks)
}

// Records a network, the last step of an enrollment (CORE-M1-09). From here a lost key for this network
// is a loss and not a first run. Every id must be set.
func (self *SidecarInstance) RecordNetwork(record SidecarNetworkRecord) error {
	if record.NetworkId == (Id{}) || record.ClientId == (Id{}) || record.SidecarId == (Id{}) ||
		record.ConnectInstanceId == (Id{}) {
		return ErrSidecarStoreName
	}
	testHookBarrier("keys.record_network.before", record.NetworkId.String())
	err := func() error {
		self.operationLock.Lock()
		defer self.operationLock.Unlock()
		return self.editDocumentWithLock(func(document *sidecarStateDocument) error {
			document.Urls = self.urls
			document.Networks = slices.DeleteFunc(document.Networks, func(other SidecarNetworkRecord) bool {
				return other.NetworkId == record.NetworkId
			})
			document.Networks = append(document.Networks, record)
			return nil
		})
	}()
	testHookBarrier("keys.record_network.after", record.NetworkId.String())
	return err
}

// The store a host's Store() answers for a Sidecar of networkId, or, with nil, for one not yet enrolled,
// whose files wait for a network. Its file calls refuse until Directory names a class.
func (self *SidecarInstance) Store(networkId *Id) SidecarStore {
	store := &sealedStore{instance: self}
	if networkId != nil {
		id := *networkId
		store.networkId = &id
	}
	return store
}

// The instance behind a host's Store(), and the network it was given. NewSidecar reads this to find
// what it shares with the instance's other Sidecars. False means the store is no instance's, which a
// Sidecar refuses, since it could not open a keychain through it.
func sidecarInstanceOfStore(store SidecarStore) (*SidecarInstance, *Id, bool) {
	sealed, ok := store.(*sealedStore)
	if !ok {
		return nil, nil, false
	}
	return sealed.instance, sealed.networkId, true
}

// Why nothing can be opened, or nil while open.
func (self *SidecarInstance) stateError() error {
	switch self.state.Value() {
	case SidecarInstanceOpen:
		return nil
	case SidecarInstanceFailed:
		return ErrSidecarStoreFailed
	case SidecarInstanceLost:
		return ErrSidecarKeystoreLost
	}
	return ErrSidecarStoreLocked
}

// This network's open keychain, opening it if it has to.
func (self *SidecarInstance) keychainFor(networkId Id) (*keychain, error) {
	var opened *keychain
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		opened = self.keychains[networkId]
	}()
	if opened != nil {
		return opened, nil
	}
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	return self.keychainWithLock(networkId)
}

// §5.9's table for a network: a lost keychain.wrap is the same loss for n, one that does not decode or
// open is Failed, and neither creates anything. ErrSidecarStoreAbsent means nothing is here and nothing
// is recorded, so an enrollment may create R_n.
func (self *SidecarInstance) keychainWithLock(networkId Id) (*keychain, error) {
	if err := self.stateError(); err != nil {
		return nil, err
	}
	var opened *keychain
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		opened = self.keychains[networkId]
	}()
	if opened != nil {
		return opened, nil
	}
	recorded := self.currentDocument().recordsNetwork(networkId)
	wrap, err := self.readKeychainWrap(networkId)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		if recorded {
			return nil, ErrSidecarKeystoreLost
		}
		return nil, ErrSidecarStoreAbsent
	}
	if err != nil {
		return nil, err
	}
	roots, err := self.openRoots(wrap)
	if err != nil {
		return nil, err
	}
	opened = newKeychain(self, networkId, roots, wrap.roots[0].generation)
	if err := opened.loadRecords(); err != nil {
		if !errors.Is(err, ErrSidecarStoreAbsent) {
			opened.close()
			return nil, err
		}
		if recorded {
			opened.close()
			return nil, ErrSidecarKeystoreLost
		}
	}
	self.cacheKeychain(opened)
	return opened, nil
}

// Reads a network's keychain.wrap, which must name that network.
func (self *SidecarInstance) readKeychainWrap(networkId Id) (*keychainWrap, error) {
	encoded, err := readBackendFile(self.backend, keychainWrapPath(networkId), keychainWrapMaxByteCount)
	if err != nil {
		return nil, err
	}
	wrap, err := decodeKeychainWrap(encoded)
	if err != nil {
		return nil, err
	}
	if wrap.networkId != networkId {
		return nil, errKeychainWrapFormat
	}
	return wrap, nil
}

// Every root in wrap, each under the U it names.
func (self *SidecarInstance) openRoots(wrap *keychainWrap) (map[uint64][]byte, error) {
	roots := map[uint64][]byte{}
	for i := range wrap.roots {
		root := &wrap.roots[i]
		// a copy, since a lock may zero the original. A file naming a U this instance never had is
		// damaged, which is a failure and not a lock
		unlockKey, err := func() ([]byte, error) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.unlockKeys == nil {
				return nil, ErrSidecarStoreLocked
			}
			unlockKey, ok := self.unlockKeys[root.unlockGeneration]
			if !ok {
				return nil, ErrSidecarStoreFailed
			}
			return slices.Clone(unlockKey), nil
		}()
		if err != nil {
			for _, opened := range roots {
				clear(opened)
			}
			return nil, err
		}
		opened, err := root.open(wrap.networkId, unlockKey)
		clear(unlockKey)
		if err != nil {
			for _, other := range roots {
				clear(other)
			}
			return nil, err
		}
		roots[root.generation] = opened
	}
	return roots, nil
}

// Keeps an opened keychain, unless a lock got here first, which closes it.
func (self *SidecarInstance) cacheKeychain(opened *keychain) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.keychains[opened.networkId] = opened
}

// Network n's keychain at its first enrollment (§5.9): R_n is created only here, and only when nothing
// is recorded for n. An existing wrap is an earlier enrollment that was killed before it recorded the
// network, so its root stands. Failed and lost create nothing.
func (self *SidecarInstance) createKeychain(networkId Id) (*keychain, error) {
	testHookBarrier("keys.create_keychain.before", networkId.String())
	var opened *keychain
	err := func() error {
		self.operationLock.Lock()
		defer self.operationLock.Unlock()
		var err error
		opened, err = self.keychainWithLock(networkId)
		if errors.Is(err, ErrSidecarStoreAbsent) {
			opened, err = self.createKeychainWithLock(networkId)
		}
		return err
	}()
	testHookBarrier("keys.create_keychain.after", networkId.String())
	return opened, err
}

// A new R_n, wrapped under the current U.
func (self *SidecarInstance) createKeychainWithLock(networkId Id) (*keychain, error) {
	unlockKey, err := self.currentUnlockKey()
	if err != nil {
		return nil, err
	}
	defer clear(unlockKey)
	root := make([]byte, localKeyByteCount)
	if _, err := io.ReadFull(self.random, root); err != nil {
		return nil, storeFault(err)
	}
	testHookSecret("R_n", root)
	self.stateLock.Lock()
	unlockGeneration := self.unlockGeneration
	self.stateLock.Unlock()
	wrapped, err := wrapKeychainRoot(networkId, 1, root, unlockGeneration, unlockKey, self.random)
	if err != nil {
		clear(root)
		return nil, storeFault(err)
	}
	wrap := &keychainWrap{networkId: networkId, roots: []keychainRoot{*wrapped}}
	if err := writeBackendFile(self.backend, keychainWrapPath(networkId), wrap.encode()); err != nil {
		clear(root)
		return nil, err
	}
	opened := newKeychain(self, networkId, map[uint64][]byte{1: root}, 1)
	self.cacheKeychain(opened)
	return opened, nil
}

// The person confirmed re-enrollment as a new device after a loss of U (D-CORE-15). Only Lost allows
// this: a Locked or Failed store deletes nothing. Everything under the lost U goes, and so does the
// old instance id, so no item of the old key store can be read as this one's. Identity is recorded until
// the last step, so a kill here is still a loss, and the person confirms again.
func (self *SidecarInstance) ConfirmNewDevice() error {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	if self.state.Value() != SidecarInstanceLost {
		return errNothingLost
	}
	if err := self.removeTreeWithLock(networkTreeName + "/"); err != nil {
		return err
	}
	if err := self.backend.Remove(unlockWrapPath); err != nil {
		return err
	}
	if err := self.backend.SyncDirectory(unlockWrapPath); err != nil {
		return err
	}
	instanceId := NewId()
	err := self.editDocumentWithLock(func(document *sidecarStateDocument) error {
		document.InstanceId = instanceId
		document.MachineIdHash = stateMachineIdHash(instanceId, self.machineId)
		document.Networks = []SidecarNetworkRecord{}
		document.PassAttemptMillis = nil
		return nil
	})
	if err != nil {
		return err
	}
	self.state.Set(SidecarInstanceLocked)
	return nil
}

// The person confirmed a lost network's re-enrollment as a new device, with the instance open
// (D-CORE-15). Only a network reading as lost allows this, and its next enrollment is a first one.
func (self *SidecarInstance) ConfirmNewNetworkDevice(networkId Id) error {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	_, err := self.keychainWithLock(networkId)
	if !errors.Is(err, ErrSidecarKeystoreLost) {
		return errNothingLost
	}
	if err := self.removeTreeWithLock(networkDirectoryPath(networkId) + "/"); err != nil {
		return err
	}
	return self.editDocumentWithLock(func(document *sidecarStateDocument) error {
		document.Networks = slices.DeleteFunc(document.Networks, func(record SidecarNetworkRecord) bool {
			return record.NetworkId == networkId
		})
		return nil
	})
}

// Removes every file under prefix.
func (self *SidecarInstance) removeTreeWithLock(prefix string) error {
	entries, err := self.backend.List(prefix)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := self.backend.Remove(entry.Name); err != nil {
			return err
		}
		if err := self.backend.SyncDirectory(entry.Name); err != nil {
			return err
		}
	}
	return nil
}

// Marks a use of the keychain, which is what holds off auto-lock. Costs an atomic store.
func (self *SidecarInstance) touch() {
	self.lastUseMillis.Store(self.now().UnixMilli())
}

// Keeps auto-lock off until the answer is called: for work that must keep serving with no keychain call
// to show for it. What counts as busy is core-types-auto-lock.md's to settle. Until then nothing but a
// keychain call or a hold counts.
func (self *SidecarInstance) Hold() func() {
	self.holdCount.Add(1)
	var once sync.Once
	return func() {
		once.Do(func() {
			self.touch()
			self.holdCount.Add(-1)
		})
	}
}

// Drops U and every R_n from memory. The next use answers ErrSidecarStoreLocked until Unlock.
func (self *SidecarInstance) Lock() {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	self.lockWithLock()
}

// See Lock.
func (self *SidecarInstance) lockWithLock() {
	var keychains []*keychain
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, unlockKey := range self.unlockKeys {
			clear(unlockKey)
		}
		self.unlockKeys = nil
		self.unlockGeneration = 0
		for _, opened := range self.keychains {
			keychains = append(keychains, opened)
		}
		self.keychains = map[Id]*keychain{}
	}()
	for _, opened := range keychains {
		opened.close()
	}
	if self.state.Value() == SidecarInstanceOpen {
		self.state.Set(SidecarInstanceLocked)
	}
}

// Ends auto-lock and locks. Safe to call again.
func (self *SidecarInstance) Close() {
	self.cancel()
	self.Lock()
}

// How long until an open keychain has been idle for AutoLockTimeout. A hold counts as use, for a full
// timeout, which also keeps the loop from spinning while one stands.
func (self *SidecarInstance) idleRemaining() time.Duration {
	if 0 < self.holdCount.Load() {
		return self.settings.AutoLockTimeout
	}
	idle := time.Duration(self.now().UnixMilli()-self.lastUseMillis.Load()) * time.Millisecond
	return max(self.settings.AutoLockTimeout-idle, 0)
}

// Auto-lock: waits out the idle time while the instance is open, and sleeps on its state otherwise. Each
// wake either locks, which ends the timer, or finds use, which sets a later one, so this never spins.
func (self *SidecarInstance) run() {
	lockIfIdle := func() {
		self.operationLock.Lock()
		defer self.operationLock.Unlock()
		if self.state.Value() == SidecarInstanceOpen && self.idleRemaining() == 0 {
			if self.log.V(1).Enabled() {
				self.log.Infof("[keys]auto-lock after %v idle", self.settings.AutoLockTimeout)
			}
			self.lockWithLock()
		}
	}
	for {
		state, changed := self.state.Get()
		var expired <-chan time.Time
		if state == SidecarInstanceOpen {
			expired = self.after(self.idleRemaining())
		}
		select {
		case <-self.ctx.Done():
			return
		case <-changed:
		case <-expired:
			lockIfIdle()
		}
	}
}

// A network's id from a path in its directory, or false for any other path.
func networkIdOfPath(path string) (Id, bool) {
	rest, ok := strings.CutPrefix(path, networkTreeName+"/")
	if !ok {
		return Id{}, false
	}
	idStr, _, ok := strings.Cut(rest, "/")
	if !ok {
		return Id{}, false
	}
	networkId, err := ParseId(idStr)
	if err != nil {
		return Id{}, false
	}
	return networkId, true
}
