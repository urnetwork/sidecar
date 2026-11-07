// U and unlock.wrap (§5.9). U is the instance's 32-byte unlock key, which opens every R_n of the
// instance, so one Argon2id run opens every network (owner decision 23). It never touches a disk
// unwrapped.
//
//	magic "URUW" | version 1 | generation, uint64 | wraps, uint8: 1 store, 2 pass |
//	[store wrap: store generation, uint64 | nonce, 24 B | wrapped key, 48 B] |
//	[pass wrap: memory in KiB, uint32 | iterations, uint32 | threads, uint8 | salt, 16 B |
//	            nonce, 24 B | wrapped key, 48 B] |
//	previous count, uint8 | previous ...
//	previous: generation, uint64 | nonce, 24 B | wrapped key, 48 B
//
// Integers are big endian. The store wrap is under a random key W that the SidecarKeyStore keeps, which
// makes "wrapped by the OS keystore" one file with the pass wrap beside it, so a change to U is a
// single rename, and a value that fails AEAD is the Failed that D-CORE-15 needs it to be. Each new W
// goes under a new item, named by the store generation, and is in the key store before the file names
// it, so the file and the store never disagree. The pass wrap is under Argon2id of the pass, its
// parameters and salt in the file and in the additional data, so opening reads its own parameters and a
// change to them only fails. previous is a rotation in flight: older U, wrapped under this one, until
// every keychain.wrap has moved off them.
//
// D-CORE-15's table is exact, and unlockWithLock is it, row for row: only Absent with no sidecar_id
// recorded creates U, Locked and Failed create, overwrite and delete nothing, and a value failing
// decoding or AEAD is Failed. A kill in any step below leaves a file that opens.

package sidecar

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// The format's values. A pass wrap's cost is read before its AEAD can refuse it, since Argon2id makes the
// key the AEAD needs, so the bounds are all that holds a damaged file's ask: 256 MiB and 16 passes, 4x
// §5.9's desktop memory and about 5x its passes, which is seconds on a desktop. A phone or a page Worker
// has less than that, and the ceiling of those hosts is not set here. A setting past the bounds is
// refused at the wrap, not at the open.
const (
	unlockWrapMagic          = "URUW"
	unlockWrapVersion        = 1
	unlockWrapHasStore       = 1
	unlockWrapHasPass        = 2
	unlockWrapMaxPrevious    = 8
	unlockWrapMaxByteCount   = 4 * 1024
	passSaltByteCount        = 16
	passMaxMemoryKibiCount   = 256 * 1024
	passMaxIterationCount    = 16
	wrappedKeyNonceByteCount = chacha20poly1305.NonceSizeX
	wrappedKeyByteCount      = localKeyByteCount + chacha20poly1305.Overhead
)

// The domains of the wraps U sits under.
const (
	unlockStoreClass = "unlock-store"
	unlockPassClass  = "unlock-pass"
)

// Where a key store keeps W, by the instance id and the store generation, so a new W never lands on the
// one in use, and a state directory wiped by hand leaves no item to be mistaken for this one.
const unlockStoreItemPrefix = "urnetwork-sidecar-v1/unlock/"

// The store generation of the first W, and the item a store is read at before any wrap names one.
const unlockFirstStoreGeneration = 1

var errUnlockWrapFormat = fmt.Errorf("%w: unlock.wrap does not decode", ErrSidecarStoreFailed)

// Failing AEAD says a value is bad, and nothing about why.
var errWrappedKeyOpen = fmt.Errorf("%w: a wrapped key failed", ErrSidecarStoreFailed)

// Reads a wrap file, each take checking what is left, so a decoder over any bytes ends and allocates
// nothing it was not given. The first short take sets failed, and every later one answers zero.
type wrapCursor struct {
	remaining []byte
	failed    bool
}

// The next byteCount bytes, or nil once they run out.
func (self *wrapCursor) take(byteCount int) []byte {
	if self.failed || len(self.remaining) < byteCount {
		self.failed = true
		return nil
	}
	taken := self.remaining[:byteCount]
	self.remaining = self.remaining[byteCount:]
	return taken
}

// The next byte.
func (self *wrapCursor) takeUint8() uint8 {
	taken := self.take(1)
	if taken == nil {
		return 0
	}
	return taken[0]
}

// The next big-endian uint16.
func (self *wrapCursor) takeUint16() uint16 {
	taken := self.take(2)
	if taken == nil {
		return 0
	}
	return binary.BigEndian.Uint16(taken)
}

// The next big-endian uint32.
func (self *wrapCursor) takeUint32() uint32 {
	taken := self.take(4)
	if taken == nil {
		return 0
	}
	return binary.BigEndian.Uint32(taken)
}

// The next big-endian uint64.
func (self *wrapCursor) takeUint64() uint64 {
	taken := self.take(8)
	if taken == nil {
		return 0
	}
	return binary.BigEndian.Uint64(taken)
}

// Whether every take fit and nothing is left over.
func (self *wrapCursor) finished() bool {
	return !self.failed && len(self.remaining) == 0
}

// One 32-byte key sealed under another by XChaCha20-Poly1305.
type wrappedKey struct {
	nonce  [wrappedKeyNonceByteCount]byte
	sealed [wrappedKeyByteCount]byte
}

// key sealed under wrapKey, with a nonce from random.
func sealWrappedKey(wrapKey []byte, key []byte, additionalData []byte, random io.Reader) (*wrappedKey, error) {
	aead, err := chacha20poly1305.NewX(wrapKey)
	if err != nil {
		return nil, err
	}
	wrapped := &wrappedKey{}
	if _, err := io.ReadFull(random, wrapped.nonce[:]); err != nil {
		return nil, err
	}
	aead.Seal(wrapped.sealed[:0], wrapped.nonce[:], key, additionalData)
	return wrapped, nil
}

// The key inside, or errWrappedKeyOpen.
func (self *wrappedKey) open(wrapKey []byte, additionalData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(wrapKey)
	if err != nil {
		return nil, errWrappedKeyOpen
	}
	key, err := aead.Open(nil, self.nonce[:], self.sealed[:], additionalData)
	if err != nil {
		return nil, errWrappedKeyOpen
	}
	return key, nil
}

// Appends the nonce and sealed key.
func (self *wrappedKey) append(encoded []byte) []byte {
	encoded = append(encoded, self.nonce[:]...)
	return append(encoded, self.sealed[:]...)
}

// Reads what append wrote.
func (self *wrappedKey) read(cursor *wrapCursor) {
	copy(self.nonce[:], cursor.take(len(self.nonce)))
	copy(self.sealed[:], cursor.take(len(self.sealed)))
}

// U under W.
type unlockStoreWrap struct {
	// Names the key store item holding W.
	generation uint64
	wrapped    wrappedKey
}

// U under the pass.
type unlockPassWrap struct {
	memoryKibiCount uint32
	iterationCount  uint32
	threadCount     uint8
	salt            [passSaltByteCount]byte
	wrapped         wrappedKey
}

// An older U during a rotation, wrapped under the current one.
type unlockPreviousKey struct {
	generation uint64
	wrapped    wrappedKey
}

// unlock.wrap's content. Holds at least one of store and pass, or nothing could open it.
type unlockWrap struct {
	generation uint64
	store      *unlockStoreWrap
	pass       *unlockPassWrap
	// newest first
	previousKeys []unlockPreviousKey
}

// The file's bytes.
func (self *unlockWrap) encode() []byte {
	encoded := make([]byte, 0, unlockWrapMaxByteCount)
	encoded = append(encoded, unlockWrapMagic...)
	encoded = append(encoded, unlockWrapVersion)
	encoded = binary.BigEndian.AppendUint64(encoded, self.generation)
	wraps := byte(0)
	if self.store != nil {
		wraps |= unlockWrapHasStore
	}
	if self.pass != nil {
		wraps |= unlockWrapHasPass
	}
	encoded = append(encoded, wraps)
	if self.store != nil {
		encoded = binary.BigEndian.AppendUint64(encoded, self.store.generation)
		encoded = self.store.wrapped.append(encoded)
	}
	if self.pass != nil {
		encoded = binary.BigEndian.AppendUint32(encoded, self.pass.memoryKibiCount)
		encoded = binary.BigEndian.AppendUint32(encoded, self.pass.iterationCount)
		encoded = append(encoded, self.pass.threadCount)
		encoded = append(encoded, self.pass.salt[:]...)
		encoded = self.pass.wrapped.append(encoded)
	}
	encoded = append(encoded, byte(len(self.previousKeys)))
	for i := range self.previousKeys {
		encoded = binary.BigEndian.AppendUint64(encoded, self.previousKeys[i].generation)
		encoded = self.previousKeys[i].wrapped.append(encoded)
	}
	return encoded
}

// A whole unlock.wrap, or ErrSidecarStoreFailed. Total, bounded by its input, and its error never
// repeats it. A cost past the bounds is refused here, before Argon2id could be asked for it.
func decodeUnlockWrap(encoded []byte) (*unlockWrap, error) {
	cursor := &wrapCursor{remaining: encoded}
	if string(cursor.take(len(unlockWrapMagic))) != unlockWrapMagic ||
		cursor.takeUint8() != unlockWrapVersion {
		return nil, errUnlockWrapFormat
	}
	wrap := &unlockWrap{generation: cursor.takeUint64()}
	wraps := cursor.takeUint8()
	if cursor.failed || wrap.generation == 0 || wraps == 0 || wraps&^(unlockWrapHasStore|unlockWrapHasPass) != 0 {
		return nil, errUnlockWrapFormat
	}
	if wraps&unlockWrapHasStore != 0 {
		wrap.store = &unlockStoreWrap{generation: cursor.takeUint64()}
		wrap.store.wrapped.read(cursor)
		if cursor.failed || wrap.store.generation == 0 {
			return nil, errUnlockWrapFormat
		}
	}
	if wraps&unlockWrapHasPass != 0 {
		pass := &unlockPassWrap{
			memoryKibiCount: cursor.takeUint32(),
			iterationCount:  cursor.takeUint32(),
			threadCount:     cursor.takeUint8(),
		}
		copy(pass.salt[:], cursor.take(len(pass.salt)))
		pass.wrapped.read(cursor)
		if cursor.failed || !pass.costFits() {
			return nil, errUnlockWrapFormat
		}
		wrap.pass = pass
	}
	previousCount := int(cursor.takeUint8())
	if unlockWrapMaxPrevious < previousCount {
		return nil, errUnlockWrapFormat
	}
	for i := 0; i < previousCount; i += 1 {
		previous := unlockPreviousKey{generation: cursor.takeUint64()}
		previous.wrapped.read(cursor)
		newerGeneration := wrap.generation
		if i != 0 {
			newerGeneration = wrap.previousKeys[i-1].generation
		}
		if cursor.failed || previous.generation == 0 || newerGeneration <= previous.generation {
			return nil, errUnlockWrapFormat
		}
		wrap.previousKeys = append(wrap.previousKeys, previous)
	}
	if !cursor.finished() {
		return nil, errUnlockWrapFormat
	}
	return wrap, nil
}

// Whether Argon2id may run at this cost.
func (self *unlockPassWrap) costFits() bool {
	return self.threadCount != 0 && self.iterationCount != 0 && self.memoryKibiCount != 0 &&
		self.iterationCount <= passMaxIterationCount && self.memoryKibiCount <= passMaxMemoryKibiCount
}

// The additional data of the store wrap of U's generation.
func (self *unlockStoreWrap) additionalData(generation uint64) []byte {
	additionalData := make([]byte, 0, len(localKeyInfoPrefix)+len(unlockStoreClass)+8+8)
	additionalData = append(additionalData, localKeyInfoPrefix...)
	additionalData = append(additionalData, unlockStoreClass...)
	additionalData = binary.BigEndian.AppendUint64(additionalData, generation)
	return binary.BigEndian.AppendUint64(additionalData, self.generation)
}

// A store wrap of unlockKey under a new W, which it answers for the caller to keep. The hook sees W as
// soon as it exists.
func newUnlockStoreWrap(unlockKey []byte, generation uint64, storeGeneration uint64,
	random io.Reader) (*unlockStoreWrap, []byte, error) {
	storeKey := make([]byte, localKeyByteCount)
	if _, err := io.ReadFull(random, storeKey); err != nil {
		return nil, nil, err
	}
	testHookSecret("W", storeKey)
	store := &unlockStoreWrap{generation: storeGeneration}
	wrapped, err := sealWrappedKey(storeKey, unlockKey, store.additionalData(generation), random)
	if err != nil {
		clear(storeKey)
		return nil, nil, err
	}
	store.wrapped = *wrapped
	return store, storeKey, nil
}

// The additional data of the pass wrap, which is why changing its cost in the file only fails.
func (self *unlockPassWrap) additionalData(generation uint64) []byte {
	additionalData := make([]byte, 0, len(localKeyInfoPrefix)+len(unlockPassClass)+8+4+4+1+passSaltByteCount)
	additionalData = append(additionalData, localKeyInfoPrefix...)
	additionalData = append(additionalData, unlockPassClass...)
	additionalData = binary.BigEndian.AppendUint64(additionalData, generation)
	additionalData = binary.BigEndian.AppendUint32(additionalData, self.memoryKibiCount)
	additionalData = binary.BigEndian.AppendUint32(additionalData, self.iterationCount)
	additionalData = append(additionalData, self.threadCount)
	return append(additionalData, self.salt[:]...)
}

// The additional data of an older U's wrap.
func unlockPreviousAdditionalData(generation uint64, previousGeneration uint64) []byte {
	additionalData := make([]byte, 0, len(localKeyInfoPrefix)+len(unlockPreviousClass)+8+8)
	additionalData = append(additionalData, localKeyInfoPrefix...)
	additionalData = append(additionalData, unlockPreviousClass...)
	additionalData = binary.BigEndian.AppendUint64(additionalData, generation)
	return binary.BigEndian.AppendUint64(additionalData, previousGeneration)
}

// The key the pass makes at this wrap's cost. The hook sees it before any use.
func (self *unlockPassWrap) passKey(passphrase []byte) []byte {
	key := argon2.IDKey(passphrase, self.salt[:], self.iterationCount, self.memoryKibiCount, self.threadCount, localKeyByteCount)
	testHookSecret("K_pass", key)
	return key
}

// U opened by the pass, or errWrappedKeyOpen for any other pass.
func (self *unlockPassWrap) open(passphrase []byte, generation uint64) ([]byte, error) {
	key := self.passKey(passphrase)
	defer clear(key)
	unlockKey, err := self.wrapped.open(key, self.additionalData(generation))
	if err != nil {
		return nil, err
	}
	testHookSecret("U", unlockKey)
	return unlockKey, nil
}

// A pass wrap of unlockKey at settings' cost, with a fresh salt.
func newUnlockPassWrap(unlockKey []byte, generation uint64, passphrase []byte, settings *SidecarKeychainSettings,
	random io.Reader) (*unlockPassWrap, error) {
	kibiCount := settings.PassMemoryByteCount / 1024
	if kibiCount <= 0 || passMaxMemoryKibiCount < kibiCount ||
		settings.PassIterationCount <= 0 || passMaxIterationCount < settings.PassIterationCount ||
		settings.PassThreadCount <= 0 || 255 < settings.PassThreadCount {
		return nil, fmt.Errorf("%w: the pass's cost is out of range", errInvalidSettings)
	}
	pass := &unlockPassWrap{
		memoryKibiCount: uint32(kibiCount),
		iterationCount:  uint32(settings.PassIterationCount),
		threadCount:     uint8(settings.PassThreadCount),
	}
	if _, err := io.ReadFull(random, pass.salt[:]); err != nil {
		return nil, err
	}
	key := pass.passKey(passphrase)
	defer clear(key)
	wrapped, err := sealWrappedKey(key, unlockKey, pass.additionalData(generation), random)
	if err != nil {
		return nil, err
	}
	pass.wrapped = *wrapped
	return pass, nil
}

// The key store item holding W of a store generation.
func unlockStoreItemName(instanceId Id, storeGeneration uint64) string {
	return fmt.Sprintf("%s%s/%d", unlockStoreItemPrefix, instanceId, storeGeneration)
}

// Reads unlock.wrap. nil with no error means it is not there.
func (self *SidecarInstance) readUnlockWrap() (*unlockWrap, error) {
	encoded, err := readBackendFile(self.backend, unlockWrapPath, unlockWrapMaxByteCount)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeUnlockWrap(encoded)
}

// Whether §5.9's table should read this instance as holding an identity. sidecar.json says so outright,
// and a keychain.wrap on disk says so too: sidecar.json is written last, and a fault that took it must
// not make a loss look like a first run, since the next step there is a new U.
func (self *SidecarInstance) identityRecordedWithLock() (bool, error) {
	if len(self.currentDocument().NetworkRecords) != 0 {
		return true, nil
	}
	entries, err := self.backend.List(networkTreeName + "/")
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(entries, func(entry SidecarStoreEntry) bool {
		return strings.HasSuffix(entry.Name, "/"+keychainWrapName)
	}), nil
}

// Opens U, by the key store's wrap with no pass and by the pass with one, as §5.9's table says. An
// instance already open stays open, whatever the pass. Answers ErrSidecarStoreLocked while the store is
// locked or a pass is needed, ErrSidecarStoreFailed on a fault, ErrSidecarKeystoreLost on a loss,
// ErrSidecarPassRefused and ErrSidecarPassLimited.
func (self *SidecarInstance) Unlock(passphrase []byte) error {
	testHookBarrier("keys.unlock.before", "")
	err := func() error {
		self.operationLock.Lock()
		defer self.operationLock.Unlock()
		if self.state.Value() == SidecarInstanceOpen {
			return nil
		}
		return self.unlockWithLock(passphrase)
	}()
	testHookBarrier("keys.unlock.after", "")
	return err
}

// D-CORE-15's table. Anything that reaches Failed or Locked here has changed nothing on any medium.
func (self *SidecarInstance) unlockWithLock(passphrase []byte) error {
	if self.currentDocument() == nil {
		return self.settle(SidecarInstanceFailed, ErrSidecarStoreFailed)
	}
	wrap, err := self.readUnlockWrap()
	if err != nil {
		return self.settle(SidecarInstanceFailed, err)
	}
	if 0 < len(passphrase) && wrap != nil && wrap.pass != nil {
		return self.unlockByPassWithLock(wrap, passphrase)
	}

	if self.keyStore == nil && wrap != nil && wrap.pass != nil {
		// pass only, and no pass came, since the pass's path above takes any that does
		return self.settle(SidecarInstanceLocked, ErrSidecarStoreLocked)
	}
	storeGeneration := uint64(unlockFirstStoreGeneration)
	if wrap != nil && wrap.store != nil {
		storeGeneration = wrap.store.generation
	}
	var value []byte
	status := SidecarKeyStoreAbsent
	if self.keyStore != nil {
		value, status = self.keyStore.GetSecret(unlockStoreItemName(self.currentDocument().InstanceId, storeGeneration))
		defer clear(value)
	}
	switch status {
	case SidecarKeyStorePresent:
		if wrap == nil {
			// W with nothing it wraps: U went with unlock.wrap
			return self.settle(SidecarInstanceLost, ErrSidecarKeystoreLost)
		}
		if wrap.store == nil {
			// this file holds U under the pass alone, so only the pass opens it
			return self.settle(SidecarInstanceLocked, ErrSidecarStoreLocked)
		}
		testHookSecret("W", value)
		unlockKey, err := wrap.store.wrapped.open(value, wrap.store.additionalData(wrap.generation))
		if err != nil {
			return self.settle(SidecarInstanceFailed, err)
		}
		testHookSecret("U", unlockKey)
		return self.openWithLock(wrap, unlockKey)
	case SidecarKeyStoreAbsent:
		recorded, err := self.identityRecordedWithLock()
		if err != nil {
			return self.settle(SidecarInstanceFailed, err)
		}
		if recorded {
			return self.settle(SidecarInstanceLost, ErrSidecarKeystoreLost)
		}
		if self.keyStore == nil && len(passphrase) == 0 {
			// pass only, and nothing to make U with yet
			return self.settle(SidecarInstanceLocked, ErrSidecarStoreLocked)
		}
		return self.createUnlockKeyWithLock(passphrase)
	case SidecarKeyStoreLocked:
		return self.settle(SidecarInstanceLocked, ErrSidecarStoreLocked)
	}
	// Failed, or a status no read may answer, which is read the same way
	return self.settle(SidecarInstanceFailed, ErrSidecarStoreFailed)
}

// Records the state an attempt ended in, and answers err.
func (self *SidecarInstance) settle(state SidecarInstanceState, err error) error {
	self.state.Set(state)
	return err
}

// U by the pass. An attempt is counted on disk before Argon2id runs, so a kill cannot buy a free guess.
// On the way out, a key store that lost W gets a new one, or this device would ask for the pass at
// every start from here on.
func (self *SidecarInstance) unlockByPassWithLock(wrap *unlockWrap, passphrase []byte) error {
	if err := self.countPassAttemptWithLock(); err != nil {
		return err
	}
	unlockKey, err := wrap.pass.open(passphrase, wrap.generation)
	if err != nil {
		return ErrSidecarPassRefused
	}
	if err := self.clearPassAttemptsWithLock(); err != nil {
		clear(unlockKey)
		return err
	}
	if err := self.openWithLock(wrap, unlockKey); err != nil {
		return err
	}
	self.restoreStoreWrapWithLock(wrap)
	return nil
}

// Refuses a pass past §5.4's limit, or counts this one, durably. Only a wrong pass stays counted, since
// the caller clears them on a right one. An attempt the clock has stepped back behind is held to now,
// which frees none of them early, and keeps a clock set wrong for a day from refusing the pass for that
// day: it is written back even when this refuses, or the next refusal would start over.
func (self *SidecarInstance) countPassAttemptWithLock() error {
	now := self.now().UnixMilli()
	window := self.settings.PassAttemptInterval.Milliseconds()
	recorded := self.currentDocument().PassAttemptMillis
	attempts := slices.DeleteFunc(slices.Clone(recorded), func(attemptMillis int64) bool {
		return attemptMillis+window <= now
	})
	for i := range attempts {
		attempts[i] = min(attempts[i], now)
	}
	limited := self.settings.PassAttemptCount <= len(attempts)
	if limited && slices.Equal(attempts, recorded) {
		return ErrSidecarPassLimited
	}
	if !limited {
		attempts = append(attempts, now)
	}
	err := self.editDocumentWithLock(func(document *sidecarStateDocument) error {
		document.PassAttemptMillis = attempts
		return nil
	})
	if err != nil {
		return err
	}
	if limited {
		return ErrSidecarPassLimited
	}
	return nil
}

// Clears the attempts once a pass opened U.
func (self *SidecarInstance) clearPassAttemptsWithLock() error {
	return self.editDocumentWithLock(func(document *sidecarStateDocument) error {
		document.PassAttemptMillis = nil
		return nil
	})
}

// Puts a store wrap back after the pass opened U with the key store's item gone, or this device would
// ask for the pass at every start from here on. This is U, wrapped anew, so it creates no identity. Only
// Absent does this: a store that is locked or failing is left alone. W goes in under a new item before
// the file names it, so a kill leaves the old wrap standing. The pass having opened U, this cannot fail
// the unlock.
func (self *SidecarInstance) restoreStoreWrapWithLock(wrap *unlockWrap) {
	if self.keyStore == nil {
		return
	}
	storeGeneration := uint64(unlockFirstStoreGeneration)
	if wrap.store != nil {
		storeGeneration = wrap.store.generation
	}
	value, status := self.keyStore.GetSecret(unlockStoreItemName(self.currentDocument().InstanceId, storeGeneration))
	clear(value)
	if status != SidecarKeyStoreAbsent {
		return
	}
	err := func() error {
		unlockKey, err := self.currentUnlockKey()
		if err != nil {
			return err
		}
		defer clear(unlockKey)
		next := *wrap
		store, storeKey, err := newUnlockStoreWrap(unlockKey, wrap.generation, storeGeneration+1, self.random)
		if err != nil {
			return err
		}
		defer clear(storeKey)
		next.store = store
		itemName := unlockStoreItemName(self.currentDocument().InstanceId, store.generation)
		if status := self.keyStore.PutSecret(itemName, storeKey); status != SidecarKeyStoreOk {
			return ErrSidecarStoreFailed
		}
		return writeBackendFile(self.backend, unlockWrapPath, next.encode())
	}()
	if err != nil {
		self.log.Warningf("[keys]the key store's wrap was not restored")
	}
}

// §5.9's first run: U, and W if a key store holds one, then sidecar.json so W's name stands, then
// unlock.wrap, and W last, since a kill here leaves a store that reads Absent with nothing recorded, and
// this simply runs again.
func (self *SidecarInstance) createUnlockKeyWithLock(passphrase []byte) error {
	unlockKey := make([]byte, localKeyByteCount)
	if _, err := io.ReadFull(self.random, unlockKey); err != nil {
		return self.settle(SidecarInstanceFailed, storeFault(err))
	}
	testHookSecret("U", unlockKey)
	keepKey := false
	defer func() {
		if !keepKey {
			clear(unlockKey)
		}
	}()
	wrap := &unlockWrap{generation: 1}
	var storeKey []byte
	if self.keyStore != nil {
		store, newStoreKey, err := newUnlockStoreWrap(unlockKey, wrap.generation, unlockFirstStoreGeneration, self.random)
		if err != nil {
			return self.settle(SidecarInstanceFailed, storeFault(err))
		}
		storeKey = newStoreKey
		defer clear(storeKey)
		wrap.store = store
	}
	if 0 < len(passphrase) {
		pass, err := newUnlockPassWrap(unlockKey, wrap.generation, passphrase, self.settings, self.random)
		if err != nil {
			return self.settle(SidecarInstanceFailed, err)
		}
		wrap.pass = pass
	}
	if err := self.editDocumentWithLock(func(document *sidecarStateDocument) error { return nil }); err != nil {
		return self.settle(SidecarInstanceFailed, err)
	}
	if err := writeBackendFile(self.backend, unlockWrapPath, wrap.encode()); err != nil {
		return self.settle(SidecarInstanceFailed, err)
	}
	if self.keyStore != nil {
		itemName := unlockStoreItemName(self.currentDocument().InstanceId, wrap.store.generation)
		switch self.keyStore.PutSecret(itemName, storeKey) {
		case SidecarKeyStoreOk:
		case SidecarKeyStoreLocked:
			return self.settle(SidecarInstanceLocked, ErrSidecarStoreLocked)
		default:
			return self.settle(SidecarInstanceFailed, ErrSidecarStoreFailed)
		}
	}
	keepKey = true
	return self.openWithLock(wrap, unlockKey)
}

// Moves to Open on unlockKey, which this takes, opening any older U a rotation left behind it.
func (self *SidecarInstance) openWithLock(wrap *unlockWrap, unlockKey []byte) error {
	generationUnlockKeys := map[uint64][]byte{wrap.generation: unlockKey}
	if len(wrap.previousKeys) != 0 {
		chainKey, err := deriveLocalKey(unlockKey, unlockPreviousClass)
		if err != nil {
			clear(unlockKey)
			return self.settle(SidecarInstanceFailed, storeFault(err))
		}
		defer clear(chainKey)
		testHookSecret("K_unlock_previous", chainKey)
		for i := range wrap.previousKeys {
			previous := &wrap.previousKeys[i]
			previousKey, err := previous.wrapped.open(chainKey, unlockPreviousAdditionalData(wrap.generation, previous.generation))
			if err != nil {
				for _, key := range generationUnlockKeys {
					clear(key)
				}
				return self.settle(SidecarInstanceFailed, err)
			}
			testHookSecret("U", previousKey)
			generationUnlockKeys[previous.generation] = previousKey
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.generationUnlockKeys = generationUnlockKeys
		self.unlockGeneration = wrap.generation
	}()
	self.touch()
	self.state.Set(SidecarInstanceOpen)
	return nil
}

// A copy of the current U, or ErrSidecarStoreLocked.
func (self *SidecarInstance) currentUnlockKey() ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	unlockKey, ok := self.generationUnlockKeys[self.unlockGeneration]
	if !ok {
		return nil, ErrSidecarStoreLocked
	}
	return bytes.Clone(unlockKey), nil
}

// §5.9's pass change, which rewraps U and nothing else. oldPassphrase must open the pass wrap, and may be
// empty only where there is none, which sets a first pass on a keychain the key store opened. An empty
// newPassphrase drops the pass wrap, but never the last wrap of U.
func (self *SidecarInstance) ChangePass(oldPassphrase []byte, newPassphrase []byte) error {
	testHookBarrier("keys.change_pass.before", "")
	err := func() error {
		self.operationLock.Lock()
		defer self.operationLock.Unlock()
		return self.changePassWithLock(oldPassphrase, newPassphrase)
	}()
	testHookBarrier("keys.change_pass.after", "")
	return err
}

// See ChangePass.
func (self *SidecarInstance) changePassWithLock(oldPassphrase []byte, newPassphrase []byte) error {
	unlockKey, err := self.currentUnlockKey()
	if err != nil {
		return err
	}
	defer clear(unlockKey)
	wrap, err := self.readUnlockWrap()
	if err != nil {
		return err
	}
	if wrap == nil {
		return ErrSidecarStoreFailed
	}
	if wrap.pass != nil {
		if err := self.checkPassWithLock(wrap, oldPassphrase, unlockKey); err != nil {
			return err
		}
	} else if 0 < len(oldPassphrase) {
		return ErrSidecarPassRefused
	}
	next := *wrap
	next.pass = nil
	if 0 < len(newPassphrase) {
		pass, err := newUnlockPassWrap(unlockKey, wrap.generation, newPassphrase, self.settings, self.random)
		if err != nil {
			return err
		}
		next.pass = pass
	} else if next.store == nil {
		return ErrSidecarPassRefused
	}
	return writeBackendFile(self.backend, unlockWrapPath, next.encode())
}

// Holds passphrase to the pass wrap, under §5.4's limit, for a caller that already has U and only needs
// to know the person does too.
func (self *SidecarInstance) checkPassWithLock(wrap *unlockWrap, passphrase []byte, unlockKey []byte) error {
	if err := self.countPassAttemptWithLock(); err != nil {
		return err
	}
	opened, err := wrap.pass.open(passphrase, wrap.generation)
	if err != nil {
		return ErrSidecarPassRefused
	}
	defer clear(opened)
	if subtle.ConstantTimeCompare(opened, unlockKey) != 1 {
		return ErrSidecarPassRefused
	}
	return self.clearPassAttemptsWithLock()
}
