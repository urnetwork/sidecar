// `ur keychain rotate`: a new U and a new R_n for every network, every file re-sealed, and nothing
// stranded by a kill at any step (§5.9).
//
//	1. unlock.wrap gains a new U with the old one wrapped under it, in one rename. W goes in under a new
//	   item first. From here the old U is reachable only through the new one.
//	2. Each network: keychain.wrap gains a new root with the old roots wrapped under the new U, in one
//	   rename. Then every file not yet on the new root is re-sealed under it, each by its own rename, and
//	   each file's header says which root it is on, which is how a resumed run knows what is left. Once
//	   none is, keychain.wrap drops the old roots.
//	3. The old W goes from the key store, then unlock.wrap drops the old U.
//
// Each step is a rename from one state that opens every file to another, so a run killed anywhere leaves
// an instance that opens, and RotateKeychain finishes it. Only that stops an old key working: while
// RotationPending answers true, the old keys still open what they opened.
//
// A write can also fail after its rename went through, when the directory's fsync fails, and the
// process goes on. Then the disk is ahead of memory, and the rename may not survive a power cut. So
// memory takes what it resumes from off the disk, never its own idea of what is current; a resumed step
// writes its file again before anything is built on it; and a step that drops a key first checks on the
// disk that nothing still names it, after syncing what might. An unlock or a keychain's open takes its
// keys up from the disk too, from a file such a write, or a process killed before its directory sync,
// may have left: nothing goes under the newest key such a file names until it is written again, unless
// this process wrote it whole (durableWrapPaths).
//
// keychain.wrap's HPKE copy of R_n (keys_recovery_seal.go) is re-sealed with step 2, in the renames that
// add the new root and drop the old ones, to the binding it already names, so the recovery code opens
// what U opens at every point of a rotation. A copy that does not decode stops the rotation before
// anything changes, rather than leave a code opening nothing.

package sidecar

import (
	"bufio"
	"bytes"
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"maps"
	"path"
	"strings"
)

// A stream still reads or writes under an old root. Nothing is lost: RotateKeychain finishes the rotation
// on a later call, and until then the old root stands.
var ErrSidecarRotationBusy = errors.New("a stream holds an old root")

// A step would drop a key the disk still names, which a run that went as it should never leaves. Nothing
// is dropped, and the rotation stays pending.
var errRotateUnfinished = fmt.Errorf("%w: a key to drop is still named on disk", ErrSidecarStoreFailed)

// Whether a rotation was begun and not finished, which RotateKeychain resumes.
func (self *SidecarInstance) RotationPending() (bool, error) {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	if err := self.stateError(); err != nil {
		return false, err
	}
	wrap, err := self.readUnlockWrap()
	if err != nil {
		return false, err
	}
	return wrap != nil && len(wrap.previousKeys) != 0, nil
}

// Rotates U and every R_n, or finishes a rotation a kill or a failed write interrupted. passphrase must
// open the pass wrap where there is one, which is how the new U gets one, and is not read on a resumed
// run, whose new U already has its wraps. A network that fails is left on its old root and the others go
// on, and the first failure is answered once they have: the rotation stays pending and this may be
// called again. Called again after a last write that failed past its rename, this finishes that rotation
// and begins none.
func (self *SidecarInstance) RotateKeychain(ctx context.Context, passphrase []byte) error {
	testHookBarrier("keys.rotate.before", "")
	err := func() error {
		self.operationLock.Lock()
		defer self.operationLock.Unlock()
		return self.rotateWithLock(ctx, passphrase)
	}()
	testHookBarrier("keys.rotate.after", "")
	return err
}

// See RotateKeychain.
func (self *SidecarInstance) rotateWithLock(ctx context.Context, passphrase []byte) error {
	if err := self.stateError(); err != nil {
		return err
	}
	wrap, err := self.readUnlockWrap()
	if err != nil {
		return err
	}
	if wrap == nil {
		return ErrSidecarStoreFailed
	}
	networkIds, err := self.rotatedNetworkIdsWithLock()
	if err != nil {
		return err
	}
	if len(wrap.previousKeys) == 0 && self.holdsOlderUnlockKey(wrap.generation) {
		return self.refinishRotationWithLock(networkIds, wrap)
	}
	if len(wrap.previousKeys) == 0 {
		if err := self.flipUnlockKeyWithLock(wrap, passphrase); err != nil {
			return err
		}
	} else if err := self.resumeUnlockKeyWithLock(wrap); err != nil {
		return err
	}
	var failed error
	for _, networkId := range networkIds {
		if err := self.rotateNetworkWithLock(ctx, networkId); err != nil && failed == nil {
			failed = err
		}
	}
	if failed != nil {
		return failed
	}
	return self.finishRotationWithLock(networkIds)
}

// Every network with a keychain.wrap on disk, recorded or not, since a killed enrollment's still rides
// on U. Refuses before anything changes if one holds a recovery copy that does not decode.
func (self *SidecarInstance) rotatedNetworkIdsWithLock() ([]Id, error) {
	entries, err := self.backend.List(networkTreeName + "/")
	if err != nil {
		return nil, err
	}
	networkIds := []Id{}
	for _, entry := range entries {
		networkId, ok := networkIdOfPath(entry.Name)
		if !ok || !strings.HasSuffix(entry.Name, "/"+keychainWrapName) {
			continue
		}
		// a wrap that does not read fails on its own turn, and holds no other network back
		wrap, err := self.readKeychainWrap(networkId)
		if err == nil && len(wrap.recovery) != 0 {
			if _, err := decodeKeychainRecoveryCopy(wrap.recovery); err != nil {
				return nil, err
			}
		}
		networkIds = append(networkIds, networkId)
	}
	return networkIds, nil
}

// Step 1. The pass is checked before anything changes, and a store that will not take the new W stops
// the rotation here with nothing done. The U moved behind the new one is the one the file names.
func (self *SidecarInstance) flipUnlockKeyWithLock(wrap *unlockWrap, passphrase []byte) error {
	currentKey, err := self.unlockKeyOf(wrap.generation)
	if err != nil {
		return err
	}
	defer clear(currentKey)
	if wrap.pass != nil {
		if err := self.checkPassWithLock(wrap, passphrase, currentKey); err != nil {
			return err
		}
	}

	nextKey := make([]byte, localKeyByteCount)
	if _, err := io.ReadFull(self.random, nextKey); err != nil {
		return storeFault(err)
	}
	testHookSecret("U", nextKey)
	keepKey := false
	defer func() {
		if !keepKey {
			clear(nextKey)
		}
	}()
	next := &unlockWrap{generation: wrap.generation + 1}
	if self.keyStore != nil {
		storeGeneration := uint64(unlockFirstStoreGeneration)
		if wrap.store != nil {
			storeGeneration = wrap.store.generation + 1
		}
		store, storeKey, err := newUnlockStoreWrap(nextKey, next.generation, storeGeneration, self.random)
		if err != nil {
			return storeFault(err)
		}
		defer clear(storeKey)
		next.store = store
		itemName := unlockStoreItemName(self.currentDocument().InstanceId, store.generation)
		switch self.keyStore.PutSecret(itemName, storeKey) {
		case SidecarKeyStoreOk:
		case SidecarKeyStoreLocked:
			return ErrSidecarStoreLocked
		default:
			return ErrSidecarStoreFailed
		}
	}
	if wrap.pass != nil {
		pass, err := newUnlockPassWrap(nextKey, next.generation, passphrase, self.settings, self.random)
		if err != nil {
			return err
		}
		next.pass = pass
	}
	if next.store == nil && next.pass == nil {
		return ErrSidecarStoreFailed
	}

	chainKey, err := deriveLocalKey(nextKey, unlockPreviousClass)
	if err != nil {
		return storeFault(err)
	}
	defer clear(chainKey)
	testHookSecret("K_unlock_previous", chainKey)
	wrapped, err := sealWrappedKey(chainKey, currentKey, unlockPreviousAdditionalData(next.generation, wrap.generation), self.random)
	if err != nil {
		return storeFault(err)
	}
	next.previousKeys = []unlockPreviousKey{{generation: wrap.generation, wrapped: *wrapped}}

	// the new U stays in memory whatever the write answers, since one that fails after its rename
	// leaves the file naming a U only this process knows, which a resumed run takes up. It is current
	// only once the write is durable. One kept from an earlier try at this generation never reached a
	// file that stands, or the file would be past it
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		clear(self.generationUnlockKeys[next.generation])
		self.generationUnlockKeys[next.generation] = nextKey
	}()
	keepKey = true
	if err := self.writeWrapWithLock(unlockWrapPath, next.encode()); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.unlockGeneration = next.generation
	return nil
}

// Step 1 found done: unlock.wrap names the new U already. This process may not have taken it as current,
// when the write failed after its rename, so it does now. First the file is written again: a rename
// whose directory sync failed may not survive a power cut, and nothing may go under the new U until the
// file is sure to name it.
func (self *SidecarInstance) resumeUnlockKeyWithLock(wrap *unlockWrap) error {
	unlockKey, err := self.unlockKeyOf(wrap.generation)
	if err != nil {
		return err
	}
	clear(unlockKey)
	if err := self.writeWrapWithLock(unlockWrapPath, wrap.encode()); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.unlockGeneration = wrap.generation
	return nil
}

// Step 2 for one network. A lost one only has its roots moved under the current U, and a failed one keeps
// the rotation pending.
func (self *SidecarInstance) rotateNetworkWithLock(ctx context.Context, networkId Id) error {
	opened, err := self.keychainWithLock(networkId)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil
	}
	if errors.Is(err, ErrSidecarKeystoreLost) {
		return self.rewrapLostNetworkWithLock(networkId)
	}
	if err != nil {
		return err
	}
	wrap, err := self.readKeychainWrap(networkId)
	if err != nil {
		return err
	}
	if err := self.addRootWithLock(opened, wrap); err != nil {
		return err
	}
	for {
		staleCommitCount := opened.staleCommitCount.Load()
		if err := opened.resealFiles(ctx); err != nil {
			return err
		}
		dropped, err := self.dropOldRootsWithLock(opened, staleCommitCount)
		if err != nil {
			return err
		}
		if dropped {
			return nil
		}
	}
}

// A network whose keychain.ur is lost keeps its keychain.wrap, and that wrap's roots move under the
// current U, its files staying where they are: it stays a loss the person can confirm, or CORE-M2-05's
// code may open, and not a wrap naming a U that step 3 drops. Written on every run, so a write that
// failed after its rename is made durable before step 3.
func (self *SidecarInstance) rewrapLostNetworkWithLock(networkId Id) error {
	wrap, err := self.readKeychainWrap(networkId)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil
	}
	if err != nil {
		return err
	}
	unlockKey, unlockGeneration, err := self.durableUnlockKeyWithLock()
	if err != nil {
		return err
	}
	defer clear(unlockKey)
	roots, err := self.openRoots(wrap)
	if err != nil {
		return err
	}
	defer func() {
		for _, root := range roots {
			clear(root)
		}
	}()
	next := &keychainWrap{networkId: wrap.networkId, recovery: wrap.recovery}
	for i := range wrap.roots {
		generation := wrap.roots[i].generation
		rewrapped, err := wrapKeychainRoot(wrap.networkId, generation, roots[generation], unlockGeneration, unlockKey, self.random)
		if err != nil {
			return storeFault(err)
		}
		next.roots = append(next.roots, *rewrapped)
	}
	return self.writeWrapWithLock(keychainWrapPath(networkId), next.encode())
}

// keychain.wrap gains a new root unless it has one under the current U, which a resumed run finds. The
// roots already there move under the current U too, so the old one can go at the end.
func (self *SidecarInstance) addRootWithLock(opened *keychain, wrap *keychainWrap) error {
	unlockKey, unlockGeneration, err := self.durableUnlockKeyWithLock()
	if err != nil {
		return err
	}
	defer clear(unlockKey)
	if wrap.roots[0].unlockGeneration == unlockGeneration {
		return self.resumeRootWithLock(opened, wrap)
	}
	roots, err := self.openRoots(wrap)
	if err != nil {
		return err
	}
	defer func() {
		for _, root := range roots {
			clear(root)
		}
	}()

	root := make([]byte, localKeyByteCount)
	if _, err := io.ReadFull(self.random, root); err != nil {
		return storeFault(err)
	}
	testHookSecret("R_n", root)
	generation := wrap.roots[0].generation + 1
	next := &keychainWrap{networkId: wrap.networkId, recovery: wrap.recovery}
	wrapped, err := wrapKeychainRoot(wrap.networkId, generation, root, unlockGeneration, unlockKey, self.random)
	if err != nil {
		clear(root)
		return storeFault(err)
	}
	next.roots = append(next.roots, *wrapped)
	for i := range wrap.roots {
		older := wrap.roots[i].generation
		rewrapped, err := wrapKeychainRoot(wrap.networkId, older, roots[older], unlockGeneration, unlockKey, self.random)
		if err != nil {
			clear(root)
			return storeFault(err)
		}
		next.roots = append(next.roots, *rewrapped)
	}
	// the recovery copy takes the new root in the same rename
	sealedRoots := maps.Clone(roots)
	sealedRoots[generation] = root
	if err := resealKeychainRecoveryCopy(next, sealedRoots); err != nil {
		clear(root)
		return err
	}
	if err := self.writeWrapWithLock(keychainWrapPath(wrap.networkId), next.encode()); err != nil {
		clear(root)
		return err
	}
	opened.stateLock.Lock()
	defer opened.stateLock.Unlock()
	if opened.closed {
		clear(root)
		return ErrSidecarStoreLocked
	}
	opened.generationRoots[generation] = root
	opened.currentGeneration = generation
	return nil
}

// The new root found in keychain.wrap already. This keychain may not hold it, when the write failed
// after its rename, so it takes every root the file holds and makes the newest current. First the file
// is written again: every file is about to be re-sealed under that root, and a rename whose directory
// sync failed may not survive a power cut.
func (self *SidecarInstance) resumeRootWithLock(opened *keychain, wrap *keychainWrap) error {
	roots, err := self.openRoots(wrap)
	if err != nil {
		return err
	}
	if err := self.writeWrapWithLock(keychainWrapPath(wrap.networkId), wrap.encode()); err != nil {
		for _, root := range roots {
			clear(root)
		}
		return err
	}
	return opened.adoptRoots(roots, wrap.roots[0].generation)
}

// Re-seals every file not on the current root, until a pass finds none. Each file is its own rename, so
// a kill costs only the file in hand.
func (self *keychain) resealFiles(ctx context.Context) error {
	directory := networkDirectoryPath(self.networkId) + "/"
	for {
		entries, err := self.instance.backend.List(directory)
		if err != nil {
			return err
		}
		resealedCount := 0
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			path := strings.TrimPrefix(entry.Name, directory)
			if path == keychainWrapName {
				continue
			}
			resealed, err := self.resealFile(path)
			if err != nil {
				return err
			}
			if resealed {
				resealedCount += 1
			}
		}
		if resealedCount == 0 {
			return nil
		}
	}
}

// Moves one file to the current root, streaming, so a large file needs no copy in memory. Reports
// whether it had to. A writer that swapped this file while it was being copied wins: the copy is
// dropped, and the next pass looks again.
func (self *keychain) resealFile(path string) (bool, error) {
	self.instance.touch()
	backendPath := networkFilePath(self.networkId, path)
	in, err := self.instance.backend.Open(backendPath)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer in.Close()
	buffered := bufio.NewReader(in)
	prefix, _ := buffered.Peek(len(storeLogMagic))
	if isStoreLog(prefix) {
		// an append-only log, which moves record by record (state_log.go)
		return self.resealLog(path)
	}
	if isSpoolPlainFile(prefix) {
		// the spool's locked segments and epoch keys, which no root seals (record_spool_locked.go)
		return false, nil
	}
	header, err := readSealHeader(buffered)
	if err != nil {
		return false, err
	}
	generation, err := self.holdGeneration(0)
	if err != nil {
		return false, err
	}
	defer self.releaseGeneration(generation)
	if header.generation == generation {
		return false, nil
	}

	writer, err := self.newSealedWriter(header.class, path, generation)
	if err != nil {
		return false, err
	}
	defer writer.file.Discard()
	reader := newSealReader(buffered, header, path, func() (cipher.AEAD, error) {
		return self.classAead(header.class, header.generation)
	})
	if _, err := io.Copy(writer.seal, reader); err != nil {
		writer.seal.abandon()
		return false, err
	}
	if err := writer.seal.finish(); err != nil {
		return false, err
	}

	replaced, err := func() (bool, error) {
		self.commitLock.Lock()
		defer self.commitLock.Unlock()
		currentIn, err := self.instance.backend.Open(backendPath)
		if errors.Is(err, ErrSidecarStoreAbsent) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		defer currentIn.Close()
		current, err := readSealHeader(currentIn)
		if err != nil {
			return false, err
		}
		if !bytes.Equal(current.encode(), header.encode()) {
			return false, nil
		}
		if err := writer.file.Sync(); err != nil {
			return false, err
		}
		if err := writer.file.Rename(backendPath); err != nil {
			return false, err
		}
		return true, nil
	}()
	if err != nil || !replaced {
		return true, err
	}
	return true, self.instance.backend.SyncDirectory(backendPath)
}

// Ends step 2: keychain.wrap goes down to the current root, unless a stream still holds an old one or a
// file reached an old root since the pass began, in which case another pass runs. Reports whether the
// old roots are gone.
func (self *SidecarInstance) dropOldRootsWithLock(opened *keychain, staleCommitCount int64) (bool, error) {
	wrap, err := self.readKeychainWrap(opened.networkId)
	if err != nil {
		return false, err
	}
	if len(wrap.roots) == 1 {
		return true, nil
	}
	opened.commitLock.Lock()
	defer opened.commitLock.Unlock()
	if opened.staleCommitCount.Load() != staleCommitCount {
		return false, nil
	}
	var currentGeneration uint64
	holdsOldRoot := func() bool {
		opened.stateLock.Lock()
		defer opened.stateLock.Unlock()
		currentGeneration = opened.currentGeneration
		for generation := range opened.generationStreams {
			if generation != opened.currentGeneration {
				return true
			}
		}
		return false
	}
	if holdsOldRoot() {
		return false, ErrSidecarRotationBusy
	}
	// the root kept must be the one every file was just re-sealed to
	if wrap.roots[0].generation != currentGeneration {
		return false, errRotateUnfinished
	}
	if err := self.syncNetworkDirectories(opened.networkId); err != nil {
		return false, err
	}
	next := *wrap
	next.roots = wrap.roots[:1]
	if len(next.recovery) != 0 {
		// the recovery copy drops the old roots in the same rename
		currentRoot := func() []byte {
			opened.stateLock.Lock()
			defer opened.stateLock.Unlock()
			return bytes.Clone(opened.generationRoots[currentGeneration])
		}()
		err := resealKeychainRecoveryCopy(&next, map[uint64][]byte{currentGeneration: currentRoot})
		clear(currentRoot)
		if err != nil {
			return false, err
		}
	}
	if err := self.writeWrapWithLock(keychainWrapPath(wrap.networkId), next.encode()); err != nil {
		return false, err
	}
	opened.stateLock.Lock()
	defer opened.stateLock.Unlock()
	if opened.closed {
		return true, nil
	}
	for generation, root := range opened.generationRoots {
		if generation != opened.currentGeneration {
			clear(root)
			delete(opened.generationRoots, generation)
		}
	}
	for classKey, key := range opened.classKeys {
		if classKey.generation != opened.currentGeneration {
			clear(key)
			delete(opened.classKeys, classKey)
		}
	}
	return true, nil
}

// Makes durable every rename and remove in the network's directories, which a re-seal whose directory
// sync failed left to chance: once the old roots go, a file a power cut put back on one would be gone.
func (self *SidecarInstance) syncNetworkDirectories(networkId Id) error {
	entries, err := self.backend.List(networkDirectoryPath(networkId) + "/")
	if err != nil {
		return err
	}
	syncedDirectories := map[string]bool{}
	for _, entry := range entries {
		directory := path.Dir(entry.Name)
		if syncedDirectories[directory] {
			continue
		}
		if err := self.backend.SyncDirectory(entry.Name); err != nil {
			return err
		}
		syncedDirectories[directory] = true
	}
	return nil
}

// Step 3. Any network that reads as failed has already stopped this, and nothing older goes until the
// disk shows nothing names it. The old W goes first: the old U stays reachable through the new one until
// the last write, so nothing depends on it.
func (self *SidecarInstance) finishRotationWithLock(networkIds []Id) error {
	wrap, err := self.readUnlockWrap()
	if err != nil {
		return err
	}
	if wrap == nil {
		return ErrSidecarStoreFailed
	}
	if len(wrap.previousKeys) == 0 {
		return nil
	}
	if err := self.requireOnlyUnlockGenerationWithLock(networkIds, wrap.generation); err != nil {
		return err
	}
	if self.keyStore != nil && wrap.store != nil && unlockFirstStoreGeneration < wrap.store.generation {
		itemName := unlockStoreItemName(self.currentDocument().InstanceId, wrap.store.generation-1)
		switch self.keyStore.DeleteSecret(itemName) {
		case SidecarKeyStoreOk:
		case SidecarKeyStoreLocked:
			return ErrSidecarStoreLocked
		default:
			return fmt.Errorf("%w: the old store item stands", ErrSidecarStoreFailed)
		}
	}
	next := *wrap
	next.previousKeys = nil
	if err := self.writeWrapWithLock(unlockWrapPath, next.encode()); err != nil {
		return err
	}
	self.dropOlderUnlockKeys(wrap.generation)
	return nil
}

// Step 3 found done, by this process, with its write failing after the rename: unlock.wrap names no
// older U, and memory still holds one. The rotation is over and none begins, since another would leave a
// new W behind if the power went before its file did. The file is written again, so the rename is
// durable before memory lets the older U go.
func (self *SidecarInstance) refinishRotationWithLock(networkIds []Id, wrap *unlockWrap) error {
	if err := self.requireOnlyUnlockGenerationWithLock(networkIds, wrap.generation); err != nil {
		return err
	}
	if err := self.writeWrapWithLock(unlockWrapPath, wrap.encode()); err != nil {
		return err
	}
	self.dropOlderUnlockKeys(wrap.generation)
	return nil
}

// Whether memory holds U of generation, current, and an older one beside it, which only a step 3 whose
// write failed after its rename leaves when unlock.wrap lists none.
func (self *SidecarInstance) holdsOlderUnlockKey(generation uint64) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, ok := self.generationUnlockKeys[generation]; !ok || self.unlockGeneration != generation {
		return false
	}
	for older := range self.generationUnlockKeys {
		if older < generation {
			return true
		}
	}
	return false
}

// Refuses unless U of generation is current and every keychain.wrap of networkIds names it alone, so
// an older U can go with nothing on disk still under it.
func (self *SidecarInstance) requireOnlyUnlockGenerationWithLock(networkIds []Id, generation uint64) error {
	if self.currentUnlockGeneration() != generation {
		return errRotateUnfinished
	}
	for _, networkId := range networkIds {
		wrap, err := self.readKeychainWrap(networkId)
		if errors.Is(err, ErrSidecarStoreAbsent) {
			continue
		}
		if err != nil {
			return err
		}
		for _, root := range wrap.roots {
			if root.unlockGeneration != generation {
				return errRotateUnfinished
			}
		}
	}
	return nil
}

// Zeroes and forgets every U but that of generation.
func (self *SidecarInstance) dropOlderUnlockKeys(generation uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for other, unlockKey := range self.generationUnlockKeys {
		if other != generation {
			clear(unlockKey)
			delete(self.generationUnlockKeys, other)
		}
	}
}
