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
// CORE-M2-05's HPKE copy of R_n must be re-sealed with step 2, which it does not exist to do yet, so a
// network holding one refuses to rotate rather than leave its recovery code opening nothing.

package sidecar

import (
	"bytes"
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"strings"
)

// A stream still reads or writes under an old root. Nothing is lost: RotateKeychain finishes the rotation
// on a later call, and until then the old root stands.
var ErrSidecarRotationBusy = errors.New("a stream holds an old root")

var errRotateRecovery = errors.New("a network's recovery copy cannot be re-sealed yet")

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

// Rotates U and every R_n, or finishes a rotation a kill interrupted. passphrase must open the pass wrap
// where there is one, which is how the new U gets one, and is not read on a resumed run, whose new U
// already has its wraps. A network that fails is left on its old root and the others go on, and the
// first failure is answered once they have: the rotation stays pending and this may be called again.
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
	if len(wrap.previousKeys) == 0 {
		if err := self.flipUnlockKeyWithLock(wrap, passphrase); err != nil {
			return err
		}
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
	return self.finishRotationWithLock()
}

// Every network with a keychain.wrap on disk, recorded or not, since a killed enrollment's still rides
// on U. Refuses before anything changes if one holds a recovery copy.
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
			return nil, errRotateRecovery
		}
		networkIds = append(networkIds, networkId)
	}
	return networkIds, nil
}

// Step 1. The pass is checked before anything changes, and a store that will not take the new W stops
// the rotation here with nothing done.
func (self *SidecarInstance) flipUnlockKeyWithLock(wrap *unlockWrap, passphrase []byte) error {
	currentKey, err := self.currentUnlockKey()
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

	if err := writeBackendFile(self.backend, unlockWrapPath, next.encode()); err != nil {
		return err
	}
	keepKey = true
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.generationUnlockKeys[next.generation] = nextKey
	self.unlockGeneration = next.generation
	return nil
}

// Step 2 for one network. A network with no usable keychain is left: a lost one holds nothing a key
// could open, and a failed one keeps the rotation pending.
func (self *SidecarInstance) rotateNetworkWithLock(ctx context.Context, networkId Id) error {
	opened, err := self.keychainWithLock(networkId)
	if errors.Is(err, ErrSidecarKeystoreLost) || errors.Is(err, ErrSidecarStoreAbsent) {
		return nil
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

// keychain.wrap gains a new root unless it has one under the current U, which a resumed run finds. The
// roots already there move under the current U too, so the old one can go at the end.
func (self *SidecarInstance) addRootWithLock(opened *keychain, wrap *keychainWrap) error {
	unlockKey, err := self.currentUnlockKey()
	if err != nil {
		return err
	}
	defer clear(unlockKey)
	var unlockGeneration uint64
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		unlockGeneration = self.unlockGeneration
	}()
	if wrap.roots[0].unlockGeneration == unlockGeneration {
		return nil
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
	next := &keychainWrap{networkId: wrap.networkId}
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
	if err := writeBackendFile(self.backend, keychainWrapPath(wrap.networkId), next.encode()); err != nil {
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
	header, err := readSealHeader(in)
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
	reader := newSealReader(in, header, path, func() (cipher.AEAD, error) {
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
	holdsOldRoot := func() bool {
		opened.stateLock.Lock()
		defer opened.stateLock.Unlock()
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
	next := *wrap
	next.roots = wrap.roots[:1]
	if err := writeBackendFile(self.backend, keychainWrapPath(wrap.networkId), next.encode()); err != nil {
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

// Step 3. Any network that reads as failed has already stopped this. The old W goes first: the old U
// stays reachable through the new one until the last write, so nothing depends on it.
func (self *SidecarInstance) finishRotationWithLock() error {
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
	if err := writeBackendFile(self.backend, unlockWrapPath, next.encode()); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for generation, unlockKey := range self.generationUnlockKeys {
		if generation != self.unlockGeneration {
			clear(unlockKey)
			delete(self.generationUnlockKeys, generation)
		}
	}
	return nil
}
