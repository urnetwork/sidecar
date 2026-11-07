// `ur keychain rotate`, from its finished state back through every way it can be stopped. The kills are
// keys_crash_test.go's.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

// What a rotation must leave: every file readable, on the one current root, with only that root and
// one U on disk.
func requireRotationFinished(t *testing.T, instance *SidecarInstance, backend SidecarStoreBackend, networkId Id) {
	t.Helper()
	pending, err := instance.RotationPending()
	if err != nil {
		t.Fatal(err)
	}
	if pending {
		t.Error("the rotation is still pending")
	}
	wrap, err := instance.readKeychainWrap(networkId)
	if err != nil {
		t.Fatal(err)
	}
	if len(wrap.roots) != 1 {
		t.Errorf("%d roots", len(wrap.roots))
	}
	directory := networkDirectoryPath(networkId) + "/"
	entries, err := backend.List(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name, keychainWrapName) {
			continue
		}
		header, err := readSealHeader(bytes.NewReader(readBackend(t, backend, entry.Name)))
		if err != nil {
			t.Fatal(err)
		}
		if header.generation != wrap.roots[0].generation {
			t.Errorf("%s is on root %d, not %d", entry.Name, header.generation, wrap.roots[0].generation)
		}
	}
}

// §5.9: rotation changes U and R_n, keeps every value, and the old keys open nothing of what is new.
func TestRotateChangesEveryKeyAndKeepsEveryValue(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	enrollTestNetwork(t, instance, otherTestNetworkId)
	content := sealTestPlaintext(3*sealChunkByteCount + 1)
	store := storeOf(t, instance, testNetworkId, "evs")
	writeStoreFile(t, store, "large", content)
	writeStoreFile(t, storeOf(t, instance, otherTestNetworkId, "gkm"), "group", []byte("synthetic"))
	opened, err := instance.keychainFor(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	oldRoot := bytes.Clone(opened.generationRoots[1])
	oldUnlockKey, err := instance.currentUnlockKey()
	if err != nil {
		t.Fatal(err)
	}
	oldItems := keyStore.snapshot()

	if err := instance.RotateKeychain(context.Background(), nil); err != nil {
		t.Fatal(err)
	}

	requireRotationFinished(t, instance, backend, testNetworkId)
	requireRotationFinished(t, instance, backend, otherTestNetworkId)
	requireStoreFile(t, store, "large", content)
	requireStoreFile(t, storeOf(t, instance, otherTestNetworkId, "gkm"), "group", []byte("synthetic"))
	seed, err := opened.secrets("identity").Get("seed")
	if err != nil || !strings.HasPrefix(string(seed), "synthetic seed") {
		t.Errorf("seed %q, err %v", seed, err)
	}

	newUnlockKey, err := instance.currentUnlockKey()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(oldUnlockKey, newUnlockKey) {
		t.Error("U did not change")
	}
	if opened.currentGeneration != 2 || len(opened.generationRoots) != 1 {
		t.Errorf("generation %d, %d roots", opened.currentGeneration, len(opened.generationRoots))
	}
	if bytes.Equal(oldRoot, opened.generationRoots[2]) {
		t.Error("R_n did not change")
	}
	// the old W went with the old U, and the old root opens no file
	for name := range oldItems {
		if _, ok := keyStore.snapshot()[name]; ok {
			t.Errorf("the old item %s stands", name)
		}
	}
	classKey, err := deriveLocalKey(oldRoot, "evs")
	if err != nil {
		t.Fatal(err)
	}
	stored := readBackend(t, backend, networkFilePath(testNetworkId, "evs/large"))
	_, err = openTestFile(stored, classKey, "evs/large")
	requireError(t, err, ErrSidecarStoreFailed)

	// a restart reads the same state back
	instance.Close()
	reopened := newInstanceOn(t, backend, keyStore)
	if err := reopened.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	requireStoreFile(t, storeOf(t, reopened, testNetworkId, "evs"), "large", content)
}

// The pass goes on working across a rotation, on a new salt.
func TestRotateCarriesThePass(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	if err := instance.ChangePass(nil, testPass); err != nil {
		t.Fatal(err)
	}
	before, err := instance.readUnlockWrap()
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.RotateKeychain(context.Background(), testPass); err != nil {
		t.Fatal(err)
	}
	after, err := instance.readUnlockWrap()
	if err != nil {
		t.Fatal(err)
	}
	if after.pass == nil || before.pass.salt == after.pass.salt {
		t.Errorf("wrap %+v", after.pass)
	}
	instance.Close()
	keyStore.answer(SidecarKeyStoreLocked)
	reopened := newInstanceOn(t, backend, keyStore)
	if err := reopened.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.keychainFor(testNetworkId); err != nil {
		t.Error(err)
	}
}

func TestRotateRefusesTheWrongPassBeforeAnythingChanges(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	if err := instance.ChangePass(nil, testPass); err != nil {
		t.Fatal(err)
	}
	before := backendSnapshot(t, backend)
	writeCount := keyStore.writeCount
	err := instance.RotateKeychain(context.Background(), []byte("synthetic wrong pass"))
	requireError(t, err, ErrSidecarPassRefused)
	after := backendSnapshot(t, backend)
	for path, content := range before {
		if path != stateJsonPath && !bytes.Equal(content, after[path]) {
			t.Errorf("%s changed", path)
		}
	}
	if keyStore.writeCount != writeCount {
		t.Error("the key store was written")
	}
}

// A locked store takes no new W, and a rotation that cannot have one changes nothing.
func TestRotateStopsAtALockedStore(t *testing.T) {
	for _, c := range []struct {
		status SidecarKeyStoreStatus
		want   error
	}{
		{status: SidecarKeyStoreLocked, want: ErrSidecarStoreLocked},
		{status: SidecarKeyStoreFailed, want: ErrSidecarStoreFailed},
	} {
		instance, backend, keyStore := enrolledInstance(t)
		before := backendSnapshot(t, backend)
		keyStore.answer(c.status)
		requireError(t, instance.RotateKeychain(context.Background(), nil), c.want)
		requireSameBackend(t, before, backend)
	}
}

func TestRotateNeedsAnOpenKeychain(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	instance.Lock()
	requireError(t, instance.RotateKeychain(context.Background(), nil), ErrSidecarStoreLocked)
	_, err := instance.RotationPending()
	requireError(t, err, ErrSidecarStoreLocked)
}

// A cancelled run stops between files, and the next one picks up from what the headers say.
func TestRotateStopsOnContextAndResumes(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	store := storeOf(t, instance, testNetworkId, "evs")
	for i := 0; i < 4; i += 1 {
		writeStoreFile(t, store, fmt.Sprintf("file-%d", i), []byte("synthetic"))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	requireError(t, instance.RotateKeychain(ctx, nil), context.Canceled)
	pending, err := instance.RotationPending()
	if err != nil || !pending {
		t.Fatalf("pending %v, err %v", pending, err)
	}
	for i := 0; i < 4; i += 1 {
		requireStoreFile(t, store, fmt.Sprintf("file-%d", i), []byte("synthetic"))
	}
	if err := instance.RotateKeychain(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	requireRotationFinished(t, instance, backend, testNetworkId)
}

// A resumed run needs no pass: the new U already has every wrap it will get.
func TestAResumedRotationNeedsNoPass(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	if err := instance.ChangePass(nil, testPass); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	requireError(t, instance.RotateKeychain(ctx, testPass), context.Canceled)
	if err := instance.RotateKeychain(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	requireRotationFinished(t, instance, backend, testNetworkId)
}

// A stream open on the old root keeps that root, so nothing is pulled out from under it, and the next
// run finishes once it closes.
func TestAnOpenStreamHoldsItsRoot(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	store := storeOf(t, instance, testNetworkId, "evs")
	content := sealTestPlaintext(2*sealChunkByteCount + 1)
	writeStoreFile(t, store, "file", content)

	reader, err := store.Open("file")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	requireError(t, instance.RotateKeychain(context.Background(), nil), ErrSidecarRotationBusy)

	read, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(read, content) {
		t.Error("the stream read something else")
	}
	reader.Close()
	if err := instance.RotateKeychain(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	requireRotationFinished(t, instance, backend, testNetworkId)
}

// A write begun under the old root and committed after the flip lands on the old root, which the
// rotation must see and re-seal, and may not outrun.
func TestAWriteInFlightAcrossTheFlipIsResealed(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	store := storeOf(t, instance, testNetworkId, "evs")
	writer, err := store.Create("file")
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.Write([]byte("in flight")); err != nil {
		t.Fatal(err)
	}
	requireError(t, instance.RotateKeychain(context.Background(), nil), ErrSidecarRotationBusy)

	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	requireStoreFile(t, store, "file", []byte("in flight"))
	if err := instance.RotateKeychain(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	requireRotationFinished(t, instance, backend, testNetworkId)
	requireStoreFile(t, store, "file", []byte("in flight"))
}

// The gap a stream's count cannot see: a write begun on the old root commits and closes after the last
// pass looked and before the old root goes. Nothing holds the root by then, so only the count of late
// commits sends the pass round again, or the file would be left on a root nobody has.
func TestAWriteLandingAfterTheLastPassIsResealed(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	store := storeOf(t, instance, testNetworkId, "evs")
	writer, err := store.Create("file")
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.Write([]byte("in flight")); err != nil {
		t.Fatal(err)
	}

	// keychain.wrap's third read is the one that ends the pass: the first two come before it
	instance.backend = &writeOnOpenBackend{
		SidecarStoreBackend: backend,
		path:                keychainWrapPath(testNetworkId),
		skipCount:           2,
		write: func() {
			if err := writer.Commit(); err != nil {
				t.Error(err)
			}
			writer.Close()
		},
	}
	err = instance.RotateKeychain(context.Background(), nil)
	instance.backend = backend
	if err != nil {
		t.Fatal(err)
	}
	requireRotationFinished(t, instance, backend, testNetworkId)
	requireStoreFile(t, store, "file", []byte("in flight"))
}

// A file replaced while its re-seal was being copied keeps the newer bytes: the re-seal must not put the
// older ones back. resealFile checks the header it copied from is still the one at the path.
func TestAResealLosesToANewerWrite(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	store := storeOf(t, instance, testNetworkId, "evs")
	writeStoreFile(t, store, "file", []byte("old"))
	opened, err := instance.keychainFor(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	wrap, err := instance.readKeychainWrap(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.flipUnlockKeyWithLock(mustUnlockWrap(t, instance), nil); err != nil {
		t.Fatal(err)
	}
	if err := instance.addRootWithLock(opened, wrap); err != nil {
		t.Fatal(err)
	}

	// the write lands just after the re-seal opened the file, so it copies the old bytes
	instance.backend = &writeOnOpenBackend{
		SidecarStoreBackend: backend,
		path:                networkFilePath(testNetworkId, "evs/file"),
		write: func() {
			instance.backend = backend
			writeStoreFile(t, store, "file", []byte("new"))
		},
	}
	resealed, err := opened.resealFile("evs/file")
	instance.backend = backend
	if err != nil || !resealed {
		t.Fatalf("resealed %v, err %v", resealed, err)
	}
	requireStoreFile(t, store, "file", []byte("new"))
}

// Runs write once, after path is opened for the skipCount+1th time, so the reader it answers holds the
// bytes from before.
type writeOnOpenBackend struct {
	SidecarStoreBackend
	path      string
	skipCount int
	write     func()
}

// Answers the reader of the old bytes, having run write behind it.
func (self *writeOnOpenBackend) Open(filePath string) (io.ReadCloser, error) {
	reader, err := self.SidecarStoreBackend.Open(filePath)
	if filePath == self.path && self.write != nil {
		if 0 < self.skipCount {
			self.skipCount -= 1
			return reader, err
		}
		write := self.write
		self.write = nil
		write()
	}
	return reader, err
}

// unlock.wrap, which must read.
func mustUnlockWrap(t *testing.T, instance *SidecarInstance) *unlockWrap {
	t.Helper()
	wrap, err := instance.readUnlockWrap()
	if err != nil {
		t.Fatal(err)
	}
	return wrap
}

// A reader that read a header just before a rotation finished finds the file on its new root, and a
// healthy file never reads as failed for having moved.
func TestAReadCrossingTheEndOfARotationOpensTheNewFile(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	store := storeOf(t, instance, testNetworkId, "evs")
	writeStoreFile(t, store, "file", []byte("synthetic"))
	path := networkFilePath(testNetworkId, "evs/file")

	// the whole rotation lands between the reader's open and its hold on the root
	instance.backend = &writeOnOpenBackend{
		SidecarStoreBackend: backend,
		path:                path,
		write: func() {
			instance.backend = backend
			if err := instance.RotateKeychain(context.Background(), nil); err != nil {
				t.Error(err)
			}
		},
	}
	requireStoreFile(t, store, "file", []byte("synthetic"))
	instance.backend = backend
	requireRotationFinished(t, instance, backend, testNetworkId)
}

// A file naming a root the network never had reads as failed, not as a loop.
func TestAFileOnAnUnknownRootFails(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	store := storeOf(t, instance, testNetworkId, "evs")
	writeStoreFile(t, store, "file", []byte("synthetic"))
	path := networkFilePath(testNetworkId, "evs/file")
	content := readBackend(t, backend, path)
	// the header's generation is the eight bytes after the magic and the version
	content[12] = 0x7f
	putBackendFile(t, backend, path, content)
	_, err := readStoreFile(store, "file")
	requireError(t, err, ErrSidecarStoreFailed)
}

// Writers, readers and a rotation at once, for the race detector and for the end state: each file and
// secret holds its last value, and every one is on the new root. A stream in the rotation's way
// answers busy, which the next run takes up, as a person's retry would.
func TestRotateWithStreamsRunning(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	store := storeOf(t, instance, testNetworkId, "evs")
	opened, err := instance.keychainFor(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	secrets := opened.secrets("load")
	const writerCount = 4
	const writeCount = 16
	var writers sync.WaitGroup
	for writer := 0; writer < writerCount; writer += 1 {
		writers.Add(1)
		go func() {
			defer writers.Done()
			name := fmt.Sprintf("file-%d", writer)
			for i := 0; i < writeCount; i += 1 {
				content := []byte(fmt.Sprintf("%s %d", name, i))
				if err := putStoreFile(store, name, content); err != nil {
					t.Error(err)
					return
				}
				read, err := readStoreFile(store, name)
				if err != nil {
					t.Error(err)
					return
				}
				if !bytes.Equal(read, content) {
					t.Errorf("%s read %q", name, read)
				}
				if err := secrets.Put(name, content); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	err = instance.RotateKeychain(context.Background(), nil)
	writers.Wait()
	if err != nil && !errors.Is(err, ErrSidecarRotationBusy) {
		t.Fatal(err)
	}
	if err := instance.RotateKeychain(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	requireRotationFinished(t, instance, backend, testNetworkId)
	for writer := 0; writer < writerCount; writer += 1 {
		name := fmt.Sprintf("file-%d", writer)
		want := []byte(fmt.Sprintf("%s %d", name, writeCount-1))
		requireStoreFile(t, store, name, want)
		value, err := secrets.Get(name)
		if err != nil || !bytes.Equal(value, want) {
			t.Errorf("%s: value %q, err %v", name, value, err)
		}
	}
}

// A network that cannot rotate holds the old U back and does not stop its neighbors.
func TestAFailedNetworkKeepsTheRotationPending(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	enrollTestNetwork(t, instance, otherTestNetworkId)
	instance.Close()
	recordsPath := networkFilePath(testNetworkId, keychainRecordsName)
	good := readBackend(t, backend, recordsPath)
	damaged := bytes.Clone(good)
	damaged[len(damaged)-1] ^= 0x01
	putBackendFile(t, backend, recordsPath, damaged)

	reopened := newInstanceOn(t, backend, keyStore)
	if err := reopened.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	requireError(t, reopened.RotateKeychain(context.Background(), nil), ErrSidecarStoreFailed)
	pending, err := reopened.RotationPending()
	if err != nil || !pending {
		t.Errorf("pending %v, err %v", pending, err)
	}
	wrap, err := reopened.readKeychainWrap(otherTestNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	if wrap.roots[0].generation != 2 || len(wrap.roots) != 1 {
		t.Errorf("the healthy network: %+v", wrap.roots)
	}

	// mended, the same run finishes it
	putBackendFile(t, backend, recordsPath, good)
	reopened.Close()
	again := newInstanceOn(t, backend, keyStore)
	if err := again.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	if err := again.RotateKeychain(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	requireRotationFinished(t, again, backend, testNetworkId)
	requireRotationFinished(t, again, backend, otherTestNetworkId)
}

// A keychain.wrap that does not read fails on its own turn too: its neighbors still rotate.
func TestADamagedWrapHoldsNoOtherNetworkBack(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	enrollTestNetwork(t, instance, otherTestNetworkId)
	instance.Close()
	putBackendFile(t, backend, keychainWrapPath(testNetworkId), []byte("not a wrap"))

	reopened := newInstanceOn(t, backend, keyStore)
	if err := reopened.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	requireError(t, reopened.RotateKeychain(context.Background(), nil), ErrSidecarStoreFailed)
	wrap, err := reopened.readKeychainWrap(otherTestNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	if wrap.roots[0].generation != 2 || len(wrap.roots) != 1 {
		t.Errorf("the healthy network: %+v", wrap.roots)
	}
	pending, err := reopened.RotationPending()
	if err != nil || !pending {
		t.Errorf("pending %v, err %v", pending, err)
	}
}

// A lost network holds nothing up, and stays a loss: its keychain.wrap moves under the new U, so the
// person can still confirm a new device for it. Its wrap once kept naming the U the rotation dropped,
// which made the loss a failure that no confirmation could clear.
func TestALostNetworkDoesNotHoldARotation(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	enrollTestNetwork(t, instance, otherTestNetworkId)
	instance.Close()
	if err := backend.Remove(networkFilePath(testNetworkId, keychainRecordsName)); err != nil {
		t.Fatal(err)
	}
	reopened := newInstanceOn(t, backend, keyStore)
	if err := reopened.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	if err := reopened.RotateKeychain(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.keychainFor(testNetworkId); !errors.Is(err, ErrSidecarKeystoreLost) {
		t.Errorf("the lost network reads %v", err)
	}
	reopened.Close()
	again := newInstanceOn(t, backend, keyStore)
	if err := again.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := again.keychainFor(testNetworkId); !errors.Is(err, ErrSidecarKeystoreLost) {
		t.Errorf("after a restart the lost network reads %v", err)
	}
	if err := again.ConfirmNewNetworkDevice(testNetworkId); err != nil {
		t.Errorf("the loss cannot be confirmed: %v", err)
	}
}

// Step 3's own check: an older U stays while a keychain.wrap still names it, however the run got there.
func TestStepThreeKeepsAnOlderUAWrapStillNames(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	writeStoreFile(t, storeOf(t, instance, testNetworkId, "evs"), "file", []byte("old file"))
	before := readBackend(t, backend, keychainWrapPath(testNetworkId))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	requireError(t, instance.RotateKeychain(ctx, nil), context.Canceled)
	putBackendFile(t, backend, keychainWrapPath(testNetworkId), before)
	requireError(t, instance.finishRotationWithLock([]Id{testNetworkId}), errRotateUnfinished)
	if wrap := mustUnlockWrap(t, instance); len(wrap.previousKeys) != 1 {
		t.Errorf("%d older U", len(wrap.previousKeys))
	}
	if len(keyStore.snapshot()) != 2 {
		t.Errorf("%d items in the store", len(keyStore.snapshot()))
	}
	instance.Close()
	reopened := newInstanceOn(t, backend, keyStore)
	if err := reopened.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	requireStoreFile(t, storeOf(t, reopened, testNetworkId, "evs"), "file", []byte("old file"))
}

// Step 2's own check: the old roots stay unless the root kept is the one the files were re-sealed to.
func TestStepTwoKeepsTheOldRootsUnlessTheFilesAreOnTheKeptOne(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	requireError(t, instance.RotateKeychain(ctx, nil), context.Canceled)
	opened, err := instance.keychainFor(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	func() {
		opened.stateLock.Lock()
		defer opened.stateLock.Unlock()
		opened.currentGeneration = 1
	}()
	_, err = instance.dropOldRootsWithLock(opened, opened.staleCommitCount.Load())
	requireError(t, err, errRotateUnfinished)
	wrap, err := instance.readKeychainWrap(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	if len(wrap.roots) != 2 {
		t.Errorf("%d roots", len(wrap.roots))
	}
}

// CORE-M2-05's copy cannot be re-sealed yet, and rotating past it would leave a recovery code opening
// nothing, so this refuses with nothing changed.
func TestARecoveryCopyRefusesARotation(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	wrap, err := instance.readKeychainWrap(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	wrap.recovery = []byte("synthetic recovery copy")
	putBackendFile(t, backend, keychainWrapPath(testNetworkId), wrap.encode())
	before := backendSnapshot(t, backend)
	requireError(t, instance.RotateKeychain(context.Background(), nil), errRotateRecovery)
	requireSameBackend(t, before, backend)
}

// A rotation with nothing enrolled still rotates U.
func TestRotateWithNoNetworks(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	keyStore := newFakeKeyStore()
	instance := newInstanceOn(t, backend, keyStore)
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	if err := instance.RotateKeychain(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if wrap := mustUnlockWrap(t, instance); wrap.generation != 2 || len(wrap.previousKeys) != 0 {
		t.Errorf("wrap %+v", wrap)
	}
}

// Two rotations in a row, so a stale item from the first cannot trip the second.
func TestRotateTwice(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	writeStoreFile(t, storeOf(t, instance, testNetworkId, "evs"), "file", []byte("synthetic"))
	for i := 0; i < 2; i += 1 {
		if err := instance.RotateKeychain(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
	}
	requireRotationFinished(t, instance, backend, testNetworkId)
	if len(keyStore.snapshot()) != 1 {
		t.Errorf("%d items in the store", len(keyStore.snapshot()))
	}
	instance.Close()
	reopened := newInstanceOn(t, backend, keyStore)
	if err := reopened.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	requireStoreFile(t, storeOf(t, reopened, testNetworkId, "evs"), "file", []byte("synthetic"))
}

// §5.9's promise, at every step of a rotation, in the worst case and the best: the machine comes back
// up with every file readable, a resumed run finishes, and nothing was lost on the way.
// Two networks with a value, a multi-chunk file and a file each, on a crash world: what a rotation
// test then holds every step to. Answers the content of the multi-chunk file.
func rotationCrashWorld(t *testing.T) (*crashWorld, []byte) {
	t.Helper()
	world := enrolledCrashWorld(t)
	content := sealTestPlaintext(sealChunkByteCount + 1)
	setup := world.open(world.keyStore())
	if err := setup.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	enrollTestNetwork(t, setup, otherTestNetworkId)
	writeStoreFile(t, storeOf(t, setup, testNetworkId, "gkm"), "group", content)
	writeStoreFile(t, storeOf(t, setup, otherTestNetworkId, "evs"), "repo", []byte("synthetic repo"))
	setup.Close()
	world.reboot(false)
	return world, content
}

// Every value and file of rotationCrashWorld, read through instance.
func requireRotationWorld(t *testing.T, instance *SidecarInstance, content []byte, trace []string) {
	t.Helper()
	first, err := instance.keychainFor(testNetworkId)
	if err != nil {
		t.Fatalf("after %q: %v", trace, err)
	}
	second, err := instance.keychainFor(otherTestNetworkId)
	if err != nil {
		t.Fatalf("after %q: %v", trace, err)
	}
	for _, opened := range []*keychain{first, second} {
		seed, err := opened.secrets("identity").Get("seed")
		if err != nil || !strings.HasPrefix(string(seed), "synthetic seed") {
			t.Errorf("after %q: seed %q, err %v", trace, seed, err)
		}
	}
	value, err := first.secrets("evs").Get("key")
	if err != nil || string(value) != "old value" {
		t.Errorf("after %q: value %q, err %v", trace, value, err)
	}
	for _, check := range []struct {
		store SidecarStore
		name  string
		want  []byte
	}{
		{store: storeOf(t, instance, testNetworkId, "evs"), name: "file", want: []byte("old file")},
		{store: storeOf(t, instance, testNetworkId, "gkm"), name: "group", want: content},
		{store: storeOf(t, instance, otherTestNetworkId, "evs"), name: "repo", want: []byte("synthetic repo")},
	} {
		got, err := readStoreFile(check.store, check.name)
		if err != nil {
			t.Errorf("after %q: %s: %v", trace, check.name, err)
		} else if !bytes.Equal(got, check.want) {
			t.Errorf("after %q: %s changed", trace, check.name)
		}
	}
}

// What a finished rotation leaves on a crash world: one root per network, every file on it, one U and
// one item in the key store.
func requireRotationWorldFinished(t *testing.T, instance *SidecarInstance, world *crashWorld, trace []string) {
	t.Helper()
	backend := &crashBackend{world: world}
	requireRotationFinished(t, instance, backend, testNetworkId)
	requireRotationFinished(t, instance, backend, otherTestNetworkId)
	if len(world.keyStoreItems) != 1 {
		t.Errorf("after %q: %d items in the store", trace, len(world.keyStoreItems))
	}
}

func TestRotateResumesAfterKill(t *testing.T) {
	world, content := rotationCrashWorld(t)
	requireEverything := func(instance *SidecarInstance, trace []string) {
		t.Helper()
		requireRotationWorld(t, instance, content, trace)
	}

	operation := func(world *crashWorld) error {
		instance := world.open(world.keyStore())
		defer instance.Close()
		if err := instance.Unlock(nil); err != nil {
			return err
		}
		return instance.RotateKeychain(context.Background(), nil)
	}
	forEachKill(t, world, operation, func(world *crashWorld, trace []string, died bool) {
		instance := restartOpen(t, world, trace)
		defer instance.Close()
		requireEverything(instance, trace)

		// the instance opened, read everything, and now a second kill anywhere in the resume would be
		// the same as this one: run it to the end
		if err := instance.RotateKeychain(context.Background(), nil); err != nil {
			t.Fatalf("after %q: %v", trace, err)
		}
		requireEverything(instance, trace)
		requireRotationWorldFinished(t, instance, world, trace)
	})
}

// A fault at any step of a rotation, the medium answering an error with the machine still on, as a
// directory's fsync does with EIO after its rename went through: the same process tries again and
// finishes, and then even the worst power cut leaves every file readable. A retry once took its idea of
// the current U and root from memory, which such a fault leaves behind the disk, and dropped the keys
// every file was on.
func TestARotationRetriedAfterAFaultAtAnyStepLosesNothing(t *testing.T) {
	world, content := rotationCrashWorld(t)
	rotate := func(world *crashWorld) (*SidecarInstance, error) {
		instance := world.open(world.keyStore())
		if err := instance.Unlock(nil); err != nil {
			t.Fatal(err)
		}
		return instance, instance.RotateKeychain(context.Background(), nil)
	}
	counted := world.clone()
	instance, err := rotate(counted)
	if err != nil {
		t.Fatalf("the unbroken run failed: %v", err)
	}
	instance.Close()
	stepCount := counted.steps
	for faultAt := 1; faultAt <= stepCount; faultAt += 1 {
		for _, loseUnsynced := range []bool{true, false} {
			faulted := world.clone()
			faulted.faultAt = faultAt
			instance, err := rotate(faulted)
			if err == nil {
				t.Errorf("a fault at step %d of %d went unanswered", faultAt, stepCount)
			}
			for retryCount := 0; err != nil; retryCount += 1 {
				if retryCount == 3 {
					t.Fatalf("a fault at step %d of %d, still failing: %v", faultAt, stepCount, err)
				}
				err = instance.RotateKeychain(context.Background(), nil)
			}
			instance.Close()
			trace := faulted.trace
			faulted.reboot(loseUnsynced)
			reopened := restartOpen(t, faulted, trace)
			requireRotationWorld(t, reopened, content, trace)
			requireRotationWorldFinished(t, reopened, faulted, trace)
			reopened.Close()
		}
	}
}

// The same with a pass: at every step the pass opens U, whichever U that is.
func TestRotateKeepsThePassAtEveryStep(t *testing.T) {
	world := enrolledCrashWorld(t)
	setup := world.open(world.keyStore())
	if err := setup.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	if err := setup.ChangePass(nil, testPass); err != nil {
		t.Fatal(err)
	}
	setup.Close()
	world.reboot(false)

	operation := func(world *crashWorld) error {
		instance := world.open(world.keyStore())
		defer instance.Close()
		if err := instance.Unlock(nil); err != nil {
			return err
		}
		return instance.RotateKeychain(context.Background(), testPass)
	}
	forEachKill(t, world, operation, func(world *crashWorld, trace []string, died bool) {
		instance := world.open(nil)
		defer instance.Close()
		if err := instance.Unlock(testPass); err != nil {
			t.Fatalf("after %q: %v", trace, err)
		}
		opened, err := instance.keychainFor(testNetworkId)
		if err != nil {
			t.Fatalf("after %q: %v", trace, err)
		}
		if _, err := opened.secrets("identity").Get("seed"); err != nil {
			t.Errorf("after %q: %v", trace, err)
		}
	})
}

// A file a component wrote after a kill, on a resumed rotation's way through, is on the new root and
// stays readable.
func TestAWriteDuringAResumeIsKept(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	store := storeOf(t, instance, testNetworkId, "evs")
	writeStoreFile(t, store, "old", []byte("old"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	requireError(t, instance.RotateKeychain(ctx, nil), context.Canceled)

	writeStoreFile(t, store, "new", []byte("new"))
	requireStoreFile(t, store, "old", []byte("old"))
	if err := instance.RotateKeychain(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	requireRotationFinished(t, instance, backend, testNetworkId)
	requireStoreFile(t, store, "new", []byte("new"))
	requireStoreFile(t, store, "old", []byte("old"))
}

// A file that is not sealed stops a rotation instead of being taken for one that is: an unknown format
// may be someone's data, and the old root stands.
func TestAnUnknownFileStopsARotation(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	putBackendFile(t, backend, networkFilePath(testNetworkId, "evs/unknown"), []byte("not sealed"))
	err := instance.RotateKeychain(context.Background(), nil)
	if !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("err %v", err)
	}
	wrap, err := instance.readKeychainWrap(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	if len(wrap.roots) != 2 {
		t.Errorf("%d roots", len(wrap.roots))
	}
}

// A directory's fsync fails after its rename went through, and the power goes out at any step of the
// retry that follows: the rename the fault left to chance may be undone, and nothing the retry built on
// it may be lost with it. A restart resumes and finishes with every file readable.
func TestARetryKilledAfterADirectorySyncFaultLosesNothing(t *testing.T) {
	world, content := rotationCrashWorld(t)
	// the fault, then the retry, which dies at dieAt when that is set
	faultThenRetry := func(world *crashWorld) {
		instance := world.open(world.keyStore())
		defer instance.Close()
		if err := instance.Unlock(nil); err != nil {
			t.Fatal(err)
		}
		if err := instance.RotateKeychain(context.Background(), nil); err == nil {
			t.Fatalf("a fault at step %d went unanswered", world.faultAt)
		}
		instance.RotateKeychain(context.Background(), nil)
	}
	counted := world.clone()
	instance := counted.open(counted.keyStore())
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	if err := instance.RotateKeychain(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	instance.Close()
	faultCount := 0
	for faultAt, name := range counted.trace {
		if !strings.HasPrefix(name, "sync directory of ") {
			continue
		}
		faultCount += 1
		// counts the steps of the fault's run and of its retry
		faulted := world.clone()
		faulted.faultAt = faultAt + 1
		instance := faulted.open(faulted.keyStore())
		if err := instance.Unlock(nil); err != nil {
			t.Fatal(err)
		}
		if err := instance.RotateKeychain(context.Background(), nil); err == nil {
			t.Fatalf("a fault at %q went unanswered", name)
		}
		faultedStepCount := faulted.steps
		if err := instance.RotateKeychain(context.Background(), nil); err != nil {
			t.Fatalf("the retry after a fault at %q: %v", name, err)
		}
		instance.Close()
		for dieAt := faultedStepCount + 1; dieAt <= faulted.steps; dieAt += 1 {
			for _, loseUnsynced := range []bool{true, false} {
				killed := world.clone()
				killed.faultAt = faultAt + 1
				killed.dieAt = dieAt
				faultThenRetry(killed)
				if !killed.dead {
					t.Fatalf("a fault at %q: no death at step %d", name, dieAt)
				}
				trace := killed.trace
				killed.reboot(loseUnsynced)
				reopened := restartOpen(t, killed, trace)
				requireRotationWorld(t, reopened, content, trace)
				if err := reopened.RotateKeychain(context.Background(), nil); err != nil {
					t.Fatalf("after %q: %v", trace, err)
				}
				requireRotationWorld(t, reopened, content, trace)
				requireRotationWorldFinished(t, reopened, killed, trace)
				reopened.Close()
			}
		}
	}
	if faultCount == 0 {
		t.Fatal("a rotation synced no directory")
	}
}
