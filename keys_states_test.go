// §5.9's table, row by row, on what each answer may change. The rows are D-CORE-15, which exists so a
// lock or a fault can never reset an identity.

package sidecar

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var (
	testNetworkId      = Id{0x01, 0x93, 0x11}
	otherTestNetworkId = Id{0x01, 0x93, 0x22}
	testPass           = []byte("synthetic pass")
)

// An enrolled instance on a store that works, with its medium and store for the next open.
func enrolledInstance(t *testing.T) (*SidecarInstance, SidecarStoreBackend, *fakeKeyStore) {
	t.Helper()
	backend := NewSidecarMemoryBackend()
	keyStore := newFakeKeyStore()
	instance := newInstanceOn(t, backend, keyStore)
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	enrollTestNetwork(t, instance, testNetworkId)
	return instance, backend, keyStore
}

func TestFirstUnlockCreatesU(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	keyStore := newFakeKeyStore()
	instance := newInstanceOn(t, backend, keyStore)
	requireState(t, instance, SidecarInstanceLocked)

	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	requireState(t, instance, SidecarInstanceOpen)
	if len(keyStore.snapshot()) != 1 {
		t.Errorf("key store holds %d items", len(keyStore.snapshot()))
	}
	wrap, err := instance.readUnlockWrap()
	if err != nil || wrap == nil {
		t.Fatalf("wrap %v, err %v", wrap, err)
	}
	if wrap.store == nil || wrap.pass != nil || wrap.generation != 1 {
		t.Errorf("wrap %+v", wrap)
	}
}

// Nothing is written before U exists, so a first run in front of a locked store leaves no trace.
func TestOpeningWritesNothing(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	newInstanceOn(t, backend, newFakeKeyStore())
	requireSameBackend(t, map[string][]byte{}, backend)
}

func TestAReopenedInstanceOpensTheSameU(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	unlockKey, err := instance.currentUnlockKey()
	if err != nil {
		t.Fatal(err)
	}
	instance.Close()

	reopened := newInstanceOn(t, backend, keyStore)
	if err := reopened.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	reopenedKey, err := reopened.currentUnlockKey()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unlockKey, reopenedKey) {
		t.Error("U changed across a restart")
	}
}

// D-CORE-15's first row of loss: W gone, an id recorded. No new U, no new file, and no store write.
func TestAbsentWithRecordedIdCreatesNothing(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	instance.Close()
	keyStore.lose()
	writeCount := keyStore.writeCount
	before := backendSnapshot(t, backend)

	reopened := newInstanceOn(t, backend, keyStore)
	requireError(t, reopened.Unlock(nil), ErrSidecarKeystoreLost)
	requireState(t, reopened, SidecarInstanceLost)
	requireSameBackend(t, before, backend)
	if keyStore.writeCount != writeCount {
		t.Error("the key store was written")
	}
}

// sidecar.json is written last, so a keychain.wrap with no record is still an identity on disk, and a
// loss there must not read as a first run.
func TestAnUnrecordedKeychainWrapStillCountsAsAnIdentity(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	keyStore := newFakeKeyStore()
	instance := newInstanceOn(t, backend, keyStore)
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := instance.createKeychain(testNetworkId); err != nil {
		t.Fatal(err)
	}
	instance.Close()
	keyStore.lose()
	before := backendSnapshot(t, backend)

	reopened := newInstanceOn(t, backend, keyStore)
	requireError(t, reopened.Unlock(nil), ErrSidecarKeystoreLost)
	requireSameBackend(t, before, backend)
}

// Absent with nothing recorded is the one row that makes U, and it does so again over a leftover wrap.
func TestAbsentWithNothingRecordedCreatesU(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	keyStore := newFakeKeyStore()
	instance := newInstanceOn(t, backend, keyStore)
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	instance.Close()
	keyStore.lose()

	reopened := newInstanceOn(t, backend, keyStore)
	if err := reopened.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	requireState(t, reopened, SidecarInstanceOpen)
}

func TestLockedCreatesNothing(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	keyStore := newFakeKeyStore()
	keyStore.answer(SidecarKeyStoreLocked)
	instance := newInstanceOn(t, backend, keyStore)

	requireError(t, instance.Unlock(nil), ErrSidecarStoreLocked)
	requireState(t, instance, SidecarInstanceLocked)
	requireSameBackend(t, map[string][]byte{}, backend)
	if len(keyStore.nameValues) != 0 {
		t.Error("a locked store was written")
	}
}

// A pass in hand changes nothing about that: Locked never creates.
func TestLockedCreatesNothingEvenWithAPass(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	keyStore := newFakeKeyStore()
	keyStore.answer(SidecarKeyStoreLocked)
	instance := newInstanceOn(t, backend, keyStore)

	requireError(t, instance.Unlock(testPass), ErrSidecarStoreLocked)
	requireSameBackend(t, map[string][]byte{}, backend)
}

func TestLockedOverAnEnrolledInstanceChangesNothing(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	instance.Close()
	before := backendSnapshot(t, backend)
	held := keyStore.snapshot()
	keyStore.answer(SidecarKeyStoreLocked)

	reopened := newInstanceOn(t, backend, keyStore)
	requireError(t, reopened.Unlock(nil), ErrSidecarStoreLocked)
	requireState(t, reopened, SidecarInstanceLocked)
	requireSameBackend(t, before, backend)
	keyStore.recover()
	for name, value := range keyStore.snapshot() {
		if !bytes.Equal(held[name], value) {
			t.Errorf("%s changed", name)
		}
	}
}

func TestFailedCreatesNothing(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	keyStore := newFakeKeyStore()
	keyStore.answer(SidecarKeyStoreFailed)
	instance := newInstanceOn(t, backend, keyStore)

	requireError(t, instance.Unlock(nil), ErrSidecarStoreFailed)
	requireState(t, instance, SidecarInstanceFailed)
	requireSameBackend(t, map[string][]byte{}, backend)
}

func TestFailedOverAnEnrolledInstanceChangesNothing(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	instance.Close()
	before := backendSnapshot(t, backend)
	keyStore.answer(SidecarKeyStoreFailed)

	reopened := newInstanceOn(t, backend, keyStore)
	requireError(t, reopened.Unlock(nil), ErrSidecarStoreFailed)
	requireState(t, reopened, SidecarInstanceFailed)
	requireSameBackend(t, before, backend)
}

// A read answering a write's status, or anything unknown, is a store at fault. Only Absent makes a key,
// so nothing but Absent may reach that row.
func TestAStatusNoReadMayAnswerIsFailed(t *testing.T) {
	for _, status := range []SidecarKeyStoreStatus{SidecarKeyStoreOk, 99, -1} {
		backend := NewSidecarMemoryBackend()
		keyStore := newFakeKeyStore()
		keyStore.answer(status)
		instance := newInstanceOn(t, backend, keyStore)
		requireError(t, instance.Unlock(nil), ErrSidecarStoreFailed)
		requireSameBackend(t, map[string][]byte{}, backend)
	}
}

// A write refused after the read said Absent: U is dropped, not used.
func TestAStoreThatRefusesTheFirstWriteOpensNothing(t *testing.T) {
	for _, c := range []struct {
		status SidecarKeyStoreStatus
		want   error
		state  SidecarInstanceState
	}{
		{status: SidecarKeyStoreLocked, want: ErrSidecarStoreLocked, state: SidecarInstanceLocked},
		{status: SidecarKeyStoreFailed, want: ErrSidecarStoreFailed, state: SidecarInstanceFailed},
	} {
		keyStore := newFakeKeyStore()
		status := c.status
		keyStore.writeStatus = &status
		instance := newInstanceOn(t, NewSidecarMemoryBackend(), keyStore)
		requireError(t, instance.Unlock(nil), c.want)
		requireState(t, instance, c.state)
		if _, err := instance.currentUnlockKey(); !errors.Is(err, ErrSidecarStoreLocked) {
			t.Errorf("U stayed in memory: %v", err)
		}
	}
}

// Each value that fails decoding or AEAD is Failed, never Absent, whichever file or item it is.
func TestCorruptBytesAreFailed(t *testing.T) {
	for _, c := range []struct {
		name   string
		damage func(t *testing.T, backend SidecarStoreBackend, keyStore *fakeKeyStore)
	}{
		{name: "W of the wrong size", damage: func(t *testing.T, backend SidecarStoreBackend, keyStore *fakeKeyStore) {
			for name := range keyStore.nameValues {
				keyStore.nameValues[name] = []byte("short")
			}
		}},
		{name: "another W", damage: func(t *testing.T, backend SidecarStoreBackend, keyStore *fakeKeyStore) {
			for name := range keyStore.nameValues {
				keyStore.nameValues[name] = bytes.Repeat([]byte{0x11}, localKeyByteCount)
			}
		}},
		{name: "unlock.wrap's bytes", damage: func(t *testing.T, backend SidecarStoreBackend, keyStore *fakeKeyStore) {
			putBackendFile(t, backend, unlockWrapPath, []byte("not a wrap"))
		}},
		{name: "unlock.wrap's seal", damage: func(t *testing.T, backend SidecarStoreBackend, keyStore *fakeKeyStore) {
			content := readBackend(t, backend, unlockWrapPath)
			content[len(unlockWrapMagic)+1+8+1+8+wrappedKeyNonceByteCount] ^= 0x01
			putBackendFile(t, backend, unlockWrapPath, content)
		}},
		{name: "unlock.wrap empty", damage: func(t *testing.T, backend SidecarStoreBackend, keyStore *fakeKeyStore) {
			putBackendFile(t, backend, unlockWrapPath, nil)
		}},
		{name: "sidecar.json", damage: func(t *testing.T, backend SidecarStoreBackend, keyStore *fakeKeyStore) {
			putBackendFile(t, backend, stateJsonPath, []byte("{"))
		}},
	} {
		instance, backend, keyStore := enrolledInstance(t)
		instance.Close()
		c.damage(t, backend, keyStore)
		before := backendSnapshot(t, backend)

		reopened := newInstanceOn(t, backend, keyStore)
		err := reopened.Unlock(nil)
		if !errors.Is(err, ErrSidecarStoreFailed) {
			t.Errorf("%s: err %v", c.name, err)
		}
		if state := reopened.state.Value(); state != SidecarInstanceFailed {
			t.Errorf("%s: state %s", c.name, state)
		}
		requireSameBackend(t, before, backend)
	}
}

// A network's own files fail alone, and read as Failed, with U open.
func TestCorruptNetworkFilesAreFailed(t *testing.T) {
	for _, c := range []struct {
		name string
		path string
	}{
		{name: "keychain.wrap", path: keychainWrapPath(testNetworkId)},
		{name: "keychain.ur", path: networkFilePath(testNetworkId, keychainRecordsName)},
	} {
		instance, backend, keyStore := enrolledInstance(t)
		instance.Close()
		content := readBackend(t, backend, c.path)
		content[len(content)-1] ^= 0x01
		putBackendFile(t, backend, c.path, content)
		before := backendSnapshot(t, backend)

		reopened := newInstanceOn(t, backend, keyStore)
		if err := reopened.Unlock(nil); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		_, err := reopened.keychainFor(testNetworkId)
		if !errors.Is(err, ErrSidecarStoreFailed) {
			t.Errorf("%s: err %v", c.name, err)
		}
		if _, err := reopened.createKeychain(testNetworkId); !errors.Is(err, ErrSidecarStoreFailed) {
			t.Errorf("%s: a failed network got a keychain: %v", c.name, err)
		}
		requireSameBackend(t, before, backend)
	}
}

// §5.9: a lost keychain.wrap is the same loss for network n.
func TestLostKeychainWrapIsKeystoreLost(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	instance.Close()
	if err := backend.Remove(keychainWrapPath(testNetworkId)); err != nil {
		t.Fatal(err)
	}
	before := backendSnapshot(t, backend)

	reopened := newInstanceOn(t, backend, keyStore)
	if err := reopened.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.keychainFor(testNetworkId); !errors.Is(err, ErrSidecarKeystoreLost) {
		t.Errorf("err %v", err)
	}
	if _, err := reopened.createKeychain(testNetworkId); !errors.Is(err, ErrSidecarKeystoreLost) {
		t.Errorf("a recorded network got a new root: %v", err)
	}
	requireSameBackend(t, before, backend)
}

// Its identity lives in keychain.ur, so that going is the same loss, and no empty keychain stands in.
func TestLostKeychainRecordsIsKeystoreLost(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	instance.Close()
	if err := backend.Remove(networkFilePath(testNetworkId, keychainRecordsName)); err != nil {
		t.Fatal(err)
	}
	reopened := newInstanceOn(t, backend, keyStore)
	if err := reopened.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.keychainFor(testNetworkId); !errors.Is(err, ErrSidecarKeystoreLost) {
		t.Errorf("err %v", err)
	}
}

// One network's loss is not its neighbor's (CORE-M6-01).
func TestALostNetworkLeavesTheOthersOpen(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	enrollTestNetwork(t, instance, otherTestNetworkId)
	instance.Close()
	if err := backend.Remove(keychainWrapPath(testNetworkId)); err != nil {
		t.Fatal(err)
	}
	reopened := newInstanceOn(t, backend, keyStore)
	if err := reopened.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.keychainFor(testNetworkId); !errors.Is(err, ErrSidecarKeystoreLost) {
		t.Errorf("err %v", err)
	}
	if _, err := reopened.keychainFor(otherTestNetworkId); err != nil {
		t.Errorf("the other network: %v", err)
	}
}

// §22.5's §18 row: a lock, then an unlock, is the same identity, with nothing made in between.
func TestLockedThenUnlockKeepsIdentity(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	opened, err := instance.keychainFor(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := opened.secrets("identity").Get("seed")
	if err != nil {
		t.Fatal(err)
	}
	record := instance.Networks()[0]
	instance.Close()
	before := backendSnapshot(t, backend)

	keyStore.answer(SidecarKeyStoreLocked)
	reopened := newInstanceOn(t, backend, keyStore)
	requireError(t, reopened.Unlock(nil), ErrSidecarStoreLocked)
	requireError(t, reopened.Unlock(nil), ErrSidecarStoreLocked)
	if _, err := reopened.keychainFor(testNetworkId); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Errorf("err %v", err)
	}
	requireSameBackend(t, before, backend)

	keyStore.recover()
	if err := reopened.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	requireSameBackend(t, before, backend)
	reopenedKeychain, err := reopened.keychainFor(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	reopenedSeed, err := reopenedKeychain.secrets("identity").Get("seed")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(seed, reopenedSeed) {
		t.Error("the identity changed")
	}
	if reopened.Networks()[0] != record {
		t.Errorf("record %+v, want %+v", reopened.Networks()[0], record)
	}
}

// The same with a store that fails and recovers.
func TestFailedThenUnlockKeepsIdentity(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	instance.Close()
	keyStore.answer(SidecarKeyStoreFailed)
	reopened := newInstanceOn(t, backend, keyStore)
	requireError(t, reopened.Unlock(nil), ErrSidecarStoreFailed)
	keyStore.recover()
	if err := reopened.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.keychainFor(testNetworkId); err != nil {
		t.Error(err)
	}
}

// §5.9's Absent row: with an id recorded, the pass still opens U. The store gets a wrap back, so the next
// start needs no person.
func TestThePassOpensALostStoreAndPutsItsWrapBack(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	if err := instance.ChangePass(nil, testPass); err != nil {
		t.Fatal(err)
	}
	unlockKey, err := instance.currentUnlockKey()
	if err != nil {
		t.Fatal(err)
	}
	instance.Close()
	keyStore.lose()

	reopened := newInstanceOn(t, backend, keyStore)
	requireError(t, reopened.Unlock(nil), ErrSidecarKeystoreLost)
	requireState(t, reopened, SidecarInstanceLost)
	if err := reopened.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	requireState(t, reopened, SidecarInstanceOpen)
	opened, err := reopened.currentUnlockKey()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, unlockKey) {
		t.Error("the pass opened some other U")
	}
	if _, err := reopened.keychainFor(testNetworkId); err != nil {
		t.Error(err)
	}
	reopened.Close()

	again := newInstanceOn(t, backend, keyStore)
	if err := again.Unlock(nil); err != nil {
		t.Fatalf("the store's wrap did not come back: %v", err)
	}
	againKey, err := again.currentUnlockKey()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(againKey, unlockKey) {
		t.Error("the restored wrap opened some other U")
	}
}

// A store that reads Locked after the pass opened U is left alone, and unlock.wrap with it.
func TestAPassUnlockLeavesALockedStoreAlone(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	if err := instance.ChangePass(nil, testPass); err != nil {
		t.Fatal(err)
	}
	instance.Close()
	before := readBackend(t, backend, unlockWrapPath)
	keyStore.answer(SidecarKeyStoreLocked)

	reopened := newInstanceOn(t, backend, keyStore)
	if err := reopened.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	requireState(t, reopened, SidecarInstanceOpen)
	if !bytes.Equal(before, readBackend(t, backend, unlockWrapPath)) {
		t.Error("unlock.wrap changed in front of a locked store")
	}
}

// A lost store with no pass wrap has only the person left.
func TestLostWithNoPassWrapStaysLost(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	instance.Close()
	keyStore.lose()
	reopened := newInstanceOn(t, backend, keyStore)
	requireError(t, reopened.Unlock(testPass), ErrSidecarKeystoreLost)
	requireState(t, reopened, SidecarInstanceLost)
}

// W with nothing it wraps is a loss of U, whatever the store says about W.
func TestALostUnlockWrapIsLost(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	instance.Close()
	if err := backend.Remove(unlockWrapPath); err != nil {
		t.Fatal(err)
	}
	before := backendSnapshot(t, backend)
	reopened := newInstanceOn(t, backend, keyStore)
	requireError(t, reopened.Unlock(nil), ErrSidecarKeystoreLost)
	requireState(t, reopened, SidecarInstanceLost)
	requireSameBackend(t, before, backend)
}

// The person's confirmation is the one way past a loss, and only past a loss.
func TestConfirmNewDeviceStartsOver(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	instance.Close()
	keyStore.lose()
	reopened := newInstanceOn(t, backend, keyStore)
	requireError(t, reopened.Unlock(nil), ErrSidecarKeystoreLost)

	if err := reopened.ConfirmNewDevice(); err != nil {
		t.Fatal(err)
	}
	requireState(t, reopened, SidecarInstanceLocked)
	if len(reopened.Networks()) != 0 {
		t.Errorf("networks %+v", reopened.Networks())
	}
	if err := reopened.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	requireState(t, reopened, SidecarInstanceOpen)
	if _, err := reopened.createKeychain(testNetworkId); err != nil {
		t.Errorf("the network's next enrollment: %v", err)
	}
}

func TestConfirmNewDeviceRefusesEverythingButALoss(t *testing.T) {
	for _, status := range []SidecarKeyStoreStatus{SidecarKeyStoreLocked, SidecarKeyStoreFailed} {
		instance, backend, keyStore := enrolledInstance(t)
		instance.Close()
		before := backendSnapshot(t, backend)
		keyStore.answer(status)
		reopened := newInstanceOn(t, backend, keyStore)
		reopened.Unlock(nil)
		if err := reopened.ConfirmNewDevice(); err == nil {
			t.Errorf("status %d: confirmed", status)
		}
		requireSameBackend(t, before, backend)
	}

	instance, backend, _ := enrolledInstance(t)
	before := backendSnapshot(t, backend)
	if err := instance.ConfirmNewDevice(); err == nil {
		t.Error("confirmed on an open instance")
	}
	requireSameBackend(t, before, backend)
}

// An item left behind by the old instance id cannot be taken for the new one's.
func TestAStaleItemCannotShadowANewInstance(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	instance.Close()
	if err := backend.Remove(unlockWrapPath); err != nil {
		t.Fatal(err)
	}
	reopened := newInstanceOn(t, backend, keyStore)
	requireError(t, reopened.Unlock(nil), ErrSidecarKeystoreLost)
	if err := reopened.ConfirmNewDevice(); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Unlock(nil); err != nil {
		t.Fatalf("the old item stood in the way: %v", err)
	}
}

func TestConfirmNewNetworkDeviceClearsOnlyThatNetwork(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	enrollTestNetwork(t, instance, otherTestNetworkId)
	instance.Close()
	if err := backend.Remove(keychainWrapPath(testNetworkId)); err != nil {
		t.Fatal(err)
	}
	reopened := newInstanceOn(t, backend, keyStore)
	if err := reopened.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	if err := reopened.ConfirmNewNetworkDevice(testNetworkId); err != nil {
		t.Fatal(err)
	}
	if networks := reopened.Networks(); len(networks) != 1 || networks[0].NetworkId != otherTestNetworkId {
		t.Errorf("networks %+v", networks)
	}
	if _, err := reopened.createKeychain(testNetworkId); err != nil {
		t.Errorf("the network's next enrollment: %v", err)
	}
	if _, err := reopened.keychainFor(otherTestNetworkId); err != nil {
		t.Errorf("the other network: %v", err)
	}
}

func TestConfirmNewNetworkDeviceRefusesAHealthyNetwork(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	before := backendSnapshot(t, backend)
	if err := instance.ConfirmNewNetworkDevice(testNetworkId); err == nil {
		t.Error("confirmed a healthy network")
	}
	requireSameBackend(t, before, backend)
}

// §5.9: R_n only at n's first enrollment, and never when an id is recorded for n.
func TestARootIsCreatedOnceAndKept(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	wrap := readBackend(t, backend, keychainWrapPath(testNetworkId))
	if _, err := instance.createKeychain(testNetworkId); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wrap, readBackend(t, backend, keychainWrapPath(testNetworkId))) {
		t.Error("a second enrollment replaced R_n")
	}
}

// An enrollment killed before it recorded the network finds its root still there, and uses it.
func TestAnInterruptedEnrollmentKeepsItsRoot(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	keyStore := newFakeKeyStore()
	instance := newInstanceOn(t, backend, keyStore)
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := instance.createKeychain(testNetworkId); err != nil {
		t.Fatal(err)
	}
	wrap := readBackend(t, backend, keychainWrapPath(testNetworkId))
	instance.Close()

	reopened := newInstanceOn(t, backend, keyStore)
	if err := reopened.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	opened, err := reopened.createKeychain(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wrap, readBackend(t, backend, keychainWrapPath(testNetworkId))) {
		t.Error("the root changed")
	}
	if names, err := opened.secrets("identity").List(""); err != nil || len(names) != 0 {
		t.Errorf("names %v, err %v", names, err)
	}
}

// A network nobody enrolled is nothing to open, and not a loss.
func TestAnUnknownNetworkIsAbsent(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	if _, err := instance.keychainFor(otherTestNetworkId); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Errorf("err %v", err)
	}
}

// Owner decision 23: one U opens every network, so one person with several memberships types one pass.
func TestOneUnlockOpensEveryNetwork(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	enrollTestNetwork(t, instance, otherTestNetworkId)
	if err := instance.ChangePass(nil, testPass); err != nil {
		t.Fatal(err)
	}
	instance.Close()
	keyStore.answer(SidecarKeyStoreLocked)

	reopened := newInstanceOn(t, backend, keyStore)
	if err := reopened.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	for _, networkId := range []Id{testNetworkId, otherTestNetworkId} {
		if _, err := reopened.keychainFor(networkId); err != nil {
			t.Errorf("%s: %v", networkId, err)
		}
	}
}

// A pass-only host (Linux headless, §5.9) makes U from the first pass it gets.
func TestPassOnlyCreatesUFromThePass(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	instance := newInstanceOn(t, backend, nil)
	requireError(t, instance.Unlock(nil), ErrSidecarStoreLocked)
	requireSameBackend(t, map[string][]byte{}, backend)

	if err := instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	wrap, err := instance.readUnlockWrap()
	if err != nil {
		t.Fatal(err)
	}
	if wrap.store != nil || wrap.pass == nil {
		t.Errorf("wrap %+v", wrap)
	}
	enrollTestNetwork(t, instance, testNetworkId)
	instance.Close()

	reopened := newInstanceOn(t, backend, nil)
	requireError(t, reopened.Unlock(nil), ErrSidecarStoreLocked)
	requireState(t, reopened, SidecarInstanceLocked)
	requireError(t, reopened.Unlock([]byte("synthetic wrong pass")), ErrSidecarPassRefused)
	requireState(t, reopened, SidecarInstanceLocked)
	if err := reopened.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.keychainFor(testNetworkId); err != nil {
		t.Error(err)
	}
}

func TestPassOnlyWithNoWrapAndARecordIsLost(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	instance := newInstanceOn(t, backend, nil)
	if err := instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	enrollTestNetwork(t, instance, testNetworkId)
	instance.Close()
	if err := backend.Remove(unlockWrapPath); err != nil {
		t.Fatal(err)
	}
	reopened := newInstanceOn(t, backend, nil)
	requireError(t, reopened.Unlock(testPass), ErrSidecarKeystoreLost)
}

// A first unlock given a pass wraps U both ways.
func TestAFirstUnlockWithAPassWrapsUBothWays(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	keyStore := newFakeKeyStore()
	instance := newInstanceOn(t, backend, keyStore)
	if err := instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	wrap, err := instance.readUnlockWrap()
	if err != nil {
		t.Fatal(err)
	}
	if wrap.store == nil || wrap.pass == nil {
		t.Errorf("wrap %+v", wrap)
	}
}

func TestAWrongPassLeavesTheStateAlone(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	if err := instance.ChangePass(nil, testPass); err != nil {
		t.Fatal(err)
	}
	instance.Close()

	reopened := newInstanceOn(t, backend, keyStore)
	requireError(t, reopened.Unlock([]byte("synthetic wrong pass")), ErrSidecarPassRefused)
	requireState(t, reopened, SidecarInstanceLocked)
	if _, err := reopened.currentUnlockKey(); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Errorf("err %v", err)
	}
}

// §5.4's limit: 5 per 10 min, whatever the pass, and it survives a restart, since a limit a restart
// resets limits nothing.
func TestPassAttemptsAreLimitedAndPersisted(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	settings := cheapKeychainSettings()
	settings.KeychainSettings.AutoLockTimeout = 0
	clock := newTestClock()
	instance := openTestInstance(t, backend, nil, settings, clock)
	if err := instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	instance.Close()

	wrong := []byte("synthetic wrong pass")
	first := openTestInstance(t, backend, nil, settings, clock)
	for i := 0; i < 3; i += 1 {
		requireError(t, first.Unlock(wrong), ErrSidecarPassRefused)
		clock.advance(time.Second)
	}
	first.Close()
	second := openTestInstance(t, backend, nil, settings, clock)
	for i := 0; i < 2; i += 1 {
		requireError(t, second.Unlock(wrong), ErrSidecarPassRefused)
		clock.advance(time.Second)
	}
	requireError(t, second.Unlock(wrong), ErrSidecarPassLimited)
	requireError(t, second.Unlock(testPass), ErrSidecarPassLimited)
	requireState(t, second, SidecarInstanceLocked)

	// the window slides past the first attempt, and no further
	clock.advance(10*time.Minute - 6*time.Second)
	requireError(t, second.Unlock(testPass), ErrSidecarPassLimited)
	clock.advance(1 * time.Second)
	if err := second.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	requireState(t, second, SidecarInstanceOpen)
}

// A right pass clears the count, so a person's typos do not add up across days of use.
func TestARightPassClearsTheAttempts(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	instance := newInstanceOn(t, backend, nil)
	if err := instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	instance.Close()
	reopened := newInstanceOn(t, backend, nil)
	requireError(t, reopened.Unlock([]byte("synthetic wrong pass")), ErrSidecarPassRefused)
	if err := reopened.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	document, err := decodeStateDocument(readBackend(t, backend, stateJsonPath))
	if err != nil {
		t.Fatal(err)
	}
	if len(document.PassAttemptMillis) != 0 {
		t.Errorf("attempts %v", document.PassAttemptMillis)
	}
}

// A clock stepped back does not free an attempt.
func TestABackwardClockFreesNoAttempt(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	settings := cheapKeychainSettings()
	settings.KeychainSettings.AutoLockTimeout = 0
	clock := newTestClock()
	instance := openTestInstance(t, backend, nil, settings, clock)
	if err := instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	instance.Close()
	reopened := openTestInstance(t, backend, nil, settings, clock)
	wrong := []byte("synthetic wrong pass")
	for i := 0; i < 5; i += 1 {
		requireError(t, reopened.Unlock(wrong), ErrSidecarPassRefused)
	}
	clock.advance(-24 * time.Hour)
	requireError(t, reopened.Unlock(testPass), ErrSidecarPassLimited)
}

// If the count cannot reach the disk, the guess does not run.
func TestAnAttemptThatCannotBeCountedIsRefused(t *testing.T) {
	world := newCrashWorld(t)
	instance := world.open(nil)
	if err := instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	instance.Close()
	reopened := world.open(nil)
	world.dieAtNextStep()
	err := reopened.Unlock(testPass)
	if err == nil || errors.Is(err, ErrSidecarPassRefused) {
		t.Errorf("err %v", err)
	}
	requireState(t, reopened, SidecarInstanceLocked)
}

// §5.9: a pass change rewraps U only, so nothing but unlock.wrap changes, and sidecar.json for its count.
func TestChangePassRewrapsUOnly(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	if err := instance.ChangePass(nil, testPass); err != nil {
		t.Fatal(err)
	}
	unlockKey, err := instance.currentUnlockKey()
	if err != nil {
		t.Fatal(err)
	}
	before := backendSnapshot(t, backend)
	held := keyStore.snapshot()

	next := []byte("synthetic next pass")
	if err := instance.ChangePass(testPass, next); err != nil {
		t.Fatal(err)
	}
	after := backendSnapshot(t, backend)
	for path, content := range before {
		if path != unlockWrapPath && path != stateJsonPath && !bytes.Equal(content, after[path]) {
			t.Errorf("%s changed", path)
		}
	}
	if bytes.Equal(before[unlockWrapPath], after[unlockWrapPath]) {
		t.Error("unlock.wrap did not change")
	}
	for name, value := range keyStore.snapshot() {
		if !bytes.Equal(held[name], value) {
			t.Errorf("%s changed", name)
		}
	}
	instance.Close()

	keyStore.answer(SidecarKeyStoreLocked)
	reopened := newInstanceOn(t, backend, keyStore)
	requireError(t, reopened.Unlock(testPass), ErrSidecarPassRefused)
	if err := reopened.Unlock(next); err != nil {
		t.Fatal(err)
	}
	opened, err := reopened.currentUnlockKey()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, unlockKey) {
		t.Error("U changed")
	}
}

func TestChangePassRefusesTheWrongPass(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	if err := instance.ChangePass(nil, testPass); err != nil {
		t.Fatal(err)
	}
	before := readBackend(t, backend, unlockWrapPath)
	requireError(t, instance.ChangePass([]byte("synthetic wrong pass"), []byte("synthetic next")), ErrSidecarPassRefused)
	requireError(t, instance.ChangePass(nil, []byte("synthetic next")), ErrSidecarPassRefused)
	if !bytes.Equal(before, readBackend(t, backend, unlockWrapPath)) {
		t.Error("unlock.wrap changed")
	}
}

func TestChangePassCountsItsAttempts(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	if err := instance.ChangePass(nil, testPass); err != nil {
		t.Fatal(err)
	}
	wrong := []byte("synthetic wrong pass")
	for i := 0; i < 5; i += 1 {
		requireError(t, instance.ChangePass(wrong, testPass), ErrSidecarPassRefused)
	}
	requireError(t, instance.ChangePass(testPass, []byte("synthetic next")), ErrSidecarPassLimited)
}

func TestChangePassNeedsAnOpenKeychain(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	instance.Lock()
	requireError(t, instance.ChangePass(nil, testPass), ErrSidecarStoreLocked)
}

func TestChangePassMayDropThePassButNotTheLastWrap(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	if err := instance.ChangePass(nil, testPass); err != nil {
		t.Fatal(err)
	}
	if err := instance.ChangePass(testPass, nil); err != nil {
		t.Fatal(err)
	}
	wrap, err := instance.readUnlockWrap()
	if err != nil {
		t.Fatal(err)
	}
	if wrap.pass != nil || wrap.store == nil {
		t.Errorf("wrap %+v", wrap)
	}
	instance.Close()
	reopened := newInstanceOn(t, backend, keyStore)
	if err := reopened.Unlock(nil); err != nil {
		t.Fatal(err)
	}

	passOnly := newInstanceOn(t, NewSidecarMemoryBackend(), nil)
	if err := passOnly.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	requireError(t, passOnly.ChangePass(testPass, nil), ErrSidecarPassRefused)
}

// The Argon2id parameters come from the file: a wrap made at one cost opens under settings at another,
// which is what lets settings change.
func TestOpeningReadsItsOwnPassParameters(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	settings := cheapKeychainSettings()
	settings.KeychainSettings.AutoLockTimeout = 0
	instance := openTestInstance(t, backend, nil, settings, newTestClock())
	if err := instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	instance.Close()

	raised := cheapKeychainSettings()
	raised.KeychainSettings.AutoLockTimeout = 0
	raised.KeychainSettings.PassMemoryByteCount = 128 * 1024
	raised.KeychainSettings.PassIterationCount = 2
	reopened := openTestInstance(t, backend, nil, raised, newTestClock())
	if err := reopened.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
}

// §5.4's default cost is what a new wrap actually carries.
func TestANewPassWrapCarriesTheSettingsCost(t *testing.T) {
	settings := DefaultSidecarSettings().KeychainSettings
	pass, err := newUnlockPassWrap(bytes.Repeat([]byte{1}, localKeyByteCount), 1, testPass, settings, bytes.NewReader(make([]byte, 64)))
	if err != nil {
		t.Fatal(err)
	}
	if pass.memoryKibiCount != 64*1024 || pass.iterationCount != 3 || pass.threadCount != 4 {
		t.Errorf("cost %d KiB, t=%d, p=%d", pass.memoryKibiCount, pass.iterationCount, pass.threadCount)
	}
}

// A setting no decoder would take back is refused before a wrap could lock a person out.
func TestAPassCostPastTheFormatIsRefused(t *testing.T) {
	for _, adjust := range []func(settings *SidecarKeychainSettings){
		func(settings *SidecarKeychainSettings) { settings.PassMemoryByteCount = 1 },
		func(settings *SidecarKeychainSettings) { settings.PassMemoryByteCount = 8 * 1024 * 1024 * 1024 },
		func(settings *SidecarKeychainSettings) { settings.PassIterationCount = passMaxIterationCount + 1 },
		func(settings *SidecarKeychainSettings) { settings.PassThreadCount = 256 },
	} {
		settings := *DefaultSidecarSettings().KeychainSettings
		adjust(&settings)
		_, err := newUnlockPassWrap(bytes.Repeat([]byte{1}, localKeyByteCount), 1, testPass, &settings, bytes.NewReader(make([]byte, 64)))
		requireError(t, err, errInvalidSettings)
	}
}

// §5.9: not secret, and only what the design lists.
func TestSidecarJsonHoldsNothingSecret(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	if err := instance.ChangePass(nil, testPass); err != nil {
		t.Fatal(err)
	}
	unlockKey, err := instance.currentUnlockKey()
	if err != nil {
		t.Fatal(err)
	}
	encoded := readBackend(t, backend, stateJsonPath)
	if bytes.Contains(encoded, unlockKey) || bytes.Contains(encoded, testPass) {
		t.Error("sidecar.json holds a secret")
	}
	fields := map[string]any{}
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for name := range fields {
		switch name {
		case "version", "instance_id", "machine_id_hash", "urls", "networks", "pass_attempt_millis":
		default:
			t.Errorf("field %s", name)
		}
	}
}

func TestUrlsReachSidecarJson(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	if urls := instance.currentDocument().Urls; urls.ApiUrl != "https://api.example" || urls.DnsUrl != "https://dns.example" {
		t.Errorf("urls %+v", urls)
	}
}

func TestStateDocumentRefusesWhatIsNotOne(t *testing.T) {
	id := NewId()
	good, err := (&sidecarStateDocument{
		Version:    stateJsonVersion,
		InstanceId: id,
		Networks: []SidecarNetworkRecord{
			{NetworkId: id, ClientId: id, SidecarId: id, ConnectInstanceId: id},
		},
	}).encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeStateDocument(good); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name    string
		encoded string
	}{
		{name: "empty", encoded: ""},
		{name: "null", encoded: "null"},
		{name: "not an object", encoded: "[]"},
		{name: "a version from later", encoded: strings.Replace(string(good), `"version": 1`, `"version": 2`, 1)},
		{name: "no id", encoded: `{"version":1,"networks":[]}`},
		{name: "a field unknown here", encoded: strings.Replace(string(good), `"version": 1`, `"version": 1, "surprise": 1`, 1)},
		{name: "two documents", encoded: string(good) + string(good)},
		{name: "a record with no client", encoded: strings.Replace(string(good), `"client_id": "`+id.String()+`"`, `"client_id": "00000000-0000-0000-0000-000000000000"`, 1)},
	} {
		if _, err := decodeStateDocument([]byte(c.encoded)); !errors.Is(err, ErrSidecarStoreFailed) {
			t.Errorf("%s: err %v", c.name, err)
		}
	}
	twice := strings.Replace(string(good), `"networks": [`, `"networks": [{"network_id": "`+id.String()+`", "client_id": "`+id.String()+`", "sidecar_id": "`+id.String()+`", "connect_instance_id": "`+id.String()+`"},`, 1)
	if _, err := decodeStateDocument([]byte(twice)); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("a network listed twice: %v", err)
	}
}

// Salted with the instance id, so two instances on one machine do not correlate.
func TestMachineIdHashIsSaltedByTheInstance(t *testing.T) {
	machineId := []byte("synthetic machine")
	first := stateMachineIdHash(Id{1}, machineId)
	second := stateMachineIdHash(Id{2}, machineId)
	if first == second || first == "" {
		t.Errorf("hashes %q, %q", first, second)
	}
	if bytes.Contains([]byte(first), machineId) {
		t.Error("the hash holds the id")
	}
	if stateMachineIdHash(Id{1}, nil) != "" {
		t.Error("no machine id still hashed")
	}
}

// An instance over backend with machineId, unlocked.
func openOnMachine(t *testing.T, backend SidecarStoreBackend, keyStore SidecarKeyStore, machineId []byte) *SidecarInstance {
	t.Helper()
	settings := cheapKeychainSettings()
	settings.KeychainSettings.AutoLockTimeout = 0
	clock := newTestClock()
	instance, err := newSidecarInstance(
		t.Context(),
		&SidecarInstanceArgs{Backend: backend, KeyStore: keyStore, MachineId: machineId, Settings: settings},
		clock.now,
		clock.after,
		bytes.NewReader(bytes.Repeat([]byte{0x5a}, 4096)),
	)
	if err != nil {
		t.Fatal(err)
	}
	return instance
}

func TestAStateCopiedToAnotherMachineReadsRestored(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	keyStore := newFakeKeyStore()
	instance := openOnMachine(t, backend, keyStore, []byte("synthetic machine a"))
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	if instance.Restored() {
		t.Error("restored on its own machine")
	}
	instance.Close()

	same := openOnMachine(t, backend, keyStore, []byte("synthetic machine a"))
	if same.Restored() {
		t.Error("restored on reopening")
	}
	same.Close()

	copied := openOnMachine(t, backend, keyStore, []byte("synthetic machine b"))
	if !copied.Restored() {
		t.Fatal("a copy went unnoticed")
	}
	// `--replace` accepts it, and it stays accepted
	if err := copied.AcceptRestored(); err != nil {
		t.Fatal(err)
	}
	if copied.Restored() {
		t.Error("still restored")
	}
	copied.Close()
	accepted := openOnMachine(t, backend, keyStore, []byte("synthetic machine b"))
	if accepted.Restored() {
		t.Error("restored after it was accepted")
	}
	accepted.Close()
}

// A host with no machine id can tell nothing, so it cries nothing.
func TestNoMachineIdReadsNothingRestored(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	keyStore := newFakeKeyStore()
	instance := openOnMachine(t, backend, keyStore, []byte("synthetic machine a"))
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	instance.Close()
	reopened := openOnMachine(t, backend, keyStore, nil)
	defer reopened.Close()
	if reopened.Restored() {
		t.Error("restored with nothing to compare")
	}
}

func TestRecordNetworkRefusesAMissingId(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	id := NewId()
	for _, record := range []SidecarNetworkRecord{
		{ClientId: id, SidecarId: id, ConnectInstanceId: id},
		{NetworkId: id, SidecarId: id, ConnectInstanceId: id},
		{NetworkId: id, ClientId: id, ConnectInstanceId: id},
		{NetworkId: id, ClientId: id, SidecarId: id},
	} {
		if err := instance.RecordNetwork(record); err == nil {
			t.Errorf("record %+v taken", record)
		}
	}
}

func TestRecordNetworkReplacesItsRow(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	record := instance.Networks()[0]
	record.ClientId = NewId()
	if err := instance.RecordNetwork(record); err != nil {
		t.Fatal(err)
	}
	if networks := instance.Networks(); len(networks) != 1 || networks[0] != record {
		t.Errorf("networks %+v", networks)
	}
}

// The store a host hands over carries the instance to NewSidecar, and only that kind does.
func TestAHostsStoreLeadsBackToItsInstance(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	networkId := testNetworkId
	found, foundNetworkId, ok := sidecarInstanceOfStore(instance.Store(&networkId))
	if !ok || found != instance || *foundNetworkId != testNetworkId {
		t.Errorf("found %v, network %v, ok %v", found, foundNetworkId, ok)
	}
	if _, foundNetworkId, ok := sidecarInstanceOfStore(instance.Store(nil)); !ok || foundNetworkId != nil {
		t.Errorf("network %v, ok %v", foundNetworkId, ok)
	}
	if _, _, ok := sidecarInstanceOfStore(nil); ok {
		t.Error("no store led somewhere")
	}
}

func TestAnInstanceNeedsItsArgs(t *testing.T) {
	settings := cheapKeychainSettings()
	for _, args := range []*SidecarInstanceArgs{
		nil,
		{Settings: settings},
		{Backend: NewSidecarMemoryBackend()},
		{Backend: NewSidecarMemoryBackend(), Settings: &SidecarSettings{}},
	} {
		if _, err := NewSidecarInstance(t.Context(), args); !errors.Is(err, errInvalidSettings) {
			t.Errorf("args %+v: err %v", args, err)
		}
	}
	bad := cheapKeychainSettings()
	bad.KeychainSettings.PassAttemptCount = 0
	_, err := NewSidecarInstance(t.Context(), &SidecarInstanceArgs{Backend: NewSidecarMemoryBackend(), Settings: bad})
	requireError(t, err, errInvalidSettings)
}

// Auto-lock, on the reading core-types-auto-lock.md recommends: idle is no keychain use and no hold.

// Runs one instance with auto-lock on, unlocked, and its timer armed.
func autoLockInstance(t *testing.T) (*SidecarInstance, *testClock, *keychain) {
	t.Helper()
	settings := cheapKeychainSettings()
	settings.KeychainSettings.AutoLockTimeout = 10 * time.Minute
	clock := newTestClock()
	instance := openTestInstance(t, NewSidecarMemoryBackend(), newFakeKeyStore(), settings, clock)
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	opened := enrollTestNetwork(t, instance, testNetworkId)
	awaitTimer(t, clock)
	return instance, clock, opened
}

// Waits for the run loop to arm a timer, and answers it.
func awaitTimer(t *testing.T, clock *testClock) time.Duration {
	t.Helper()
	select {
	case timeout := <-clock.timerArmed:
		return timeout
	case <-t.Context().Done():
		t.Fatal("no timer armed")
		return 0
	}
}

// Fires the armed timer and waits for the loop to take it.
func fireTimer(clock *testClock) {
	clock.timerFire <- clock.now()
}

// Waits for the instance to reach state.
func awaitState(t *testing.T, instance *SidecarInstance, want SidecarInstanceState) {
	t.Helper()
	for {
		state, changed := instance.State()
		if state == want {
			return
		}
		select {
		case <-changed:
		case <-t.Context().Done():
			t.Fatalf("state stayed %s", state)
		}
	}
}

func TestAutoLockLocksAnIdleKeychain(t *testing.T) {
	instance, clock, opened := autoLockInstance(t)
	clock.advance(10 * time.Minute)
	fireTimer(clock)
	awaitState(t, instance, SidecarInstanceLocked)

	if _, err := instance.currentUnlockKey(); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Errorf("U stayed: %v", err)
	}
	if _, err := opened.secrets("identity").Get("seed"); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Errorf("a secret stayed: %v", err)
	}
	if opened.roots != nil || opened.records != nil {
		t.Error("the keychain kept its keys")
	}
}

// A use during the wait moves the lock out, and the timer rearms for what is left.
func TestAutoLockWaitsOutAKeychainInUse(t *testing.T) {
	instance, clock, opened := autoLockInstance(t)
	clock.advance(9 * time.Minute)
	if _, err := opened.secrets("identity").Get("seed"); err != nil {
		t.Fatal(err)
	}
	clock.advance(1 * time.Minute)
	fireTimer(clock)
	if remaining := awaitTimer(t, clock); remaining != 9*time.Minute {
		t.Errorf("rearmed for %v", remaining)
	}
	requireState(t, instance, SidecarInstanceOpen)
}

// A hold keeps it open with no keychain call to show for it, and the idle time runs from its end.
func TestAHoldKeepsTheKeychainOpen(t *testing.T) {
	instance, clock, _ := autoLockInstance(t)
	release := instance.Hold()
	clock.advance(1 * time.Hour)
	fireTimer(clock)
	if remaining := awaitTimer(t, clock); remaining != 10*time.Minute {
		t.Errorf("rearmed for %v", remaining)
	}
	requireState(t, instance, SidecarInstanceOpen)

	release()
	release()
	if count := instance.holdCount.Load(); count != 0 {
		t.Errorf("hold count %d", count)
	}
	fireTimer(clock)
	if remaining := awaitTimer(t, clock); remaining != 10*time.Minute {
		t.Errorf("rearmed for %v", remaining)
	}
	clock.advance(10 * time.Minute)
	fireTimer(clock)
	awaitState(t, instance, SidecarInstanceLocked)
}

func TestZeroAutoLockNeverStartsATimer(t *testing.T) {
	settings := cheapKeychainSettings()
	settings.KeychainSettings.AutoLockTimeout = 0
	clock := newTestClock()
	instance := openTestInstance(t, NewSidecarMemoryBackend(), newFakeKeyStore(), settings, clock)
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	select {
	case timeout := <-clock.timerArmed:
		t.Errorf("armed for %v", timeout)
	default:
	}
}

func TestLockDropsTheKeysAndUnlockBringsThemBack(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	opened, err := instance.keychainFor(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	instance.Lock()
	requireState(t, instance, SidecarInstanceLocked)
	if _, err := instance.keychainFor(testNetworkId); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Errorf("err %v", err)
	}
	if _, err := opened.secrets("identity").Get("seed"); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Errorf("err %v", err)
	}
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	reopened, err := instance.keychainFor(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.secrets("identity").Get("seed"); err != nil {
		t.Error(err)
	}
}

// §5.9's rule, on each name.
func TestSidecarInstanceNames(t *testing.T) {
	for _, name := range []string{"default", "a", "0", "work-2", strings.Repeat("a", 32)} {
		if !isSidecarInstanceName(name) {
			t.Errorf("%q refused", name)
		}
	}
	for _, name := range []string{"", "-a", "A", "a_b", "a/b", "..", "a b", strings.Repeat("a", 33)} {
		if isSidecarInstanceName(name) {
			t.Errorf("%q taken", name)
		}
	}
}

func TestSidecarInstanceNameTakesTheFlagThenTheEnvironment(t *testing.T) {
	t.Setenv(sidecarInstanceEnvironmentName, "")
	if name, err := SidecarInstanceName(""); err != nil || name != "default" {
		t.Errorf("name %q, err %v", name, err)
	}
	t.Setenv(sidecarInstanceEnvironmentName, "from-env")
	if name, err := SidecarInstanceName(""); err != nil || name != "from-env" {
		t.Errorf("name %q, err %v", name, err)
	}
	if name, err := SidecarInstanceName("from-flag"); err != nil || name != "from-flag" {
		t.Errorf("name %q, err %v", name, err)
	}
	if _, err := SidecarInstanceName("../escape"); err == nil {
		t.Error("a path was taken for a name")
	}
	t.Setenv(sidecarInstanceEnvironmentName, "../escape")
	if _, err := SidecarInstanceName(""); err == nil {
		t.Error("a path was taken from the environment")
	}
}

// §5.9's three rows, each read on any platform.
func TestStateDirectoryPerPlatform(t *testing.T) {
	environment := map[string]string{
		"XDG_STATE_HOME": "/synthetic/state",
		"LOCALAPPDATA":   `C:\synthetic`,
	}
	getEnvironment := func(name string) string { return environment[name] }
	getHome := func() (string, error) { return "/synthetic/home", nil }

	directory, err := sidecarStateDirectoryFor("work", "darwin", getEnvironment, getHome)
	if err != nil || !strings.HasSuffix(directory, "Library/Application Support/ur/work") {
		t.Errorf("darwin: %q, %v", directory, err)
	}
	directory, err = sidecarStateDirectoryFor("work", "linux", getEnvironment, getHome)
	if err != nil || !strings.HasPrefix(directory, "/synthetic/state") || !strings.HasSuffix(directory, "ur/work") {
		t.Errorf("linux: %q, %v", directory, err)
	}
	delete(environment, "XDG_STATE_HOME")
	directory, err = sidecarStateDirectoryFor("work", "linux", getEnvironment, getHome)
	if err != nil || !strings.Contains(directory, ".local/state/ur/work") {
		t.Errorf("linux without XDG: %q, %v", directory, err)
	}
	environment["XDG_STATE_HOME"] = "relative/path"
	directory, err = sidecarStateDirectoryFor("work", "linux", getEnvironment, getHome)
	if err != nil || !strings.Contains(directory, ".local/state/ur/work") {
		t.Errorf("linux with a relative XDG: %q, %v", directory, err)
	}
	directory, err = sidecarStateDirectoryFor("work", "windows", getEnvironment, getHome)
	if err != nil || !strings.HasPrefix(directory, `C:\synthetic`) || !strings.Contains(directory, "URnetwork") {
		t.Errorf("windows: %q, %v", directory, err)
	}
	delete(environment, "LOCALAPPDATA")
	if _, err := sidecarStateDirectoryFor("work", "windows", getEnvironment, getHome); err == nil {
		t.Error("windows with no LOCALAPPDATA")
	}
}

func TestStateDirectoryRefusesABadName(t *testing.T) {
	if _, err := SidecarStateDirectory("../escape"); err == nil {
		t.Error("taken")
	}
}
