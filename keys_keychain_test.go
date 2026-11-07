// keychain.ur, the wraps' formats, a network's store and D-CORE-14's separation.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"runtime"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestKeychainRecordsRoundTrip(t *testing.T) {
	nameValues := map[string][]byte{
		"a/b":      []byte("value"),
		"a/empty":  {},
		"evs/key":  bytes.Repeat([]byte{0xff}, 1000),
		"identity": []byte("synthetic"),
	}
	decoded, err := decodeKeychainRecords(encodeKeychainRecords(nameValues))
	if err != nil {
		t.Fatal(err)
	}
	if !maps.EqualFunc(nameValues, decoded, bytes.Equal) {
		t.Errorf("records %v", decoded)
	}
}

func TestKeychainRecordsEncodeInOneOrder(t *testing.T) {
	first := encodeKeychainRecords(map[string][]byte{"a": {1}, "b": {2}, "c": {3}})
	second := encodeKeychainRecords(map[string][]byte{"c": {3}, "a": {1}, "b": {2}})
	if !bytes.Equal(first, second) {
		t.Error("one set of records encoded two ways")
	}
}

func TestAnEmptyKeychainDecodes(t *testing.T) {
	decoded, err := decodeKeychainRecords(encodeKeychainRecords(map[string][]byte{}))
	if err != nil || len(decoded) != 0 {
		t.Errorf("decoded %v, err %v", decoded, err)
	}
}

func TestKeychainRecordsRefuseWhatIsNotOne(t *testing.T) {
	good := encodeKeychainRecords(map[string][]byte{"a": []byte("x"), "b": []byte("y")})
	swapped := bytes.Clone(good)
	// the two names, each one byte, trade places
	swapped[11], swapped[11+7+1] = swapped[11+7+1], swapped[11]
	emptyName := append(encodeKeychainRecords(map[string][]byte{})[:5:5], 0, 0, 0, 1, 0, 0, 0, 0, 0, 0)
	for _, c := range []struct {
		name    string
		encoded []byte
	}{
		{name: "empty", encoded: nil},
		{name: "magic", encoded: append([]byte("XXXX"), good[4:]...)},
		{name: "version", encoded: append([]byte("URKR\x02"), good[5:]...)},
		{name: "one record short", encoded: good[:len(good)-1]},
		{name: "trailing", encoded: append(bytes.Clone(good), 0)},
		{name: "out of order", encoded: swapped},
		{name: "an empty name", encoded: emptyName},
	} {
		if _, err := decodeKeychainRecords(c.encoded); !errors.Is(err, ErrSidecarStoreFailed) {
			t.Errorf("%s: err %v", c.name, err)
		}
	}
	long := strings.Repeat("a", keychainNameMaxByteCount+1)
	if _, err := decodeKeychainRecords(encodeKeychainRecords(map[string][]byte{long: {}})); err == nil {
		t.Error("a name past the bound decoded")
	}
}

// A claimed count or length of any size costs what the input holds, and no more. What a decoder would
// allocate past that is the attack, so this measures it.
func TestDecodersAllocateNoMoreThanTheirInput(t *testing.T) {
	claims := [][]byte{
		// four billion records
		[]byte("URKR\x01\xff\xff\xff\xff"),
		// a 4 GiB value
		[]byte("URKR\x01\x00\x00\x00\x01\x00\x01a\xff\xff\xff\xff"),
		// a keychain.wrap of 255 roots
		append(append([]byte("URKW\x01"), make([]byte, 16)...), 0xff),
		// an unlock.wrap at 4 TiB of memory
		append(append(append([]byte("URUW\x01"), 0, 0, 0, 0, 0, 0, 0, 1, 2), 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 1, 1), make([]byte, 16+24+48)...),
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for _, claim := range claims {
		if _, err := decodeKeychainRecords(claim); err == nil {
			t.Errorf("%x decoded", claim)
		}
		decodeKeychainWrap(claim)
		decodeUnlockWrap(claim)
	}
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; 1024*1024 < allocated {
		t.Errorf("%d bytes allocated for a few short inputs", allocated)
	}
}

// §5.9's derivation, on the design's own string, from the standard's vector-free form: a change to the
// info string changes every key, so it is pinned here and in testdata/keychain/.
func TestClassKeysAreDerivedPerClass(t *testing.T) {
	root := bytes.Repeat([]byte{0x07}, localKeyByteCount)
	first, err := deriveLocalKey(root, "evs")
	if err != nil {
		t.Fatal(err)
	}
	second, err := deriveLocalKey(root, "search")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) || bytes.Equal(first, root) {
		t.Error("two classes share a key")
	}
	if len(first) != localKeyByteCount || localKeyInfoPrefix != "urnetwork-sidecar-v1/local/" {
		t.Errorf("%d bytes under %q", len(first), localKeyInfoPrefix)
	}
}

func TestUnlockWrapRoundTrip(t *testing.T) {
	wrapped := wrappedKey{}
	wrapped.nonce[0] = 1
	wrapped.sealed[0] = 2
	for _, wrap := range []*unlockWrap{
		{generation: 1, store: &unlockStoreWrap{generation: 1, wrapped: wrapped}},
		{generation: 2, pass: &unlockPassWrap{memoryKibiCount: 64, iterationCount: 1, threadCount: 1, wrapped: wrapped}},
		{
			generation: 3,
			store:      &unlockStoreWrap{generation: 2, wrapped: wrapped},
			pass:       &unlockPassWrap{memoryKibiCount: 64, iterationCount: 1, threadCount: 1, wrapped: wrapped},
			previous:   []unlockPreviousKey{{generation: 2, wrapped: wrapped}, {generation: 1, wrapped: wrapped}},
		},
	} {
		encoded := wrap.encode()
		decoded, err := decodeUnlockWrap(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decoded.encode(), encoded) {
			t.Errorf("generation %d changed", wrap.generation)
		}
	}
}

func TestUnlockWrapRefusesWhatIsNotOne(t *testing.T) {
	wrapped := wrappedKey{}
	cost := unlockPassWrap{memoryKibiCount: 64, iterationCount: 1, threadCount: 1}
	good := &unlockWrap{generation: 2, pass: &cost}
	encoded := good.encode()

	withCost := func(adjust func(pass *unlockPassWrap)) []byte {
		pass := cost
		adjust(&pass)
		return (&unlockWrap{generation: 2, pass: &pass}).encode()
	}
	for _, c := range []struct {
		name    string
		encoded []byte
	}{
		{name: "empty", encoded: nil},
		{name: "magic", encoded: append([]byte("XXXX"), encoded[4:]...)},
		{name: "version", encoded: append([]byte("URUW\x02"), encoded[5:]...)},
		{name: "no generation", encoded: (&unlockWrap{generation: 0, pass: &cost}).encode()},
		{name: "no wrap at all", encoded: (&unlockWrap{generation: 1}).encode()},
		{name: "no store generation", encoded: (&unlockWrap{generation: 1, store: &unlockStoreWrap{wrapped: wrapped}}).encode()},
		{name: "cut", encoded: encoded[:len(encoded)-1]},
		{name: "trailing", encoded: append(bytes.Clone(encoded), 0)},
		{name: "no memory", encoded: withCost(func(pass *unlockPassWrap) { pass.memoryKibiCount = 0 })},
		{name: "memory past the bound", encoded: withCost(func(pass *unlockPassWrap) { pass.memoryKibiCount = passMaxMemoryKibiCount + 1 })},
		{name: "no iterations", encoded: withCost(func(pass *unlockPassWrap) { pass.iterationCount = 0 })},
		{name: "iterations past the bound", encoded: withCost(func(pass *unlockPassWrap) { pass.iterationCount = passMaxIterationCount + 1 })},
		{name: "no threads", encoded: withCost(func(pass *unlockPassWrap) { pass.threadCount = 0 })},
		{name: "a previous key above the current", encoded: (&unlockWrap{generation: 2, pass: &cost, previous: []unlockPreviousKey{{generation: 2}}}).encode()},
		{name: "previous keys out of order", encoded: (&unlockWrap{generation: 5, pass: &cost, previous: []unlockPreviousKey{{generation: 2}, {generation: 3}}}).encode()},
		{name: "a previous key of no generation", encoded: (&unlockWrap{generation: 5, pass: &cost, previous: []unlockPreviousKey{{generation: 0}}}).encode()},
	} {
		if _, err := decodeUnlockWrap(c.encoded); !errors.Is(err, ErrSidecarStoreFailed) {
			t.Errorf("%s: err %v", c.name, err)
		}
	}
	unknownWraps := bytes.Clone(encoded)
	unknownWraps[13] = 4
	if _, err := decodeUnlockWrap(unknownWraps); err == nil {
		t.Error("an unknown wrap decoded")
	}
	tooMany := bytes.Clone(encoded)
	tooMany[len(tooMany)-1] = unlockWrapMaxPrevious + 1
	if _, err := decodeUnlockWrap(tooMany); err == nil {
		t.Error("too many previous keys decoded")
	}
}

// Changing the stored cost, downward above all, does not get past the wrap.
func TestAPassCostChangedInTheFileOnlyFails(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	if err := instance.ChangePass(nil, testPass); err != nil {
		t.Fatal(err)
	}
	wrap, err := instance.readUnlockWrap()
	if err != nil {
		t.Fatal(err)
	}
	wrap.pass.iterationCount += 1
	putBackendFile(t, backend, unlockWrapPath, wrap.encode())
	if _, err := wrap.pass.open(testPass, wrap.generation); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("err %v", err)
	}
}

func TestKeychainWrapRoundTrip(t *testing.T) {
	wrapped := wrappedKey{}
	wrapped.nonce[0] = 1
	wrap := &keychainWrap{
		networkId: testNetworkId,
		roots: []keychainRoot{
			{generation: 2, unlockGeneration: 3, wrapped: wrapped},
			{generation: 1, unlockGeneration: 3, wrapped: wrapped},
		},
		recovery: []byte("synthetic recovery copy"),
	}
	encoded := wrap.encode()
	decoded, err := decodeKeychainWrap(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.encode(), encoded) {
		t.Error("the wrap changed")
	}
}

// §5.9: the HPKE slot exists and starts empty, which is what no current binding reads as.
func TestANewKeychainWrapHasAnEmptyRecoverySlot(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	wrap, err := instance.readKeychainWrap(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	if len(wrap.recovery) != 0 || len(wrap.roots) != 1 || wrap.roots[0].generation != 1 {
		t.Errorf("wrap %+v", wrap)
	}
}

func TestKeychainWrapRefusesWhatIsNotOne(t *testing.T) {
	root := keychainRoot{generation: 1, unlockGeneration: 1}
	good := (&keychainWrap{networkId: testNetworkId, roots: []keychainRoot{root}}).encode()
	for _, c := range []struct {
		name    string
		encoded []byte
	}{
		{name: "empty", encoded: nil},
		{name: "magic", encoded: append([]byte("XXXX"), good[4:]...)},
		{name: "version", encoded: append([]byte("URKW\x02"), good[5:]...)},
		{name: "no roots", encoded: (&keychainWrap{networkId: testNetworkId}).encode()},
		{name: "cut", encoded: good[:len(good)-1]},
		{name: "trailing", encoded: append(bytes.Clone(good), 0)},
		{name: "roots out of order", encoded: (&keychainWrap{roots: []keychainRoot{
			{generation: 1, unlockGeneration: 1},
			{generation: 2, unlockGeneration: 1},
		}}).encode()},
		{name: "one root twice", encoded: (&keychainWrap{roots: []keychainRoot{root, root}}).encode()},
		{name: "a root of no generation", encoded: (&keychainWrap{roots: []keychainRoot{{unlockGeneration: 1}}}).encode()},
		{name: "a root under no U", encoded: (&keychainWrap{roots: []keychainRoot{{generation: 1}}}).encode()},
		{name: "a recovery copy past the bound", encoded: (&keychainWrap{
			roots:    []keychainRoot{root},
			recovery: make([]byte, keychainRecoveryMaxByteCount+1),
		}).encode()},
	} {
		if _, err := decodeKeychainWrap(c.encoded); !errors.Is(err, ErrSidecarStoreFailed) {
			t.Errorf("%s: err %v", c.name, err)
		}
	}
}

// §22.5's §5 row, as far as M1 goes: every way one network's material might reach another's, with the
// whole state directory in hand. CORE-M2-05 reruns this with real recovery codes.
func TestOneNetworkCannotOpenAnother(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	enrollTestNetwork(t, instance, otherTestNetworkId)
	first, err := instance.keychainFor(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	second, err := instance.keychainFor(otherTestNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	firstRoot := bytes.Clone(first.roots[1])
	secondRoot := bytes.Clone(second.roots[1])
	if bytes.Equal(firstRoot, secondRoot) {
		t.Fatal("two networks share a root")
	}
	secret := []byte("synthetic secret of the second network")
	writeStoreFile(t, storeOf(t, instance, otherTestNetworkId, "evs"), "file", secret)
	if err := second.secrets("evs").Put("key", secret); err != nil {
		t.Fatal(err)
	}

	// the first network's root, which its recovery code will open, against the whole state: nothing it
	// derives opens the second's wrap, records or files
	wrap, err := instance.readKeychainWrap(otherTestNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	root := &wrap.roots[0]
	if _, err := root.open(otherTestNetworkId, firstRoot); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("the first root opened the second's wrap: %v", err)
	}
	additionalData := keychainRootAdditionalData(otherTestNetworkId, root.generation, root.unlockGeneration)
	if _, err := root.wrapped.open(firstRoot, additionalData); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("the first root opened the second's wrap directly: %v", err)
	}
	for _, class := range []string{"evs", keychainRecordsClass, keychainWrapClass} {
		classKey, err := deriveLocalKey(firstRoot, class)
		if err != nil {
			t.Fatal(err)
		}
		for path, content := range backendSnapshot(t, backend) {
			if !strings.HasPrefix(path, networkDirectoryPath(otherTestNetworkId)) || path == keychainWrapPath(otherTestNetworkId) {
				continue
			}
			relative := strings.TrimPrefix(path, networkDirectoryPath(otherTestNetworkId)+"/")
			if opened, err := openTestFile(content, classKey, relative); !errors.Is(err, ErrSidecarStoreFailed) {
				t.Errorf("%s opened under the first root's %s key: %d bytes, %v", relative, class, len(opened), err)
			}
		}
		if _, err := wrap.roots[0].wrapped.open(classKey, additionalData); err == nil {
			t.Error("a derived key opened the second's wrap")
		}
	}

	// a copy of the first network's own keychain.wrap, moved in, opens nothing of the second
	instance.Close()
	stolen := readBackend(t, backend, keychainWrapPath(testNetworkId))
	putBackendFile(t, backend, keychainWrapPath(otherTestNetworkId), stolen)
	reopened := newInstanceOn(t, backend, keyStore)
	if err := reopened.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.keychainFor(otherTestNetworkId); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("another network's wrap opened: %v", err)
	}
}

// A file carried into another network's directory, at the same path and class, fails there.
func TestAFileMovedBetweenNetworksFails(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	enrollTestNetwork(t, instance, otherTestNetworkId)
	writeStoreFile(t, storeOf(t, instance, testNetworkId, "evs"), "file", []byte("synthetic"))
	content := readBackend(t, backend, networkFilePath(testNetworkId, "evs/file"))
	putBackendFile(t, backend, networkFilePath(otherTestNetworkId, "evs/file"), content)

	_, err := readStoreFile(storeOf(t, instance, otherTestNetworkId, "evs"), "file")
	requireError(t, err, ErrSidecarStoreFailed)
}

// The same inside one network: a file moved or renamed fails, and so does one opened under the wrong
// class.
func TestAFileMovedInsideANetworkFails(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	store := storeOf(t, instance, testNetworkId, "evs")
	writeStoreFile(t, store, "a", []byte("synthetic a"))
	writeStoreFile(t, store, "b", []byte("synthetic b"))
	first := readBackend(t, backend, networkFilePath(testNetworkId, "evs/a"))
	second := readBackend(t, backend, networkFilePath(testNetworkId, "evs/b"))
	putBackendFile(t, backend, networkFilePath(testNetworkId, "evs/a"), second)
	putBackendFile(t, backend, networkFilePath(testNetworkId, "evs/b"), first)

	_, err := readStoreFile(store, "a")
	requireError(t, err, ErrSidecarStoreFailed)
	_, err = readStoreFile(store, "b")
	requireError(t, err, ErrSidecarStoreFailed)
}

func TestAFileOpensOnlyUnderItsClass(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	store, err := instance.Store(&testNetworkId).Directory("shared", "evs")
	if err != nil {
		t.Fatal(err)
	}
	writeStoreFile(t, store, "file", []byte("synthetic"))
	other, err := instance.Store(&testNetworkId).Directory("shared", "gkm")
	if err != nil {
		t.Fatal(err)
	}
	_, err = readStoreFile(other, "file")
	requireError(t, err, ErrSidecarStoreFailed)
}

// A file's bytes hold none of its plaintext, in the temp file included, since that is where a kill
// would leave them.
func TestNothingReachesTheMediumUnsealed(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	canary := []byte("synthetic canary of a file's plaintext")
	store := storeOf(t, instance, testNetworkId, "evs")

	recording := &recordingBackend{SidecarStoreBackend: backend}
	instance.backend = recording
	writeStoreFile(t, store, "file", bytes.Repeat(canary, 4000))
	opened, err := instance.keychainFor(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	if err := opened.secrets("evs").Put("secret", canary); err != nil {
		t.Fatal(err)
	}
	if len(recording.written) == 0 {
		t.Fatal("nothing was written")
	}
	if bytes.Contains(recording.written, canary) {
		t.Error("plaintext reached a temp file")
	}
	for path, content := range backendSnapshot(t, backend) {
		if bytes.Contains(content, canary) {
			t.Errorf("plaintext reached %s", path)
		}
	}
}

// Sees every byte handed to a temp file.
type recordingBackend struct {
	SidecarStoreBackend
	written []byte
}

// A temp file that reports what it is handed.
func (self *recordingBackend) CreateTemp() (SidecarStoreBackendFile, error) {
	file, err := self.SidecarStoreBackend.CreateTemp()
	if err != nil {
		return nil, err
	}
	return &recordingFile{SidecarStoreBackendFile: file, backend: self}, nil
}

// A temp file of a recordingBackend.
type recordingFile struct {
	SidecarStoreBackendFile
	backend *recordingBackend
}

// Keeps a copy of p for the test to scan.
func (self *recordingFile) Write(p []byte) (int, error) {
	self.backend.written = append(self.backend.written, p...)
	return self.SidecarStoreBackendFile.Write(p)
}

func TestSecretsRoundTrip(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	opened, err := instance.keychainFor(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	secrets := opened.secrets("evs")
	if _, err := secrets.Get("key"); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Errorf("err %v", err)
	}
	if err := secrets.Put("key", []byte("value")); err != nil {
		t.Fatal(err)
	}
	if err := secrets.Put("key/2", nil); err != nil {
		t.Fatal(err)
	}
	value, err := secrets.Get("key")
	if err != nil || string(value) != "value" {
		t.Errorf("value %q, err %v", value, err)
	}
	if value, err := secrets.Get("key/2"); err != nil || value == nil || len(value) != 0 {
		t.Errorf("value %v, err %v", value, err)
	}
	names, err := secrets.List("key")
	if err != nil || !slices.Equal(names, []string{"key", "key/2"}) {
		t.Errorf("names %v, err %v", names, err)
	}
	if err := secrets.Delete("key"); err != nil {
		t.Fatal(err)
	}
	if err := secrets.Delete("never there"); err != nil {
		t.Errorf("deleting nothing: %v", err)
	}
	if _, err := secrets.Get("key"); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Errorf("err %v", err)
	}
}

// What a caller holds is its own, on the way in and on the way out.
func TestSecretsAreCopied(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	opened, err := instance.keychainFor(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	secrets := opened.secrets("evs")
	value := []byte("value")
	if err := secrets.Put("key", value); err != nil {
		t.Fatal(err)
	}
	value[0] = 'X'
	got, err := secrets.Get("key")
	if err != nil || string(got) != "value" {
		t.Fatalf("got %q, err %v", got, err)
	}
	got[0] = 'Y'
	again, err := secrets.Get("key")
	if err != nil || string(again) != "value" {
		t.Errorf("got %q, err %v", again, err)
	}
}

// §5.4: a component sees its own names only.
func TestNamespacesKeepTheirNames(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	opened, err := instance.keychainFor(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	first := opened.secrets("evs")
	second := opened.secrets("evs2")
	if err := first.Put("key", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Get("key"); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Errorf("err %v", err)
	}
	if names, err := second.List(""); err != nil || len(names) != 0 {
		t.Errorf("names %v, err %v", names, err)
	}
}

func TestSecretNamesAreBounded(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	opened, err := instance.keychainFor(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	secrets := opened.secrets("evs")
	requireError(t, secrets.Put("", []byte("x")), ErrSidecarStoreName)
	requireError(t, secrets.Put(strings.Repeat("a", keychainNameMaxByteCount), []byte("x")), ErrSidecarStoreName)
	_, err = secrets.Get("")
	requireError(t, err, ErrSidecarStoreName)
	requireError(t, secrets.Delete(""), ErrSidecarStoreName)
}

// Past §18.4's budget, a Put refuses and the keychain stays as it was, in memory and on disk.
func TestAKeychainPastItsBoundRefuses(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	opened, err := instance.keychainFor(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	before := backendSnapshot(t, backend)
	err = opened.secrets("evs").Put("key", make([]byte, keychainMaxByteCount))
	requireError(t, err, ErrSidecarStoreFailed)
	requireSameBackend(t, before, backend)
	if _, err := opened.secrets("evs").Get("key"); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Errorf("the refused value is readable: %v", err)
	}
}

// A write that does not reach the disk does not reach memory either.
func TestAFailedWriteLeavesTheRecords(t *testing.T) {
	world := enrolledCrashWorld(t)
	instance := world.open(world.keyStore())
	defer instance.Close()
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	opened, err := instance.keychainFor(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	world.dieAtNextStep()
	err = opened.secrets("evs").Put("key", []byte("new value"))
	if err == nil {
		t.Fatal("a write with no medium took")
	}
	value, err := opened.secrets("evs").Get("key")
	if err != nil || string(value) != "old value" {
		t.Errorf("value %q, err %v", value, err)
	}
}

// A lock in the middle of a write stops it, and the write answers the lock.
func TestALockStopsASecretWrite(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	opened, err := instance.keychainFor(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	instance.Lock()
	requireError(t, opened.secrets("evs").Put("key", []byte("value")), ErrSidecarStoreLocked)
	requireError(t, opened.secrets("evs").Delete("key"), ErrSidecarStoreLocked)
	_, err = opened.secrets("evs").List("")
	requireError(t, err, ErrSidecarStoreLocked)
}

func TestStoreFilesRoundTrip(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	store := storeOf(t, instance, testNetworkId, "evs")
	content := sealTestPlaintext(3*sealChunkByteCount + 1)
	writeStoreFile(t, store, "a/b/file", content)
	requireStoreFile(t, store, "a/b/file", content)

	writeStoreFile(t, store, "a/b/file", []byte("replaced"))
	requireStoreFile(t, store, "a/b/file", []byte("replaced"))

	if err := store.Remove("a/b/file"); err != nil {
		t.Fatal(err)
	}
	_, err := readStoreFile(store, "a/b/file")
	requireError(t, err, ErrSidecarStoreAbsent)
	if err := store.Remove("a/b/file"); err != nil {
		t.Errorf("removing nothing: %v", err)
	}
}

// Nothing shows until Commit, and a writer dropped without one leaves what was there.
func TestAnUncommittedWriteShowsNothing(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	store := storeOf(t, instance, testNetworkId, "evs")
	writeStoreFile(t, store, "file", []byte("old"))

	writer, err := store.Create("file")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("new")); err != nil {
		t.Fatal(err)
	}
	requireStoreFile(t, store, "file", []byte("old"))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Errorf("a second close: %v", err)
	}
	requireStoreFile(t, store, "file", []byte("old"))
	if _, err := writer.Write([]byte("late")); err == nil {
		t.Error("a closed writer took bytes")
	}
	if err := writer.Commit(); err == nil {
		t.Error("a closed writer committed")
	}
}

func TestACommittedWriterIsDone(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	store := storeOf(t, instance, testNetworkId, "evs")
	writer, err := store.Create("file")
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.Write([]byte("content")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Commit(); err == nil {
		t.Error("committed twice")
	}
	if _, err := writer.Write([]byte("late")); err == nil {
		t.Error("took bytes after its commit")
	}
	requireStoreFile(t, store, "file", []byte("content"))
}

func TestStoreNamesAreClean(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	store := storeOf(t, instance, testNetworkId, "evs")
	for _, name := range []string{
		"", "/", "a/", "/a", "a//b", ".", "..", "../a", "a/../b", "a/./b", ".hidden", "a/.hidden",
		`a\b`, "a:b", "a\x00b", "a\nb", "a\x7fb", "a.", "a ", "a./b", "a /b",
	} {
		if _, err := store.Create(name); !errors.Is(err, ErrSidecarStoreName) {
			t.Errorf("Create(%q): %v", name, err)
		}
		if _, err := store.Open(name); !errors.Is(err, ErrSidecarStoreName) {
			t.Errorf("Open(%q): %v", name, err)
		}
		if err := store.Remove(name); !errors.Is(err, ErrSidecarStoreName) {
			t.Errorf("Remove(%q): %v", name, err)
		}
		if name != "" {
			if _, err := store.Directory(name, ""); !errors.Is(err, ErrSidecarStoreName) {
				t.Errorf("Directory(%q): %v", name, err)
			}
		}
	}
	for _, prefix := range []string{"../", "a/../", "/a", `a\`} {
		if _, err := store.List(prefix); !errors.Is(err, ErrSidecarStoreName) {
			t.Errorf("List(%q): %v", prefix, err)
		}
	}
	for _, name := range []string{"a", "a/b.c", "UPPER", "a-b_c", "search.state", "é"} {
		if _, err := store.Directory(name, ""); err != nil {
			t.Errorf("Directory(%q): %v", name, err)
		}
	}
}

// A component that names the keychain's own files, by any class, is refused them.
func TestTheKeychainsFilesAreNoComponents(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	before := backendSnapshot(t, backend)
	store, err := instance.Store(&testNetworkId).Directory("", "evs")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		keychainRecordsName,
		keychainWrapName,
		// the same files on a case-insensitive volume
		strings.ToUpper(keychainRecordsName),
		"Keychain.Wrap",
	} {
		if _, err := store.Create(name); !errors.Is(err, ErrSidecarStoreName) {
			t.Errorf("Create(%s): %v", name, err)
		}
		if _, err := store.Open(name); !errors.Is(err, ErrSidecarStoreName) {
			t.Errorf("Open(%s): %v", name, err)
		}
		if err := store.Remove(name); !errors.Is(err, ErrSidecarStoreName) {
			t.Errorf("Remove(%s): %v", name, err)
		}
	}
	if _, err := instance.Store(&testNetworkId).Directory("", keychainRecordsClass); !errors.Is(err, ErrSidecarStoreName) {
		t.Errorf("class %s: %v", keychainRecordsClass, err)
	}
	entries, err := store.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("entries %+v", entries)
	}
	requireSameBackend(t, before, backend)
}

// The store a host hands over names no class, so a file cannot be sealed under nothing.
func TestAStoreWithNoClassRefusesFiles(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	store := instance.Store(&testNetworkId)
	if _, err := store.Create("file"); !errors.Is(err, ErrSidecarStoreNoClass) {
		t.Errorf("err %v", err)
	}
	if _, err := store.Open("file"); !errors.Is(err, ErrSidecarStoreNoClass) {
		t.Errorf("err %v", err)
	}
	if err := store.Remove("file"); !errors.Is(err, ErrSidecarStoreNoClass) {
		t.Errorf("err %v", err)
	}
	if _, err := store.List(""); !errors.Is(err, ErrSidecarStoreNoClass) {
		t.Errorf("err %v", err)
	}
	named, err := store.Directory("evs", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := named.Create("file"); !errors.Is(err, ErrSidecarStoreNoClass) {
		t.Errorf("a directory with no class: %v", err)
	}
}

func TestDirectoryRefusesABadClass(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	for _, class := range []string{"Evs", "e/v", "-e", strings.Repeat("a", sealClassMaxByteCount+1)} {
		if _, err := instance.Store(&testNetworkId).Directory("a", class); !errors.Is(err, ErrSidecarStoreName) {
			t.Errorf("%q: %v", class, err)
		}
	}
}

// §5.9's tree: search.state sits at the network's top, under class search, and classes nest as the
// design lists them.
func TestDirectoriesFollowTheTree(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	store := instance.Store(&testNetworkId)
	searchRoot, err := store.Directory("", "search")
	if err != nil {
		t.Fatal(err)
	}
	writeStoreFile(t, searchRoot, "search.state", []byte("synthetic"))
	approvals, err := store.Directory("approvals", "approval")
	if err != nil {
		t.Fatal(err)
	}
	child, err := approvals.Directory("a/b", "")
	if err != nil {
		t.Fatal(err)
	}
	writeStoreFile(t, child, "c", []byte("synthetic"))
	for _, path := range []string{"search.state", "approvals/a/b/c"} {
		if _, err := readBackendFile(backend, networkFilePath(testNetworkId, path), 1024); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
	requireStoreFile(t, child, "c", []byte("synthetic"))
	reread, err := store.Directory("approvals/a", "approval")
	if err != nil {
		t.Fatal(err)
	}
	requireStoreFile(t, reread, "b/c", []byte("synthetic"))
}

func TestListNamesFilesInItsDirectory(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	store := storeOf(t, instance, testNetworkId, "evs")
	other := storeOf(t, instance, testNetworkId, "gkm")
	writeStoreFile(t, store, "repo/b", []byte("b"))
	writeStoreFile(t, store, "repo/a", []byte("aa"))
	writeStoreFile(t, store, "repo2", []byte("c"))
	writeStoreFile(t, other, "repo/a", []byte("d"))

	entries, err := store.List("repo/")
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, entry := range entries {
		names = append(names, entry.Name)
		if entry.ByteCount <= 0 {
			t.Errorf("%s: %d bytes", entry.Name, entry.ByteCount)
		}
	}
	if !slices.Equal(names, []string{"repo/a", "repo/b"}) {
		t.Errorf("names %v", names)
	}
	entries, err = store.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Errorf("entries %+v", entries)
	}
}

// A store over a locked instance answers the lock for every call, and writes and deletes nothing.
func TestALockedStoreAnswersLocked(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	store := storeOf(t, instance, testNetworkId, "evs")
	writeStoreFile(t, store, "file", []byte("synthetic"))
	instance.Lock()
	before := backendSnapshot(t, backend)

	_, err := store.Open("file")
	requireError(t, err, ErrSidecarStoreLocked)
	_, err = store.Create("file")
	requireError(t, err, ErrSidecarStoreLocked)
	requireError(t, store.Remove("file"), ErrSidecarStoreLocked)
	_, err = store.List("")
	requireError(t, err, ErrSidecarStoreLocked)
	requireSameBackend(t, before, backend)

	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	requireStoreFile(t, store, "file", []byte("synthetic"))
}

// A store with no network yet waits for one, whatever class it names.
func TestAStoreWithNoNetworkAnswersLocked(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	store, err := instance.Store(nil).Directory("evs", "evs")
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Create("file")
	requireError(t, err, ErrSidecarStoreLocked)
}

// A lock reaches a stream in flight: the read stops at its next chunk, and a write cannot commit.
func TestALockStopsOpenStreams(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	store := storeOf(t, instance, testNetworkId, "evs")
	writeStoreFile(t, store, "file", sealTestPlaintext(2*sealChunkByteCount+1))

	reader, err := store.Open("file")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := io.ReadFull(reader, make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	writer, err := store.Create("other")
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.Write([]byte("synthetic")); err != nil {
		t.Fatal(err)
	}

	instance.Lock()

	_, err = io.ReadAll(reader)
	requireError(t, err, ErrSidecarStoreLocked)
	requireError(t, writer.Commit(), ErrSidecarStoreLocked)

	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	_, err = readStoreFile(store, "other")
	requireError(t, err, ErrSidecarStoreAbsent)
}

// One backend, two instances' worth of names: nothing here knows the other exists, which is what keeps
// two ur instances apart.
func TestTwoInstancesHaveTheirOwnItems(t *testing.T) {
	keyStore := newFakeKeyStore()
	first := newInstanceOn(t, NewSidecarMemoryBackend(), keyStore)
	second := newInstanceOn(t, NewSidecarMemoryBackend(), keyStore)
	if err := first.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	if err := second.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	if len(keyStore.snapshot()) != 2 {
		t.Errorf("items %d", len(keyStore.snapshot()))
	}
	firstKey, err := first.currentUnlockKey()
	if err != nil {
		t.Fatal(err)
	}
	secondKey, err := second.currentUnlockKey()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstKey, secondKey) {
		t.Error("two instances share U")
	}
}

// An ephemeral sidecar writes nowhere but memory, and its keys go with it (§5.6).
func TestAnEphemeralInstanceRunsInMemory(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	keyStore := NewSidecarMemoryKeyStore()
	instance := newInstanceOn(t, backend, keyStore)
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	opened := enrollTestNetwork(t, instance, testNetworkId)
	if _, err := opened.secrets("identity").Get("seed"); err != nil {
		t.Error(err)
	}
	if status := keyStore.DeleteSecret("not there"); status != SidecarKeyStoreOk {
		t.Errorf("status %d", status)
	}
}

// Decoders answer one fixed error, so nothing of a file's content reaches a log. A secret in a
// keychain.ur or a wrap is the very input they are handed.
func TestDecodersEchoNothing(t *testing.T) {
	canary := "syntheticcanary"
	inputs := [][]byte{
		[]byte(canary),
		[]byte("URKR\x01\x00\x00\x00\x01\x00\x0f" + canary + "\x00"),
		[]byte("URKW\x01" + canary),
		[]byte("URUW\x01" + canary),
		[]byte(`{"version":1,"` + canary + `":1}`),
	}
	for _, input := range inputs {
		for _, decode := range []func(encoded []byte) error{
			func(encoded []byte) error { _, err := decodeKeychainRecords(encoded); return err },
			func(encoded []byte) error { _, err := decodeKeychainWrap(encoded); return err },
			func(encoded []byte) error { _, err := decodeUnlockWrap(encoded); return err },
			func(encoded []byte) error { _, err := decodeStateDocument(encoded); return err },
		} {
			err := decode(input)
			if err == nil {
				t.Fatalf("%q decoded", input)
			}
			if strings.Contains(err.Error(), canary) || strings.Contains(fmt.Sprintf("%+v", err), canary) {
				t.Errorf("%q: the error repeats its input: %v", input, err)
			}
		}
	}
}

// The chunk a store seals with really is the class's key, so what a test seals by hand and what the
// store seals agree: this is what lets the vectors stand for the store.
func TestTheStoreSealsWithTheClassKey(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	store := storeOf(t, instance, testNetworkId, "evs")
	writeStoreFile(t, store, "file", []byte("synthetic"))
	opened, err := instance.keychainFor(testNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	classKey, err := deriveLocalKey(opened.roots[1], "evs")
	if err != nil {
		t.Fatal(err)
	}
	content := readBackend(t, backend, networkFilePath(testNetworkId, "evs/file"))
	plaintext, err := openTestFile(content, classKey, "evs/file")
	if err != nil || string(plaintext) != "synthetic" {
		t.Errorf("plaintext %q, err %v", plaintext, err)
	}
	if _, err := chacha20poly1305.NewX(classKey); err != nil {
		t.Error(err)
	}
}
