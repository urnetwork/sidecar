//go:build sidecar_testhooks

package sidecar

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"testing"
)

// What a run shows the harness (§22.4).
type hookRecorder struct {
	stateLock sync.Mutex
	kinds     map[string]bool
	secrets   [][]byte
	barriers  map[string]bool
}

// Installs a recorder for the test's length.
func recordHooks(t *testing.T) *hookRecorder {
	t.Helper()
	recorder := &hookRecorder{kinds: map[string]bool{}, barriers: map[string]bool{}}
	SetTestHooks(&TestHooks{
		Secret: func(kind string, secret []byte) {
			recorder.stateLock.Lock()
			defer recorder.stateLock.Unlock()
			recorder.kinds[kind] = true
			recorder.secrets = append(recorder.secrets, secret)
		},
		Barrier: func(name string, key string) {
			recorder.stateLock.Lock()
			defer recorder.stateLock.Unlock()
			recorder.barriers[name] = true
		},
	})
	t.Cleanup(func() { SetTestHooks(nil) })
	return recorder
}

// Runs the whole life of a keychain under the hooks, returning the medium and the store it ended on.
func exerciseKeychain(t *testing.T) (SidecarStoreBackend, *fakeKeyStore) {
	t.Helper()
	backend := NewSidecarMemoryBackend()
	keyStore := newFakeKeyStore()
	instance := newInstanceOn(t, backend, keyStore)
	if err := instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	enrollTestNetwork(t, instance, testNetworkId)
	writeStoreFile(t, storeOf(t, instance, testNetworkId, "evs"), "file", []byte("synthetic"))
	if err := instance.RotateKeychain(context.Background(), testPass); err != nil {
		t.Fatal(err)
	}
	instance.Close()
	reopened := newInstanceOn(t, backend, keyStore)
	if err := reopened.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.keychainFor(testNetworkId); err != nil {
		t.Fatal(err)
	}
	if err := reopened.ChangePass(testPass, []byte("synthetic next pass")); err != nil {
		t.Fatal(err)
	}
	reopened.Close()
	return backend, keyStore
}

// Every key of §5.9 reaches the harness, at its creation and at each unwrap, or the privacy harness
// cannot catch it leaking.
func TestEveryLocalKeyReachesTheHook(t *testing.T) {
	recorder := recordHooks(t)
	exerciseKeychain(t)
	for _, kind := range []string{"U", "W", "K_pass", "R_n", "K_local", "K_keychain_wrap", "K_unlock_previous"} {
		if !recorder.kinds[kind] {
			t.Errorf("no %s reached the hook", kind)
		}
	}
}

// The scan the privacy harness runs (§22.7): no key the hook saw is on the medium, in any file, and W is
// in the key store and nowhere else.
func TestNoKeyReachesTheMedium(t *testing.T) {
	recorder := recordHooks(t)
	backend, keyStore := exerciseKeychain(t)
	files := backendSnapshot(t, backend)
	if len(files) == 0 {
		t.Fatal("nothing on the medium")
	}
	for _, secret := range recorder.secrets {
		if len(secret) != localKeyByteCount {
			t.Errorf("a key of %d bytes", len(secret))
		}
		for path, content := range files {
			if bytes.Contains(content, secret) {
				t.Errorf("%s holds a key", path)
			}
		}
	}
	for _, value := range keyStore.snapshot() {
		if !slices.ContainsFunc(recorder.secrets, func(secret []byte) bool { return bytes.Equal(secret, value) }) {
			t.Error("the store holds a key the hook never saw")
		}
	}
}

func TestLinearizationPointsHaveTheirBarriers(t *testing.T) {
	recorder := recordHooks(t)
	exerciseKeychain(t)
	for _, name := range []string{
		"keys.unlock.before",
		"keys.unlock.after",
		"keys.change_pass.before",
		"keys.change_pass.after",
		"keys.rotate.before",
		"keys.rotate.after",
		"keys.create_keychain.before",
		"keys.create_keychain.after",
		"keys.record_network.before",
		"keys.record_network.after",
		"keys.keychain_write.before",
		"keys.keychain_write.after",
		"state.commit.before",
		"state.commit.after",
	} {
		if !recorder.barriers[name] {
			t.Errorf("no barrier %s", name)
		}
	}
}
