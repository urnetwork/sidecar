//go:build sidecar_testhooks

// The twin of testhook_test.go: under the tag, the same call sites reach what sidecartest installs.

package sidecar

import (
	"bytes"
	"testing"
)

func TestHookSecretHandsTheSinkItsOwnCopy(t *testing.T) {
	t.Cleanup(func() { SetTestHooks(nil) })
	var hookedKind string
	var hookedSecret []byte
	SetTestHooks(&TestHooks{
		Secret: func(kind string, secret []byte) {
			hookedKind = kind
			hookedSecret = secret
		},
	})

	secret := []byte("synthetic-test-key")
	testHookSecret("K_test", secret)
	// the caller zeroing its key must not blank what the harness scans for
	clear(secret)

	if hookedKind != "K_test" {
		t.Errorf("kind %q", hookedKind)
	}
	if !bytes.Equal(hookedSecret, []byte("synthetic-test-key")) {
		t.Errorf("secret %q", hookedSecret)
	}
}

func TestHookBarrierHoldsTheCallerUntilReleased(t *testing.T) {
	t.Cleanup(func() { SetTestHooks(nil) })
	reached := make(chan [2]string)
	release := make(chan struct{})
	SetTestHooks(&TestHooks{
		Barrier: func(name string, key string) {
			reached <- [2]string{name, key}
			<-release
		},
	})

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		testHookBarrier("test.step", "test-key")
	}()

	if site := <-reached; site != [2]string{"test.step", "test-key"} {
		t.Errorf("reached %v", site)
	}
	select {
	case <-returned:
		t.Fatal("returned while the barrier was held")
	default:
	}
	close(release)
	<-returned
}

func TestHooksDoNothingUntilInstalled(t *testing.T) {
	t.Cleanup(func() { SetTestHooks(nil) })
	for _, hooks := range []*TestHooks{nil, {}} {
		SetTestHooks(hooks)
		testHookSecret("K_test", []byte("synthetic-test-key"))
		testHookBarrier("test.step", "test-key")
	}
}

func TestExportedEntriesReachTheHooks(t *testing.T) {
	t.Cleanup(func() { SetTestHooks(nil) })
	var hookedKinds []string
	var hookedNames []string
	SetTestHooks(&TestHooks{
		Secret: func(kind string, secret []byte) {
			hookedKinds = append(hookedKinds, kind)
		},
		Barrier: func(name string, key string) {
			hookedNames = append(hookedNames, name)
		},
	})

	TestHookSecret("K_test", []byte("synthetic-test-key"))
	TestHookBarrier("test.step", "test-key")

	if len(hookedKinds) != 1 || hookedKinds[0] != "K_test" {
		t.Errorf("kinds %v", hookedKinds)
	}
	if len(hookedNames) != 1 || hookedNames[0] != "test.step" {
		t.Errorf("names %v", hookedNames)
	}
}
