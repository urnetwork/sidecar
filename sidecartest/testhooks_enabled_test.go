//go:build sidecar_testhooks

package sidecartest

import (
	"bytes"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar"
)

func TestInstalledHooksReachTheDriverFromTheRoot(t *testing.T) {
	driver, table := newBarrierFixture(t, nil)
	remove, err := InstallTestHooks(nil, driver.Hit)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	if err := driver.Arm("evs.head_cas.before", "", 0); err != nil {
		t.Fatal(err)
	}

	stepsDone := 0
	run := driver.Start(table.Actor(t.Context(), "writerA"), func() error {
		sidecar.TestHookBarrier("evs.head_cas.before", "01JTESTREPO")
		stepsDone += 1
		return nil
	})
	if err := driver.AwaitHeld(t.Context(), "evs.head_cas.before", "writerA"); err != nil {
		t.Fatal(err)
	}
	if stepsDone != 0 {
		t.Fatal("the hook did not hold its caller")
	}
	if err := driver.Release("evs.head_cas.before"); err != nil {
		t.Fatal(err)
	}
	awaitEnded(t, run)
	if stepsDone != 1 {
		t.Errorf("%d steps", stepsDone)
	}
}

func TestInstalledHooksSendKeysToTheSink(t *testing.T) {
	hooked := [][]byte{}
	remove, err := InstallTestHooks(func(kind string, secret []byte) {
		hooked = append(hooked, secret)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()

	secret := []byte("synthetic-test-key")
	sidecar.TestHookSecret("K_test", secret)
	clear(secret)

	if len(hooked) != 1 || !bytes.Equal(hooked[0], []byte("synthetic-test-key")) {
		t.Errorf("hooked %q", hooked)
	}
}

func TestHooksAreOneInstallationAtATime(t *testing.T) {
	remove, err := InstallTestHooks(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InstallTestHooks(nil, nil); !errors.Is(err, ErrHooksInstalled) {
		t.Errorf("err %v", err)
	}
	remove()

	remove, err = InstallTestHooks(nil, nil)
	if err != nil {
		t.Errorf("after remove: %v", err)
		return
	}
	remove()
}
