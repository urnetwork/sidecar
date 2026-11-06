//go:build sidecar_testhooks

// The twin of testhook_test.go: under the tag, the same call sites reach what sidecartest installs.
// swapForTest is the convention in one function: what a linearization point in this package looks
// like.

package device

import (
	"bytes"
	"testing"
)

// A linearization point in a file named route_*.go: the step's own name, .before and .after around
// it, and an opaque id for the instance. The keys it swaps report through testHookSecret before
// their first use. The names are literals, so a schedule can match them, and no state lock is held
// across a barrier.
func swapForTest(clientId string, freshKey []byte, swap func()) {
	testHookSecret("K_route", freshKey)
	testHookBarrier("route.pin_swap.before", clientId)
	swap()
	testHookBarrier("route.pin_swap", clientId)
	testHookBarrier("route.pin_swap.after", clientId)
}

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

func TestLinearizationPointMarksEachStepInOrder(t *testing.T) {
	t.Cleanup(func() { SetTestHooks(nil) })
	var kinds []string
	var sites [][2]string
	SetTestHooks(&TestHooks{
		Secret: func(kind string, secret []byte) {
			kinds = append(kinds, kind)
		},
		Barrier: func(name string, key string) {
			sites = append(sites, [2]string{name, key})
		},
	})

	swapped := 0
	swapForTest("01JDEVICETESTCLIENT", []byte("synthetic-test-key"), func() {
		// the point itself sits between .before and the point's own barrier
		if len(sites) != 1 {
			t.Errorf("%d barriers before the swap, want .before alone", len(sites))
		}
		swapped += 1
	})

	if swapped != 1 {
		t.Errorf("swapped %d times", swapped)
	}
	if len(kinds) != 1 || kinds[0] != "K_route" {
		t.Errorf("kinds %v", kinds)
	}
	want := [][2]string{
		{"route.pin_swap.before", "01JDEVICETESTCLIENT"},
		{"route.pin_swap", "01JDEVICETESTCLIENT"},
		{"route.pin_swap.after", "01JDEVICETESTCLIENT"},
	}
	if len(sites) != len(want) {
		t.Fatalf("sites %v", sites)
	}
	for i := range want {
		if sites[i] != want[i] {
			t.Errorf("site %d: %v, want %v", i, sites[i], want[i])
		}
	}
}
