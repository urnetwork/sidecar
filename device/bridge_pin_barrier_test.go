//go:build sidecar_testhooks

// An entry's swap is its linearization point: a pick while an edit is held before its swap sees the snapshot in
// force, whole, and the next one after the swap sees the new one, by the driver's barriers rather than by timing.

package device_test

import (
	"testing"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/sidecartest"
)

func TestPinEntrySwapIsHeldAtItsBarrier(t *testing.T) {
	clock, settings := bridgePinTestSettings(1024)
	driver := sidecartest.NewBarrierDriver(nil)
	t.Cleanup(driver.Close)
	actors := sidecartest.NewActorTable(clock, driver)
	remove, err := sidecartest.InstallTestHooks(nil, driver.Hit)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()

	table := device.NewBridgePinTable(settings)
	entry := device.NewBridgeEntryState(bridgePinTestLinks(1, 2), settings)
	site := sidecartest.BarrierSite("bridge_pin_entry.swap.before", "")
	if err := driver.Arm(site, "", 0); err != nil {
		t.Fatal(err)
	}
	run := driver.Start(actors.Actor(t.Context(), "editor"), func() error {
		entry.Set(bridgePinTestLinks(3))
		return nil
	})
	if err := driver.AwaitHeld(t.Context(), site, ""); err != nil {
		t.Fatal(err)
	}
	for i := range 64 {
		if link := table.Pick(entry, bridgePinTestUdp(bridgePinTestSource(i), 0, false)); link != 1 && link != 2 {
			t.Fatalf("a pick before the swap took %d", link)
		}
	}
	if err := driver.Release(site); err != nil {
		t.Fatal(err)
	}
	<-run.Ended()
	for i := 100; i < 164; i += 1 {
		if link := table.Pick(entry, bridgePinTestUdp(bridgePinTestSource(i), 0, false)); link != 3 {
			t.Fatalf("a pick after the swap took %d", link)
		}
	}
	if violations := driver.Violations(); len(violations) != 0 {
		t.Errorf("the sites broke the naming rule: %v", violations)
	}
}
