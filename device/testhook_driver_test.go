//go:build sidecar_testhooks

// The convention end to end: a schedule's driver holds a call site in this package, though the package
// never imports the root. This is an external test, a separate consumer, so it may import sidecartest
// (connect/CODESTYLE.md:30-37).

package device_test

import (
	"testing"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/sidecartest"
)

func TestDriverHoldsADeviceBarrierAndSeesItsKeys(t *testing.T) {
	driver := sidecartest.NewBarrierDriver(nil)
	t.Cleanup(driver.Close)
	table := sidecartest.NewActorTable(sidecartest.NewFakeClock(sidecartest.DefaultClockStart()), driver)
	kinds := []string{}
	remove, err := sidecartest.InstallTestHooks(func(kind string, secret []byte) {
		kinds = append(kinds, kind)
	}, driver.Hit)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()

	const clientId = "01JDEVICETESTCLIENT"
	site := sidecartest.BarrierSite("route.pin_swap.before", clientId)
	if err := driver.Arm(site, "", 0); err != nil {
		t.Fatal(err)
	}
	swapped := false
	run := driver.Start(table.Actor(t.Context(), "deviceA"), func() error {
		device.SwapForTest(clientId, []byte("synthetic-test-key"), func() { swapped = true })
		return nil
	})

	if err := driver.AwaitHeld(t.Context(), site, ""); err != nil {
		t.Fatal(err)
	}
	if swapped {
		t.Fatal("the swap ran past a held .before barrier")
	}
	if err := driver.Release(site); err != nil {
		t.Fatal(err)
	}
	<-run.Ended()
	if !swapped {
		t.Error("the swap never ran")
	}
	if len(kinds) != 1 || kinds[0] != "K_route" {
		t.Errorf("kinds %v", kinds)
	}
	if violations := driver.Violations(); len(violations) != 0 {
		t.Errorf("the convention's own sites broke it: %v", violations)
	}
}
