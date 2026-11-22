//go:build sidecar_testhooks

// The solver's one write a name at a time under §22.8's barriers: a wait held where it found the name's
// write under way (QD-1189).

package certsservice_test

import (
	"slices"
	"testing"

	"github.com/mholt/acmez/v3/acme"

	"github.com/urnetwork/sidecar/sidecartest"
)

// A second wait that finds the name's write under way waits for it: held there it has written nothing and
// asked about no serial, and once the write has landed and it goes on, it asks about that write's serial
// and nothing more is written.
func TestCertsDnsSolverWaitBehindAWriteUnderWayWritesNothing(t *testing.T) {
	driver := sidecartest.NewBarrierDriver(nil)
	t.Cleanup(driver.Close)
	remove, err := sidecartest.InstallTestHooks(nil, driver.Hit)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	world, gated := newTestGatedSolver(t)
	table := sidecartest.NewActorTable(world.clock, driver)
	name := "k5solver13." + testRoot
	base := testChallenge(name, "token-base", false)
	wildcard := testChallenge(name, "token-wild", true)
	for _, challenge := range []acme.Challenge{base, wildcard} {
		if err := world.solver.Present(world.ctx, challenge); err != nil {
			t.Fatal(err)
		}
	}
	first := testGo(func() error { return world.solver.Wait(world.ctx, base) })
	if values := gated.awaitWrite(t); len(values) != 2 {
		t.Fatalf("the write holds %v", values)
	}
	site := "certs.dns_write.queued"
	if err := driver.Arm(site, "", 0); err != nil {
		t.Fatal(err)
	}
	second := driver.Start(table.Actor(world.ctx, "second"), func() error { return world.solver.Wait(world.ctx, wildcard) })
	if err := driver.AwaitHeld(t.Context(), site, "second"); err != nil {
		t.Fatal(err)
	}
	if writeCount, _, readyCount := world.dns.Counts(); writeCount != 0 || readyCount != 0 {
		t.Fatalf("while the write is under way: %d writes, ready asked %d", writeCount, readyCount)
	}
	gated.letThrough(t)
	if err := testAwait(t, first); err != nil {
		t.Fatal(err)
	}
	if err := driver.Release(site); err != nil {
		t.Fatal(err)
	}
	select {
	case <-second.Ended():
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	if err := second.Err(); err != nil {
		t.Fatal(err)
	}
	if writeCount, _, _ := world.dns.Counts(); writeCount != 1 {
		t.Fatalf("writes %d", writeCount)
	}
	if serials := world.dns.ReadySerials(); !slices.Equal(serials, []uint64{1, 1}) {
		t.Fatalf("ready asked about %v", serials)
	}
}
