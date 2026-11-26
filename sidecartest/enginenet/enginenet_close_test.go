package enginenet

// The engine world's gate cache closes at the test's end and waits for its loaders (enginenet.go's header): a test that
// ends with the gate's cold start parked at the store has that load's OnLoad run, with the close's cancel and nothing
// installed, before the cleanups registered ahead of the world run, so nothing of the gate reads the Net's stores,
// reaches its hooks or counts a load as the Net closes. Before, the cleanup closed the cache without waiting, and the
// parked load ran on past it.

import (
	"context"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

func TestEnginesCleanupWaitsForTheGatesLoad(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	t.Cleanup(cancel)
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	tier, err := net.AdmissionTier()
	if err != nil {
		t.Fatal(err)
	}
	tier.AclCompile = sidecartest.AclAdmissionCompile
	network := sidecartest.NewAdmissionNet(t, tier)
	t.Cleanup(network.Close)
	networkId := network.NetworkId()
	var engines *Engines
	// after the world's cleanups, the cache's among them, and before the network's and the Net's
	t.Cleanup(func() {
		if count, _ := engines.loads.Get(); count != 1 {
			t.Errorf("%d loads had run their OnLoad when the world's cleanups returned, want the parked one", count)
		}
		if _, status := engines.Gate().State(networkId); status == sidecar.AclGateLoaded {
			t.Error("the parked load installed: some other read took the fault plan")
		}
	})
	engines = NewEngines(t, net, nil)

	// the cold start's first read, the Genesis at proj/'s entry 0, parks at the store until its caller gives up
	fired, err := net.Faults().Add(&sidecartest.FaultPlan{
		Op:        sidecartest.FaultOpGet,
		KeyPrefix: sidecar.ConfigEntryKey(networkId, 0),
		Result:    sidecartest.Delay,
		Delay:     sidecartest.DelayInNetwork,
	})
	if err != nil {
		t.Fatal(err)
	}
	engines.Gate().Changed(networkId)
	select {
	case <-fired:
	case <-ctx.Done():
		t.Fatalf("the gate's cold start never read the store: %v", ctx.Err())
	}
	if count, _ := engines.loads.Get(); count != 0 {
		t.Fatalf("%d loads ran with the cold start parked", count)
	}
}
