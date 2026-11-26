package fault

// FS-62's gates end with their schedule (fs_acl.go's fs62AclClose): a gate's close ends its life and waits for its
// cache's loaders. Its OnLoad sends each load on loads while the gate lives, so a load nobody takes, which before waited
// for room on loads with no end and held its loader there past any close, gives up at the close, and the close returns
// with nothing of the gate running.

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A gate whose loads channel is full when a load installs: the load's OnLoad finds no room, and the gate's close ends
// that wait and returns once the loader has, sending nothing on loads.
func TestFs62AclGateCloseEndsALoadNobodyTakes(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	tier, err := net.AdmissionTier()
	if err != nil {
		t.Fatal(err)
	}
	tier.AclCompile = sidecartest.AclAdmissionCompile
	admission := sidecartest.NewAdmissionNet(t, tier)
	defer admission.Close()
	// a failure's bound only: a close that waits on the loader it should end never returns
	guard := sidecartest.DefaultBarrierDriverSettings().AwaitTimeout
	gate := newFs62AclGate(net, admission, "api")
	// ends the gate before the world and the Net on a path that fails before the close below, and nothing once that
	// close has started: a broken one never returns, and its guard has failed the test
	closing := false
	defer func() {
		if !closing {
			gate.close()
		}
	}()

	// no room on loads, so the next load's OnLoad waits for some
	for len(gate.loads) < cap(gate.loads) {
		gate.loads <- nil
	}
	installed := make(chan *sidecar.AclGateSnapshot, 1)
	removeInstall := gate.cache.AddInstallCallback(func(networkId sidecar.Id, snapshot *sidecar.AclGateSnapshot) {
		select {
		case installed <- snapshot:
		default:
		}
	})
	defer removeInstall()
	gate.cache.Changed(admission.NetworkId())
	select {
	case snapshot := <-installed:
		if !proto.Equal(snapshot.Pin, admission.Tip()) {
			t.Fatalf("the gate installed %d, the tip is %d", snapshot.Pin.GetVersion(), admission.Tip().GetVersion())
		}
	case <-time.After(guard):
		t.Fatal("the gate never installed the network")
	}

	// the install's OnLoad comes next on the loader, with no room on loads
	closing = true
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		gate.close()
	}()
	select {
	case <-closed:
	case <-time.After(guard):
		t.Fatal("the gate's close waited on a load nobody takes")
	}
	if len(gate.loads) != cap(gate.loads) {
		t.Fatalf("loads holds %d of %d after the close", len(gate.loads), cap(gate.loads))
	}
	for range cap(gate.loads) {
		if pin := <-gate.loads; pin != nil {
			t.Errorf("a load's OnLoad sent %d after the gate ended", pin.GetVersion())
		}
	}
}
