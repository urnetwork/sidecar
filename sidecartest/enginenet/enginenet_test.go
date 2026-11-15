// The engine world's own seams on an admission network whose log api holds: the exchange's scopes come from the gate's
// state of the token's network, and a network the gate has not loaded, a bootstrapping one before its base 1 among
// them, answers a server error and is asked for. A network's bootstrap past KF1 on these engines is the daemon's test
// (cli/daemon_clients_evs_test.go), whose key client and follower are the daemon's own.

package enginenet

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The exchange's scopes for the owner's device: refused with a server error until the gate holds the network, then
// §8's table at the gate's state, which grants the config's r and refuses a repo the state does not hold.
func TestEnginesScopesComeFromTheGatesState(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	tier, err := net.AdmissionTier()
	if err != nil {
		t.Fatal(err)
	}
	tier.AclCompile = sidecartest.AclAdmissionCompile
	network := sidecartest.NewAdmissionNet(t, tier)
	t.Cleanup(network.Close)
	engines := NewEngines(t, net, nil)
	owner := network.Owner().SidecarId
	configScope := "repo:" + network.ConfigRepoId().String() + ":r"
	unknownScope := "repo:" + sidecar.NewId().String() + ":r"
	request := &sidecartest.FakeApiScopeRequest{
		NetworkId: network.NetworkId(), SidecarId: &owner, Audience: "evs", Scopes: []string{configScope, unknownScope},
	}
	if _, err := engines.exchangeScopes(ctx, request); err == nil || errors.Is(err, sidecartest.ErrFakeApiInvalidScope) {
		t.Fatalf("scopes before the gate holds the network: %v", err)
	}
	if err := engines.Sync(ctx, network.NetworkId()); err != nil {
		t.Fatal(err)
	}
	grant, err := engines.exchangeScopes(ctx, request)
	if err != nil || !slices.Equal(grant.Scopes, []string{configScope}) || grant.ProjVersion != network.Tip().GetVersion() {
		t.Fatalf("the gate's scopes: %+v %v", grant, err)
	}
	if grant.MemberId == nil || *grant.MemberId != network.Owner().MemberId {
		t.Fatal("the grant names no member")
	}
}
