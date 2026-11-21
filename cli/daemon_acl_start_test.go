package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/enginenet"
)

// Restart after the first base was published, before the first push lands. The signed base,
// its rule ids, the decrypted EVS head and the new follower must all describe the same starter.
func TestDaemonTeamOwnerRestartsWithItsFirstPolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*urTestTimeout)
	defer cancel()
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	settings := enginenet.DefaultEnginesSettings()
	settings.FollowBeforeExchange = true
	engines := enginenet.NewEngines(t, net, settings)
	networkId, ownerId := sidecar.NewId(), sidecar.NewId()
	engines.OpenNetwork(networkId)
	engines.Api().SetTeamOwner(networkId, sidecar.NewId(), ownerId)
	net.Fakes().Quota.SetEnforced(true)
	net.Fakes().Quota.SetLimits(connect.Id(networkId), &sidecar.QuotaLimits{
		Tier: "team", Limits: map[string]int64{"acl_rules": 5000, "acl_requests": 1},
	})
	instance, err := net.StartInstance("team-owner", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(instance.Close)
	running, err := instance.AddSidecarIn(networkId, nil)
	if err != nil {
		t.Fatal(err)
	}
	site := sidecartest.BarrierSite("api.config.appended", networkId.String())
	if err := net.Barriers().Arm(site, "", 0); err != nil {
		t.Fatal(err)
	}
	follower := startUrConfigFollower(running, sidecar.NewNoopLogger())
	if err := net.Barriers().AwaitHeld(ctx, site, ""); err != nil {
		t.Fatalf("first policy was not signed: %v (%+v)", err, follower.Status())
	}
	follower.Close()
	if err := net.Barriers().Release(site); err != nil {
		t.Fatal(err)
	}
	if err := instance.Restart(); err != nil {
		t.Fatal(err)
	}
	running = instance.Sidecar(networkId)
	follower = startUrConfigFollower(running, sidecar.NewNoopLogger())
	client, err := follower.WaitStanding(ctx)
	if err != nil {
		t.Fatalf("team owner startup: %v (%+v)", err, follower.Status())
	}
	state := client.State()
	acl, err := state.Acl()
	if err != nil || !acl.HasDocument() || state.Base().GetConfigVersion() != 1 || !bytes.Equal(state.Genesis().GetOwnerMemberId(), ownerId.Bytes()) {
		t.Fatalf("first signed policy: %v, %v", state.Base(), err)
	}
	head, err := follower.Heads().ReadConfigHead(ctx, 1, state.Base().GetConfigHeadSha256())
	if err != nil || !bytes.Equal(head.File(sidecar.ConfigHeadPolicyPath), sidecar.AclTeamStartDocument()) {
		t.Fatalf("verified first head: %v", err)
	}
	if reads := engines.Api().RouteCount("GET /sidecar/limits"); reads != 1 {
		t.Fatalf("prepared a second starter after restart: %d limit reads", reads)
	}
}
