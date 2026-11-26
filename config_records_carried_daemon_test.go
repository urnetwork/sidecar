//go:build !ios_extension && !sidecar_http && !js

// The carried records in ur daemon's shape (QD-1207, QD-1424), on the follower world's hosted Sidecars: a host whose
// head source gives a ref for confirmed saves alone, as ur daemon's does, runs no general config writer, so ur admin
// settings', ur admin versioning's, ur admin directory's and ur admin scopes' filings save through the writer for
// confirmed saves, as ur bridge block's does. The hosted device lists the records a revoked device signed and files
// fresh ones in their place, the listing clearing as each lands. Before QD-1424 each filing refused there, no config
// writer running.

package sidecar_test

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// In ur daemon's shape, the owner's first device signs the network's ServiceSettings and VersioningRules, and the
// owner's hosted device revokes it as lost. The hosted device then lists both records as carried by the revoked device,
// revoked at the revocation, and files fresh settings through its writer for confirmed saves, after which only the rules
// are listed, and fresh rules, after which nothing is. ur admin directory's and ur admin scopes' filings land the same
// way, each head's ServiceSettings now signed by the hosted device, and no general writer is installed at any point.
func TestAdminFilingsInUrDaemonsShapeReplaceTheCarriedRecords(t *testing.T) {
	world := newTestCarryFollowWorld(t)
	network := world.networks[0]
	owner := network.Owner()
	rules := testRevokedSignerRules()
	network.SaveHead(func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
		current, _, err := head.ServiceSettings()
		if err != nil {
			return nil, err
		}
		settings := &protocol.ServiceSettings{}
		if current != nil {
			settings = proto.Clone(current).(*protocol.ServiceSettings)
		}
		settings.MailStrict = true
		if head, err = head.WithFile(sidecar.ConfigHeadServiceSettingsPath, network.Sign(owner, bridge.SignedType_SIGNED_SERVICE_SETTINGS, settings)); err != nil {
			return nil, err
		}
		return head.WithFile(sidecar.ConfigHeadVersioningRulesPath, network.Sign(owner, bridge.SignedType_SIGNED_VERSIONING_RULES, rules))
	})
	running := world.host(network, nil)
	client := world.standing(running, network)
	testCarryConfirmedOnly(t, client)
	ctx, cancel := context.WithTimeout(world.ctx, configFollowTestTimeout)
	defer cancel()
	listing := func(label string) []*sidecar.ConfigCarriedRecord {
		t.Helper()
		records, err := running.CarriedConfigRecords(ctx)
		if err != nil {
			t.Fatalf("%s: the listing: %v", label, err)
		}
		return records
	}
	testCarriedRecordsAre(t, "the hosted device while the first device stands", listing("before the revocation"))

	plan, err := running.PreviewDeviceRevoke(ctx, owner.SidecarId, sidecar.DeviceRevokeLost, time.Time{}, 0)
	if err != nil || plan.Signatures != 1 {
		t.Fatalf("the revocation's plan %+v: %v", plan, err)
	}
	if entry, proposalId, err := running.RevokeDevice(ctx, plan.PlanId, nil, nil); err != nil || entry == nil || proposalId != nil {
		t.Fatalf("the revocation: %v %x %v", entry, proposalId, err)
	}
	revokedAt := client.State().SidecarRow(owner.SidecarId).GetRevokedAt()
	if revokedAt == 0 {
		t.Fatal("the first device is not revoked")
	}
	revoked := func(record string) *sidecar.ConfigCarriedRecord {
		memberId := owner.MemberId
		return &sidecar.ConfigCarriedRecord{Record: record, SignerId: owner.SidecarId, MemberId: &memberId, Why: sidecar.ConfigCarriedRevoked, At: revokedAt, Role: "owner"}
	}
	testCarriedRecordsAre(t, "the hosted device after the revocation", listing("after the revocation"),
		revoked(sidecar.ConfigHeadServiceSettingsPath), revoked(sidecar.ConfigHeadVersioningRulesPath))

	on := true
	filed, err := running.SaveServiceSettings(ctx, &sidecar.ServiceSettingsChange{RecordRequired: &on}, sidecar.SidecarActConfirmed)
	if err != nil || !filed.MailStrict || !filed.RecordRequired {
		t.Fatalf("ur admin settings in ur daemon's shape filed %+v: %v", filed, err)
	}
	testCarriedRecordsAre(t, "the hosted device after its settings", listing("after the settings"), revoked(sidecar.ConfigHeadVersioningRulesPath))
	if err := running.SaveVersioningRules(ctx, rules, sidecar.SidecarActConfirmed); err != nil {
		t.Fatalf("ur admin versioning in ur daemon's shape: %v", err)
	}
	testCarriedRecordsAre(t, "the hosted device after its rules", listing("after the rules"))

	workers := protocol.DirectoryWorkersMode_DIRECTORY_WORKERS_MODE_OFF
	if _, err := running.SaveDirectoryServiceSettings(ctx, &sidecar.DirectoryServiceSettingsChange{Workers: &workers}, sidecar.SidecarActConfirmed); err != nil {
		t.Fatalf("ur admin directory in ur daemon's shape: %v", err)
	}
	if _, err := running.SaveTeamScope(ctx, &sidecar.TeamScopeBinding{Label: "crew", MemberId: owner.MemberId}, sidecar.SidecarActConfirmed); err != nil {
		t.Fatalf("ur admin scopes in ur daemon's shape: %v", err)
	}
	state := client.State()
	held, known := state.HeadSettings()
	if !known || !held.GetMailStrict() || !held.GetRecordRequired() || held.GetDirectory().GetWorkers() != workers ||
		len(held.GetTeamScopes()) != 1 || held.GetTeamScopes()[0].GetLabel() != "crew" {
		t.Fatalf("the hosted device holds the settings %v (known %t)", held, known)
	}
	if heldRules, _ := state.VersioningRules(); !proto.Equal(heldRules, rules) {
		t.Fatalf("the hosted device holds the rules %v", heldRules)
	}
	head := testCarryBaseHead(t, world, network, state)
	for _, path := range []string{sidecar.ConfigHeadServiceSettingsPath, sidecar.ConfigHeadVersioningRulesPath} {
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(head.File(path), signed); err != nil {
			t.Fatal(err)
		}
		if signerId, err := sidecar.IdFromBytes(signed.GetSignerId()); err != nil || signerId != running.Identity().SidecarId {
			t.Fatalf("the newest head's %s is %s's: %v", path, signerId, err)
		}
	}
	testCarriedRecordsAre(t, "the hosted device at the end", listing("at the end"))
	testCarryConfirmedOnly(t, client)
}
