//go:build !sidecar_http && !js

// The carried records' listing (config_records_carried.go; D-TEAM-26; owner decision 699; QD-1207): a ServiceSettings or
// VersioningRules record that a config head carries under a signer who no longer stands as one who may sign it is
// listed for admins, with that signer and why, until an Owner or Admin, or for VersioningRules a Network admin, files
// another. On T2's fake api with real ConfigClients, ConfigWriters and ConfigLogs, as config_head_records_revoked_test.go
// runs them:
//
//	revoked  the owner's first device signs both records and the owner's desktop revokes it as lost: from the
//	         revocation on, before any base and at every base after, every reader lists both, a new device from the
//	         genesis and one that starts at a base past api's retention point included; the desktop files fresh
//	         settings, which clears that record alone, then fresh rules, which clears the listing
//	role     an Admin's device signs both: as a Network admin its settings are listed and its rules not, as a Member
//	         both, and once its member is removed both as revoked with the member gone; the owner's fresh records clear it
//	parked   a compromise revocation parks the device that signed both, which the listing names as parked
//	head     a head holding another record than the state, one the state lacks, or none, is refused; a rows-only reader
//	         knows no record
//
// The listing changes no verdict: each reader takes every base here, as the carry rule has it.

package sidecar_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// client's listing once it stands at api's tip, failing the test on an error.
func testCarriedListing(world *testWriterWorld, label string, client *sidecar.ConfigClient) []*sidecar.ConfigCarriedRecord {
	world.t.Helper()
	world.caughtUp(client)
	records, err := client.CarriedRecords(world.ctx)
	if err != nil {
		world.t.Fatalf("%s: the listing: %v", label, err)
	}
	return records
}

// Fails unless records are want, field by field, as their JSON says them.
func testCarriedRecordsAre(t *testing.T, label string, records []*sidecar.ConfigCarriedRecord, want ...*sidecar.ConfigCarriedRecord) {
	t.Helper()
	if want == nil {
		want = []*sidecar.ConfigCarriedRecord{}
	}
	got, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	wanted, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(wanted) {
		t.Fatalf("%s lists\n  %s\nwant\n  %s", label, got, wanted)
	}
}

// A carried record of the head path record signed by device, its member device, as the listing names it.
func testCarriedRecordOf(record string, device testWriterDevice, why string) *sidecar.ConfigCarriedRecord {
	memberId := device.memberId
	return &sidecar.ConfigCarriedRecord{Record: record, SignerId: device.sidecarId, MemberId: &memberId, Why: why}
}

// signer admits device, answering the entry's pin.
func testCarriedAdmit(world *testWriterWorld, signer testWriterDevice, device testWriterDevice) *bridge.AuthPin {
	world.t.Helper()
	pin, err := world.api.AppendStatement(world.ctx, world.networkId, world.statement(signer, bridge.SignedType_SIGNED_SIDECAR_ADMIT, &protocol.SidecarAdmit{
		Header:            world.header(),
		NetworkId:         world.networkId.Bytes(),
		SidecarId:         device.sidecarId.Bytes(),
		IdentityPublicKey: device.key.Public().(ed25519.PublicKey),
		IdentityAlg:       "ed25519",
		MemberId:          device.memberId.Bytes(),
	}))
	if err != nil {
		world.t.Fatalf("admitting %s: %v", device.sidecarId, err)
	}
	return pin
}

// A publish bounded so a base no follower takes fails the test rather than hanging it.
func testCarriedPublish(world *testWriterWorld, label string, publish func(ctx context.Context) (*bridge.AuthPin, error)) *bridge.AuthPin {
	world.t.Helper()
	ctx, cancel := context.WithTimeout(world.ctx, 30*time.Second)
	defer cancel()
	pin, err := publish(ctx)
	if err != nil || pin == nil {
		world.t.Fatalf("%s landed at %v: %v", label, pin, err)
	}
	return pin
}

// The owner's first device signs the network's ServiceSettings and VersioningRules and the owner's desktop revokes it
// as lost. From the revocation on every reader lists both records, signed by the revoked device of the owner's member,
// revoked at the revocation's position: before any base, and at the desktop's next fold, which carries both, at the
// desktop's own follower, a new device from the genesis and one that starts at that base past api's retention point,
// which took them unjudged. The desktop then files fresh settings under its own signature, and only the rules stay
// listed; then fresh rules, and nothing does.
func TestCarriedRecordsListARevokedSignersRecordsUntilAnAdminFilesAnother(t *testing.T) {
	// its ServiceSettings records are the test's own, so the network holds no feature a fresh record would clear
	sidecar.WithAuthFeaturesImplementedForTest(t, 0, nil)
	world := newTestWriterWorld(t)
	world.started()
	ownerClient := world.client()
	world.caughtUp(ownerClient)
	ownerWriter := world.writer(world.owner, ownerClient, nil, 0, nil)
	settings, rules := testRevokedSignerSettings(), testRevokedSignerRules()
	testCarriedPublish(world, "the first device's records", func(ctx context.Context) (*bridge.AuthPin, error) {
		return ownerWriter.SaveHead(ctx, testRevokedSignerRecords(world, world.owner, settings, rules))
	})
	desktop := testWriterDeviceOf("owner desktop", world.owner.memberId)
	testCarriedAdmit(world, world.owner, desktop)
	reader := world.client()
	testCarriedRecordsAre(t, "a device while the first device stands", testCarriedListing(world, "a device", reader))
	gate := newTestRevokedSignerGate(world)
	gate.caughtUp()

	testRevokedSignerRevoke(world, desktop, world.owner)
	state := world.caughtUp(reader)
	revokedAt := state.SidecarRow(world.owner.sidecarId).GetRevokedAt()
	if revokedAt == 0 {
		t.Fatal("the first device is not revoked")
	}
	revoked := func(record string) *sidecar.ConfigCarriedRecord {
		carried := testCarriedRecordOf(record, world.owner, sidecar.ConfigCarriedRevoked)
		carried.At, carried.Role = revokedAt, "owner"
		return carried
	}
	both := []*sidecar.ConfigCarriedRecord{revoked(sidecar.ConfigHeadServiceSettingsPath), revoked(sidecar.ConfigHeadVersioningRulesPath)}
	// the revocation changes no head, so the base before it still names the records
	testCarriedRecordsAre(t, "a device after the revocation", testCarriedListing(world, "a device after the revocation", reader), both...)

	desktopClient := world.client()
	world.caughtUp(desktopClient)
	desktopWriter := world.writer(desktop, desktopClient, nil, 0, nil)
	base := testCarriedPublish(world, "the desktop's fold", func(ctx context.Context) (*bridge.AuthPin, error) {
		return desktopWriter.PublishBase(ctx, true)
	})
	if base.GetVersion() != state.Pin().GetVersion()+1 {
		t.Fatalf("the desktop's fold landed at %d after %d", base.GetVersion(), state.Pin().GetVersion())
	}
	testRevokedSignerHolds(t, "a device at the fold", world.caughtUp(reader), settings, rules)
	point := gate.caughtUp().RetentionPoint()
	if point <= 1 {
		t.Fatalf("the retention point is %d: a new device would read the log from 1", point)
	}
	cold := newTestRevokedSignerReader(world, &testRevokedSignerRetained{reader: world.reader(), from: point})
	for _, c := range []struct {
		label  string
		client *sidecar.ConfigClient
	}{
		{label: "a device at the fold", client: reader},
		{label: "the desktop at its fold", client: desktopClient},
		{label: "a new device from the genesis", client: world.client()},
		{label: "a new device starting at the fold", client: cold.client},
	} {
		testCarriedRecordsAre(t, c.label, testCarriedListing(world, c.label, c.client), both...)
	}
	if coldState := cold.client.State(); coldState.Base().GetVersion() != base.GetVersion() || coldState.Pin().GetVersion() != base.GetVersion() {
		t.Fatalf("the new device starting at the fold stands at %d on the base at %d", coldState.Pin().GetVersion(), coldState.Base().GetVersion())
	}

	// fresh settings under the desktop's signature, judged where they land: that record is no longer listed
	testCarriedPublish(world, "the desktop's settings", func(ctx context.Context) (*bridge.AuthPin, error) {
		return desktopWriter.SaveHead(ctx, testRevokedSignerRecords(world, desktop, settings, nil))
	})
	for _, c := range []struct {
		label  string
		client *sidecar.ConfigClient
	}{
		{label: "a device after the desktop's settings", client: reader},
		{label: "the desktop after its settings", client: desktopClient},
		{label: "a new device after the desktop's settings", client: world.client()},
	} {
		testCarriedRecordsAre(t, c.label, testCarriedListing(world, c.label, c.client), revoked(sidecar.ConfigHeadVersioningRulesPath))
	}

	// and fresh rules: the listing clears
	testCarriedPublish(world, "the desktop's rules", func(ctx context.Context) (*bridge.AuthPin, error) {
		return desktopWriter.SaveHead(ctx, testRevokedSignerRecords(world, desktop, nil, rules))
	})
	testCarriedRecordsAre(t, "a device after the desktop's rules", testCarriedListing(world, "a device after the desktop's rules", reader))
	testCarriedRecordsAre(t, "the desktop after its rules", testCarriedListing(world, "the desktop after its rules", desktopClient))
	testRevokedSignerHolds(t, "a device after the desktop's rules", reader.State(), settings, rules)
}

// An Admin's laptop signs both records. Made a Network admin, its member no longer holds a role that signs
// ServiceSettings, which is listed with that role, while its VersioningRules, which a Network admin signs, is not; made
// a Member, both are listed. Its member's removal revokes the laptop, and both are listed as revoked with the member
// gone. The owner then files both records afresh and nothing stays listed.
func TestCarriedRecordsNameTheSignersRoleOnceItsMemberIsDemotedOrRemoved(t *testing.T) {
	// its ServiceSettings records are the test's own, so the network holds no feature a fresh record would clear
	sidecar.WithAuthFeaturesImplementedForTest(t, 0, nil)
	world := newTestWriterWorld(t)
	world.started()
	adminMemberId := testWriterId("admin member")
	if _, err := world.api.AppendStatement(world.ctx, world.networkId, world.statement(world.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, &protocol.MemberAdmit{
		Header: world.header(), MemberId: adminMemberId.Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_MEMBER,
	})); err != nil {
		t.Fatal(err)
	}
	laptop := testWriterDeviceOf("admin laptop", adminMemberId)
	testCarriedAdmit(world, world.owner, laptop)
	adminSet := func(admins []sidecar.Id, networkAdmins []sidecar.Id) {
		t.Helper()
		set := &protocol.AdminSet{Header: world.header(), Owners: [][]byte{world.owner.memberId.Bytes()}}
		for _, admin := range admins {
			set.Admins = append(set.Admins, admin.Bytes())
		}
		for _, networkAdmin := range networkAdmins {
			set.NetworkAdmins = append(set.NetworkAdmins, networkAdmin.Bytes())
		}
		if _, err := world.api.AppendStatement(world.ctx, world.networkId, world.statement(world.owner, bridge.SignedType_SIGNED_ADMIN_SET, set)); err != nil {
			t.Fatalf("an AdminSet of %d admins and %d network admins: %v", len(admins), len(networkAdmins), err)
		}
	}
	adminSet([]sidecar.Id{adminMemberId}, nil)

	laptopClient := world.client()
	world.caughtUp(laptopClient)
	laptopWriter := world.writer(laptop, laptopClient, nil, 0, nil)
	settings, rules := testRevokedSignerSettings(), testRevokedSignerRules()
	testCarriedPublish(world, "the admin's records", func(ctx context.Context) (*bridge.AuthPin, error) {
		return laptopWriter.SaveHead(ctx, testRevokedSignerRecords(world, laptop, settings, rules))
	})
	reader := world.client()
	testCarriedRecordsAre(t, "a device while the admin stands", testCarriedListing(world, "a device", reader))

	role := func(record string, role string) *sidecar.ConfigCarriedRecord {
		carried := testCarriedRecordOf(record, laptop, sidecar.ConfigCarriedRole)
		carried.Role = role
		return carried
	}
	adminSet(nil, []sidecar.Id{adminMemberId})
	testCarriedRecordsAre(t, "a device once the admin is a Network admin", testCarriedListing(world, "a device after the first demotion", reader),
		role(sidecar.ConfigHeadServiceSettingsPath, "network_admin"))

	adminSet(nil, nil)
	testCarriedRecordsAre(t, "a device once the admin is a Member", testCarriedListing(world, "a device after the second demotion", reader),
		role(sidecar.ConfigHeadServiceSettingsPath, "member"), role(sidecar.ConfigHeadVersioningRulesPath, "member"))

	if _, err := world.api.AppendStatement(world.ctx, world.networkId, world.statement(world.owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, &bridge.MemberRevoke{
		Header: world.header(), MemberId: adminMemberId.Bytes(),
	})); err != nil {
		t.Fatalf("removing the member: %v", err)
	}
	state := world.caughtUp(reader)
	revokedAt := state.SidecarRow(laptop.sidecarId).GetRevokedAt()
	if revokedAt == 0 || state.Member(adminMemberId) != nil {
		t.Fatalf("the removal left the laptop revoked at %d, the member %v", revokedAt, state.Member(adminMemberId))
	}
	removed := func(record string) *sidecar.ConfigCarriedRecord {
		carried := testCarriedRecordOf(record, laptop, sidecar.ConfigCarriedRevoked)
		carried.At, carried.MemberRemoved = revokedAt, true
		return carried
	}
	testCarriedRecordsAre(t, "a device once the member is removed", testCarriedListing(world, "a device after the removal", reader),
		removed(sidecar.ConfigHeadServiceSettingsPath), removed(sidecar.ConfigHeadVersioningRulesPath))

	ownerClient := world.client()
	world.caughtUp(ownerClient)
	ownerWriter := world.writer(world.owner, ownerClient, nil, 0, nil)
	testCarriedPublish(world, "the owner's records", func(ctx context.Context) (*bridge.AuthPin, error) {
		return ownerWriter.SaveHead(ctx, testRevokedSignerRecords(world, world.owner, settings, rules))
	})
	testCarriedRecordsAre(t, "a device after the owner's records", testCarriedListing(world, "a device after the owner's records", reader))
	testCarriedRecordsAre(t, "the owner after its records", testCarriedListing(world, "the owner after its records", ownerClient))
}

// The owner's first device admits the owner's desktop, then the owner's laptop, which signs both records. The desktop
// revokes the first device for compromise from the laptop's admission on, so the cascade parks the laptop, which the
// first device admitted there: both records are listed as parked at the revocation.
func TestCarriedRecordsNameAParkedSigner(t *testing.T) {
	// its ServiceSettings records are the test's own, so the network holds no feature a fresh record would clear
	sidecar.WithAuthFeaturesImplementedForTest(t, 0, nil)
	world := newTestWriterWorld(t)
	world.started()
	desktop := testWriterDeviceOf("owner desktop", world.owner.memberId)
	testCarriedAdmit(world, world.owner, desktop)
	laptop := testWriterDeviceOf("owner laptop", world.owner.memberId)
	admitted := testCarriedAdmit(world, world.owner, laptop)

	laptopClient := world.client()
	world.caughtUp(laptopClient)
	laptopWriter := world.writer(laptop, laptopClient, nil, 0, nil)
	testCarriedPublish(world, "the laptop's records", func(ctx context.Context) (*bridge.AuthPin, error) {
		return laptopWriter.SaveHead(ctx, testRevokedSignerRecords(world, laptop, testRevokedSignerSettings(), testRevokedSignerRules()))
	})
	reader := world.client()
	testCarriedRecordsAre(t, "a device while the laptop stands", testCarriedListing(world, "a device", reader))

	if _, err := world.api.AppendStatement(world.ctx, world.networkId, world.statement(desktop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, &bridge.SidecarRevoke{
		Header: world.header(), SidecarId: world.owner.sidecarId.Bytes(), Reason: bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE, SinceN: admitted.GetVersion(),
	})); err != nil {
		t.Fatalf("the compromise revocation: %v", err)
	}
	state := world.caughtUp(reader)
	parkedAt := state.SidecarRow(laptop.sidecarId).GetParkedAt()
	if parkedAt == 0 || state.SidecarRow(laptop.sidecarId).GetRevokedAt() != 0 {
		t.Fatalf("the cascade left the laptop parked at %d, revoked at %d", parkedAt, state.SidecarRow(laptop.sidecarId).GetRevokedAt())
	}
	parked := func(record string) *sidecar.ConfigCarriedRecord {
		carried := testCarriedRecordOf(record, laptop, sidecar.ConfigCarriedParked)
		carried.At, carried.Role = parkedAt, "owner"
		return carried
	}
	testCarriedRecordsAre(t, "a device after the cascade", testCarriedListing(world, "a device after the cascade", reader),
		parked(sidecar.ConfigHeadServiceSettingsPath), parked(sidecar.ConfigHeadVersioningRulesPath))
}

// The listing reads only the head the state stands on: a head holding other settings than the state, one without the
// state's settings, one holding rules the state does not, and none at all are refused, ErrConfigCarriedHead; the
// state's own head lists nothing while its signer stands. A rows-only reader, which opens no head, knows no record.
func TestCarriedRecordsRefuseAHeadTheStateDoesNotStandOn(t *testing.T) {
	// its ServiceSettings records are the test's own, so the network holds no feature a fresh record would clear
	sidecar.WithAuthFeaturesImplementedForTest(t, 0, nil)
	world := newTestWriterWorld(t)
	world.started()
	ownerClient := world.client()
	world.caughtUp(ownerClient)
	ownerWriter := world.writer(world.owner, ownerClient, nil, 0, nil)
	testCarriedPublish(world, "the owner's settings", func(ctx context.Context) (*bridge.AuthPin, error) {
		return ownerWriter.SaveHead(ctx, testRevokedSignerRecords(world, world.owner, testRevokedSignerSettings(), nil))
	})
	state := world.caughtUp(ownerClient)
	head, err := world.heads.ReadConfigHead(world.ctx, state.Base().GetConfigVersion(), state.Base().GetConfigHeadSha256())
	if err != nil {
		t.Fatal(err)
	}
	if records, err := state.CarriedRecords(head); err != nil || len(records) != 0 {
		t.Fatalf("the state's own head lists %v: %v", records, err)
	}

	other, err := head.WithFile(sidecar.ConfigHeadServiceSettingsPath, world.statement(world.owner, bridge.SignedType_SIGNED_SERVICE_SETTINGS, &protocol.ServiceSettings{MailStrict: false, RecordRequired: true}))
	if err != nil {
		t.Fatal(err)
	}
	without, err := head.WithFile(sidecar.ConfigHeadServiceSettingsPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	extra, err := head.WithFile(sidecar.ConfigHeadVersioningRulesPath, world.statement(world.owner, bridge.SignedType_SIGNED_VERSIONING_RULES, testRevokedSignerRules()))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		label string
		head  *sidecar.ConfigHead
	}{
		{label: "other settings", head: other},
		{label: "no settings", head: without},
		{label: "rules the state does not hold", head: extra},
		{label: "no head", head: nil},
	} {
		if records, err := state.CarriedRecords(c.head); !errors.Is(err, sidecar.ErrConfigCarriedHead) {
			t.Errorf("a head with %s lists %v: %v", c.label, records, err)
		}
	}

	gate := newTestRevokedSignerGate(world)
	if records, err := gate.caughtUp().CarriedRecords(head); !errors.Is(err, sidecar.ErrConfigCarriedUnknown) {
		t.Errorf("a rows-only reader lists %v: %v", records, err)
	}
}
