//go:build !ios_extension && !sidecar_http

// Sidecar.CarriedConfigRecords (config_records_carried.go), the call ur admin settings' and ur admin versioning's
// control methods make: it reads the installed authority's newest verified state and the head that state's base names,
// and refuses before a verified state.

package sidecar

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// With no authority installed the call refuses. On an Owner's laptop whose state stands on a base whose head holds the
// owner's first device's ServiceSettings, nothing is listed while that device stands; once the owner's phone revokes it
// as lost, the record is listed as revoked, with no base in between.
func TestSidecarCarriedConfigRecordsReadsItsAuthoritysHead(t *testing.T) {
	ctx := context.Background()
	if records, err := (&Sidecar{}).CarriedConfigRecords(ctx); !errors.Is(err, ErrSidecarActNoAuthority) {
		t.Fatalf("no authority lists %v: %v", records, err)
	}
	world := newTestConfigClientWorld(t)
	net := world.net
	phone := net.device("owner phone", net.ownerMemberId)
	net.admitDevice(net.owner, phone, 0)
	configVersion := net.log.State().Base().GetConfigVersion() + 1
	net.source.settings[[sha256.Size]byte(testConfigHeadSha256(configVersion))] = &protocol.ServiceSettings{MailStrict: true}
	if verdict := net.fold(net.owner, net.n, configVersion); !verdict.Accepted() {
		t.Fatalf("the base holding the settings: %v", verdict.Refusal)
	}
	running, client := testServiceSettingsSidecar(t, world, "owner laptop", net.ownerMemberId)
	if held, known := client.State().HeadSettings(); !known || !held.GetMailStrict() {
		t.Fatalf("the laptop holds the settings %v (known %t)", held, known)
	}
	if records, err := running.CarriedConfigRecords(ctx); err != nil || len(records) != 0 {
		t.Fatalf("while the first device stands it lists %v: %v", records, err)
	}

	revoked := net.mustPost(phone, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(net.owner, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	world.publish()
	world.caughtUp(client)
	records, err := running.CarriedConfigRecords(ctx)
	if err != nil || len(records) != 1 {
		t.Fatalf("after the revocation it lists %v: %v", records, err)
	}
	carried := records[0]
	if carried.Record != ConfigHeadServiceSettingsPath || carried.SignerId != net.owner.sidecarId || carried.Why != ConfigCarriedRevoked ||
		carried.At != revoked.Pin.GetVersion() || carried.MemberId == nil || *carried.MemberId != net.ownerMemberId || carried.Role != "owner" || carried.MemberRemoved {
		t.Errorf("after the revocation it lists %+v", carried)
	}
}
