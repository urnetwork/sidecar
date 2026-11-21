//go:build !ios_extension

// The native and HTTP member replica both authorize record reads from the published full replay.

package sidecar

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// No row from either startup replay reaches a real reader. Publishing the log activates the bound rights and gate.
func TestRecordReplicaWaitsForPublishedConfig(t *testing.T) {
	world := NewDirectoryAuthTestNetwork(t)
	state := world.net.log.State()
	device := world.net.owner
	identity := &SidecarIdentity{NetworkId: state.NetworkId(), SidecarId: device.sidecarId, IdentityPublicKey: device.publicKey()}
	config := &ConfigClient{args: &ConfigClientArgs{NetworkId: identity.NetworkId}}
	config.unconfirmed.Store(world.net.log)
	config.starting.Store(world.net.log)
	evs := &EvsClient{args: &EvsClientArgs{NetworkId: identity.NetworkId, Identity: func() *SidecarIdentity { return identity }}}
	record, err := NewSidecarRecord(&SidecarRecordArgs{
		SidecarId: device.sidecarId, IdentityPublicKey: identity.IdentityPublicKey, Store: newTestConfigClientStore(),
		Settings: DefaultSidecarSettings().Record,
		Sign: func(purpose string, kind bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error) {
			return &bridge.Signed{Body: body, Type: uint32(kind), SignerId: device.sidecarId.Bytes(), Signature: ed25519.Sign(device.key, bridge.SignedBytes(purpose, kind, body))}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := record.BindMemberReplica(config, evs); err != nil {
		t.Fatal(err)
	}
	if err := record.Reader().Sync(t.Context(), world.DirectoryId); !errors.Is(err, ErrRecordNotReader) {
		t.Fatalf("unpublished config reached a record read: %v", err)
	}
	config.configLog.Store(world.net.log)
	auth := record.reader.authNow()
	if _, ok := record.writer.boundStreams().(*RecordEvsStreams); !ok || evs.preDecryptHook == nil ||
		auth.Pin().GetVersion() != world.Tip() || !auth.Reads(world.DirectoryId, device.sidecarId) ||
		auth.Reads(world.VaultId, device.sidecarId) {
		t.Fatal("published config did not bind the member's exact live rights, streams and receipts")
	}
	identity = nil
	if err := record.Reader().Sync(t.Context(), world.DirectoryId); !errors.Is(err, ErrRecordNotReader) {
		t.Fatalf("a previous identity authorized a read: %v", err)
	}
}
