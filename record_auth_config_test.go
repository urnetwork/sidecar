// The record's production authority over a verified authorization log, including past pins and per-vault consent.

package sidecar

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Only consented owners write their vault. Other devices can deposit, and read-only owners can deposit receipts.
func TestRecordAuthPublishedLogRightsAtTheirOwnPin(t *testing.T) {
	world := NewDirectoryAuthTestNetwork(t)
	member := world.net.device("directory member first device", world.MemberId)
	mailboxId := testConfigId("record receipt mailbox")
	world.net.mustPost(member, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
		Header: world.net.header(), RepoId: mailboxId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_MAILBOX,
	})
	state := world.net.log.State()
	auth := newConfigRecordAuth(state, time.UnixMilli(state.TimeMs()))
	if id, ok := auth.Vault(world.MemberId); !ok || id != world.VaultId {
		t.Fatalf("member vault %s, %v", id, ok)
	}
	if !auth.Consented(world.VaultId, world.MemberDevice) || !auth.Writes(world.VaultId, world.MemberDevice) ||
		!auth.Reads(world.VaultId, world.MemberDevice) || !auth.Admins(world.VaultId, world.MemberDevice) {
		t.Fatal("the creator lost its vault")
	}
	// the deposit its write implies (QD-1173) is none of the record's: its stream is its route, and a gap in it
	// alarms at once
	if auth.Deposits(world.VaultId, world.MemberDevice) {
		t.Fatal("the vault's writer reads as a depositor of its own log")
	}
	if auth.Consented(world.VaultId, world.Unconsented) || !auth.Deposits(world.VaultId, world.Unconsented) ||
		auth.Reads(world.VaultId, world.Unconsented) || auth.Writes(world.VaultId, world.Unconsented) {
		t.Fatal("a depositor acquired owner access")
	}
	if !auth.Consented(world.VaultId, world.ReadOnly) || !auth.Reads(world.VaultId, world.ReadOnly) ||
		!auth.ReceiptOnly(world.VaultId, world.ReadOnly) || auth.Writes(world.VaultId, world.ReadOnly) ||
		auth.Admins(world.VaultId, world.ReadOnly) {
		t.Fatal("read-only owner rights")
	}
	if auth.Reads(world.VaultId, world.OwnerDevice) || auth.Admins(world.VaultId, world.OwnerDevice) ||
		auth.Admins(world.GeneralRepoId, world.MemberDevice) {
		t.Fatal("record administration crossed the vault or log kind")
	}
	if !auth.Deposits(mailboxId, world.ReadOnly) || !auth.ReceiptOnly(mailboxId, world.ReadOnly) ||
		auth.Reads(mailboxId, world.ReadOnly) || auth.Admins(mailboxId, world.MemberDevice) {
		t.Fatal("mailbox receipts and record log powers crossed")
	}
	historical, err := auth.At(world.PinAt(world.VaultAt))
	if err != nil || !historical.Writes(world.VaultId, world.Revoked) || auth.Writes(world.VaultId, world.Revoked) {
		t.Fatalf("historical membership: %v", err)
	}
	ended, ok := auth.RightEnded(world.VaultId, world.Revoked, world.VaultAt)
	if !ok || ended != world.net.statesAt[world.RevokedAt].TimeMs() {
		t.Fatalf("wrong right-end time %d, %v", ended, ok)
	}
	if !bytes.Equal(auth.IdentityKey(world.Revoked), historical.IdentityKey(world.Revoked)) {
		t.Fatal("revocation discarded the historical signer")
	}
	if _, err := auth.At(&bridge.AuthPin{Version: world.Tip(), Chain: make([]byte, 32)}); !errors.Is(err, ErrRecordAuthOffChain) {
		t.Fatalf("wrong-chain pin: %v", err)
	}
	if _, err := auth.AtPosition(world.Tip() + 1); !errors.Is(err, ErrRecordAuthAhead) {
		t.Fatalf("ahead pin: %v", err)
	}
	// A later compromise reaches signed entries from before the original lost revocation.
	revoke := &bridge.SidecarRevoke{Header: world.net.header(), SidecarId: world.Revoked.Bytes(),
		Reason: bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE, SinceN: world.VaultAt}
	world.net.mustPost(member, bridge.SignedType_SIGNED_SIDECAR_REVOKE, revoke)
	if since, ok := NewRecordAuthView(world.net.log.State()).CompromisedSince(world.Revoked); !ok || since != world.VaultAt {
		t.Fatalf("later compromise did not reach its original pin: %d, %v", since, ok)
	}
}
