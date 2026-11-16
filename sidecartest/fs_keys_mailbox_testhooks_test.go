//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// FS-23's depositor check in the mailbox with evs's gate off (KEYS-M7-01; D-KEYS-17, D-TEST-6), on the world
// fs_keys_mailbox_test.go builds: only a sidecar_testhooks build can turn evs's 5d off
// (evsservice.SwitchGateOffForTest), so what refuses a deposit sealed to a stale drop key is the receiver's own
// depositor rule.

package sidecartest_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
)

// A depositor that skips the depositor rule: it seals to the drop key it was handed once, whatever its state shows
// since, as a stale or careless one would.
type fsKeysMailboxStaleDropKeys struct {
	sidecar.GkmClient
	dropKey *sidecar.GkmDropKey
}

func (self *fsKeysMailboxStaleDropKeys) DropKey(ctx context.Context, repoId sidecar.Id) (*sidecar.GkmDropKey, error) {
	return self.dropKey, nil
}

// A mail deposit's plaintext as a receiver writes it (MAIL-FORMAT.md): the message, its MailDeposit, and u32be of
// that encoding's length.
func fsKeysMailboxDepositBody(t *testing.T, message []byte, receiverId sidecar.Id) []byte {
	t.Helper()
	trailer, err := proto.Marshal(&protocol.MailDeposit{
		Version: fsKeysMailboxIngressVersion, Recipients: []string{fsKeysMailboxAddress}, ReceiverSidecarId: receiverId.Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	body := append(bytes.Clone(message), trailer...)
	return binary.BigEndian.AppendUint32(body, uint32(len(trailer)))
}

// With evs's gate off, after b's revocation: a depositor that skips the rule deposits at generation 1's drop key,
// unexpired and stale, and evs takes it; the receiver answers 451 4.3.0 for a message until a's REMOVE rotation covers
// the shrink, then 250 at generation 2, which b, revoked, does not reach, though it reaches the stale deposit's.
func TestFsKeysMailboxWithEvsGateOffTheReceiverRefusesAStaleDropKey(t *testing.T) {
	evsservice.SwitchGateOffForTest(true)
	t.Cleanup(func() { evsservice.SwitchGateOffForTest(false) })
	world := newFsKeysMailboxSessionWorld(t)
	keys := world.keys
	aEvs := world.evsClient(world.a, world.a.Client, keys.Clock)
	first := fsKeysMailboxMessage("first")
	if reply := world.send(first); !reply.Is(250) {
		t.Fatalf("a message at a covered drop key: %s", reply)
	}
	held, err := world.receiver.Client.DropKey(world.ctx, keys.RepoId)
	if err != nil || held.Generation != 1 {
		t.Fatalf("the receiver's drop key: %v", err)
	}

	keys.Revoke(world.b)
	keys.Advance()
	stale := world.evsClient(world.receiver, &fsKeysMailboxStaleDropKeys{GkmClient: world.receiver.Client, dropKey: held}, world.receiverClock)
	staleMessage := fsKeysMailboxMessage("stale")
	staleBody := fsKeysMailboxDepositBody(t, staleMessage, world.receiver.SidecarId())
	if _, err := stale.Repo(keys.RepoId).Deposit(world.ctx, &sidecar.EvsDepositArgs{Body: bytes.NewReader(staleBody), Size: int64(len(staleBody))}); err != nil {
		t.Fatalf("evs refused a deposit at the stale drop key, so its gate is not off: %v", err)
	}
	second := fsKeysMailboxMessage("second")
	if reply := world.send(second); !fsKeysMailboxTryLater(reply) {
		t.Fatalf("a message after the removal, before a REMOVE rotation: %s", reply)
	}

	if key, err := world.a.Client.EnsureWritable(world.ctx, keys.RepoId); err != nil || key.Generation() != 2 {
		t.Fatalf("a's REMOVE rotation: %v", err)
	}
	if cause := sidecar.GkmCause(keys.Generation(2).Rotate.GetCause()); cause != sidecar.GkmCauseRemove {
		t.Fatalf("generation 2's cause: %d", cause)
	}
	if reply := world.send(second); !reply.Is(250) {
		t.Fatalf("the retry at the REMOVE generation: %s", reply)
	}
	if dropKey, err := world.receiver.Client.DropKey(world.ctx, keys.RepoId); err != nil || dropKey.Generation != 2 {
		t.Fatalf("the receiver's drop key after the REMOVE rotation: %v", err)
	}
	ingested := world.ingest(world.a, aEvs)
	if len(ingested) != 3 || !bytes.Equal(ingested[0].message, first) || !bytes.Equal(ingested[1].message, staleMessage) ||
		!bytes.Equal(ingested[2].message, second) {
		t.Fatalf("a's ingest: %d deposits", len(ingested))
	}
	// b, revoked, reaches generation 1, so the stale deposit, and nothing the receiver sealed after the removal
	if reach := keys.RemovedReach(world.b); reach != 1 {
		t.Errorf("revoked b reaches generation %d, not 1", reach)
	}
}
