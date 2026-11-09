//go:build sidecar_testhooks && !sidecar_http

// record_receipt.go's hooks, under the tag: a receipt's send passes record.receipt.deposit.before and .after, keyed
// by its log's hex id, its deposit committing between them and nothing decrypted until the read goes on after; and
// the receipt's key and salt reach the secret hook where they are drawn.

package sidecar_test

import (
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// What a schedule parked at a receipt barrier would see there.
type testReceiptBarrierSight struct {
	name        string
	key         string
	depositRead int
	keyUses     int
}

func TestRecordReceiptBarriersSurroundItsDeposit(t *testing.T) {
	world := newTestRecordWorld(t)
	author := world.device(true)
	reader := world.shareReader()
	key := &testReceiptKey{}
	sights := []*testReceiptBarrierSight{}
	hooks, _ := installTestRecordHooks(t, func(name string, barrierKey string) {
		if !strings.HasPrefix(name, "record.receipt.") {
			return
		}
		// the read is synchronous, so this runs on the test's goroutine
		sights = append(sights, &testReceiptBarrierSight{
			name:        name,
			key:         barrierKey,
			depositRead: len(world.waitingDeposits(author, reader.sidecarId)),
			keyUses:     key.uses(),
		})
	})
	if err := testReceiptRead(t.Context(), reader.open(), world, key, sidecar.RecordReadPurposeRead, testReceiptObjectIds(t, 1, 16)); err != nil {
		t.Fatal(err)
	}
	logKey := hex.EncodeToString(world.vaultId[:])
	names := []string{}
	for _, sight := range sights {
		names = append(names, sight.name)
		if sight.key != logKey || sight.keyUses != 0 {
			t.Errorf("%s: key %q, %d decrypts", sight.name, sight.key, sight.keyUses)
		}
	}
	if !slices.Equal(names, []string{"record.receipt.deposit.before", "record.receipt.deposit.after"}) {
		t.Fatalf("receipt barriers %v", names)
	}
	if sights[0].depositRead != 0 || sights[1].depositRead != 1 {
		t.Errorf("deposits at the barriers: %d before, %d after", sights[0].depositRead, sights[1].depositRead)
	}
	waiting := world.receiptsWaiting(author, reader)
	if len(waiting) != 1 {
		t.Fatalf("%d receipts", len(waiting))
	}
	hooks.stateLock.Lock()
	keyCount := len(hooks.kindSecrets["record_entry_key"])
	saltCount := len(hooks.kindSecrets["record_entry_salt"])
	hooks.stateLock.Unlock()
	if keyCount == 0 || saltCount == 0 {
		t.Errorf("the receipt's key and salt reached the hook %d and %d times", keyCount, saltCount)
	}
}
