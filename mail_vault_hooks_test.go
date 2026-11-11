//go:build sidecar_testhooks

// MAIL-M8-02's hook sites: every vault secret reaches the privacy harness, which scans each capture for it, and the
// vault's write, ERASE and removal sit between barriers a fault schedule holds.

package sidecar

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A password, each earlier password and a totp secret reach testHookSecret as a write encodes them and a read opens
// them, and the totp secret again as a code is derived from it; a write, a delete's ERASE and its removal each pass
// their before and after barriers.
func TestMailVaultSecretsReachTheSecretHook(t *testing.T) {
	recorder := recordHooks(t)
	ctx := context.Background()
	store := newMailVaultTestStore()
	device := newMailVaultTestDevice(t, store, testMailVaultDeviceId, nil)
	const address = "shop@otter-4821.acme.root.example"
	first := []byte("first password canary 7e1f")
	second := []byte("second password canary 2c9d")
	secret := []byte("totp secret canary 4b8a")
	entry := testMailVaultEntry(address, string(first))
	entry.Totp.Secret = secret
	written, err := device.vault.PutVaultEntry(ctx, entry)
	if err != nil {
		t.Fatal(err)
	}
	update := proto.Clone(written).(*protocol.VaultEntry)
	update.Password = string(second)
	if written, err = device.vault.PutVaultEntry(ctx, update); err != nil {
		t.Fatal(err)
	}
	entryId, _ := IdFromBytes(written.GetEntryId())
	recorder.stateLock.Lock()
	recorder.secrets = nil
	recorder.stateLock.Unlock()
	if _, err := newMailVaultTestDevice(t, store, testMailVaultOtherId, nil).vault.VaultEntry(ctx, entryId); err != nil {
		t.Fatal(err)
	}
	if _, _, err := MailTotpCode(written.GetTotp(), device.clock.now); err != nil {
		t.Fatal(err)
	}
	if err := device.vault.DeleteVaultEntry(ctx, entryId); err != nil {
		t.Fatal(err)
	}
	recorder.stateLock.Lock()
	defer recorder.stateLock.Unlock()
	if !recorder.kinds["vault_password"] || !recorder.kinds["vault_totp_secret"] {
		t.Fatalf("kinds %v", recorder.kinds)
	}
	for _, want := range [][]byte{first, second, secret} {
		if !slices.ContainsFunc(recorder.secrets, func(hooked []byte) bool { return bytes.Equal(hooked, want) }) {
			t.Errorf("%q never reached the hook as a read opened it", want)
		}
	}
	totpCount := 0
	for _, hooked := range recorder.secrets {
		if bytes.Equal(hooked, secret) {
			totpCount += 1
		}
	}
	if totpCount < 2 {
		t.Errorf("the totp secret reached the hook %d times, not at the read and at the code", totpCount)
	}
	for _, barrier := range []string{
		"mail.vault.write.before", "mail.vault.write.after",
		"mail.vault.erase.before", "mail.vault.erase.after",
		"mail.vault.remove.before", "mail.vault.remove.after",
	} {
		if !recorder.barriers[barrier] {
			t.Errorf("barrier %s never fired", barrier)
		}
	}
}
