// ur keychain recovery-rotate: a no changes nothing; a yes hands the daemon a binding's public half whose genesis_sig
// verifies, and shows on the terminal alone the 12 words that derive exactly that binding; --compromise rides the
// call and lists the member's other devices; and the bind method is a Confirm one (D-CORE-13).

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A daemon target that runs a Sidecar's recovery binding, as a test sets it.
type testUrRecoveryTarget struct {
	testUrDaemonTarget
	networkId     sidecar.Id
	genesisSha256 []byte
	bindings      []*sidecar.RecoveryBinding
	compromises   []bool
	devices       []sidecar.MemberDevice
}

func (self *testUrRecoveryTarget) recoveryAnchor() (sidecar.Id, []byte, error) {
	return self.networkId, self.genesisSha256, nil
}

func (self *testUrRecoveryTarget) bindRecovery(ctx context.Context, binding *sidecar.RecoveryBinding, compromise bool) (*sidecar.RecoveryRotation, error) {
	self.bindings = append(self.bindings, binding)
	self.compromises = append(self.compromises, compromise)
	return &sidecar.RecoveryRotation{
		KeySha256: sidecar.RecoveryKeySha256(binding.Ed25519PublicKey),
		Devices:   self.devices,
	}, nil
}

func TestKeychainRecoveryRotateShowsTheCodeOnce(t *testing.T) {
	genesisSha256 := sha256.Sum256([]byte("a synthetic Signed Genesis"))
	otherId := sidecar.NewId()
	target := &testUrRecoveryTarget{
		networkId:     sidecar.NewId(),
		genesisSha256: genesisSha256[:],
		devices:       []sidecar.MemberDevice{{SidecarId: sidecar.NewId(), This: true, State: "live"}, {SidecarId: otherId, State: "live"}},
	}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, _ := newTestUrCli(daemon.socketPath)

	// with no terminal nothing is asked of the daemon's signer
	if code := cli.main(context.Background(), []string{"ur", "keychain", "recovery-rotate"}); code == urExitOk || len(target.bindings) != 0 {
		t.Fatalf("with no terminal: exit %d, %d bindings", code, len(target.bindings))
	}
	tty := &testTty{lines: []string{"n"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), []string{"ur", "keychain", "recovery-rotate"}); code != urExitOk || len(target.bindings) != 0 {
		t.Fatalf("a no bound: exit %d, %d bindings", code, len(target.bindings))
	}
	if !strings.Contains(tty.written.String(), sidecar.RecoveryBackupRule) {
		t.Errorf("the terminal showed no backup rule: %q", tty.written.String())
	}

	tty = &testTty{lines: []string{"yes"}}
	stdout.Reset()
	if code := cli.main(context.Background(), []string{"ur", "keychain", "recovery-rotate", "--compromise"}); code != urExitOk || len(target.bindings) != 1 || !target.compromises[0] {
		t.Fatalf("a yes: exit %d, %d bindings", code, len(target.bindings))
	}
	binding := target.bindings[0]
	if err := sidecar.VerifyRecoveryGenesisSig(binding.Ed25519PublicKey, target.networkId, target.genesisSha256, binding.GenesisSig); err != nil {
		t.Fatal(err)
	}
	// the words on the terminal are the binding's code
	written := tty.written.String()
	_, after, found := strings.Cut(written, "shown this once.")
	if !found {
		t.Fatalf("the terminal showed no code: %q", written)
	}
	lines := strings.Split(after, "\n")
	words := []string{}
	for _, line := range lines[1:] {
		if strings.HasPrefix(line, "  ") && !strings.Contains(line, "ur devices") {
			words = append(words, strings.Fields(line)...)
		}
	}
	code, err := sidecar.ParseRecoveryCode(strings.Join(words, " "))
	if err != nil {
		t.Fatalf("the terminal's words are no code: %v: %q", err, words)
	}
	keys, err := code.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keys.Ed25519PublicKey(), binding.Ed25519PublicKey) || !bytes.Equal(keys.XwingPublicKey(), binding.XwingPublicKey) {
		t.Error("the words shown do not derive the binding signed")
	}
	// stdout holds no word of it, as a whole word: a code word can sit inside one of stdout's own ("cover" in "recovery")
	printed := map[string]bool{}
	for _, field := range strings.Fields(stdout.String()) {
		printed[field] = true
	}
	for _, word := range words {
		if 4 < len(word) && printed[word] && word != "recovery" && word != "rotate" {
			t.Errorf("stdout holds the code's word %q: %q", word, stdout.String())
		}
	}
	if !strings.Contains(written, "ur devices revoke "+otherId.String()+" --compromise") {
		t.Errorf("a compromise rotation listed no device to review: %q", written)
	}
}

// keychain.recovery_bind is a Confirm method: only a confirmed control call runs it, never MCP or an unconfirmed call.
func TestKeychainRecoveryBindIsConfirmOnly(t *testing.T) {
	methods := urKeychainRecoveryMethods(&testUrRecoveryTarget{})
	for _, method := range methods {
		if method.Name == urMethodKeychainRecoveryBind && !method.Confirm {
			t.Error("keychain.recovery_bind runs unconfirmed")
		}
	}
	if len(methods) != 2 {
		t.Errorf("%d methods", len(methods))
	}
	if methods := urKeychainRecoveryMethods(&testUrDaemonTarget{}); len(methods) != 0 {
		t.Error("a target with no Sidecar serves the recovery methods")
	}
}
