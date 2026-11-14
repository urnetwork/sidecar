//go:build sidecar_testhooks

// MAIL-M7-04's hook sites: a mailcfg record's write and removal sit between barriers a fault schedule holds, and a
// restart's Lookup reconciles a use whose process stopped at either side of its record's push.

package sidecar

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A restart's Lookup finds a record written just before a crash (D-MCP-11): the creating process is held after its
// record's push and never answers its gate; another MailConfig of the same sidecar, with only the stored action and
// the use's key, answers done, and the use run again writes no second record. Held before the push instead, the
// Lookup answers uncertain, since that attempt may still commit, and done once it has.
func TestMailConfigRestartLookupFindsARecordWrittenBeforeACrash(t *testing.T) {
	repo, authority := newMailConfigTestWorld(t)
	ctx := context.Background()
	stored, err := NewCanonicalAction(&protocol.CanonicalAction{Kind: uint32(SidecarActionAliasCreate), Alias: "ada"})
	if err != nil {
		t.Fatal(err)
	}
	key := mailConfigTestEffectKey(stored.Bytes)
	path := testMailConfigAddressPath(t, "ada@acme.root.example")
	for _, barrier := range []string{"mail.config.write.before", "mail.config.write.after"} {
		for _, removed := range repo.standingPaths() {
			repo.commit(removed, testMailConfigPhoneId, nil)
		}
		versionsBefore := repo.versionCount(path)
		reached := make(chan struct{})
		release := make(chan struct{})
		var once sync.Once
		SetTestHooks(&TestHooks{Barrier: func(name string, barrierKey string) {
			if name != barrier {
				return
			}
			held := false
			once.Do(func() { held = true })
			if held {
				close(reached)
				<-release
			}
		}})
		t.Cleanup(func() { SetTestHooks(nil) })
		crashing := newMailConfigTestDevice(t, repo, authority, testMailConfigPhoneId, nil)
		finished := make(chan error, 1)
		go func() {
			_, err := crashing.config.CreateAddress(ctx, &MailCreateAddressArgs{
				LocalPart: "ada", Kind: protocol.MailAddressKind_MAIL_ADDRESS_ID, MailboxRepoId: testMailConfigMailboxId,
			})
			finished <- err
		}()
		<-reached

		restarted := newMailConfigTestDevice(t, repo, authority, testMailConfigPhoneId, nil)
		outcome, err := restarted.config.Lookup(ctx, stored.Bytes, key)
		if err != nil {
			t.Fatal(err)
		}
		if barrier == "mail.config.write.before" {
			if outcome.State != ApprovalOutcomeUncertain || repo.versionCount(path) != versionsBefore {
				t.Fatalf("held before the push: %+v", outcome)
			}
			close(release)
			if err := <-finished; err != nil {
				t.Fatal(err)
			}
			if outcome, err = restarted.config.Lookup(ctx, stored.Bytes, key); err != nil || outcome.State != ApprovalOutcomeDone {
				t.Fatalf("once the push landed: %+v, %v", outcome, err)
			}
			continue
		}
		if outcome.State != ApprovalOutcomeDone || repo.versionCount(path) != versionsBefore+1 {
			t.Fatalf("held after the push: %+v", outcome)
		}
		// the gate's retry of the reserved use, with the first process still stopped: the record is found, not made
		effect := &mailConfigCreateAddressEffect{
			config: restarted.config,
			name:   &mailConfigName{key: "ada@acme.root.example", alias: "ada", path: path},
			address: &protocol.MailAddress{
				Kind: protocol.MailAddressKind_MAIL_ADDRESS_ID, Mailbox: testMailConfigMailboxId.Bytes(), Creator: testMailConfigPhoneId.Bytes(),
			},
		}
		effectRef, err := effect.Run(ctx, key)
		if err != nil || !bytes.Equal(effectRef, outcome.EffectRef) || repo.versionCount(path) != versionsBefore+1 {
			t.Fatalf("the use run again: %x, %v", effectRef, err)
		}
		if lookup := restarted.resolve(t, "ada@acme.root.example"); !lookup.Known {
			t.Fatalf("the record: %+v", lookup)
		}
		close(release)
		if err := <-finished; err != nil {
			t.Fatal(err)
		}
	}
}

// A creation, a burn and a deletion each pass their before and after barriers.
func TestMailConfigWritesPassTheirBarriers(t *testing.T) {
	recorder := recordHooks(t)
	repo, authority := newMailConfigTestWorld(t)
	phone := newMailConfigTestDevice(t, repo, authority, testMailConfigPhoneId, func(args *MailConfigArgs) {
		args.BurnerLabels = func(effectKey []byte) []string { return []string{"otter-4821"} }
	})
	ctx := context.Background()
	phone.createId(t, "ada")
	if _, err := phone.config.CreateBurnerRecord(ctx, &MailCreateBurnerArgs{Alias: "shop", MailboxRepoId: testMailConfigMailboxId}); err != nil {
		t.Fatal(err)
	}
	if err := phone.config.SetBurnerState(ctx, "otter-4821", protocol.MailBurnerState_MAIL_BURNER_BURNED); err != nil {
		t.Fatal(err)
	}
	if err := phone.config.DeleteAddress(ctx, &MailDeleteAddressArgs{LocalPart: "ada"}); err != nil {
		t.Fatal(err)
	}
	recorder.stateLock.Lock()
	defer recorder.stateLock.Unlock()
	for _, name := range []string{"mail.config.write.before", "mail.config.write.after", "mail.config.remove.before", "mail.config.remove.after"} {
		if !recorder.barriers[name] {
			t.Errorf("barrier %s was not passed", name)
		}
	}
}
