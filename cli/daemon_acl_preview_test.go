package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/enginenet"
)

// The ordinary EVS reader previews the named member and reports its write capability.
// A host providing ConfigHeadRef's exact commit contract takes the same confirmation to a new signed base.
func testDaemonOwnerAclPlanAndConfirm(t *testing.T, ctx context.Context, running *sidecar.Sidecar, first *enginenet.BootstrapResult, quota *sidecartest.FakeQuota) {
	t.Helper()
	setRuleLimit := func(rules int64) {
		quota.SetLimits(connect.Id(running.Identity().NetworkId), &sidecar.QuotaLimits{Tier: "free", Limits: map[string]int64{"acl_rules": rules}})
	}
	quota.SetEnforced(true)
	setRuleLimit(50)
	owner, err := sidecar.IdFromBytes(first.Bootstrap.State.Genesis().GetOwnerMemberId())
	if err != nil {
		t.Fatal(err)
	}
	daemon := startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		if err := daemon.AddSidecar(running.Identity().NetworkId, running); err != nil {
			t.Fatal(err)
		}
		target := &urDaemonNetwork{daemon: daemon}
		if err := registerUrDaemonMethods(daemon, "test", target, osKeyStoreKeyFile, func() []sidecar.SidecarHostCredentialStore { return nil }); err != nil {
			t.Fatal(err)
		}
	})
	const email = "first@team.example"
	const policy = `{"grants":[{"src":["user:first@team.example"],"dst":["autogroup:self"],"allow":["dial"]}]}`
	path := testUrAclPolicyFile(t, policy)
	old := urAdminRunCommand
	t.Cleanup(func() { urAdminRunCommand = old })
	urAdminRunCommand = func(ctx context.Context, cli *urCli, command *sidecar.AdminCommand, device bool) ([]byte, error) {
		if command.Method != "GET" || command.Path != "/network/members" || len(command.Body) != 0 {
			t.Fatalf("unexpected directory read: %+v", command)
		}
		return json.Marshal(map[string]any{"members": []map[string]any{{"email": email, "member_id": owner}}})
	}
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	ttyOpens := 0
	cli.openTty = func() (urTty, error) {
		ttyOpens++
		return &testTty{lines: []string{"yes"}}, nil
	}
	if code := cli.main(ctx, []string{"ur", "acl", "push", path}); code != urExitFailed || ttyOpens != 1 ||
		!strings.Contains(stderr.String(), "writable config ref") {
		t.Fatalf("read-only ref: exit %d, %d terminal opens, %s", code, ttyOpens, stderr)
	}
	for _, value := range []string{email, owner.String(), running.Identity().SidecarId.String()} {
		if !strings.Contains(stdout.String(), value) {
			t.Fatalf("missing %s in stock preview: %s", value, stdout)
		}
	}
	if state := running.ConfigFollower().Client().State(); state.Base().GetConfigVersion() != 1 {
		t.Fatalf("preview changed the config head: %v", state.Base())
	}

	// Install an exact-CAS host over the real first head and push. Subsequent writes use
	// the owner's existing key and the ordinary authenticated projection publisher.
	running.ConfigFollower().Close()
	heads := sidecartest.NewFakeConfigHeadsOnRef(first.ConfigRepoId, first.MainRefId)
	ref := heads.ForSigner(running.Identity().SidecarId, func(purpose string, kind bridge.SignedType, body []byte) (*bridge.Signed, error) {
		return running.Sign(purpose, kind, body, nil)
	})
	if err := ref.CommitConfigHead(ctx, first.Bootstrap.Push); err != nil {
		t.Fatal(err)
	}
	read := urDaemonConfigHeads
	urDaemonConfigHeads = func(*sidecar.Sidecar) sidecar.ConfigHeadReader {
		return struct {
			*sidecartest.FakeConfigHeads
			*sidecartest.FakeConfigHeadRef
		}{heads, ref}
	}
	follower := startUrConfigFollower(running, sidecar.NewNoopLogger())
	urDaemonConfigHeads = read
	if follower == nil {
		t.Fatal("the exact-CAS host did not start its follower")
	}
	client, err := follower.WaitStanding(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// A downgrade after preview must be reapplied before the signed push is prepared.
	confirmationOpens := 0
	cli.openTty = func() (urTty, error) {
		confirmationOpens++
		if confirmationOpens == 2 {
			setRuleLimit(0)
		}
		return &testTty{lines: []string{"yes"}}, nil
	}
	stderr.Reset()
	if code := cli.main(ctx, []string{"ur", "acl", "push", path}); code != urExitFailed || confirmationOpens != 2 ||
		client.State().Base().GetConfigVersion() != 1 || !strings.Contains(stderr.String(), "acl_rules") {
		t.Fatalf("confirmed after downgrade: exit %d, %d terminal opens, %s", code, confirmationOpens, stderr)
	}
	setRuleLimit(50)
	stdout.Reset()
	stderr.Reset()
	if code := cli.main(ctx, []string{"ur", "acl", "push", path}); code != urExitOk {
		t.Fatalf("named save on an exact ref: exit %d, %s", code, stderr)
	}
	state := client.State()
	if state.Base().GetConfigVersion() != 2 || !strings.Contains(stdout.String(), "in force from the base at") {
		t.Fatalf("confirmed save: %v, %s", state.Base(), stdout)
	}
	head, err := follower.Heads().ReadConfigHead(ctx, state.Base().GetConfigVersion(), state.Base().GetConfigHeadSha256())
	if err != nil || !bytes.Equal(head.File(sidecar.ConfigHeadPolicyPath), []byte(policy)) {
		t.Fatalf("confirmed head differs from the policy: %v", err)
	}
}
