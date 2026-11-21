package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/enginenet"
	"google.golang.org/protobuf/proto"
)

// An owner previews and confirms a named-member policy through the stock daemon and its EVS ref.
func testDaemonOwnerAclPlanAndConfirm(t *testing.T, ctx context.Context, running *sidecar.Sidecar, first *enginenet.BootstrapResult, net *sidecartest.Net, engines *enginenet.Engines) {
	t.Helper()
	quota := net.Fakes().Quota
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
	api := engines.Api()
	host := net.Process("evs").(interface{ Handler() http.Handler }).Handler()
	var oldHostWrites atomic.Int32
	api.ServeService("evs", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		isRead := req.Method == http.MethodGet || req.Method == http.MethodHead ||
			(req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/read"))
		if !isRead {
			oldHostWrites.Add(1)
		}
		serveEvsWithoutExactHead(t, host, w, req)
	}))
	t.Cleanup(func() { api.ServeService("evs", host) })
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
	follower := running.ConfigFollower()
	client := follower.Client()
	if client.Writer() != nil {
		t.Fatal("the stock follower installed a general or background config writer")
	}
	if oldHostWrites.Load() != 0 || client.State().Base().GetConfigVersion() != 1 {
		t.Fatalf("old host received %d writes, signed base %d", oldHostWrites.Load(), client.State().Base().GetConfigVersion())
	}
	api.ServeService("evs", host)
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
	// Between preview and terminal consent, an ordinary writer updates an independent config file.
	// Its push can land at version 2. The approval for version 1 can never save the policy on top.
	evs, err := testUrClientsOf(running).evsClient()
	if err != nil {
		t.Fatal(err)
	}
	names, err := proto.Marshal(&protocol.ConfigNameTable{Names: []*protocol.ConfigName{{SidecarId: running.Identity().SidecarId.Bytes(), Name: "team-device"}}})
	if err != nil {
		t.Fatal(err)
	}
	confirmationOpens = 0
	cli.openTty = func() (urTty, error) {
		confirmationOpens++
		if confirmationOpens == 2 {
			result, err := evs.Repo(first.ConfigRepoId).WritePaths(ctx, &sidecar.EvsWritePathsArgs{
				Writes: []*sidecar.EvsPathWrite{{Path: sidecar.ConfigHeadNamesPath, Content: bytes.NewReader(names)}},
			})
			if err != nil || result.Version != 2 {
				t.Fatalf("ordinary file-mode config update: %+v, %v", result, err)
			}
		}
		return &testTty{lines: []string{"yes"}}, nil
	}
	stdout.Reset()
	stderr.Reset()
	if code := cli.main(ctx, []string{"ur", "acl", "push", path}); code != urExitFailed || confirmationOpens != 2 ||
		!strings.Contains(stderr.String(), "preview again") || client.State().Base().GetConfigVersion() != 1 {
		t.Fatalf("stale approval: exit %d, %d terminal opens, %s", code, confirmationOpens, stderr)
	}
	ref, err := testUrClientsOf(running).headReader(nil)
	if err != nil {
		t.Fatal(err)
	}
	tip, err := ref.CurrentConfigHeadTip(ctx)
	if err != nil || tip.Version != 2 || !bytes.Equal(tip.Head.File(sidecar.ConfigHeadNamesPath), names) ||
		bytes.Equal(tip.Head.File(sidecar.ConfigHeadPolicyPath), []byte(policy)) {
		t.Fatalf("the ref after the stale confirmation: %+v, %v", tip, err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := cli.main(ctx, []string{"ur", "acl", "push", path}); code != urExitOk {
		t.Fatalf("fresh named ACL save through the stock daemon: exit %d, %s", code, stderr)
	}
	state := client.State()
	if state.Base().GetConfigVersion() != 3 || !strings.Contains(stdout.String(), "in force from the base at") {
		t.Fatalf("confirmed save: %v, %s", state.Base(), stdout)
	}
	head, err := follower.Heads().ReadConfigHead(ctx, state.Base().GetConfigVersion(), state.Base().GetConfigHeadSha256())
	if err != nil || !bytes.Equal(head.File(sidecar.ConfigHeadPolicyPath), []byte(policy)) || !bytes.Equal(head.File(sidecar.ConfigHeadNamesPath), names) {
		t.Fatalf("confirmed head differs from the approved policy or the independent update: %v", err)
	}
	walk, err := evs.Verifier().Walk(ctx, first.ConfigRepoId, first.MainRefId, 1, first.Chain, 3)
	if err != nil || len(walk) != 2 {
		t.Fatalf("reading the two signed EVS pushes: %v", err)
	}
	exact := uint32(protocol.EvsPushFlag_EVS_PUSH_EXACT_HEAD)
	if walk[0].Statement.Push.GetFlags()&exact != 0 || walk[1].Statement.Push.GetFlags()&exact == 0 ||
		walk[1].Statement.Push.GetBaseVersion() != 2 || !bytes.Equal(walk[1].Statement.Push.GetBaseChain(), tip.Chain[:]) ||
		!bytes.Equal(walk[1].Chain[:], state.Base().GetConfigHeadSha256()) {
		t.Fatal("the signed ACL push must name the confirmed parent and reach the published base")
	}
	if client.Writer() != nil {
		t.Fatal("a confirmed ACL save installed a general config writer")
	}
	t.Run("prepared commits and retries", func(t *testing.T) {
		// Deliver the newly published projection to the fixture's EVS and GKM gates.
		if err := engines.Sync(ctx, running.Identity().NetworkId); err != nil {
			t.Fatal(err)
		}
		testDaemonConfigHeadCommit(t, ctx, ref, evs.Repo(first.ConfigRepoId), running.Identity().SidecarId, state.Base().GetConfigVersion())
	})

}

// A disjoint write after an exact push was signed makes the commit itself stale. A lost receipt
// for a push that really landed can be replayed after another commit using the same signed bytes.
func testDaemonConfigHeadCommit(t *testing.T, ctx context.Context, ref *sidecar.EvsConfigHeadReader, repo *sidecar.EvsRepo, id sidecar.Id, base uint64) {
	t.Helper()
	writer := ref.ConfirmedAclConfigRef()
	prepare := func() *sidecar.ConfigHeadPush {
		tip, err := ref.CurrentConfigHeadTip(ctx)
		if err != nil {
			t.Fatal(err)
		}
		head, err := tip.Head.WithFile(sidecar.ConfigHeadPolicyPath, []byte(`{"grants":[]}`))
		if err != nil {
			t.Fatal(err)
		}
		push, err := writer.PrepareConfigHead(ctx, head, tip.Version)
		if err != nil {
			t.Fatal(err)
		}
		return push
	}
	writeName := func(name string, want uint64) {
		names, err := proto.Marshal(&protocol.ConfigNameTable{Names: []*protocol.ConfigName{{SidecarId: id.Bytes(), Name: name}}})
		if err != nil {
			t.Fatal(err)
		}
		result, err := repo.WritePaths(ctx, &sidecar.EvsWritePathsArgs{Writes: []*sidecar.EvsPathWrite{{Path: sidecar.ConfigHeadNamesPath, Content: bytes.NewReader(names)}}})
		if err != nil || result.Version != want {
			t.Fatalf("ordinary config write, expected version %d: %+v, %v", want, result, err)
		}
	}
	stale := prepare()
	writeName("after-preview", base+1)
	if err := writer.CommitConfigHead(ctx, stale); !errors.Is(err, sidecar.ErrConfigHeadConflict) {
		t.Fatalf("committing the older signed push: %v", err)
	}
	tip, err := ref.CurrentConfigHeadTip(ctx)
	if err != nil || tip.Version != base+1 || bytes.Equal(tip.Head.File(sidecar.ConfigHeadPolicyPath), stale.Head.File(sidecar.ConfigHeadPolicyPath)) {
		t.Fatalf("stale prepared push changed the ref: %+v, %v", tip, err)
	}
	fresh := prepare()
	if err := writer.CommitConfigHead(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	writeName("after-commit", base+3)
	if err := writer.CommitConfigHead(ctx, fresh); err != nil {
		t.Fatalf("retrying an applied exact push after the ref advanced: %v", err)
	}
	prefix, err := writer.ConfigHeadPushes(ctx, base, base+2)
	if err != nil || len(prefix) != 2 || !bytes.Equal(prefix[1], fresh.SignedPush) {
		t.Fatalf("reading the original two config pushes after the ref advanced: count %d, %v", len(prefix), err)
	}
	tip, err = ref.CurrentConfigHeadTip(ctx)
	if err != nil || tip.Version != base+3 {
		t.Fatalf("replaying the signed push changed the live ref: %+v, %v", tip, err)
	}
}

// An older EVS host serves the same verified ref history but omits the optional capability.
func serveEvsWithoutExactHead(t *testing.T, host http.Handler, w http.ResponseWriter, req *http.Request) {
	t.Helper()
	if !strings.HasSuffix(req.URL.Path, "/read") {
		host.ServeHTTP(w, req)
		return
	}
	rec := httptest.NewRecorder()
	host.ServeHTTP(rec, req)
	body := rec.Body.Bytes()
	if rec.Code == http.StatusOK {
		if len(body) < 4 || int(binary.BigEndian.Uint32(body[:4])) > len(body)-4 {
			t.Error("EVS returned an invalid first read frame")
			http.Error(w, "invalid test read frame", http.StatusBadGateway)
			return
		}
		end := 4 + int(binary.BigEndian.Uint32(body[:4]))
		frame := &protocol.EvsReadFrame{}
		if err := proto.Unmarshal(body[4:end], frame); err != nil || frame.GetHead() == nil {
			t.Errorf("EVS first read frame lacks a head: %v", err)
			http.Error(w, "missing test read head", http.StatusBadGateway)
			return
		}
		frame.Head.SupportsExactHead = false
		encoded, err := sidecar.EncodeEvsReadFrame(frame)
		if err != nil {
			t.Error(err)
			http.Error(w, "invalid test read head", http.StatusBadGateway)
			return
		}
		body = append(encoded, body[end:]...)
	}
	for k, values := range rec.Header() {
		for _, value := range values {
			w.Header().Add(k, value)
		}
	}
	w.Header().Del("Content-Length")
	w.WriteHeader(rec.Code)
	_, _ = w.Write(body)
}
