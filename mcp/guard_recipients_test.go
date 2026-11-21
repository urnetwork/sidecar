//go:build !js && !ios && !android && !sdk_mobile_bind

// The protected recipient family through the EVS and search tools' common guard.
package mcp

import (
	"context"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A hosted network's verified group view, or its refusal while mailcfg cannot be read.
type testMcpRecipientNetwork struct {
	*fakeMcpEvsNetwork
	groups map[sidecar.Id]bool
	err    error
}

func (self *testMcpRecipientNetwork) MailGroupInboxes(ctx context.Context) (map[sidecar.Id]bool, error) {
	return self.groups, self.err
}

// A group inbox and an unclassified repo withhold the entire family, including in listings and subscriptions.
func TestMcpApprovedRecipientsRequireAConfirmedOrdinaryRepo(t *testing.T) {
	env := newTestEvsToolEnv(t)
	host := &testMcpRecipientNetwork{fakeMcpEvsNetwork: env.evs, groups: map[sidecar.Id]bool{env.general: true}}
	env.daemon.hostNetwork(env.networkId, host)
	env.putWith(env.general, "rcpt/a/file", "ordinary file", env.tools.identity.SidecarId, testEvsCleanProvenance())
	env.evs.repos[env.general].children[""] = []string{"docs", "rcpt"}
	conn := env.conn("2025-11-25")
	uri := McpEvsUri(env.general, "rcpt/a/file")
	for _, unavailable := range []bool{false, true} {
		if unavailable {
			host.groups, host.err = nil, errors.New("no verified mailcfg")
		}
		for _, method := range []string{"resources/read", "resources/subscribe"} {
			wantMcpError(t, conn.call(method, map[string]any{"uri": uri}), McpCodeRefused, "approved-recipient")
		}
		for _, tool := range []string{"evs_list", "evs_read", "evs_history"} {
			wantMcpError(t, env.callTool(conn, "2025-11-25", tool, map[string]any{
				"repo": env.general.String(), "path": "rcpt/a",
			}), McpCodeRefused, "approved-recipient")
		}
		wantMcpError(t, env.callTool(conn, "2025-11-25", "evs_write", map[string]any{
			"repo": env.general.String(), "path": "rcpt/new", "content": "sample", "base_version": 0,
		}), McpCodeRefused, "approved-recipient")
		wantMcpError(t, env.callTool(conn, "2025-11-25", "evs_delete", map[string]any{
			"repo": env.general.String(), "path": "rcpt/a/file", "base_version": 1,
		}), McpCodeRefused, "approved-recipient")
		var listing mcpEvsListOut
		testViewData(t, env.callTool(conn, "2025-11-25", "evs_list", map[string]any{"repo": env.general.String()}), &listing)
		if len(listing.Entries) != 1 || listing.Entries[0].Name != "docs" {
			t.Fatal("listing revealed the protected family")
		}
		call := &McpCall{Network: host}
		call.bindRecipientGuard(t.Context())
		targets, err := mcpSearchTargets(call, []string{env.general.String()}, "rcpt/a")
		if err != nil || McpGuard(targets) == nil {
			t.Fatal("search admitted the protected family")
		}
	}
	host.groups, host.err = map[sidecar.Id]bool{}, nil
	testResourceEnvelope(t, conn.call("resources/read", map[string]any{"uri": uri}), uri)
	target := McpTarget{Kind: McpTargetRepo, RepoKind: protocol.RepoKind_REPO_KIND_MAILBOX, Operation: McpRepoRead, Ref: "other", Path: "rcpt", OrdinaryFileRepo: true}
	if McpGuardAdmits(target) {
		t.Fatal("a mailbox admitted its recipient family on another ref")
	}
	target.Path = "rcpt-notes"
	if !McpGuardAdmits(target) {
		t.Fatal("a sibling of the recipient directory was refused")
	}
}
