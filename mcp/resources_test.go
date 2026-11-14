//go:build !js && !ios && !android && !sdk_mobile_bind

// MCP-M3-14's resource map: the family whose template matches judges a subscription at once, so a subscription on a
// refused repo refuses at subscribe, never at its first event, leases nothing and holds nothing a later change could
// reach; a URI no family names is not found. The families' reads and notifications are tools_team_test.go's and
// resources_evs_test.go's.

package mcp

import (
	"encoding/json"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Whether conn has been told uri changed.
func testResourceUpdatedSeen(conn *testMcpConn, uri string) bool {
	conn.stateLock.Lock()
	notifications := append([]json.RawMessage{}, conn.notifications...)
	conn.stateLock.Unlock()
	for _, notification := range notifications {
		parsed := struct {
			Method string `json:"method"`
			Params struct {
				Uri string `json:"uri"`
			} `json:"params"`
		}{}
		json.Unmarshal(notification, &parsed)
		if parsed.Method == "notifications/resources/updated" && parsed.Params.Uri == uri {
			return true
		}
	}
	return false
}

// A subscription on a repo the guard refuses refuses at subscribe: a secret repo, the config repo, the search index's
// files, the team directory and a repo the network does not hold, and so does one the policy does not let this
// sidecar read. None leases its path, and a change of a refused URI reaches no session.
func TestSubscribeRefusedOnSecret(t *testing.T) {
	env := newTestEvsToolEnv(t)
	directory := sidecar.NewId()
	unallowed := sidecar.NewId()
	env.tools.repoKinds[directory] = protocol.RepoKind_REPO_KIND_DIRECTORY
	env.tools.repoKinds[unallowed] = protocol.RepoKind_REPO_KIND_GENERAL
	env.evs.repos[directory] = newFakeMcpEvsRepo()
	env.evs.repos[unallowed] = newFakeMcpEvsRepo()
	env.tools.allow(McpAccess{Action: protocol.AclAction_ACL_ACTION_READ, Resource: sidecar.AclResource{Kind: sidecar.AclResourceRepo, RepoId: directory}})
	conn := env.conn("2025-11-25")
	cases := []struct {
		uri         string
		messagePart string
	}{
		{uri: McpEvsUri(env.secret, "key.pem"), messagePart: "secret repo"},
		{uri: McpEvsUri(env.config, "acl.hujson"), messagePart: "config repo"},
		{uri: McpEvsUri(env.general, ".ur-index/manifest"), messagePart: "search index"},
		{uri: McpEvsUri(directory, "announcements/a.json"), messagePart: "team directory"},
		{uri: McpEvsUri(env.other, "a.md"), messagePart: "does not hold"},
		{uri: McpEvsUri(unallowed, "a.md"), messagePart: "does not allow"},
	}
	for _, c := range cases {
		wantMcpError(t, conn.call("resources/subscribe", map[string]any{"uri": c.uri}), McpCodeRefused, c.messagePart)
	}
	for repoId, repo := range env.evs.repos {
		repo.stateLock.Lock()
		leased := len(repo.subscribed)
		repo.stateLock.Unlock()
		if leased != 0 {
			t.Errorf("a refused subscription leased repo %s", repoId)
		}
	}

	// a change of a refused URI goes nowhere: sent before an admitted one, it would have arrived first
	refused := McpEvsUri(env.secret, "key.pem")
	if err := env.resources.Updated(t.Context(), refused); err != nil {
		t.Fatal(err)
	}
	admitted := McpEvsUri(env.general, "notes.md")
	if response := conn.call("resources/subscribe", map[string]any{"uri": admitted}); response.Error != nil {
		t.Fatalf("subscribe: %s", response.Error.Message)
	}
	if err := env.resources.Updated(t.Context(), admitted); err != nil {
		t.Fatal(err)
	}
	testAwaitResourceUpdated(t, conn, admitted)
	if testResourceUpdatedSeen(conn, refused) {
		t.Error("a refused subscription's URI was sent its change")
	}

	notFound := conn.call("resources/subscribe", map[string]any{"uri": "ur://nothing/here"})
	if notFound.Error == nil || notFound.Error.Code != gomcp.CodeResourceNotFound {
		t.Errorf("a URI no family names: %+v", notFound.Error)
	}
}
