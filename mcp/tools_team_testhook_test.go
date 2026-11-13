//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind

// MCP-M3-14's privacy scan (§22.7, I-7), under the tag: no view's result, nor ur://acl/grants' or ur://approval/{id}'s,
// holds a secret of the world in any encoding. The secrets are each key the root reports to testHookSecret where it
// creates, derives or unwraps one, and the admission suite's own device and Delegation keys, which sidecartest derives
// from labels without passing the hook, so the scan names them itself.

package mcp

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A secret's forms a result could carry it in: raw, hex and each base64.
func testSecretForms(secret []byte) [][]byte {
	return [][]byte{
		secret,
		[]byte(hex.EncodeToString(secret)),
		[]byte(base64.StdEncoding.EncodeToString(secret)),
		[]byte(base64.RawStdEncoding.EncodeToString(secret)),
		[]byte(base64.URLEncoding.EncodeToString(secret)),
		[]byte(base64.RawURLEncoding.EncodeToString(secret)),
	}
}

// Every view and the two resources, over a config with an owner, a consented member, a Delegation and an agent it
// admitted: no secret of the world in any result.
func TestViewsHoldNoSecret(t *testing.T) {
	var stateLock sync.Mutex
	hooked := [][]byte{}
	t.Cleanup(func() { sidecar.SetTestHooks(nil) })
	sidecar.SetTestHooks(&sidecar.TestHooks{Secret: func(kind string, secret []byte) {
		stateLock.Lock()
		defer stateLock.Unlock()
		hooked = append(hooked, secret)
	}})
	env := newTestTeamToolEnv(t)
	owner := env.admission.Owner()
	tagId := env.admission.Id("tag scanned")
	env.admission.SetTagOwners(map[sidecar.Id]sidecar.Id{tagId: owner.MemberId})
	notAfter := env.admission.Clock().Now().Add(30 * 24 * time.Hour).UnixMilli()
	delegation := env.admission.Delegate(owner, "scanned agents", []sidecar.Id{tagId}, 2, notAfter)
	agent := env.admission.Device("scanned agent", sidecar.Id{})
	env.admission.MustLand(env.admission.SignByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT,
		env.admission.Admission(agent, []sidecar.Id{tagId}, false, notAfter, 0)))
	env.team.state = env.admission.State()
	memberDevice := env.admission.Device("team viewer first device", env.member)
	approvalId := sidecar.NewId()
	env.team.approvals[approvalId] = &sidecar.ApprovalStatus{
		ApprovalId: approvalId, State: sidecar.ApprovalStatusPending, ActionId: bytes.Repeat([]byte{5}, 32),
		NotAfter: env.clock.Now().Add(time.Hour), Uses: 1,
		Channels: []protocol.ApprovalChannel{protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE},
	}
	env.tools.allow(McpAccess{Action: protocol.AclAction_ACL_ACTION_DIAL, Resource: sidecar.AclResource{Kind: sidecar.AclResourceSocket, Name: "db"}})
	conn := env.conn("2025-11-25")

	agents := &mcpTeamAgentsOut{}
	testViewData(t, env.callTool(conn, "2025-11-25", "team_agents", map[string]any{}), agents)
	if len(agents.Delegations) != 1 || len(agents.Agents) != 1 {
		t.Fatalf("team_agents lists %d Delegations and %d agents, so the scan would miss keys it holds", len(agents.Delegations), len(agents.Agents))
	}
	results := [][]byte{}
	calls := []struct {
		tool      string
		arguments map[string]any
	}{
		{tool: "team_members", arguments: map[string]any{}},
		{tool: "team_agents", arguments: map[string]any{}},
		{tool: "acl_grants", arguments: map[string]any{}},
		{tool: "acl_check", arguments: map[string]any{"action": "dial", "resource": "sock:db"}},
	}
	for _, call := range calls {
		response := env.callTool(conn, "2025-11-25", call.tool, call.arguments)
		if response.Error != nil {
			t.Fatalf("%s: %s", call.tool, response.Error.Message)
		}
		results = append(results, response.Result)
	}
	for _, uri := range []string{McpAclGrantsUri, McpApprovalUri(approvalId)} {
		read := conn.call("resources/read", map[string]any{"uri": uri})
		if read.Error != nil {
			t.Fatalf("%s: %s", uri, read.Error.Message)
		}
		results = append(results, read.Result)
	}

	stateLock.Lock()
	secrets := slices.Clone(hooked)
	stateLock.Unlock()
	for _, key := range []ed25519.PrivateKey{owner.Key, memberDevice.Key, delegation.Key, agent.Key} {
		secrets = append(secrets, key.Seed(), []byte(key))
	}
	for _, result := range results {
		for _, secret := range secrets {
			// a key is 16 bytes or more; a shorter run would match text by chance
			if len(secret) < 16 {
				continue
			}
			for _, form := range testSecretForms(secret) {
				if bytes.Contains(result, form) {
					t.Errorf("a result holds a secret: %s", result)
				}
			}
		}
	}
}
