//go:build !js && !ios && !android && !sdk_mobile_bind

// socket_listen's expires (owner decision 687; QD-1172) on the tool framework, with the daemon's sockets and the gate
// faked as tools_socket_test.go fakes them, over a real grant filer whose requests rule gives at most 7 days:
//
//   - an outward listen asking an end 3 days on files its action for that end, presents the same action asked again a
//     minute later, and once a person approves names the grant its use activated and when it ends, those 3 days;
//   - one asking an end 30 days on is refused before the gate, the error's text naming the rule's maxExpiry and its
//     data the 7 days, while an end 7 days on reaches the gate;
//   - a word, a time already past and now itself are refused before anything acts, covered or not;
//   - the action is kept per end asked, so another end files its own action and the first end asked again finds the
//     first;
//   - a covered listen names its covering grant's end as the network's grants hold it, and none for a grant with none.
//
// The real gate's half, that the activated grant ends at the end asked, is socket_listen_grant's own
// (listen_expires_surfaces_test.go). Synthetic values only.

package mcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The longest the tests' requests rule gives, as the implicit document's tls/ and smtp/ rule does.
const testSocketListenRuleMax = 7 * 24 * time.Hour

// The network given a grant filer over an engine holding a requests rule by which its member asks listen on name, by
// its token path under the network's current K_sock, and approves it itself, for at most maxExpiry. The rule's id.
func (self *fakeMcpSocketNetwork) useRequestsWithin(t *testing.T, name string, maxExpiry time.Duration) []byte {
	t.Helper()
	tokenPath, err := self.ring.Current().TokenPath(name)
	if err != nil {
		t.Fatal(err)
	}
	ruleId := testSocketGrantId("a listen's requests rule within " + maxExpiry.String()).Bytes()
	rows := &protocol.AclRows{HasDocument: true, Requests: []*protocol.AclRequestRule{{
		RuleId:           ruleId,
		SrcAtoms:         [][]byte{sidecar.AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()},
		Targets:          []*protocol.AclTarget{{SocketTokens: [][]byte{tokenPath}}},
		Actions:          []uint32{uint32(protocol.AclAction_ACL_ACTION_LISTEN)},
		ApproverAtoms:    [][]byte{sidecar.AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF).Bytes()},
		MaxExpirySeconds: int64(maxExpiry / time.Second),
	}}}
	sidecarId := self.Identity().SidecarId
	state, err := sidecar.NewAclState(rows, &testSocketAclView{sidecarId: sidecarId, memberId: testSocketGrantId("the network's member")})
	if err != nil {
		t.Fatal(err)
	}
	engine := sidecar.NewAclEngine(sidecarId, nil, nil, nil)
	if err := engine.Install(state, nil); err != nil {
		t.Fatal(err)
	}
	self.grants = sidecar.NewAclGrantFiler(nil, engine)
	return ruleId
}

// The tool network with the grants in force a covered listen reads its grant's end from (mcpSocketGrantList).
type testGrantListSocketNetwork struct {
	*fakeMcpSocketNetwork
	grants []sidecar.AclGrantInfo
}

func (self *testGrantListSocketNetwork) Grants(now time.Time) []sidecar.AclGrantInfo {
	return self.grants
}

// An end of the test's clock d on, to the second RFC 3339 carries.
func testSocketListenEnd(env *testSocketToolEnv, d time.Duration) time.Time {
	return env.clock.Now().Add(d).UTC().Truncate(time.Second)
}

// An outward listen asking an end 3 days on under a rule giving at most 7 files its action for that end, presents the
// same action a minute later, and once a person approves names the grant its use activated and that end.
func TestSocketListenAsksItsExpires(t *testing.T) {
	env := newTestSocketToolEnv(t, nil)
	ruleId := env.network.useRequestsWithin(t, "db/primary", testSocketListenRuleMax)
	approvalId := sidecar.NewId()
	env.network.authorize = &sidecar.ApprovalPendingError{ApprovalId: approvalId}
	conn := env.conn("2025-06-18")
	end := testSocketListenEnd(env, 3*24*time.Hour)
	listen := map[string]any{"name": "db/primary", "local_port": 5432, "expires": end.Format(time.RFC3339)}
	out := &mcpSocketListenOut{}
	testSocketToolData(t, env.callTool(conn, "2025-06-18", "socket_listen", listen), out)
	if out.Status != "approval_pending" || out.ApprovalId != approvalId.String() || out.Expires != "" {
		t.Fatalf("the first listen: %+v", out)
	}
	filed := env.network.asked(t, 0)
	if !bytes.Equal(filed.Action.GetRuleId(), ruleId) || filed.Action.GetExpiresMillis() != end.UnixMilli() {
		t.Fatalf("the filed action: %+v", filed.Action)
	}

	env.clock.Advance(time.Minute)
	grantId := bytes.Repeat([]byte{0x6c}, sha256.Size)
	env.network.authorize = nil
	env.network.outcome = &sidecar.SidecarOutcome{State: sidecar.ApprovalOutcomeDone, EffectRef: grantId}
	testSocketToolData(t, env.callTool(conn, "2025-06-18", "socket_listen", listen), out)
	if out.Status != "listening" || out.GrantId != hex.EncodeToString(grantId) || out.Expires != end.Format(time.RFC3339) {
		t.Errorf("the approved listen: %+v", out)
	}
	if spent := env.network.asked(t, 1); !bytes.Equal(spent.Bytes, filed.Bytes) {
		t.Error("the approved listen presented another action than its request's")
	}
	if asked := env.sockets.listensAsked(); len(asked) != 1 || asked[0] != "db/primary 127.0.0.1:5432" {
		t.Errorf("listens %q", asked)
	}
}

// An end 30 days on under a rule giving at most 7 is refused before the gate, listening on nothing: the error's
// constant text names the rule's maxExpiry, and its data the 7 days. An end 7 days on reaches the gate.
func TestSocketListenPastTheMaxExpiryIsRefusedNamingIt(t *testing.T) {
	env := newTestSocketToolEnv(t, nil)
	env.network.useRequestsWithin(t, "db/primary", testSocketListenRuleMax)
	conn := env.conn("2025-06-18")
	response := env.callTool(conn, "2025-06-18", "socket_listen", map[string]any{
		"name": "db/primary", "local_port": 5432, "expires": testSocketListenEnd(env, 30*24*time.Hour).Format(time.RFC3339),
	})
	wantMcpError(t, response, McpCodeRefused, "maxExpiry")
	data := &McpErrorData{}
	if err := json.Unmarshal(response.Error.Data, data); err != nil || data.MaxExpiryMillis != testSocketListenRuleMax.Milliseconds() || data.Retryable {
		t.Errorf("the refusal's data %s: %v", response.Error.Data, err)
	}
	if len(env.network.authorized) != 0 || len(env.sockets.listensAsked()) != 0 || len(env.sink.sunk()) != 0 {
		t.Error("a listen past the maximum acted")
	}

	approvalId := sidecar.NewId()
	env.network.authorize = &sidecar.ApprovalPendingError{ApprovalId: approvalId}
	week := env.clock.Now().Add(testSocketListenRuleMax).UTC().Truncate(time.Second)
	out := &mcpSocketListenOut{}
	testSocketToolData(t, env.callTool(conn, "2025-06-18", "socket_listen", map[string]any{
		"name": "db/primary", "local_port": 5432, "expires": week.Format(time.RFC3339),
	}), out)
	if out.Status != "approval_pending" || env.network.asked(t, 0).Action.GetExpiresMillis() != week.UnixMilli() {
		t.Errorf("an end at the maximum: %+v", out)
	}
}

// A word, a time already past and now itself are refused before anything acts, on an outward listen and a covered one
// alike.
func TestSocketListenRefusesABadExpires(t *testing.T) {
	env := newTestSocketToolEnv(t, nil)
	env.network.useRequestsWithin(t, "db/primary", testSocketListenRuleMax)
	conn := env.conn("2025-06-18")
	bad := []string{"tomorrow", "3d", env.clock.Now().Add(-time.Hour).UTC().Format(time.RFC3339), env.clock.Now().UTC().Truncate(time.Second).Format(time.RFC3339)}
	for _, expires := range bad {
		wantMcpError(t, env.callTool(conn, "2025-06-18", "socket_listen", map[string]any{"name": "db/primary", "local_port": 5432, "expires": expires}),
			McpCodeInvalidArguments, "expires")
	}
	env.network.allow(McpAccess{Action: protocol.AclAction_ACL_ACTION_LISTEN, Resource: sidecar.AclResource{Kind: sidecar.AclResourceSocket, Name: "db/primary"}})
	for _, expires := range bad {
		wantMcpError(t, env.callTool(conn, "2025-06-18", "socket_listen", map[string]any{"name": "db/primary", "local_port": 5432, "expires": expires}),
			McpCodeInvalidArguments, "expires")
	}
	if len(env.network.authorized) != 0 || len(env.sockets.listensAsked()) != 0 {
		t.Error("a listen with a bad expires acted")
	}
}

// The action is kept per end asked: an end 5 days on after one 3 days on files its own action, where a keeper by name
// and port alone would present the 3 days', and the 3 days asked again a minute on find the first.
func TestSocketListenKeepsAnActionPerEndAsked(t *testing.T) {
	env := newTestSocketToolEnv(t, nil)
	env.network.useRequestsWithin(t, "db/primary", testSocketListenRuleMax)
	env.network.authorize = &sidecar.ApprovalPendingError{ApprovalId: sidecar.NewId()}
	conn := env.conn("2025-06-18")
	threeDays := map[string]any{"name": "db/primary", "local_port": 5432, "expires": testSocketListenEnd(env, 3*24*time.Hour).Format(time.RFC3339)}
	fiveDays := map[string]any{"name": "db/primary", "local_port": 5432, "expires": testSocketListenEnd(env, 5*24*time.Hour).Format(time.RFC3339)}
	out := &mcpSocketListenOut{}
	testSocketToolData(t, env.callTool(conn, "2025-06-18", "socket_listen", threeDays), out)
	env.clock.Advance(time.Minute)
	testSocketToolData(t, env.callTool(conn, "2025-06-18", "socket_listen", fiveDays), out)
	env.clock.Advance(time.Minute)
	testSocketToolData(t, env.callTool(conn, "2025-06-18", "socket_listen", threeDays), out)
	first, longer, again := env.network.asked(t, 0), env.network.asked(t, 1), env.network.asked(t, 2)
	if bytes.Equal(longer.Bytes, first.Bytes) || longer.Action.GetExpiresMillis() <= first.Action.GetExpiresMillis() {
		t.Errorf("the 5 days presented the 3 days' action: %+v", longer.Action)
	}
	if !bytes.Equal(again.Bytes, first.Bytes) {
		t.Error("the 3 days asked again presented another action than the first")
	}
}

// A covered listen runs as W and names its covering grant's end as the network's grants in force hold it, and no end
// for a covering grant with none, a document's rule.
func TestSocketListenCoveredNamesItsGrantsEnd(t *testing.T) {
	env := newTestSocketToolEnv(t, nil)
	end := testSocketListenEnd(env, 2*24*time.Hour)
	network := &testGrantListSocketNetwork{fakeMcpSocketNetwork: env.network, grants: []sidecar.AclGrantInfo{
		{GrantId: []byte{0x01}, ExpiresMs: end.Add(time.Hour).UnixMilli()},
		{GrantId: env.network.grantId, ExpiresMs: end.UnixMilli()},
	}}
	env.daemon.hostNetwork(env.networkId, network)
	env.network.allow(McpAccess{Action: protocol.AclAction_ACL_ACTION_LISTEN, Resource: sidecar.AclResource{Kind: sidecar.AclResourceSocket, Name: "db/primary"}})
	conn := env.conn("2025-06-18")
	out := &mcpSocketListenOut{}
	testSocketToolData(t, env.callTool(conn, "2025-06-18", "socket_listen", map[string]any{"name": "db/primary", "local_port": 5432}), out)
	if out.Status != "listening" || out.GrantId != hex.EncodeToString(env.network.grantId) || out.Expires != end.Format(time.RFC3339) {
		t.Errorf("a covered listen: %+v", out)
	}
	if len(env.network.authorized) != 0 {
		t.Error("a covered listen went through the gate")
	}

	network.grants = []sidecar.AclGrantInfo{{GrantId: env.network.grantId}}
	env.sockets.Unlisten(env.networkId, "db/primary")
	noEnd := &mcpSocketListenOut{}
	testSocketToolData(t, env.callTool(conn, "2025-06-18", "socket_listen", map[string]any{"name": "db/primary", "local_port": 5432}), noEnd)
	if noEnd.Status != "listening" || noEnd.GrantId != hex.EncodeToString(env.network.grantId) || noEnd.Expires != "" {
		t.Errorf("a covered listen on a grant with no end: %+v", noEnd)
	}
}
