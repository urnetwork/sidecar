//go:build !js && !ios && !android && !sdk_mobile_bind

// MCP-M3-14: the team and acl views answer from a real config log where the config repo's own reads are refused,
// carry ids and roles and never a key, validate at every MCP version, and ur://acl/grants and ur://approval/{id} are
// subscribable, each change going out as its URI alone.

package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A tool network with a verified config and grants, and an approval state.
type fakeMcpTeamNetwork struct {
	*fakeMcpToolNetwork
	state     *sidecar.ConfigState
	grants    []sidecar.AclGrantInfo
	approvals map[sidecar.Id]*sidecar.ApprovalStatus
}

func (self *fakeMcpTeamNetwork) ConfigState() *sidecar.ConfigState {
	return self.state
}

func (self *fakeMcpTeamNetwork) Grants(now time.Time) []sidecar.AclGrantInfo {
	return self.grants
}

func (self *fakeMcpTeamNetwork) ApprovalStatus(ctx context.Context, approvalId sidecar.Id) (*sidecar.ApprovalStatus, error) {
	status, ok := self.approvals[approvalId]
	if !ok {
		return nil, sidecar.ErrApprovalUnknown
	}
	return status, nil
}

// A config log on T2's fake api: an owner, and a member whose first device is consented.
func newTestTeamAdmissionNet(t *testing.T) *sidecartest.AdmissionNet {
	t.Helper()
	blobs := sidecartest.NewFakeBlobs(sidecartest.NewFakeClock(sidecartest.DefaultClockStart()), sidecartest.NewFaultQueue(), nil, sidecartest.DefaultFakeBlobsSettings())
	cluster, err := blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	net := sidecartest.NewAdmissionNet(t, &sidecartest.AdmissionTier{
		Cluster: cluster,
		NewApi: func(clock sidecar.Clock, cluster sidecar.BlobCluster) sidecartest.AdmissionApi {
			return sidecartest.FakeApiAdmission(sidecartest.NewFakeApi(t.Context(), clock, sidecartest.NewFaultQueue(), nil, cluster, nil))
		},
	})
	t.Cleanup(net.Close)
	return net
}

// The tool env with the views installed over a real config.
type testTeamToolEnv struct {
	*testToolEnv
	team      *fakeMcpTeamNetwork
	admission *sidecartest.AdmissionNet
	member    sidecar.Id
	resources *McpResources
}

func newTestTeamToolEnv(t *testing.T) *testTeamToolEnv {
	t.Helper()
	env := &testTeamToolEnv{testToolEnv: newTestToolEnv(t), admission: newTestTeamAdmissionNet(t)}
	env.member, _ = env.admission.ConsentedMember("team viewer")
	env.team = &fakeMcpTeamNetwork{
		fakeMcpToolNetwork: env.tools,
		state:              env.admission.State(),
		approvals:          map[sidecar.Id]*sidecar.ApprovalStatus{},
		grants: []sidecar.AclGrantInfo{{
			GrantId: bytes.Repeat([]byte{7}, 32), SourceRuleId: bytes.Repeat([]byte{8}, 16),
			Actions: []protocol.AclAction{protocol.AclAction_ACL_ACTION_DIAL},
			Targets: []*protocol.AclTarget{{SidecarId: sidecar.NewId().Bytes()}},
		}},
	}
	env.daemon.hostNetwork(env.networkId, env.team)
	catalog := NewMcpCatalog(env.server.settings.Mcp, env.clock, nil)
	addTeamTools(catalog)
	catalog.Install(env.server)
	env.resources = NewMcpResources(t.Context(), env.server)
	addCoreMcpResources(env.resources)
	env.resources.Install()
	return env
}

// A view's data.
func testViewData(t *testing.T, response *testMcpResponse, data any) *mcpResultEnvelope {
	t.Helper()
	envelope := testEnvelopeOf(t, response)
	if err := json.Unmarshal(envelope.Data, data); err != nil {
		t.Fatalf("data %s: %v", envelope.Data, err)
	}
	return envelope
}

// The views answer where an evs read of the config repo is refused (QD-205; §22.7's actions row): ids and roles from
// the verified config, its version named, trust member.
func TestViewsAnswerWhereConfigReadRefused(t *testing.T) {
	env := newTestTeamToolEnv(t)
	if refusal := McpGuard([]McpTarget{{Kind: McpTargetRepo, RepoKind: protocol.RepoKind_REPO_KIND_CONFIG, Operation: McpRepoRead, Ref: "main", Path: "acl.hujson"}}); refusal == nil {
		t.Fatal("an evs read of the config repo passes the guard")
	}
	conn := env.conn("2025-11-25")
	members := &mcpTeamMembersOut{}
	envelope := testViewData(t, env.callTool(conn, "2025-11-25", "team_members", map[string]any{}), members)
	if envelope.Trust != McpTrustMember || members.Version != env.admission.State().Pin().GetVersion() {
		t.Errorf("trust %s, version %d", envelope.Trust, members.Version)
	}
	found := false
	for _, member := range members.Members {
		if member.MemberId == env.member.String() {
			found = member.Role == "member" && len(member.Devices) == 1 && member.Devices[0].Consented && member.Devices[0].ApprovalCapable
		}
	}
	if !found {
		t.Errorf("the member and its consented device are not listed: %+v", members.Members)
	}
	filtered := &mcpTeamMembersOut{}
	testViewData(t, env.callTool(conn, "2025-11-25", "team_members", map[string]any{"member": env.member.String()}), filtered)
	if len(filtered.Members) != 1 {
		t.Errorf("a member filter lists %d", len(filtered.Members))
	}
	agents := &mcpTeamAgentsOut{}
	testViewData(t, env.callTool(conn, "2025-11-25", "team_agents", map[string]any{}), agents)
	if agents.Agents == nil || agents.Delegations == nil {
		t.Errorf("agents %+v", agents)
	}
	grants := &mcpAclGrantsOut{}
	testViewData(t, env.callTool(conn, "2025-11-25", "acl_grants", map[string]any{"action": "dial"}), grants)
	if len(grants.Grants) != 1 || grants.Grants[0].Actions[0] != "dial" || !strings.HasPrefix(grants.Grants[0].Targets[0], "sidecar:") {
		t.Errorf("grants %+v", grants.Grants)
	}
	none := &mcpAclGrantsOut{}
	testViewData(t, env.callTool(conn, "2025-11-25", "acl_grants", map[string]any{"action": "publish"}), none)
	if len(none.Grants) != 0 {
		t.Errorf("an action filter lists %d", len(none.Grants))
	}
	env.tools.allow(McpAccess{Action: protocol.AclAction_ACL_ACTION_LISTEN, Resource: sidecar.AclResource{Kind: sidecar.AclResourceSocket, Name: "db"}})
	check := &mcpAclCheckOut{}
	testViewData(t, env.callTool(conn, "2025-11-25", "acl_check", map[string]any{"action": "listen", "resource": "sock:db"}), check)
	if !check.Allowed {
		t.Errorf("check %+v", check)
	}
	denied := &mcpAclCheckOut{}
	testViewData(t, env.callTool(conn, "2025-11-25", "acl_check", map[string]any{"action": "listen", "resource": "sock:other"}), denied)
	if denied.Allowed || denied.Reason != "no_grant" {
		t.Errorf("denied %+v", denied)
	}
	wantMcpError(t, env.callTool(conn, "2025-11-25", "acl_check", map[string]any{"action": "fly", "resource": "sock:db"}), McpCodeInvalidArguments, "action is one of")
}

// No view carries a key: every admitted device's identity key, in each form, is absent from every result.
func TestViewsCarryNoKey(t *testing.T) {
	env := newTestTeamToolEnv(t)
	conn := env.conn("2025-11-25")
	state := env.admission.State()
	keys := [][]byte{}
	for _, sidecarId := range state.SidecarIds() {
		if key := state.IdentityKey(sidecarId); 0 < len(key) {
			keys = append(keys, key)
		}
	}
	if len(keys) < 2 {
		t.Fatalf("keys %d", len(keys))
	}
	results := [][]byte{}
	for _, tool := range []string{"team_members", "team_agents", "acl_grants"} {
		response := env.callTool(conn, "2025-11-25", tool, map[string]any{})
		if response.Error != nil {
			t.Fatalf("%s: %s", tool, response.Error.Message)
		}
		results = append(results, response.Result)
	}
	read := conn.call("resources/read", map[string]any{"uri": McpAclGrantsUri})
	if read.Error != nil {
		t.Fatalf("ur://acl/grants: %s", read.Error.Message)
	}
	results = append(results, read.Result)
	for _, result := range results {
		for _, key := range keys {
			for _, form := range []string{string(key), hex.EncodeToString(key), base64.StdEncoding.EncodeToString(key), base64.RawURLEncoding.EncodeToString(key)} {
				if bytes.Contains(result, []byte(form)) {
					t.Errorf("a result holds an identity key: %s", result)
				}
			}
		}
	}
}

// Each view validates at every MCP version, against the wire schema and its outputSchema.
func TestTeamToolsSchemasAtEveryVersion(t *testing.T) {
	env := newTestTeamToolEnv(t)
	calls := []struct {
		tool      string
		arguments map[string]any
	}{
		{tool: "team_members", arguments: map[string]any{}},
		{tool: "team_agents", arguments: map[string]any{}},
		{tool: "acl_grants", arguments: map[string]any{}},
		{tool: "acl_check", arguments: map[string]any{"action": "dial", "resource": "sock:db"}},
	}
	for _, version := range testMcpVersions {
		conn := env.conn(version)
		for _, call := range calls {
			response := env.callTool(conn, version, call.tool, call.arguments)
			if response.Error != nil {
				t.Fatalf("%s %s: %s", version, call.tool, response.Error.Message)
			}
			testValidateWire(t, version, response.Result)
			result := testWireResult{}
			json.Unmarshal(response.Result, &result)
			var structured any
			json.Unmarshal(result.StructuredContent, &structured)
			if err := testOutputSchema(t, conn, version, call.tool).Validate(structured); err != nil {
				t.Errorf("%s %s: structuredContent against outputSchema: %v", version, call.tool, err)
			}
		}
	}
}

// Waits for a resources/updated notification of uri on conn, failing past the test's bound.
func testAwaitResourceUpdated(t *testing.T, conn *testMcpConn, uri string) {
	t.Helper()
	deadline := time.Now().Add(mcpTestTimeout)
	for time.Now().Before(deadline) {
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
				if strings.Contains(string(notification), `"title"`) || strings.Contains(string(notification), `"contents"`) {
					t.Errorf("an update carries more than its uri: %s", notification)
				}
				return
			}
		}
		// the notification arrives on the reader's goroutine: wait on a round trip, not a sleep
		conn.call("ping", map[string]any{})
	}
	t.Fatalf("no update of %s", uri)
}

// ur://acl/grants is subscribable, and an entry the network's config applies goes out as its update.
func TestGrantsChangeNotifies(t *testing.T) {
	env := newTestTeamToolEnv(t)
	follower := env.admission.Follower()
	remove := env.resources.WatchConfig(follower)
	defer remove()
	conn := env.conn("2025-11-25")
	if response := conn.call("resources/subscribe", map[string]any{"uri": McpAclGrantsUri}); response.Error != nil {
		t.Fatalf("subscribe: %s", response.Error.Message)
	}
	env.admission.ConsentedMember("a new member")
	if err := follower.CatchUp(t.Context()); err != nil {
		t.Fatal(err)
	}
	testAwaitResourceUpdated(t, conn, McpAclGrantsUri)
}

// ur://approval/{id} reads one of this sidecar's approvals by ids and states, and a decision's update goes out as
// its URI alone; a URI no family names is not found at subscribe.
func TestApprovalResourceNotifiesOnDecision(t *testing.T) {
	env := newTestTeamToolEnv(t)
	approvalId := sidecar.NewId()
	env.team.approvals[approvalId] = &sidecar.ApprovalStatus{
		ApprovalId: approvalId, State: sidecar.ApprovalStatusApproved, ActionId: bytes.Repeat([]byte{3}, 32),
		NotAfter: env.clock.Now().Add(time.Hour), Uses: 1,
		Channels: []protocol.ApprovalChannel{protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS},
	}
	conn := env.conn("2025-11-25")
	uri := McpApprovalUri(approvalId)
	if response := conn.call("resources/subscribe", map[string]any{"uri": uri}); response.Error != nil {
		t.Fatalf("subscribe: %s", response.Error.Message)
	}
	read := conn.call("resources/read", map[string]any{"uri": uri})
	if read.Error != nil {
		t.Fatalf("read: %s", read.Error.Message)
	}
	if !strings.Contains(string(read.Result), `\"state\":\"approved\"`) || !strings.Contains(string(read.Result), `\"channels\":[\"harness\"]`) {
		t.Errorf("read %s", read.Result)
	}
	env.resources.Notify(uri)
	testAwaitResourceUpdated(t, conn, uri)
	unknown := conn.call("resources/read", map[string]any{"uri": McpApprovalUri(sidecar.NewId())})
	if unknown.Error == nil {
		t.Error("an unknown approval reads")
	}
	if response := conn.call("resources/subscribe", map[string]any{"uri": "ur://nothing/here"}); response.Error == nil {
		t.Error("a URI no family names is subscribed")
	}
}

// The registered families are §16.5's this build links: the approval and grants resources.
func TestResourceFamiliesRegistered(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	server := newTestMcpServer(newFakeMcpDaemon(), clock)
	resources := NewDaemonMcpResources(t.Context(), server)
	templates := resources.Templates()
	for _, want := range []string{"ur://acl/grants", "ur://approval/{id}"} {
		found := false
		for _, template := range templates {
			found = found || template == want
		}
		if !found {
			t.Errorf("%s is not registered: %q", want, templates)
		}
	}
	family := &mcpResourceFamily{}
	family.parts, _ = parseMcpTemplate("ur://evs/{repo}/{+path}")
	variables, ok := family.match("ur://evs/01ARZ3NDEKTSV4RRFFQ69G5FAV/docs/a%20b.md")
	if !ok || variables["repo"] != "01ARZ3NDEKTSV4RRFFQ69G5FAV" || variables["path"] != "docs/a b.md" {
		t.Errorf("match %v %t", variables, ok)
	}
	if _, ok := family.match("ur://evs/onlyrepo"); ok {
		t.Error("a URI with no path matches")
	}
}
