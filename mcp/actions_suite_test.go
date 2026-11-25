//go:build !js && !ios && !android && !sdk_mobile_bind

// §22.7's actions row at M3 (MCP-M3-26; R-MCP-5, R-MCP-9, D-MCP-3, D-MCP-17, I-7, I-8, I-13, X1), through the server's
// sessions and the tools as registered, and CC4's rows for MCP work (sidecartest.McpCc4):
//
//   - an admin sidecar's agent calling evs_write or evs_read on the config repo, or reading or subscribing to it through
//     ur://evs, is refused, while team_members, team_agents, acl_grants and acl_check answer from the verified config
//     (TestActionsConfigRepoRefusedViewsAnswer); `ur acl push` from a caller with no terminal is cli's, which this
//     module's tests cannot link, and cli's TestAclPushNeedsATerminalAndAWriter holds it;
//   - on a secret repo holding a fixture ACME account key, evs_repos names it not, and evs_list, evs_history, evs_read,
//     evs_write, evs_delete and ur://evs reads and subscriptions are refused, the scan finding the key, and every key
//     testHookSecret reports, in no result (TestActionsSecretRepoRefused);
//   - no path signs BridgeBlock, BridgeEgress, Suspend, EvsShare, OwnerConfirm or an access-log statement: the guard
//     refuses each whatever a tool claims of its own resources, and a tool that reports one is refused before its
//     handler runs (TestActionsStatementsRefused);
//   - the descriptor lint: every O tool, and every W tool that may act, names a kind MCP-M3-02's table holds, its row's
//     fields are CanonicalAction's, and no row's field is a key, so tls_publish's keeps the key in the sidecar (X1)
//     (TestActionsDescriptorLint);
//   - CC4: canaries in a harness's prompt, tool inputs and tool outputs, canaries in a call's own input, and every key
//     testHookSecret reports, are absent from every MCP result, the environment, each hook's answer and the daemon's
//     log, raw and in every encoding the capture scans (TestActionsCc4);
//   - the rcpt/ family (QD-1097): an agent's evs_read, evs_write, evs_list, search and ur://evs read are refused on a
//     mailbox's and a group inbox's, and on every general repo's while mailcfg cannot be read, and answer on an
//     ordinary file repo's (TestActionsApprovedRecipientsRefused);
//   - DROP (D-MCP-32, MCP-M10-01): a DROP push or its cancel is refused before any handler, no catalog tool but the
//     dry run reaches drops, and an admin's evs_drop_preview files nothing, refused on the config and secret repos
//     (TestActionsDropRefused).
//
// The row's later clauses join with their owners, each adding its case here: BridgeAddress filings with MCP-M4-01, the
// directory's and claims' with RECORD-M6-22.

package mcp

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The version the suite's sessions speak.
const actionsSuiteVersion = "2025-11-25"

// The evs repos and the team views on one network: what an admin sidecar's agent reaches.
type actionsSuiteNetwork struct {
	*fakeMcpEvsNetwork
	team *fakeMcpTeamNetwork
}

func (self *actionsSuiteNetwork) ConfigState() *sidecar.ConfigState {
	return self.team.ConfigState()
}

func (self *actionsSuiteNetwork) Grants(now time.Time) []sidecar.AclGrantInfo {
	return self.team.Grants(now)
}

func (self *actionsSuiteNetwork) ApprovalStatus(ctx context.Context, approvalId sidecar.Id) (*sidecar.ApprovalStatus, error) {
	return self.team.ApprovalStatus(ctx, approvalId)
}

// The evs tools and ur://evs over repos of every kind the guard judges, and the team views over a real config, on
// one server.
type actionsSuiteEnv struct {
	*testEvsToolEnv
	team      *fakeMcpTeamNetwork
	admission *sidecartest.AdmissionNet
}

func newActionsSuiteEnv(t *testing.T) *actionsSuiteEnv {
	t.Helper()
	env := &actionsSuiteEnv{testEvsToolEnv: newTestEvsToolEnv(t), admission: newTestTeamAdmissionNet(t)}
	env.admission.ConsentedMember("an admin's agent")
	env.team = &fakeMcpTeamNetwork{
		fakeMcpToolNetwork: env.tools,
		state:              env.admission.State(),
		approvals:          map[sidecar.Id]*sidecar.ApprovalStatus{},
		grants:             []sidecar.AclGrantInfo{},
	}
	env.daemon.hostNetwork(env.networkId, &actionsSuiteNetwork{fakeMcpEvsNetwork: env.evs, team: env.team})
	catalog := NewMcpCatalog(env.server.settings.Mcp, env.clock, nil)
	addTeamTools(catalog)
	catalog.Install(env.server)
	return env
}

// An agent's evs_write and evs_read of the config repo, and its ur://evs read and subscription, are refused; the
// views answer.
func TestActionsConfigRepoRefusedViewsAnswer(t *testing.T) {
	env := newActionsSuiteEnv(t)
	env.put(env.config, "acl.hujson", `{"acls": []}`, sidecar.NewId())
	conn := env.conn(actionsSuiteVersion)
	for _, c := range []struct {
		tool      string
		arguments map[string]any
	}{
		{tool: "evs_read", arguments: map[string]any{"repo": env.config.String(), "path": "acl.hujson"}},
		{tool: "evs_write", arguments: map[string]any{"repo": env.config.String(), "path": "acl.hujson", "content": "{}", "base_version": 3}},
	} {
		wantMcpError(t, env.callTool(conn, actionsSuiteVersion, c.tool, c.arguments), McpCodeRefused, "config repo")
	}
	uri := McpEvsUri(env.config, "acl.hujson")
	for _, method := range []string{"resources/read", "resources/subscribe"} {
		if response := conn.call(method, map[string]any{"uri": uri}); response.Error == nil {
			t.Errorf("%s of the config repo answered %s", method, response.Result)
		}
	}
	if len(env.evs.repos[env.config].writes) != 0 {
		t.Error("a refused call reached the config repo")
	}
	for _, view := range []struct {
		tool      string
		arguments map[string]any
	}{
		{tool: "team_members", arguments: map[string]any{}},
		{tool: "team_agents", arguments: map[string]any{}},
		{tool: "acl_grants", arguments: map[string]any{}},
		{tool: "acl_check", arguments: map[string]any{"action": "listen", "resource": "sock:db"}},
	} {
		response := env.callTool(conn, actionsSuiteVersion, view.tool, view.arguments)
		if response.Error != nil {
			t.Errorf("%s: %d %s", view.tool, response.Error.Code, response.Error.Message)
			continue
		}
		// the config's views are the members', acl_check's answer this sidecar's own
		if envelope := testEnvelopeOf(t, response); envelope.Trust != McpTrustMember && envelope.Trust != McpTrustOwn {
			t.Errorf("%s answered trust %s", view.tool, envelope.Trust)
		}
	}
}

// On a secret repo holding a fixture ACME account key: evs_repos names it not, every other evs tool and ur://evs read
// and subscription is refused, and no result holds the key in any encoding.
func TestActionsSecretRepoRefused(t *testing.T) {
	cc4, err := sidecartest.NewMcpCc4()
	if err != nil {
		t.Fatal(err)
	}
	defer cc4.Close()
	env := newActionsSuiteEnv(t)
	key, err := sidecartest.NewFixtureAcmeAccountKey(cc4.Capture)
	if err != nil {
		t.Fatal(err)
	}
	env.put(env.secret, "acme/account.pem", string(key.Pem), sidecar.NewId())
	conn := env.conn(actionsSuiteVersion)
	keep := func(name string, response *testMcpResponse) *testMcpResponse {
		encoded, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		cc4.Result(name, encoded)
		return response
	}
	repos := &mcpEvsReposOut{}
	testViewData(t, keep("evs_repos", env.callTool(conn, actionsSuiteVersion, "evs_repos", map[string]any{})), repos)
	for _, repo := range repos.Repos {
		if repo.RepoId == env.secret.String() {
			t.Errorf("evs_repos names the secret repo: %+v", repo)
		}
	}
	secret := env.secret.String()
	for _, c := range []struct {
		tool      string
		arguments map[string]any
	}{
		{tool: "evs_list", arguments: map[string]any{"repo": secret}},
		{tool: "evs_list", arguments: map[string]any{"repo": secret, "path": "acme"}},
		{tool: "evs_history", arguments: map[string]any{"repo": secret, "path": "acme/account.pem"}},
		{tool: "evs_read", arguments: map[string]any{"repo": secret, "path": "acme/account.pem"}},
		{tool: "evs_write", arguments: map[string]any{"repo": secret, "path": "acme/account.pem", "content": "-", "base_version": 3}},
		{tool: "evs_delete", arguments: map[string]any{"repo": secret, "path": "acme/account.pem", "base_version": 3}},
	} {
		response := keep(c.tool, env.callTool(conn, actionsSuiteVersion, c.tool, c.arguments))
		if response.Error == nil || response.Error.Code != McpCodeRefused || !strings.Contains(response.Error.Message, "secret repo") {
			t.Errorf("%s on the secret repo: %s %+v", c.tool, response.Result, response.Error)
		}
	}
	uri := McpEvsUri(env.secret, "acme/account.pem")
	for _, method := range []string{"resources/read", "resources/subscribe"} {
		if response := keep(method, conn.call(method, map[string]any{"uri": uri})); response.Error == nil {
			t.Errorf("%s of the secret repo answered %s", method, response.Result)
		}
	}
	if len(env.evs.repos[env.secret].writes) != 0 {
		t.Error("a refused call reached the secret repo")
	}
	for _, finding := range cc4.Scan() {
		t.Errorf("CC4: %s", finding)
	}
}

// The suite's fixture tool: it reports the statement its input names and records whether it ran.
type actionsStatementIn struct {
	Statement   uint32 `json:"statement"`
	OwnResource bool   `json:"own_resource"`
}

type actionsStatementOut struct {
	Filed bool `json:"filed"`
}

// No MCP path signs BridgeBlock, BridgeEgress, Suspend, EvsShare, OwnerConfirm or an access-log statement: the guard
// refuses each whatever a tool claims of its own resources, and a tool that would file one is refused before its
// handler runs. The own-resource filings 16.5's tools make pass where the tool has checked they are its own.
func TestActionsStatementsRefused(t *testing.T) {
	refused := sidecartest.McpRefusedStatements()
	for _, signedType := range refused {
		for _, ownResource := range []bool{false, true} {
			if McpGuard([]McpTarget{{Kind: McpTargetStatement, SignedType: signedType, OwnResource: ownResource}}) == nil {
				t.Errorf("%s (own resource %t) passes the guard", signedType, ownResource)
			}
		}
	}
	for _, signedType := range mcpOwnResourceStatements {
		if slices.Contains(refused, signedType) {
			t.Errorf("%s is both an own-resource filing and refused", signedType)
		}
		if McpGuard([]McpTarget{{Kind: McpTargetStatement, SignedType: signedType, OwnResource: true}}) != nil {
			t.Errorf("%s, checked as this sidecar's own, is refused", signedType)
		}
	}
	env := newActionsSuiteEnv(t)
	ran := 0
	catalog := NewMcpCatalog(env.server.settings.Mcp, env.clock, nil)
	AddTool(catalog, &McpToolSpec[actionsStatementIn]{
		Name:        "actions_fixture_file",
		Tier:        McpTierWrite,
		Description: "files one fixture statement",
		Targets: func(call *McpCall, in *actionsStatementIn) ([]McpTarget, error) {
			return []McpTarget{{Kind: McpTargetStatement, SignedType: bridge.SignedType(in.Statement), OwnResource: in.OwnResource}}, nil
		},
		Access: func(call *McpCall, in *actionsStatementIn) ([]McpAccess, error) { return nil, nil },
	}, func(ctx context.Context, call *McpCall, in *actionsStatementIn, result *McpResult) (*actionsStatementOut, error) {
		ran += 1
		return &actionsStatementOut{Filed: true}, nil
	})
	catalog.Install(env.server)
	conn := env.conn(actionsSuiteVersion)
	for _, signedType := range refused {
		response := env.callTool(conn, actionsSuiteVersion, "actions_fixture_file", map[string]any{"statement": uint32(signedType), "own_resource": true})
		wantMcpError(t, response, McpCodeRefused, "MCP signs no")
	}
	if ran != 0 {
		t.Errorf("the handler ran %d times for refused statements", ran)
	}
}

// The O tools' kinds and the W tools' that may act: what each files through §5.4's gate (§16.5).
var actionsToolKinds = map[string]sidecar.SidecarActionKind{
	"tls_publish":       sidecar.SidecarActionPublish,
	"socket_listen":     sidecar.SidecarActionListen,
	"bridge_forward":    sidecar.SidecarActionForward,
	"bridge_expose":     sidecar.SidecarActionExpose,
	"mail_alias_create": sidecar.SidecarActionAliasCreate,
	"mail_alias_delete": sidecar.SidecarActionAliasDelete,
	"evs_write":         sidecar.SidecarActionAgentConfigWrite,
	"evs_delete":        sidecar.SidecarActionAgentConfigDelete,
	"dns_set":           sidecar.SidecarActionDnsSet,
	"dns_delete":        sidecar.SidecarActionDnsDelete,
	"mail_send":         sidecar.SidecarActionMail,
	"directory_request": sidecar.SidecarActionAccessRequest,
	"run_restore":       sidecar.SidecarActionRestore,
	"support_send":      sidecar.SidecarActionSupportSend,
}

// What a field's name may not hold: a key, a secret or anything that opens one.
var actionsKeyWords = []string{"key", "secret", "private", "seed", "token", "password", "pem", "cert"}

// Every O tool, and every W tool that may act, names a kind MCP-M3-02's table holds; each row's fields are
// CanonicalAction's, and none is a key, so tls_publish's row keeps the key in the sidecar (X1).
func TestActionsDescriptorLint(t *testing.T) {
	fields := (&protocol.CanonicalAction{}).ProtoReflect().Descriptor().Fields()
	kinds := []sidecar.SidecarActionKind{}
	for _, design := range mcpCatalogDesign {
		if design.tier != McpTierOutward && !design.mayAct {
			continue
		}
		kind, ok := actionsToolKinds[design.name]
		if !ok {
			t.Errorf("%s acts outward and names no kind", design.name)
			continue
		}
		if slices.Contains(kinds, kind) {
			t.Errorf("%s names a kind another tool names", design.name)
		}
		kinds = append(kinds, kind)
		row, ok := sidecar.CanonicalActionFields(kind)
		if !ok {
			t.Errorf("%s's kind %d has no row in the kind table", design.name, kind)
			continue
		}
		if len(row.Required) == 0 {
			t.Errorf("%s's row requires nothing of its action", design.name)
		}
		for _, numbers := range [][]protoreflect.FieldNumber{row.Required, row.Optional, row.Version2, row.Server, row.TemplateRequired} {
			for _, number := range numbers {
				field := fields.ByNumber(number)
				if field == nil {
					t.Errorf("%s's row names field %d, which CanonicalAction does not hold", design.name, number)
					continue
				}
				for _, word := range actionsKeyWords {
					if strings.Contains(string(field.Name()), word) {
						t.Errorf("%s's row names %s, a key's field", design.name, field.Name())
					}
				}
			}
		}
	}
	for name := range actionsToolKinds {
		if !slices.ContainsFunc(mcpCatalogDesign, func(design mcpCatalogDesignTool) bool { return design.name == name }) {
			t.Errorf("%s is no tool of §16.5's", name)
		}
	}
	// tls_publish's own row: the host, port, audience and mode, a grant's fields and the link's SPKI hash, no key
	publish, _ := sidecar.CanonicalActionFields(sidecar.SidecarActionPublish)
	for _, number := range append(slices.Clone(publish.Required), publish.Optional...) {
		if name := string(fields.ByNumber(number).Name()); strings.Contains(name, "key") {
			t.Errorf("tls_publish's action carries %s", name)
		}
	}
}

// CC4 over MCP work: canaries in a harness's prompt, tool inputs and outputs, canaries in a call's content and message,
// which no result echoes, the fixture key, and every key testHookSecret reports, absent from every MCP result, the
// environment, each hook's answer and the daemon's log.
func TestActionsCc4(t *testing.T) {
	cc4, err := sidecartest.NewMcpCc4()
	if err != nil {
		t.Fatal(err)
	}
	defer cc4.Close()
	env := newActionsSuiteEnv(t)
	// the daemon's log, kept: the binder's and the ingest's lines go where an operator would read them
	env.server.log = cc4.Log("mcp daemon")
	redactor, err := sidecar.NewRedactor(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writer := newTestRecordWriter()
	NewIngest(&IngestArgs{
		Server:    env.server,
		Writers:   func(network McpNetwork) (sidecar.RecordWriter, error) { return writer, nil },
		Redactors: func(network McpNetwork) (*sidecar.Redactor, error) { return redactor, nil },
		Record:    sidecar.DefaultSidecarSettings().Record,
	})
	key, err := sidecartest.NewFixtureAcmeAccountKey(cc4.Capture)
	if err != nil {
		t.Fatal(err)
	}
	env.put(env.secret, "acme/account.pem", string(key.Pem), sidecar.NewId())
	capture := cc4.Capture
	prompt := capture.CanaryText("harness prompt")
	input := capture.CanaryText("harness tool input")
	output := capture.CanaryText("harness tool output")
	answer := func(source string, err error) {
		if err != nil {
			cc4.Hook(source, []byte(err.Error()))
		}
	}
	harness := env.claude
	session := "tool session"
	answer("prompt", harness.Hook(harness.Payload(session, "UserPromptSubmit", map[string]any{"prompt": prompt})))
	answer("shell", harness.Hook(harness.Payload(session, "PostToolUse", map[string]any{
		"tool_name":     "Bash",
		"tool_input":    map[string]any{"command": "cat " + input},
		"tool_response": map[string]any{"stdout": output},
		"tool_use_id":   "toolu_cc4_shell",
	})))
	// payloads an adapter cannot read, a canary where a careless answer would echo it
	answer("unreadable", harness.Hook([]byte(`{"session_id": 7, "tool_input": "`+input+`"}`)))
	answer("drifted", harness.Hook(harness.Payload(session, "PostToolUse", map[string]any{
		"tool_name": "Bash", "tool_input": map[string]any{"command": input}, "tool_use_id": "toolu_cc4_drift", "added_field": output,
	})))
	cursorPayload := []byte(`{"conversation_id":"c1","hook_event_name":"beforeMCPExecution","workspace_roots":["/tmp/sidecartest/project"],` +
		`"tool_name":"mail_send","tool_input":"{\"subject\":\"` + input + `\"}","command":"/tmp/sidecartest/bin/ur mcp"}`)
	if adapter, ok := HookAdapterFor(cursorHookHarness); ok {
		if parsed, err := adapter.Parse(cursorPayload, env.server.settings.Ingest); err == nil {
			cc4.Hook("cursor answer", CursorHookAnswer(parsed))
		}
	}
	conn := env.conn(actionsSuiteVersion)
	keep := func(name string, response *testMcpResponse) {
		encoded, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		cc4.Result(name, encoded)
	}
	written := capture.CanaryText("written content")
	message := capture.CanaryText("commit message")
	for _, call := range []struct {
		tool      string
		arguments map[string]any
	}{
		{tool: "team_members", arguments: map[string]any{}},
		{tool: "team_agents", arguments: map[string]any{}},
		{tool: "evs_repos", arguments: map[string]any{}},
		{tool: "evs_write", arguments: map[string]any{"repo": env.general.String(), "path": "notes.md", "content": written, "base_version": 0, "message": message}},
		{tool: "evs_read", arguments: map[string]any{"repo": env.secret.String(), "path": "acme/account.pem"}},
		{tool: "evs_write", arguments: map[string]any{"repo": env.config.String(), "path": "x", "content": written, "base_version": 1}},
	} {
		keep(call.tool, env.callTool(conn, actionsSuiteVersion, call.tool, call.arguments))
	}
	if !env.network.runs.Tainted(env.runId) {
		// the unreadable and drifted payloads lapsed the run's coverage
		t.Error("the run is untainted after events its adapter could not read")
	}
	for _, finding := range cc4.Scan() {
		t.Errorf("CC4: %s", finding)
	}
}

// The capture the suite scans catches a leak: the fixture key's DER in a result, base64'd, is found.
func TestActionsCc4CatchesALeak(t *testing.T) {
	capture := sidecartest.NewPrivacyCapture()
	key, err := sidecartest.NewFixtureAcmeAccountKey(capture)
	if err != nil {
		t.Fatal(err)
	}
	leaked, err := json.Marshal(map[string]any{"text": key.Der})
	if err != nil {
		t.Fatal(err)
	}
	capture.Add(sidecartest.PrivacyClassMcp, "a result that leaks", leaked)
	if findings := capture.Scan(); len(findings) == 0 {
		t.Error("a result holding the key, base64'd, was not found")
	}
}

// The suite's network with mailcfg's group records behind it: the general repos that are group inboxes, or an error
// while mailcfg cannot be read (QD-1097).
type actionsSuiteRecipientNetwork struct {
	*actionsSuiteNetwork
	stateLock sync.Mutex
	groups    map[sidecar.Id]bool
	groupsErr error
}

func (self *actionsSuiteRecipientNetwork) MailGroupInboxes(ctx context.Context) (map[sidecar.Id]bool, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.groups, self.groupsErr
}

// QD-1097 (owner decision 635; §16.6's refused table): an agent's evs_read, evs_write, evs_list, search and ur://evs
// read of the rcpt/ family are refused on a mailbox and on a group inbox, the family left out of their listings, so no
// agent reads a standing approved-recipient record to write its bytes back; the same paths on an ordinary file repo
// answer, until mailcfg cannot be read, when every general repo's rcpt/ is refused too.
func TestActionsApprovedRecipientsRefused(t *testing.T) {
	env := newActionsSuiteEnv(t)
	mailbox, group := sidecar.NewId(), sidecar.NewId()
	env.tools.repoKinds[mailbox] = protocol.RepoKind_REPO_KIND_MAILBOX
	env.tools.repoKinds[group] = protocol.RepoKind_REPO_KIND_GENERAL
	for _, repoId := range []sidecar.Id{mailbox, group} {
		env.evs.repos[repoId] = newFakeMcpEvsRepo()
		for _, action := range []protocol.AclAction{protocol.AclAction_ACL_ACTION_READ, protocol.AclAction_ACL_ACTION_WRITE} {
			env.tools.allow(McpAccess{Action: action, Resource: sidecar.AclResource{Kind: sidecar.AclResourceRepo, RepoId: repoId}})
		}
	}
	for _, repoId := range []sidecar.Id{mailbox, group, env.general} {
		env.putWith(repoId, "rcpt/ab/record", "a recipient approval's bytes", env.tools.identity.SidecarId, testEvsCleanProvenance())
		env.putWith(repoId, "notes", "ordinary", env.tools.identity.SidecarId, testEvsCleanProvenance())
		// the fake lists a file's own directory alone, so the root names the family's directory here
		env.evs.repos[repoId].children[""] = []string{"notes", "rcpt"}
	}
	network := &actionsSuiteRecipientNetwork{
		actionsSuiteNetwork: &actionsSuiteNetwork{fakeMcpEvsNetwork: env.evs, team: env.team},
		groups:              map[sidecar.Id]bool{group: true},
	}
	env.daemon.hostNetwork(env.networkId, network)
	search := newTestSessionSearch()
	catalog := NewMcpCatalog(env.server.settings.Mcp, env.clock, nil)
	addSearchTools(catalog, func(call *McpCall) (McpSearch, error) { return search, nil })
	catalog.Install(env.server)
	conn := env.conn(actionsSuiteVersion)
	reaches := func(repoId sidecar.Id) map[string]*testMcpResponse {
		repo := repoId.String()
		return map[string]*testMcpResponse{
			"evs_read":  env.callTool(conn, actionsSuiteVersion, "evs_read", map[string]any{"repo": repo, "path": "rcpt/ab/record"}),
			"evs_write": env.callTool(conn, actionsSuiteVersion, "evs_write", map[string]any{"repo": repo, "path": "rcpt/ab/record", "content": "a recipient approval's bytes", "base_version": 3}),
			"evs_list":  env.callTool(conn, actionsSuiteVersion, "evs_list", map[string]any{"repo": repo, "path": "rcpt"}),
			"search": env.callTool(conn, actionsSuiteVersion, "search", map[string]any{
				"query": "recipient", "repos": []string{repo}, "filters": map[string]any{"path_prefix": "rcpt"},
			}),
			"ur://evs": conn.call("resources/read", map[string]any{"uri": McpEvsUri(repoId, "rcpt/ab/record")}),
		}
	}
	listed := func(repoId sidecar.Id) []string {
		listing := &mcpEvsListOut{}
		testViewData(t, env.callTool(conn, actionsSuiteVersion, "evs_list", map[string]any{"repo": repoId.String()}), listing)
		names := []string{}
		for _, entry := range listing.Entries {
			names = append(names, entry.Name)
		}
		return names
	}
	for name, repoId := range map[string]sidecar.Id{"a mailbox": mailbox, "a group inbox": group} {
		for reach, response := range reaches(repoId) {
			if response.Error == nil || response.Error.Code != McpCodeRefused || !strings.Contains(response.Error.Message, "approved-recipient") ||
				strings.Contains(string(response.Result), "a recipient approval's bytes") {
				t.Errorf("%s on %s: %s %+v", reach, name, response.Result, response.Error)
			}
		}
		if names := listed(repoId); slices.Contains(names, "rcpt") || !slices.Contains(names, "notes") {
			t.Errorf("%s's listing: %v", name, names)
		}
		if writes := env.evs.repos[repoId].writes; len(writes) != 0 {
			t.Errorf("a refused write reached %s", name)
		}
	}
	for reach, response := range reaches(env.general) {
		if response.Error != nil {
			t.Errorf("%s on an ordinary file repo: %d %s", reach, response.Error.Code, response.Error.Message)
		}
	}
	if names := listed(env.general); !slices.Contains(names, "rcpt") {
		t.Errorf("an ordinary file repo's listing: %v", names)
	}

	// while mailcfg cannot be read, no general repo's rcpt/ is reachable
	network.stateLock.Lock()
	network.groups, network.groupsErr = nil, sidecar.ErrMailConfigNotSynced
	network.stateLock.Unlock()
	for reach, response := range reaches(env.general) {
		if response.Error == nil || !strings.Contains(response.Error.Message, "approved-recipient") {
			t.Errorf("%s while mailcfg cannot be read: %s %+v", reach, response.Result, response.Error)
		}
	}
}

// The actions row's DROP clause (D-MCP-32; §16.6's refused table): no MCP path signs a DROP push or its cancel. A tool
// that reports one is refused by the guard before its handler runs, whatever it claims; no tool of the daemon's
// catalog but the dry run reaches drops; and an admin's evs_drop_preview answers its dry run and files nothing, while
// the same call on the config repo and a secret repo is refused before evs is asked.
func TestActionsDropRefused(t *testing.T) {
	env := newActionsSuiteEnv(t)
	ran := 0
	catalog := NewMcpCatalog(env.server.settings.Mcp, env.clock, nil)
	AddTool(catalog, &McpToolSpec[actionsStatementIn]{
		Name:        "actions_fixture_drop",
		Tier:        McpTierWrite,
		Description: "pushes one fixture DROP",
		Targets: func(call *McpCall, in *actionsStatementIn) ([]McpTarget, error) {
			return []McpTarget{{Kind: McpTargetDrop}}, nil
		},
		Access: func(call *McpCall, in *actionsStatementIn) ([]McpAccess, error) { return nil, nil },
	}, func(ctx context.Context, call *McpCall, in *actionsStatementIn, result *McpResult) (*actionsStatementOut, error) {
		ran += 1
		return &actionsStatementOut{Filed: true}, nil
	})
	catalog.Install(env.server)
	conn := env.conn(actionsSuiteVersion)
	if response := env.callTool(conn, actionsSuiteVersion, "actions_fixture_drop", map[string]any{"statement": 0, "own_resource": true}); response.Error == nil ||
		response.Error.Code != McpCodeRefused {
		t.Fatalf("a DROP through MCP: %s %+v", response.Result, response.Error)
	}
	if ran != 0 {
		t.Errorf("the DROP's handler ran %d times", ran)
	}
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	for _, name := range NewDaemonMcpCatalog(newTestMcpServer(newFakeMcpDaemon(), clock), nil).Names() {
		if strings.Contains(name, "drop") && name != "evs_drop_preview" {
			t.Errorf("%s reaches drops", name)
		}
	}

	env.put(env.general, "notes.md", "the notes", env.tools.identity.SidecarId)
	for _, repoId := range []sidecar.Id{env.general, env.config, env.secret} {
		env.tools.allow(McpAccess{Action: protocol.AclAction_ACL_ACTION_ADMIN, Resource: sidecar.AclResource{Kind: sidecar.AclResourceRepo, RepoId: repoId}})
	}
	preview := &mcpEvsDropPreviewOut{}
	testViewData(t, env.callTool(conn, actionsSuiteVersion, "evs_drop_preview", map[string]any{"repo": env.general.String(), "path": "notes.md"}), preview)
	repo := env.evs.repos[env.general]
	if !preview.ListMatch || len(repo.previews) != 1 || len(repo.writes) != 0 || len(env.evs.actions) != 0 {
		t.Fatalf("an admin's dry run: %+v, %d dry runs, %d writes, %d actions", preview, len(repo.previews), len(repo.writes), len(env.evs.actions))
	}
	for _, c := range []struct {
		repoId      sidecar.Id
		messagePart string
	}{
		{repoId: env.config, messagePart: "config repo"},
		{repoId: env.secret, messagePart: "secret repo"},
	} {
		wantMcpError(t, env.callTool(conn, actionsSuiteVersion, "evs_drop_preview", map[string]any{"repo": c.repoId.String(), "path": "a"}), McpCodeRefused, c.messagePart)
		if previews := env.evs.repos[c.repoId].previews; len(previews) != 0 {
			t.Errorf("a refused dry run reached the %s", c.messagePart)
		}
	}
}
