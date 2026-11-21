//go:build !js && !ios && !android && !sdk_mobile_bind

// MCP-M10-01: the evs tools on format 2 (§16.5's format-2 text; D-MCP-8, D-MCP-17, D-MCP-32), on tools_evs_test.go's
// fake repos with a network that says whether it is inside §19.11's format2 gate and which repos are locked: each
// version's setting and state on evs_list, evs_history and evs_read; a dropped version's read answering EVS_DROPPED
// with its drop named in the answer's data, a pending one reading with its drop and a warning, a collected one
// answering collected; evs_write's versioning, off refused outside the gate, in a locked repo and on a git-mode ref,
// and an outward write naming one carrying field 37 at version 2; and evs_drop_preview, an admin's dry run that never
// drops, refused where the guard refuses a read and past the repo's daily dry runs. The reader's drop checks, the
// dry run's walk and the lock's fold are EVS2's and ACL's own tests; the actions row's DROP clause is
// actions_suite_test.go's.

package mcp

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// An evs network inside, or outside, §19.11's format2 gate, whose repos a test locks.
type testFormat2EvsNetwork struct {
	*fakeMcpEvsNetwork
	stateLock sync.Mutex
	format2   bool
	locked    map[sidecar.Id]bool
}

func (self *testFormat2EvsNetwork) EvsFormat2Admitted() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.format2
}

func (self *testFormat2EvsNetwork) EvsRepoLocked(repoId sidecar.Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.locked[repoId]
}

// The evs tool env on a network inside the gate, nothing locked.
func newTestFormat2EvsEnv(t *testing.T) (*testEvsToolEnv, *testFormat2EvsNetwork) {
	t.Helper()
	env := newTestEvsToolEnv(t)
	network := &testFormat2EvsNetwork{fakeMcpEvsNetwork: env.evs, format2: true, locked: map[sidecar.Id]bool{}}
	env.daemon.hostNetwork(env.networkId, network)
	return env, network
}

// A drop's state as a reader found it.
func testDropState(signer sidecar.Id, notBefore time.Time) *sidecar.EvsDropState {
	return &sidecar.EvsDropState{DropId: sidecar.NewId(), DropVersion: 12, SignerSidecarId: signer, NotBefore: notBefore}
}

// evs_history names each version's setting and state: kept, collected, drop_pending with its window's end, and
// dropped, each listed one with its drop's id and signer; evs_list names each file's setting.
func TestEvsHistoryNamesEachState(t *testing.T) {
	env, _ := newTestFormat2EvsEnv(t)
	signer := sidecar.NewId()
	pending := testDropState(signer, time.UnixMilli(1800000000000))
	dropped := testDropState(signer, time.UnixMilli(1700000000000))
	repo := env.evs.repos[env.general]
	repo.histories = map[string]*sidecar.EvsHistory{"notes.md": {Path: "notes.md", HeadVersion: 9, Versions: []*sidecar.EvsHistoryVersion{
		{Version: 4, CommitVersion: 9, State: "kept", Versioning: 1},
		{Version: 3, CommitVersion: 8, State: "collected", Versioning: 1},
		{Version: 2, CommitVersion: 7, State: sidecar.EvsVersionStateDropPending, DropId: pending.DropId, DropSignerId: signer, DropNotBefore: pending.NotBefore},
		{Version: 1, CommitVersion: 6, State: sidecar.EvsVersionStateDropped, DropId: dropped.DropId, DropSignerId: signer, DropNotBefore: dropped.NotBefore},
	}}}
	env.put(env.general, "notes.md", "the newest notes", env.tools.identity.SidecarId)
	conn := env.conn("2025-11-25")
	history := &mcpEvsHistoryOut{}
	testViewData(t, env.callTool(conn, "2025-11-25", "evs_history", map[string]any{"repo": env.general.String(), "path": "notes.md"}), history)
	want := []struct {
		state, versioning, dropId string
		notBefore                 int64
	}{
		{state: "kept", versioning: "off"},
		{state: "collected", versioning: "off"},
		{state: "drop_pending", versioning: "on", dropId: pending.DropId.String(), notBefore: pending.NotBefore.UnixMilli()},
		{state: "dropped", versioning: "on", dropId: dropped.DropId.String(), notBefore: dropped.NotBefore.UnixMilli()},
	}
	if len(history.Versions) != len(want) {
		t.Fatalf("%d versions", len(history.Versions))
	}
	for i, version := range history.Versions {
		if version.State != want[i].state || version.Versioning != want[i].versioning || version.DropId != want[i].dropId ||
			version.NotBeforeMillis != want[i].notBefore || (want[i].dropId != "") != (version.DropSignerId == signer.String()) {
			t.Errorf("version %d: %+v", version.Version, version)
		}
	}

	repo.versionings = map[string]uint32{"notes.md": 1}
	listing := &mcpEvsListOut{}
	testViewData(t, env.callTool(conn, "2025-11-25", "evs_list", map[string]any{"repo": env.general.String()}), listing)
	if len(listing.Entries) != 1 || listing.Entries[0].Versioning != "off" {
		t.Fatalf("the listing: %+v", listing.Entries)
	}
	if args := repo.listArgs[len(repo.listArgs)-1]; !args.Settings || args.IndexFiles {
		t.Errorf("the listing asked %+v", args)
	}
	testViewData(t, env.callTool(conn, "2025-11-25", "evs_list", map[string]any{"repo": env.general.String(), "include_index": true}), listing)
	if args := repo.listArgs[len(repo.listArgs)-1]; !args.IndexFiles {
		t.Error("include_index did not ask for the index's files")
	}
}

// A dropped version's read answers EVS_DROPPED, FAILED_PRECONDITION, its data naming the drop by id and signer and
// nothing of the version in it, through evs_read and ur://evs alike; a pending one reads, its drop named beside a
// warning; a replaced versionless one answers collected.
func TestDroppedReadNamesDrop(t *testing.T) {
	env, _ := newTestFormat2EvsEnv(t)
	signer := sidecar.NewId()
	drop := testDropState(signer, time.UnixMilli(1700000000000))
	env.putWith(env.general, "old.md", "words a drop took", env.tools.identity.SidecarId, testEvsCleanProvenance())
	env.evs.repos[env.general].files["old.md"].readErr = &sidecar.EvsDroppedError{Drop: *drop}
	conn := env.conn("2025-11-25")
	for name, response := range map[string]*testMcpResponse{
		"evs_read": env.callTool(conn, "2025-11-25", "evs_read", map[string]any{"repo": env.general.String(), "path": "old.md"}),
		"ur://evs": conn.call("resources/read", map[string]any{"uri": McpEvsUri(env.general, "old.md")}),
	} {
		if response.Error == nil || response.Error.Code != McpCodeFailedPrecondition || !strings.Contains(response.Error.Message, "EVS_DROPPED") {
			t.Fatalf("%s: %s %+v", name, response.Result, response.Error)
		}
		data := &McpErrorData{}
		if err := json.Unmarshal(response.Error.Data, data); err != nil || data.Drop == nil {
			t.Fatalf("%s: the refusal's data %s", name, response.Error.Data)
		}
		if data.Drop.DropId != drop.DropId.String() || data.Drop.SignerId != signer.String() || data.Drop.NotBeforeMillis != drop.NotBefore.UnixMilli() ||
			strings.Contains(response.Error.Message, drop.DropId.String()) || strings.Contains(string(response.Error.Data), "words a drop took") {
			t.Errorf("%s: the drop named %+v in %q", name, data.Drop, response.Error.Message)
		}
	}

	pending := testDropState(signer, time.UnixMilli(1800000000000))
	env.putWith(env.general, "soon.md", "words a drop lists", env.tools.identity.SidecarId, testEvsCleanProvenance())
	env.evs.repos[env.general].files["soon.md"].drop = pending
	env.evs.repos[env.general].files["soon.md"].versioning = 1
	read := &mcpEvsReadOut{}
	testViewData(t, env.callTool(conn, "2025-11-25", "evs_read", map[string]any{"repo": env.general.String(), "path": "soon.md"}), read)
	if read.Content != "words a drop lists" || read.State != "drop_pending" || read.DropId != pending.DropId.String() || read.DropSignerId != signer.String() ||
		read.NotBeforeMillis != pending.NotBefore.UnixMilli() || read.Warning == "" || read.Versioning != "off" {
		t.Fatalf("a pending drop's version: %+v", read)
	}

	env.putWith(env.general, "replaced.md", "gone", env.tools.identity.SidecarId, testEvsCleanProvenance())
	env.evs.repos[env.general].files["replaced.md"].readErr = sidecar.ErrEvsCollected
	wantMcpError(t, env.callTool(conn, "2025-11-25", "evs_read", map[string]any{"repo": env.general.String(), "path": "replaced.md"}),
		McpCodeFailedPrecondition, "versionless")
}

// evs_write's versioning: on or off reaches the plan as the write's setting, the path's own when omitted; off is
// refused FAILED_PRECONDITION outside §19.11's format2 gate, in a locked repo and on a git-mode ref, nothing written.
func TestEvsWriteVersioning(t *testing.T) {
	env, network := newTestFormat2EvsEnv(t)
	conn := env.conn("2025-11-25")
	repo := env.evs.repos[env.general]
	write := func(versioning string) *testMcpResponse {
		arguments := map[string]any{"repo": env.general.String(), "path": "big.bin", "content": "bytes", "base_version": 0}
		if versioning != "" {
			arguments["versioning"] = versioning
		}
		return env.callTool(conn, "2025-11-25", "evs_write", arguments)
	}
	for _, versioning := range []string{"", "on", "off"} {
		testViewData(t, write(versioning), &mcpEvsWriteOut{})
		last := repo.writes[len(repo.writes)-1]
		options, ok := last.Options.(*sidecar.EvsWriteOptions)
		if !ok || options.Versioning != versioning {
			t.Errorf("%q: the plan's options %+v", versioning, last.Options)
		}
	}
	writes := len(repo.writes)
	network.locked[env.general] = true
	wantMcpError(t, write("off"), McpCodeFailedPrecondition, "versioning off")
	testViewData(t, write("on"), &mcpEvsWriteOut{})
	network.locked[env.general] = false
	network.format2 = false
	wantMcpError(t, write("off"), McpCodeFailedPrecondition, "versioning off")
	network.format2 = true
	repo.writeErr = sidecar.ErrEvsGitRef
	wantMcpError(t, write("off"), McpCodeFailedPrecondition, "versioning off")
	if len(repo.atTips) != 0 {
		t.Error("versioning off reached a git-mode ref's local tier")
	}
	if len(repo.writes) != writes+2 {
		t.Errorf("%d writes reached the plan past the refusals, want %d", len(repo.writes), writes+2)
	}
	wantMcpError(t, write("maybe"), McpCodeInvalidArguments, "do not fit")
}

// An outward write that names its versioning carries field 37 at version 2, 0 on and 1 off, and its effect the same
// setting; one that names none stays at version 1 with no field 37 (§16.8).
func TestVersioningFieldNeedsVersion2(t *testing.T) {
	env, _ := newTestFormat2EvsEnv(t)
	conn := env.conn("2025-11-25")
	cases := []struct {
		versioning string
		version    uint32
		field37    uint32
	}{
		{versioning: "", version: 1, field37: 0},
		{versioning: "on", version: 2, field37: 0},
		{versioning: "off", version: 2, field37: 1},
	}
	for i, c := range cases {
		arguments := map[string]any{"repo": env.general.String(), "path": "AGENTS.md", "content": "Use the formatter.", "base_version": 0}
		if c.versioning != "" {
			arguments["versioning"] = c.versioning
		}
		out := &mcpEvsWriteOut{}
		testViewData(t, env.callTool(conn, "2025-11-25", "evs_write", arguments), out)
		if out.Status != "approval_pending" || len(env.evs.actions) != i+1 {
			t.Fatalf("%q: %+v, %d actions", c.versioning, out, len(env.evs.actions))
		}
		stored, err := sidecar.ParseStoredCanonicalAction(env.evs.actions[i].Canonical)
		if err != nil {
			t.Fatal(err)
		}
		if stored.Action.GetVersion() != c.version || stored.Action.GetVersioning() != c.field37 ||
			stored.Action.GetKind() != uint32(sidecar.SidecarActionAgentConfigWrite) {
			t.Errorf("%q: the action at version %d, field 37 %d", c.versioning, stored.Action.GetVersion(), stored.Action.GetVersioning())
		}
		if effect := env.evs.effects[i]; effect.Versioning != c.versioning {
			t.Errorf("%q: the effect's versioning %q", c.versioning, effect.Versioning)
		}
	}
	// and field 37 at version 1 is no action the builder makes
	if _, err := sidecar.NewCanonicalAction(&protocol.CanonicalAction{
		Kind: uint32(sidecar.SidecarActionAgentConfigWrite), RepoId: env.general.Bytes(), Path: "AGENTS.md", ContentSha256: make([]byte, 32),
		Version: 1, Versioning: 1,
	}); !errors.Is(err, sidecar.ErrCanonicalActionInvalid) {
		t.Errorf("field 37 at version 1: %v", err)
	}
}

// evs_drop_preview is a dry run and never a drop (D-MCP-32): an admin-scoped sidecar's call asks the repo's dry run of
// the path and answers its figures and preview id, writing nothing and filing no action; a history that moved under
// the walk answers list_match false alone; follow is refused; a sidecar §8 does not let administer the repo is
// refused before evs is asked.
func TestPreviewNeverDrops(t *testing.T) {
	env, _ := newTestFormat2EvsEnv(t)
	env.put(env.general, "notes.md", "the notes", env.tools.identity.SidecarId)
	repo := env.evs.repos[env.general]
	previewId := sidecar.NewId()
	repo.preview = func(args *sidecar.EvsDropPreviewArgs) (*sidecar.EvsDropPreview, error) {
		return &sidecar.EvsDropPreview{
			PreviewId: previewId.Bytes(), VersionCount: 12, FreedBytes: 4096, SharedBytes: 512, InlineBytes: 64, YoungBytes: 128,
		}, nil
	}
	conn := env.conn("2025-11-25")
	arguments := map[string]any{"repo": env.general.String(), "path": "notes.md"}
	wantMcpError(t, env.callTool(conn, "2025-11-25", "evs_drop_preview", arguments), McpCodeRefused, "does not allow")
	if len(repo.previews) != 0 {
		t.Fatal("a sidecar with no admin grant reached the dry run")
	}
	env.tools.allow(McpAccess{Action: protocol.AclAction_ACL_ACTION_ADMIN, Resource: sidecar.AclResource{Kind: sidecar.AclResourceRepo, RepoId: env.general}})
	preview := &mcpEvsDropPreviewOut{}
	envelope := testViewData(t, env.callTool(conn, "2025-11-25", "evs_drop_preview", arguments), preview)
	if preview.PreviewId != hex.EncodeToString(previewId.Bytes()) || preview.Versions != 12 || preview.FreesBytes != 4096 || preview.SharedBytes != 512 ||
		preview.InlineBytes != 64 || preview.Young != 128 || !preview.ListMatch || envelope.Source != "evs:"+env.general.String() {
		t.Fatalf("the dry run: %+v %+v", preview, envelope)
	}
	if len(repo.previews) != 1 || len(repo.previews[0].Paths) != 1 || repo.previews[0].Paths[0] != "notes.md" || repo.previews[0].Follow ||
		len(repo.previews[0].ResumePreviewIds) != 0 {
		t.Fatalf("what the dry run was asked: %+v", repo.previews)
	}
	if len(repo.writes) != 0 || len(repo.atTips) != 0 || len(env.evs.actions) != 0 || len(env.evs.effects) != 0 {
		t.Fatal("a dry run wrote or filed something")
	}

	repo.preview = func(args *sidecar.EvsDropPreviewArgs) (*sidecar.EvsDropPreview, error) {
		return nil, errors.Join(sidecar.ErrEvsDropListMismatch, errors.New("lineage 0 lists 12 versions where evs resolved 13"))
	}
	moved := &mcpEvsDropPreviewOut{}
	testViewData(t, env.callTool(conn, "2025-11-25", "evs_drop_preview", arguments), moved)
	if moved.ListMatch || moved.PreviewId != "" || moved.Versions != 0 {
		t.Fatalf("a moved history: %+v", moved)
	}
	wantMcpError(t, env.callTool(conn, "2025-11-25", "evs_drop_preview", map[string]any{"repo": env.general.String(), "path": "notes.md", "follow": true}),
		McpCodeInvalidArguments, "not built")
	// no tool of the catalog drops or cancels a drop: the dry run is the one drop tool
	clock := env.clock
	for _, name := range NewDaemonMcpCatalog(newTestMcpServer(newFakeMcpDaemon(), clock), nil).Names() {
		if strings.Contains(name, "drop") && name != "evs_drop_preview" {
			t.Errorf("%s reaches drops", name)
		}
	}
}

// The guard keeps refusing evs_drop_preview where it refuses a read (D-MCP-17; g0-recheck-2): a secret repo, the
// config repo, the team directory, a mailbox's vault/ and rcpt/ families and the index's files, each before evs is
// asked.
func TestPreviewRefusedOnSecret(t *testing.T) {
	env, _ := newTestFormat2EvsEnv(t)
	directory, mailbox := sidecar.NewId(), sidecar.NewId()
	env.tools.repoKinds[directory] = protocol.RepoKind_REPO_KIND_DIRECTORY
	env.tools.repoKinds[mailbox] = protocol.RepoKind_REPO_KIND_MAILBOX
	for _, repoId := range []sidecar.Id{directory, mailbox} {
		env.evs.repos[repoId] = newFakeMcpEvsRepo()
	}
	for repoId := range env.evs.repos {
		env.tools.allow(McpAccess{Action: protocol.AclAction_ACL_ACTION_ADMIN, Resource: sidecar.AclResource{Kind: sidecar.AclResourceRepo, RepoId: repoId}})
	}
	conn := env.conn("2025-11-25")
	for _, c := range []struct {
		repoId      sidecar.Id
		path        string
		messagePart string
	}{
		{repoId: env.secret, path: "acme/account.pem", messagePart: "secret repo"},
		{repoId: env.config, path: "acl.hujson", messagePart: "config repo"},
		{repoId: directory, path: "a/1", messagePart: "team directory"},
		{repoId: mailbox, path: "vault/m1", messagePart: "vault"},
		{repoId: mailbox, path: "rcpt/ab/x", messagePart: "approved-recipient"},
		{repoId: env.general, path: ".ur-index/i1/b0", messagePart: "search index"},
	} {
		wantMcpError(t, env.callTool(conn, "2025-11-25", "evs_drop_preview", map[string]any{"repo": c.repoId.String(), "path": c.path}), McpCodeRefused, c.messagePart)
	}
	for repoId, repo := range env.evs.repos {
		if len(repo.previews) != 0 {
			t.Errorf("a refused dry run reached repo %s", repoId)
		}
	}
}

// A dry run past the repo's evs_drop_previews_per_day, as evs answers it, 429 RESOURCE_EXHAUSTED or a quota's 403, is
// refused in constant text; so is evs's SCOPE for a sidecar its state holds no admin.
func TestPreviewOutsideBudgetRefused(t *testing.T) {
	env, _ := newTestFormat2EvsEnv(t)
	env.put(env.general, "notes.md", "the notes", env.tools.identity.SidecarId)
	env.tools.allow(McpAccess{Action: protocol.AclAction_ACL_ACTION_ADMIN, Resource: sidecar.AclResource{Kind: sidecar.AclResourceRepo, RepoId: env.general}})
	repo := env.evs.repos[env.general]
	conn := env.conn("2025-11-25")
	for _, c := range []struct {
		refusal     *sidecar.EvsError
		messagePart string
	}{
		{refusal: &sidecar.EvsError{Status: 429, Code: protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED, RetryAfter: time.Hour}, messagePart: "dry runs for today are spent"},
		{refusal: &sidecar.EvsError{Status: 403, Code: protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_LIMIT}, messagePart: "dry runs for today are spent"},
		{refusal: &sidecar.EvsError{Status: 403, Code: protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE}, messagePart: "only from the repo's admins"},
	} {
		refusal := c.refusal
		repo.preview = func(args *sidecar.EvsDropPreviewArgs) (*sidecar.EvsDropPreview, error) {
			return nil, refusal
		}
		wantMcpError(t, env.callTool(conn, "2025-11-25", "evs_drop_preview", map[string]any{"repo": env.general.String(), "path": "notes.md"}), McpCodeRefused, c.messagePart)
	}
}
