//go:build !js && !ios && !android && !sdk_mobile_bind

package sidecartest_test

// S9 on T2 (§22.7; §3.7's F8, MCP recording; R-MCP-4, R-MCP-5, I-2, I-7, I-8; MCP-M3-26): an agent's run recorded into
// the member's vault alone, under the privacy harness. The daemon is the one mcp composes, each part the real one: its
// server and run binder on a fake process table, its ingest, and RECORD's writer sealing every entry into the
// member's vault on sidecartest's record streams, which keep the sealed bytes as they came. A Claude Code session,
// FakeHarness's, starts, takes a prompt, runs a shell call whose input and output carry canaries and a synthetic
// secret, asks about an outward tool, and ends. Then:
//
//   - vault only: every entry the run made is one of the member's vault's, and the streams hold no other log;
//   - redaction: the secret is in no entry's opened body, and the run's Coverage names the redaction;
//   - gaps: the Coverage is sealed at the end and names each gap the run counted;
//   - evidence labels: the entries made of hook events, the PermissionRequest's among them, say source hook, the label
//     an approver's screen and the record carry for harness evidence (§16.6's residual row);
//   - the privacy harness: the vault's stream bytes as stored, the daemon's log and each hook's answer are captured,
//     and the scan finds no canary and no secret in them, raw or in any encoding.
//
// T3 runs it on server's stores once server's sidecart3 composes the daemon, which is not built yet (MCP-M3-26's
// incomplete list).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mcp"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

var _ = sidecartest.RegisterScenario("S9", "", sidecartest.ScenarioTierT2, &sidecartest.ScenarioTest{
	Repo:    "sidecar",
	Package: "github.com/urnetwork/sidecar/sidecartest",
	Name:    "TestScenarioS9",
})

func TestScenarioS9(t *testing.T) {
	sidecartest.RunScenario(t, &sidecartest.Scenario{Id: "S9", Run: s9Run}, nil)
}

// The daemon's one network: Online, its run files and local state a fake store's.
type s9Network struct {
	store *sidecartest.FakeStore
	runs  *sidecar.RunStore
}

func (self *s9Network) Status() sidecar.SidecarStatus {
	return sidecar.SidecarStatus{State: sidecar.SidecarStateOnline}
}

func (self *s9Network) Runs() (*sidecar.RunStore, error) {
	return self.runs, nil
}

func (self *s9Network) Spool() (*sidecar.Spool, error) {
	return nil, sidecar.ErrSidecarStoreLocked
}

func (self *s9Network) LocalStore() sidecar.SidecarStore {
	return self.store.Root()
}

// The daemon as the server reads it: the one network.
type s9Daemon struct {
	networkId sidecar.Id
	network   *s9Network
}

func (self *s9Daemon) ResolveNetwork(hello *sidecar.DaemonHello, network string) (sidecar.Id, error) {
	return self.networkId, nil
}

func (self *s9Daemon) Network(networkId sidecar.Id) (mcp.McpNetwork, bool) {
	return self.network, networkId == self.networkId
}

func (self *s9Daemon) Agent(hello *sidecar.DaemonHello) (*sidecar.SidecarAgent, error) {
	return nil, nil
}

// The run store's taint, as RECORD's writer reads it.
type s9RunView struct {
	runs *sidecar.RunStore
}

func (self *s9RunView) RunTainted(runId sidecar.Id) bool {
	return self.runs.Tainted(runId)
}

func s9Run(ctx context.Context, run *sidecartest.ScenarioRun) error {
	net := run.Net
	clock := net.Clock()
	capture := net.Capture()
	prompt := run.CanaryText("run prompt")
	toolInput := run.CanaryText("tool input")
	toolOutput := run.CanaryText("tool output")
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	// the redactor's ur_sk_ rule's form, synthetic
	secret := "ur_sk_" + hex.EncodeToString(random)
	capture.Forbid("synthetic secret", []byte(secret))

	// the member's vault, its writer sealing every entry
	streams := sidecartest.NewFakeRecordStreams(clock, nil, nil)
	vaultId, err := streams.NewRepo(ctx)
	if err != nil {
		return err
	}
	publicKey, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	sidecarId, memberId := sidecar.NewId(), sidecar.NewId()
	if err := streams.Grant(vaultId, sidecarId, sidecartest.RecordStreamsScope{Read: true, Write: true, Deposit: true}); err != nil {
		return err
	}
	auth := sidecartest.NewFakeRecordAuth()
	auth.Append(&sidecartest.FakeRecordAuthFixture{
		TimeMillis:   clock.Now().UnixMilli(),
		IdentityKeys: map[sidecar.Id][]byte{sidecarId: publicKey},
		Members:      map[sidecar.Id]sidecar.Id{sidecarId: memberId},
		Sponsors:     map[sidecar.Id]sidecar.Id{},
		Repos: map[sidecar.Id]*sidecartest.FakeRecordRepoAuth{vaultId: {
			Readers:   []sidecar.Id{sidecarId},
			Writers:   []sidecar.Id{sidecarId},
			Consented: []sidecar.Id{sidecarId},
		}},
		Vaults: map[sidecar.Id]sidecar.Id{memberId: vaultId},
	})
	settings := sidecar.DefaultSidecarSettings()
	store := sidecartest.NewFakeStore()
	runs, err := sidecar.NewRunStore(store.Root(), settings.Mcp, clock)
	if err != nil {
		return err
	}
	recordStore, err := store.Root().Directory("record", "record")
	if err != nil {
		return err
	}
	record, err := sidecar.OpenSidecarRecord(ctx, &sidecar.SidecarRecordArgs{
		SidecarId:         sidecarId,
		IdentityPublicKey: publicKey,
		Store:             recordStore,
		Sign: func(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
			return &bridge.Signed{
				Body:      bytes.Clone(body),
				SignerId:  sidecarId.Bytes(),
				Signature: ed25519.Sign(key, bridge.SignedBytes(purpose, signedType, body)),
				Type:      uint32(signedType),
			}, nil
		},
		Runs:     &s9RunView{runs: runs},
		Streams:  streams.For(sidecarId),
		Auth:     func() sidecar.RecordAuthView { return auth.Tip() },
		Clock:    clock,
		Settings: settings.Record,
	})
	if err != nil {
		return err
	}

	// the daemon: its server and binder, its ingest over the vault's writer, and harness evidence after it
	networkId := sidecar.NewId()
	network := &s9Network{store: store, runs: runs}
	table := sidecartest.NewFakeProcessTable(clock)
	terminal := table.Spawn(1, "zsh")
	serverSettings := mcp.NewMcpServerSettings(settings, sidecar.Version)
	serverSettings.Clock = clock
	serverSettings.Processes = table
	serverSettings.Log = capture.Logger("mcp daemon")
	server := mcp.NewMcpServer(&s9Daemon{networkId: networkId, network: network}, serverSettings)
	server.Binder().SetConfigCheck(func(ctx context.Context, harness string, cwd string) (bool, error) {
		return false, nil
	})
	redactor, err := sidecar.NewRedactor(rand.Reader)
	if err != nil {
		return err
	}
	mcp.NewIngest(&mcp.IngestArgs{
		Server:    server,
		Writers:   func(network mcp.McpNetwork) (sidecar.RecordWriter, error) { return record.Writer(), nil },
		Redactors: func(network mcp.McpNetwork) (*sidecar.Redactor, error) { return redactor, nil },
		Record:    settings.Record,
	})
	mcp.NewHarnessEvidenceStore(serverSettings.Ingest, clock).Install(server)

	// the project, its transcript the harness keeps
	cwd, err := os.MkdirTemp("", "s9-project-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(cwd)
	transcripts := filepath.Join(cwd, ".transcripts")
	if err := os.MkdirAll(transcripts, 0o700); err != nil {
		return err
	}
	transcript, err := json.Marshal(map[string]any{"type": "user", "message": map[string]any{"role": "user", "content": prompt}})
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(transcripts, "s9.jsonl"), append(transcript, '\n'), 0o600); err != nil {
		return err
	}
	sink := func(hello *sidecar.DaemonHello, payload []byte) error {
		err := server.HandleHook(ctx, hello, networkId, network, &mcp.HookEventParams{Payload: payload, ByteCount: int64(len(payload))})
		if err != nil {
			capture.Add(sidecartest.PrivacyClassHook, "hook answer", []byte(err.Error()))
		}
		return err
	}
	harness := sidecartest.NewFakeHarness(table, terminal.Identity.Pid, sidecartest.FakeHarnessClaudeCode, cwd, sink)
	session := "s9"
	steps := []func() error{
		func() error { return harness.SessionStart(session, "startup") },
		func() error {
			return harness.Hook(harness.Payload(session, "UserPromptSubmit", map[string]any{"prompt": prompt + " with " + secret}))
		},
		func() error {
			return harness.Hook(harness.Payload(session, "PostToolUse", map[string]any{
				"tool_name":     "Bash",
				"tool_input":    map[string]any{"command": "echo " + toolInput + " " + secret},
				"tool_response": map[string]any{"stdout": toolOutput + "\n"},
				"tool_use_id":   "toolu_s9_shell",
			}))
		},
		func() error {
			return harness.Hook(harness.Payload(session, "PermissionRequest", map[string]any{
				"tool_name":  "mcp__ur__mail_send",
				"tool_input": map[string]any{"from_alias": "agent", "to": []string{"someone@mail.example"}, "subject": "a report"},
			}))
		},
		func() error {
			return harness.Hook(harness.Payload(session, "Stop", map[string]any{"stop_hook_active": false}))
		},
		func() error { return harness.SessionEnd(session, "prompt_input_exit") },
	}
	for i, step := range steps {
		if err := step(); err != nil {
			return fmt.Errorf("hook %d: %w", i, err)
		}
	}
	if err := record.Flush(ctx); err != nil {
		return err
	}
	if err := record.Reader().Sync(ctx, vaultId); err != nil {
		return err
	}

	// the stream as stored: sealed bytes, which the scan reads for every canary and the secret
	versions, err := streams.For(sidecarId).ReadStream(ctx, vaultId, sidecarId, 0)
	if err != nil {
		return err
	}
	if len(versions) == 0 {
		return errors.New("the run wrote nothing to the member's vault")
	}
	for _, version := range versions {
		for _, entry := range version.Entries {
			capture.Add(sidecartest.PrivacyClassObject, "vault stream "+entry.Path, entry.Entry)
		}
	}

	errs := []error{}
	entries := record.Reader().Entries(vaultId)
	var coverage *protocol.Coverage
	sources := map[sidecar.RecordKind][]sidecar.RecordSource{}
	for _, entry := range entries {
		header := entry.Header.Header
		kind := entry.Header.Kind()
		sources[kind] = append(sources[kind], sidecar.RecordSource(header.GetSource()))
		if entry.BodyInvalid || entry.Body == nil {
			errs = append(errs, fmt.Errorf("a %v entry's body did not open", kind))
			continue
		}
		if bytes.Contains(entry.Body, []byte(secret)) {
			errs = append(errs, fmt.Errorf("a %v entry was sealed with the secret", kind))
		}
		if kind == sidecar.RecordKindCoverage {
			coverage = &protocol.Coverage{}
			if err := proto.Unmarshal(entry.Body, coverage); err != nil {
				return err
			}
		}
	}
	// vault only: the member's vault holds the run's every entry, and no other log was written
	if heads, err := streams.For(sidecarId).Streams(ctx, vaultId); err != nil || len(heads) != 1 {
		errs = append(errs, fmt.Errorf("the vault's streams: %d, %v", len(heads), err))
	}
	// gaps and redaction: the Coverage, sealed at the end, names the redactions
	if coverage == nil {
		errs = append(errs, errors.New("no Coverage was sealed at the session's end"))
	} else if !slices.ContainsFunc(coverage.Gaps, func(gap string) bool { return strings.HasPrefix(gap, sidecar.RecordCoverageGapRedaction) }) {
		errs = append(errs, fmt.Errorf("the Coverage names no redaction: %v", coverage.Gaps))
	}
	// evidence labels: hook events, the PermissionRequest's included, are source hook
	for _, kind := range []sidecar.RecordKind{sidecar.RecordKindPermission, sidecar.RecordKindHookEvent} {
		if len(sources[kind]) == 0 || slices.ContainsFunc(sources[kind], func(source sidecar.RecordSource) bool { return source != sidecar.RecordSourceHook }) {
			errs = append(errs, fmt.Errorf("%v entries by source: %v, want hook", kind, sources[kind]))
		}
	}
	return errors.Join(errs...)
}
