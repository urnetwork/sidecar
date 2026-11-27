//go:build !ios_extension && !sidecar_http

// The inbox refusal (§20.4, D-SKILL-7) in the write planner every entry point plans through: in an agent repo, the
// agents repo and the Team inbox, evs_write's path (EvsRepo.Write), a delete, the inbox directory's removal, a
// create-only write with no grant, a grant for another path and a git-mode plan under inbox/ are all refused before
// anything is read or sent, while the agents client's message write lands and writes outside inbox/ pass; a general
// repo that is no Team inbox takes inbox/ as any other path.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A blob source a refused git plan never reads.
type testAgentsNoBlobs struct{}

func (testAgentsNoBlobs) CopyBlob(ctx context.Context, oid EvsGitOid, out io.Writer) (int64, error) {
	return 0, errors.New("no blob is read before the guard refuses")
}

func TestInboxWriteRefusedEverywhere(t *testing.T) {
	ctx := context.Background()
	thread, id := AgentThreadId(testConfigId("guard thread")), AgentMessageIdForCall(testConfigId("guard run"), "call")
	path := AgentMessagePath(thread, id)
	content := []byte(`{"v":1}`)
	zero := uint64(0)
	for _, repo := range []struct {
		name  string
		kind  protocol.RepoKind
		inbox protocol.RepoInbox
	}{
		{name: "agent", kind: protocol.RepoKind_REPO_KIND_AGENT},
		{name: "agents", kind: protocol.RepoKind_REPO_KIND_AGENTS},
		{name: "team inbox", kind: protocol.RepoKind_REPO_KIND_GENERAL, inbox: protocol.RepoInbox_REPO_INBOX_TEAM},
	} {
		writer := newEvsTestWriter(t)
		writer.world.config.repo.Kind, writer.world.config.repo.Inbox = repo.kind, repo.inbox
		refused := []struct {
			why   string
			write func() error
		}{
			{why: "evs_write", write: func() error {
				_, err := writer.write(t, path, content)
				return err
			}},
			{why: "a delete", write: func() error {
				_, err := writer.write(t, path, nil)
				return err
			}},
			{why: "the inbox's removal", write: func() error {
				_, err := writer.write(t, "inbox", nil)
				return err
			}},
			{why: "a file named inbox", write: func() error {
				_, err := writer.write(t, "inbox", content)
				return err
			}},
			{why: "a create-only write with no grant", write: func() error {
				_, err := writer.repo.WritePaths(ctx, &EvsWritePathsArgs{Writes: []*EvsPathWrite{{Path: path, Content: bytes.NewReader(content), IfVersion: &zero}}})
				return err
			}},
			{why: "a grant for another path", write: func() error {
				other := AgentMessagePath(thread, AgentMessageIdForCall(testConfigId("guard run"), "other"))
				_, err := writer.repo.WritePaths(ctx, &EvsWritePathsArgs{Writes: []*EvsPathWrite{{Path: path, Content: bytes.NewReader(content),
					IfVersion: &zero, inboxMessage: &evsInboxMessageGrant{path: other}}}})
				return err
			}},
			{why: "a granted write that is not create-only", write: func() error {
				_, err := writer.repo.WritePaths(ctx, &EvsWritePathsArgs{Writes: []*EvsPathWrite{{Path: path, Content: bytes.NewReader(content),
					inboxMessage: &evsInboxMessageGrant{path: path}}}})
				return err
			}},
			{why: "a git-mode plan", write: func() error {
				_, err := writer.repo.PlanGitUpdate(ctx, &EvsGitPlanArgs{RefName: []byte("work"), RefId: writer.world.refId,
					Update: &protocol.EvsGitUpdate{}, Blobs: testAgentsNoBlobs{},
					Changes: []*EvsGitPathChange{{Path: path, Kind: protocol.EvsEntryKind_EVS_ENTRY_FILE}}})
				return err
			}},
		}
		for _, c := range refused {
			if err := c.write(); !errors.Is(err, ErrEvsInboxMessagesOnly) {
				t.Errorf("%s: %s: %v", repo.name, c.why, err)
			}
		}
		if version, _ := writer.world.head(); version != 0 {
			t.Fatalf("%s: a refused write reached evs: head %d", repo.name, version)
		}
		// the agents client's message write lands, and a path outside inbox/ is any path
		writer.server.know(path)
		if _, err := writer.repo.WritePaths(ctx, &EvsWritePathsArgs{Writes: []*EvsPathWrite{{Path: path, Content: bytes.NewReader(content),
			IfVersion: &zero, inboxMessage: &evsInboxMessageGrant{path: path}}}}); err != nil {
			t.Fatalf("%s: the message write: %v", repo.name, err)
		}
		if version, _ := writer.world.head(); version != 1 {
			t.Fatalf("%s: the message write committed at head %d", repo.name, version)
		}
		if _, err := writer.write(t, "notes/plan.md", content); err != nil {
			t.Fatalf("%s: a write outside inbox/: %v", repo.name, err)
		}
		if err := AgentsInboxGuard(writer.world.config.repo, path); !errors.Is(err, ErrEvsInboxMessagesOnly) {
			t.Errorf("%s: the guard as one call: %v", repo.name, err)
		}
	}
	// a general repo that is no Team inbox: inbox/ is any path
	writer := newEvsTestWriter(t)
	if _, err := writer.write(t, path, content); err != nil {
		t.Fatalf("a general repo's inbox/: %v", err)
	}
	if err := AgentsInboxGuard(writer.world.config.repo, path); err != nil {
		t.Fatalf("the guard on a general repo: %v", err)
	}
	// the client's own guard runs after the inbox refusal, which it cannot remove
	writer.test.client.SetWriteGuard(func(ctx context.Context, check *EvsWriteGuardCheck) error {
		return ErrEvsReservedPath
	})
	if _, err := writer.write(t, "notes/other.md", content); !errors.Is(err, ErrEvsReservedPath) {
		t.Fatalf("the client's guard: %v", err)
	}
	writer.test.client.SetWriteGuard(nil)
	if _, err := writer.write(t, "notes/other.md", content); err != nil {
		t.Fatalf("with the client's guard removed: %v", err)
	}
}
