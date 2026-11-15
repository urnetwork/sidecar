//go:build !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-87's M6 directory legs on T2 (§22.8; §16.11's Erasure and removal block and its retention row, owner decisions
// 177 and 181, FI-25; RECORD-M6-26, over RECORD-M6-20's runner and RECORD-M6-21's removal), in the directory world
// (fs85_test.go):
//
//	mask      a MemberRevoke masks the removed member's pending request at its position, in the approver's view and in
//	          a fresh reader's, the notice file still standing
//	cleanup   with no indexer designated, a member device's cleanup 24 h later removes the revoked device's notices in
//	          one push, and not a minute before
//	revoke    repo admin A revokes repo P's announcement while a member's run names P; the run's daemon renews before it
//	          reads the marker; the directory admin's runner then erases every copy naming P, the renewal included,
//	          and no announce entry naming P has a readable key at evs
//	expiry    with no runner, an announce entry past its 30 days waits, and the directory admin's ur status lines name
//	          the oldest one waiting
//
// After every step, FI-26 as the directory world holds it. FI-19 and FI-21 are TEST-M10-02's oracles and FI-25
// RECORD-M6-25's: until they are bound this case checks their M6 clauses itself (no copy naming a revoked repo keeps a
// readable key; a masked writer's request shows nowhere). Not here: the group's Removes and rotation (KEYS-M6-03's
// leg), the T3 run, and the index and card cases at the later of M6-out and M10-out.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

var Fs87M6 = Register("FS-87", "", []Tier{TierT2}, Fs87RemovalAndRetention)

// The announce entries naming repoId whose key a fresh read at evs still opens.
func (self *dirWorld) readableNaming(ctx context.Context, repoId sidecar.Id) (int, error) {
	reader := self.admin.record.Reader()
	if err := reader.Sync(ctx, self.directoryId); err != nil {
		return 0, err
	}
	entries, _ := reader.EntriesOfKinds(self.directoryId, 0, sidecar.RecordKindAnnounce)
	readable := 0
	for _, entry := range entries {
		if entry.State != sidecar.RecordEntryLive || entry.Body == nil {
			continue
		}
		item, err := sidecar.DirectoryDecodeAnnouncement(entry.Body)
		if err != nil {
			continue
		}
		if bytes.Equal(item.GetWhere().GetRepoId(), repoId.Bytes()) && !item.GetWhere().GetPrivate() {
			readable += 1
		}
	}
	return readable, nil
}

// FS-87's M6 directory legs: see the file header.
func Fs87RemovalAndRetention(net *Net) *Schedule {
	state := &dirState{}
	var runner *sidecar.DirectoryErasureRunner
	var removal *sidecar.DirectoryRemoval
	member := &dirDevice{}
	runId := sidecar.NewId()
	return dirSchedule(state, "FI-26/removal", []*Step{
		dirStep(state, "daemonR", func(ctx context.Context, world *dirWorld) error {
			return world.file(ctx, "read", world.requester, &protocol.RequestTarget{RepoId: world.repoId.Bytes()}, protocol.RepoGrantRole_REPO_GRANT_ROLE_READER, 0)
		}),
		dirStep(state, "authority", func(ctx context.Context, world *dirWorld) error {
			// R's member is removed: its device revoked at the next position
			world.directoryFixture.Sidecars[world.requester.sidecarId].RevokedAt = world.directoryAuth.Tip().Pin().GetVersion() + 1
			world.publish()
			return nil
		}),
		dirStep(state, "daemonA", func(ctx context.Context, world *dirWorld) error {
			if err := world.approver.client.Sync(ctx); err != nil {
				return err
			}
			requestId := world.filed["read"].RequestId
			views, err := world.approver.client.GetRequests(ctx, &sidecar.DirectoryRequestFilter{RequestId: &requestId})
			if err != nil {
				return err
			}
			if len(views) != 0 {
				return fmt.Errorf("A still shows a removed member's request: %+v", views[0])
			}
			if notice, _, err := world.notice(ctx, "read"); err != nil || notice == nil {
				return fmt.Errorf("the notice went before any cleanup: %v", err)
			}
			return nil
		}),
		dirStep(state, "daemonA", func(ctx context.Context, world *dirWorld) error {
			var err error
			if removal, err = sidecar.NewDirectoryRemoval(&sidecar.DirectoryRemovalArgs{Client: world.approver.client}); err != nil {
				return err
			}
			world.clock.Advance(24*time.Hour - time.Minute)
			world.publish()
			if err := world.approver.client.Sync(ctx); err != nil {
				return err
			}
			pass, err := removal.Cleanup(ctx)
			if err != nil {
				return err
			}
			if !pass.Cleans || len(pass.Removed) != 0 || len(pass.Waiting) != 1 {
				return fmt.Errorf("a cleanup a minute before 24 h: %+v", pass)
			}
			return nil
		}),
		dirStep(state, "daemonA", func(ctx context.Context, world *dirWorld) error {
			world.clock.Advance(time.Minute)
			world.publish()
			if err := world.approver.client.Sync(ctx); err != nil {
				return err
			}
			pushes := world.cards.Counts().RemovalPushes
			pass, err := removal.Cleanup(ctx)
			if err != nil {
				return err
			}
			if !slices.Equal(pass.Removed, []string{world.filed["read"].NoticePath}) || world.cards.Counts().RemovalPushes != pushes+1 {
				return fmt.Errorf("the cleanup at 24 h: %+v", pass)
			}
			if notice, _, err := world.notice(ctx, "read"); err != nil || notice != nil {
				return fmt.Errorf("the notice after the cleanup: %v %v", notice, err)
			}
			return nil
		}),
		dirStep(state, "daemonA", func(ctx context.Context, world *dirWorld) error {
			// P announced by its admin; a member's device runs in P
			if _, err := world.approver.client.AnnounceRepo(ctx, &sidecar.DirectoryRepoAnnounceArgs{RepoId: world.repoId, DisplayName: "launch plans", Confirmed: true}); err != nil {
				return err
			}
			if err := world.approver.record.Flush(ctx); err != nil {
				return err
			}
			var err error
			if member, err = world.device("member M", sidecar.NewId(), false); err != nil {
				return err
			}
			world.publish()
			if err := world.open(member); err != nil {
				return err
			}
			if err := member.client.Sync(ctx); err != nil {
				return err
			}
			repoId := world.repoId
			if err := member.client.Runs().Started(&sidecar.DirectoryRunStart{
				RunId: runId, Claims: sidecar.DirectoryRunClaimsAuto, ProjectKey: "launch", AgentLabel: "planner", Harness: "codex",
				Title: "draft the launch", RepoId: &repoId, Branch: "main",
			}); err != nil {
				return err
			}
			// a second run in no repo, which stops renewing and expires: what retention later erases
			if err := member.client.Runs().Started(&sidecar.DirectoryRunStart{
				RunId: sidecar.NewId(), Claims: sidecar.DirectoryRunClaimsAuto, ProjectKey: "notes", AgentLabel: "scribe", Harness: "codex",
				Title: "tidy the notes", Project: "example.org/team/notes", Branch: "main",
			}); err != nil {
				return err
			}
			world.clock.Advance(10 * time.Second)
			return member.record.Flush(ctx)
		}),
		dirStep(state, "daemonA", func(ctx context.Context, world *dirWorld) error {
			if err := world.approver.client.Sync(ctx); err != nil {
				return err
			}
			revocation, err := world.approver.client.RevokeRepo(ctx, &sidecar.DirectoryRevokeArgs{RepoId: world.repoId, Confirmed: true})
			if err != nil {
				return err
			}
			if revocation.State != sidecar.DirectoryRevocationPending {
				return fmt.Errorf("the revocation: %+v", revocation)
			}
			return world.approver.record.Flush(ctx)
		}),
		dirStep(state, "daemonM", func(ctx context.Context, world *dirWorld) error {
			// the run's daemon renews before it reads the marker: a copy naming P written after the request
			member.client.Runs().Moved(runId)
			world.clock.Advance(66 * time.Minute)
			return member.record.Flush(ctx)
		}),
		dirStep(state, "daemonD", func(ctx context.Context, world *dirWorld) error {
			world.admin.client.BindEraser(world.admin.record.Eraser().Erase)
			var err error
			runner, err = sidecar.NewDirectoryErasureRunner(&sidecar.DirectoryErasureRunnerArgs{
				Client: world.admin.client, Erase: world.admin.record.Eraser().Erase, Random: zeroReader{},
			})
			if err != nil {
				return err
			}
			for range 2 {
				if err := world.admin.client.Sync(ctx); err != nil {
					return err
				}
				if _, err := runner.Pass(ctx); err != nil {
					return err
				}
				if err := world.admin.record.Flush(ctx); err != nil {
					return err
				}
			}
			readable, err := world.readableNaming(ctx, world.repoId)
			if err != nil {
				return err
			}
			if readable != 0 {
				return fmt.Errorf("%d announce entries naming the revoked repo keep a readable key", readable)
			}
			return nil
		}),
		dirStep(state, "daemonD", func(ctx context.Context, world *dirWorld) error {
			// with no runner pass, an expired announce entry waits, and D's status names the oldest
			world.clock.Advance(32 * 24 * time.Hour)
			world.publish()
			if err := world.admin.client.Sync(ctx); err != nil {
				return err
			}
			waiting := world.admin.client.RetentionWaiting(nil)
			if len(waiting) == 0 {
				return errors.New("nothing waits for expiry 32 days on")
			}
			lines := world.admin.client.ErasureStatusLines(nil)
			if !slices.ContainsFunc(lines, func(line string) bool { return strings.Contains(line, waiting[0].EntryId.String()) }) {
				return fmt.Errorf("D's status lines name no oldest entry: %q", lines)
			}
			return nil
		}),
	})
}

// Randomness that draws zero, so a runner's wait is none.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestFs87M6(t *testing.T) {
	RunRow(t, "FS-87", "", nil)
}
