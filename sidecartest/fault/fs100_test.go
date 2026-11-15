//go:build !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-100's format-1 case on T2 (§22.8; §16.11's receipt row, D-MCP-34, FI-26; RECORD-M6-26), in the wakes' world
// (fs100_wake_test.go): requester R a surrogate that leases only its own notice's path, with no directory view open, no
// indexer and no stream sync; approver A denies R's repo request: R gets exactly one hint, reads that notice version and
// the one decision entry its DecisionRef names and no other stream, listing or cards read, shows denied with A's note
// through access_decided, and its pending count falls at once, so a request that met the 20-pending limit is then
// taken. The rest of the row (an approval seating R, a reach approval spent once, a kill between the entry and the
// rewrite, two approvers at once, a cancel racing an approval, a forged DecisionRef) runs in RECORD-M6-19's unit
// schedules and FS-85's case; their place in this row is the review phase's.

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

var Fs100Format1 = Register("FS-100", "format-1", []Tier{TierT2}, Fs100DenialReachesItsRequester)

// FS-100's format-1 case: see the file header.
func Fs100DenialReachesItsRequester(net *Net) *Schedule {
	state := &wakeState{}
	return wakeSchedule(state, []*Step{
		wakeStep(state, "surrogateR", func(ctx context.Context, world *wakeWorld) error {
			if err := world.file(ctx); err != nil {
				return err
			}
			// R files 19 more, reaching the 20 pending requests a sidecar holds
			for index := 0; index < 19; index += 1 {
				if _, err := world.requester.client.Request(ctx, &sidecar.DirectoryRequestAsk{
					Target: &protocol.RequestTarget{RepoId: world.repoId.Bytes()}, Role: uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_READER),
					Reason: "one of many", FiledBy: sidecar.DirectoryFiledByPerson,
				}); err != nil {
					return fmt.Errorf("pending request %d: %w", index+2, err)
				}
			}
			if _, err := world.requester.client.Request(ctx, &sidecar.DirectoryRequestAsk{
				Target: &protocol.RequestTarget{RepoId: world.repoId.Bytes()}, Role: uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_READER),
				Reason: "the 21st", FiledBy: sidecar.DirectoryFiledByPerson,
			}); !errors.Is(err, sidecar.ErrDirectoryRequestLimit) {
				return fmt.Errorf("the 21st pending request: %v", err)
			}
			state.beforeDecision = world.requester.surrogate.Counts()
			return nil
		}),
		wakeStep(state, "daemonA", func(ctx context.Context, world *wakeWorld) error {
			return world.deny(ctx)
		}),
		wakeStep(state, "judge", func(ctx context.Context, world *wakeWorld) error {
			// one hint on R's own notice path for the denial's rewrite
			if wakes := world.requester.surrogate.Wakes(); len(wakes) != 1 {
				return fmt.Errorf("R got %d hints for one denial", len(wakes))
			}
			return nil
		}),
		wakeStep(state, "surrogateR", func(ctx context.Context, world *wakeWorld) error {
			resynced, err := world.requester.phone.Resync(ctx)
			if err != nil {
				return err
			}
			if resynced.Decided != 1 {
				return fmt.Errorf("R's resync %+v", resynced)
			}
			return nil
		}),
		wakeStep(state, "judge", func(ctx context.Context, world *wakeWorld) error {
			before, after := state.beforeDecision, world.requester.surrogate.Counts()
			if after.NoticeReads-before.NoticeReads != 1 || after.EntryReads-before.EntryReads != 1 {
				return fmt.Errorf("R read %d notices and %d entries for its outcome", after.NoticeReads-before.NoticeReads, after.EntryReads-before.EntryReads)
			}
			if after.Listings != 0 || after.Refs != 0 || after.ReadStreams != 0 || after.ReadStreamLogs != 0 || after.ReadCards != 0 {
				return fmt.Errorf("R read beyond one notice and one entry: %+v", after)
			}
			event := "access_decided/denied/" + world.filed.RequestId.String()
			if count := world.requester.raisedCount(event); count != 1 {
				return fmt.Errorf("R raised %s %d times: %v", event, count, world.requester.raised())
			}
			recorded := world.requester.recordedReceipts()
			if len(recorded) != 1 || len(recorded[0].Decisions) != 1 || recorded[0].Decisions[0].Decision.GetNote() != "not this quarter" {
				return fmt.Errorf("R's vault recorded %+v", recorded)
			}
			return nil
		}),
		wakeStep(state, "surrogateR", func(ctx context.Context, world *wakeWorld) error {
			// the decided rewrite freed R's pending count at once: the request the limit refused is taken now
			_, err := world.requester.client.Request(ctx, &sidecar.DirectoryRequestAsk{
				Target: &protocol.RequestTarget{RepoId: world.repoId.Bytes()}, Role: uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_READER),
				Reason: "the 21st, again", FiledBy: sidecar.DirectoryFiledByPerson,
			})
			return err
		}),
	})
}

func TestFs100Format1(t *testing.T) {
	RunRow(t, "FS-100", "format-1", nil)
}
