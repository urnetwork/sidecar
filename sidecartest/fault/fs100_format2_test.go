//go:build !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-100's format-2 case on T2 (§22.8; §16.11's receipt row and its ref cards block's versionless q/ notices,
// D-MCP-34, D-PHASE-11, FI-26; RECORD-M10-06): the format-1 case's steps (fs100_test.go) in the wakes' world with its
// directory at format 2, so every notice is a versionless file, a rewrite's replaced content purged about a minute
// later.
//
//	versionless  R files its request while the directory reads format 2; A's denial rewrites R's notice by path CAS
//	             from the version it read, the path's second version; a minute on the store holds the pending
//	             version's statement and none of its content, and the decided version stands
//	requester    R, leasing only its notice's path, gets exactly one hint for the rewrite and, resyncing only after the
//	             purge, reads that one notice version and the one decision entry its DecisionRef names and no other
//	             stream, listing or cards read; shows denied with A's note through access_decided; and its pending
//	             count falls at once, so a request that met the 20-pending limit is then taken
//	late         a member device that first syncs after the purge finds the pending version's content gone and the
//	             decided notice standing, and alarms nothing
//
// After every step, FI-26 as the wake cases hold it (fs100_wake_test.go).
//
// Not here, as in the format-1 case: an approval seating R, a reach approval spent once, a kill between the entry and
// the rewrite, two approvers at once, a cancel racing an approval and a forged DecisionRef run on versionless notices
// in RECORD-M6-19's and RECORD-M10-03's unit schedules, not as steps of this row; the T3 run, since no DirectoryCards
// binding writes q/ versionless at T3's evs in a composed daemon yet; and the wakes, FS-100's M8 case.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs100Format2 = Register("FS-100", "format-2", []Tier{TierT2}, Fs100DenialOnVersionlessNotices)

// FS-100's format-2 case: see the file header.
func Fs100DenialOnVersionlessNotices(net *Net) *Schedule {
	state := &wakeState{}
	return wakeSchedule(state, fs100DenialSteps(state,
		func(ctx context.Context, world *wakeWorld) error {
			world.cards.RaiseFormat(world.directoryId)
			return nil
		},
		func(ctx context.Context, world *wakeWorld) error {
			// past the purge: the pending version's statement stands with no content, the decided version whole
			world.clock.Advance(sidecartest.DefaultFakeDirectoryCardsSettings().PurgeDelay + time.Second)
			changes, err := world.cards.For(world.approver.sidecarId).ReadCards(ctx, world.directoryId, 0)
			if err != nil {
				return err
			}
			versions := []*sidecar.DirectoryCardFile{}
			for _, file := range changes.Files {
				if file.Path == world.filed.NoticePath {
					versions = append(versions, file)
				}
			}
			if len(versions) != 2 || versions[0].Version != 1 || versions[1].Version != 2 {
				return fmt.Errorf("R's notice path holds %d versions, not the pending one and its rewrite", len(versions))
			}
			if versions[0].Content != nil {
				return errors.New("a versionless notice's replaced content stands a minute after its rewrite")
			}
			if versions[0].SignerSidecarId != world.requester.sidecarId || versions[1].SignerSidecarId != world.approver.sidecarId {
				return fmt.Errorf("R's notice written by %s and rewritten by %s", versions[0].SignerSidecarId, versions[1].SignerSidecarId)
			}
			notice, err := sidecar.DirectoryDecodeNotice(versions[1].Content)
			if err != nil {
				return err
			}
			if sidecar.DirectoryNoticeState(notice.GetState()) != sidecar.DirectoryNoticeStateDecided || sidecar.DirectoryOutcome(notice.GetOutcome()) != sidecar.DirectoryOutcomeDenied {
				return fmt.Errorf("the notice standing after the purge: %v", notice)
			}
			// a device that first syncs now reads the directory at format 2, shows the request denied and alarms nothing
			late, err := world.device("a late member's desktop", sidecar.NewId())
			if err != nil {
				return err
			}
			world.recordFixture.TimeMillis = world.clock.Now().UnixMilli()
			world.directoryFixture.TimeMillis = world.recordFixture.TimeMillis
			world.recordAuth.Append(world.recordFixture)
			world.directoryAuth.Append(world.directoryFixture)
			if err := world.open(late, false); err != nil {
				return err
			}
			if err := late.client.Sync(ctx); err != nil {
				return err
			}
			if !late.client.Format2() {
				return errors.New("the late device does not read the directory at format 2")
			}
			requestId := world.filed.RequestId
			views, err := late.client.GetRequests(ctx, &sidecar.DirectoryRequestFilter{RequestId: &requestId})
			if err != nil {
				return err
			}
			if len(views) != 1 || views[0].State != sidecar.DirectoryRequestDenied || len(views[0].Decisions) != 1 {
				return fmt.Errorf("the late device's view of R's request: %+v", views)
			}
			late.stateLock.Lock()
			defer late.stateLock.Unlock()
			if 0 < len(late.alarms) {
				return fmt.Errorf("the late device alarmed over a purged notice version: %v", late.alarms)
			}
			return nil
		},
	))
}

func TestFs100Format2(t *testing.T) {
	RunRow(t, "FS-100", "format-2", nil)
}
