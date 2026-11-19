// History drops, versioning rules and the repo lock on the evs world (EVS2-M10-31; §11.7's choose, refused, action and
// states rows, §11.13's drop job, §8.8's lock; FS-68, FS-91, FS-94, FS-95): what a world sets so a row drives the
// client's dry run, DropHistory and CancelDrop through the engine's own drop routes and push route, with the drop table
// the engine keeps, and runs taskworker's halves beside them.
//
//	limits     EvsWorldSettings.Drops gives the world's network its evs_drops_per_day and evs_drop_previews_per_day in
//	           the fake Quota, which evs counts a DROP and a dry run against; nil gives none, and evs refuses both
//	dry runs   a device's read of a dry run first runs the repo's queued dry runs as taskworker's job does, over the
//	           real resolve and mark and the nightly pass's own horizon (runDropPreviews), so a client's poll finds its
//	           dry run done within one read
//	drops      Drop is `ur history drop`: the dry run and the DROP push it confirms, kept by path; DropRefused is one
//	           the client or evs refuses, its error handed to the schedule's check; CancelDrop cancels a path's drop
//	job        RunDropJob runs the repo's drop job as taskworker runs it, over the real resolve, mark, dropverify's
//	           verify and deletes, its horizon the nightly pass's own, its lock the world's newest authorization state
//	           and its mode the Net's gates', until it ends or waits on the clock
//	readers    HistoryStates and ReadVersionEnds read a path through a device and hold each listed version to the state
//	           and the read's end a clause names
//	lock       LockRepo files or lifts the repo's lock in the world's authorization state, a new position every device
//	           and evs instance reads, or one instance alone still holds the old one (EvsWorld.HoldView)
//	rules      SetVersioningRules sets the network's VersioningRules record and the repo's own RepoVersioning rules as
//	           every format-2 device reads them. A device takes a new path's setting from sidecar.ConfigVersioningUnder
//	           over the repo's rules, else the network's, else the platform rule, a present record replacing the next
//	           entirely and a lock keeping versioning on: ConfigState.VersioningFor's order, which the world stands in
//	           for since its authorization state is rows, not a config head (TEAM-M10-01's tests hold the real one)
//	consent    in an owner-bound world the gate view answers D-ACL-25 from the repo's row, its owner and consented
//	           devices, as AclState.MayDrop does over a projection: the world's state is rows alone
//
// A hand-built push (PostPlan) is a plan a schedule fills over the pins the world reads from the ref's newest
// committed statement, signed by a device's key and posted through the world's lb, so a schedule holds its instance at
// a barrier: the reuse copies FS-91 races, which the client's planner writes only from a git tier's publish.

package fault

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/evsservice/dropverify"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The network's drop limits as Setup gives them to the fake Quota.
type EvsWorldDropSettings struct {
	// evs_drops_per_day and evs_drop_previews_per_day.
	DropsPerDay        int64
	DropPreviewsPerDay int64
	// How many runs RunDropJob gives a job before it fails as never ending.
	JobRunCount int
	// The segment cluster's drive figures the world publishes before each job run, as §19.6's hdd loop does: well
	// under the pause line.
	HddDriveOpsPerSecond float64
	HddCapacityOps       int64
	// The job's read pace and DELETE rate, past anything a schedule's clock would wait on: a schedule moves the clock
	// itself.
	ReadBytesPerSecond int64
	DeletesPerSecond   int
}

// Ten drops and ten dry runs a day, past what any schedule files unless it sets fewer.
func DefaultEvsWorldDropSettings() *EvsWorldDropSettings {
	return &EvsWorldDropSettings{
		DropsPerDay:          10,
		DropPreviewsPerDay:   10,
		JobRunCount:          20,
		HddDriveOpsPerSecond: 10,
		HddCapacityOps:       1000,
		ReadBytesPerSecond:   1000 * 1000 * 1000 * 1000 * 1000,
		DeletesPerSecond:     1000 * 1000,
	}
}

// One committed drop of a path as the world keeps it.
type EvsWorldDrop struct {
	Device string
	Path   string
	Push   *sidecar.EvsDropPushResult
}

// dropverify.Verify behind evsservice.DropVerifier, as taskworker injects it.
type fsDropVerifier struct{}

func (self fsDropVerifier) Verify(ctx context.Context, request *evsservice.DropVerifyRequest) (*evsservice.DropVerifyResult, error) {
	drops := make([]*dropverify.Drop, 0, len(request.Drops))
	for _, drop := range request.Drops {
		drops = append(drops, &dropverify.Drop{DropId: drop.DropId, RefId: drop.RefId, Version: drop.Version})
	}
	result, err := dropverify.Verify(ctx, &dropverify.Request{
		Cluster: request.Cluster, SegmentCluster: request.SegmentCluster, RepoId: request.RepoId, JobId: request.JobId,
		Round: request.Round, Marked: request.Marked, Since: request.Since, Drops: drops,
		Executed: request.Liveness.Executed, LockStanding: request.LockStanding, Pace: request.Pace,
	})
	if err != nil {
		return nil, err
	}
	lateMarks := make([]evsservice.DropScanId, 0, len(result.LateMarks))
	for _, id := range result.LateMarks {
		lateMarks = append(lateMarks, evsservice.DropScanId{Id: id.Id, Kind: evsservice.DropIdKind(id.Kind)})
	}
	return &evsservice.DropVerifyResult{
		Snapshot: result.Snapshot, Disagree: result.Disagree, Detail: result.Detail, LateMarks: lateMarks,
		Cancelled: result.Cancelled, Locked: result.Locked, ScanByteCount: result.ScanByteCount,
	}, nil
}

// The lock the drop job's start CAS and verify read: the world's newest authorization state's.
type evsWorldDropLocks struct {
	world *EvsWorld
}

func (self *evsWorldDropLocks) LockStanding(networkId sidecar.Id, repoId sidecar.Id) (bool, evsservice.EvsAuthAnswer) {
	view := self.world.currentView()
	if view == nil || networkId != self.world.NetworkId {
		return false, evsservice.EvsAuthUnknown
	}
	row := view.Repo(repoId)
	if row == nil {
		return false, evsservice.EvsAuthUnknown
	}
	return row.GetLock() == protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED, evsservice.EvsAuthAllowed
}

// A gate view that answers D-ACL-25 from the repo's row: see the file header's consent row.
type evsWorldConsentView struct {
	sidecar.GkmAuthView
}

func (self *evsWorldConsentView) MayDrop(subjectId sidecar.Id, repoId sidecar.Id, now time.Time) sidecar.AclDecision {
	repo := self.GkmAuthView.Repo(repoId)
	row := self.GkmAuthView.SidecarRow(subjectId)
	if repo == nil || row == nil {
		return sidecar.AclDecision{Reason: sidecar.AclReasonNoRepo}
	}
	admin := slices.ContainsFunc(repo.GetAdmins(), func(admin *protocol.AclRepoAdminRow) bool {
		return bytes.Equal(admin.GetSidecarId(), subjectId.Bytes())
	})
	consented := slices.ContainsFunc(repo.GetConsentedSidecarIds(), func(consentedId []byte) bool {
		return bytes.Equal(consentedId, subjectId.Bytes())
	})
	if !admin || !consented || !bytes.Equal(row.GetMemberId(), repo.GetOwnerMemberId()) {
		return sidecar.AclDecision{Reason: sidecar.AclReasonNoGrant}
	}
	return sidecar.AclDecision{Allowed: true}
}

func (self *evsWorldConsentView) At(pin *bridge.AuthPin) (sidecar.GkmAuthView, error) {
	view, err := self.GkmAuthView.At(pin)
	if err != nil {
		return nil, err
	}
	return &evsWorldConsentView{GkmAuthView: view}, nil
}

// The drop settings of the world, the defaults where it names none.
func (self *EvsWorld) dropSettings() *EvsWorldDropSettings {
	if self.settings.Drops != nil {
		return self.settings.Drops
	}
	return DefaultEvsWorldDropSettings()
}

// taskworker's drop settings: the defaults, with no pace a schedule's clock would wait on.
func (self *EvsWorld) dropJobSettings() *evsservice.DropSettings {
	settings := evsservice.DefaultDropSettings()
	settings.ReadBytesPerSecond = self.dropSettings().ReadBytesPerSecond
	settings.DeletesPerSecond = self.dropSettings().DeletesPerSecond
	return settings
}

// taskworker's engine settings at format 2: the tier's where it names any, as EvacuateAt takes them.
func (self *EvsWorld) dropEvsSettings(net *Net) (*evsservice.EvsSettings, error) {
	settings := evsservice.DefaultEvsSettings()
	settings.InstanceFormat = sidecar.EvsRepoFormat2
	if tier := evsTierOf(net); tier != nil && tier.JobSettings != nil {
		tierSettings, err := tier.JobSettings(sidecar.EvsRepoFormat2)
		if err != nil {
			return nil, err
		}
		if tierSettings != nil {
			settings = tierSettings
		}
	}
	return settings, nil
}

// The repo's cluster's id.
func (self *EvsWorld) repoClusterId(net *Net) (string, error) {
	first, err := net.Host().Blobs.FirstCluster()
	if err != nil {
		return "", err
	}
	return first.ClusterId(), nil
}

// Runs the repo's queued dry runs as taskworker's job does, until none is queued: see the file header.
func (self *EvsWorld) runDropPreviews(ctx context.Context) error {
	net := self.net
	evsSettings, err := self.dropEvsSettings(net)
	if err != nil {
		return err
	}
	dropSettings := self.dropJobSettings()
	resolver, err := evsservice.NewDropResolve(net.Host(), &evsservice.DropResolveDeps{Settings: dropSettings, EvsSettings: evsSettings})
	if err != nil {
		return err
	}
	marker, err := evsservice.NewDropMark(net.Host(), &evsservice.DropMarkDeps{Settings: dropSettings, EvsSettings: evsSettings})
	if err != nil {
		return err
	}
	previews, err := evsservice.NewDropPreviews(net.Host(), &evsservice.DropPreviewDeps{
		Resolver: resolver, Marker: marker, Settings: dropSettings, EvsSettings: evsSettings,
	})
	if err != nil {
		return err
	}
	clusterId, err := self.repoClusterId(net)
	if err != nil {
		return err
	}
	for range self.dropSettings().JobRunCount {
		result, err := previews.Run(ctx, clusterId, self.RepoId)
		if err != nil {
			return err
		}
		if result.PreviewId == (sidecar.Id{}) {
			return nil
		}
	}
	return errors.New("the repo's dry runs never ran out")
}

// Whether request reads a dry run's result.
func evsWorldReadsDropPreview(request *http.Request) bool {
	return request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/drops/preview/")
}

// A step action: device drops path's history on main, the dry run first and the DROP it confirms, with now or after
// the 7-day window, which must commit as one push. The world keeps the drop by path.
func (self *EvsWorld) Drop(device string, path string, now bool) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		result, err := self.drop(ctx, device, path, now)
		if err != nil {
			return fmt.Errorf("%s's drop of %q: %w", device, path, err)
		}
		if len(result.Pushes) != 1 {
			return fmt.Errorf("%s's drop of %q went as %d pushes", device, path, len(result.Pushes))
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.drops[path] = &EvsWorldDrop{Device: device, Path: path, Push: result.Pushes[0]}
		return nil
	}
}

// A step action: device's drop of path's history must be refused, by the client before it sends or by evs, and check
// judges the error.
func (self *EvsWorld) DropRefused(device string, path string, now bool, check func(err error) error) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		_, err := self.drop(ctx, device, path, now)
		if err == nil {
			return fmt.Errorf("%s's drop of %q committed", device, path)
		}
		if failure := check(err); failure != nil {
			return fmt.Errorf("%s's drop of %q ended %v: %w", device, path, err, failure)
		}
		return nil
	}
}

// The dry run and the DROP it confirms.
func (self *EvsWorld) drop(ctx context.Context, deviceName string, path string, now bool) (*sidecar.EvsDropHistoryResult, error) {
	return self.dropTampered(ctx, deviceName, path, now, nil)
}

// drop, with tamper, nil for none, changing each lineage between the dry run and the DROP it confirms: a modified
// client's DROP, signed over a list its dry run did not compare.
func (self *EvsWorld) dropTampered(ctx context.Context, deviceName string, path string, now bool, tamper func(lineage *sidecar.EvsDropLineage) error) (*sidecar.EvsDropHistoryResult, error) {
	device := self.Device(deviceName)
	if device.Repo == nil {
		return nil, fmt.Errorf("device %s is not started: Setup runs first", deviceName)
	}
	preview, err := device.Repo.DropHistoryPreview(ctx, &sidecar.EvsDropPreviewArgs{Paths: []string{path}})
	if err != nil {
		return nil, err
	}
	if tamper != nil {
		for _, lineage := range preview.Lineages {
			if err := tamper(lineage); err != nil {
				return nil, err
			}
		}
	}
	args := &sidecar.EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: sidecar.EvsDropConfirmText(preview), Now: now}
	if now {
		args.ConfirmNow = sidecar.EvsDropConfirmNow
	}
	return device.Repo.DropHistory(ctx, args)
}

// A step action: a modified client's drop of path's history on main, with now: device's dry run, then a DROP whose
// list for the path leaves out its oldest listed version or, with adding, lists one entry hash more, no version's,
// the count and hash signed over the list as sent. It must commit, as evs holds a list only to its bound and its
// base (§11.7's list row), and the job's resolve judges the rest ({mismatch}). The world keeps the drop by path.
func (self *EvsWorld) DropWithWrongList(device string, path string, now bool, adding bool) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		result, err := self.dropTampered(ctx, device, path, now, func(lineage *sidecar.EvsDropLineage) error {
			sent := slices.Clone(lineage.Listed)
			if adding {
				extra := sha256.Sum256([]byte("evs world: an entry hash of no version of " + path))
				sent = append(sent, extra[:])
				slices.SortFunc(sent, bytes.Compare)
			} else {
				if len(sent) < 2 {
					return fmt.Errorf("%q lists %d versions: none to leave out beside another", path, len(sent))
				}
				// the versions walked are newest first: the oldest listed version's entry hash is the one left out
				oldest := lineage.Versions[len(lineage.Versions)-1]
				sent = slices.DeleteFunc(sent, func(hash []byte) bool { return bytes.Equal(hash, oldest.EntrySha256) })
				if len(sent) != len(lineage.Listed)-1 {
					return fmt.Errorf("%q's oldest version is not in its list", path)
				}
			}
			signed := proto.Clone(lineage.DropPath).(*protocol.EvsDropPath)
			if _, err := sidecar.EvsBuildDropLists([]*protocol.EvsDropPath{signed}, [][][]byte{sent}); err != nil {
				return err
			}
			lineage.Listed = sent
			lineage.DropPath.Count, lineage.DropPath.ListedSha256 = signed.GetCount(), signed.GetListedSha256()
			return nil
		})
		if err != nil {
			return fmt.Errorf("%s's drop of %q with a list that is not its versions: %w", device, path, err)
		}
		if len(result.Pushes) != 1 {
			return fmt.Errorf("%s's drop of %q went as %d pushes", device, path, len(result.Pushes))
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.drops[path] = &EvsWorldDrop{Device: device, Path: path, Push: result.Pushes[0]}
		return nil
	}
}

// The drop of path the world keeps, nil for none.
func (self *EvsWorld) DropOf(path string) *EvsWorldDrop {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.drops[path]
}

// A step action: device cancels path's drop, which must commit.
func (self *EvsWorld) CancelDrop(device string, path string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		_, err := self.cancelDrop(ctx, device, path)
		if err != nil {
			return fmt.Errorf("%s's cancel of %q's drop: %w", device, path, err)
		}
		return nil
	}
}

// A step action: device's cancel of path's drop must be refused, and check judges the error.
func (self *EvsWorld) CancelDropRefused(device string, path string, check func(err error) error) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		_, err := self.cancelDrop(ctx, device, path)
		if err == nil {
			return fmt.Errorf("%s's cancel of %q's drop committed", device, path)
		}
		if failure := check(err); failure != nil {
			return fmt.Errorf("%s's cancel of %q's drop ended %v: %w", device, path, err, failure)
		}
		return nil
	}
}

func (self *EvsWorld) cancelDrop(ctx context.Context, deviceName string, path string) (*sidecar.EvsCancelDropResult, error) {
	drop := self.DropOf(path)
	if drop == nil {
		return nil, fmt.Errorf("the world holds no drop of %q", path)
	}
	return self.Device(deviceName).Repo.CancelDrop(ctx, &sidecar.EvsCancelDropArgs{DropId: drop.Push.DropId})
}

// Whether err is evs's refusal with code.
func EvsWorldRefusedWith(err error, code protocol.EvsRefusalCode) bool {
	evsError, ok := sidecar.EvsErrorOf(err)
	return ok && evsError.Code == code
}

// A DropRefused check: evs refused the push with code at status.
func EvsWorldExpectRefusal(status int, code protocol.EvsRefusalCode) func(err error) error {
	return func(err error) error {
		evsError, ok := sidecar.EvsErrorOf(err)
		if !ok || evsError.Status != status || evsError.Code != code {
			return fmt.Errorf("not evs's %d %s", status, code)
		}
		return nil
	}
}

// A DropRefused check: the client refused with target before or after it sent.
func EvsWorldExpectError(target error) func(err error) error {
	return func(err error) error {
		if !errors.Is(err, target) {
			return fmt.Errorf("not %v", target)
		}
		return nil
	}
}

// The segment cluster's capacity known and well under the pause line, as §19.6's hdd loop publishes it.
func (self *EvsWorld) publishHdd(ctx context.Context, net *Net) error {
	segmentCluster, err := net.Host().Blobs.SegmentCluster()
	if err != nil {
		return err
	}
	settings := self.dropSettings()
	figures, err := json.Marshal(&evsservice.HddFigures{
		ClusterId: segmentCluster.ClusterId(), TimeMs: net.Clock().Now().UnixMilli(),
		DriveOpsPerSecond: settings.HddDriveOpsPerSecond, CapacityOps: settings.HddCapacityOps,
	})
	if err != nil {
		return err
	}
	return net.Host().Redis.HashSet(sidecartest.InspectContext(ctx), "{nvb_"+segmentCluster.ClusterId()+"}", map[string][]byte{"hdd": figures})
}

// A step action: the repo's drop job as taskworker's instance runs it (see the file header's job row), run again
// while it asks to at once, until it ends or waits past the clock; check gets the last run's result, nil for none.
func (self *EvsWorld) RunDropJob(instance string, check func(result *evsservice.DropJobResult) error) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		evsSettings, err := self.dropEvsSettings(net)
		if err != nil {
			return err
		}
		dropSettings := self.dropJobSettings()
		format2 := evsservice.NewFormat2Gate(net.Host())
		resolver, err := evsservice.NewDropResolve(net.Host(), &evsservice.DropResolveDeps{Settings: dropSettings, EvsSettings: evsSettings})
		if err != nil {
			return err
		}
		marker, err := evsservice.NewDropMark(net.Host(), &evsservice.DropMarkDeps{Settings: dropSettings, EvsSettings: evsSettings})
		if err != nil {
			return err
		}
		deleter, err := evsservice.NewDropDelete(net.Host(), &evsservice.DropDeleteDeps{Format2: format2, Settings: dropSettings, EvsSettings: evsSettings})
		if err != nil {
			return err
		}
		job, err := evsservice.NewDropJob(net.Host(), &evsservice.DropJobDeps{
			Resolver: resolver, Marker: marker, Verifier: fsDropVerifier{}, Deleter: deleter, Locks: &evsWorldDropLocks{world: self},
			Format2: format2, Settings: dropSettings, EvsSettings: evsSettings, Instance: fsDropInstanceId(instance),
		})
		if err != nil {
			return err
		}
		clusterId, err := self.repoClusterId(net)
		if err != nil {
			return err
		}
		var result *evsservice.DropJobResult
		for range self.dropSettings().JobRunCount {
			if err := self.publishHdd(ctx, net); err != nil {
				return err
			}
			if result, err = job.Run(ctx, clusterId, self.RepoId); err != nil {
				return fmt.Errorf("the drop job: %w", err)
			}
			if result.Ended || result.Next.IsZero() || net.Clock().Now().Before(result.Next) {
				break
			}
		}
		if check == nil {
			return nil
		}
		if err := check(result); err != nil {
			return fmt.Errorf("the drop job (round %d, waiting %q, ended %t, moved %v): %w", result.Round, result.Waiting, result.Ended, result.Moved, err)
		}
		return nil
	}
}

// A job instance's id from its name.
func fsDropInstanceId(instance string) sidecar.Id {
	digest := sha256.Sum256([]byte("evs world drop job instance " + instance))
	return sidecar.Id(digest[:16])
}

// The drop table's state of path's drop: 0 where the table holds none.
func (self *EvsWorld) DropState(ctx context.Context, path string) (evsservice.DropState, error) {
	drop := self.DropOf(path)
	if drop == nil {
		return 0, fmt.Errorf("the world holds no drop of %q", path)
	}
	net := self.net
	table, err := evsservice.NewDropTable(net.Host(), evsservice.NewBudgetedBlobs(net.Host().Blobs), self.dropJobSettings(), nil)
	if err != nil {
		return 0, err
	}
	cluster, err := net.Host().Blobs.FirstCluster()
	if err != nil {
		return 0, err
	}
	read, err := table.Read(sidecartest.InspectContext(ctx), cluster, self.RepoId)
	if err != nil {
		return 0, err
	}
	if entry := read.State.Drop(drop.Push.DropId); entry != nil {
		return entry.State, nil
	}
	if void := read.State.Void(drop.Push.DropId); void != nil {
		return void.State, nil
	}
	return 0, nil
}

// A step action: the drop table holds path's drop in state.
func (self *EvsWorld) ExpectDropState(path string, state evsservice.DropState) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		got, err := self.DropState(ctx, path)
		if err != nil {
			return err
		}
		if got != state {
			return fmt.Errorf("%q's drop stands in state %d, not %d", path, got, state)
		}
		return nil
	}
}

// The path version of path's ordinal-th write on main, from 1: a path's versions count up from the ref version its
// first write committed at, one a write, a drop's rewrite of its head included.
func (self *EvsWorld) PathVersion(path string, ordinal int) (uint64, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, write := range self.pathWrites[path] {
		if write.state == evsWorldWriteCommitted {
			return write.version + uint64(ordinal) - 1, nil
		}
	}
	return 0, fmt.Errorf("no write of %q committed", path)
}

// A step action: device reads path's history, whose versions must read in states, each named by its write's ordinal
// (PathVersion): "kept", "collected", sidecar.EvsVersionStateDropPending or sidecar.EvsVersionStateDropped. A version
// states does not name is not judged.
func (self *EvsWorld) HistoryStates(device string, path string, states map[int]string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		history, err := self.Device(device).Repo.History(ctx, &sidecar.EvsReadArgs{Path: path, Fresh: true})
		if err != nil {
			return fmt.Errorf("%s's history of %q: %w", device, path, err)
		}
		seen := map[uint64]string{}
		for _, version := range history.Versions {
			seen[version.Version] = version.State
		}
		for ordinal, state := range states {
			version, err := self.PathVersion(path, ordinal)
			if err != nil {
				return err
			}
			got, listed := seen[version]
			if !listed {
				return fmt.Errorf("%s's history of %q lists no version %d, its write %d: %v", device, path, version, ordinal, seen)
			}
			if got != state {
				return fmt.Errorf("%s's history of %q reads version %d, its write %d, as %q, not %q", device, path, version, ordinal, got, state)
			}
		}
		return nil
	}
}

// A step action: device reads path at the version its ordinal-th write made (PathVersion), which must end as check
// says; check gets the content read and the read's error.
func (self *EvsWorld) ReadVersionEnds(device string, path string, ordinal int, check func(content []byte, err error) error) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		version, err := self.PathVersion(path, ordinal)
		if err != nil {
			return err
		}
		out := &bytes.Buffer{}
		_, err = self.Device(device).Repo.ReadVersion(ctx, &sidecar.EvsReadArgs{Path: path, Version: version, Fresh: true}, out)
		if failure := check(out.Bytes(), err); failure != nil {
			return fmt.Errorf("%s's read of %q at version %d, its write %d, ended %v: %w", device, path, version, ordinal, err, failure)
		}
		return nil
	}
}

// A ReadVersionEnds check: the version reads whole as content.
func EvsWorldReadsContent(content []byte) func(read []byte, err error) error {
	return func(read []byte, err error) error {
		if err != nil {
			return errors.New("not read")
		}
		if !bytes.Equal(read, content) {
			return fmt.Errorf("read %d bytes that are not the version's", len(read))
		}
		return nil
	}
}

// A ReadVersionEnds check: the version reads as dropped, nothing of it shown.
func EvsWorldReadsDropped() func(read []byte, err error) error {
	return func(read []byte, err error) error {
		if !errors.Is(err, sidecar.ErrEvsDropped) {
			return errors.New("not EVS_DROPPED")
		}
		if len(read) != 0 {
			return fmt.Errorf("%d bytes of a dropped version shown", len(read))
		}
		return nil
	}
}

// A step action: the repo's lock is filed (locked) or lifted in the world's authorization state, a new position every
// device and every evs instance not held stale reads.
func (self *EvsWorld) LockRepo(locked bool) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		self.stateLock.Lock()
		self.locked = locked
		self.stateLock.Unlock()
		self.appendView()
		return nil
	}
}

// Whether the world's newest authorization state holds the repo locked.
func (self *EvsWorld) lockStanding() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.locked
}

// A step action: the network's VersioningRules record becomes network and the repo's own RepoVersioning rules
// repo, nil for none of either, as every format-2 device reads them from then on.
func (self *EvsWorld) SetVersioningRules(network *protocol.VersioningRules, repo *protocol.VersioningRules) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		for _, rules := range []*protocol.VersioningRules{network, repo} {
			if rules == nil {
				continue
			}
			if err := sidecar.CheckVersioningRules(rules); err != nil {
				return err
			}
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.networkRules, self.repoRules = network, repo
		return nil
	}
}

// The setting the rules give a path a device creates: see the file header's rules row.
func (self *EvsWorld) versioningFor(repoId sidecar.Id, filePath string, size uint64) (uint32, error) {
	if repoId != self.RepoId {
		return 0, fmt.Errorf("%w: no repo %s", sidecar.ErrConfigVersioningNotCovered, repoId)
	}
	kind := self.settings.Kind
	switch kind {
	case protocol.RepoKind_REPO_KIND_CONFIG, protocol.RepoKind_REPO_KIND_MAILCFG:
		return 0, fmt.Errorf("%w: a %s repo", sidecar.ErrConfigVersioningNotCovered, kind)
	}
	self.stateLock.Lock()
	network, repo, locked := self.networkRules, self.repoRules, self.locked
	self.stateLock.Unlock()
	rules := sidecar.ConfigPlatformVersioningRules()
	switch {
	case repo != nil:
		rules = repo
	case network != nil:
		rules = network
	}
	setting := sidecar.ConfigVersioningUnder(rules, repoId, kind, filePath, size)
	if setting == sidecar.ConfigVersioningVersionless && locked {
		return sidecar.ConfigVersioningKeep, nil
	}
	return setting, nil
}

// A step action: device reads path's newest version, which must be written at versioning (0 kept, 1 versionless).
func (self *EvsWorld) ExpectVersioning(device string, path string, versioning uint32) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		got, err := self.versioningOf(ctx, device, path)
		if err != nil {
			return err
		}
		if got != versioning {
			return fmt.Errorf("%s reads %q's newest version at versioning %d, not %d", device, path, got, versioning)
		}
		return nil
	}
}

// path's newest version's versioning as device's listing of its directory reads it.
func (self *EvsWorld) versioningOf(ctx context.Context, device string, path string) (uint32, error) {
	directory, name := "", path
	if index := strings.LastIndex(path, "/"); 0 <= index {
		directory, name = path[:index], path[index+1:]
	}
	listing, err := self.Device(device).Repo.List(ctx, &sidecar.EvsReadArgs{Path: directory, Fresh: true, Settings: true})
	if err != nil {
		return 0, fmt.Errorf("%s's listing of %q: %w", device, directory, err)
	}
	for _, entry := range listing.Entries {
		if string(entry.Name) == name {
			return entry.Versioning, nil
		}
	}
	return 0, fmt.Errorf("%s's listing of %q holds no %q", device, directory, name)
}

// The head of refId as the store holds it and its newest version's statement and payload as the lb carried them: what
// a hand-built push takes its pins and its sealed metadata from.
func (self *EvsWorld) newestStatement(ctx context.Context, refId sidecar.Id) (*protocol.EvsHead, *sidecar.EvsStatement, *sidecar.EvsCheckedPayload, error) {
	stored, err := NewStoreView(self.net, nil).Head(sidecartest.InspectContext(ctx), self.RepoId, refId)
	if err != nil {
		return nil, nil, nil, err
	}
	if stored == nil || stored.Head.GetVersion() == 0 {
		return nil, nil, nil, fmt.Errorf("the store holds no committed version of ref %s", refId)
	}
	pushId, err := sidecar.IdFromBytes(stored.Head.GetPushId())
	if err != nil {
		return nil, nil, nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	statement := self.pushStatements[pushId]
	if statement == nil {
		return nil, nil, nil, fmt.Errorf("ref %s's newest push %s did not pass the world's lb", refId, pushId)
	}
	payload, err := sidecar.EvsCheckStoredPayload(statement, self.pushPayloads[pushId])
	if err != nil {
		return nil, nil, nil, err
	}
	return stored.Head, statement, payload, nil
}

// What PostPlan's answer was.
type EvsWorldPosted struct {
	PushId sidecar.Id
	Status int
	Code   protocol.EvsRefusalCode
	// A 200's version.
	Version uint64
}

// A step action: device posts a hand-built push on the ref named refName (nil for main): fill gets a plan holding the
// ref's base, the pins of its newest committed statement, a fresh push id and the clock's time, and adds the changes,
// new objects and reuse list; the world signs it with device's key, as format 2, and posts it through the lb, into
// getting the answer. See the file header.
func (self *EvsWorld) PostPlan(device string, refName []byte, into *EvsWorldPosted, fill func(ctx context.Context, plan *sidecar.EvsPushPlan) error) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		worldDevice := self.Device(device)
		refId := self.RefId()
		if refName != nil {
			var err error
			if refId, err = worldDevice.Repo.RefIdOf(ctx, refName); err != nil {
				return err
			}
		}
		head, newest, newestPayload, err := self.newestStatement(ctx, refId)
		if err != nil {
			return err
		}
		push := newest.Push
		plan := &sidecar.EvsPushPlan{
			RepoId: self.RepoId, RefId: refId, RefKind: protocol.EvsRefKind(push.GetRefKind()), RefMode: protocol.EvsRefMode(push.GetRefMode()),
			PushId: sidecar.NewId(), BaseVersion: head.GetVersion(), BaseChain: [32]byte(head.GetChain()),
			Generation: push.GetGeneration(), GroupId: sidecar.Id(push.GetGroupId()),
			GenerationCommitment: bytes.Clone(push.GetGenerationCommitment()), PathEpoch: evsservice.EvsHeadCurrentEpoch(head),
			Auth: proto.Clone(push.GetAuth()).(*bridge.AuthPin), SignerSidecarId: worldDevice.Signer.SidecarId, ClientId: worldDevice.ClientId,
			TimeMs: net.Clock().Now().UnixMilli(),
			// the newest push's sealed metadata, which opens under the ref's manifest key as any reader opens it
			SealedMetadata: bytes.Clone(newestPayload.SealedMetadata),
		}
		if err := fill(ctx, plan); err != nil {
			return err
		}
		built, err := sidecar.NewEvsStatementBuilder(sidecar.EvsSignFunction(worldDevice.Signer.Sign)).BuildFormat2(plan)
		if err != nil {
			return err
		}
		body, err := proto.Marshal(&protocol.EvsPushRequest{Statement: built.Statement.Bytes, Payload: built.Payload})
		if err != nil {
			return err
		}
		// a DROP is its repo's admin scope's, which an issuer gives an admin alone: any other device's goes out under
		// the write scope it can get
		scope := "rw"
		if plan.Flags&uint32(protocol.EvsPushFlag_EVS_PUSH_DROP) != 0 && worldDevice.settings.Admin {
			scope = "admin"
		}
		token, err := self.issueToken(worldDevice, []string{"repo:" + self.RepoId.String() + ":" + scope})
		if err != nil {
			return err
		}
		url := "https://evs.example/evs/v1/repos/" + hex.EncodeToString(self.RepoId[:]) + "/push"
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/x-protobuf")
		response, err := self.roundTrip(worldDevice, request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		answered, err := io.ReadAll(response.Body)
		if err != nil {
			return err
		}
		into.PushId, into.Status = plan.PushId, response.StatusCode
		if response.StatusCode == http.StatusOK {
			reply := &protocol.EvsPushReply{}
			if err := proto.Unmarshal(answered, reply); err != nil {
				return err
			}
			into.Version = reply.GetVersion()
			return nil
		}
		refusal := &protocol.EvsRefusalReply{}
		if err := proto.Unmarshal(answered, refusal); err == nil {
			into.Code = refusal.GetCode()
		}
		return nil
	}
}

// reads without the answers to a request's paths that asked for an older version by its number, as History's walk,
// ReadVersion and a drop's lineage do: FI-15's read clause holds a head read to each path's newest, which such an
// answer is not meant to be. A reply whose paths do not line up with the request's, one head and a reply a path in
// the request's order, records nothing where the request asked for any older version.
func evsWorldNewestReads(requestBody []byte, reads []*LedgerRead) []*LedgerRead {
	request := &protocol.EvsReadRequest{}
	if err := proto.Unmarshal(requestBody, request); err != nil {
		return reads
	}
	if !slices.ContainsFunc(request.GetPaths(), func(path *protocol.EvsReadPath) bool { return path.GetVersion() != 0 }) {
		return reads
	}
	if len(reads) != 1 || len(reads[0].Paths) != len(request.GetPaths()) {
		return nil
	}
	read := *reads[0]
	read.Paths = nil
	for index, reply := range reads[0].Paths {
		if request.GetPaths()[index].GetVersion() == 0 {
			read.Paths = append(read.Paths, reply)
		}
	}
	return []*LedgerRead{&read}
}

// A file version a device committed on main, as its push's payload carried it: its token path, its entry version and
// that entry's bytes.
type EvsWorldCommittedEntry struct {
	TokenPath  sidecar.EvsTokenPath
	Entry      *protocol.EvsEntryVersion
	EntryBytes []byte
}

// The file version device's newest committed write of path wrote, read from the push the lb carried: the one change
// of that push that writes a file's entry version. A hand-built push cites it by its token path and locators.
func (self *EvsWorld) CommittedEntry(device string, path string) (*EvsWorldCommittedEntry, error) {
	_, pushId, err := self.CommittedVersion(device, path)
	if err != nil {
		return nil, err
	}
	return self.pushEntry(pushId)
}

// Every file version the world's committed writes of path wrote, oldest first.
func (self *EvsWorld) CommittedEntries(path string) ([]*EvsWorldCommittedEntry, error) {
	self.stateLock.Lock()
	writes := slices.Clone(self.pathWrites[path])
	self.stateLock.Unlock()
	slices.SortStableFunc(writes, func(a *evsWorldWrite, b *evsWorldWrite) int { return cmp.Compare(a.version, b.version) })
	entries := []*EvsWorldCommittedEntry{}
	for _, write := range writes {
		if write.state != evsWorldWriteCommitted || write.content == nil {
			continue
		}
		entry, err := self.pushEntry(write.pushId)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// The one file version the push pushId wrote, as the lb carried it.
func (self *EvsWorld) pushEntry(pushId sidecar.Id) (*EvsWorldCommittedEntry, error) {
	self.stateLock.Lock()
	statement, payloadBytes := self.pushStatements[pushId], self.pushPayloads[pushId]
	self.stateLock.Unlock()
	if statement == nil {
		return nil, fmt.Errorf("push %s did not pass the world's lb", pushId)
	}
	payload, err := sidecar.EvsCheckStoredPayload(statement, payloadBytes)
	if err != nil {
		return nil, err
	}
	var found *EvsWorldCommittedEntry
	for _, change := range payload.Changes {
		if !change.WritesEntry() {
			continue
		}
		entry := &protocol.EvsEntryVersion{}
		if err := proto.Unmarshal(change.EntryVersion, entry); err != nil {
			return nil, err
		}
		if entry.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("push %s writes more than one file", pushId)
		}
		found = &EvsWorldCommittedEntry{TokenPath: change.TokenPath, Entry: entry, EntryBytes: change.EntryVersion}
	}
	if found == nil {
		return nil, fmt.Errorf("push %s writes no file", pushId)
	}
	return found, nil
}

// The segments entry's chain names, by id.
func (self *EvsWorldCommittedEntry) SegmentIds() [][]byte {
	ids := [][]byte{}
	for _, locator := range self.Entry.GetChain() {
		if id := locator.GetId(); len(id) != 0 {
			ids = append(ids, bytes.Clone(id))
		}
	}
	return ids
}

// A fill for PostPlan: a file created at a new path of the push's ref as a copy of source, a committed version of
// main, which the push names as its reuse source and whose locators the new version cites, uploading nothing: the
// reuse copy §11.8's 5h holds to what no DROP lists.
func (self *EvsWorld) ReuseFill(label string, source func() (*EvsWorldCommittedEntry, error)) func(ctx context.Context, plan *sidecar.EvsPushPlan) error {
	return func(ctx context.Context, plan *sidecar.EvsPushPlan) error {
		cited, err := source()
		if err != nil {
			return err
		}
		entryBytes, err := protoMarshalDeterministic(&protocol.EvsEntryVersion{
			Version: plan.BaseVersion + 1, PushId: plan.PushId.Bytes(), BaseVersion: plan.BaseVersion, TimeMs: plan.TimeMs,
			Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), PaddedSize: cited.Entry.GetPaddedSize(),
			SealedFields: cited.Entry.GetSealedFields(), Chain: cited.Entry.GetChain(),
		})
		if err != nil {
			return err
		}
		plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{TokenPath: evsWorldHandPath(label), EntryVersion: entryBytes})
		plan.ReuseList = append(plan.ReuseList, &sidecar.EvsReuse{RefId: self.RefId(), EntryVersion: cited.Entry.GetVersion(), TokenPath: cited.TokenPath})
		return nil
	}
}

// A fill for PostPlan: path's newest committed version written again with the versioning value versioning, naming
// that version's own locators and uploading nothing, as a writer ignoring its repo's kind, its ref's mode or a lock
// sends a file's turn to versioning off (§11.7's refused row). On a path whose newest version names kind-1 segments
// that is the push an honest writer sends where the turn is allowed, so its twin commits.
func (self *EvsWorld) VersioningFill(path string, versioning uint32) func(ctx context.Context, plan *sidecar.EvsPushPlan) error {
	return func(ctx context.Context, plan *sidecar.EvsPushPlan) error {
		entries, err := self.CommittedEntries(path)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			return fmt.Errorf("no write of %q committed: a hand-built write names its newest version's locators", path)
		}
		head := entries[len(entries)-1]
		entryBytes, err := protoMarshalDeterministic(&protocol.EvsEntryVersion{
			Version: head.Entry.GetVersion() + 1, PushId: plan.PushId.Bytes(), BaseVersion: plan.BaseVersion, TimeMs: plan.TimeMs,
			Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), PaddedSize: head.Entry.GetPaddedSize(),
			SealedFields: head.Entry.GetSealedFields(), Chain: head.Entry.GetChain(), SlotIds: head.Entry.GetSlotIds(),
			Versioning: versioning,
		})
		if err != nil {
			return err
		}
		plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
			TokenPath: head.TokenPath, BaseEntryVersion: head.Entry.GetVersion(), EntryVersion: entryBytes,
		})
		return nil
	}
}

// A fill for PostPlan: a DROP of path's history on main, with now, built by hand as a modified client builds it,
// with none of the honest client's own refusals: one written lineage in the push's path epoch, listing every
// committed version of path below its newest, whose content the push writes again at through_version by naming the
// newest version's own locators, so the head needs no upload.
func (self *EvsWorld) DropFill(path string, now bool) func(ctx context.Context, plan *sidecar.EvsPushPlan) error {
	return func(ctx context.Context, plan *sidecar.EvsPushPlan) error {
		entries, err := self.CommittedEntries(path)
		if err != nil {
			return err
		}
		if len(entries) < 2 {
			return fmt.Errorf("%q has %d committed versions: a drop lists at least one below its newest", path, len(entries))
		}
		head := entries[len(entries)-1]
		listed := [][]byte{}
		for _, entry := range entries[:len(entries)-1] {
			hash := sha256.Sum256(entry.EntryBytes)
			listed = append(listed, hash[:])
		}
		slices.SortFunc(listed, bytes.Compare)
		through := head.Entry.GetVersion() + 1
		notBeforeMs := plan.TimeMs
		if !now {
			notBeforeMs += sidecar.DefaultEvsFormatSettings().DropWindowMs()
		}
		dropId := sha256.Sum256(append([]byte("evs world hand-built drop "), plan.PushId.Bytes()...))
		history := &protocol.EvsDropHistory{
			DropId: dropId[:16], Action: 1, NotBeforeMs: notBeforeMs,
			Paths: []*protocol.EvsDropPath{{
				Lineage:        []*protocol.EvsSourcePath{{Epoch: plan.PathEpoch, TokenPath: head.TokenPath.Components()}},
				ThroughVersion: through, Boundary: sidecar.EvsDropBoundaryWritten,
			}},
		}
		lists, err := sidecar.EvsBuildDropLists(history.GetPaths(), [][][]byte{listed})
		if err != nil {
			return err
		}
		body, err := protoMarshalDeterministic(history)
		if err != nil {
			return err
		}
		entryBytes, err := protoMarshalDeterministic(&protocol.EvsEntryVersion{
			Version: through, PushId: plan.PushId.Bytes(), BaseVersion: plan.BaseVersion, TimeMs: plan.TimeMs,
			Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), PaddedSize: head.Entry.GetPaddedSize(),
			SealedFields: head.Entry.GetSealedFields(), Chain: head.Entry.GetChain(), SlotIds: head.Entry.GetSlotIds(),
		})
		if err != nil {
			return err
		}
		plan.DropBody, plan.DropLists = body, lists
		plan.Flags |= uint32(protocol.EvsPushFlag_EVS_PUSH_DROP)
		plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
			TokenPath: head.TokenPath, BaseEntryVersion: head.Entry.GetVersion(), EntryVersion: entryBytes,
		})
		return nil
	}
}

// The token path of a file a hand-built push creates at the root of its ref: one token derived from label, which
// names nothing a reader can open, as the world's devices never list it.
func evsWorldHandPath(label string) sidecar.EvsTokenPath {
	digest := sha256.Sum256([]byte("evs world hand-built path " + label))
	return sidecar.EvsTokenPath{sidecar.EvsToken(digest[:sidecar.EvsTokenByteCount])}
}

// A step action: into's push ended as status and, when refused, with code.
func EvsWorldExpectPosted(into *EvsWorldPosted, status int, code protocol.EvsRefusalCode) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		if into.Status != status || (status != http.StatusOK && into.Code != code) {
			return fmt.Errorf("the hand-built push %s was answered %d %v, not %d %v", into.PushId, into.Status, into.Code, status, code)
		}
		return nil
	}
}

// A step action: each segment of ids, a function so a schedule names what an earlier step wrote, is stored on the
// segment cluster, or with stored false is not.
func (self *EvsWorld) ExpectSegments(what string, stored bool, ids func() ([][]byte, error)) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		segmentIds, err := ids()
		if err != nil {
			return err
		}
		if len(segmentIds) == 0 {
			return fmt.Errorf("%s names no segment", what)
		}
		cluster, err := net.Host().Blobs.SegmentCluster()
		if err != nil {
			return err
		}
		for _, id := range segmentIds {
			key := evsservice.SegmentKey(self.RepoId, [32]byte(id))
			_, err := cluster.Head(sidecartest.InspectContext(ctx), key)
			switch {
			case err == nil && !stored:
				return fmt.Errorf("%s: %s is still stored", what, key)
			case errors.Is(err, sidecar.ErrBlobNotFound) && stored:
				return fmt.Errorf("%s: %s is not stored", what, key)
			case err != nil && !errors.Is(err, sidecar.ErrBlobNotFound):
				return err
			}
		}
		return nil
	}
}

// message's deterministic encoding, as an entry version's bytes are signed over.
func protoMarshalDeterministic(message proto.Message) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(message)
}

// A step action: device writes content to both paths in one push, which must commit; the ledger keeps a write of
// each. Small content gives the push one record whose inline bytes both versions hold (FS-94).
func (self *EvsWorld) WritePair(deviceName string, pathA string, pathB string, content []byte) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		device := self.Device(deviceName)
		if device.Repo == nil {
			return fmt.Errorf("device %s is not started: Setup runs first", deviceName)
		}
		writes := []*evsWorldWrite{}
		self.stateLock.Lock()
		for _, path := range []string{pathA, pathB} {
			write := &evsWorldWrite{device: deviceName, content: bytes.Clone(content), state: evsWorldWritePending}
			self.pathWrites[path] = append(self.pathWrites[path], write)
			writes = append(writes, write)
		}
		self.stateLock.Unlock()
		result, err := device.Repo.WritePaths(ctx, &sidecar.EvsWritePathsArgs{Writes: []*sidecar.EvsPathWrite{
			{Path: pathA, Content: bytes.NewReader(content)}, {Path: pathB, Content: bytes.NewReader(content)},
		}})
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, write := range writes {
			write.err = err
			switch evsError, ok := sidecar.EvsErrorOf(err); {
			case err == nil:
				write.state, write.version, write.pushId = evsWorldWriteCommitted, result.Version, result.PushId
			case ok && !evsError.RefusesNothing() && !evsError.OutcomeUnknown:
				write.state = evsWorldWriteRefused
			default:
				write.state = evsWorldWriteUnknown
			}
		}
		if err != nil {
			return fmt.Errorf("%s's write of %q and %q in one push did not commit: %w", deviceName, pathA, pathB, err)
		}
		return nil
	}
}

// A step action: device writes content to path on the ref named refName, creating the ref with its first write,
// which must commit. The ledger keeps main's writes alone, so no reader verifies it: a schedule's hand-built pushes
// build on the ref.
func (self *EvsWorld) WriteRef(deviceName string, refName []byte, path string, content []byte) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		device := self.Device(deviceName)
		if device.Repo == nil {
			return fmt.Errorf("device %s is not started: Setup runs first", deviceName)
		}
		_, err := device.Repo.WritePaths(ctx, &sidecar.EvsWritePathsArgs{RefName: refName, Writes: []*sidecar.EvsPathWrite{
			{Path: path, Content: bytes.NewReader(content)},
		}})
		if err != nil {
			return fmt.Errorf("%s's write of %q on ref %q did not commit: %w", deviceName, path, refName, err)
		}
		return nil
	}
}
