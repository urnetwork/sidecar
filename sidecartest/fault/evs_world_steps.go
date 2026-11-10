// More of the evs world's step actions (evs_world.go): what a schedule expects of a write's end, what the store holds
// of a push's records, and the authorization state a schedule moves.

package fault

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A step action: device's newest write of path ended refused with code.
func (self *EvsWorld) ExpectRefused(device string, path string, code protocol.EvsRefusalCode) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		write := self.newestWrite(device, path)
		if write == nil {
			return fmt.Errorf("%s wrote no %q", device, path)
		}
		evsError, ok := sidecar.EvsErrorOf(write.err)
		if write.state != evsWorldWriteRefused || !ok || evsError.Code != code {
			return fmt.Errorf("%s's write of %q ended %v, not refused %s", device, path, write.err, code)
		}
		return nil
	}
}

// A step action: device's newest write of path committed.
func (self *EvsWorld) ExpectCommitted(device string, path string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		_, _, err := self.CommittedVersion(device, path)
		return err
	}
}

// device's newest write of path, or nil.
func (self *EvsWorld) newestWrite(device string, path string) *evsWorldWrite {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	writes := self.pathWrites[path]
	for index := len(writes) - 1; 0 <= index; index -= 1 {
		if writes[index].device == device {
			return writes[index]
		}
	}
	return nil
}

// How many records of pushId the repo's cluster holds in pb/ batches, read under an inspecting context.
func (self *EvsWorld) BatchRecordCount(ctx context.Context, pushId sidecar.Id) (int, error) {
	view := NewStoreView(self.net, nil)
	clusterId, err := view.RepoClusterId(ctx, self.RepoId)
	if err != nil {
		return 0, err
	}
	batches, err := view.Batches(sidecartest.InspectContext(ctx), clusterId)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, batch := range batches {
		for _, record := range batch.Records {
			if record.RepoId == self.RepoId && record.PushId == pushId {
				count += 1
			}
		}
	}
	return count, nil
}

// The push ids device posted, in order.
func (self *EvsWorld) DevicePushIds(device string) []sidecar.Id {
	pushIds := []sidecar.Id{}
	for _, push := range self.DevicePushes(device) {
		pushIds = append(pushIds, push.PushId)
	}
	return pushIds
}

// The instance answers of device's newest push, the lb's left out.
func (self *EvsWorld) NewestAnswers(device string) ([]*EvsWorldAnswer, sidecar.Id, error) {
	pushes := self.DevicePushes(device)
	if len(pushes) == 0 {
		return nil, sidecar.Id{}, fmt.Errorf("%s posted no push", device)
	}
	push := pushes[len(pushes)-1]
	return push.InstanceAnswers(), push.PushId, nil
}

// Whether an answer is a 200 naming version.
func (self *EvsWorldAnswer) Committed(version uint64) bool {
	return self.Status == http.StatusOK && self.Version == version
}

// A step action: a new authorization position at which dropped no longer reads the repo and the repo's holders
// shrank there, given to evs's instances and every device: the projection drop that closes the gate on every
// generation older than the next rotation (§10.6, §11.8's 5d).
func (self *EvsWorld) DropReader(dropped string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		self.Device(dropped)
		self.stateLock.Lock()
		self.droppedReaders[dropped] = true
		// the holders shrink at the position appended now
		self.shrunkAt = self.viewCount + 1
		self.stateLock.Unlock()
		self.appendView()
		return nil
	}
}

// A step action: instance's gate views stay at the newest position as it stands now, as an instance whose projection
// has not read what comes next.
func (self *EvsWorld) HoldView(instance string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.staleViews[instance] = self.view
		return nil
	}
}

// A step action: device's creation of path waits for the ref's path epoch, sending nothing for it, the ledger
// keeping it as never written.
func (self *EvsWorld) WriteDue(device string, path string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		write, err := self.write(ctx, device, path, EvsWorldContent("fs4 due "+path, 200))
		if err != nil {
			return err
		}
		if !errors.Is(write.err, sidecar.ErrEvsPathEpochDue) {
			return fmt.Errorf("%s's creation of %q while due ended %v", device, path, write.err)
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		write.state = evsWorldWriteRefused
		return nil
	}
}

// A step action: device's mapper ticks once on main (EvsRepo.TickMapper), building, uploading and committing a
// PATH_EPOCH when one is due.
func (self *EvsWorld) TickMapper(device string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		return self.Device(device).Repo.TickMapper(ctx, self.RefId())
	}
}

// A step action: evs's copy into epoch runs as taskworker runs it and its successors, at a rate the Net's still
// clock never holds, until it drops its sources; one that misses an entry fails the step.
func (self *EvsWorld) CopyInto(epoch uint64) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		first, err := net.Host().Blobs.FirstCluster()
		if err != nil {
			return err
		}
		settings := evsservice.DefaultEvsSettings()
		settings.CopyRepoOpsPerSecond = 1024 * 1024
		settings.CopyRepoSourcesOpsPerSecond = 1024 * 1024
		net.Fakes().Budget.SetCopyOpsPerSecond(first.ClusterId(), 1024*1024)
		for range 16 {
			result, err := evsservice.RunPathEpochCopy(ctx, net.Host(), &evsservice.EvsEpochCopyDeps{Settings: settings}, evsservice.EvsEpochCopyArgs(self.RepoId, self.RefId(), epoch))
			if err != nil {
				return fmt.Errorf("the copy into epoch %d: %w", epoch, err)
			}
			if 0 < result.MissedCount {
				return fmt.Errorf("the copy into epoch %d missed %d entries", epoch, result.MissedCount)
			}
			if result.SourcesDropped || result.Superseded {
				return nil
			}
		}
		return fmt.Errorf("the copy into epoch %d never dropped its sources", epoch)
	}
}

// A step action: main's head stands at path epoch current with exactly sources listed.
func (self *EvsWorld) ExpectEpoch(current uint64, sources ...uint64) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		head, err := self.Head(ctx)
		if err != nil {
			return err
		}
		if head == nil {
			return errors.New("main has no head")
		}
		listed := []uint64{}
		for _, source := range head.GetPathEpoch().GetSources() {
			listed = append(listed, source.GetEpoch())
		}
		if evsservice.EvsHeadCurrentEpoch(head) != current || !slices.Equal(listed, sources) {
			return fmt.Errorf("main's path epoch %v, not %d over %v", head.GetPathEpoch(), current, sources)
		}
		return nil
	}
}

// A step action: device places the repo, PUT /evs/v1/repos/<id> through its lb under an admin token, as
// EvsClient.CreateRepo does when it resumes the RepoCreate the world's projection holds: place/ and repo/, keying.
// It must answer 200.
func (self *EvsWorld) PlaceRepo(device string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		if err := self.PlaceRepoAny(device)(ctx, net); err != nil {
			return err
		}
		if status := self.PlaceStatus(device); status != http.StatusOK {
			return fmt.Errorf("%s's placement answered %d", device, status)
		}
		return nil
	}
}

// A step action: device's placement, which may answer anything, its status kept (PlaceStatus).
func (self *EvsWorld) PlaceRepoAny(device string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		world := self.Device(device)
		token, err := self.issueToken(world, []string{"repo:" + self.RepoId.String() + ":admin"})
		if err != nil {
			return err
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPut, "https://evs.example/evs/v1/repos/"+hex.EncodeToString(self.RepoId[:]), nil)
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+token)
		status := 0
		response, err := world.transport.RoundTrip(request)
		if err == nil {
			status = response.StatusCode
			response.Body.Close()
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.placeStatuses[device] = status
		return nil
	}
}

// What device's placement answered, 0 for no answer.
func (self *EvsWorld) PlaceStatus(device string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.placeStatuses[device]
}

// A step action: what KF1's group and the activation give a repo device placed, which the fakes cannot run through
// the route, since sidecartest's FakeGkm writes no GroupForm (gkm/repo/<id>/) for the activation to read: device
// makes the group under an inspecting context, and repo/, keying, is set active by hand, as the activation's If-Match
// would. Then main's ref id is known and the world's checks and reads start.
func (self *EvsWorld) FinishCreate(device string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		inspect := sidecartest.InspectContext(ctx)
		repoKey, err := self.Device(device).Gkm.CreateGroup(inspect, &sidecar.GkmCreateGroupArgs{RepoId: self.RepoId, Kind: self.settings.Kind})
		if err != nil {
			return fmt.Errorf("the repo's group: %w", err)
		}
		view := NewStoreView(net, nil)
		clusterId, err := view.RepoClusterId(inspect, self.RepoId)
		if err != nil {
			return err
		}
		cluster, err := net.Host().Blobs.Cluster(clusterId)
		if err != nil {
			return err
		}
		object, err := view.Object(inspect, clusterId, sidecar.EvsRepoObjectKey(self.RepoId))
		if err != nil {
			return fmt.Errorf("repo/: %w", err)
		}
		repo := &protocol.EvsRepoObject{}
		if err := proto.Unmarshal(object.Body, repo); err != nil {
			return err
		}
		if repo.GetState() != protocol.EvsRepoState_EVS_REPO_KEYING {
			return fmt.Errorf("repo/ is %s, not keying", repo.GetState())
		}
		repo.State = protocol.EvsRepoState_EVS_REPO_ACTIVE
		repo.StateMs = net.Clock().Now().UnixMilli()
		repoBytes, err := proto.Marshal(repo)
		if err != nil {
			return err
		}
		if _, err := cluster.PutIfMatch(inspect, sidecar.EvsRepoObjectKey(self.RepoId), object.Etag, repoBytes, nil); err != nil {
			return fmt.Errorf("repo/'s activation: %w", err)
		}
		refKey, err := sidecar.NewEvsRefKey(repoKey)
		if err != nil {
			return err
		}
		refId, err := sidecar.EvsRefId(refKey, sidecar.EvsMainRefName)
		if err != nil {
			return err
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.refId = refId
		self.setUp = true
		return nil
	}
}
