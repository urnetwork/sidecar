// The evs world's repo lifecycle (§11.12; FS-6, EVS1-M2-41), beside evs_world.go: the access log takes a device's
// RepoDelete and RepoRestore as api would, each at a new position every device, every evs instance and FI-1's
// excuses read; taskworker's shred runs as a step, each pass when the schedule says; and a holder's projection, an
// evs instance's or the shred's ("shred"), can be held where it stands (HoldProjection), as one that has not read what
// comes next.

package fault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The holder name of the shred's projection.
const evsWorldShredHolder = "shred"

// §8.8's window: api takes a RepoRestore only within 7 d of its RepoDelete's entry.
const evsWorldRestoreWindow = 7 * 24 * time.Hour

// One RepoDelete the access log holds, with its RepoRestore's position once one is filed.
type evsWorldDeletion struct {
	deletionId sidecar.Id
	now        bool
	time       time.Time
	signer     sidecar.Id
	deletedAt  uint64
	// 0 while no RepoRestore of it is filed
	restoredAt uint64
}

// A holder's projection held where it stood: its newest RepoDelete then, nil for none.
type evsWorldProjection struct {
	deletion *evsWorldDeletion
}

// What a device's statement does to the access log: a RepoDelete or a RepoRestore of the world's repo is taken at a
// new position, as api takes it; any other kind is refused, as before.
func (self *EvsWorld) fileStatement(device *EvsWorldDevice, signedType bridge.SignedType, statement proto.Message) error {
	now := self.net.Clock().Now()
	err := func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		position := self.viewCount + 1
		switch signedType {
		case bridge.SignedType_SIGNED_REPO_DELETE:
			deletion, ok := statement.(*protocol.RepoDelete)
			if !ok || !bytes.Equal(deletion.GetRepoId(), self.RepoId.Bytes()) {
				return errors.New("the evs world takes a RepoDelete of its own repo alone")
			}
			deletionId, err := sidecar.IdFromBytes(deletion.GetDeletionId())
			if err != nil {
				return err
			}
			self.deletions = append(self.deletions, &evsWorldDeletion{
				deletionId: deletionId, now: deletion.GetNow(), time: now, signer: device.Signer.SidecarId, deletedAt: position,
			})
			return nil
		case bridge.SignedType_SIGNED_REPO_RESTORE:
			restore, ok := statement.(*protocol.RepoRestore)
			if !ok || len(self.deletions) == 0 {
				return errors.New("the evs world takes a RepoRestore of its repo's newest RepoDelete alone")
			}
			newest := self.deletions[len(self.deletions)-1]
			switch {
			case !bytes.Equal(restore.GetDeletionId(), newest.deletionId.Bytes()):
				return errors.New("a RepoRestore of another RepoDelete than the newest")
			case newest.now:
				return errors.New("a RepoRestore of a RepoDelete with now")
			case newest.restoredAt != 0:
				return errors.New("a RepoRestore of a RepoDelete restored already")
			case evsWorldRestoreWindow < now.Sub(newest.time):
				return errors.New("a RepoRestore past its RepoDelete's 7 d")
			}
			newest.restoredAt = position
			return nil
		}
		return fmt.Errorf("the evs world files no %s", signedType)
	}()
	if err != nil {
		return err
	}
	self.appendView()
	return nil
}

// The newest RepoDelete's row as §8.8's AclRepo carries it, nil for none. Under the world's lock.
func (self *EvsWorld) deletionRowWithLock() *protocol.AclRepoDeletionRow {
	if len(self.deletions) == 0 {
		return nil
	}
	newest := self.deletions[len(self.deletions)-1]
	return &protocol.AclRepoDeletionRow{
		DeletionId: newest.deletionId.Bytes(), Now: newest.now, DeletedAt: newest.deletedAt, RestoredAt: newest.restoredAt,
	}
}

// The newest RepoDelete as holder's projection shows it, nil for none.
func (self *EvsWorld) deletionFacts(holder string) *evsservice.EvsRepoDeletionFacts {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	var deletion *evsWorldDeletion
	if held, ok := self.heldProjections[holder]; ok {
		deletion = held.deletion
	} else if 0 < len(self.deletions) {
		deletion = self.deletions[len(self.deletions)-1]
	}
	if deletion == nil {
		return nil
	}
	return &evsservice.EvsRepoDeletionFacts{
		DeletionId: deletion.deletionId, Now: deletion.now, Time: deletion.time, SignerSidecarId: deletion.signer,
		Restored: deletion.restoredAt != 0,
	}
}

// A step action: holder's projection, an evs instance's or "shred", stays at what the access log holds now.
func (self *EvsWorld) HoldProjection(holder string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		held := &evsWorldProjection{}
		if 0 < len(self.deletions) {
			copied := *self.deletions[len(self.deletions)-1]
			held.deletion = &copied
		}
		self.heldProjections[holder] = held
		return nil
	}
}

// The shred's projection: the world's newest RepoDelete, or what HoldProjection kept for "shred".
type evsWorldDeletions struct {
	world *EvsWorld
}

func (self *evsWorldDeletions) RepoDeletion(ctx context.Context, networkId sidecar.Id, repoId sidecar.Id) (*evsservice.EvsRepoDeletionFacts, error) {
	if networkId != self.world.NetworkId || repoId != self.world.RepoId {
		return nil, nil
	}
	return self.world.deletionFacts(evsWorldShredHolder), nil
}

// A step action: device deletes the repo (EvsRepo.Delete), restorable unless now, which must answer 200.
func (self *EvsWorld) DeleteRepo(device string, now bool) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		if err := self.Device(device).Repo.Delete(ctx, now); err != nil {
			return fmt.Errorf("%s's delete: %w", device, err)
		}
		return nil
	}
}

// A step action: device deletes the repo, which may end any way, its end kept (ExpectLifecycle).
func (self *EvsWorld) DeleteRepoAny(device string, now bool) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		err := self.Device(device).Repo.Delete(ctx, now)
		self.noteLifecycle(device, err)
		return nil
	}
}

// A step action: device restores the repo (EvsRepo.Restore), which must answer 200.
func (self *EvsWorld) RestoreRepo(device string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		if err := self.Device(device).Repo.Restore(ctx); err != nil {
			return fmt.Errorf("%s's restore: %w", device, err)
		}
		return nil
	}
}

// A step action: device restores the repo, which may end any way, its end kept (ExpectLifecycle).
func (self *EvsWorld) RestoreRepoAny(device string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		err := self.Device(device).Repo.Restore(ctx)
		self.noteLifecycle(device, err)
		return nil
	}
}

func (self *EvsWorld) noteLifecycle(device string, err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lifecycleEnds[device] = append(self.lifecycleEnds[device], err)
}

// A step action: device's newest delete or restore answered 200 (code unspecified), or was refused with code.
func (self *EvsWorld) ExpectLifecycle(device string, code protocol.EvsRefusalCode) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		self.stateLock.Lock()
		ends := self.lifecycleEnds[device]
		self.stateLock.Unlock()
		if len(ends) == 0 {
			return fmt.Errorf("%s made no delete or restore", device)
		}
		err := ends[len(ends)-1]
		if code == protocol.EvsRefusalCode_EVS_REFUSAL_CODE_UNSPECIFIED {
			if err != nil {
				return fmt.Errorf("%s's delete or restore ended %v, not 200", device, err)
			}
			return nil
		}
		if !sidecar.IsEvsRefusal(err, code) {
			return fmt.Errorf("%s's delete or restore ended %v, not refused %s", device, err, code)
		}
		return nil
	}
}

// A step action: device's newest delete or restore did not answer 200, refused at the access log or at evs.
func (self *EvsWorld) ExpectLifecycleFailed(device string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		self.stateLock.Lock()
		ends := self.lifecycleEnds[device]
		self.stateLock.Unlock()
		if len(ends) == 0 {
			return fmt.Errorf("%s made no delete or restore", device)
		}
		if ends[len(ends)-1] == nil {
			return fmt.Errorf("%s's delete or restore answered 200", device)
		}
		return nil
	}
}

// A step action: device's read of path is refused with code.
func (self *EvsWorld) ExpectReadRefused(device string, path string, code protocol.EvsRefusalCode) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		_, err := self.Device(device).Repo.ReadHead(ctx, &sidecar.EvsReadArgs{Path: path, Fresh: true}, io.Discard)
		if !sidecar.IsEvsRefusal(err, code) {
			return fmt.Errorf("%s's read of %q ended %v, not refused %s", device, path, err, code)
		}
		return nil
	}
}

// repo/ as the repo's cluster holds it, read under an inspecting context.
func (self *EvsWorld) RepoObject(ctx context.Context) (*protocol.EvsRepoObject, error) {
	view := NewStoreView(self.net, nil)
	inspect := sidecartest.InspectContext(ctx)
	clusterId, err := view.RepoClusterId(inspect, self.RepoId)
	if err != nil {
		return nil, err
	}
	object, err := view.Object(inspect, clusterId, sidecar.EvsRepoObjectKey(self.RepoId))
	if err != nil {
		return nil, fmt.Errorf("repo/: %w", err)
	}
	repo := &protocol.EvsRepoObject{}
	if err := proto.Unmarshal(object.Body, repo); err != nil {
		return nil, err
	}
	return repo, nil
}

// A step action: repo/ is in state.
func (self *EvsWorld) ExpectRepoState(state protocol.EvsRepoState) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		repo, err := self.RepoObject(ctx)
		if err != nil {
			return err
		}
		if repo.GetState() != state {
			return fmt.Errorf("repo/ is %s, not %s", repo.GetState(), state)
		}
		return nil
	}
}

// A step action: one pass of evs.shred on the newest RepoDelete, as taskworker runs it (evsservice.RunShred): the
// first pass, or the final. Its outcome is kept (ExpectShred), and a store error ends the step.
func (self *EvsWorld) Shred(final bool) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		self.stateLock.Lock()
		if len(self.deletions) == 0 {
			self.stateLock.Unlock()
			return errors.New("no RepoDelete to shred")
		}
		deletionId := self.deletions[len(self.deletions)-1].deletionId
		self.stateLock.Unlock()
		return self.shred(ctx, net, deletionId, final)
	}
}

// A step action: one pass of evs.shred on the index-th RepoDelete the access log took, from 0: an earlier
// incarnation's job.
func (self *EvsWorld) ShredDeletion(index int, final bool) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		self.stateLock.Lock()
		if len(self.deletions) <= index {
			self.stateLock.Unlock()
			return fmt.Errorf("no RepoDelete %d to shred", index)
		}
		deletionId := self.deletions[index].deletionId
		self.stateLock.Unlock()
		return self.shred(ctx, net, deletionId, final)
	}
}

func (self *EvsWorld) shred(ctx context.Context, net *Net, deletionId sidecar.Id, final bool) error {
	// the job queues its next pass in taskworker's queue, which on both tiers is the Net's fake here: a schedule
	// runs each pass as a step of its own
	host := *net.Host()
	host.Tasks = net.Fakes().Tasks
	outcome, err := evsservice.RunShred(ctx, &host, &evsservice.EvsShredDeps{
		ShredGroup: self.shredGroup(net),
		Deletions:  &evsWorldDeletions{world: self},
	}, evsservice.EvsShredArgs(self.RepoId, deletionId, final))
	if err != nil {
		return fmt.Errorf("the shred: %w", err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.shredOutcomes = append(self.shredOutcomes, outcome)
	return nil
}

// Step 3's gkm half: gkmservice.ShredGroup over the repo's GroupForms, and, since sidecartest's FakeGkm writes no
// GroupForm, the objects and acks of the group the fake names, each delete P0 of kind shred.
func (self *EvsWorld) shredGroup(net *Net) func(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, final bool) error {
	return func(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, final bool) error {
		if err := gkmservice.ShredGroup(ctx, net.Host(), cluster, repoId, final, nil); err != nil {
			return err
		}
		self.stateLock.Lock()
		gkm := self.gkm
		self.stateLock.Unlock()
		groupId, _, ok := gkm.Newest(repoId)
		if !ok {
			return nil
		}
		prefix := gkmservice.GkmGroupPrefix(groupId)
		startAfter := ""
		for {
			infos, more, err := cluster.List(ctx, prefix, startAfter, 1000)
			if err != nil {
				return err
			}
			for _, info := range infos {
				deleteCtx := net.Host().Budget.IssueP0(ctx, cluster.ClusterId(), sidecar.WriteP0KindShred, 1)
				if err := cluster.Delete(deleteCtx, info.Key); err != nil && !errors.Is(err, sidecar.ErrBlobNotFound) {
					return err
				}
			}
			if !more || len(infos) == 0 {
				break
			}
			startAfter = infos[len(infos)-1].Key
		}
		return net.Host().Redis.Delete(ctx, []string{gkmservice.GkmAckRedisKey(groupId)})
	}
}

// A step action: the newest pass of the shred answered outcome.
func (self *EvsWorld) ExpectShred(outcome evsservice.EvsShredOutcome) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if len(self.shredOutcomes) == 0 {
			return errors.New("no shred pass ran")
		}
		if newest := self.shredOutcomes[len(self.shredOutcomes)-1]; newest != outcome {
			return fmt.Errorf("the shred's pass answered %d, not %d", newest, outcome)
		}
		return nil
	}
}

// A step action: the repo is shredded: repo/ the tombstone and place/ kept, and nothing else of the repo on its
// metadata cluster or the segment cluster, nor of its group, nor in Redis; read under an inspecting context.
func (self *EvsWorld) ExpectShredded() func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		repo, err := self.RepoObject(ctx)
		if err != nil {
			return err
		}
		if repo.GetState() != protocol.EvsRepoState_EVS_REPO_SHREDDED {
			return fmt.Errorf("repo/ is %s, not shredded", repo.GetState())
		}
		inspect := sidecartest.InspectContext(ctx)
		repoKey := sidecar.EvsKeyId(self.RepoId)
		kept := map[string]bool{sidecar.EvsPlaceKey(self.RepoId): true, sidecar.EvsRepoObjectKey(self.RepoId): true}
		self.stateLock.Lock()
		gkm := self.gkm
		self.stateLock.Unlock()
		groupPrefix := ""
		if groupId, _, ok := gkm.Newest(self.RepoId); ok {
			groupPrefix = gkmservice.GkmGroupPrefix(groupId)
		}
		blobs := net.Host().Blobs
		clusters := []sidecar.BlobCluster{}
		for _, find := range []func() (sidecar.BlobCluster, error){blobs.FirstCluster, blobs.SegmentCluster} {
			cluster, err := find()
			if err != nil {
				return err
			}
			clusters = append(clusters, cluster)
		}
		for _, cluster := range clusters {
			startAfter := ""
			for {
				infos, more, err := cluster.List(inspect, "", startAfter, 1000)
				if err != nil {
					return err
				}
				for _, info := range infos {
					if kept[info.Key] {
						continue
					}
					if strings.Contains(info.Key, repoKey) || (groupPrefix != "" && strings.HasPrefix(info.Key, groupPrefix)) {
						return fmt.Errorf("%s keeps %s after the shred", cluster.ClusterId(), info.Key)
					}
				}
				if !more || len(infos) == 0 {
					break
				}
				startAfter = infos[len(infos)-1].Key
			}
		}
		if _, found, err := self.redisValue(ctx, evsservice.PushSequenceKey(self.RepoId)); err != nil || found {
			return fmt.Errorf("Redis keeps the push sequence after the shred (%v)", err)
		}
		for _, key := range []string{evsservice.LeaseKey(self.RepoId), evsservice.HeadCacheKey(self.RepoId)} {
			fields, err := net.Host().Redis.HashGetAll(inspect, key)
			if err != nil || 0 < len(fields) {
				return fmt.Errorf("Redis keeps %s after the shred (%v)", key, err)
			}
		}
		return nil
	}
}
