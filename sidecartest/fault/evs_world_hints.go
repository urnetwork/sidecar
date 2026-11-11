// The evs world's subscriptions and hints (§11.10; FS-12, EVS1-M2-41), beside evs_world.go: a device subscribes as
// EvsRepo.Subscribe does, and its subscriber's rounds run one a step on the device's actor, never on a goroutine of
// their own, since the world answers every wait at once; the hints evs sends reach the Net's push fake, which T3 keeps
// too, and a step hands a device what it was sent, as its push client would. The subscriber's draws for the resync's
// offset and a renewal's time are each half the span, so a schedule repeats. The rounds' entry point is the root's
// under sidecar_testhooks (evs_subscribe_testhooks.go), which evs_world_hints_testhooks.go installs here, so a
// schedule that subscribes runs only in that build, as every schedule holding a barrier does.

package fault

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The root's subscriber seams, set under sidecar_testhooks: one round now on the caller's goroutine, and the draw the
// subscriber takes. nil in any other build, where a schedule that subscribes fails.
var (
	evsWorldRunSubscriptionRound  func(ctx context.Context, client *sidecar.EvsClient) time.Time
	evsWorldSetSubscriptionRandom func(client *sidecar.EvsClient, random func(limit time.Duration) time.Duration)
)

// A schedule that subscribes outside the sidecar_testhooks build.
var errEvsWorldNoSubscriptionRounds = errors.New("the evs world drives subscriptions only in the sidecar_testhooks build")

// One device's subscription as the world keeps it: the changes it raised and how many of its hints it was handed.
type evsWorldSubscriber struct {
	subscription *sidecar.EvsSubscription
	changes      []*sidecar.EvsRepoChange
	hintCount    int
	// each hint handed over, its EvsHeadChanged
	hinted []*protocol.EvsHeadChanged
}

// The subscriber of device, made on first use. Under the world's lock.
func (self *EvsWorld) subscriberWithLock(device string) *evsWorldSubscriber {
	if self.subscribers == nil {
		self.subscribers = map[string]*evsWorldSubscriber{}
	}
	subscriber := self.subscribers[device]
	if subscriber == nil {
		subscriber = &evsWorldSubscriber{}
		self.subscribers[device] = subscriber
	}
	return subscriber
}

// A step action: device subscribes to main, its whole ref, the changes kept for ExpectChange. Subscribe answers once
// the lease answered 200, or with the lease still owed once its retries ran out, which the device's rounds keep
// trying; ExpectLease tells the two apart.
func (self *EvsWorld) Subscribe(device string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		if evsWorldRunSubscriptionRound == nil || evsWorldSetSubscriptionRandom == nil {
			return errEvsWorldNoSubscriptionRounds
		}
		world := self.Device(device)
		evsWorldSetSubscriptionRandom(world.Client, func(limit time.Duration) time.Duration { return limit / 2 })
		refId := self.RefId()
		subscription, err := world.Repo.Subscribe(ctx, &sidecar.EvsSubscribeArgs{
			RefId: &refId,
			Changes: func(change *sidecar.EvsRepoChange) {
				copied := *change
				copied.Paths = slices.Clone(change.Paths)
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				subscriber := self.subscriberWithLock(device)
				subscriber.changes = append(subscriber.changes, &copied)
			},
		})
		if err != nil {
			return fmt.Errorf("%s's subscription: %w", device, err)
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.subscriberWithLock(device).subscription = subscription
		return nil
	}
}

// A step action: one round of device's subscriber, now, on device's actor.
func (self *EvsWorld) SubscriptionRound(device string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		if evsWorldRunSubscriptionRound == nil {
			return errEvsWorldNoSubscriptionRounds
		}
		evsWorldRunSubscriptionRound(ctx, self.Device(device).Client)
		return nil
	}
}

// A step action: device is handed every hint on the repo's topic the push fake holds for its client and has not
// handed it yet, in order, as its push client would deliver them (EvsClient.ReceiveHint).
func (self *EvsWorld) DeliverHints(device string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		world := self.Device(device)
		hints := net.Fakes().Push.Hints(connect.Id(world.ClientId))
		self.stateLock.Lock()
		subscriber := self.subscriberWithLock(device)
		fresh := hints[min(subscriber.hintCount, len(hints)):]
		subscriber.hintCount = len(hints)
		self.stateLock.Unlock()
		topic := sidecar.PushTopicEvs(self.RepoId)
		for _, hint := range fresh {
			if hint.Topic != topic || hint.Kind != uint32(protocol.MessageType_EVS_HEAD_CHANGED) {
				continue
			}
			changed := &protocol.EvsHeadChanged{}
			if err := proto.Unmarshal(hint.Body, changed); err != nil {
				return fmt.Errorf("a hint to %s that is no EvsHeadChanged: %w", device, err)
			}
			self.stateLock.Lock()
			subscriber.hinted = append(subscriber.hinted, changed)
			self.stateLock.Unlock()
			world.Client.ReceiveHint(self.RepoId, hint.Version, hint.Body)
		}
		return nil
	}
}

// The version path's newest committed write committed at, from the ledger.
func (self *EvsWorld) newestCommittedVersion(path string) (uint64, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	version := uint64(0)
	for _, write := range self.pathWrites[path] {
		if write.state == evsWorldWriteCommitted {
			version = max(version, write.version)
		}
	}
	if version == 0 {
		return 0, fmt.Errorf("no write of %q committed", path)
	}
	return version, nil
}

// A step action: device's subscription raised a change naming the version path's newest committed write committed
// at, or one past it.
func (self *EvsWorld) ExpectChange(device string, path string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		version, err := self.newestCommittedVersion(path)
		if err != nil {
			return err
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		seen := []uint64{}
		for _, change := range self.subscriberWithLock(device).changes {
			if change.RefId == self.refId && (change.Version == version || (change.Gap && version <= change.Version)) {
				return nil
			}
			seen = append(seen, change.Version)
		}
		return fmt.Errorf("%s's subscription raised no change at %q's version %d, only at %v", device, path, version, seen)
	}
}

// A step action: device was handed a hint naming the version path's newest committed write committed at (hinted) or
// none naming it (not hinted).
func (self *EvsWorld) ExpectHinted(device string, path string, hinted bool) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		version, err := self.newestCommittedVersion(path)
		if err != nil {
			return err
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		found := false
		for _, changed := range self.subscriberWithLock(device).hinted {
			if sidecar.Id(changed.GetRefId()) == self.refId && changed.GetVersion() == version {
				found = true
			}
		}
		if found != hinted {
			return fmt.Errorf("%s hinted of %q's version %d: %t, not %t", device, path, version, found, hinted)
		}
		return nil
	}
}

// A step action: {evsl_<repo_id>} holds a live lease of device's on main (held), or none of its (not held).
func (self *EvsWorld) ExpectLease(device string, held bool) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		world := self.Device(device)
		leases, err := evsservice.ReadLeases(sidecartest.InspectContext(ctx), net.Host().Redis, self.RepoId)
		if err != nil {
			return err
		}
		now := net.Clock().Now()
		found := false
		for _, lease := range leases {
			if lease.ClientId == world.ClientId && lease.SidecarId == world.Signer.SidecarId && now.Before(lease.ExpiresAt) &&
				(lease.EveryRef || lease.RefId == self.RefId()) {
				found = true
			}
		}
		if found != held {
			return fmt.Errorf("%s's lease on main held: %t, not %t (%d leases)", device, found, held, len(leases))
		}
		return nil
	}
}

// A step action: the repo's leases and their version are lost from Redis at once, as a Redis restart loses the family,
// under an inspecting context.
func (self *EvsWorld) LoseLeases() func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		inspect := sidecartest.InspectContext(ctx)
		if err := net.Host().Redis.Delete(inspect, []string{evsservice.LeaseKey(self.RepoId), evsservice.LeaseVersionKey(self.RepoId)}); err != nil {
			return fmt.Errorf("losing the leases: %w", err)
		}
		return nil
	}
}

