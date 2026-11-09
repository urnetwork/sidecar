// GkmHint sending (§10.14, D-KEYS-19, §6.8): a hint is only a wake, carrying ids, kinds and versions and never
// content, and lossy, since a client that misses one finds the change at its next fetch or its hourly resync. So a
// request hands its hints to a bounded queue and never waits on Redis: a full queue drops the hint and counts it,
// and a send that fails is counted and passed over.
//
// Two topics:
//
//   - gkm:<group_id> carries commit, versioned epoch x 2^24 + generation, so a rotation with no commit raises it
//     too, and a same-epoch rotation is never dropped as stale (D-KEYS-19);
//   - gkm, per client, carries the work hints, pending, welcome, key-packages-low and wrap-pending, to the sidecars
//     that must act, versioned by gkm's clock in µs, which the hint script raises past the stored value, so skew
//     between gkm processes never makes a work hint stale (§6.8's topic registry).
//
// gkm knows sidecars, not clients: the host's Push.HintSidecars resolves each to its current client
// (plan-KEYS-hint-addressing, decided), and a sidecar it cannot resolve is a lost hint, which the hourly resync
// covers.
//
// Safe for concurrent use.

package gkmservice

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// One hint on its way: who it goes to and what it says.
type gkmQueuedHint struct {
	sidecarIds []sidecar.Id
	hint       *sidecar.ClientHint
	// the hint's kind, a closed set, for the counters
	kindName string
}

// The body of a GkmHint: group, epoch, kind and, for a late wrap's ask, its recipient as the wrap path writes it.
func gkmHintBody(groupId *sidecar.Id, epoch uint64, kind protocol.GkmHintKind, recipient []byte) ([]byte, error) {
	hint := &protocol.GkmHint{Epoch: epoch, Kind: kind, Recipient: recipient}
	if groupId != nil {
		hint.GroupId = groupId.Bytes()
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(hint)
}

// Queues a commit hint on gkm:<group_id> to sidecarIds, at epoch and generation.
func (self *GkmEngine) hintCommit(sidecarIds []sidecar.Id, groupId sidecar.Id, epoch uint64, generation uint64) {
	version, err := sidecar.GkmGroupVersion(epoch, generation)
	if err != nil {
		self.metrics.hintsDropped.Add(1, protocol.GkmHintKind_GKM_HINT_COMMIT.String())
		return
	}
	body, err := gkmHintBody(&groupId, epoch, protocol.GkmHintKind_GKM_HINT_COMMIT, nil)
	if err != nil {
		self.metrics.hintsDropped.Add(1, protocol.GkmHintKind_GKM_HINT_COMMIT.String())
		return
	}
	self.queueHint(&gkmQueuedHint{
		sidecarIds: sidecarIds,
		hint: &sidecar.ClientHint{
			Topic:   sidecar.PushTopicGkmGroup(groupId),
			Version: version,
			Kind:    uint32(protocol.MessageType_GKM_HINT),
			Body:    body,
		},
		kindName: protocol.GkmHintKind_GKM_HINT_COMMIT.String(),
	})
}

// Queues a work hint, pending, welcome, key-packages-low or wrap-pending, on the per-client gkm topic of
// sidecarIds. groupId is nil for one about no group, as key-packages-low is.
func (self *GkmEngine) hintWork(sidecarIds []sidecar.Id, kind protocol.GkmHintKind, groupId *sidecar.Id, epoch uint64, recipient []byte) {
	if kind == protocol.GkmHintKind_GKM_HINT_COMMIT || kind == protocol.GkmHintKind_GKM_HINT_KIND_UNSPECIFIED {
		self.metrics.hintsDropped.Add(1, kind.String())
		return
	}
	body, err := gkmHintBody(groupId, epoch, kind, recipient)
	if err != nil {
		self.metrics.hintsDropped.Add(1, kind.String())
		return
	}
	// gkm's clock in µs, which the script raises past the stored value when it is not above it (§6.8)
	version := uint64(max(1, self.clock.Now().UnixMicro()))
	self.queueHint(&gkmQueuedHint{
		sidecarIds: sidecarIds,
		hint: &sidecar.ClientHint{
			Topic:   sidecar.PushTopicGkm,
			Version: version,
			Kind:    uint32(protocol.MessageType_GKM_HINT),
			Body:    body,
		},
		kindName: kind.String(),
	})
}

// Hands a hint to the senders without waiting: dropped and counted when the queue is full or the engine is closing.
func (self *GkmEngine) queueHint(queued *gkmQueuedHint) {
	if len(queued.sidecarIds) == 0 {
		return
	}
	self.hintPendingCount.Update(func(count int) int { return count + 1 })
	select {
	case self.hintQueue <- queued:
	default:
		self.hintPendingCount.Update(func(count int) int { return count - 1 })
		self.metrics.hintsDropped.Add(1, queued.kindName)
	}
}

// One sender: takes queued hints until the engine ends.
func (self *GkmEngine) runHintSender() {
	for {
		select {
		case <-self.ctx.Done():
			return
		case queued := <-self.hintQueue:
			self.sendHint(queued)
			self.hintPendingCount.Update(func(count int) int { return count - 1 })
		}
	}
}

// Sends one hint under HintTimeout. A failure is counted and passed over: the hourly resync covers it (§6.8).
func (self *GkmEngine) sendHint(queued *gkmQueuedHint) {
	push := self.host.Push
	if push == nil {
		self.metrics.hintsFailed.Add(1, queued.kindName)
		return
	}
	ctx, cancel := context.WithCancel(self.ctx)
	defer cancel()
	stop := self.clock.AfterFunc(self.settings.HintTimeout, cancel)
	defer stop()
	connectSidecarIds := make([]connect.Id, len(queued.sidecarIds))
	for i, sidecarId := range queued.sidecarIds {
		connectSidecarIds[i] = connect.Id(sidecarId)
	}
	if err := push.HintSidecars(ctx, connectSidecarIds, queued.hint); err != nil {
		self.metrics.hintsFailed.Add(1, queued.kindName)
		if self.log.V(1).Enabled() {
			self.log.Infof("[gkm] a %s hint to %d sidecars failed: %v", queued.kindName, len(queued.sidecarIds), err)
		}
		return
	}
	self.metrics.hintsSent.Add(1, queued.kindName)
}

// Hints queued and not yet sent, and a channel that closes when the count next changes: what a test waits on
// instead of sleeping.
func (self *GkmEngine) HintsPending() (count int, changed chan struct{}) {
	return self.hintPendingCount.Get()
}

// Waits until every queued hint has been sent or dropped, or ctx ends.
func (self *GkmEngine) AwaitHints(ctx context.Context) error {
	for {
		count, changed := self.hintPendingCount.Get()
		if count == 0 {
			return nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return fmt.Errorf("gkm: %d hints still pending: %w", count, ctx.Err())
		}
	}
}
