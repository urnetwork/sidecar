// A client's path epochs (§11.6's read row; D-EVS-12; DESIGN-DETAILS 9.2.1 to 9.2.5): what a request may name of a
// path while a ref's entries live in two to four epochs, and what a push does when the epoch moves under it.
//
//	floor     the lowest epoch in which this device holds evidence evs was shown the path's token (9.2.3's E1 to
//	          E4): a token evs served back in a verified statement or row, a request of its own that evs answered,
//	          or the push a verified version names as its predecessor. A floor only falls, and only on evidence: a
//	          lost record loses it, which only sends less
//	exempt    deposit and erasure refs name entries by random ids under no path key, stay at path epoch 1 for life,
//	          and take neither floors nor rules: every push on them declares epoch 1 and can meet neither 412
//	          PATH_EPOCH nor PATH_EPOCH_DUE (plan-EVS1-epoch-kinds #2)
//	retoken   a push refused 412 PATH_EPOCH never commits, since the epoch only rises; the sender lowers the floor of
//	          every path it named to its epoch (E3), reads the new head, and sends it again with every sealed byte
//	          kept and every token made again in the new epoch (evs_push.go, EvsWritePlan.Retoken)
//
// The ref epoch held for a ref is the epoch state of the last head this client verified, with the time it verified
// it, in memory only.
//
// On every leg. Package-level functions are safe for concurrent use.

package sidecar

import (
	"context"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// Whether a ref of refKind is a deposit or the erasure ref: see the file header.
func evsEpochExempt(refKind protocol.EvsRefKind) bool {
	return refKind == protocol.EvsRefKind_EVS_REF_DEPOSIT || refKind == protocol.EvsRefKind_EVS_REF_ERASURE
}

// floor lowered by evidence of epoch, 0 meaning none.
func evsLowerFloor(floor uint64, epoch uint64) uint64 {
	if epoch == 0 {
		return floor
	}
	if floor == 0 || epoch < floor {
		return epoch
	}
	return floor
}

// A head's current path epoch: 1 before a ref's first PATH_EPOCH.
func evsCurrentEpoch(epoch *protocol.EvsPathEpoch) uint64 {
	return max(1, epoch.GetCurrent())
}

// The epochs a head lists as sources, newest first.
func evsSourceEpochs(epoch *protocol.EvsPathEpoch) []uint64 {
	sources := make([]uint64, 0, len(epoch.GetSources()))
	for _, source := range epoch.GetSources() {
		sources = append(sources, source.GetEpoch())
	}
	return sources
}

// The epoch state of the last head this client verified for a ref, and when it verified it.
type evsRefEpoch struct {
	epoch      *protocol.EvsPathEpoch
	verifiedAt time.Time
	// the head's version and generation pin then
	version    uint64
	generation uint64
}

// The ref's epoch state as the last verified head gave it, nil when this client has verified none.
func (self *EvsClient) refEpochState(repoId Id, refId Id) *evsRefEpoch {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.refEpochs[evsRefKey{repoId: repoId, refId: refId}]
}

// Keeps a verified head's epoch state, verified now, unless a newer head's is held.
func (self *EvsClient) noteVerifiedHead(repoId Id, refId Id, head *protocol.EvsHeadSummary) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := evsRefKey{repoId: repoId, refId: refId}
	if held := self.refEpochs[key]; held != nil && head.GetVersion() < held.version {
		return
	}
	self.refEpochs[key] = &evsRefEpoch{
		epoch:      head.GetPathEpoch(),
		verifiedAt: self.clock.Now(),
		version:    head.GetVersion(),
		generation: head.GetGeneration(),
	}
}

// One round for the ref's head alone (§11.9's read with no path), verified from the pin and pinned, its epoch state
// kept: what a read does first when it holds no epoch state for the ref or a new name needs a fresh one, and what a
// retoken waits on.
func (self *EvsRepo) readHeadAlone(ctx context.Context, refId Id, fresh bool) (*EvsVerifiedHead, error) {
	fromVersion := uint64(0)
	fromChain := EvsChainStart(self.repoId, refId)
	pin, pinned, err := self.client.pins.Pin(self.repoId, refId)
	if err != nil {
		return nil, err
	}
	if pinned {
		fromVersion, fromChain = pin.Version, pin.Chain
		if pin.Version < self.client.hintedVersion(self.repoId, refId) {
			fresh = true
		}
	}
	reply, objects, err := self.client.postRead(ctx, self.repoId, &protocol.EvsReadRequest{RefId: refId.Bytes(), PinVersion: fromVersion, Fresh: fresh})
	if err != nil {
		return nil, err
	}
	objects.close()
	head, err := self.client.verifier.VerifyHead(ctx, &EvsHeadRead{
		RepoId:      self.repoId,
		RefId:       refId,
		Head:        reply.head,
		FromVersion: fromVersion,
		FromChain:   fromChain,
		Statements:  reply.statements,
		Behind:      reply.behind,
	})
	if err != nil {
		return nil, err
	}
	if err := self.client.verifier.Pin(head); err != nil {
		return nil, err
	}
	self.client.noteVerifiedHead(self.repoId, refId, head.Head)
	return head, nil
}

// The ref's head read fresh until its current epoch is above epoch: what a push refused 412 PATH_EPOCH waits for
// before it is re-tokenized (DESIGN-DETAILS 9.2.5). evs refuses a push's epoch only when its head's current epoch
// differs, and the current epoch only rises, so a head that still shows epoch is a cache or a lagging read, asked
// again after ReadRetryWait at most ReadRetryCount times.
func (self *EvsRepo) readHeadPast(ctx context.Context, refId Id, epoch uint64) (*EvsVerifiedHead, error) {
	for attempt := 0; ; attempt += 1 {
		head, err := self.readHeadAlone(ctx, refId, true)
		if err != nil {
			return nil, err
		}
		if epoch < evsCurrentEpoch(head.Head.GetPathEpoch()) {
			return head, nil
		}
		if self.client.settings.ReadRetryCount <= attempt {
			return nil, fmt.Errorf("%w: a head still in path epoch %d after 412 PATH_EPOCH", ErrEvsReplyInvalid, epoch)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-self.client.clock.After(self.client.settings.ReadRetryWait):
		}
	}
}
