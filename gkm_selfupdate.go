// Path-only self-updates (KEYS-M2-23; D-KEYS-14, D-KEYS-26; §10.4, DESIGN-DETAILS 6.2.6): a leaf that committed no
// path for SelfUpdateInterval, SelfUpdateIntervalLarge in a group above LargeGroupLeafCount leaves, commits one, a
// read_only leaf too, under the rules of any commit (R1 to R4): it carries no proposal, GenWrap_{e+1} of the newest
// generation and, at 16 leaves or fewer, the sealed GroupInfo.
//
//	last path  the later of what this leaf's own credential in the tree shows, its not_after less a credential's
//	           life, since every path and external join signs it afresh, and the time this device recorded at its
//	           last adopted path commit or external join (the sync record), which also covers an engine that keeps a
//	           credential across paths
//	at once    a join through the last-resort KeyPackage owes a path at its first opportunity, whatever the
//	           interval: until then its leaf's HPKE key is every other Welcome's that package serves (RFC 9420
//	           §16.8; 6.2.2)
//	writer     a leaf that may commit Removes and Adds runs the pending engine first: its commit with a Remove
//	           carries a path, which is its self-update
//	R3 wait    a leaf that may not commit the Remove its tree needs, a read_only one, commits nothing while a
//	           dropped leaf stands: its own check refuses the path before any upload (ErrGkmDroppedLeafStands), it
//	           asks H2 at most once a LateAskInterval, and the self-update lands once a writer leaf's Remove has
//	           (gkm_sync.go)
//
// A waiting self-update makes no leaf stale by itself: §10.9's stale rule reads the leaf's credential, so a leaf
// that cannot commit because a dropped leaf stands is removed only after stale_leaf_days, as any quiet leaf, and
// returns by resync once the Remove lands.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// When a leaf's own credential says it last changed: not_after less a credential's life; zero for one that does not
// parse.
func gkmLeafLastChange(member MlsMember) time.Time {
	credential := &protocol.UrMlsCredential{}
	if err := proto.Unmarshal(member.Credential, credential); err != nil || credential.GetNotAfter() <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(credential.GetNotAfter()).Add(-gkmCredentialLifetime)
}

// Whether this leaf's self-update is due at now, and when its last path was. A leaf with no last path either source
// shows is due.
func (self *gkmGroupManager) selfUpdateDueInFlow(group MlsGroup, now time.Time) (bool, time.Time, error) {
	client := self.client
	record, err := client.syncRecord(self.repoId)
	if err != nil {
		return false, time.Time{}, err
	}
	lastPath := gkmLeafLastChange(group.Self())
	if lastPath.Before(record.pathCommittedAt) {
		lastPath = record.pathCommittedAt
	}
	if record.selfUpdateOwed {
		return true, lastPath, nil
	}
	interval := client.settings.SelfUpdateInterval
	if client.settings.LargeGroupLeafCount < len(group.Roster()) {
		interval = client.settings.SelfUpdateIntervalLarge
	}
	return !now.Before(lastPath.Add(interval)), lastPath, nil
}

// Whether the repo's self-update is due now: false for a repo this device holds no leaf of.
func (self *GkmGroupClient) SelfUpdateDue(repoId Id) (bool, error) {
	manager := self.manager(repoId)
	manager.flowLock.Lock()
	defer manager.flowLock.Unlock()
	pins, err := self.repoPins(repoId)
	if errors.Is(err, ErrGkmKeyMissing) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	group, err := self.loadGroup(pins.groupId)
	if errors.Is(err, ErrMlsGroupUnknown) || errors.Is(err, ErrMlsNotMember) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	due, _, err := manager.selfUpdateDueInFlow(group, self.clock.Now())
	return due, err
}

// The repo's self-update, if one is due: see the file header. Nil when none is due or it landed;
// ErrGkmDroppedLeafStands, wrapped in ErrGkmCommitRefused, while it waits under R3; ErrGkmWait when another's commit
// took its epoch, after which it is due again.
func (self *GkmGroupClient) RunSelfUpdate(ctx context.Context, repoId Id) error {
	manager := self.manager(repoId)
	manager.flowLock.Lock()
	defer manager.flowLock.Unlock()
	state, err := self.currentState()
	if err != nil {
		return err
	}
	// due is read at the newest epoch, after whatever this device may commit: a writer leaf's Remove is its path
	leaf := func() (*gkmRepoPins, MlsGroup, bool, error) {
		pins, err := self.repoPins(repoId)
		if errors.Is(err, ErrGkmKeyMissing) {
			return nil, nil, false, nil
		}
		if err != nil {
			return nil, nil, false, err
		}
		group, err := self.loadGroup(pins.groupId)
		if errors.Is(err, ErrMlsGroupUnknown) || errors.Is(err, ErrMlsNotMember) {
			return nil, nil, false, nil
		}
		if err != nil {
			return nil, nil, false, err
		}
		due, _, err := manager.selfUpdateDueInFlow(group, self.clock.Now())
		return pins, group, due, err
	}
	_, _, due, err := leaf()
	if err != nil || !due {
		return err
	}
	if err := manager.runPendingInFlow(ctx); err != nil {
		return err
	}
	pins, group, due, err := leaf()
	if err != nil || !due {
		return err
	}
	outcome, err := manager.commitInFlow(ctx, state, pins, group, &MlsCommitArgs{Path: true}, nil)
	if err != nil {
		if errors.Is(err, ErrGkmDroppedLeafStands) {
			// R3's wait: a writer leaf's Remove releases it, and H2 keeps one awake
			self.askWant(ctx, repoId, pins.groupId, pins.epoch+1)
		}
		return err
	}
	if outcome == gkmCommitLost {
		return fmt.Errorf("%w: the self-update lost its epoch", ErrGkmWait)
	}
	return nil
}

// A path this leaf committed was adopted, or it joined by an external commit: the self-update interval starts
// over, and a last-resort join's path is paid.
func (self *GkmGroupClient) notePathCommitted(repoId Id) error {
	now := self.clock.Now()
	return self.editSyncRecord(repoId, func(record *gkmSyncRecord) {
		record.pathCommittedAt = now
		record.selfUpdateOwed = false
	})
}

// The path a last-resort join owes, for each repo just joined, each on its own goroutine as any hint's work: a repo
// joined under a one-time KeyPackage owes none, and its check costs one keychain read.
func (self *GkmGroupClient) selfUpdateJoined(ctx context.Context, joinedRepoIds []Id) {
	for _, repoId := range joinedRepoIds {
		self.hintWork(ctx, "self-update", repoId, func() {
			self.logFlowError("self-update", self.RunSelfUpdate(ctx, repoId))
		})
	}
}
