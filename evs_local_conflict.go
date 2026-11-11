//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// Conflict branches (DESIGN-DETAILS 8.2.7; QD-602, owner decision 240): a local ref holding commits evs's ref does
// not hold, when evs's ref has moved elsewhere or will not take them (an owned ref whose sidecar's state was restored
// or copied, a queued update evs refused for good, a ref moved outside the daemon), keeps them on a branch of its own
// before it follows evs.
//
//	conflict(r)  one git update-ref --stdin transaction: create
//	             refs/heads/ur/<sidecar_id>/conflicts/<r's name bytes>/<time> at L's commit, and update r from L to E
//	             (delete when E is none); <time> UTC yyyymmddThhmmssZ, a second later while the name is taken
//	             then: r's journal updates deleted, a queue update (LOCAL, kind 4) added for the conflict branch, and
//	             SidecarEvent evs_conflict {RepoId, RefId: r's, Path: the conflict ref's name}
//	lifecycle    an owned ref of this sidecar like any other: the queue publishes it, as an overlay of r (the base search
//	             finds r's tip on its line), so the commits are safe off the device and visible to the member's other
//	             devices; nothing merges it, moves it or deletes it but its owner, with stock git (D-EVS-8); `ur status`
//	             lists each until its ref is deleted
//	bound        a ref with ConflictBranchCount conflict branches stops settling, its local ref left alone, and `ur
//	             status` says so, until one is deleted
//
// A conflict branch is never made for a commit evs's ref holds: settle follows whenever L is E or an ancestor of it,
// before it considers a conflict (G9).
//
// Desktop legs only. Called under L_r; the conflict branch's own journal is written after it, under that ref's L.

package sidecar

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// A conflict branch settle made.
type evsGitConflictMade struct {
	name   []byte
	commit *EvsGitOid
}

// Makes ref's conflict branch at local's commit and moves the local ref to evsTip in one transaction (see the file
// header); nil at the bound, having made nothing.
func (self *EvsGitSyncEngine) conflictWithLock(ctx context.Context, ref *EvsGitRef, gitRef string, local *EvsGitOid, evsTip *EvsGitOid) (*evsGitConflictMade, error) {
	mount := self.mount
	sidecarId := self.client.args.Identity().SidecarId
	prefix := evsGitBranchPrefix + string(EvsOwnedRefName(sidecarId, "conflicts/")) + string(ref.Name) + "/"
	out, err := mount.Git(ctx, "for-each-ref", "--format=%(refname)", prefix)
	if err != nil {
		return nil, err
	}
	standing := map[string]bool{}
	for _, line := range strings.Fields(string(out)) {
		standing[line] = true
	}
	if self.settings.ConflictBranchCount <= len(standing) {
		self.client.log.Warningf("[evs]ref %s of repo %s has %d conflict branches and stops settling", ref.RefId, self.repo.repoId, len(standing))
		return nil, nil
	}
	if local == nil {
		// nothing local to keep: the deletion of a local ref is followed
		return &evsGitConflictMade{}, mount.updateRefs(ctx, []string{evsUpdateRefLine(gitRef, evsTip, local)})
	}
	commit, err := mount.peel(ctx, *local)
	if err != nil {
		return nil, err
	}
	at := self.clock.Now().UTC().Truncate(time.Second)
	name := EvsConflictRefName(sidecarId, ref.Name, at)
	for standing[evsGitBranchPrefix+string(name)] {
		at = at.Add(time.Second)
		name = EvsConflictRefName(sidecarId, ref.Name, at)
	}
	if err := mount.updateRefs(ctx, []string{
		evsUpdateRefLine(evsGitBranchPrefix+string(name), &commit, nil),
		evsUpdateRefLine(gitRef, evsTip, local),
	}); err != nil {
		return nil, fmt.Errorf("evs: a conflict branch's transaction: %w", err)
	}
	// the conflicted ref's queued updates go: the conflict branch's queue carries its commits now
	journal, err := self.state.journal(ref.RefId)
	if err != nil {
		return nil, err
	}
	journal.Updates, journal.Attempts, journal.HoldCode, journal.HoldMs, journal.HoldLocal = nil, nil, "", 0, ""
	if err := self.state.writeJournal(ref.RefId, journal); err != nil {
		return nil, err
	}
	repoId, refId := self.repo.repoId, ref.RefId
	self.client.emit(SidecarEvent{Kind: SidecarEventEvsConflict, RepoId: &repoId, RefId: &refId, Path: string(name)})
	self.client.log.Warningf("[evs]ref %s of repo %s diverged: its local commits are on a conflict branch", refId, repoId)
	return &evsGitConflictMade{name: name, commit: &commit}, nil
}

// The conflict branch's queue update (LOCAL, kind 4), under its own L, and the queue woken: what settle's caller does
// once r's L is released. A crash before it leaves a conflict branch with no journal, which the restart's queue scan
// finds (evs_local_receive.go).
func (self *EvsGitSyncEngine) queueConflict(ctx context.Context, settled *evsGitSettled) error {
	if settled == nil || settled.conflictCommit == nil {
		return nil
	}
	refId, err := self.repo.resolveRefId(ctx, settled.conflictRef, nil)
	if err != nil {
		return err
	}
	release, err := self.mount.locks.LockApply(ctx, refId)
	if err != nil {
		return err
	}
	err = func() error {
		defer release()
		journal, err := self.state.journal(refId)
		if err != nil {
			return err
		}
		journal.RefName = settled.conflictRef
		journal.add(nil, settled.conflictCommit, EvsJournalLocal, EvsJournalKindConflict, self.clock.Now())
		return self.state.writeJournal(refId, journal)
	}()
	if err != nil {
		return err
	}
	self.wakeQueue(refId)
	return nil
}

// The conflict branches of the mount's refs that stand, by ref name: what `ur status` lists.
func (self *EvsGitSyncEngine) ConflictBranches(ctx context.Context) ([][]byte, error) {
	sidecarId := self.client.args.Identity().SidecarId
	prefix := evsGitBranchPrefix + string(EvsOwnedRefName(sidecarId, "conflicts/"))
	out, err := self.mount.Git(ctx, "for-each-ref", "--format=%(refname)", prefix)
	if err != nil {
		return nil, err
	}
	names := [][]byte{}
	for _, line := range strings.Fields(string(out)) {
		names = append(names, []byte(strings.TrimPrefix(line, evsGitBranchPrefix)))
	}
	return names, nil
}
