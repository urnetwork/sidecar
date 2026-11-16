//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// The git-lfs tip check (§11.11's tip check and journal rows; R-EVS-20, D-EVS-28, D-EVS-41, FI-2, FI-9, FS-73;
// EVS2-M10-27). git-lfs uploads only objects of commits the remote's old tip does not reach, so a force push to an
// ancestor, a new ref or tag at old history, an import, `--no-verify` and GIT_LFS_SKIP_PUSH upload nothing: §11.16
// rejected trusting pre-push for that. So for every git-mode update from old to new, through any listener or
// git-remote-ur, the daemon takes R(new) less R(old) (evs_lfs_required.go), old being the tip the push's TIP CAS names,
// none for a new ref or the first push after a DELETE, and reads each object's newest ur/lfs version, by a head read
// wherever the store's cache shows none:
//
//	fresh    a creation or touch signed under LfsFreshAge (5 days) ago: nothing to write
//	stale    older: one protecting touch of them all, in one ur/lfs push (parts as the sender needs), retried as the
//	         journal's pushes are, whose 200 comes before the git push's POST, each naming the version read so a prune
//	         that read it fails path-level CAS; a 409 rereads the path, a newer version counting as fresh
//	missing  absent or removed: `ng <ref> lfs objects missing`, nothing published, the journal entry dropped, the
//	         hook printing `git lfs push --object-id <remote> <oid>...` and up to LfsMissingShownCount (20) oids, each
//	         with a path that needs it and when its prune committed
//	again    before a push id's first POST when the check is over LfsCheckMaxAge (1 h) old
//	owned    an owned ref, accepted at once, is checked before its first POST, where a missing object holds its entry,
//	         `ur status` naming the objects and the command, until `ur evs retry` after their upload, or a later tip
//	         that does not need them
//
// The check and the git push are two commits ordered by the journal, never merged: git-mode refs commit only on TIP.
// Ordinary pushes write no touch, since their objects were just uploaded and read as fresh. `ur evs import` first
// uploads, through the store, each object the imported tip requires that <dir>'s own git-lfs store holds.
//
// The check runs while the network is in §19.11's format2 gate (EvsClient.Format2Admitted), which git-lfs's store
// rides: outside it a push is published as before M10. The plaintext paths it prints go to the pushing client's own
// terminal, never a log (I-13).
//
// Desktop legs only. Package-level functions are safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// What git hears for an update the check refuses.
const evsLfsTipCheckRefusal = "lfs objects missing"

// The check found objects the store does not hold: the update is refused and nothing is published.
var ErrEvsLfsObjectsMissing = errors.New("evs: git-lfs objects missing")

// One check's inputs.
type EvsLfsTipCheckArgs struct {
	Mount *EvsLocalRepo
	Store *EvsLfsStore
	// The tip the push's TIP CAS names; nil for a new ref or the first push after a DELETE.
	Old *EvsGitOid
	New EvsGitOid
}

// What one check found.
type EvsLfsTipCheckResult struct {
	// The objects the new tip needs that the store does not hold, by oid, each with a path and its prune's time.
	Missing []*EvsLfsMissingObject
	// How many required objects were fresh, and how many the check touched.
	FreshCount   int
	TouchedCount int
	CheckedAt    time.Time
}

// An object a tip needs that the store does not hold.
type EvsLfsMissingObject struct {
	Requirement *EvsLfsRequirement
	// zero when the store never held it
	RemovedAt time.Time
}

// Runs the check: see the file header. An error other than the result's Missing is the store's or git's, which refuses
// the update as any publish error would.
func EvsLfsTipCheck(ctx context.Context, args *EvsLfsTipCheckArgs) (*EvsLfsTipCheckResult, error) {
	settings := args.Store.settings
	result := &EvsLfsTipCheckResult{CheckedAt: args.Store.clock.Now()}
	required, err := EvsLfsRequiredDiff(ctx, &EvsLfsGitRepo{Git: args.Mount.git, Dir: args.Mount.BareDir, Settings: settings}, args.Old, args.New)
	if err != nil || len(required) == 0 {
		return result, err
	}
	oids := make([]EvsLfsOid, 0, len(required))
	byOid := map[EvsLfsOid]*EvsLfsRequirement{}
	for _, requirement := range required {
		oids = append(oids, requirement.Oid)
		byOid[requirement.Oid] = requirement
	}
	newest, err := args.Store.Newest(ctx, oids, false)
	if err != nil {
		return nil, err
	}
	stale := []*EvsLfsObject{}
	for _, object := range newest {
		switch {
		case !object.Present():
			result.Missing = append(result.Missing, &EvsLfsMissingObject{Requirement: byOid[object.Oid], RemovedAt: object.removedAt()})
		case result.CheckedAt.Sub(object.SignedAt) < settings.LfsFreshAge:
			result.FreshCount += 1
		default:
			stale = append(stale, object)
		}
	}
	if 0 < len(result.Missing) || len(stale) == 0 {
		return result, nil
	}
	_, err = args.Store.Touch(ctx, stale)
	var conflict *EvsPathConflictError
	switch {
	case errors.As(err, &conflict):
		// another touch or a prune moved one: read them again, a newer version counting as fresh
		staleOids := make([]EvsLfsOid, 0, len(stale))
		for _, object := range stale {
			staleOids = append(staleOids, object.Oid)
		}
		reread, err := args.Store.Newest(ctx, staleOids, true)
		if err != nil {
			return nil, err
		}
		again := []*EvsLfsObject{}
		for i, object := range reread {
			switch {
			case !object.Present():
				result.Missing = append(result.Missing, &EvsLfsMissingObject{Requirement: byOid[object.Oid], RemovedAt: object.removedAt()})
			case stale[i].Version < object.Version:
				result.FreshCount += 1
			default:
				again = append(again, object)
			}
		}
		if 0 < len(result.Missing) || len(again) == 0 {
			return result, nil
		}
		if _, err := args.Store.Touch(ctx, again); err != nil {
			return nil, err
		}
		result.TouchedCount = len(again)
	case err != nil:
		return nil, err
	default:
		result.TouchedCount = len(stale)
	}
	return result, nil
}

// The lines the hook prints for a check that found missing objects, refName's: the command that uploads them and up to
// LfsMissingShownCount objects, each with a path that needs it and when its prune committed.
func EvsLfsMissingLines(refName string, missing []*EvsLfsMissingObject, settings *EvsSettings) []string {
	oids := make([]string, 0, len(missing))
	for _, object := range missing {
		oids = append(oids, object.Requirement.Oid.String())
	}
	lines := []string{
		fmt.Sprintf("ur: %s: %d git-lfs object(s) this push needs are not stored; upload them, then push again:", refName, len(missing)),
		"ur:   git lfs push --object-id <remote> " + strings.Join(oids, " "),
	}
	for i, object := range missing {
		if settings.LfsMissingShownCount <= i {
			lines = append(lines, fmt.Sprintf("ur:   and %d more", len(missing)-i))
			break
		}
		line := fmt.Sprintf("ur:   %s needed by %s", object.Requirement.Oid, object.Requirement.Path)
		if !object.RemovedAt.IsZero() {
			line += ", pruned " + object.RemovedAt.UTC().Format(time.RFC3339)
		}
		lines = append(lines, line)
	}
	return lines
}

// The receiver's git-lfs store, made once.
func (self *EvsGitReceiver) lfsStore() *EvsLfsStore {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.lfs == nil {
		self.lfs = NewEvsLfsStore(self.repo)
	}
	return self.lfs
}

// The check of an update from old to new on this receiver's mount, nil while the network is outside the format2 gate
// or for a deletion, and in the sidecar_testhooks build where FS-73's twin switched it off (evs_lfs_tipcheck_testhooks.go).
func (self *EvsGitReceiver) lfsTipCheck(ctx context.Context, old *EvsGitOid, new *EvsGitOid) (*EvsLfsTipCheckResult, error) {
	if new == nil || !self.client.Format2Admitted() || evsLfsTipCheckSwitchedOff(self.mount) {
		return nil, nil
	}
	return EvsLfsTipCheck(ctx, &EvsLfsTipCheckArgs{Mount: self.mount, Store: self.lfsStore(), Old: old, New: *new})
}

// An import's uploads (§11.11's import row): each object the imported tip requires that dir's own git-lfs store holds,
// stored or touched before the first push, so the tip check refuses only what neither store holds.
func (self *evsImporter) uploadLfs(ctx context.Context, dir string, tip EvsGitOid) error {
	if !self.repo.client.Format2Admitted() {
		return nil
	}
	required, err := EvsLfsRequired(ctx, &EvsLfsGitRepo{Git: self.mount.git, Dir: self.mount.BareDir, Settings: self.settings}, tip)
	if err != nil {
		return err
	}
	if len(required) == 0 {
		return nil
	}
	objectsDirs := []string{filepath.Join(dir, ".git", "lfs", "objects"), filepath.Join(dir, "lfs", "objects")}
	store := NewEvsLfsStore(self.repo)
	for _, requirement := range required {
		text := requirement.Oid.String()
		for _, objectsDir := range objectsDirs {
			path := filepath.Join(objectsDir, text[0:2], text[2:4], text)
			if _, err := os.Stat(path); err != nil {
				continue
			}
			if _, err := store.UploadFile(ctx, requirement.Oid, requirement.Size, path); err != nil {
				return err
			}
			break
		}
	}
	return nil
}
