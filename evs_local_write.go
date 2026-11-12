//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// WriteAtTip (§16.2's evs_write and evs_delete on a git-mode ref; owner decisions 81, 141; D-EVS-22; EVS1-M3-01): a
// git-mode ref takes no file write from head mode (EVS_GIT_REF), so the daemon commits the change through its local
// tier, on the ref's current tip, and publishes it as any git push to the mount is published:
//
//	mount    the repo's mount, or an implicit one made now (§11.11's names row), its bare repository brought to evs's
//	         tip by the sync engine's replay first
//	check    each try only while the path's newest version on evs is still base_version, 0 for a path that does not
//	         stand, so a write never lands over a change it did not see (ErrEvsPathMoved)
//	commit   the tip's tree with the one path written or removed, through a scratch index of the bare repository's own
//	         (git read-tree, update-index, write-tree), then git commit-tree on the tip: author and committer the agent
//	         label as name and <client_id>@ur.invalid as email, so the commit is one of this sidecar's new commits by
//	         8.2.3's rule, dated by the client's clock; its objects are loose in the bare repository
//	publish  the receive path's own per-ref flow for a shared branch, P_r, settle, the journal, EvsLocalPublish and the
//	         replay that moves the local ref (evs_local_receive.go), so the push is journaled, resolved after a kill
//	         and answered by G7's rules as a git client's would be
//	answers  ok: the version Lookup then finds; non-fast-forward: the tip moved, so the commit is built again on the
//	         newer tip, at most WriteAtTipTryCount tries in all, then ErrEvsGitWriteRefused wrapping
//	         ErrEvsGitTipMoved; remote outcome pending: ErrEvsGitOutcomePending, which the journal resolves; anything
//	         else: ErrEvsGitWriteRefused naming the receive path's reason
//
// Only a shared branch is written so: an owned ref's update is answered by the local queue before evs takes it, so no
// version would stand for Lookup to find, and a tag takes no update past its creation (both refused, incomplete for
// owned refs). A client with no mount registry answers EVS_GIT_REF, as §16.2 says a daemon with no local tier does.
// A refusal names no path or content (I-13).
//
// Desktop legs only; head mode's is evs_local_none.go's. Safe for concurrent use: the receive path's locks order
// tries against every other publisher of the ref.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// A git-mode write whose commit would change nothing: the path holds that content already, or a removal names a
// path the tip's tree lacks.
var ErrEvsGitWriteUnchanged = errors.New("evs: a git-mode write that changes nothing")

// Commits a path's write or removal on a shared git-mode ref's tip through the local tier: see the file header.
func (self *EvsRepo) WriteAtTip(ctx context.Context, args *EvsWriteAtTipArgs) (*EvsWriteAtTipResult, error) {
	mounts := func() *EvsMounts {
		self.client.stateLock.Lock()
		defer self.client.stateLock.Unlock()
		mounts, _ := self.client.localTier.(*EvsMounts)
		return mounts
	}()
	if mounts == nil {
		return nil, fmt.Errorf("%w: this client has no local tier", ErrEvsGitRef)
	}
	if args == nil {
		return nil, fmt.Errorf("%w: no write", ErrEvsWriteInvalid)
	}
	if _, err := evsPathNames(args.Path); err != nil {
		return nil, err
	}
	switch {
	case args.Remove && args.Content != nil:
		return nil, fmt.Errorf("%w: a removal with content", ErrEvsWriteInvalid)
	case !args.Remove && args.Content == nil:
		return nil, fmt.Errorf("%w: a write with no content", ErrEvsWriteInvalid)
	case evsLocalReceiveBlobMaxByteCount < int64(len(args.Content)):
		return nil, fmt.Errorf("%w: content past §11.19's file bound", ErrEvsWriteInvalid)
	case args.Mode != 0 && !evsFileModeValid(args.Mode):
		return nil, fmt.Errorf("%w: mode %o is no file's", ErrEvsWriteInvalid, args.Mode)
	}
	refName := args.RefName
	if refName == nil {
		refName = EvsMainRefName
	}
	for _, reserved := range evsLocalReservedBranchNames {
		if bytes.Equal(refName, reserved) {
			return nil, fmt.Errorf("%w: a ref only the daemon names", ErrEvsWriteInvalid)
		}
	}
	if _, owned := EvsOwnedRefOwner(refName); owned || bytes.HasPrefix(refName, []byte(evsOwnedRefPrefix)) {
		return nil, fmt.Errorf("%w: an owned ref answers from its queue before evs", ErrEvsWriteNotBuilt)
	}
	gitRef := EvsGitRefOfName(refName)
	if strings.HasPrefix(gitRef, evsGitTagPrefix) {
		return nil, fmt.Errorf("%w: a tag takes no write", ErrEvsWriteInvalid)
	}
	mount, ok := mounts.Get(self.repoId)
	if !ok {
		var err error
		if mount, err = mounts.Add(ctx, self.repoId, &EvsMountArgs{AgentLabel: args.AgentLabel}); err != nil {
			return nil, err
		}
	}
	if mount.sync == nil || mount.receiver == nil {
		return nil, fmt.Errorf("%w: a mount with no receive path", ErrEvsNotBuilt)
	}
	label := args.AgentLabel
	if label == "" {
		label = mount.AgentLabel
	}
	if label == "" || strings.ContainsAny(label, "<>\n\x00") || strings.TrimSpace(label) != label {
		return nil, fmt.Errorf("%w: an agent label git takes as no committer name", ErrEvsWriteInvalid)
	}
	refId, err := self.resolveRefId(ctx, refName, nil)
	if err != nil {
		return nil, err
	}
	lookupArgs := &EvsLookupArgs{RefName: refName, Path: args.Path, BaseVersion: args.BaseVersion, Remove: args.Remove}
	if !args.Remove {
		oid, err := EvsGitBlobOid(bytes.NewReader(args.Content), int64(len(args.Content)))
		if err != nil {
			return nil, err
		}
		lookupArgs.GitOid = &oid
	}
	identity := self.client.args.Identity()
	tries := max(1, self.client.settings.WriteAtTipTryCount)
	for try := 0; try < tries; try += 1 {
		newest, err := self.pathNewestVersion(ctx, refName, args.Path)
		if err != nil {
			return nil, err
		}
		if newest != args.BaseVersion {
			return nil, ErrEvsPathMoved
		}
		if err := mount.sync.Replay(ctx, refId); err != nil {
			return nil, err
		}
		ref, err := mount.sync.GitRef(ctx, refId)
		if err != nil {
			return nil, err
		}
		if ref.StuckAt != 0 {
			return nil, fmt.Errorf("%w: the ref is stopped at a refused version", ErrEvsGitWriteRefused)
		}
		commit, err := mount.writeTipCommit(ctx, &evsLocalTipCommit{
			tip: ref.Tip, path: args.Path, content: args.Content, mode: args.Mode, remove: args.Remove,
			message: args.Message, name: label, email: identity.ClientId.String() + evsCommitterDomain,
			timeSeconds: self.client.clock.Now().Unix(),
		})
		if err != nil {
			return nil, err
		}
		status := mount.receiver.receive(ctx, nil, &evsGitReceiveCommand{gitRef: gitRef, old: ref.Tip, new: &commit})
		reason := strings.TrimPrefix(status, "ng "+gitRef+" ")
		switch {
		case status == "ok "+gitRef, reason == "committed remotely, local update pending":
			found, err := self.Lookup(ctx, lookupArgs)
			if err != nil {
				return nil, err
			}
			if found.State != EvsLookupFound {
				return nil, fmt.Errorf("%w: a committed write the path's versions do not show", ErrEvsLookupUnknown)
			}
			return &EvsWriteAtTipResult{
				PushId: found.Version.PushId, Version: found.Version.CommitVersion, PathVersion: found.Version.Version,
				Commit: commit,
			}, nil
		case reason == "non-fast-forward":
			// the tip moved: the next try builds on the newer one, while the path stays at its base
			continue
		case reason == "remote outcome pending":
			return nil, ErrEvsGitOutcomePending
		default:
			return nil, fmt.Errorf("%w: %s", ErrEvsGitWriteRefused, evsOneLine(reason))
		}
	}
	return nil, fmt.Errorf("%w: %w on each of %d tries", ErrEvsGitWriteRefused, ErrEvsGitTipMoved, tries)
}

// The path's newest version on the ref, a standing file's or its removal's, 0 for a path never written: what a try
// holds to its base version.
func (self *EvsRepo) pathNewestVersion(ctx context.Context, refName []byte, path string) (uint64, error) {
	history, err := self.History(ctx, &EvsReadArgs{RefName: refName, Path: path, Fresh: true})
	if errors.Is(err, ErrEvsPathAbsent) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if len(history.Versions) == 0 {
		return 0, nil
	}
	return history.Versions[0].Version, nil
}

// One commit WriteAtTip makes.
type evsLocalTipCommit struct {
	// nil for a ref with no commit yet, whose first commit has no parent
	tip     *EvsGitOid
	path    string
	content []byte
	mode    uint32
	remove  bool
	message string
	// the committer's, which is the author's too
	name        string
	email       string
	timeSeconds int64
}

// The commit on tip with one path written or removed, its blob, trees and commit written loose to the bare repository
// through a scratch index of its own, removed after.
func (self *EvsLocalRepo) writeTipCommit(ctx context.Context, commit *evsLocalTipCommit) (EvsGitOid, error) {
	scratch, err := os.MkdirTemp(self.BareDir, "ur-write-")
	if err != nil {
		return EvsGitOid{}, err
	}
	defer os.RemoveAll(scratch)
	env := []string{"GIT_INDEX_FILE=" + scratch + string(os.PathSeparator) + "index"}
	run := func(input []byte, extra []string, args ...string) ([]byte, error) {
		runArgs := &EvsGitRunArgs{Dir: self.BareDir, Args: args, Env: append(append([]string{}, env...), extra...)}
		if input != nil {
			runArgs.Input = bytes.NewReader(input)
		}
		return self.git.RunWith(ctx, runArgs)
	}
	oidOf := func(out []byte) (EvsGitOid, error) {
		return evsGitOidDecodeHex(bytes.TrimSpace(out))
	}
	var tipTree *EvsGitOid
	if commit.tip != nil {
		if _, err := run(nil, nil, "read-tree", commit.tip.String()); err != nil {
			return EvsGitOid{}, err
		}
		out, err := run(nil, nil, "rev-parse", "--verify", commit.tip.String()+"^{tree}")
		if err != nil {
			return EvsGitOid{}, err
		}
		tree, err := oidOf(out)
		if err != nil {
			return EvsGitOid{}, err
		}
		tipTree = &tree
	} else if _, err := run(nil, nil, "read-tree", "--empty"); err != nil {
		return EvsGitOid{}, err
	}
	record := ""
	if commit.remove {
		record = "0 " + evsGitZeroOidText + "\t" + commit.path + "\x00"
	} else {
		out, err := run(commit.content, nil, "hash-object", "-w", "--stdin")
		if err != nil {
			return EvsGitOid{}, err
		}
		blob, err := oidOf(out)
		if err != nil {
			return EvsGitOid{}, err
		}
		mode := commit.mode
		if mode == 0 {
			mode = EvsGitModeFile
			if listed, err := run(nil, nil, "ls-files", "-s", "-z", "--", commit.path); err == nil {
				if fields := strings.Fields(string(listed)); 0 < len(fields) {
					if previous, err := strconv.ParseUint(fields[0], 8, 32); err == nil && evsFileModeValid(uint32(previous)) {
						mode = uint32(previous)
					}
				}
			}
		}
		record = fmt.Sprintf("%o %s\t%s\x00", mode, hex.EncodeToString(blob[:]), commit.path)
	}
	if _, err := run([]byte(record), nil, "update-index", "--replace", "-z", "--index-info"); err != nil {
		return EvsGitOid{}, err
	}
	out, err := run(nil, nil, "write-tree")
	if err != nil {
		return EvsGitOid{}, err
	}
	tree, err := oidOf(out)
	if err != nil {
		return EvsGitOid{}, err
	}
	if tipTree != nil && tree == *tipTree {
		return EvsGitOid{}, ErrEvsGitWriteUnchanged
	}
	message := commit.message
	if message == "" {
		message = "evs_write"
		if commit.remove {
			message = "evs_delete"
		}
	}
	if !strings.HasSuffix(message, "\n") {
		message += "\n"
	}
	date := fmt.Sprintf("%d +0000", commit.timeSeconds)
	ident := []string{
		"GIT_AUTHOR_NAME=" + commit.name, "GIT_AUTHOR_EMAIL=" + commit.email, "GIT_AUTHOR_DATE=" + date,
		"GIT_COMMITTER_NAME=" + commit.name, "GIT_COMMITTER_EMAIL=" + commit.email, "GIT_COMMITTER_DATE=" + date,
	}
	commitArgs := []string{"commit-tree", tree.String()}
	if commit.tip != nil {
		commitArgs = append(commitArgs, "-p", commit.tip.String())
	}
	commitArgs = append(commitArgs, "-F", "-")
	out, err = run([]byte(message), ident, commitArgs...)
	if err != nil {
		return EvsGitOid{}, err
	}
	return oidOf(out)
}
