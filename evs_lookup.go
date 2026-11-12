//go:build !ios_extension

// §16.6's evs effects (D-MCP-11, AU1-AU4; §11.20; EVS1-M3-01): an O-tier evs_write or evs_delete of an agent-config
// file, and any other outward action whose effect is a write on evs (mail_alias_delete's mailcfg record removal), is
// idempotent through the path's own versions rather than a key evs keeps, since §11.20's per-path version, signer and
// git oid answer Lookup:
//
//	lookup   the path's first version after the action's base_version, read fresh and walked back from its newest:
//	         versions only rise (a write is v + 1, a removal the version past the one it removes, a creation
//	         max(its push's base, a standing removal's) + 1, I-EVS-8), so it is the smallest the walk sees above
//	         base_version. base_version is the path's newest version as the action read it, a standing file's or a
//	         removal's, 0 for a path evs showed nothing of. Found when this sidecar signed that version and it is the
//	         action's (its content, or for a delete a removal); other when anything else holds it, so the action's
//	         push, which evs holds to base_version (5g), can never commit; none while the path's newest is still
//	         base_version. The walk stops at a creation, whose removed past History does not read, so a path removed
//	         and made again more than once since base_version reads as its newest life
//	effect   EvsWriteEffect pushes only while Lookup finds none, and looks again after any refusal: found is done,
//	         other is not_done, and none after a refusal that refused every attempt for good (an evs refusal that is
//	         not a 429 or a 503, or a refusal before anything was sent) is not_done too; anything that leaves an
//	         attempt's outcome open leaves the use uncertain, and a retry of the action completes it
//	modes    a file-mode ref through WritePaths with base_version as its CAS (EvsPathWrite.IfBaseVersion); a git-mode
//	         ref, which Write answers EVS_GIT_REF, through the local tier's WriteAtTip (evs_local_write.go), a client
//	         with no local tier answering EVS_GIT_REF
//	restart  NewEvsEffectLookup reads only the stored CanonicalAction (repo_id, path, content_sha256, base_version), so
//	         a restart reconciles a reserved use with no caller alive; none is uncertain there, since an attempt the
//	         last run sent may still commit
//
// §16.6 says "with content_sha256", which format 1 seals only for versionless files (format 2's): a format-1 version's
// sealed fields hold its git oid. So a live effect, which holds the content, compares the version's oid with the
// content's, and a restart's Lookup, which holds only the stored action, reads the version and compares SHA-256 of its
// bytes. The action names no ref: §16.2's tools write main, and an effect may name another.
//
// On every leg but the ios_extension legs. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A Lookup that names no path, both or neither of a write's content hashes, or content for a removal, or a stored
	// action that is not an evs effect's.
	ErrEvsLookupInvalid = errors.New("evs: lookup invalid")
	// Lookup cannot tell whose the path's first version after base_version is: its removal's marker is gone, or the
	// walk passed LookupVersionCount. The use it reconciles stays uncertain.
	ErrEvsLookupUnknown = errors.New("evs: the first version after base_version cannot be read")
	// A git-mode write the local tier refused for good: the tip moved on each of WriteAtTipTryCount tries, or the
	// receive path refused the update with no attempt of it left open.
	ErrEvsGitWriteRefused = errors.New("evs: the local tier refused the git-mode write")
	// A git-mode write whose push may yet commit: the receive path answered `remote outcome pending`, which the
	// history resolves.
	ErrEvsGitOutcomePending = errors.New("evs: the git-mode write's outcome is pending")
)

// What Lookup looks for: one write or removal of a path made on base_version.
type EvsLookupArgs struct {
	// The ref's name bytes, nil for main.
	RefName []byte
	Path    string
	// The path version the action was made on, §16.2's base_version: 0 for a path read as absent.
	BaseVersion uint64
	// A removal (evs_delete); else a write, whose content one of the two hashes names: its git blob oid, which needs
	// no read, or SHA-256 of its bytes, the stored action's content_sha256, which reads the version.
	Remove        bool
	GitOid        *EvsGitOid
	ContentSha256 []byte
}

// What Lookup found.
type EvsLookupState int

const (
	// The path stands at base_version still: nothing after it.
	EvsLookupNone EvsLookupState = iota + 1
	// The first version after base_version is this sidecar's, with the action's content or its removal.
	EvsLookupFound
	// The first version after base_version is not the action's, or the path stands where base_version never was:
	// the action's push can never commit.
	EvsLookupOther
)

// What Lookup found, and the version it found it at.
type EvsLookupResult struct {
	State EvsLookupState
	// The first version after base_version, for found and other.
	Version *EvsHistoryVersion
	// The ref's head the walk read.
	HeadVersion uint64
}

// The effect's reference a found version gives: its push id and the path's version.
func (self *EvsLookupResult) EffectRef() []byte {
	if self.State != EvsLookupFound || self.Version == nil {
		return nil
	}
	return EvsEffectRef(self.Version.PushId, self.Version.Version)
}

// An evs effect's reference, opaque to the gate: the push id, then the path version, big-endian.
func EvsEffectRef(pushId Id, pathVersion uint64) []byte {
	effectRef := make([]byte, 0, len(pushId)+8)
	effectRef = append(effectRef, pushId[:]...)
	return binary.BigEndian.AppendUint64(effectRef, pathVersion)
}

// The push id and path version of an EvsEffectRef.
func ParseEvsEffectRef(effectRef []byte) (Id, uint64, error) {
	if len(effectRef) != len(Id{})+8 {
		return Id{}, 0, fmt.Errorf("%w: an effect reference of %d bytes", ErrEvsLookupInvalid, len(effectRef))
	}
	pushId, err := IdFromBytes(effectRef[:len(Id{})])
	if err != nil {
		return Id{}, 0, err
	}
	return pushId, binary.BigEndian.Uint64(effectRef[len(Id{}):]), nil
}

// Finds the path's first version after args.BaseVersion and whether it is the effect args names: see the file header.
func (self *EvsRepo) Lookup(ctx context.Context, args *EvsLookupArgs) (*EvsLookupResult, error) {
	switch {
	case args == nil || args.Path == "":
		return nil, fmt.Errorf("%w: no path", ErrEvsLookupInvalid)
	case args.Remove && (args.GitOid != nil || args.ContentSha256 != nil):
		return nil, fmt.Errorf("%w: content for a removal", ErrEvsLookupInvalid)
	case !args.Remove && (args.GitOid == nil) == (args.ContentSha256 == nil):
		return nil, fmt.Errorf("%w: a write names its content by one hash", ErrEvsLookupInvalid)
	case args.ContentSha256 != nil && len(args.ContentSha256) != sha256.Size:
		return nil, fmt.Errorf("%w: a content hash of %d bytes", ErrEvsLookupInvalid, len(args.ContentSha256))
	}
	refName := args.RefName
	if refName == nil {
		refName = EvsMainRefName
	}
	refId, err := self.resolveRefId(ctx, refName, nil)
	if err != nil {
		return nil, err
	}
	result := &EvsLookupResult{}
	// the walk from the newest version down: versions only rise (I-EVS-8), so the smallest it sees above
	// base_version is the first after it; it stops at or below base_version, or where History reads no further, a
	// creation, whose removed past it does not walk
	var first *EvsHistoryVersion
	version := uint64(0)
	walked := 0
	newest := uint64(0)
	for {
		history, err := self.History(ctx, &EvsReadArgs{RefName: refName, Path: args.Path, Version: version, Fresh: version == 0})
		if errors.Is(err, ErrEvsPathAbsent) {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(history.Versions) == 0 {
			break
		}
		if result.HeadVersion == 0 {
			result.HeadVersion = history.HeadVersion
		}
		if newest == 0 {
			newest = history.Versions[0].Version
		}
		reached := false
		for _, read := range history.Versions {
			if read.Version <= args.BaseVersion {
				reached = true
				break
			}
			first = read
		}
		walked += len(history.Versions)
		last := history.Versions[len(history.Versions)-1]
		// History stops short of its count only at a creation or at version 1
		if reached || len(history.Versions) < self.client.settings.HistoryVersionCount || last.Version <= 1 {
			break
		}
		if self.client.settings.LookupVersionCount <= walked {
			return nil, fmt.Errorf("%w: past %d versions", ErrEvsLookupUnknown, walked)
		}
		version = last.Version - 1
	}
	switch {
	case newest == 0 && args.BaseVersion == 0:
		// evs shows nothing of the path: nothing after a base of none
		result.State = EvsLookupNone
		return result, nil
	case newest == 0:
		// a path that stood at base_version reads absent with no removal: whose its removal was is gone
		return nil, fmt.Errorf("%w: the path's removal is no longer shown", ErrEvsLookupUnknown)
	case first == nil && newest == args.BaseVersion:
		result.State = EvsLookupNone
		return result, nil
	case first == nil:
		// versions never go back (I-EVS-8): the action names a version past the path's newest, which it never stood at
		result.State = EvsLookupOther
		return result, nil
	}
	result.Version = first
	result.State = EvsLookupOther
	if first.SignerSidecarId != self.client.args.Identity().SidecarId || first.Removed != args.Remove {
		return result, nil
	}
	if !args.Remove {
		matches, err := self.versionMatches(ctx, refId, args, first)
		if err != nil {
			return nil, err
		}
		if !matches {
			return result, nil
		}
	}
	result.State = EvsLookupFound
	return result, nil
}

// Whether a file version holds the content args names: its oid from its sealed fields, or SHA-256 of its bytes, both
// read in one reconstruction of the version.
func (self *EvsRepo) versionMatches(ctx context.Context, refId Id, args *EvsLookupArgs, version *EvsHistoryVersion) (bool, error) {
	path := &evsReadPath{path: args.Path, version: version.Version, commitVersion: version.CommitVersion}
	result, err := self.readPaths(ctx, refId, []*evsReadPath{path}, false)
	if err != nil {
		return false, err
	}
	defer result.objects.close()
	verified := result.replies[0]
	if verified.Entry == nil || verified.Entry.GetVersion() != version.Version {
		return false, fmt.Errorf("%w: version %d did not read back", ErrEvsLookupUnknown, version.Version)
	}
	if verified.Entry.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE) {
		return false, nil
	}
	var digest hash.Hash
	out := io.Discard
	if args.ContentSha256 != nil {
		digest = sha256.New()
		out = digest
	}
	info, err := self.reconstruct(ctx, result, verified, out)
	if err != nil {
		return false, err
	}
	if args.GitOid != nil {
		return info.GitOid == *args.GitOid, nil
	}
	return bytes.Equal(digest.Sum(nil), args.ContentSha256), nil
}

// What WriteAtTip commits (§16.2's git-mode evs_write and evs_delete; evs_local_write.go).
type EvsWriteAtTipArgs struct {
	// The ref's name bytes, nil for main: a shared branch.
	RefName []byte
	Path    string
	// The path version the write was made on: each try commits only while the path's newest version is still it,
	// 0 for a path that does not stand.
	BaseVersion uint64
	// The new content, nil with Remove; git's mode, 0 keeping the path's, or a regular file's for a new one.
	Content []byte
	Mode    uint32
	Remove  bool
	// The commit's message, and the agent label its committer name carries, the mount's when empty.
	Message    string
	AgentLabel string
}

// What a committed WriteAtTip did, as Lookup found it after the receive path's ok.
type EvsWriteAtTipResult struct {
	PushId Id
	// The ref version its push committed at, and the path's new version.
	Version     uint64
	PathVersion uint64
	// The commit it made.
	Commit EvsGitOid
}

// §16.2's O-tier evs_write or evs_delete as §16.6's effect: see the file header. A Run's content is held whole, as an
// agent-config file's is.
type EvsWriteEffect struct {
	Repo *EvsRepo
	// The ref's name bytes, nil for main.
	RefName     []byte
	Path        string
	BaseVersion uint64
	// The new content, nil with Remove; git's mode, 0 keeping the path's.
	Content []byte
	Mode    uint32
	Remove  bool
	// A git-mode ref's commit: its message, and the agent label its committer name carries (owner decision 81).
	Message    string
	AgentLabel string
}

// What Lookup asks of the effect: its content by git oid, which the live effect can compute.
func (self *EvsWriteEffect) lookupArgs() (*EvsLookupArgs, error) {
	args := &EvsLookupArgs{RefName: self.RefName, Path: self.Path, BaseVersion: self.BaseVersion, Remove: self.Remove}
	if self.Remove {
		if self.Content != nil {
			return nil, fmt.Errorf("%w: content for a removal", ErrEvsLookupInvalid)
		}
		return args, nil
	}
	if self.Content == nil {
		return nil, fmt.Errorf("%w: a write with no content", ErrEvsLookupInvalid)
	}
	oid, err := EvsGitBlobOid(bytes.NewReader(self.Content), int64(len(self.Content)))
	if err != nil {
		return nil, err
	}
	args.GitOid = &oid
	return args, nil
}

// Runs the write under §16.6's rule: see the file header. effectKey is not kept anywhere, since the path's versions
// are the effect's own record.
func (self *EvsWriteEffect) Run(ctx context.Context, effectKey []byte) ([]byte, error) {
	if self.Repo == nil {
		return nil, fmt.Errorf("%w: %w: no repo", ErrSidecarEffectNotDone, ErrEvsLookupInvalid)
	}
	args, err := self.lookupArgs()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, err)
	}
	found, err := self.Repo.Lookup(ctx, args)
	if err != nil {
		return nil, err
	}
	switch found.State {
	case EvsLookupFound:
		return found.EffectRef(), nil
	case EvsLookupOther:
		return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, ErrEvsPathMoved)
	}
	effectRef, writeErr := self.write(ctx)
	if writeErr == nil && effectRef != nil {
		return effectRef, nil
	}
	// after a refusal, or a git-mode commit whose version the local tier did not name: look again
	found, err = self.Repo.Lookup(ctx, args)
	if err != nil {
		if writeErr != nil {
			return nil, writeErr
		}
		return nil, err
	}
	switch found.State {
	case EvsLookupFound:
		return found.EffectRef(), nil
	case EvsLookupOther:
		return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, errors.Join(ErrEvsPathMoved, writeErr))
	}
	if writeErr == nil {
		return nil, fmt.Errorf("%w: a commit the path's versions do not show", ErrEvsLookupUnknown)
	}
	if evsWriteRefusedForGood(writeErr) {
		return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, writeErr)
	}
	return nil, writeErr
}

// One write: WritePaths on a file-mode ref, WriteAtTip on a git-mode one. A nil reference with no error is a git-mode
// commit whose version Lookup then finds.
func (self *EvsWriteEffect) write(ctx context.Context) ([]byte, error) {
	base := self.BaseVersion
	write := &EvsPathWrite{Path: self.Path, Mode: self.Mode, Remove: self.Remove, IfBaseVersion: &base}
	if !self.Remove {
		write.Content = bytes.NewReader(self.Content)
	}
	result, err := self.Repo.WritePaths(ctx, &EvsWritePathsArgs{RefName: self.RefName, Writes: []*EvsPathWrite{write}})
	if err == nil {
		return EvsEffectRef(result.PushId, result.PathVersions[0]), nil
	}
	if !errors.Is(err, ErrEvsGitRef) {
		return nil, err
	}
	written, err := self.Repo.WriteAtTip(ctx, &EvsWriteAtTipArgs{
		RefName: self.RefName, Path: self.Path, BaseVersion: self.BaseVersion, Content: self.Content, Mode: self.Mode,
		Remove: self.Remove, Message: self.Message, AgentLabel: self.AgentLabel,
	})
	if err != nil {
		return nil, err
	}
	return EvsEffectRef(written.PushId, written.PathVersion), nil
}

// Whether a write's error refused every attempt it made for good, so none can still commit: a refusal before
// anything was sent, or evs's answer to the last attempt that was neither a 429, a 503 nor of unknown outcome (each
// earlier attempt was refused too, since a write builds a new push only on a refusal). Anything else, a lost answer or
// a canceled call among them, leaves an attempt open.
func evsWriteRefusedForGood(err error) bool {
	if evsError, ok := EvsErrorOf(err); ok {
		return !evsError.OutcomeUnknown && !evsError.RefusesNothing()
	}
	for _, refused := range []error{
		ErrEvsWriteInvalid, ErrEvsPathMoved, ErrEvsPathAbsent, ErrEvsPathKind, ErrEvsGitRef, ErrEvsWriteNotBuilt,
		ErrEvsFormatUnsupported, ErrEvsPathEpochDue, ErrEvsGitWriteRefused,
	} {
		if errors.Is(err, refused) {
			return true
		}
	}
	return false
}

// The kinds whose effect is an evs write the gate reconciles through Lookup: §16.5's agent-config writes and deletes.
var evsEffectKinds = []SidecarActionKind{SidecarActionAgentConfigWrite, SidecarActionAgentConfigDelete}

// The Lookup the gate reconciles an evs kind's reserved use by at restart (§16.6's restart row): the stored
// CanonicalAction's repo_id, path, content_sha256 and base_version, on main. done with the effect's reference,
// not_done when another version holds the path, uncertain while the path stands at base_version.
func NewEvsEffectLookup(client *EvsClient) SidecarEffectLookup {
	return func(ctx context.Context, canonical []byte, effectKey []byte) (*SidecarOutcome, error) {
		action := &protocol.CanonicalAction{}
		if err := proto.Unmarshal(canonical, action); err != nil {
			return nil, fmt.Errorf("%w: a stored action that does not parse", ErrEvsLookupInvalid)
		}
		repoId, args, err := evsLookupArgsOfAction(action)
		if err != nil {
			return nil, err
		}
		found, err := client.Repo(repoId).Lookup(ctx, args)
		if err != nil {
			return nil, err
		}
		switch found.State {
		case EvsLookupFound:
			return &SidecarOutcome{State: ApprovalOutcomeDone, EffectRef: found.EffectRef()}, nil
		case EvsLookupOther:
			return &SidecarOutcome{State: ApprovalOutcomeNotDone}, nil
		}
		return &SidecarOutcome{State: ApprovalOutcomeUncertain}, nil
	}
}

// What Lookup asks of a stored agent-config action.
func evsLookupArgsOfAction(action *protocol.CanonicalAction) (Id, *EvsLookupArgs, error) {
	kind := SidecarActionKind(action.GetKind())
	if kind != SidecarActionAgentConfigWrite && kind != SidecarActionAgentConfigDelete {
		return Id{}, nil, fmt.Errorf("%w: an action of kind %d", ErrEvsLookupInvalid, kind)
	}
	repoId, err := IdFromBytes(action.GetRepoId())
	if err != nil {
		return Id{}, nil, fmt.Errorf("%w: the action's repo", ErrEvsLookupInvalid)
	}
	args := &EvsLookupArgs{Path: action.GetPath(), BaseVersion: action.GetBaseVersion()}
	if kind == SidecarActionAgentConfigDelete {
		args.Remove = true
		return repoId, args, nil
	}
	args.ContentSha256 = action.GetContentSha256()
	return repoId, args, nil
}

// Registers NewEvsEffectLookup over client for the agent-config kinds on running's gate; the answer removes them, after
// which those kinds are refused before their Reserve again.
func RegisterEvsEffectLookups(running *Sidecar, client *EvsClient) func() {
	lookup := NewEvsEffectLookup(client)
	unregisters := []func(){}
	for _, kind := range evsEffectKinds {
		unregisters = append(unregisters, running.RegisterEffectLookup(kind, lookup))
	}
	return func() {
		for _, unregister := range unregisters {
			unregister()
		}
	}
}
