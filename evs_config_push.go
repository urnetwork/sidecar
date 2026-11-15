//go:build !ios_extension

// The config kind's prepare and commit (QD-824; plan-TEAM-api-config-head-reach #4; §7.9's bootstrap row): the
// network's first config head, the one push that creates its config repo's main ref, sealed and signed before base 1
// and sent once the repo is active. Base 1 names that push's chain value C_1 and carries the push for api's walk from
// C_0, so the push exists before anything of the network does at evs or gkm:
//
//	key      the generation KF1's bootstrap draft drew (GkmGroupClient.DraftGroup): the push's generation pin is
//	         {group_id, 1, C_1}, its records and names under RK_1's keys, though gen/1's statement is signed only after
//	         base 1, at S(1); C_1 holds no pin, so gen/1 names the same commitment
//	auth     the genesis state's pin {0, A_0}, which evs takes on a config repo's first push alone: a pin of A_1 would
//	         be circular, since A_1 hashes the base that names C_1
//	plan     on a ref with no head, read from nowhere: version 0 at C_0, every path and each parent directory a
//	         creation, the root's table among them (evs_directory.go), in path epoch 1, the epoch a ref starts in at
//	         generation 1 (firstEpoch). Pressure needs a REMOVE generation above the head's, and generation 1 is the
//	         repo's only one; the genesis state holds no statement, so no prefix rule set; the config repo carries no
//	         index, so M10's plan hook is not asked
//	inline   every record rides inline in its entry version and the push goes in one part: a segment's upload day is
//	         its receipt's, and no segment uploads before the repo exists, so a head that does not fit is refused
//	signed   by this device's identity key, which must be the Genesis's owner sidecar, the one config writer the
//	         genesis state holds
//
// Nothing here sends anything, reads the network's state or asks GkmClient: the key and the state come in. Commit
// posts the push as prepared, the same bytes on every retry, so a lost answer's retry returns the version evs
// committed (FS-1).
//
// A later head's prepare, a config writer's ref over evs (TEAM-M2-09's EvsClient for the config kind), is not built
// here: PrepareConfigHead refuses every head but the first.

package sidecar

import (
	"bytes"
	"context"
	"fmt"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
)

// The config kind's prepare of the first head: see the file header. head's files become the paths of the config
// repo's main ref at version 1, the Genesis's own file among them. genesis is the genesis state, S(0), of the network
// whose config repo it names; key is generation 1 of that repo as KF1's bootstrap draft holds it. Answers the push,
// its version 1 and C_1, with the payload CommitConfigHead posts.
func (self *EvsClient) PrepareConfigHead(ctx context.Context, key *EvsRepoKey, genesis *ConfigState, head *ConfigHead) (*ConfigHeadPush, error) {
	if key == nil || genesis == nil || head == nil {
		return nil, fmt.Errorf("%w: a first config head needs its key, its genesis state and its files", ErrEvsWriteInvalid)
	}
	if err := key.checkHeld(); err != nil {
		return nil, err
	}
	repoId := key.RepoId()
	switch {
	case genesis.Pin().GetVersion() != 0:
		return nil, fmt.Errorf("%w: a first config head is signed at the genesis state, not at position %d", ErrEvsWriteInvalid, genesis.Pin().GetVersion())
	case !bytes.Equal(genesis.Genesis().GetConfigRepoId(), repoId.Bytes()):
		return nil, fmt.Errorf("%w: a key of a repo the Genesis does not name as its config repo", ErrEvsWriteInvalid)
	case key.Generation() != 1:
		return nil, fmt.Errorf("%w: the first config head seals to generation 1, not %d", ErrEvsWriteInvalid, key.Generation())
	}
	if repo := genesis.Repo(repoId); repo == nil || repo.GetKind() != protocol.RepoKind_REPO_KIND_CONFIG {
		return nil, fmt.Errorf("%w: the genesis state holds no config repo %s", ErrEvsNoConfig, repoId)
	}
	identity := self.args.Identity()
	if identity == nil || !bytes.Equal(genesis.Genesis().GetOwnerSidecarId(), identity.SidecarId.Bytes()) {
		return nil, fmt.Errorf("%w: only the Genesis's owner sidecar writes the first config head", ErrEvsWriteInvalid)
	}

	repo := self.Repo(repoId)
	refKey, err := NewEvsRefKey(key)
	if err != nil {
		return nil, err
	}
	refId, err := EvsRefId(refKey, EvsMainRefName)
	if err != nil {
		return nil, err
	}
	keys := newEvsReadKeys(repo)
	keys.generations[1] = key
	plan := &EvsWritePlan{
		RepoId: repoId, RefId: refId, BaseVersion: 0, BaseChain: EvsChainStart(repoId, refId),
		Head: &protocol.EvsHeadSummary{}, PathEpoch: evsCurrentEpoch(nil), Generation: 1, keys: keys,
		floors: map[string]uint64{}, refName: EvsMainRefName, repoKind: protocol.RepoKind_REPO_KIND_CONFIG,
		firstPush: true,
	}
	if err := plan.setRef(plan.Head, EvsMainRefName, identity.SidecarId, false); err != nil {
		return nil, err
	}
	if plan.pathKey, err = keys.path(ctx, plan.PathEpoch); err != nil {
		return nil, err
	}
	if plan.nameKey, err = keys.manifest(ctx, plan.PathEpoch); err != nil {
		return nil, err
	}

	// every file a creation, read as a ref with no head reads it: absent, its token path in the head's epoch
	files := head.Files()
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	readPathOf := func(path string) (*evsReadPath, error) {
		names, err := evsReadPathNames(path)
		if err != nil {
			return nil, err
		}
		current, err := plan.tokenPathIn(ctx, names, plan.PathEpoch)
		if err != nil {
			return nil, err
		}
		return &evsReadPath{path: path, names: names, current: current}, nil
	}
	planned := map[string]*EvsPlannedPath{}
	for _, path := range paths {
		readPath, err := readPathOf(path)
		if err != nil {
			return nil, err
		}
		if len(readPath.names) == 0 {
			return nil, fmt.Errorf("%w: a config file at the root's own path", ErrEvsWriteInvalid)
		}
		write := &EvsPathWrite{Path: path, Content: bytes.NewReader(files[path])}
		change, err := repo.planPath(ctx, plan, nil, readPath, &EvsVerifiedPath{Absent: true}, write)
		if err != nil {
			return nil, err
		}
		planned[path] = change
		plan.Paths = append(plan.Paths, change)
	}
	directories := map[string]*evsDirectoryRead{}
	for _, directory := range append([]string{""}, evsParentDirectories(paths)...) {
		readPath, err := readPathOf(directory)
		if err != nil {
			return nil, err
		}
		directories[directory] = evsDirectoryReadOf(readPath, &EvsVerifiedPath{Absent: true})
	}
	directoryPaths, err := evsDirectoryChanges(ctx, plan, planned, directories)
	if err != nil {
		return nil, err
	}
	plan.Paths = append(plan.Paths, directoryPaths...)
	epoch, err := repo.firstEpoch(ctx, plan.RefKind, nil, plan.Generation)
	if err != nil {
		return nil, err
	}
	if err := plan.tokenizeIn(ctx, epoch); err != nil {
		return nil, err
	}
	for _, change := range plan.Paths {
		if change.Kind == protocol.EvsEntryKind_EVS_ENTRY_FILE && !change.Inline {
			return nil, fmt.Errorf("%w: %d bytes at one config path, past what rides inline before the repo exists", ErrEvsWriteInvalid, change.Fields.GetSize())
		}
	}

	sealed, err := self.sealWrite(ctx, plan, key)
	if err != nil {
		return nil, err
	}
	defer sealed.Close()
	if 0 < len(sealed.Segments) || 0 < len(sealed.Slots) {
		return nil, fmt.Errorf("%w: a first config head with a segment or slot to upload before its repo exists", ErrEvsWriteInvalid)
	}
	manifest, err := NewEvsManifestKey(key)
	if err != nil {
		return nil, err
	}
	metadata := &protocol.EvsSealedMetadata{Provenance: &protocol.EvsProvenance{}}
	if self.args.GroupHead != nil {
		if groupHead, ok := self.args.GroupHead(key.GroupId()); ok {
			metadata.Group = groupHead
		}
	}
	pushId := NewEvsPushId()
	timeMs := self.clock.Now().UnixMilli()
	pushPlan := &EvsPushPlan{
		RepoId: repoId, RefId: refId, RefKind: plan.RefKind, RefMode: plan.RefMode, PushId: pushId,
		BaseVersion: plan.BaseVersion, BaseChain: plan.BaseChain, Generation: key.Generation(), GroupId: key.GroupId(),
		GenerationCommitment: key.Commitment(), PathEpoch: plan.PathEpoch, Auth: genesis.Pin(),
		SignerSidecarId: identity.SidecarId, ClientId: identity.ClientId, TimeMs: timeMs,
	}
	if pushPlan.SealedMetadata, err = EvsSealMetadata(manifest, metadata); err != nil {
		return nil, err
	}
	for _, path := range sealed.Paths {
		change, err := path.change(pushId, plan.BaseVersion, timeMs)
		if err != nil {
			return nil, err
		}
		pushPlan.Changes = append(pushPlan.Changes, change)
	}
	built, err := NewEvsStatementBuilder(self.args.Sign).Build(pushPlan)
	if err != nil {
		return nil, err
	}
	if 0 < len(built.Parts) {
		return nil, fmt.Errorf("%w: a first config head past one part, which no seal lease takes before its repo exists", ErrEvsWriteInvalid)
	}
	chain := EvsChainNext(plan.BaseChain, pushId, EvsStatementSha256(built.Statement.Bytes))
	return &ConfigHeadPush{Head: head, Version: 1, Chain: chain, SignedPush: built.Statement.Bytes, Payload: built.Payload}, nil
}

// The config kind's commit: posts a push PrepareConfigHead made, once its repo is active, the same bytes until evs
// answers. evs committing it at its version is success, a retry of a push evs already committed among them;
// ErrConfigHeadConflict where the ref moved first; any other refusal as evs gave it.
func (self *EvsClient) CommitConfigHead(ctx context.Context, push *ConfigHeadPush) error {
	if push == nil || len(push.SignedPush) == 0 || push.Payload == nil {
		return fmt.Errorf("%w: a config head push this client did not prepare", ErrEvsWriteInvalid)
	}
	statement, err := ParseEvsStatement(push.SignedPush)
	if err != nil {
		return err
	}
	repoId, err := IdFromBytes(statement.Push.GetRepoId())
	if err != nil {
		return fmt.Errorf("%w: the push's repo", ErrEvsPushInvalid)
	}
	refId, err := IdFromBytes(statement.Push.GetRefId())
	if err != nil {
		return fmt.Errorf("%w: the push's ref", ErrEvsPushInvalid)
	}
	pushId, err := IdFromBytes(statement.Push.GetPushId())
	if err != nil {
		return fmt.Errorf("%w: the push's id", ErrEvsPushInvalid)
	}
	if statement.Push.GetBaseVersion()+1 != push.Version {
		return fmt.Errorf("%w: a push on version %d named as version %d", ErrEvsPushInvalid, statement.Push.GetBaseVersion(), push.Version)
	}
	request := &protocol.EvsPushRequest{Statement: push.SignedPush, Payload: push.Payload}
	reply, err := self.Repo(repoId).postPushAs(ctx, pushId, request, evsScopeWrite)
	switch {
	case err == nil && reply.GetVersion() == push.Version:
		self.epochs.noteCommitted(repoId, refId, reply.GetVersion())
		return nil
	case err == nil:
		return fmt.Errorf("%w: committed at %d, not %d", ErrConfigHeadConflict, reply.GetVersion(), push.Version)
	case IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE), evsCreationConflict(err):
		return fmt.Errorf("%w: %w", ErrConfigHeadConflict, err)
	}
	return err
}
