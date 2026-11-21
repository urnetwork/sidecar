//go:build !ios_extension

package sidecar

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var _ ConfigHeadRef = (*EvsConfigHeadReader)(nil)

// Builds the exact signed push on version. Only its encrypted objects may be staged until CommitConfigHead.
func (self *EvsConfigHeadReader) PrepareConfigHead(ctx context.Context, head *ConfigHead, version uint64) (*ConfigHeadPush, error) {
	tip, err := self.CurrentConfigHeadTip(ctx)
	if err != nil {
		return nil, err
	}
	if !tip.SupportsExactHead {
		return nil, fmt.Errorf("%w: EVS does not advertise signed exact-head commits", ErrConfigWriterNotWriter)
	}
	if tip.Head == nil || head == nil || tip.Version != version {
		return nil, ErrConfigHeadConflict
	}
	writes := evsConfigHeadWrites(tip.Head, head)
	if len(writes) == 0 {
		return nil, ErrConfigWriterNothing
	}
	repo := self.repo
	state, ok := repo.client.args.Config().(*ConfigState)
	if !ok || state == nil || state.Base() == nil {
		return nil, ErrConfigHeadUnavailable
	}
	// A pending head can be adopted only when its signed pushes descend exactly from
	// the last base. Discover an incompatible older file-mode landing before writing.
	base := state.Base().GetConfigVersion()
	if version < base || version-base >= ConfigPushesMaxCount {
		return nil, fmt.Errorf("%w: the next push would fall outside the window of a signed base", ErrConfigHeadConflict)
	}
	if base != version {
		if _, err := self.ConfigHeadPushes(ctx, base, version); err != nil {
			return nil, err
		}
	}
	key, err := repo.client.args.Gkm.EnsureWritable(ctx, repo.repoId)
	if err != nil {
		return nil, err
	}
	refId, err := repo.resolveRefId(ctx, EvsMainRefName, nil)
	if err != nil {
		return nil, err
	}
	exact := uint32(protocol.EvsPushFlag_EVS_PUSH_EXACT_HEAD)
	plan, err := repo.PlanWrite(ctx, &EvsPlanArgs{RefName: EvsMainRefName, RefId: refId, Writes: writes, Generation: key.Generation(), Fresh: true, Flags: exact})
	if err != nil {
		return nil, err
	}
	if plan.repoKind != protocol.RepoKind_REPO_KIND_CONFIG || plan.RefMode != protocol.EvsRefMode_EVS_REF_FILE || plan.BaseVersion != version || plan.BaseChain != tip.Chain {
		return nil, ErrConfigHeadConflict
	}
	plan.Flags = exact
	sealed, err := repo.client.sealWrite(ctx, plan, key)
	if err != nil {
		return nil, err
	}
	defer sealed.Close()
	if err := repo.checkSlotBodies(sealed, writes, nil); err != nil {
		return nil, err
	}
	pushId := NewEvsPushId()
	if err := repo.client.bindPush(sealed, pushId); err != nil {
		return nil, err
	}
	if err := repo.uploadSegments(ctx, sealed, pushId); err != nil {
		return nil, err
	}
	attempt, err := repo.buildPush(ctx, sealed, pushId)
	if err != nil {
		return nil, err
	}
	statement := attempt.built.Statement.Bytes
	return &ConfigHeadPush{
		Head: head, Version: version + 1, Chain: EvsChainNext(tip.Chain, pushId, EvsStatementSha256(statement)),
		SignedPush: bytes.Clone(statement), deliver: func(ctx context.Context, networkId Id, repoId Id) error {
			if networkId != repo.client.NetworkId() || repoId != repo.repoId {
				return ErrConfigHeadConflict
			}
			reply, err := repo.sendPush(ctx, attempt)
			switch {
			case IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE), evsCreationConflict(err):
				return fmt.Errorf("%w: %w", ErrConfigHeadConflict, err)
			case err != nil:
				return err
			case reply.GetVersion() != version+1:
				return ErrConfigHeadConflict
			}
			repo.client.epochs.noteCommitted(repoId, refId, reply.GetVersion())
			return nil
		},
	}, nil
}

// A config head changes the paths whose contents differ, including creation and deletion of empty files.
func evsConfigHeadWrites(previous *ConfigHead, next *ConfigHead) []*EvsPathWrite {
	before, after := previous.files, next.files
	changed := map[string]bool{}
	for path, data := range after {
		if old, exists := before[path]; !exists || !bytes.Equal(old, data) {
			changed[path] = true
		}
	}
	for path := range before {
		if _, exists := after[path]; !exists {
			changed[path] = true
		}
	}
	writes := make([]*EvsPathWrite, 0, len(changed))
	for _, path := range slices.Sorted(maps.Keys(changed)) {
		data, kept := after[path]
		write := &EvsPathWrite{Path: path, Remove: !kept}
		if kept {
			write.Content = bytes.NewReader(data)
		}
		writes = append(writes, write)
	}
	return writes
}

func (self *EvsConfigHeadReader) CommitConfigHead(ctx context.Context, push *ConfigHeadPush) error {
	if push == nil || push.deliver == nil {
		return ErrConfigHeadConflict
	}
	return push.deliver(ctx, self.repo.client.NetworkId(), self.repo.repoId)
}

// The config pushes since the verified base. Each signature and chain link is checked against the newest
// ref head, which also catches a short or divergent answer when another writer committed in the meantime.
func (self *EvsConfigHeadReader) ConfigHeadPushes(ctx context.Context, after uint64, through uint64) ([][]byte, error) {
	state, ok := self.repo.client.args.Config().(*ConfigState)
	if !ok || state == nil || state.Base() == nil || state.Base().GetConfigVersion() != after || through < after {
		return nil, ErrConfigHeadConflict
	}
	if after == through {
		return nil, nil
	}
	if through-after > ConfigPushesMaxCount {
		return nil, fmt.Errorf("%w: more pending pushes than a signed base can carry", ErrConfigHeadConflict)
	}
	chain, err := EvsChainFromBytes(state.Base().GetConfigHeadSha256())
	if err != nil {
		return nil, err
	}
	refId, err := self.repo.resolveRefId(ctx, EvsMainRefName, nil)
	if err != nil {
		return nil, err
	}
	tip, err := self.CurrentConfigHeadTip(ctx)
	if err != nil {
		return nil, err
	}
	if !tip.SupportsExactHead {
		return nil, fmt.Errorf("%w: EVS does not advertise signed exact-head commits", ErrConfigWriterNotWriter)
	}
	if tip.Version < through {
		return nil, ErrConfigHeadConflict
	}
	walked, err := self.repo.client.verifier.Walk(ctx, self.repo.repoId, refId, after, chain, through)
	if err != nil {
		return nil, err
	}
	if uint64(len(walked)) != through-after {
		return nil, ErrConfigHeadConflict
	}
	last := walked[len(walked)-1]
	// Anchor this prefix to the fresh head, even when later pushes were committed by
	// the time the receipt was retried. Only the requested prefix goes into the base.
	at := last
	for at.Version < tip.Version {
		end := at.Version + min(tip.Version-at.Version, uint64(self.settings.PushReadCount))
		tail, err := self.repo.client.verifier.Walk(ctx, self.repo.repoId, refId, at.Version, at.Chain, end)
		if err != nil {
			return nil, err
		}
		if uint64(len(tail)) != end-at.Version {
			return nil, ErrConfigHeadConflict
		}
		at = tail[len(tail)-1]
	}
	if at.Chain != tip.Chain {
		return nil, ErrConfigHeadConflict
	}
	pushes := make([][]byte, 0, len(walked))
	for _, link := range walked {
		pushes = append(pushes, link.Statement.Bytes)
	}
	target := &bridge.ProjectionHeader{ConfigVersion: through, ConfigHeadSha256: last.Chain[:]}
	if err := CheckConfigPushes(self.repo.repoId, state.Base(), target, pushes); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigHeadConflict, err)
	}
	return pushes, nil
}
