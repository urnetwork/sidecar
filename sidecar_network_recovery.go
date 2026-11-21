//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"context"
	"fmt"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Installs recovery on the network's real group client and EVS transport. The code-derived config key stays in
// memory while verifying the recovery anchor. Only a successful anchor publishes it to the shared keychain.
func (self *Sidecar) InstallNetworkRecovery(group *GkmGroupClient) func() {
	recovery := &networkRecovery{running: self, GkmGroupClient: group}
	removeKeys := self.InstallConfigKeys(recovery)
	removeRecovery := self.InstallRecovery(&SidecarRecoveryArgs{Groups: recovery, Heads: recovery, JoiningAuthority: self.recoveryJoiningAuthority})
	return func() {
		removeRecovery()
		removeKeys()
	}
}

type networkRecovery struct {
	running *Sidecar
	*GkmGroupClient
}

// The code has anchored the config key. Its follower must finish verifying the config before recovering data repos.
func (self *networkRecovery) RunRecovery(ctx context.Context, args *GkmRecoverArgs) ([]*GkmRecoveryRepo, error) {
	follower := self.running.ConfigFollower()
	if follower == nil {
		return nil, ErrConfigHeadUnavailable
	}
	// AnchorRecovery installed the generation before the identity record advanced to anchored. Wake a
	// follower that saw the key in that interval and correctly withheld another full pass.
	follower.stateLock.Lock()
	client := follower.client
	follower.stateLock.Unlock()
	if client == nil {
		return nil, ErrConfigHeadUnavailable
	}
	client.requestFollow()
	if _, err := follower.WaitStanding(ctx); err != nil {
		return nil, err
	}
	return self.GkmGroupClient.RunRecovery(ctx, args)
}

func (self *networkRecovery) configRepoId() (Id, error) {
	state, err := self.GkmGroupClient.currentState()
	if err != nil {
		return Id{}, err
	}
	config, ok := state.(*ConfigState)
	if !ok {
		return Id{}, ErrConfigSealGenerationMissing
	}
	return IdFromBytes(config.Genesis().GetConfigRepoId())
}

func (self *networkRecovery) CurrentConfigKey(ctx context.Context) (*EvsRepoKey, error) {
	repoId, err := self.configRepoId()
	if err != nil {
		return nil, err
	}
	return self.GkmGroupClient.CurrentRepoKey(ctx, repoId)
}

func (self *networkRecovery) ConfigKeyAt(generation uint64) *EvsRepoKey {
	repoId, err := self.configRepoId()
	if err != nil {
		return nil
	}
	return self.running.GkmHeldKey(repoId, generation)
}

// The anchor's view is read-only and tied to one repo. It never calls back into the locked recovery flow.
type recoveryHeadKeys struct {
	gkmRefusingClient
	keys []*EvsRepoKey
}

func (self *recoveryHeadKeys) CurrentRepoKey(ctx context.Context, repoId Id) (*EvsRepoKey, error) {
	return self.RepoKey(ctx, repoId, uint64(len(self.keys)))
}

func (self *recoveryHeadKeys) RepoKey(ctx context.Context, repoId Id, generation uint64) (*EvsRepoKey, error) {
	if generation == 0 || uint64(len(self.keys)) < generation || self.keys[generation-1].RepoId() != repoId {
		return nil, ErrGkmKeyMissing
	}
	return self.keys[generation-1], nil
}

func (self *networkRecovery) ReadRecoveryHead(ctx context.Context, top *EvsRepoKey, version uint64, digest []byte) (*ConfigHead, func(uint64) *EvsRepoKey, error) {
	view, configRepoId, confirmed, err := self.GkmGroupClient.joiningState()
	if err != nil {
		return nil, nil, err
	}
	state, ok := view.(*ConfigState)
	if !ok || top == nil {
		return nil, nil, ErrConfigHeadUnavailable
	}
	if confirmed {
		configRepoId, err = IdFromBytes(state.Genesis().GetConfigRepoId())
	}
	if err != nil || configRepoId != top.RepoId() {
		return nil, nil, ErrGkmRecoveryAnchor
	}
	groupId, err := self.GkmGroupClient.manager(configRepoId).formedGroupId(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrConfigHeadUnavailable, err)
	}
	generations := []*GkmGeneration{}
	for number := uint64(1); number < top.Generation(); number++ {
		generation, err := self.GkmGroupClient.fetchGeneration(ctx, state, configRepoId, groupId, number)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w", ErrConfigHeadUnavailable, err)
		}
		generations = append(generations, generation)
	}
	keys, err := OpenGkmLadder(top, generations)
	if err != nil {
		return nil, nil, err
	}
	source := &recoveryHeadKeys{keys: keys}
	args, err := self.running.EvsClientArgs(source, func() GkmAuthView { return state }, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrConfigHeadUnavailable, err)
	}
	// The reader raises EVS pins during replay. Keep those private until the code's genesis signature also checks.
	args.Store = newSearchMemoryStore()
	client, err := NewEvsClient(args)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrConfigHeadUnavailable, err)
	}
	defer client.Close()
	reader, err := NewEvsConfigHeadReader(&EvsConfigHeadReaderArgs{Repo: client.Repo(configRepoId)})
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrConfigHeadUnavailable, err)
	}
	head, err := reader.ReadConfigHeadAtAnchor(ctx, version, digest, state)
	if err != nil {
		return nil, nil, err
	}
	return head, func(generation uint64) *EvsRepoKey {
		key, _ := source.RepoKey(ctx, configRepoId, generation)
		return key
	}, nil
}

// The pre-confirmation log can authorize only the admission being made with the code. It is never installed as
// the running sidecar's general authority, and its rows are anchored against the code before any recovery key is kept.
func (self *Sidecar) recoveryJoiningAuthority() SidecarAuthority {
	follower := self.ConfigFollower()
	if follower == nil {
		return nil
	}
	follower.stateLock.Lock()
	defer follower.stateLock.Unlock()
	client := follower.client
	if client == nil || follower.state.Value() != SidecarConfigFollowerCatchingUp || client.unconfirmed.Load() == nil {
		return nil
	}
	return &codeRecoveryAuthority{ConfigAuthority: client.Authority()}
}

type codeRecoveryAuthority struct {
	*ConfigAuthority
}

func (self *codeRecoveryAuthority) log() *ConfigLog {
	if log := self.client.unconfirmed.Load(); log != nil {
		return log
	}
	return self.client.Log()
}

func (self *codeRecoveryAuthority) Pin() *bridge.AuthPin {
	if log := self.log(); log != nil {
		return log.Pin()
	}
	return nil
}
func (self *codeRecoveryAuthority) Admission(sidecarId Id) *AclSidecar {
	if log := self.log(); log != nil {
		return configCloneAclSidecar(log.State().Sidecar(sidecarId))
	}
	return nil
}
func (self *codeRecoveryAuthority) CurrentBinding(memberId Id) *bridge.RecoveryBindingRow {
	if log := self.log(); log != nil {
		return log.State().CurrentBinding(memberId)
	}
	return nil
}
func (self *codeRecoveryAuthority) PendingProposal(proposalId []byte) *bridge.ProposalRow {
	log := self.log()
	if log == nil || len(proposalId) != 32 {
		return nil
	}
	proposal := log.State().proposals[[32]byte(proposalId)]
	if proposal == nil || !proposal.open(log.State().TimeMs()) {
		return nil
	}
	return proposal.row
}
func (self *codeRecoveryAuthority) JudgeStatement(signedBytes []byte) error {
	self.client.followLock.Lock()
	defer self.client.followLock.Unlock()
	log := self.log()
	if log == nil {
		return ErrConfigClientClosed
	}
	return configJudgeStatement(log, signedBytes, self.statementTime())
}
func (self *codeRecoveryAuthority) RecoveryLog() (*SidecarRecoveryLog, error) {
	self.client.followLock.Lock()
	defer self.client.followLock.Unlock()
	log := self.log()
	if log == nil {
		return nil, ErrConfigClientClosed
	}
	return configRecoveryLog(log)
}
