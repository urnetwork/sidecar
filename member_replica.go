//go:build !ios_extension

// An enrolled member app's verified configuration, key intake and EVS client share one network lifetime.
// The HTTP Worker reads the same encrypted heads and keys as a native app.
package sidecar

import (
	"bytes"
	"context"
	"slices"
	"sync"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One enrolled network's replica, closed by its host or when either owner context ends.
type MemberReplica struct {
	running        *Sidecar
	ctx            context.Context
	cancel         context.CancelFunc
	identity       SidecarIdentity
	trustFirstUse  bool
	presenceLock   sync.Mutex
	presence       SidecarPresenceCheck
	headsLock      sync.Mutex
	heads          *EvsConfigHeadReader
	configRepoId   Id
	evs            *EvsClient
	hints          *GkmHints
	upkeep         *GkmUpkeep
	removeRecovery func()
	follower       *SidecarConfigFollower
	recordLock     sync.Mutex
	record         *SidecarRecord
	closeOnce      sync.Once

	removeSearchRequester func()
}

// Opens the enrolled identity's replica. Calls for the same identity share the same replica and its lifetime.
func (self *Sidecar) OpenMemberReplica(ctx context.Context) (*MemberReplica, error) {
	return self.openMemberReplica(ctx, false)
}

// The native SDK marks a child in its durable network record. An HTTP member
// identifies its top-level browser sign-in explicitly after the account handoff.
func (self *Sidecar) openMemberReplica(ctx context.Context, browserSignIn bool) (*MemberReplica, error) {
	self.memberReplicaLock.Lock()
	defer self.memberReplicaLock.Unlock()
	if self.ctx == nil || self.ctx.Err() != nil || ctx.Err() != nil {
		return nil, ErrSidecarClosed
	}
	identity := self.Identity()
	if identity == nil {
		return nil, ErrSidecarNoIdentity
	}
	if current, ok := self.memberReplica.(*MemberReplica); ok {
		sameIdentity := current.identity.SidecarId == identity.SidecarId && current.identity.NetworkId == identity.NetworkId &&
			bytes.Equal(current.identity.IdentityPublicKey, identity.IdentityPublicKey)
		if current.ctx.Err() == nil && sameIdentity && (!browserSignIn || current.trustFirstUse || current.Config() != nil) {
			return current, nil
		}
		current.Close()
	}
	runCtx, cancel := context.WithCancel(ctx)
	replica := &MemberReplica{ctx: runCtx, cancel: cancel, running: self, identity: *identity, trustFirstUse: browserSignIn || self.Paired()}
	if err := replica.open(); err != nil {
		replica.Close()
		return nil, err
	}
	self.memberReplica = replica
	go func() {
		select {
		case <-self.ctx.Done():
		case <-runCtx.Done():
		}
		replica.Close()
	}()
	return replica, nil
}

// The member replica this host opened, nil before enrollment or after close.
func (self *Sidecar) MemberReplica() *MemberReplica {
	replica := self.registeredMemberReplica()
	if replica == nil || self.ctx.Err() != nil || replica.ctx.Err() != nil {
		return nil
	}
	return replica
}

// A closed app replica still identifies the host as a member. Its components
// cannot fall back to a previously attached raw EVS client while closing.
func (self *Sidecar) registeredMemberReplica() *MemberReplica {
	self.memberReplicaLock.Lock()
	defer self.memberReplicaLock.Unlock()
	replica, _ := self.memberReplica.(*MemberReplica)
	return replica
}

// The file client once the enrollment anchor and configuration have been verified.
func (self *MemberReplica) Evs() *EvsClient {
	config := self.Config()
	if config == nil || !self.running.Admitted() {
		return nil
	}
	state := config.State()
	if state == nil || !bytes.Equal(state.IdentityKey(self.identity.SidecarId), self.identity.IdentityPublicKey) {
		return nil
	}
	return self.evs
}

// The configuration only once its follower has verified the enrolled anchor.
func (self *MemberReplica) Config() *ConfigClient {
	if self.activeIdentity() == nil {
		return nil
	}
	return self.follower.Client()
}

// The live identity for file and record access. The core retains the public
// identity while locked, although the instance can no longer serve member data.
func (self *MemberReplica) activeIdentity() *SidecarIdentity {
	if self.ctx.Err() != nil || self.running.ctx.Err() != nil {
		return nil
	}
	if state, _ := self.running.instance.State(); state != SidecarInstanceOpen {
		return nil
	}
	identity := self.running.Identity()
	if identity == nil || identity.SidecarId != self.identity.SidecarId || identity.NetworkId != self.identity.NetworkId ||
		!bytes.Equal(identity.IdentityPublicKey, self.identity.IdentityPublicKey) {
		return nil
	}
	return identity
}

// Ends the follower, hints and key upkeep, and releases any open repo subscriptions.
func (self *MemberReplica) Close() {
	self.closeOnce.Do(func() {
		self.cancel()
		if self.removeSearchRequester != nil {
			self.removeSearchRequester()
		}
		if self.follower != nil {
			self.follower.Close()
		}
		self.recordLock.Lock()
		if self.record != nil {
			self.record.Bind(nil, func() RecordAuthView { return RecordAuthUnavailable{} })
			self.record = nil
		}
		self.recordLock.Unlock()
		if self.evs != nil {
			self.evs.Close()
		}
		if self.removeRecovery != nil {
			self.removeRecovery()
		}
		if self.upkeep != nil {
			self.upkeep.Close()
		}
		if self.hints != nil {
			self.hints.Close()
		}
	})
}

// Open EVS before the follower so even its first anchored base can read the config repo over that same client.
func (self *MemberReplica) open() error {
	running := self.running
	apiArgs, err := running.GkmApiArgs()
	if err != nil {
		return err
	}
	api, err := NewGkmApi(apiArgs)
	if err != nil {
		return err
	}
	self.hints, err = NewGkmHints(self.ctx, &GkmHintsArgs{Clock: running.clock, Settings: running.settings.Gkm, Log: running.log})
	if err != nil {
		return err
	}
	upkeepArgs, err := running.GkmUpkeepArgs(api, self.hints)
	if err != nil {
		return err
	}
	self.upkeep, err = NewGkmUpkeep(self.ctx, upkeepArgs)
	if err != nil {
		return err
	}
	groupArgs, err := running.GkmGroupClientArgs(api, nil)
	if err != nil {
		return err
	}
	groupArgs.ReaderPrivateKey = self.upkeep.ReaderPrivateKey
	groupArgs.ReaderKeySha256 = self.upkeep.CurrentReaderKeySha256
	keys := &memberReplicaKeys{replica: self, api: api}
	groupArgs.ReaderRepoIds = keys.readerRepos
	group, err := NewGkmGroupClient(groupArgs)
	if err != nil {
		return err
	}
	keys.GkmGroupClient = group
	self.installRecovery(group)
	group.AttachHints(self.ctx, self.hints)
	args, err := running.EvsClientArgs(keys, self.verifiedConfig, nil)
	if err != nil {
		return err
	}
	args.GroupHead = group.GroupHead
	args.Identity = self.activeIdentity
	self.setStatementPoster(args)
	self.evs, err = NewEvsClient(args)
	if err != nil {
		return err
	}
	self.evs.EnablePrefixRules(running.EvsPrefixRulesArgs())
	running.BindMemberSearch(self.ctx, func() (*EvsClient, error) {
		evs := self.Evs()
		if evs == nil {
			return nil, ErrSidecarSearchUnavailable
		}
		return evs, nil
	})
	if err := running.BindSearchWrites(self.evs); err != nil {
		return err
	}
	// A signed-in member without an invitation may have no stored anchor. The follower records the
	// first self-verified genesis of this network for its admitter's safety-number comparison.
	settings := DefaultSidecarConfigFollowerSettings()
	settings.TrustFirstUse = self.trustFirstUse
	self.follower, err = running.FollowConfig(&SidecarConfigFollowerArgs{Heads: self, Gkm: keys, Hints: self.hints, Settings: settings, beforeStanding: self.bindRecord})
	if err != nil {
		return err
	}
	if err := self.follower.followIdentity(&self.identity); err != nil {
		return err
	}
	return self.bindSearchRequester()
}

// Opens the record streams and their receipt gate only after the enrolled anchor
// has verified, and before either host can obtain the file client for a read.
func (self *MemberReplica) bindRecord(config *ConfigClient) error {
	self.recordLock.Lock()
	defer self.recordLock.Unlock()
	if self.ctx.Err() != nil {
		return self.ctx.Err()
	}
	record, err := self.running.Record()
	if err != nil {
		return err
	}
	if err := record.BindMemberReplica(config, self.evs); err != nil {
		return err
	}
	self.record = record
	return nil
}

// A config head's verifier may need its previously verified rows while the initial anchor check is in progress.
func (self *MemberReplica) verifiedConfig() GkmAuthView {
	if self.activeIdentity() == nil {
		return nil
	}
	follower := self.running.ConfigFollower()
	if follower != nil {
		if state := follower.VerifiedState(); state != nil {
			return state
		}
	}
	return nil
}

// The config repo is the only candidate during a rows-only join. Once standing, the
// verified ACL also identifies the other repos that admit this device as a reader.
func (self *memberReplicaKeys) readerRepos() []Id {
	view, configId, confirmed, err := self.joiningState()
	if err != nil {
		return nil
	}
	if !confirmed {
		return []Id{configId}
	}
	state, ok := view.(*ConfigState)
	if !ok {
		return nil
	}
	var candidates []Id
	if configId, err = IdFromBytes(state.Genesis().GetConfigRepoId()); err == nil {
		candidates = append(candidates, configId)
	}
	if acl, err := state.Acl(); err == nil {
		candidates = append(candidates, acl.RepoIds()...)
	}
	var repos []Id
	for _, repoId := range candidates {
		if !slices.Contains(repos, repoId) && slices.Contains(state.RepoReaders(repoId), self.replica.identity.SidecarId) {
			repos = append(repos, repoId)
		}
	}
	return repos
}

// Uses the immutable config repo named by the pinned genesis. Its reader keeps the verified tree across checks.
func (self *MemberReplica) headReader(genesis *bridge.Genesis) (*EvsConfigHeadReader, error) {
	if genesis == nil {
		if state, ok := self.verifiedConfig().(*ConfigState); ok {
			genesis = state.Genesis()
		}
	}
	repoId, err := IdFromBytes(genesis.GetConfigRepoId())
	if err != nil {
		return nil, ErrConfigHeadUnavailable
	}
	self.headsLock.Lock()
	defer self.headsLock.Unlock()
	if self.heads != nil {
		if self.configRepoId != repoId {
			return nil, ErrConfigHeadUnavailable
		}
		return self.heads, nil
	}
	self.heads, err = NewEvsConfigHeadReader(&EvsConfigHeadReaderArgs{Repo: self.evs.Repo(repoId)})
	self.configRepoId = repoId
	return self.heads, err
}

// Reads an ordinary base at the verified chain.
func (self *MemberReplica) ReadConfigHead(ctx context.Context, version uint64, digest []byte) (*ConfigHead, error) {
	reader, err := self.headReader(nil)
	if err != nil {
		return nil, err
	}
	return reader.ReadConfigHead(ctx, version, digest)
}

// Reads an anchored base under its own genesis and rows.
func (self *MemberReplica) ReadConfigHeadAtAnchor(ctx context.Context, version uint64, digest []byte, anchor ConfigHeadAnchor) (*ConfigHead, error) {
	if anchor == nil {
		return nil, ErrConfigHeadUnavailable
	}
	reader, err := self.headReader(anchor.Genesis())
	if err != nil {
		return nil, err
	}
	return reader.ReadConfigHeadAtAnchor(ctx, version, digest, anchor)
}

// The group's verified or joining state also supplies the scopes requested at the GKM token exchange.
type memberReplicaKeys struct {
	*GkmGroupClient
	replica    *MemberReplica
	api        *GkmApi
	scopesLock sync.Mutex
}

// Publish the current state to the key client after selecting its scoped tokens.
func (self *memberReplicaKeys) AuthAdvanced(view GkmAuthView) {
	self.scopesLock.Lock()
	defer self.scopesLock.Unlock()
	self.GkmGroupClient.AuthAdvanced(view)
	self.setScopes()
	self.replica.hints.Resync()
}

// The rows-only pass can ask for the config repo's key alone.
func (self *memberReplicaKeys) AuthUnconfirmed(view GkmAuthView, repoId Id) {
	self.scopesLock.Lock()
	defer self.scopesLock.Unlock()
	self.GkmGroupClient.AuthUnconfirmed(view, repoId)
	self.setScopes()
	self.replica.hints.Resync()
}

// Derives the requested scopes from the latest state the group accepted.
func (self *memberReplicaKeys) setScopes() {
	view, configId, confirmed, err := self.joiningState()
	if err != nil {
		return
	}
	state, ok := view.(*ConfigState)
	if !ok {
		return
	}
	acl, err := state.Acl()
	if err != nil {
		return
	}
	subject := AclSidecarSubject(self.replica.identity.SidecarId)
	now := self.replica.running.clock.Now()
	var scopes []GkmRepoScope
	for _, repoId := range acl.RepoIds() {
		if !confirmed && repoId != configId {
			continue
		}
		rights := acl.EvsAccess(subject, repoId, AclTokenAudienceGkm, now).Rights
		var role string
		switch {
		case rights.Has(AclEvsAdmin):
			role = GkmScopeRoleAdmin
		case rights.Has(AclEvsWrite):
			role = GkmScopeRoleWrite
		case rights.Has(AclEvsRead):
			role = GkmScopeRoleRead
		case rights.Has(AclEvsDeposit):
			role = GkmScopeRoleDeposit
		default:
			continue
		}
		scopes = append(scopes, GkmRepoScope{RepoId: repoId, Role: role})
	}
	self.api.SetRepoScopes(scopes)
}
