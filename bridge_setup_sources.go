//go:build !ios_extension && !sidecar_http

// The forwarding setup shares its network's standing config follower, signing authority and config group.
package sidecar

import "context"

// The two GKM writes made by forwarding setup after its signed Delegation lands.
type forwardingSetupGkm interface {
	UploadDelegationKey(ctx context.Context, delegationId []byte, readerKey []byte) error
	DeliverDelegationWraps(ctx context.Context, delegationId []byte) error
}

// The reader's public key goes to the same authenticated GKM service that supplies its wraps.
func (self *GkmGroupClient) UploadDelegationKey(ctx context.Context, delegationId []byte, readerKey []byte) error {
	api, ok := self.args.Api.(interface {
		UploadDelegationKey(context.Context, []byte, []byte) error
	})
	if !ok {
		return ErrGkmUnavailable
	}
	return api.UploadDelegationKey(ctx, delegationId, readerKey)
}

// The config group's lookup is gated on the verified follower standing, including on restart.
type followerConfigKeys struct {
	follower *SidecarConfigFollower
}

// Seals new material only under a generation that covers removals and expiries at the current pin.
func (self *followerConfigKeys) CurrentConfigKey(ctx context.Context) (*EvsRepoKey, error) {
	return self.follower.CurrentConfigKey(ctx)
}

// Opens existing statements under precisely the generation carried in their seal.
func (self *followerConfigKeys) ConfigKeyAt(generation uint64) *EvsRepoKey {
	return self.follower.RepoKeyAt(generation)
}

// Tears down all sources together on close, a refused anchor, or an installation racing either.
func (self *SidecarConfigFollower) installForwardingSources(client *ConfigClient, removeAuthority func()) func() {
	gkm, ok := self.args.Gkm.(forwardingSetupGkm)
	if !ok {
		return removeAuthority
	}
	removeKeys := self.sidecar.InstallConfigKeys(&followerConfigKeys{follower: self})
	removeSetup := self.sidecar.InstallForwardingSetup(&ForwardingSetupSources{
		Config:                 client,
		UploadDelegationKey:    gkm.UploadDelegationKey,
		DeliverDelegationWraps: gkm.DeliverDelegationWraps,
	})
	return func() {
		removeSetup()
		removeKeys()
		removeAuthority()
	}
}
