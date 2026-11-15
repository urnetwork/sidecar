//go:build !ios_extension

// §7.6's scim_signer (TEAM-M6-07; D-TEAM-25, owner decision 150, QD-629): the indexer ServiceSettings.scim_signer
// names signs SCIM's removals of members outside the AdminSet at once, so a deactivation in the team's IdP becomes
// cryptographic without waiting for an admin's device.
//
//	rule    a MemberRevoke of a member outside the AdminSet is accepted when signed by the sidecar scim_signer names,
//	        standing at the statement's time (admitted, not revoked, parked, expired, suspended or read_only),
//	        whatever its role; scim_signer compiles into ProjectionRows.settings, so api and every rows-only reader
//	        judge it as a full reader does (QD-629, DESIGN-DETAILS 5.2.3). An AdminSet member's removal still needs k
//	        of n, and scim_signer counts for nothing there. The presence row still holds: a scim_signer that registered
//	        a live presence key must countersign, which a headless indexer cannot, so it signs nothing then
//	signer  ConfigScimSigner, on that indexer: each pass reads SCIM's queued removals, and for each member still in
//	        the config and outside the AdminSet signs the MemberRevoke through sidecarAct, the designation in the
//	        signed ServiceSettings being the confirmation this act stands on (D-CORE-13: an owner or admin signed
//	        it). An AdminSet member is left to admin devices; a member already gone is passed; a covered act stops
//	        the pass. Nothing it reads from api is trusted for more than which members to remove: the verifier
//	        judges every statement
//
// How the indexer reads the queue is open (questions/team-m6-07-scim-signer-queue.md): GET /network/scim-changes is
// a Network route its token cannot call. ScimChangeSource is that seam, and nothing installs one, so in production
// the signer signs nothing until the question is answered.
//
// The rule is config_admit.go's configScimSignerSigns, which every verifier links, the forwarding role's included; this
// file is the signer alone, which no app's VPN component runs (owner decision 197).
//
// Nothing here creates, derives or unwraps a key. Root Id, no connect type.

package sidecar

import (
	"context"
	"errors"
	"time"
)

// What ConfigScimSigner reads SCIM's queue from (the file header).
type ScimChangeSource interface {
	// The members SCIM deactivated or deleted whose MemberRevoke is owed, oldest first.
	ScimMemberRevokes(ctx context.Context) ([]Id, error)
}

// Tunables of the scim_signer.
type ConfigScimSignerSettings struct {
	// How often a running signer reads the queue: 1 min, so an IdP's deactivation becomes cryptographic within a
	// minute of the server's denial. Non-positive runs no loop.
	PollInterval time.Duration
	// The most MemberRevokes one pass signs: 64, so a burst of deactivations spreads over passes inside the network's
	// append limits (§7.9).
	PassMaxCount int
}

// The defaults, a fresh value each call.
func DefaultConfigScimSignerSettings() *ConfigScimSignerSettings {
	return &ConfigScimSignerSettings{
		PollInterval: time.Minute,
		PassMaxCount: 64,
	}
}

// What one pass did.
type ConfigScimSignerPass struct {
	// This sidecar is the one scim_signer names at the state the pass read; false, it signed nothing.
	Designated bool
	// The members whose MemberRevoke it signed, landed or pending its post's retry.
	Signed []Id
	// The members in the AdminSet, whose removal needs k of n: left to admin devices.
	AdminSet []Id
	// The members the config no longer holds: already removed.
	Gone []Id
	// The pass stopped: the log covers this sidecar's MemberRevoke with a presence countersignature, which a
	// headless indexer cannot give.
	PresenceNeeded bool
}

// The scim_signer of one Sidecar. Safe for concurrent use: passes are serial.
type ConfigScimSigner struct {
	ctx      context.Context
	cancel   context.CancelFunc
	sidecar  *Sidecar
	source   ScimChangeSource
	settings *ConfigScimSignerSettings
	passLock chan struct{}
}

// A scim_signer for sidecar reading source; with source set and a positive PollInterval its loop runs from here until
// ctx ends or Close.
func NewConfigScimSigner(ctx context.Context, sidecar *Sidecar, source ScimChangeSource, settings *ConfigScimSignerSettings) *ConfigScimSigner {
	if settings == nil {
		settings = DefaultConfigScimSignerSettings()
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &ConfigScimSigner{
		ctx:      cancelCtx,
		cancel:   cancel,
		sidecar:  sidecar,
		source:   source,
		settings: settings,
		passLock: make(chan struct{}, 1),
	}
	if source != nil && 0 < settings.PollInterval {
		go self.run()
	}
	return self
}

// Ends the loop.
func (self *ConfigScimSigner) Close() {
	self.cancel()
}

// The loop: a pass every PollInterval, a failed one logged and tried again at the next.
func (self *ConfigScimSigner) run() {
	for {
		if _, err := self.Pass(self.ctx); err != nil && self.ctx.Err() == nil {
			self.sidecar.log.Infof("[config]a scim_signer pass stopped: %s", err)
		}
		select {
		case <-self.ctx.Done():
			return
		case <-self.sidecar.clock.After(self.settings.PollInterval):
		}
	}
}

// One pass (the file header): reads the queue and signs what this sidecar, as the one scim_signer names, may sign at
// once. A pass with no source, or on a sidecar scim_signer does not name, signs nothing.
func (self *ConfigScimSigner) Pass(ctx context.Context) (*ConfigScimSignerPass, error) {
	select {
	case self.passLock <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-self.passLock }()

	pass := &ConfigScimSignerPass{}
	identity := self.sidecar.currentIdentity()
	if identity == nil {
		return pass, ErrSidecarNoIdentity
	}
	state, err := self.sidecar.memberRevokeState()
	if err != nil {
		return pass, err
	}
	scimSigner, ok := state.ScimSigner()
	if !ok || scimSigner != identity.SidecarId {
		return pass, nil
	}
	pass.Designated = true
	if self.source == nil {
		return pass, nil
	}
	memberIds, err := self.source.ScimMemberRevokes(ctx)
	if err != nil {
		return pass, err
	}
	for _, memberId := range memberIds {
		if max(self.settings.PassMaxCount, 1) <= len(pass.Signed) {
			break
		}
		// the newest state each time: the pass's own revocations land as it goes
		state, err := self.sidecar.memberRevokeState()
		if err != nil {
			return pass, err
		}
		member := state.Member(memberId)
		switch {
		case member == nil:
			pass.Gone = append(pass.Gone, memberId)
			continue
		case configRoleInAdminSet(member.GetRole()):
			pass.AdminSet = append(pass.AdminSet, memberId)
			continue
		}
		_, err = self.sidecar.signMemberRevoke(ctx, memberId, nil)
		switch {
		case errors.Is(err, ErrSidecarActPresence):
			pass.PresenceNeeded = true
			return pass, nil
		case err == nil, errors.Is(err, ErrSidecarActPending):
			pass.Signed = append(pass.Signed, memberId)
		default:
			return pass, err
		}
	}
	return pass, nil
}
