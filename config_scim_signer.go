//go:build !ios_extension

// §7.6's scim_signer (TEAM-M6-07; D-TEAM-25, owner decision 150, QD-629, QD-829): the indexer ServiceSettings.scim_signer
// names signs SCIM's removals of members outside the AdminSet at once, so a deactivation in the team's IdP becomes
// cryptographic without waiting for an admin's device.
//
//	rule    a MemberRevoke of a member outside the AdminSet is accepted when signed by the sidecar scim_signer names,
//	        standing at the statement's time (admitted, not revoked, parked, expired, suspended or read_only),
//	        whatever its role; scim_signer compiles into ProjectionRows.settings, so api and every rows-only reader
//	        judge it as a full reader does (QD-629, DESIGN-DETAILS 5.2.3). An AdminSet member's removal still needs k
//	        of n, and scim_signer counts for nothing there. The presence row still holds: a scim_signer that registered
//	        a live presence key must countersign, which a headless indexer cannot, so it signs nothing then
//	queue   GET /sidecar/scim-changes (QD-829; config_scim_source.go): api answers it only to the client of the sidecar
//	        the newest projection's ProjectionSettings.scim_signer names, standing as the rule asks
//	        (ScimSignerStanding), and only with the queued member_revoke changes of the members those rows hold
//	        outside the AdminSet (ScimSignerMemberIds), by the rows api already judges statements by
//	signer  ConfigScimSigner, on that indexer: each pass reads the queue, and for each member still in the config and
//	        outside the AdminSet signs the MemberRevoke through sidecarAct, the designation in the signed
//	        ServiceSettings being the confirmation this act stands on (D-CORE-13: an owner or admin signed it). An
//	        AdminSet member is left to admin devices; a member already gone is passed; a covered act stops the pass.
//	        ur daemon runs it beside each network's config follower, the queue's source installed only while that
//	        network's Sidecar is the one scim_signer names (sidecar_scim_signer.go, cli/daemon_config.go)
//
// The indexer acts on api's unsigned word: which members SCIM deactivated is the server's to say, so a breached server
// can have the indexer remove members outside the AdminSet. That is a denial only, since a removal adds no reader (I-4),
// on a designation that is the owner's choice (owner decision 150); every statement the indexer signs is still judged
// by the verifier at api and at every reader, and nothing it reads from api is trusted for more than which members to
// remove.
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

// Tunables of the scim_signer, its source over GET /sidecar/scim-changes included.
type ConfigScimSignerSettings struct {
	// How often a running signer reads the queue: 1 min, so an IdP's deactivation becomes cryptographic within a
	// minute of the server's denial. Non-positive runs no loop of a NewConfigScimSigner's own; the daemon's
	// SidecarScimSigner, which drives its passes itself, refuses it.
	PollInterval time.Duration
	// The most MemberRevokes one pass signs: 64, so a burst of deactivations spreads over passes inside the network's
	// append limits (§7.9).
	PassMaxCount int
	// The most queued removals one read of GET /sidecar/scim-changes asks api for: 100, about 25 KiB of JSON, far
	// inside SidecarSettings.ApiResponseByteCount; api caps it at its own page (model.NetworkScimSettings'
	// ChangeReadLimit, 1,000). Non-positive asks for api's own page.
	PageCount int
	// The most pages one pass reads: 20, so a pass examines at most 2,000 queued removals and a longer queue waits
	// for the next pass, whose first pages no longer hold what this one signed. Non-positive reads one.
	PassPageMaxCount int
}

// The defaults, a fresh value each call.
func DefaultConfigScimSignerSettings() *ConfigScimSignerSettings {
	return &ConfigScimSignerSettings{
		PollInterval:     time.Minute,
		PassMaxCount:     64,
		PageCount:        100,
		PassPageMaxCount: 20,
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
	// closed once the loop has returned, at once where none runs
	runDone chan struct{}
}

// A scim_signer for sidecar reading source; with source set and a positive PollInterval its loop runs from here until
// ctx ends or Close.
func NewConfigScimSigner(ctx context.Context, sidecar *Sidecar, source ScimChangeSource, settings *ConfigScimSignerSettings) *ConfigScimSigner {
	self := newConfigScimSigner(ctx, sidecar, source, settings)
	if source != nil && 0 < self.settings.PollInterval {
		go self.run()
	} else {
		close(self.runDone)
	}
	return self
}

// A scim_signer that runs no loop of its own, whose passes its caller drives: the daemon's SidecarScimSigner's.
func newConfigScimSigner(ctx context.Context, sidecar *Sidecar, source ScimChangeSource, settings *ConfigScimSignerSettings) *ConfigScimSigner {
	if settings == nil {
		settings = DefaultConfigScimSignerSettings()
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	return &ConfigScimSigner{
		ctx:      cancelCtx,
		cancel:   cancel,
		sidecar:  sidecar,
		source:   source,
		settings: settings,
		passLock: make(chan struct{}, 1),
		runDone:  make(chan struct{}),
	}
}

// Ends the loop.
func (self *ConfigScimSigner) Close() {
	self.cancel()
}

// The loop: a pass every PollInterval, a failed one logged and tried again at the next. No pass starts once the
// signer has closed, a timer taken as it closed included, and a closed signer asks the clock for nothing.
func (self *ConfigScimSigner) run() {
	defer close(self.runDone)
	// select takes either of two ready cases at random: a timer taken as the signer closed reads as the end
	for self.ctx.Err() == nil {
		if _, err := self.Pass(self.ctx); err != nil && self.ctx.Err() == nil {
			self.sidecar.log.Infof("[config]a scim_signer pass stopped: %s", err)
		}
		if self.ctx.Err() != nil {
			return
		}
		select {
		case <-self.ctx.Done():
		case <-self.sidecar.clock.After(self.settings.PollInterval):
		}
	}
}

// One pass (the file header): reads the queue and signs what this sidecar, as the one scim_signer names, may sign at
// once. A pass with no source, or on a sidecar scim_signer does not name, signs nothing.
func (self *ConfigScimSigner) Pass(ctx context.Context) (*ConfigScimSignerPass, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case self.passLock <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-self.passLock }()
	// select takes either of two ready cases at random: a lock taken as ctx ended goes back, and the end answers, so
	// no pass reads the queue or signs on an ended context
	if err := ctx.Err(); err != nil {
		return nil, err
	}

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

// Whether sidecarId is the sidecar ServiceSettings.scim_signer names at this state, standing at at as the MemberRevokes
// it signs must find it (configScimSignerSigns): admitted, not revoked, parked or expired, its member still a member
// where it is a member device, and neither suspended nor read_only. api serves GET /sidecar/scim-changes to the client
// of such a sidecar alone (QD-829), and the daemon installs the queue's source only on it (sidecar_scim_signer.go).
func (self *ConfigState) ScimSignerStanding(sidecarId Id, at time.Time) bool {
	return configScimSignerSigns(self, []ConfigSigner{{Kind: ConfigSignerSidecar, SidecarId: sidecarId}}, at.UnixMilli())
}

// The members this state holds outside the AdminSet, in id order: those whose MemberRevoke the scim_signer may sign at
// once (D-TEAM-25), and so the members whose queued SCIM removals GET /sidecar/scim-changes answers (QD-829). A member
// the state no longer holds, removed already or never admitted, is none of them.
func (self *ConfigState) ScimSignerMemberIds() []Id {
	memberIds := []Id{}
	for _, memberId := range self.MemberIds() {
		if !configRoleInAdminSet(self.members[memberId].GetRole()) {
			memberIds = append(memberIds, memberId)
		}
	}
	return memberIds
}
