//go:build !ios_extension && !sidecar_http

// The scim_signer on a hosted network's Sidecar (QD-829; §7.6, D-TEAM-25, owner decision 150): ur daemon runs it beside
// each network's config follower (cli/daemon_config.go), as the Sidecar's "scim-signer" component, so the indexer
// ServiceSettings.scim_signer names signs SCIM's removals of members outside the AdminSet at once.
//
//	look     on each client generation, the component reads the verified state the installed authority holds: this
//	         sidecar is the one scim_signer names, standing as api requires (ConfigState.ScimSignerStanding), or it is
//	         not. A sidecar with no identity or no verified state is not
//	install  only while it is, the component makes SCIM's queue source over the generation's api (GET
//	         /sidecar/scim-changes, config_scim_source.go) and a ConfigScimSigner reading it; when the designation goes,
//	         both go, so no sidecar scim_signer does not name ever calls the route
//	pass     a pass at once when the source is installed, then one every PollInterval while it stays
//	wake     each entry the installed authority applies, and the network's follower standing, look again at once, so a
//	         designation landing installs the source without waiting out the interval; an authority installed later
//	         is noticed at the next interval otherwise
//
// The indexer acts on api's unsigned word (config_scim_signer.go's header says why that is a denial only).
//
// Daemon hosts only: an indexer is an always-on ur daemon, never an app (§3.6). Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
)

// The component's name: its keychain namespace and directory, both unused.
const sidecarScimSignerComponentName = "scim-signer"

// What a Sidecar's scim_signer runs on.
type SidecarScimSignerArgs struct {
	// Nil is DefaultConfigScimSignerSettings. PollInterval must be positive.
	Settings *ConfigScimSignerSettings
	// The queue's source over one generation's api, which the component calls only while this sidecar is the one
	// ServiceSettings.scim_signer names. Nil is GET /sidecar/scim-changes through that api.
	NewSource func(api *SidecarApi) ScimChangeSource
}

// What a Sidecar's scim_signer has done, ids only (I-13).
type SidecarScimSignerStatus struct {
	// Looks at the designation since the component started.
	LookCount int
	// The queue's source is installed: this sidecar is the one scim_signer names at the state the newest look read.
	Installed bool
	// Passes run since the component started.
	PassCount int
	// The members whose MemberRevoke its passes signed, landed or pending, oldest first.
	Signed []Id
	// The newest pass's failure, "" for none.
	PassErr string
}

// One Sidecar's scim_signer component (the file header).
type SidecarScimSigner struct {
	sidecar   *Sidecar
	settings  *ConfigScimSignerSettings
	newSource func(api *SidecarApi) ScimChangeSource
	// raised at each change of status, for WaitStatus
	changes   *MonitorValue[uint64]
	closeOnce sync.Once

	stateLock sync.Mutex
	status    SidecarScimSignerStatus
	closed    bool
	// takes the component off the Sidecar
	remove func()
}

// Starts the network's scim_signer on args as the Sidecar's "scim-signer" component, which ends with the Sidecar or at
// the answer's Close. One a Sidecar: a second is refused while one runs.
func (self *Sidecar) RunScimSigner(args *SidecarScimSignerArgs) (*SidecarScimSigner, error) {
	if args == nil {
		args = &SidecarScimSignerArgs{}
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultConfigScimSignerSettings()
	}
	if settings.PollInterval <= 0 {
		return nil, fmt.Errorf("%w: the scim_signer's poll interval", errInvalidSettings)
	}
	newSource := args.NewSource
	if newSource == nil {
		newSource = func(api *SidecarApi) ScimChangeSource {
			return newSidecarApiScimChangeSource(api, settings)
		}
	}
	signer := &SidecarScimSigner{
		sidecar:   self,
		settings:  settings,
		newSource: newSource,
		changes:   NewMonitorValue[uint64](0),
	}
	remove, err := self.AddComponent(signer)
	if err != nil {
		return nil, err
	}
	signer.setRemove(remove)
	return signer, nil
}

// The Sidecar's scim_signer, nil when it runs none.
func (self *Sidecar) ScimSigner() *SidecarScimSigner {
	leg, ok := self.leg.(*sidecarConnectLeg)
	if !ok {
		return nil
	}
	for _, component := range leg.componentList() {
		if scimSigner, ok := component.(*SidecarScimSigner); ok {
			return scimSigner
		}
	}
	return nil
}

// "scim-signer".
func (self *SidecarScimSigner) Name() string {
	return sidecarScimSignerComponentName
}

// Follows the designation on this generation until the generation ends. See SidecarComponent.
func (self *SidecarScimSigner) Attach(env *SidecarEnv) error {
	if env.Identity == nil {
		return fmt.Errorf("%w: a generation with no identity", ErrSidecarNoIdentity)
	}
	if env.SidecarApi == nil {
		return errors.New("the scim_signer needs the generation's api")
	}
	go self.run(env.Ctx, env.Identity.SidecarId, env.SidecarApi)
	return nil
}

// Ends the component for good, taking it off the Sidecar. See SidecarComponent.
func (self *SidecarScimSigner) Close() {
	self.closeOnce.Do(func() {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.closed = true
		}()
		self.changes.Update(func(n uint64) uint64 { return n + 1 })
	})
	remove := func() func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		remove := self.remove
		self.remove = nil
		return remove
	}()
	if remove != nil {
		// the leg calls Close again, which is done
		remove()
	}
}

// Keeps the function that takes the component off the Sidecar, or calls it at once when the component closed
// meanwhile.
func (self *SidecarScimSigner) setRemove(remove func()) {
	closed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return true
		}
		self.remove = remove
		return false
	}()
	if closed {
		remove()
	}
}

// A copy of the status.
func (self *SidecarScimSigner) Status() *SidecarScimSignerStatus {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	status := self.status
	status.Signed = slices.Clone(self.status.Signed)
	return &status
}

// Waits until until holds of the status, which it is handed a copy of, and answers that status; ctx's error when ctx
// ends first, ErrSidecarClosed once the component has closed.
func (self *SidecarScimSigner) WaitStatus(ctx context.Context, until func(status *SidecarScimSignerStatus) bool) (*SidecarScimSignerStatus, error) {
	for {
		_, changed := self.changes.Get()
		status := self.Status()
		if until(status) {
			return status, nil
		}
		closed := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.closed
		}()
		if closed {
			return status, ErrSidecarClosed
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return status, ctx.Err()
		}
	}
}

// Changes the status under its lock and raises the change.
func (self *SidecarScimSigner) edit(change func(status *SidecarScimSignerStatus)) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		change(&self.status)
	}()
	self.changes.Update(func(n uint64) uint64 { return n + 1 })
}

// Whether this sidecar is the one scim_signer names, standing, at the newest verified state. Fails closed: no verified
// state is no designation.
func (self *SidecarScimSigner) designated(sidecarId Id) bool {
	state, err := self.sidecar.memberRevokeState()
	if err != nil {
		return false
	}
	return state.ScimSignerStanding(sidecarId, self.sidecar.clock.Now())
}

// The component's part of one generation (the file header), until ctx ends, when the source goes. No look starts once
// ctx has ended, a wake or a poll taken as it ended included, so no signer is installed and no pass runs or is
// counted past the end, and an ended ctx asks the clock for nothing.
func (self *SidecarScimSigner) run(ctx context.Context, sidecarId Id, api *SidecarApi) {
	wake := make(chan struct{}, 1)
	poke := func() {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
	var signer *ConfigScimSigner
	var authority SidecarAuthority
	removeCallback := func() {}
	waitingStanding := false
	defer func() {
		removeCallback()
		if signer != nil {
			signer.Close()
		}
		self.edit(func(status *SidecarScimSignerStatus) {
			status.Installed = false
		})
	}()
	if ctx.Err() != nil {
		return
	}
	// the first look's pass is due at once; then one every PollInterval while the source stays
	due := true
	poll := self.sidecar.clock.After(self.settings.PollInterval)
	// select takes any of its ready cases at random: a wake or a poll taken as ctx ended reads as the end
	for ctx.Err() == nil {
		if current := self.sidecar.authority(); current != authority {
			removeCallback()
			authority, removeCallback = current, func() {}
			if authority != nil {
				removeCallback = authority.AddEntryCallback(func(*SidecarAuthorityEntry) {
					poke()
				})
			}
		}
		if authority == nil && !waitingStanding {
			if follower := self.sidecar.ConfigFollower(); follower != nil {
				waitingStanding = true
				go func() {
					if _, err := follower.WaitStanding(ctx); err == nil {
						poke()
					}
				}()
			}
		}
		installed := false
		designated := self.designated(sidecarId)
		switch {
		case designated && signer == nil:
			signer = newConfigScimSigner(ctx, self.sidecar, self.newSource(api), self.settings)
			installed = true
		case !designated && signer != nil:
			signer.Close()
			signer = nil
		}
		self.edit(func(status *SidecarScimSignerStatus) {
			status.LookCount += 1
			status.Installed = signer != nil
		})
		if signer != nil && (installed || due) {
			due = false
			pass, err := signer.Pass(ctx)
			if err != nil && ctx.Err() == nil {
				self.sidecar.log.Infof("[config]a scim_signer pass stopped: %s", err)
			}
			self.edit(func(status *SidecarScimSignerStatus) {
				status.PassCount += 1
				if pass != nil {
					status.Signed = append(status.Signed, pass.Signed...)
				}
				status.PassErr = ""
				if err != nil {
					status.PassErr = err.Error()
				}
			})
		}
		select {
		case <-ctx.Done():
		case <-wake:
		case <-poll:
			// a poll taken as ctx ended asks the clock for no next one
			if ctx.Err() == nil {
				due = true
				poll = self.sidecar.clock.After(self.settings.PollInterval)
			}
		}
	}
}
