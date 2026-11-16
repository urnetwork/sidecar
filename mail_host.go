//go:build !ios_extension

// §15.6's and §18.4's receiver hosting (R-MAIL-8, R-MAIL-13, D-MAIL-15, FS-82; owner decisions 12, 150, 197;
// MAIL-M8-04, as DESIGN-DETAILS' owner decision 197 table changes it): which hosts receive when, and which may be a
// mail indexer.
//
//	daemon   ur daemon on a desktop, NAS or VPS: always on, so it receives whenever policy grants its listen, and it is
//	         the one host that may be a mail indexer. SetReceiverEnabled(true) files its IndexerSet for mail at member
//	         scope, which in a personal network covers every mailbox and in a Team this member's (§15.6: "in a personal
//	         network or a member scope"), and false retires mail from it; a remote-mode desktop app calls it on its
//	         daemon (§18.5). The designation is a person's act, never MCP's or a hook's (§7.9)
//	android  an app listens only while it is open, its VPN component running forwarding alone (owner decision 197): it
//	ios      is never a mail indexer, so SetReceiverEnabled refuses, and in the background it registers no listener.
//	         A wake on either only resyncs: ingest runs, nothing listens (Resync), so nothing here promises delivery
//	         on a phone, and coverage says so (mail_coverage.go)
//
// What SetReceiverEnabled files keeps the designation's other services: it reads the standing designation's services
// with the binding's MailIndexerServices, adds or removes mail, and files the rest, retiring the designation once
// nothing is left. A standing designation whose services this device cannot open is left alone and the call refused,
// never refiled with services it could not read. A retry finds mail filed already and files nothing.
//
// On a phone the spool keeps every message off the heap (mail_spool.go), so §18.4's 16 MiB and 32 MiB budgets hold
// with max_streams' 16 sessions and the 4 check slots as §15.5 fixes them, and only deposits drop to 2 at once
// (ApplyMobileMailSettings). Nothing here logs. On every leg but the extension's.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
)

// The kind of host a MailClient runs on (the file header).
type MailHostProfile string

const (
	// ur daemon on a desktop, NAS or VPS.
	MailHostProfileDaemon MailHostProfile = "daemon"
	// The Android app.
	MailHostProfileAndroid MailHostProfile = "android"
	// The iOS app.
	MailHostProfileIos MailHostProfile = "ios"
)

// Whether the host may be a mail indexer: an always-on daemon, never an app (owner decisions 150, 197).
func (self MailHostProfile) MayIndex() bool {
	return self == MailHostProfileDaemon || self == ""
}

// Whether the host listens only while its app is open.
func (self MailHostProfile) ForegroundOnly() bool {
	return self == MailHostProfileAndroid || self == MailHostProfileIos
}

var (
	// An app host receives only while it is open and is never a mail indexer (owner decision 197): designate an
	// always-on device, a desktop ur daemon, a NAS or VPS.
	ErrMailHostNotIndexer = errors.New("mail host: an app receives mail only while it is open, so it is never a mail indexer")
	// A designation is a person's act, through a ur command or an app's UI, never an MCP tool or a hook (§7.9).
	ErrMailHostNotConfirmed = errors.New("mail host: a designation needs a person's act")
	// A designation of this device stands whose services this device cannot open, so mail cannot be added to or taken
	// from it without dropping what it does not know: nothing is filed.
	ErrMailHostServicesSealed = errors.New("mail host: this device's designation has services it cannot read")
)

// What SetReceiverEnabled files a designation through: *Sidecar's DesignateIndexer and RetireIndexerScope.
type MailIndexerDesignator interface {
	DesignateIndexer(ctx context.Context, scope protocol.IndexerScope, services []protocol.IndexerService, appHost bool,
		configKey func(ctx context.Context) (*EvsRepoKey, error), origin SidecarActOrigin, check SidecarPresenceCheck) error
	RetireIndexerScope(ctx context.Context, scope protocol.IndexerScope, origin SidecarActOrigin, check SidecarPresenceCheck) error
}

// The scope SetReceiverEnabled designates at: member, which covers a personal network's mail and a Team member's own
// (the file header's daemon row).
const mailHostDesignationScope = protocol.IndexerScope_INDEXER_SCOPE_MEMBER

// The host this client runs on.
func (self *MailClient) Profile() MailHostProfile {
	if self.settings.Profile == "" {
		return MailHostProfileDaemon
	}
	return self.settings.Profile
}

// Designates this daemon as a mail indexer, or with enabled false takes mail from its designation (see the file
// header), as a person confirmed it: origin must be SidecarActConfirmed. An app host refuses with
// ErrMailHostNotIndexer.
func (self *MailClient) SetReceiverEnabled(ctx context.Context, enabled bool, origin SidecarActOrigin, check SidecarPresenceCheck) error {
	if !self.Profile().MayIndex() {
		return ErrMailHostNotIndexer
	}
	if origin != SidecarActConfirmed {
		return ErrMailHostNotConfirmed
	}
	binding, _, err := self.bound()
	if err != nil {
		return err
	}
	if binding.Designator == nil || binding.Config == nil {
		return fmt.Errorf("%w: no designator or config to file through", ErrMailUnbound)
	}
	state, err := binding.Config()
	if err != nil {
		return err
	}
	services, standing, err := mailHostStandingServices(state, self.sidecarId, binding.IndexerServices)
	if err != nil {
		return err
	}
	hasMail := slices.Contains(services, protocol.IndexerService_INDEXER_SERVICE_MAIL)
	switch {
	case enabled && hasMail, !enabled && !hasMail:
		// filed already, or nothing to take away: a retry files nothing
		return nil
	case enabled:
		next := append(slices.Clone(services), protocol.IndexerService_INDEXER_SERVICE_MAIL)
		slices.Sort(next)
		return binding.Designator.DesignateIndexer(ctx, mailHostDesignationScope, next, false, binding.ConfigKey, origin, check)
	}
	rest := slices.DeleteFunc(slices.Clone(services), func(service protocol.IndexerService) bool {
		return service == protocol.IndexerService_INDEXER_SERVICE_MAIL
	})
	if len(rest) == 0 && standing {
		return binding.Designator.RetireIndexerScope(ctx, mailHostDesignationScope, origin, check)
	}
	return binding.Designator.DesignateIndexer(ctx, mailHostDesignationScope, rest, false, binding.ConfigKey, origin, check)
}

// The services of sidecarId's designation at the designation scope, and whether one stands: none when none stands,
// ErrMailHostServicesSealed when one stands that services cannot open.
func mailHostStandingServices(state *ConfigState, sidecarId Id, services MailIndexerServices) ([]protocol.IndexerService, bool, error) {
	for _, indexer := range state.Indexers() {
		if indexer.SidecarId != sidecarId || indexer.Scope != mailHostDesignationScope {
			continue
		}
		if services == nil {
			return nil, true, ErrMailHostServicesSealed
		}
		offered, opened := services(indexer)
		if !opened {
			return nil, true, ErrMailHostServicesSealed
		}
		return slices.Clone(offered), true, nil
	}
	return nil, false, nil
}

// Tells an app host's client whether its app is open: in the background a foreground-only host registers no listener
// and ends the one it holds, and in the foreground it receives again where policy grants the listen (the file
// header's android and ios rows). A daemon's client ignores it.
func (self *MailClient) SetForeground(foreground bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.background == !foreground {
		return
	}
	self.background = !foreground
	self.notifyWithLock()
}

// Whether a foreground-only host is in the background now.
func (self *MailClient) inBackground() bool {
	if !self.Profile().ForegroundOnly() {
		return false
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.background
}
