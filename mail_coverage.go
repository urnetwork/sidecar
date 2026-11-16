//go:build !sidecar_http && !ios_extension

// §18.5's Coverage and §15.9's copy (R-MAIL-6, R-MAIL-13, D-MAIL-15, FS-82, FS-123; owner decisions 12, 150, 197;
// MAIL-M8-03): GetReceiverCoverage's three values, which SDK-M8-04 wraps into SidecarMail.
//
//	indexer          an IndexerSet designates a mail indexer whose designation covers this user's mail: a network
//	                 scope's, a member scope's of this device's member, or in a personal network either (§7.9, §15.6;
//	                 mail_indexer.go's covers row)
//	foreground-only  receivers, but no mail indexer that this device can show: some device of the network may hold the
//	                 receiver's listen on smtp/25/mx and register it (policy's grant, and MailReceiverEligible where
//	                 the config is bound), so mail arrives only while one runs. A designation whose sealed services
//	                 this device cannot open is not shown to be a mail indexer, so it reads here too: the value never
//	                 claims an indexer it cannot show, as the sdk's own fallback does
//	none             no device may receive at all
//
// The copy is owner decisions 12's and 197's words, one text for foreground-only and none (CreateBurner shows it
// before the first burner under either, §15.9), and none for indexer. No value and no copy speaks of sending, whose
// limits are CheckSend's (FS-123 as plan-MAIL-small-readings#21 reads it): a send's copy names no indexer, receiver
// or coverage. Nothing here logs. Off the page Worker's leg, which receives nothing, and the extension's.

package sidecar

import (
	"context"
	"time"
)

// GetReceiverCoverage's values (§18.5). Format values: apps read them.
type MailCoverage string

const (
	// An IndexerSet designates a mail indexer for this user's mail.
	MailCoverageIndexer MailCoverage = "indexer"
	// Receivers, but no mail indexer.
	MailCoverageForegroundOnly MailCoverage = "foreground-only"
	// No receiver.
	MailCoverageNone MailCoverage = "none"
)

// §15.9's and §18.5's copy for foreground-only, which CreateBurner shows under none too (owner decisions 12, 197): the
// one text, which §15.6's indexer prompt is too (MailIndexerPrompt, on every leg).
const MailCoverageForegroundOnlyCopy = MailIndexerPrompt

// The copy shown beside a coverage value: the foreground-only copy for foreground-only and none, nothing for indexer
// or a value this build does not know.
func MailCoverageCopy(coverage MailCoverage) string {
	switch coverage {
	case MailCoverageForegroundOnly, MailCoverageNone:
		return MailCoverageForegroundOnlyCopy
	}
	return ""
}

// This user's receiver coverage at the bound state (the file header): ErrMailUnbound before a state is bound.
func (self *MailClient) ReceiverCoverage(ctx context.Context) (MailCoverage, error) {
	binding, _, state, err := self.state()
	if err != nil {
		return MailCoverageNone, err
	}
	var config *ConfigState
	if binding.Config != nil {
		if config, err = binding.Config(); err != nil {
			config = nil
		}
	}
	return mailCoverageOf(state, config, self.sidecarId, binding.IndexerServices, self.clock.Now()), nil
}

// sidecarId's user's coverage at state and config, config nil where none is bound (the file header).
func mailCoverageOf(state *AclState, config *ConfigState, sidecarId Id, services MailIndexerServices, now time.Time) MailCoverage {
	if config != nil {
		if covers, err := mailIndexerCovers(config, sidecarId, services); covers && err == nil {
			return MailCoverageIndexer
		}
	}
	if mailAnyReceiver(state, config, services, now) {
		return MailCoverageForegroundOnly
	}
	return MailCoverageNone
}

// Whether any device of the network may receive: an admitted, unrevoked sidecar that policy grants the receiver's
// listen at now, and that registers it by its own choice where config is bound (MailReceiverEligible).
func mailAnyReceiver(state *AclState, config *ConfigState, services MailIndexerServices, now time.Time) bool {
	for index := range state.sidecars {
		sidecar := &state.sidecars[index]
		if !sidecar.valid || sidecar.revoked || sidecar.parked || sidecar.suspended {
			continue
		}
		subject := AclSidecarSubject(sidecar.id)
		if !state.MayListen(subject, AclSocketName{PublicName: aclMailReceiverName}, now).Allowed {
			continue
		}
		if config != nil && !MailReceiverEligible(config, sidecar.id, services) {
			continue
		}
		return true
	}
	return false
}
