// smtpedgeservice.SmtpGate in memory, until SMTP-M9-20's production gate fills the same shape from api's
// internal gate routes. It starts with nothing loaded, as a cold edge does, so every preamble answers
// TRY_LATER until a test loads what the gate reads: a network's facts, its mail_send decisions, the breaker
// state and the Community limits. A miss is counted as the load it would ask for, so a test can see a cold
// gate start its loads, and every call is counted, so a test can see the preamble path asked nothing but
// memory. Nothing here does I/O. Safe for concurrent use.

package sidecartest

import (
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

var _ smtpedgeservice.SmtpGate = (*FakeSmtpGate)(nil)

type FakeSmtpGate struct {
	stateLock      sync.Mutex
	networkIdFacts map[sidecar.Id]*smtpedgeservice.SmtpGateFacts
	// a network's mail_send decisions by sidecar; a network with no entry is not loaded
	networkIdSidecarIdSends map[sidecar.Id]map[sidecar.Id]sidecar.AclDecision
	breaker                 *smtpedgeservice.SmtpBreakerState
	communityLimits         *sidecar.QuotaLimits
	networkIdLoadAsks       map[sidecar.Id]int
	opCounts                map[string]int
}

// Nothing loaded.
func NewFakeSmtpGate() *FakeSmtpGate {
	return &FakeSmtpGate{
		networkIdFacts:          map[sidecar.Id]*smtpedgeservice.SmtpGateFacts{},
		networkIdSidecarIdSends: map[sidecar.Id]map[sidecar.Id]sidecar.AclDecision{},
		networkIdLoadAsks:       map[sidecar.Id]int{},
		opCounts:                map[string]int{},
	}
}

// Loads the network's facts, replacing any.
func (self *FakeSmtpGate) SetFacts(networkId sidecar.Id, facts *smtpedgeservice.SmtpGateFacts) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	kept := *facts
	self.networkIdFacts[networkId] = &kept
}

// Loads whether the sidecar holds mail_send in the network, which also loads the network's state.
func (self *FakeSmtpGate) SetMailSend(networkId sidecar.Id, sidecarId sidecar.Id, allowed bool) {
	decision := sidecar.AclDecision{Allowed: allowed, Reason: sidecar.AclReasonRule}
	if !allowed {
		decision.Reason = sidecar.AclReasonNoGrant
	}
	self.SetMailSendDecision(networkId, sidecarId, decision)
}

// Loads one decision as the gate cache would answer it, a refusal's reason included.
func (self *FakeSmtpGate) SetMailSendDecision(networkId sidecar.Id, sidecarId sidecar.Id, decision sidecar.AclDecision) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	sends, ok := self.networkIdSidecarIdSends[networkId]
	if !ok {
		sends = map[sidecar.Id]sidecar.AclDecision{}
		self.networkIdSidecarIdSends[networkId] = sends
	}
	sends[sidecarId] = decision
}

// Forgets everything of the network, as an eviction does.
func (self *FakeSmtpGate) Unload(networkId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.networkIdFacts, networkId)
	delete(self.networkIdSidecarIdSends, networkId)
}

// Loads §21.5's breaker state; nil unloads it.
func (self *FakeSmtpGate) SetBreaker(state *smtpedgeservice.SmtpBreakerState) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if state == nil {
		self.breaker = nil
		return
	}
	kept := *state
	kept.ListedAddresses = slices.Clone(state.ListedAddresses)
	self.breaker = &kept
}

// Loads the Community tier's limits; nil unloads them.
func (self *FakeSmtpGate) SetCommunityLimits(limits *sidecar.QuotaLimits) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if limits == nil {
		self.communityLimits = nil
		return
	}
	self.communityLimits = &sidecar.QuotaLimits{Tier: limits.Tier, Limits: maps.Clone(limits.Limits), Enforced: limits.Enforced}
}

// How many loads of the network a miss has asked for.
func (self *FakeSmtpGate) LoadAsks(networkId sidecar.Id) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.networkIdLoadAsks[networkId]
}

// Calls by method.
func (self *FakeSmtpGate) OpCounts() map[string]int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return maps.Clone(self.opCounts)
}

// See smtpedgeservice.SmtpGate.
func (self *FakeSmtpGate) Facts(networkId sidecar.Id) (*smtpedgeservice.SmtpGateFacts, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.opCounts["Facts"] += 1
	facts, ok := self.networkIdFacts[networkId]
	if !ok {
		self.networkIdLoadAsks[networkId] += 1
		return nil, false
	}
	kept := *facts
	return &kept, true
}

// See smtpedgeservice.SmtpGate.
func (self *FakeSmtpGate) MaySendMail(networkId sidecar.Id, sidecarId sidecar.Id, now time.Time) sidecar.AclDecision {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.opCounts["MaySendMail"] += 1
	sends, ok := self.networkIdSidecarIdSends[networkId]
	if !ok {
		self.networkIdLoadAsks[networkId] += 1
		return sidecar.AclDecision{Reason: sidecar.AclReasonNoState}
	}
	decision, ok := sends[sidecarId]
	if !ok {
		return sidecar.AclDecision{Reason: sidecar.AclReasonNoGrant}
	}
	return decision
}

// See smtpedgeservice.SmtpGate.
func (self *FakeSmtpGate) Breaker() (*smtpedgeservice.SmtpBreakerState, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.opCounts["Breaker"] += 1
	if self.breaker == nil {
		return nil, false
	}
	kept := *self.breaker
	kept.ListedAddresses = slices.Clone(self.breaker.ListedAddresses)
	return &kept, true
}

// See smtpedgeservice.SmtpGate.
func (self *FakeSmtpGate) CommunityLimits() (*sidecar.QuotaLimits, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.opCounts["CommunityLimits"] += 1
	if self.communityLimits == nil {
		return nil, false
	}
	return &sidecar.QuotaLimits{Tier: self.communityLimits.Tier, Limits: maps.Clone(self.communityLimits.Limits), Enforced: self.communityLimits.Enforced}, true
}
