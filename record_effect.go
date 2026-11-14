//go:build !ios_extension

// §16.6's effects (MCP-M3-06; D-MCP-11, AU1-AU4; plan-MCP-effect-seam): each O kind's component runs its effect under
// the use's effect_key, idempotent per key, and registers the Lookup a restart reconciles a reserved use by, reading
// only the stored action and the key, so no caller need be alive:
//
//	component  kinds                                                  Lookup's owner
//	outbox     mail_send                                              MAIL, registered by MCP-M9-01
//	gate       dns_set, dns_delete                                    DNS-M5-21's DnsClient.Lookup
//	grant      publish, listen, forward, access_request               ACL-M4-02
//	bridge     expose                                                 MCP-M4-01, on BridgeFiler.FindRule
//	evs        agent_config_write and _delete, alias_create, _delete  EVS1-M3-01's EvsRepo.Lookup
//	restore    restore                                                MCP-M3-22
//	sender     mail_tls_unauthenticated                               SmtpTlsPolicy.Lookup, registered by SMTP-M9-07
//
// A kind with no registered Lookup is refused before its Reserve, so no use is taken that a restart could not
// reconcile. A gate kind's effect is presented to §8.10's server gate, which consumes the use in the effect's own
// transaction: such a use reserves until not_after minus §8.6's skew, and a refusal on a second presentation proves
// nothing, since the first may still commit, so it reads uncertain.
//
// The spend a use runs under reaches its effect and its Lookup on the context (ApprovalSpendFromContext): a gate
// kind's component carries those decisions and that action to the server gate (§16.6's flow), which reads no other
// field. Safe for concurrent use. On every leg but the ios_extension legs, whose forwarding role spends nothing.

package sidecar

import (
	"bytes"
	"context"
	"sync"
)

// Whether a kind's effect is consumed at §8.10's server gate rather than on this device: in v0 only §12.8's POST
// /dns/records, since grant activations use grant_id (§16.6's server row).
func sidecarActionServerGated(kind SidecarActionKind) bool {
	return kind == SidecarActionDnsSet || kind == SidecarActionDnsDelete
}

// Registers kind's Lookup for this sidecar's gate, replacing any before; the answer removes it, if it is still the
// registered one, after which the kind is refused before its Reserve again.
func (self *Sidecar) RegisterEffectLookup(kind SidecarActionKind, lookup SidecarEffectLookup) func() {
	entry := &sidecarEffectLookupEntry{lookup: lookup}
	func() {
		self.records.stateLock.Lock()
		defer self.records.stateLock.Unlock()
		if self.records.effectLookups == nil {
			self.records.effectLookups = map[SidecarActionKind]*sidecarEffectLookupEntry{}
		}
		self.records.effectLookups[kind] = entry
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			self.records.stateLock.Lock()
			defer self.records.stateLock.Unlock()
			if self.records.effectLookups[kind] == entry {
				delete(self.records.effectLookups, kind)
			}
		})
	}
}

// The Lookup registered for kind, nil for none.
func (self *Sidecar) effectLookup(kind SidecarActionKind) SidecarEffectLookup {
	self.records.stateLock.Lock()
	defer self.records.stateLock.Unlock()
	entry := self.records.effectLookups[kind]
	if entry == nil || entry.lookup == nil {
		return nil
	}
	return entry.lookup
}

// The spend one use runs under, which a gate kind's component carries to §8.10's server gate with Idempotency-Key:
// <effect_key>. Read-only once set.
type ApprovalSpend struct {
	ApprovalId Id
	// Each decision the use spends on, its Signed as stored.
	Decisions [][]byte
	// The action the decisions hash, as stored: the use's own, or the template it falls inside.
	Action []byte
	// What the approved request binds beside its action, the socket name, local port, weight and ALPNs every decision's
	// request_sha256 covers (QD-740, QD-772), which the effect applies; nil for none.
	Detail *SidecarActionDetail
}

// The context key of an ApprovalSpend.
type approvalSpendContextKey struct{}

// ctx carrying spend, a copy.
func withApprovalSpend(ctx context.Context, spend *ApprovalSpend) context.Context {
	copied := &ApprovalSpend{ApprovalId: spend.ApprovalId, Action: bytes.Clone(spend.Action), Detail: spend.Detail.clone()}
	for _, decision := range spend.Decisions {
		copied.Decisions = append(copied.Decisions, bytes.Clone(decision))
	}
	return context.WithValue(ctx, approvalSpendContextKey{}, copied)
}

// The spend an effect or a Lookup runs under, false under a standing grant, which spends none.
func ApprovalSpendFromContext(ctx context.Context) (*ApprovalSpend, bool) {
	spend, ok := ctx.Value(approvalSpendContextKey{}).(*ApprovalSpend)
	return spend, ok && spend != nil
}
