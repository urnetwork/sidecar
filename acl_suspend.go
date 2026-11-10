//go:build !ios_extension

// §8.6's one switch on a client (D-ACL-8): a Suspend, a revocation or a cascade park removes a subject's atoms and
// activations across client generations, since every check keys on its sidecar_id, and hard deny wins over every
// grant. A sidecar whose next state newly hard-denies a subject does, in this order:
//
//	install   the new state and its local policy into the AclEngine, so every check from here on refuses the subject
//	streams   resets every open stream with the subject (§6)
//	aliases   drops the aliases the subject held (§15.10)
//	flows     hands the subject to the bridge's CloseFlows, BRIDGE-M4-11's Bridge.Revoke (C-15)
//
// The policy is swapped before CloseFlows (D-BRIDGE-21), so a flow the bridge closes cannot be admitted again by the
// state it closed under. Each step is idempotent: a second Apply of a state already installed finds no subject newly
// denied and does nothing. The server's half, closing the subject's open contracts so forwarding stops within the 5 s
// positive-cache bound, is server/model's CloseAclSubjectContracts.
//
// A Suspend of an agent a live Delegation admitted also drops that Delegation's shared reader key at its position,
// which TEAM's rows take from AclStatementEffect (acl_statement.go's configApplyAclEffect), so the next generation
// reaches its other agents only by their own wraps; an Unsuspend returns the agent uncovered (§10.5). A Suspend never
// changes AdminSet or its n.
//
// On every leg, the sidecar_http page Worker's included: root Id, no connect type.

package sidecar

import (
	"slices"
	"time"
)

// What a client does to a subject its state newly hard-denies. The calls must not block on the subject: each hands
// its work to its own owner and returns.
type AclSuspendHooks interface {
	// Resets every open stream with the subject, and says how many.
	ResetStreams(subjectId Id) int
	// Drops every alias the subject held, and says how many.
	DropAliases(subjectId Id) int
	// Closes the subject's flows (BRIDGE-M4-11's Bridge.Revoke), and says how many.
	CloseFlows(subjectId Id) int
}

// What one Apply did.
type AclSuspendReport struct {
	// The sidecars the new state hard-denies and the installed one did not, sorted.
	DeniedSidecarIds []Id
	Streams          int
	Aliases          int
	Flows            int
}

// The one switch's client side over one engine.
type AclSuspendEffects struct {
	engine *AclEngine
	hooks  AclSuspendHooks
}

// The effects for an engine and the components that hold a subject's streams, aliases and flows.
func NewAclSuspendEffects(engine *AclEngine, hooks AclSuspendHooks) *AclSuspendEffects {
	return &AclSuspendEffects{engine: engine, hooks: hooks}
}

// The sidecars next hard-denies at now that previous did not: suspended, revoked, parked, past their not_after or
// their member gone, sorted. With no previous state, every one next hard-denies.
func AclNewlyDenied(previous *AclState, next *AclState, now time.Time) []Id {
	nowMs := now.UnixMilli()
	denied := []Id{}
	for i := range next.sidecars {
		sidecar := &next.sidecars[i]
		if sidecar.hardDeny(nowMs) == 0 {
			continue
		}
		if previous != nil {
			if before := previous.sidecarState(sidecar.id); before != nil && before.hardDeny(nowMs) != 0 {
				continue
			}
		}
		denied = append(denied, sidecar.id)
	}
	slices.SortFunc(denied, Id.Cmp)
	return denied
}

// Installs next and applies the one switch to every sidecar it newly hard-denies: the policy first, then each
// subject's streams, aliases and flows. An Install the engine refuses applies nothing.
func (self *AclSuspendEffects) Apply(next *AclState, local *AclLocalPolicy, now time.Time) (*AclSuspendReport, error) {
	previous := self.engine.State()
	report := &AclSuspendReport{}
	if previous == next {
		return report, nil
	}
	report.DeniedSidecarIds = AclNewlyDenied(previous, next, now)
	if err := self.engine.Install(next, local); err != nil {
		return nil, err
	}
	for _, subjectId := range report.DeniedSidecarIds {
		testHookBarrier("acl_suspend.streams", subjectId.String())
		report.Streams += self.hooks.ResetStreams(subjectId)
		testHookBarrier("acl_suspend.aliases", subjectId.String())
		report.Aliases += self.hooks.DropAliases(subjectId)
		testHookBarrier("acl_suspend.flows", subjectId.String())
		report.Flows += self.hooks.CloseFlows(subjectId)
	}
	return report, nil
}
