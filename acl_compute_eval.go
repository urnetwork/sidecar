// §16.2's evaluation over one AclState (DESIGN-COMPUTE §16.2, §16.6; D-CACL-1; CACL-M12-04): ComputeAllows answers
// whether a subject may take one of §16.2's actions on its resource, by the rows alone, so a device (the router's
// model: infer, the search tool's query, an enclave create, a buy) and the broker, which reads the same signed rows,
// judge alike:
//
//	infer           a rule in force naming the subject in its src, infer among its actions and a model_glob target
//	                that matches the model's canonical name; a glob is never read as a label, so a grant never
//	                passes the network's floor or the person's tee_only, which ComputeModelGate holds apart, and a
//	                local model needs no grant (CO-9), so the router never asks for one
//	create, admin   a compute_resource target of compute:enclave; admin stops or deletes another subject's enclave
//	buy             compute:buy's, beside the Owner's and Billing admin's roles, which api checks (§9.10)
//	query           compute:search's
//	ssh             a subject target naming the destination, the enclave's incarnation, as dial's do; its users and
//	                check period are the device's (AclLocalSsh), which the enclave's SSH server holds a login to
//
// A subject hard denied, revoked, parked, suspended or past its admission, takes nothing, as every check's. listener:
// targets are indexed here and evaluated at the host's hook (LSTN's C§26.7).
//
// Each check reads the state's rules in order and allocates nothing beyond the subject's resolution: the rules are
// bounded by the tier's acl_rules. On every leg, as acl_eval.go is.

package sidecar

import (
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// What one of §16.2's checks asks about: a model by its canonical name, a compute: resource, or a subject for ssh.
type AclComputeTarget struct {
	// infer's: the canonical name the call runs, its effort included.
	Model string
	// create, admin, buy and query's.
	Resource protocol.AclComputeResource
	// ssh's: the enclave's incarnation, or another subject; zero for the other actions.
	Subject AclSubject
}

// A rule's §16.2 targets, beside aclRule's own: what classifyTarget sorts model_glob, compute_resource and listener
// targets into.
type aclComputeRuleTargets struct {
	modelGlobs []string
	resources  []protocol.AclComputeResource
	// listener: targets' atoms, which LSTN's hook evaluates
	listenerAtoms []int32
}

// Sorts one of §16.2's targets into the rule's compute targets; false for a target of another kind.
func (self *AclState) classifyComputeTarget(rule *aclRule, target *protocol.AclTarget, field string) (bool, error) {
	compute := func() *aclComputeRuleTargets {
		if self.computeTargets == nil {
			self.computeTargets = map[int32]*aclComputeRuleTargets{}
		}
		targets := self.computeTargets[rule.index]
		if targets == nil {
			targets = &aclComputeRuleTargets{}
			self.computeTargets[rule.index] = targets
		}
		return targets
	}
	switch {
	case target.GetModelGlob() != "":
		if !aclComputeModelGlob(target.GetModelGlob(), DefaultAclComputeBlockSettings()) {
			return true, aclRowsRefusal("%s.model_glob is no glob within canonical names", field)
		}
		compute().modelGlobs = append(compute().modelGlobs, target.GetModelGlob())
		return true, nil
	case target.GetComputeResource() != protocol.AclComputeResource_ACL_COMPUTE_RESOURCE_UNSPECIFIED:
		if aclComputeResourceName(target.GetComputeResource()) == "" {
			return true, aclRowsRefusal("%s names a compute resource this build does not know", field)
		}
		compute().resources = append(compute().resources, target.GetComputeResource())
		return true, nil
	case len(target.GetListener()) != 0:
		atom, err := aclRowsId(target.GetListener(), field+".listener")
		if err != nil {
			return true, err
		}
		compute().listenerAtoms = append(compute().listenerAtoms, self.atomIndex(atom))
		return true, nil
	}
	return false, nil
}

// How many of §16.2's target kinds a target sets, which classifyTarget counts beside §8.4's.
func aclComputeTargetKindCount(target *protocol.AclTarget) int {
	count := 0
	for _, set := range []bool{
		target.GetModelGlob() != "",
		target.GetComputeResource() != protocol.AclComputeResource_ACL_COMPUTE_RESOURCE_UNSPECIFIED,
		len(target.GetListener()) != 0,
	} {
		if set {
			count += 1
		}
	}
	return count
}

// Whether subject may take action on target at now, by a rule in force, as the file header says. The decision names the
// rule that allowed it, or why it refused: the subject's hard deny, ssh's destination's, or AclReasonNoGrant.
func (self *AclState) ComputeAllows(subject AclSubject, target AclComputeTarget, action protocol.AclAction, now time.Time) AclDecision {
	if !aclComputeAction(action) && action != protocol.AclAction_ACL_ACTION_ADMIN {
		return aclDeny(AclReasonNoGrant)
	}
	nowMs := now.UnixMilli()
	source := self.resolve(&subject, nowMs)
	if source.deny != 0 {
		return aclDeny(source.deny)
	}
	var destination aclResolved
	if action == protocol.AclAction_ACL_ACTION_SSH {
		if target.Subject.Kind == 0 {
			return aclDeny(AclReasonNoGrant)
		}
		destination = self.resolve(&target.Subject, nowMs)
		if destination.deny != 0 {
			return aclDeny(destination.deny)
		}
	}
	for i := range self.rules {
		rule := &self.rules[i]
		if !rule.activeAt(nowMs) || !rule.allows(action) || !self.inSrc(&source, rule) {
			continue
		}
		if self.computeRuleTakes(rule, &source, &destination, &target, action) {
			return aclAllowRule(rule)
		}
	}
	return aclDeny(AclReasonNoGrant)
}

// Whether subject holds atomId at now: an autogroup it is in, a tag or group atom whose row names it or its member, or
// its own derived atom; false for a subject hard denied. What a compute block's budget row binds (ComputePolicyBudgetsBinding).
func (self *AclState) SubjectHoldsAtom(subject AclSubject, atomId Id, now time.Time) bool {
	resolved := self.resolve(&subject, now.UnixMilli())
	if resolved.deny != 0 {
		return false
	}
	if autogroup, isAutogroup := aclAtomAutogroup(atomId); isAutogroup {
		bit := aclAutogroupBit(autogroup)
		if resolved.sidecar != nil {
			return resolved.sidecar.autogroups&bit != 0
		}
		return resolved.autogroups&bit != 0
	}
	index, known := self.atomIndexes[atomId]
	if !known {
		return false
	}
	if resolved.sidecar != nil {
		_, found := slices.BinarySearch(resolved.sidecar.atoms, index)
		return found
	}
	return self.holdsAtom(&resolved, index)
}

// Whether rule's targets take action on target.
func (self *AclState) computeRuleTakes(rule *aclRule, source *aclResolved, destination *aclResolved, target *AclComputeTarget, action protocol.AclAction) bool {
	if action == protocol.AclAction_ACL_ACTION_SSH {
		return self.targetsSubject(source, destination, rule)
	}
	targets := self.computeTargets[rule.index]
	if targets == nil {
		return false
	}
	switch action {
	case protocol.AclAction_ACL_ACTION_INFER:
		return target.Model != "" && slices.ContainsFunc(targets.modelGlobs, func(glob string) bool {
			return AclComputeModelGlobMatch(glob, target.Model)
		})
	}
	return slices.Contains(targets.resources, target.Resource) &&
		slices.Contains(aclComputeResourceActions[target.Resource], action)
}
