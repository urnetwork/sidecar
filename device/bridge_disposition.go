// §17.8's disposition, the provider side (D-BRIDGE-7, D-BRIDGE-21): which rule tags a newly published state no longer
// keeps, so the bridge ends their flows with CloseFlows after the swap. A tag names a (subject, rule) pair
// (plan-BRIDGE-small-readings #11), so the bridge enumerates a subject's tags from its rows and the pseudo rules without
// tracking the flows it admitted.
//
// Each tag a state admits under, at a time, rests on atoms: the rows and rules its flows could have been admitted by.
// A tag whose atoms at the last publish are not all present now has lost something one of its flows may have stood on,
// and since a tag cannot tell its flows apart, all of them end:
//
//	every tag of a subject    the subject is gone, revoked or suspended, by the state or between states, or the state
//	                          denies every Network flow (pending, refused rules, legacy at a host)
//	(subject, map)            the map, while kept: in force, or draining until its drain ends, its flows kept and no new
//	                          ones taken; and the subject's dial rows
//	(subject, 3, address)     the hosted address, until its block's drain ends; the subject's dial rows; the allow-all,
//	                          which a document or a tag ends
//	(subject, 4)              the allow-all
//	(subject, route)          the served route, until its drain ends, and its remap, until its block's; the subject's
//	                          route rows that meet it; the allow-all for a remap
//	(subject, 7)              the subject's exit rows, and at a host that it serves an exit
//
// So a revocation or an expiry resets at once, an edit drains: a removed route or address keeps admitting until
// max(drain_seconds, 600 s), a retargeted map keeps only the flows it opened, and then their tags end. Rule 3's tag
// names the hosted address (bridge-m4-11-rule-three-tags, DESIGN-DETAILS 12.2.2), so an old address's drain end closes
// its own flows and none to the new address. Elsewhere a tag is coarse, and an ending reaches every flow of its pair: a
// revoked grant ends the subject's flows under every rule the grant reached.
//
// A rule 0 change ends nothing: an open flow is connected to wherever it was dialed, and rule 0 is checked per flow.

package device

import (
	"fmt"
	"net/netip"
	"slices"
	"time"
)

// A tag's atoms: the rows and rules its flows could stand on.
type bridgeAdmission map[uint64]map[string]bool

// Adds an atom to a tag's.
func (self bridgeAdmission) add(tag uint64, atoms ...string) {
	held := self[tag]
	if held == nil {
		held = map[string]bool{}
		self[tag] = held
	}
	for _, atom := range atoms {
		held[atom] = true
	}
}

// A row's atom: what it admits and until when, and its grant.
func (self *bridgePolicyReach) atom(kind string) string {
	return fmt.Sprintf("%s:%x:%v:%d:%v:%d", kind, self.grantId, self.prefix, self.protocol, self.ports, self.expires.UnixMilli())
}

// The atoms of a subject's rows that admit at a time, of one kind.
func bridgeReachAtoms(kind string, rows []bridgePolicyReach, at time.Time, meets func(row *bridgePolicyReach) bool) []string {
	atoms := []string{}
	for i := range rows {
		row := &rows[i]
		if row.revoked || (!row.expires.IsZero() && !at.Before(row.expires)) {
			continue
		}
		if meets != nil && !meets(row) {
			continue
		}
		atoms = append(atoms, row.atom(kind))
	}
	return atoms
}

// Whether a map keeps its flows at a time: in force, or draining until its drain ends, or until the next state times
// a drain begun between states.
func (self *bridgePolicyState) mapKept(policyMap *bridgePolicyMap, at time.Time) bool {
	if policyMap.withdrawn || (!policyMap.expires.IsZero() && !at.Before(policyMap.expires)) {
		return false
	}
	if self.lapsedInPreviousBlock(policyMap.match.Addr(), at) {
		return false
	}
	return !policyMap.draining || policyMap.drainEnd.IsZero() || at.Before(policyMap.drainEnd)
}

// The tags this state admits under at a time, and their atoms (the file's comment).
func (self *bridgePolicyState) admission(profile BridgePolicyProfile, at time.Time) bridgeAdmission {
	admission := bridgeAdmission{}
	if !self.posture.Enforcing() || self.rulesRefused {
		return admission
	}
	sdk := profile == BridgePolicyProfileSdkProvider
	subjects := make([]*bridgePolicySubject, 0, len(self.subjectBySidecarId)+1)
	for _, subject := range self.subjectBySidecarId {
		subjects = append(subjects, subject)
	}
	if sdk {
		subjects = append(subjects, self.otherClient)
	}
	hostedAddrs := []netip.Addr{}
	for _, addr := range self.hostedAddrs {
		if !self.lapsedInPreviousBlock(addr, at) {
			hostedAddrs = append(hostedAddrs, addr)
		}
	}
	servesExit := self.servesExit(at)
	for _, subject := range subjects {
		if !subject.admitted || (!sdk && !subject.hasIdentity) {
			continue
		}
		tag := func(ruleId []byte) uint64 {
			return BridgeRuleTag(subject.sidecarId, ruleId)
		}
		allowAll := self.posture == PostureEnforcingNoDocument && !subject.tagged
		allowAllAtoms := []string{}
		if allowAll {
			allowAllAtoms = append(allowAllAtoms, "allow_all")
			admission.add(tag([]byte{BridgeRuleAllowAll}), allowAllAtoms...)
		}
		exitAtoms := bridgeReachAtoms("exit", subject.exit, at, nil)
		if 0 < len(exitAtoms) && (sdk || servesExit) {
			if !sdk {
				exitAtoms = append(exitAtoms, "serves_exit")
			}
			admission.add(tag([]byte{BridgeRuleExit}), exitAtoms...)
		}
		if sdk {
			continue
		}
		dialAtoms := bridgeReachAtoms("dial", subject.dial, at, nil)
		if 0 < len(dialAtoms) {
			for _, policyMap := range self.maps {
				if self.mapKept(policyMap, at) {
					mapAtom := fmt.Sprintf("map:%x:%v:%d:%v:%v:%d", policyMap.mapId, policyMap.match, policyMap.protocol,
						policyMap.ports, policyMap.target, policyMap.targetPort)
					admission.add(tag(policyMap.mapId), append(slices.Clone(dialAtoms), mapAtom)...)
				}
			}
		}
		if allowAll || 0 < len(dialAtoms) {
			// one tag an address, so an address's end closes its flows alone
			for _, addr := range hostedAddrs {
				ruleId := bridgeHostedRuleId(addr)
				admission.add(tag(ruleId[:]), slices.Concat([]string{"hosted:" + addr.String()}, dialAtoms, allowAllAtoms)...)
			}
		}
		for _, served := range self.served {
			if served.exit || !served.admits(at) {
				continue
			}
			remapKept := served.exposed.IsValid() && !self.lapsedInPreviousBlock(served.exposed.Addr(), at)
			routeAtoms := bridgeReachAtoms("route", subject.route, at, func(row *bridgePolicyReach) bool {
				return row.prefix.Overlaps(served.prefix) || (served.exposed.IsValid() && row.prefix.Overlaps(served.exposed))
			})
			atoms := slices.Clone(routeAtoms)
			if remapKept && allowAll {
				atoms = append(atoms, allowAllAtoms...)
			}
			if len(atoms) == 0 {
				continue
			}
			atoms = append(atoms, fmt.Sprintf("served:%x:%v", served.routeId, served.prefix))
			if remapKept {
				atoms = append(atoms, fmt.Sprintf("remap:%x:%v", served.routeId, served.exposed))
			}
			admission.add(tag(served.routeId), atoms...)
		}
	}
	return admission
}

// The tags previous admitted under at previousAt whose atoms next, at now, no longer holds all of, sorted (the file's
// comment). At an sdk provider legacy passes every flow, as no hook does, so a move to it ends nothing.
func bridgeDispositionTags(
	previous *bridgePolicyState,
	previousAt time.Time,
	next *bridgePolicyState,
	now time.Time,
	profile BridgePolicyProfile,
) []uint64 {
	if profile == BridgePolicyProfileSdkProvider && next.posture == PostureLegacy {
		return nil
	}
	before := previous.admission(profile, previousAt)
	after := next.admission(profile, now)
	tags := []uint64{}
	for tag, atoms := range before {
		kept := after[tag]
		for atom := range atoms {
			if !kept[atom] {
				tags = append(tags, tag)
				break
			}
		}
	}
	slices.Sort(tags)
	return tags
}
