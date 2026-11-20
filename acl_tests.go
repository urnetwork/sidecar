//go:build !ios_extension

// §8.5's tests, which the writer's device runs over the compiled result before it signs a head (D-ACL-9; QD-592): a
// failing test blocks the head, and readers never rerun them at replay. AclPolicyTestRun compiles the document from the
// same input CompileAcl reads, builds the state the rows evaluate to over the writer's view, and holds each test's
// src to every accept and deny.
//
// How a test reads a selector or a set (ACL-M2-01's open reading, settled here):
//
//	src, dst subject   one subject the selector names: user:<email> a new member device of that member, tag:<name> a
//	                   tagged sidecar carrying it and no other tag, autogroup:<name> a new subject of that class (a
//	                   member device of a new member of the role, a tagged sidecar carrying one tag no table names, an
//	                   untagged ephemeral one, an app device, an anonymous visitor), sidecar:<id> and client:<id> the
//	                   subject itself, network:<net> that network, role: and principal: an app device holding it;
//	                   group:<name> every member of the group, each as a user, so an accept holds for all of them and a
//	                   deny for none; as a destination, autogroup:self another new device of the source's own member. A
//	                   new subject is admitted by no one's consent, so an owner-bound read never passes on one
//	names              a socket, repo, host or alias check names one: a glob or a bare * fails the test, since a deny
//	                   over a set checked at any one name would pass unseen
//	ip                 a CIDR is a set an accept must hold whole and a deny must not touch at any address, by each route
//	                   rule's prefixes (§8.8's Saving). A route rule that names no ip: destination, no * and no
//	                   autogroup:internet reaches the routes in force of a sidecar among both its via subjects and its
//	                   subject destinations for the source (owner decision 575), which no save can see, so it holds no
//	                   accept, and it fails every deny where it names such a sidecar for the source: one the writer's
//	                   state holds, a test's subject, or a new one of a class its via and destinations name, as above,
//	                   with a tagged one carrying every tag it names and, for autogroup:self, another new device of the
//	                   source's own member and a tagged sidecar that member sponsors. The failure names the rule by its
//	                   grant's index (owner decision 615)
//	ports              a dial check with ports holds at every port of the range for an accept and at none for a deny,
//	                   at a sidecar destination, whose own engine checks ports; with none it is the rows' dial alone;
//	                   a route check's ports meet a rule's ports before its prefixes do
//
// A check this runner cannot judge, a user resolve does not hold, a repo label the labels file does not hold, a set,
// fails its test: a test passes only on what was shown. Failures name the test and its check by index, never a value
// (I-13); the person's own device shows the document's text beside them.

package sidecar

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A document's tests did not all pass: the head is not signed (D-ACL-9).
var ErrAclPolicyTests = errors.New("acl policy tests failed")

// One check of one test that did not pass, or a test that could not run.
type AclPolicyTestFailure struct {
	// The test's index among tests.
	Test int
	// "src" for the test as a whole, else "accept" or "deny".
	List string
	// The check's index in its list; -1 for src.
	Check int
	// Why: refused and its reason for an accept, allowed for a deny, or what could not be judged.
	Reason string
}

// The failure as a preview line, which names no value.
func (self AclPolicyTestFailure) String() string {
	if self.List == "src" {
		return fmt.Sprintf("tests[%d].src: %s", self.Test, self.Reason)
	}
	return fmt.Sprintf("tests[%d].%s[%d]: %s", self.Test, self.List, self.Check, self.Reason)
}

// One run's answer.
type AclPolicyTestReport struct {
	TestCount  int
	CheckCount int
	Failures   []AclPolicyTestFailure
	// The tests ran over the document's own world, no state of the network's (AclPolicyTestOver).
	DocumentAlone bool
}

// Whether every test passed.
func (self *AclPolicyTestReport) Passed() bool {
	return self != nil && len(self.Failures) == 0
}

// nil when every test passed, else ErrAclPolicyTests naming each failure.
func (self *AclPolicyTestReport) Err() error {
	if self.Passed() {
		return nil
	}
	if self == nil {
		return fmt.Errorf("%w: no report", ErrAclPolicyTests)
	}
	lines := make([]string, 0, len(self.Failures))
	for _, failure := range self.Failures {
		lines = append(lines, failure.String())
	}
	return fmt.Errorf("%w: %s", ErrAclPolicyTests, strings.Join(lines, "; "))
}

// What a run reads: the compile's input, whose policy and tables the tests name through, and the view of the state the
// rows evaluate over, the writer's own.
type AclPolicyTestInput struct {
	Compile *AclCompileInput
	View    AclAuthView
	// The time the tests judge at.
	Now time.Time
}

// Runs the document's tests over its compiled result. An error is a document that does not compile; failing tests
// come back in the report.
func AclPolicyTestRun(input *AclPolicyTestInput) (*AclPolicyTestReport, error) {
	if input == nil || input.Compile == nil || input.View == nil {
		return nil, fmt.Errorf("%w: no input", ErrAclCompile)
	}
	compiler, err := newAclCompiler(input.Compile)
	if err != nil {
		return nil, err
	}
	run := &aclTestRun{
		compiler:     compiler,
		probes:       newAclTestProbeView(input.View),
		nowMs:        input.Now.UnixMilli(),
		report:       &AclPolicyTestReport{TestCount: len(compiler.policy.Tests)},
		grantIndexes: map[Id]int{},
	}
	// each grant's rule id, the first of identical grants naming the rule they compile to
	keys, err := AclPolicyRuleKeys(compiler.policy)
	if err != nil {
		return nil, err
	}
	for i := range compiler.policy.Grants {
		ruleId, err := compiler.ruleId(keys[i], uint32(i))
		if err != nil {
			return nil, err
		}
		if _, found := run.grantIndexes[ruleId]; !found {
			run.grantIndexes[ruleId] = i
		}
	}
	// every subject a test names first, since the state is built once over all of them, then the sidecars a route rule
	// that names no prefix could route through
	plans := make([]aclTestPlan, len(compiler.policy.Tests))
	for i, test := range compiler.policy.Tests {
		plans[i] = run.plan(i, test)
	}
	run.addRouteStandIns(plans)
	state, err := NewAclState(compiler.rows, run.probes)
	if err != nil {
		return nil, err
	}
	run.state = state
	run.localRules = make([]*AclLocalRule, len(state.rules))
	for i := range state.rules {
		run.localRules[i] = compiler.local.Rule(state.rules[i].row.GetRuleId())
	}
	run.engines = map[Id]*AclEngine{}
	run.engine = run.engineFor(Id{})
	for i := range plans {
		run.judge(&plans[i])
	}
	return run.report, nil
}

// One test made ready: its sources, and each check's destinations where it names subjects.
type aclTestPlan struct {
	index       int
	test        AclPolicyTest
	sources     []AclSubject
	srcUnjudged string
	accept      []aclTestCheckPlan
	deny        []aclTestCheckPlan
}

// One check made ready: why it cannot be judged, or, for a subject check, the destinations it names for each source.
type aclTestCheckPlan struct {
	unjudged string
	// by source index; autogroup:self names another device of that source's own member
	destinations [][]AclSubject
}

// One run's working state.
type aclTestRun struct {
	compiler   *aclCompiler
	probes     *aclTestProbeView
	state      *AclState
	localRules []*AclLocalRule
	engine     *AclEngine
	engines    map[Id]*AclEngine
	nowMs      int64
	report     *AclPolicyTestReport
	// the index of the first grant compiling to each rule id, by which a failure names a rule
	grantIndexes map[Id]int
}

// The subjects a test names, made where they are none of the view's.
func (self *aclTestRun) plan(index int, test AclPolicyTest) aclTestPlan {
	plan := aclTestPlan{index: index, test: test}
	label := fmt.Sprintf("tests[%d]", index)
	plan.sources, plan.srcUnjudged = self.subjects(test.Src, label+".src")
	checkPlans := func(list string, checks []AclPolicyCheck) []aclTestCheckPlan {
		plans := make([]aclTestCheckPlan, len(checks))
		for j, check := range checks {
			checkPlan := &plans[j]
			checkLabel := fmt.Sprintf("%s.%s[%d]", label, list, j)
			checkPlan.unjudged = aclTestCheckUnjudged(check)
			if checkPlan.unjudged == "" && check.Resource.Kind == AclResourceRepo && check.Resource.RepoId == (Id{}) {
				if _, found := self.compiler.labelRepoIds[check.Resource.Name]; !found {
					checkPlan.unjudged = "a repo label the labels file does not hold"
				}
			}
			if checkPlan.unjudged != "" || check.Resource.Kind != AclResourceSubject {
				continue
			}
			destination := check.Resource.Subject
			if destination.Kind == AclSelectorAutogroup && destination.Autogroup == protocol.AclAutogroup_ACL_AUTOGROUP_SELF {
				for si, source := range plan.sources {
					memberId, found := self.probes.ownerOf(source)
					if !found {
						checkPlan.unjudged = "a source with no owner, for whom autogroup:self names no one"
						break
					}
					checkPlan.destinations = append(checkPlan.destinations,
						[]AclSubject{self.probes.memberDevice(fmt.Sprintf("%s.self[%d]", checkLabel, si), memberId, false)})
				}
				continue
			}
			subjects, unjudged := self.subjects(destination, checkLabel)
			checkPlan.unjudged = unjudged
			for range plan.sources {
				checkPlan.destinations = append(checkPlan.destinations, subjects)
			}
		}
		return plans
	}
	plan.accept = checkPlans("accept", test.Accept)
	plan.deny = checkPlans("deny", test.Deny)
	return plan
}

// Why a check names what no test can judge, empty when it names one thing.
func aclTestCheckUnjudged(check AclPolicyCheck) string {
	resource := check.Resource
	switch resource.Kind {
	case AclResourceAll:
		return "a check over a set: name one resource"
	case AclResourceSocket, AclResourceDns, AclResourceMail:
		if strings.Contains(resource.Name, "*") {
			return "a check over a set of names: name one"
		}
	case AclResourceRepo:
		if resource.RepoId == (Id{}) && strings.Contains(resource.Name, "*") {
			return "a check over a set of repos: name one"
		}
	case AclResourceIp:
		if !resource.Cidr.IsValid() {
			return "an ip: name hosts does not hold"
		}
		if check.Action != protocol.AclAction_ACL_ACTION_ROUTE {
			return "an ip: resource takes only route"
		}
	case AclResourceSubject:
		switch check.Action {
		case protocol.AclAction_ACL_ACTION_DIAL, protocol.AclAction_ACL_ACTION_ROUTE:
		default:
			return "a subject takes only dial and route"
		}
	}
	return ""
}

// The subjects a selector names for a test, or why it names none the test can stand for.
func (self *aclTestRun) subjects(selector AclSelector, label string) ([]AclSubject, string) {
	compiler := self.compiler
	switch selector.Kind {
	case AclSelectorUser:
		memberId, found := compiler.memberIds[selector.Name]
		if !found {
			return nil, "a user resolve does not hold"
		}
		if self.probes.Member(memberId) == nil {
			return nil, "a user the state does not hold"
		}
		return []AclSubject{self.probes.memberDevice(label, memberId, false)}, ""
	case AclSelectorGroup:
		memberIds, err := compiler.groupMembers(selector)
		if err != nil {
			return nil, "a group whose users resolve does not hold"
		}
		subjects := []AclSubject{}
		for i, memberId := range memberIds {
			subjects = append(subjects, self.probes.memberDevice(fmt.Sprintf("%s.member[%d]", label, i), memberId, false))
		}
		if len(subjects) == 0 {
			return nil, "a group holding no member of the state"
		}
		return subjects, ""
	case AclSelectorTag:
		tagId, found := compiler.tagIds[selector.Name]
		if !found {
			return nil, "a tag the tags file does not hold"
		}
		return []AclSubject{self.probes.tagged(label, []Id{tagId}, Id{})}, ""
	case AclSelectorSidecar:
		if self.probes.Sidecar(selector.Id) == nil {
			return nil, "a sidecar the state does not hold"
		}
		return []AclSubject{AclSidecarSubject(selector.Id)}, ""
	case AclSelectorClient:
		if sidecarId, found := compiler.clientIds[selector.Id]; found && sidecarId != (Id{}) {
			return []AclSubject{AclSidecarSubject(sidecarId)}, ""
		}
		return []AclSubject{AclClientSubject(selector.Id, Id{}, nil, "")}, ""
	case AclSelectorRole:
		return []AclSubject{AclClientSubject(aclTestProbeId(label), Id{}, []string{selector.Name}, "")}, ""
	case AclSelectorPrincipal:
		return []AclSubject{AclClientSubject(aclTestProbeId(label), Id{}, nil, selector.Name)}, ""
	case AclSelectorNetwork:
		if selector.Name == "*" {
			return nil, "a check over every network: name one"
		}
		networkId, found := compiler.networkIds[selector.Name]
		if !found {
			return nil, "a network resolve does not hold"
		}
		return []AclSubject{AclRemoteSubject(networkId)}, ""
	case AclSelectorAutogroup:
		switch selector.Autogroup {
		case protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER, protocol.AclAutogroup_ACL_AUTOGROUP_SIDECAR,
			protocol.AclAutogroup_ACL_AUTOGROUP_NETWORK:
			return []AclSubject{self.probes.memberDevice(label, self.probes.member(label, bridge.MemberRole_MEMBER_ROLE_MEMBER), false)}, ""
		case protocol.AclAutogroup_ACL_AUTOGROUP_OWNER:
			return []AclSubject{self.probes.memberDevice(label, self.probes.member(label, bridge.MemberRole_MEMBER_ROLE_OWNER), false)}, ""
		case protocol.AclAutogroup_ACL_AUTOGROUP_ADMIN:
			return []AclSubject{self.probes.memberDevice(label, self.probes.member(label, bridge.MemberRole_MEMBER_ROLE_ADMIN), false)}, ""
		case protocol.AclAutogroup_ACL_AUTOGROUP_AUDITOR:
			return []AclSubject{self.probes.memberDevice(label, self.probes.member(label, bridge.MemberRole_MEMBER_ROLE_AUDITOR), false)}, ""
		case protocol.AclAutogroup_ACL_AUTOGROUP_EPHEMERAL:
			return []AclSubject{self.probes.memberDevice(label, self.probes.member(label, bridge.MemberRole_MEMBER_ROLE_MEMBER), true)}, ""
		case protocol.AclAutogroup_ACL_AUTOGROUP_TAGGED:
			return []AclSubject{self.probes.tagged(label, nil, Id{})}, ""
		case protocol.AclAutogroup_ACL_AUTOGROUP_UNTAGGED:
			return []AclSubject{AclClientSubject(aclTestProbeId(label), self.probes.member(label, bridge.MemberRole_MEMBER_ROLE_MEMBER), nil, "")}, ""
		case protocol.AclAutogroup_ACL_AUTOGROUP_PUBLIC:
			return []AclSubject{AclPublicSubject()}, ""
		}
		return nil, "an autogroup no subject stands for"
	}
	return nil, "a selector no subject stands for"
}

// Whether a grant is a route rule that names no prefix, which reaches the routes in force of a sidecar among both its
// via subjects and its subject destinations (§8.4's readings; owner decision 575): it allows route and names no ip:
// destination, no *, which gives every prefix, and no autogroup:internet, as aclRouteBySubject reads its compiled rule.
func aclTestRoutesBySubject(grant *AclGrant) bool {
	if !slices.Contains(grant.Allow, protocol.AclAction_ACL_ACTION_ROUTE) {
		return false
	}
	for _, resource := range grant.Dst {
		switch resource.Kind {
		case AclResourceIp, AclResourceAll:
			return false
		case AclResourceSubject:
			if resource.Subject.Kind == AclSelectorAutogroup && resource.Subject.Autogroup == protocol.AclAutogroup_ACL_AUTOGROUP_INTERNET {
				return false
			}
		}
	}
	return true
}

// Adds the sidecars a route rule that names no prefix could route a test's source through where the writer's state may
// hold none of their class yet (owner decision 615), as new subjects after every test's own, so they take the last
// admission positions. Only a run with an ip: deny takes any. For each grant aclTestRoutesBySubject holds: the subjects
// each of its via subjects and subject destinations names, as a test reads it (subjects), and a tagged sidecar carrying
// every tag it names, since one sidecar may carry them all; and where it names autogroup:self, for each source of a test
// with an ip: deny that has an owner, another new device of that member and a tagged sidecar the member sponsors
// carrying those tags. routeBySubjectReaches reads every sidecar of the state, so each of these only stands for its
// class, and one the writer's state already holds answers the same.
func (self *aclTestRun) addRouteStandIns(plans []aclTestPlan) {
	type testSource struct {
		label  string
		source AclSubject
	}
	sources := []testSource{}
	for i := range plans {
		plan := &plans[i]
		judgesIpDeny := false
		for j, check := range plan.test.Deny {
			judgesIpDeny = judgesIpDeny || (check.Resource.Kind == AclResourceIp && plan.deny[j].unjudged == "")
		}
		if plan.srcUnjudged != "" || !judgesIpDeny {
			continue
		}
		for si, source := range plan.sources {
			sources = append(sources, testSource{label: fmt.Sprintf("tests[%d].src[%d]", plan.index, si), source: source})
		}
	}
	if len(sources) == 0 {
		return
	}
	for i := range self.compiler.policy.Grants {
		grant := &self.compiler.policy.Grants[i]
		if !aclTestRoutesBySubject(grant) {
			continue
		}
		label := fmt.Sprintf("grants[%d]", i)
		namesSelf := false
		tagIds := []Id{}
		standIn := func(selector AclSelector, selectorLabel string) {
			if selector.Kind == AclSelectorAutogroup && selector.Autogroup == protocol.AclAutogroup_ACL_AUTOGROUP_SELF {
				namesSelf = true
				return
			}
			if selector.Kind == AclSelectorTag {
				if tagId, found := self.compiler.tagIds[selector.Name]; found && !slices.Contains(tagIds, tagId) {
					tagIds = append(tagIds, tagId)
				}
			}
			// a selector that names nothing a test can stand for adds nothing
			self.subjects(selector, selectorLabel)
		}
		for j, via := range grant.Via {
			standIn(via, fmt.Sprintf("%s.via[%d]", label, j))
		}
		for j, resource := range grant.Dst {
			if resource.Kind == AclResourceSubject {
				standIn(resource.Subject, fmt.Sprintf("%s.dst[%d]", label, j))
			}
		}
		if 1 < len(tagIds) {
			self.probes.tagged(label+".tags", tagIds, Id{})
		}
		if !namesSelf {
			continue
		}
		for _, held := range sources {
			memberId, found := self.probes.ownerOf(held.source)
			if !found {
				continue
			}
			self.probes.memberDevice(held.label+".self", memberId, false)
			self.probes.tagged(held.label+"."+label+".sponsored", tagIds, memberId)
		}
	}
}

// An engine whose own sidecar is sidecarId, over the run's state and local policy, made once: what checks a dial to that
// sidecar with ports. Its clock skew is none, so a test judges at exactly its time.
func (self *aclTestRun) engineFor(sidecarId Id) *AclEngine {
	if engine, found := self.engines[sidecarId]; found {
		return engine
	}
	engine := NewAclEngine(sidecarId, nil, nil, &AclEngineSettings{ClockSkew: 0})
	// the run's own state and policy, which nothing else holds, install at any pin
	_ = engine.Install(self.state, self.compiler.local)
	self.engines[sidecarId] = engine
	return engine
}

// Judges one test's checks, recording each failure.
func (self *aclTestRun) judge(plan *aclTestPlan) {
	fail := func(list string, check int, reason string) {
		self.report.Failures = append(self.report.Failures, AclPolicyTestFailure{Test: plan.index, List: list, Check: check, Reason: reason})
	}
	self.report.CheckCount += len(plan.test.Accept) + len(plan.test.Deny)
	if plan.srcUnjudged != "" {
		fail("src", -1, plan.srcUnjudged)
		return
	}
	lists := []struct {
		name   string
		want   bool
		checks []AclPolicyCheck
		plans  []aclTestCheckPlan
	}{
		{name: "accept", want: true, checks: plan.test.Accept, plans: plan.accept},
		{name: "deny", want: false, checks: plan.test.Deny, plans: plan.deny},
	}
	for _, list := range lists {
		for j, check := range list.checks {
			checkPlan := list.plans[j]
			if checkPlan.unjudged != "" {
				fail(list.name, j, checkPlan.unjudged)
				continue
			}
			for si, source := range plan.sources {
				var destinations []AclSubject
				if si < len(checkPlan.destinations) {
					destinations = checkPlan.destinations[si]
				}
				if reason := self.holds(source, check, destinations, list.want); reason != "" {
					fail(list.name, j, reason)
					break
				}
			}
		}
	}
}

// Whether one check holds for one source as want says: empty when it does, else why not.
func (self *aclTestRun) holds(source AclSubject, check AclPolicyCheck, destinations []AclSubject, want bool) string {
	answer := func(decision AclDecision) string {
		switch {
		case want && !decision.Allowed:
			return "refused: " + decision.Reason.String()
		case !want && decision.Allowed:
			return "allowed by " + decision.Reason.String()
		}
		return ""
	}
	now := time.UnixMilli(self.nowMs)
	resource := check.Resource
	switch resource.Kind {
	case AclResourceSubject:
		for _, destination := range destinations {
			if reason := self.holdsSubject(source, destination, check, want); reason != "" {
				return reason
			}
		}
		return ""
	case AclResourceSocket, AclResourceDns, AclResourceMail:
		result := self.engine.Check(source, check.Action, resource, now)
		return answer(AclDecision{Allowed: result.Allowed, Reason: result.Reason})
	case AclResourceRepo:
		repoResource := resource
		if repoResource.RepoId == (Id{}) {
			repoResource.RepoId = self.compiler.labelRepoIds[resource.Name]
		}
		result := self.engine.Check(source, check.Action, repoResource, now)
		return answer(AclDecision{Allowed: result.Allowed, Reason: result.Reason})
	case AclResourceIp:
		decision, bySubject := self.routeToPrefix(source, resource.Cidr, check.Ports, want)
		if bySubject {
			return "allowed by " + self.ruleName(decision.Rule) + ", which names no prefix: a sidecar among both its via " +
				"subjects and its destinations could serve any range by its routes in force"
		}
		return answer(decision)
	}
	return "a check no test can judge"
}

// A rule as a failure names it, by no value (I-13): its grant's index in the document, the first of identical grants,
// else its id, for a rule no grant of the document gave.
func (self *aclTestRun) ruleName(rule *protocol.AclRule) string {
	ruleId, err := IdFromBytes(rule.GetRuleId())
	if err != nil {
		return "a rule"
	}
	if index, found := self.grantIndexes[ruleId]; found {
		return fmt.Sprintf("grants[%d]", index)
	}
	return "rule " + ruleId.String()
}

// One subject check at one destination: dial through the destination's own engine where it is a sidecar and the
// check names ports, else the rows' dial; route through the rows.
func (self *aclTestRun) holdsSubject(source AclSubject, destination AclSubject, check AclPolicyCheck, want bool) string {
	now := time.UnixMilli(self.nowMs)
	answer := func(allowed bool, reason AclReason) string {
		switch {
		case want && !allowed:
			return "refused: " + reason.String()
		case !want && allowed:
			return "allowed by " + reason.String()
		}
		return ""
	}
	if check.Action == protocol.AclAction_ACL_ACTION_ROUTE {
		decision := self.state.MayRoute(source, netip.Addr{}, destination, now)
		return answer(decision.Allowed, decision.Reason)
	}
	if check.Ports == nil {
		decision := self.state.MayDial(source, destination, now)
		return answer(decision.Allowed, decision.Reason)
	}
	if destination.Kind != AclSubjectSidecar {
		return "ports at a destination that is no sidecar, whose own device checks them"
	}
	engine := self.engineFor(destination.Id)
	for port := uint64(check.Ports.First); port <= uint64(check.Ports.Last); port += 1 {
		decision := engine.AllowInbound(&AclInbound{Source: source, IpProtocol: check.Ports.Protocol, Port: uint32(port)}, now)
		if reason := answer(decision.Allowed, decision.Reason); reason != "" {
			return reason + " at port " + strconv.FormatUint(port, 10)
		}
	}
	return ""
}

// A route to a prefix: for an accept, a route rule in force whose prefixes hold the whole of it, at every port of the
// check's range; for a deny, whether any route rule in force reaches any address of it at any of those ports, by its
// prefixes, or, for a rule that names none, by naming for the source a sidecar among both its via subjects and its
// subject destinations, whose routes in force could serve any range (owner decision 615). Such a rule holds no accept,
// since no save sees what its sidecars' routes serve. The second answer is whether the decision's rule is one, which a
// deny's failure names.
func (self *aclTestRun) routeToPrefix(source AclSubject, cidr netip.Prefix, ports *AclPortRange, want bool) (AclDecision, bool) {
	portsMatch := func(local *AclLocalRule) bool {
		if ports == nil || local == nil || len(local.Ports) == 0 {
			return true
		}
		for _, held := range local.Ports {
			protocolMatches := held.Protocol == 0 || ports.Protocol == 0 || held.Protocol == ports.Protocol
			if !protocolMatches {
				continue
			}
			if want && held.First <= ports.First && ports.Last <= held.Last {
				return true
			}
			if !want && held.First <= ports.Last && ports.First <= held.Last {
				return true
			}
		}
		return false
	}
	sourceResolved := self.state.resolve(&source, self.nowMs)
	bySubject := false
	decision := self.state.resourceDecision(source, self.nowMs, protocol.AclAction_ACL_ACTION_ROUTE, func(rule *aclRule) bool {
		local := self.localRules[rule.index]
		if local == nil || !portsMatch(local) {
			return false
		}
		if aclRouteBySubject(local, rule.internetTarget) {
			bySubject = !want && self.routeBySubjectReaches(&sourceResolved, rule)
			return bySubject
		}
		for _, held := range local.Cidrs {
			if want && held.Bits() <= cidr.Bits() && held.Contains(cidr.Addr()) {
				return true
			}
			if !want && held.Overlaps(cidr) {
				return true
			}
		}
		return false
	})
	return decision, bySubject
}

// Whether a route rule that names no prefix names, for the source, a sidecar among both its via subjects and its subject
// destinations (owner decision 615): one whose routes in force, which no save sees, could serve any range. Every sidecar
// the state holds stands as one, the writer's, each test's subjects and addRouteStandIns' new ones, a hard-denied one
// too, since what counts is that the rule names it. A rule that names no via takes every advertiser whose route names
// it, and the filer names it in the route of any sidecar among its destinations (AclLocalPolicy.routeCovered), so there
// a destination alone is one. A sidecar the rule names by id that the state does not hold could be admitted as any, so
// it is one too, the closed direction.
func (self *aclTestRun) routeBySubjectReaches(source *aclResolved, rule *aclRule) bool {
	state := self.state
	unheld := func(sidecarIds []Id) bool {
		return slices.ContainsFunc(sidecarIds, func(sidecarId Id) bool { return state.sidecarState(sidecarId) == nil })
	}
	if unheld(rule.sidecarTargets) || (rule.viaNamed && unheld(rule.viaSidecars)) {
		return true
	}
	for i := range state.sidecars {
		subject := AclSidecarSubject(state.sidecars[i].id)
		candidate := state.resolve(&subject, self.nowMs)
		if (!rule.viaNamed || state.routeTakes(source, &candidate, rule)) && state.targetsSubject(source, &candidate, rule) {
			return true
		}
	}
	return false
}

// A new subject's id for a test: fixed by its label, so a run made twice names the same subjects.
func aclTestProbeId(label string) Id {
	digest := sha256.Sum256([]byte("urnetwork-sidecar-v1/acl-test-probe\x00" + label))
	return Id(digest[:aclAtomByteCount])
}

// The writer's view with the subjects tests stand for added: their admissions and their new members. A view never
// changes once a state is built from it, so probes are all added first.
type aclTestProbeView struct {
	base     AclAuthView
	sidecars map[Id]*AclSidecar
	members  map[Id]*bridge.MemberRow
	// a tagged probe's sponsor, where it has one
	sponsors map[Id]Id
	order    []Id
}

// A probe view over base holding no probe yet.
func newAclTestProbeView(base AclAuthView) *aclTestProbeView {
	return &aclTestProbeView{base: base, sidecars: map[Id]*AclSidecar{}, members: map[Id]*bridge.MemberRow{}, sponsors: map[Id]Id{}}
}

// The next admission position a probe takes, past every one the base holds.
func (self *aclTestProbeView) nextPosition() uint64 {
	return self.base.Pin().GetVersion() + uint64(len(self.order)) + 1
}

// The member a source's devices belong to: a probe's or an admitted sidecar's member, or a tagged one's live sponsor.
func (self *aclTestProbeView) ownerOf(subject AclSubject) (Id, bool) {
	switch subject.Kind {
	case AclSubjectSidecar:
		admission := self.Sidecar(subject.Id)
		if admission == nil {
			return Id{}, false
		}
		if admission.MemberId != (Id{}) {
			return admission.MemberId, true
		}
		return self.Sponsor(subject.Id)
	case AclSubjectClient:
		return subject.MemberId, subject.MemberId != (Id{})
	}
	return Id{}, false
}

// A new member of role, its id.
func (self *aclTestProbeView) member(label string, role bridge.MemberRole) Id {
	memberId := aclTestProbeId(label + ".member")
	self.members[memberId] = &bridge.MemberRow{MemberId: memberId.Bytes(), Role: role}
	return memberId
}

// A new untagged sidecar of a member, ephemeral or not: a member device, as a new admission would make it.
func (self *aclTestProbeView) memberDevice(label string, memberId Id, ephemeral bool) AclSubject {
	sidecarId := aclTestProbeId(label + ".device")
	if self.sidecars[sidecarId] == nil {
		self.sidecars[sidecarId] = &AclSidecar{
			Row:       &bridge.SidecarRow{SidecarId: sidecarId.Bytes(), MemberId: memberId.Bytes(), AdmittedAt: self.nextPosition(), Ephemeral: ephemeral},
			MemberId:  memberId,
			Ephemeral: ephemeral,
		}
		self.order = append(self.order, sidecarId)
	}
	return AclSidecarSubject(sidecarId)
}

// A new tagged sidecar carrying exactly tagIds, or with none one tag no table names, so it holds autogroup:tagged and no
// tag's atom: an admission names tags or a member, and one naming neither is no admission at all. Sponsored by
// sponsorId, or with a zero one by no member, so autogroup:admin stands in.
func (self *aclTestProbeView) tagged(label string, tagIds []Id, sponsorId Id) AclSubject {
	sidecarId := aclTestProbeId(label + ".tagged")
	if self.sidecars[sidecarId] == nil {
		if len(tagIds) == 0 {
			tagIds = []Id{aclTestProbeId(label + ".tag")}
		}
		row := &bridge.SidecarRow{SidecarId: sidecarId.Bytes(), AdmittedAt: self.nextPosition()}
		for _, tagId := range tagIds {
			row.TagIds = append(row.TagIds, tagId.Bytes())
		}
		if sponsorId != (Id{}) {
			row.Sponsor = sponsorId.Bytes()
			self.sponsors[sidecarId] = sponsorId
		}
		self.sidecars[sidecarId] = &AclSidecar{Row: row, TagIds: slices.Clone(tagIds)}
		self.order = append(self.order, sidecarId)
	}
	return AclSidecarSubject(sidecarId)
}

// The base's pin: probes add no entry, so the state stands where the writer's does.
func (self *aclTestProbeView) Pin() *bridge.AuthPin {
	return self.base.Pin()
}

// The base's genesis, its owner and config repo unchanged by any probe.
func (self *aclTestProbeView) Genesis() *bridge.Genesis {
	return self.base.Genesis()
}

// Every admission the base holds, then each probe in the order a test added it.
func (self *aclTestProbeView) SidecarIds() []Id {
	return slices.Concat(self.base.SidecarIds(), self.order)
}

// A probe's admission, or the base's when sidecarId names no probe.
func (self *aclTestProbeView) Sidecar(sidecarId Id) *AclSidecar {
	if probe := self.sidecars[sidecarId]; probe != nil {
		return probe
	}
	return self.base.Sidecar(sidecarId)
}

// A probe's new member, or the base's when memberId names none.
func (self *aclTestProbeView) Member(memberId Id) *bridge.MemberRow {
	if probe := self.members[memberId]; probe != nil {
		return probe
	}
	return self.base.Member(memberId)
}

// Whether the base counts the sidecar a config writer; a probe never is one.
func (self *aclTestProbeView) IsConfigWriter(sidecarId Id) bool {
	return self.sidecars[sidecarId] == nil && self.base.IsConfigWriter(sidecarId)
}

// Whether a cascade parks the sidecar in the base; a probe is never parked.
func (self *aclTestProbeView) Parked(sidecarId Id) bool {
	return self.sidecars[sidecarId] == nil && self.base.Parked(sidecarId)
}

// A tagged sidecar's live sponsor in the base, or a probe's own; a probe made with none has none, so autogroup:admin
// stands in for a tagged one.
func (self *aclTestProbeView) Sponsor(sidecarId Id) (Id, bool) {
	if self.sidecars[sidecarId] != nil {
		sponsorId, found := self.sponsors[sidecarId]
		return sponsorId, found
	}
	return self.base.Sponsor(sidecarId)
}

// The base's cascade judgment of what signer signed at at; probes sign nothing.
func (self *aclTestProbeView) CascadeVoids(signer []byte, at uint64) bool {
	return self.base.CascadeVoids(signer, at)
}

// The leaves rule's view, where the base has one, for a state over the probes: no probe is leaf-entitled.
func (self *aclTestProbeView) LeafEntitled(sidecarId Id) bool {
	if self.sidecars[sidecarId] != nil {
		return false
	}
	if ranked, ok := self.base.(AclLeafRankView); ok {
		return ranked.LeafEntitled(sidecarId)
	}
	return false
}
