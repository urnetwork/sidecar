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
//	                   grant's index (owner decision 615). A rule that names autogroup:internet reaches every public
//	                   address (aclAddressPublic) through an exit among its vias, by routes in force no save sees
//	                   either, so it holds no accept by that and fails every deny of a range holding a public address,
//	                   named the same way (QD-1125)
//	activated grants   an ip: check judges effective access at the verified base the save stands on, so a surviving
//	                   activated route grant counts beside the document's rules (QD-1164): one whose action seals no
//	                   detail names no prefix and routes by its subjects alone, as above; one whose sealed detail the
//	                   writer opens under its config keys (owner decision 220, QD-003) is judged by the detail's
//	                   prefixes, its cidrs and ip: destinations, and by the ports its sidecar destinations name, none
//	                   meaning every port; and one whose detail does not open here, the action not held, its key
//	                   generation missing or a detail not its action's, may apply to any range at any port, so it
//	                   establishes no accept and a deny it may apply to fails as indeterminate. Such a failure names
//	                   the grant by its id and the test by its index, and the writer restores its config keys, removes
//	                   the test or waits for the grant to end before saving. A rule a definite failure matches that an
//	                   activated grant gave is named by its grant id
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
	"encoding/hex"
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

// An activated grant's sealed detail did not open here, so its ip: checks are indeterminate (QD-1164): the base holds
// no action for it, or the action's detail did not open to it.
var ErrAclGrantDetailUnread = errors.New("acl tests: an activated grant's detail did not open")

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
	// The activated grant whose sealed detail did not open here, for a check it left indeterminate or kept from an
	// accept (QD-1164); nil otherwise. An opaque id, as rule ids are (I-13).
	GrantId []byte
}

// Opens an activated grant's sealed detail at the verified base a run stands on (owner decision 220, QD-003, QD-1164):
// the CanonicalActionDetail its action's sealed_detail opens to under the device's config keys, held to that action.
// grantId is the grant's rule id in the rows. An error, ErrAclGrantDetailUnread or the opener's own
// (ErrConfigSealGenerationMissing, ErrConfigSealInvalid, ErrCanonicalActionDetailInvalid), says it did not open here.
type AclGrantDetails interface {
	GrantDetail(grantId []byte) (*protocol.CanonicalActionDetail, error)
}

// The details a writer's verified state opens: each activated grant's action as the state holds it, or as the base's
// head's folds hold it for a reader that joined after the grant landed (ConfigState.grantActionsAtHead), opened in the
// state's network under the config repo's key of the generation it names, which repoKeyAt answers, nil holding none.
type aclStateGrantDetails struct {
	actions   map[string][]byte
	networkId Id
	repoKeyAt func(generation uint64) *EvsRepoKey
}

// The details state opens at the base head stands on; nil for no state.
func newAclStateGrantDetails(state *ConfigState, head *ConfigHead, repoKeyAt func(generation uint64) *EvsRepoKey) AclGrantDetails {
	if state == nil {
		return nil
	}
	return &aclStateGrantDetails{actions: state.grantActionsAtHead(head), networkId: state.NetworkId(), repoKeyAt: repoKeyAt}
}

// See AclGrantDetails. A detail that opens to nil, an action that seals none, is unread too: a rule the fold marked
// as limiting ports names them nowhere else.
func (self *aclStateGrantDetails) GrantDetail(grantId []byte) (*protocol.CanonicalActionDetail, error) {
	encoded := self.actions[string(grantId)]
	if len(encoded) == 0 {
		return nil, fmt.Errorf("%w: the base holds no action for the grant", ErrAclGrantDetailUnread)
	}
	action, err := ParseStoredCanonicalAction(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAclGrantDetailUnread, err)
	}
	detail, err := OpenCanonicalActionDetail(action, self.networkId, self.repoKeyAt)
	if err != nil {
		return nil, err
	}
	if detail == nil {
		return nil, fmt.Errorf("%w: the grant's action seals no detail", ErrAclGrantDetailUnread)
	}
	return detail, nil
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
	// Opens the sealed detail of each activated grant the compile carries, which its ip: checks judge by (QD-1164);
	// nil opens none, so every such grant whose action seals a detail leaves the checks it may apply to indeterminate.
	GrantDetails AclGrantDetails
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
		grantDetails: input.GrantDetails,
		grantRoutes:  map[string]*aclTestGrantRoute{},
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
	// the opener of activated grants' sealed details, and what each grant's gave, by its rule id (QD-1164)
	grantDetails AclGrantDetails
	grantRoutes  map[string]*aclTestGrantRoute
}

// An activated grant's route as a run reads it: the detail its ip: checks judge by, or why it did not open.
type aclTestGrantRoute struct {
	local  *AclLocalRule
	unread string
}

// What an ip: check found for one source (routeToPrefix).
type aclTestRouteAnswer struct {
	decision AclDecision
	// what a deny's failure says of a rule matched by a reach no save sees, after its name; empty for one matched by its
	// prefixes
	unseen string
	// the first activated grant that may apply whose detail did not open, and why (QD-1164)
	unreadGrantId []byte
	unread        string
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
	fail := func(list string, check int, reason string, grantId []byte) {
		self.report.Failures = append(self.report.Failures, AclPolicyTestFailure{Test: plan.index, List: list, Check: check, Reason: reason,
			GrantId: slices.Clone(grantId)})
	}
	self.report.CheckCount += len(plan.test.Accept) + len(plan.test.Deny)
	if plan.srcUnjudged != "" {
		fail("src", -1, plan.srcUnjudged, nil)
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
				fail(list.name, j, checkPlan.unjudged, nil)
				continue
			}
			for si, source := range plan.sources {
				var destinations []AclSubject
				if si < len(checkPlan.destinations) {
					destinations = checkPlan.destinations[si]
				}
				if reason, grantId := self.holds(source, check, destinations, list.want); reason != "" {
					fail(list.name, j, reason, grantId)
					break
				}
			}
		}
	}
}

// Whether one check holds for one source as want says: empty when it does, else why not, with the activated grant
// whose unopened detail the failure stands on, nil for none (QD-1164).
func (self *aclTestRun) holds(source AclSubject, check AclPolicyCheck, destinations []AclSubject, want bool) (string, []byte) {
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
				return reason, nil
			}
		}
		return "", nil
	case AclResourceSocket, AclResourceDns, AclResourceMail:
		result := self.engine.Check(source, check.Action, resource, now)
		return answer(AclDecision{Allowed: result.Allowed, Reason: result.Reason}), nil
	case AclResourceRepo:
		repoResource := resource
		if repoResource.RepoId == (Id{}) {
			repoResource.RepoId = self.compiler.labelRepoIds[resource.Name]
		}
		result := self.engine.Check(source, check.Action, repoResource, now)
		return answer(AclDecision{Allowed: result.Allowed, Reason: result.Reason}), nil
	case AclResourceIp:
		route := self.routeToPrefix(source, resource.Cidr, check.Ports, want)
		decision := route.decision
		grant := ""
		if route.unreadGrantId != nil {
			grant = "grant " + hex.EncodeToString(route.unreadGrantId)
		}
		switch {
		case want && decision.Allowed, !want && !decision.Allowed && route.unreadGrantId == nil:
			return "", nil
		case want && route.unreadGrantId != nil:
			// an accept another rule did not hold, which the unread grant cannot establish
			return answer(decision) + "; " + grant + " may route it, but its sealed detail " + route.unread +
				", so it establishes no accept", route.unreadGrantId
		case want:
			return answer(decision), nil
		case !decision.Allowed:
			return "indeterminate: " + grant + " may route its source into the range, but its sealed detail " + route.unread +
				": restore this device's config keys, remove the test or wait for the grant to end", route.unreadGrantId
		case route.unseen != "":
			return "allowed by " + self.ruleName(decision.Rule) + ", " + route.unseen, nil
		case len(decision.Rule.GetSourceRuleId()) != 0:
			// an activated grant its opened detail matched
			return "allowed by " + self.ruleName(decision.Rule), nil
		}
		return answer(decision), nil
	}
	return "a check no test can judge", nil
}

// A rule as a failure names it, by no value (I-13): an activated grant by its grant id; else its grant's index in the
// document, the first of identical grants, else its id, for a rule no grant of the document gave.
func (self *aclTestRun) ruleName(rule *protocol.AclRule) string {
	if len(rule.GetSourceRuleId()) != 0 {
		return "grant " + hex.EncodeToString(rule.GetRuleId())
	}
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
// prefixes, or by a reach no save sees: for a rule that names no prefix, by naming for the source a sidecar among both
// its via subjects and its subject destinations, whose routes in force could serve any range (owner decision 615); for
// a rule that names autogroup:internet, by a public address in the range, which an exit among its vias could serve by
// its routes in force (QD-1125). Neither holds an accept, since no save sees what those routes serve. A surviving
// activated grant is judged by its detail as grantRoute reads it, and one whose detail did not open matches nothing,
// the answer naming the first such grant the source's route reaches, which a deny then fails on as indeterminate when
// no rule matched it outright (QD-1164).
func (self *aclTestRun) routeToPrefix(source AclSubject, cidr netip.Prefix, ports *AclPortRange, want bool) aclTestRouteAnswer {
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
	holdsPublic := !want && aclPrefixHoldsPublic(cidr)
	answer := aclTestRouteAnswer{}
	answer.decision = self.state.resourceDecision(source, self.nowMs, protocol.AclAction_ACL_ACTION_ROUTE, func(rule *aclRule) bool {
		local := self.localRules[rule.index]
		if local == nil {
			grant := self.grantRoute(rule)
			if grant == nil {
				return false
			}
			if grant.unread != "" {
				// it may apply to any range at any port: it holds no accept, and a deny falls back on it below
				if answer.unreadGrantId == nil {
					answer.unreadGrantId, answer.unread = rule.row.GetRuleId(), grant.unread
				}
				return false
			}
			local = grant.local
		}
		if !portsMatch(local) {
			return false
		}
		if aclRouteBySubject(local, rule.internetTarget) {
			if !want && self.routeBySubjectReaches(&sourceResolved, rule) {
				answer.unseen = "which names no prefix: a sidecar among both its via subjects and its destinations could serve " +
					"any range by its routes in force"
				return true
			}
			return false
		}
		for _, held := range local.Cidrs {
			if want && held.Bits() <= cidr.Bits() && held.Contains(cidr.Addr()) {
				return true
			}
			if !want && held.Overlaps(cidr) {
				return true
			}
		}
		if holdsPublic && rule.internetTarget {
			answer.unseen = "which names autogroup:internet: an exit among its via subjects could serve any public address by " +
				"its routes in force"
			return true
		}
		return false
	})
	return answer
}

// An activated grant's route as an ip: check judges it (QD-1164), read once a run; nil for a rule no grant activated,
// whose detail the document gives. A grant whose action seals no detail, its rule limiting no ports, names no prefix
// and no port, so it routes by its subjects alone. One whose rule limits ports seals a detail, which it is judged by
// where the run's opener opens it: its prefixes are its cidrs and its ip: destinations, and its ports those its sidecar
// destinations name, taken together since rows mark ports for the rule whole, none meaning every port. A detail naming
// target_port alone names no protocol, so its ports are not read whole and it stays unread, as one that does not open.
func (self *aclTestRun) grantRoute(rule *aclRule) *aclTestGrantRoute {
	if len(rule.row.GetSourceRuleId()) == 0 {
		return nil
	}
	grantId := rule.row.GetRuleId()
	if held, found := self.grantRoutes[string(grantId)]; found {
		return held
	}
	grant := func() *aclTestGrantRoute {
		if !rule.portsLimited {
			return &aclTestGrantRoute{local: &AclLocalRule{}}
		}
		if self.grantDetails == nil {
			return &aclTestGrantRoute{unread: "has no opener on this run"}
		}
		detail, err := self.grantDetails.GrantDetail(grantId)
		switch {
		case errors.Is(err, ErrConfigSealGenerationMissing):
			return &aclTestGrantRoute{unread: "needs a config key generation this device does not hold"}
		case err != nil:
			return &aclTestGrantRoute{unread: "did not open here"}
		case detail == nil:
			return &aclTestGrantRoute{unread: "is missing"}
		}
		local := &AclLocalRule{}
		for _, text := range detail.GetCidrs() {
			prefix, err := netip.ParsePrefix(text)
			if err != nil {
				return &aclTestGrantRoute{unread: "holds a prefix that does not read"}
			}
			local.Cidrs = append(local.Cidrs, prefix)
		}
		for _, dst := range detail.GetGrantDst() {
			if text, isPrefix := strings.CutPrefix(dst, "ip:"); isPrefix {
				prefix, err := netip.ParsePrefix(text)
				if err != nil {
					return &aclTestGrantRoute{unread: "holds a prefix that does not read"}
				}
				local.Cidrs = append(local.Cidrs, prefix)
				continue
			}
			_, ports, err := ParseAclGrantDst(dst)
			if err != nil || ports == nil {
				return &aclTestGrantRoute{unread: "holds a destination that does not read"}
			}
			local.Ports = append(local.Ports, AclPortRange{Protocol: ports.GetProtocol(), First: ports.GetFirst(), Last: ports.GetLast()})
		}
		if detail.GetTargetPort() != 0 && len(local.Ports) == 0 {
			return &aclTestGrantRoute{unread: "names a port with no protocol"}
		}
		return &aclTestGrantRoute{local: local}
	}()
	self.grantRoutes[string(grantId)] = grant
	return grant
}

// Whether a prefix holds an address aclAddressPublic takes, which autogroup:internet reaches (§8.4): one outside every
// range netip reads as unspecified, loopback, link-local, multicast or private, and IPv4's broadcast address. A prefix
// one of those ranges holds whole holds none, one that overlaps none holds only public ones, and one that strictly holds
// a range holds one exactly where a half of it does, since each range is a prefix too. An IPv4-mapped prefix reads as
// IPv4, as netip's reads do.
func aclPrefixHoldsPublic(prefix netip.Prefix) bool {
	if !prefix.IsValid() {
		return false
	}
	prefix = prefix.Masked()
	if prefix.Addr().Is4In6() && 96 <= prefix.Bits() {
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	ranges := []netip.Prefix{
		netip.MustParsePrefix("::/128"), netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"),
	}
	if prefix.Addr().Is4() {
		ranges = []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/32"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("127.0.0.0/8"),
			netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
			netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("224.0.0.0/4"),
			netip.MustParsePrefix("255.255.255.255/32"),
		}
	}
	var holds func(prefix netip.Prefix) bool
	holds = func(prefix netip.Prefix) bool {
		overlaps := false
		for _, held := range ranges {
			if held.Bits() <= prefix.Bits() && held.Contains(prefix.Addr()) {
				return false
			}
			overlaps = overlaps || held.Overlaps(prefix)
		}
		if !overlaps {
			return true
		}
		// it strictly holds a range, so it is wider than one address: its two halves
		bits := prefix.Bits()
		var high netip.Addr
		if prefix.Addr().Is4() {
			address := prefix.Addr().As4()
			address[bits/8] |= 0x80 >> (bits % 8)
			high = netip.AddrFrom4(address)
		} else {
			address := prefix.Addr().As16()
			address[bits/8] |= 0x80 >> (bits % 8)
			high = netip.AddrFrom16(address)
		}
		return holds(netip.PrefixFrom(prefix.Addr(), bits+1)) || holds(netip.PrefixFrom(high, bits+1))
	}
	return holds(prefix)
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
