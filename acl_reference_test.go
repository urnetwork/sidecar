// A second evaluator, written straight from §8.4-§8.6's text over the parsed AclPolicy and the world's facts, sharing
// no code with AclState's rows and bitsets (§22.5's compiled = reference). It lives in a _test.go file, so no release
// leg links it. It answers what rows decide exactly: reach, socket dials and listens on exact names, a repo's rights
// for general, record and config repos, publishes and sends.
//
//	allowed(s, a, r, t) = not hardDeny(s, t) and some grant g in force at t has s in src(g), r in dst(g), a in allow(g),
//	                      within the ceiling
//
// Its mutants each break one clause on purpose, so the property test proves the oracle sees the clause.

package sidecar

import (
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A clause the reference breaks on purpose.
type aclReferenceMutant int

const (
	aclReferenceExact aclReferenceMutant = iota
	// §8.6's ceiling ignored: an ephemeral sidecar takes every evs rule naming it any way
	aclReferenceMutantCeiling
	// * and evs:* reaching every kind, the config included
	aclReferenceMutantStarKinds
	// autogroup:untagged taking untagged sidecars too
	aclReferenceMutantUntagged
)

// One sidecar or client as the reference sees it.
type aclReferenceSubject struct {
	sidecarId Id
	clientId  Id
	isClient  bool
	memberId  Id
	tags      []string
	sponsor   Id
	ephemeral bool
	readOnly  bool
	revoked   bool
}

// The reference's world: the document, its names, and the subjects.
type aclReference struct {
	policy  *AclPolicy
	mutant  aclReferenceMutant
	members map[Id]bridge.MemberRole
	emails  map[string]Id
	labels  map[string]Id
	kinds   map[Id]protocol.RepoKind
}

func newAclReference(world *aclCompileWorld, mutant aclReferenceMutant) (*aclReference, error) {
	source := world.policy
	if source == nil {
		source = AclImplicitPolicySource()
	}
	policy, err := ParseAclPolicy(source)
	if err != nil {
		return nil, err
	}
	reference := &aclReference{
		policy:  policy,
		mutant:  mutant,
		members: map[Id]bridge.MemberRole{},
		emails:  map[string]Id{},
		labels:  map[string]Id{},
		kinds:   map[Id]protocol.RepoKind{},
	}
	for _, member := range world.members {
		reference.members[Id(member.MemberId)] = member.Role
	}
	for _, row := range world.resolve.Members {
		reference.emails[row.Email] = Id(row.MemberId)
	}
	for _, row := range world.labels.Labels {
		reference.labels[row.Label] = Id(row.RepoId)
	}
	for _, repo := range world.statements.Repos {
		reference.kinds[Id(repo.RepoId)] = repo.Kind
	}
	return reference, nil
}

// The reference's subject of a world's sidecar.
func aclReferenceSidecar(world *aclCompileWorld, sidecarId Id) aclReferenceSubject {
	for _, row := range world.sidecars {
		if Id(row.SidecarId) != sidecarId {
			continue
		}
		subject := aclReferenceSubject{
			sidecarId: sidecarId,
			ephemeral: world.ephemeral[sidecarId],
			readOnly:  row.Capabilities&uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY) != 0,
			revoked:   row.RevokedAt != 0,
		}
		if len(row.MemberId) != 0 {
			subject.memberId = Id(row.MemberId)
		}
		for _, tagId := range row.TagIds {
			for _, tag := range world.tags.Atoms {
				if Id(tag.AtomId) == Id(tagId) {
					subject.tags = append(subject.tags, tag.Name)
				}
			}
		}
		if len(row.Sponsor) != 0 {
			subject.sponsor = Id(row.Sponsor)
		}
		return subject
	}
	return aclReferenceSubject{sidecarId: sidecarId, revoked: true}
}

// Whether the subject is hard denied: unadmitted, revoked, or its member gone (§8.6).
func (self *aclReference) hardDenied(subject aclReferenceSubject) bool {
	if subject.revoked {
		return true
	}
	if len(subject.tags) == 0 {
		_, member := self.members[subject.memberId]
		return !member
	}
	return false
}

// The owner autogroup:self and approvers read: a member's, or a tagged sidecar's sponsor.
func (self *aclReference) owner(subject aclReferenceSubject) (Id, bool) {
	if len(subject.tags) == 0 {
		return subject.memberId, subject.memberId != (Id{})
	}
	_, live := self.members[subject.sponsor]
	return subject.sponsor, live
}

// Whether the subject holds a selector (§8.4).
func (self *aclReference) holds(subject aclReferenceSubject, selector AclSelector) bool {
	tagged := 0 < len(subject.tags)
	untaggedSidecar := !subject.isClient && !tagged
	switch selector.Kind {
	case AclSelectorUser:
		return !tagged && self.emails[selector.Name] == subject.memberId
	case AclSelectorGroup:
		if tagged {
			return false
		}
		for _, group := range self.policy.Groups {
			if group.Group != selector {
				continue
			}
			for _, member := range group.Members {
				if self.emails[member.Name] == subject.memberId {
					return true
				}
			}
		}
		return false
	case AclSelectorTag:
		return slices.Contains(subject.tags, selector.Name)
	case AclSelectorSidecar:
		return !subject.isClient && selector.Id == subject.sidecarId
	case AclSelectorAutogroup:
		role := self.members[subject.memberId]
		switch selector.Autogroup {
		case protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER:
			return untaggedSidecar
		case protocol.AclAutogroup_ACL_AUTOGROUP_UNTAGGED:
			// untagged non-sidecars: app devices, never a sidecar (D-ACL-20)
			if self.mutant == aclReferenceMutantUntagged {
				return !tagged
			}
			return subject.isClient
		case protocol.AclAutogroup_ACL_AUTOGROUP_TAGGED:
			return tagged
		case protocol.AclAutogroup_ACL_AUTOGROUP_SIDECAR:
			return !subject.isClient
		case protocol.AclAutogroup_ACL_AUTOGROUP_NETWORK:
			return true
		case protocol.AclAutogroup_ACL_AUTOGROUP_EPHEMERAL:
			return untaggedSidecar && subject.ephemeral
		case protocol.AclAutogroup_ACL_AUTOGROUP_OWNER:
			return !tagged && role == bridge.MemberRole_MEMBER_ROLE_OWNER
		case protocol.AclAutogroup_ACL_AUTOGROUP_ADMIN:
			return !tagged && (role == bridge.MemberRole_MEMBER_ROLE_OWNER || role == bridge.MemberRole_MEMBER_ROLE_ADMIN)
		case protocol.AclAutogroup_ACL_AUTOGROUP_AUDITOR:
			return !tagged && role == bridge.MemberRole_MEMBER_ROLE_AUDITOR
		}
	}
	return false
}

// Whether a selector names the subject directly, as §8.6's ceiling counts: its sidecar:<id>, a tag it carries, or
// autogroup:ephemeral.
func (self *aclReference) namesDirectly(subject aclReferenceSubject, selector AclSelector) bool {
	switch selector.Kind {
	case AclSelectorSidecar, AclSelectorTag:
		return self.holds(subject, selector)
	case AclSelectorAutogroup:
		return selector.Autogroup == protocol.AclAutogroup_ACL_AUTOGROUP_EPHEMERAL && self.holds(subject, selector)
	}
	return false
}

// Whether a grant is in force at t: its expiry, if any, after t (§8.6's rows(t)).
func aclReferenceInForce(grant *AclGrant, t time.Time) bool {
	return grant.Expires.IsZero() || t.Before(grant.Expires)
}

// Whether a destination resource takes a destination subject for this source (§8.4): a selector it holds,
// autogroup:self by a shared owner or sponsor, and a bare * any subject of the network.
func (self *aclReference) dstHoldsSubject(source aclReferenceSubject, destination aclReferenceSubject, resource AclResource) bool {
	switch resource.Kind {
	case AclResourceAll:
		return true
	case AclResourceSubject:
		if resource.Subject.Kind == AclSelectorAutogroup && resource.Subject.Autogroup == protocol.AclAutogroup_ACL_AUTOGROUP_SELF {
			sourceOwner, sourceKnown := self.owner(source)
			destinationOwner, destinationKnown := self.owner(destination)
			return sourceKnown && destinationKnown && sourceOwner == destinationOwner
		}
		return self.holds(destination, resource.Subject)
	}
	return false
}

// reach(a, b): a dial or route grant from a to b, a socket dial grant reaching the subjects that listen on one of its
// sockets among names, and a route grant reaching its via subjects (§8.10).
func (self *aclReference) reach(source aclReferenceSubject, destination aclReferenceSubject, names []string, t time.Time) bool {
	if self.hardDenied(source) || self.hardDenied(destination) {
		return false
	}
	for i := range self.policy.Grants {
		grant := &self.policy.Grants[i]
		if !aclReferenceInForce(grant, t) || !self.inSrc(source, grant.Src) {
			continue
		}
		dials := slices.Contains(grant.Allow, protocol.AclAction_ACL_ACTION_DIAL)
		routes := slices.Contains(grant.Allow, protocol.AclAction_ACL_ACTION_ROUTE)
		if !dials && !routes {
			continue
		}
		for _, resource := range grant.Dst {
			if self.dstHoldsSubject(source, destination, resource) {
				return true
			}
			// sockets expand to their listeners, which are sidecars: an app device registers no listener (§9.5)
			if dials && !destination.isClient && (resource.Kind == AclResourceSocket || resource.Kind == AclResourceAll) {
				for _, name := range names {
					if aclReferenceSocketCovers(resource, name) && self.listens(destination, name, t) {
						return true
					}
				}
			}
		}
		if routes {
			for _, via := range grant.Via {
				if self.holds(destination, via) {
					return true
				}
			}
		}
	}
	return false
}

// Whether a resource takes a concrete socket name: a bare * every application and share/ name (§8.4).
func aclReferenceSocketCovers(resource AclResource, name string) bool {
	return resource.covers(AclResource{Kind: AclResourceSocket, Name: name})
}

// Whether the subject holds src.
func (self *aclReference) inSrc(subject aclReferenceSubject, src []AclSelector) bool {
	for _, selector := range src {
		if self.holds(subject, selector) {
			return true
		}
	}
	return false
}

// Whether the subject holds a grant of action on a concrete socket name at t.
func (self *aclReference) socket(subject aclReferenceSubject, action protocol.AclAction, name string, t time.Time) bool {
	if self.hardDenied(subject) {
		return false
	}
	for i := range self.policy.Grants {
		grant := &self.policy.Grants[i]
		if !aclReferenceInForce(grant, t) || !slices.Contains(grant.Allow, action) || !self.inSrc(subject, grant.Src) {
			continue
		}
		for _, resource := range grant.Dst {
			if aclReferenceSocketCovers(resource, name) {
				return true
			}
		}
	}
	return false
}

// Whether the subject listens on a name at t.
func (self *aclReference) listens(subject aclReferenceSubject, name string, t time.Time) bool {
	return self.socket(subject, protocol.AclAction_ACL_ACTION_LISTEN, name, t)
}

// The rights a sidecar holds on a general, record or config repo at t (§8.5's kind defaults, §8.6's rules and
// ceiling, plan-ACL-small-readings #3's admin implying write and read, D-TEAM-24's read_only).
func (self *aclReference) evsRights(subject aclReferenceSubject, repoId Id, t time.Time) AclEvsRights {
	if self.hardDenied(subject) {
		return 0
	}
	kind := self.kinds[repoId]
	rights := AclEvsRights(0)
	if kind == protocol.RepoKind_REPO_KIND_CONFIG {
		// every admitted sidecar reads it; config writers write it, which no world here holds
		rights |= AclEvsRead
	}
	starReaches := kind == protocol.RepoKind_REPO_KIND_GENERAL || kind == protocol.RepoKind_REPO_KIND_RECORD
	if self.mutant == aclReferenceMutantStarKinds {
		starReaches = true
	}
	namedReaches := kind == protocol.RepoKind_REPO_KIND_GENERAL || kind == protocol.RepoKind_REPO_KIND_RECORD
	for i := range self.policy.Grants {
		grant := &self.policy.Grants[i]
		if !aclReferenceInForce(grant, t) {
			continue
		}
		holds := false
		for _, selector := range grant.Src {
			if !self.holds(subject, selector) {
				continue
			}
			ceilingHolds := !subject.ephemeral || self.mutant == aclReferenceMutantCeiling || self.namesDirectly(subject, selector)
			holds = holds || ceilingHolds
		}
		if !holds {
			continue
		}
		reaches := false
		for _, resource := range grant.Dst {
			switch {
			case resource.Kind == AclResourceAll || (resource.Kind == AclResourceRepo && resource.Name == "*"):
				reaches = reaches || starReaches
			case resource.Kind == AclResourceRepo:
				named := resource.RepoId == repoId || (resource.Name != "" && self.labelTakes(resource.Name, repoId))
				reaches = reaches || (named && namedReaches)
			}
		}
		if !reaches {
			continue
		}
		for _, action := range grant.Allow {
			switch action {
			case protocol.AclAction_ACL_ACTION_DEPOSIT:
				rights |= AclEvsDeposit
			case protocol.AclAction_ACL_ACTION_READ:
				rights |= AclEvsRead
			case protocol.AclAction_ACL_ACTION_WRITE:
				rights |= AclEvsWrite | AclEvsRead
			case protocol.AclAction_ACL_ACTION_ADMIN:
				rights |= AclEvsAdmin | AclEvsWrite | AclEvsRead
			}
		}
	}
	if subject.readOnly {
		if rights.Has(AclEvsRead) {
			return AclEvsRead | AclEvsDeposit
		}
		return 0
	}
	return rights
}

// Whether a label pattern takes a repo through the labels file.
func (self *aclReference) labelTakes(pattern string, repoId Id) bool {
	for label, labeled := range self.labels {
		if labeled == repoId && aclGlobMatches(pattern, label) {
			return true
		}
	}
	return false
}

// Whether the subject may publish a dns host at t.
func (self *aclReference) publishes(subject aclReferenceSubject, host string, t time.Time) bool {
	if self.hardDenied(subject) {
		return false
	}
	for i := range self.policy.Grants {
		grant := &self.policy.Grants[i]
		if !aclReferenceInForce(grant, t) || !slices.Contains(grant.Allow, protocol.AclAction_ACL_ACTION_PUBLISH) || !self.inSrc(subject, grant.Src) {
			continue
		}
		for _, resource := range grant.Dst {
			if resource.Kind == AclResourceDns && (resource.Name == "*" || resource.covers(AclResource{Kind: AclResourceDns, Name: host})) {
				return true
			}
		}
	}
	return false
}

// Whether the subject may send mail at t: a send grant on any alias, all a server sees (D-ACL-12).
func (self *aclReference) sends(subject aclReferenceSubject, t time.Time) bool {
	if self.hardDenied(subject) {
		return false
	}
	for i := range self.policy.Grants {
		grant := &self.policy.Grants[i]
		if !aclReferenceInForce(grant, t) || !slices.Contains(grant.Allow, protocol.AclAction_ACL_ACTION_SEND) || !self.inSrc(subject, grant.Src) {
			continue
		}
		if slices.ContainsFunc(grant.Dst, func(resource AclResource) bool { return resource.Kind == AclResourceMail }) {
			return true
		}
	}
	return false
}

// Whether a name is one a test may ask about, in §9.4's form.
func aclReferenceName(name string) bool {
	canonical, _, err := ParseSocketName(name)
	return err == nil && canonical == name && !strings.Contains(name, "*")
}

// The world every property run evaluates: an owner, an admin, a member and an auditor, their devices (one ephemeral,
// one read_only), tagged agents carrying a and b, an app device, and a general, a record and the config repo.
type aclPropertyWorld struct {
	world     *aclCompileWorld
	sidecars  []Id
	client    Id
	clientOf  Id
	repos     []Id
	names     []string
	hosts     []string
	selectors []string
	resources []string
}

func newAclPropertyWorld() *aclPropertyWorld {
	world := newAclCompileWorld("property")
	property := &aclPropertyWorld{world: world}
	owner := world.member("owner@acme.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	admin := world.member("admin@acme.example", bridge.MemberRole_MEMBER_ROLE_ADMIN)
	member := world.member("member@acme.example", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	world.member("auditor@acme.example", bridge.MemberRole_MEMBER_ROLE_AUDITOR)
	property.sidecars = append(property.sidecars,
		world.device("owner laptop", owner), world.device("admin laptop", admin), world.device("member laptop", member),
		world.device("member phone", member), world.device("member burner", member), world.device("member viewer", member))
	world.ephemeral[property.sidecars[4]] = true
	world.sidecars[5].Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	property.sidecars = append(property.sidecars,
		world.agent("agent a", member, "a"), world.agent("agent b", owner, "b"), world.agent("agent ab", admin, "a", "b"))
	world.group("eng")
	property.client, property.clientOf = world.id("app client"), member
	property.repos = []Id{
		world.repo("notes", protocol.RepoKind_REPO_KIND_GENERAL, Id{}),
		world.repo("runs", protocol.RepoKind_REPO_KIND_RECORD, Id{}),
		world.repo("cfg", protocol.RepoKind_REPO_KIND_CONFIG, Id{}),
	}
	property.names = []string{"db", "app/db", "app/web", "app/x/y", "share/" + strings.Repeat("a", socketShareTokenByteCount)}
	property.hosts = []string{"app", "x-preview", "@"}
	property.selectors = []string{"autogroup:member", "autogroup:tagged", "autogroup:untagged", "autogroup:admin", "autogroup:owner",
		"autogroup:auditor", "autogroup:ephemeral", "autogroup:network", "autogroup:sidecar", "tag:a", "tag:b", "group:eng",
		"user:member@acme.example", "sidecar:" + property.sidecars[4].String()}
	property.resources = []string{"autogroup:member", "autogroup:tagged", "autogroup:untagged", "autogroup:self", "tag:a",
		"group:eng", "sidecar:" + property.sidecars[2].String(), "*", "sock:db", "sock:app/db", "sock:app/*", "sock:*",
		"evs:notes", "evs:runs", "evs:*", "evs:cfg", "dns:app", "dns:*-preview", "dns:*", "mail:ops"}
	return property
}

// A random document over the world's pools: grants with sources, destinations, actions and expiries, a via on some.
func (self *aclPropertyWorld) policy(random *rand.Rand) string {
	actions := []string{"dial", "route", "listen", "read", "write", "admin", "deposit", "publish", "send"}
	quoteAll := func(texts []string) string {
		quoted := make([]string, 0, len(texts))
		for _, text := range texts {
			quoted = append(quoted, `"`+text+`"`)
		}
		return strings.Join(quoted, ", ")
	}
	pick := func(pool []string, most int) []string {
		picked := []string{}
		for range 1 + random.IntN(most) {
			text := pool[random.IntN(len(pool))]
			if !slices.Contains(picked, text) {
				picked = append(picked, text)
			}
		}
		return picked
	}
	grants := []string{}
	for range 1 + random.IntN(5) {
		grant := `{"src": [` + quoteAll(pick(self.selectors, 2)) + `], "dst": [` + quoteAll(pick(self.resources, 3)) +
			`], "allow": [` + quoteAll(pick(actions, 3)) + `]`
		switch random.IntN(4) {
		case 0:
			grant += `, "expires": "` + aclTestNow.Add(-time.Hour).UTC().Format(time.RFC3339) + `"`
		case 1:
			grant += `, "expires": "` + aclTestNow.UTC().Format(time.RFC3339) + `"`
		case 2:
			grant += `, "expires": "` + aclTestNow.Add(time.Hour).UTC().Format(time.RFC3339) + `"`
		}
		if random.IntN(4) == 0 {
			grant += `, "via": ["tag:b"]`
		}
		grants = append(grants, grant+"}")
	}
	return `{"tagOwners": {"tag:a": ["autogroup:admin"], "tag:b": ["autogroup:admin"]},
  "groups": {"group:eng": ["member@acme.example", "admin@acme.example"]},
  "grants": [` + strings.Join(grants, ",\n") + `]}`
}

// How many checks the compiled rows and the reference answer differently for the world's current document.
func (self *aclPropertyWorld) disagreements(t testing.TB, mutant aclReferenceMutant) int {
	t.Helper()
	world := self.world
	reference, err := newAclReference(world, mutant)
	if err != nil {
		t.Fatal(err)
	}
	state := world.state(t)
	clientSubject := aclReferenceSubject{clientId: self.client, isClient: true, memberId: self.clientOf}
	clientAclSubject := AclClientSubject(self.client, self.clientOf, nil, "")
	count := 0
	differ := func(rows bool, oracle bool) {
		if rows != oracle {
			count += 1
		}
	}
	subjects := []AclSubject{clientAclSubject}
	referenceSubjects := []aclReferenceSubject{clientSubject}
	for _, sidecarId := range self.sidecars {
		subjects = append(subjects, AclSidecarSubject(sidecarId))
		referenceSubjects = append(referenceSubjects, aclReferenceSidecar(world, sidecarId))
	}
	for i := range subjects {
		for j := range subjects {
			if i != j {
				differ(state.Reach(subjects[i], subjects[j], aclTestNow).Allowed, reference.reach(referenceSubjects[i], referenceSubjects[j], self.names, aclTestNow))
			}
		}
		for _, name := range self.names {
			tokenPath := world.tokenPath(t, name)
			differ(state.MayDialSocket(subjects[i], tokenPath, aclTestNow).Allowed, reference.socket(referenceSubjects[i], protocol.AclAction_ACL_ACTION_DIAL, name, aclTestNow))
			differ(state.MayListen(subjects[i], AclSocketName{NameToken: tokenPath}, aclTestNow).Allowed, reference.listens(referenceSubjects[i], name, aclTestNow))
		}
		for _, host := range self.hosts {
			differ(state.MayPublish(subjects[i], host, aclTestNow).Allowed, reference.publishes(referenceSubjects[i], host, aclTestNow))
		}
		differ(state.MaySend(subjects[i], aclTestNow).Allowed, reference.sends(referenceSubjects[i], aclTestNow))
		if referenceSubjects[i].isClient {
			continue
		}
		for _, repoId := range self.repos {
			rows := state.EvsAccess(subjects[i], repoId, AclTokenAudienceEvs, aclTestNow).Rights
			if oracle := reference.evsRights(referenceSubjects[i], repoId, aclTestNow); rows != oracle {
				count += 1
			}
		}
	}
	return count
}

// compiled = reference (§22.5): over generated documents at a fixed seed, and over the implicit document, the compiled
// rows and the reference answer every check alike.
func TestAclCompiledEqualsReference(t *testing.T) {
	property := newAclPropertyWorld()
	property.world.policy = nil
	if count := property.disagreements(t, aclReferenceExact); count != 0 {
		t.Fatalf("the implicit document: %d disagreements", count)
	}
	random := rand.New(rand.NewPCG(1, 2))
	for run := range 200 {
		property.world.rules = &protocol.ConfigRuleTable{}
		source := property.policy(random)
		property.world.setPolicy(t, source)
		if count := property.disagreements(t, aclReferenceExact); count != 0 {
			t.Fatalf("run %d: %d disagreements on\n%s", run, count, source)
		}
	}
}

// Each mutant of the reference breaks one clause, and the same runs find it: the oracle sees the ceiling, the * kind
// rule and autogroup:untagged.
func TestAclReferenceSeesItsMutants(t *testing.T) {
	for _, mutant := range []aclReferenceMutant{aclReferenceMutantCeiling, aclReferenceMutantStarKinds, aclReferenceMutantUntagged} {
		property := newAclPropertyWorld()
		found := 0
		property.world.policy = nil
		found += property.disagreements(t, mutant)
		property.world.setPolicy(t, `{"tagOwners": {"tag:a": ["autogroup:admin"]}, "grants": [{"src": ["autogroup:untagged"], "dst": ["tag:a"], "allow": ["dial"]}]}`)
		found += property.disagreements(t, mutant)
		if found == 0 {
			t.Errorf("mutant %d went unseen", mutant)
		}
	}
}
