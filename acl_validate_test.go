// ValidateAclPolicy and AclRowsCheckLimits: one case per §8.8 Saving refusal beside its nearest accepted twin, the
// limits at their bounds, and a downgrade that refuses the next head while the old one still evaluates. Pure, on every
// leg.

package sidecar

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A Pro tier's limits, as a test writes them.
func aclTestProLimits() *AclLimits {
	return &AclLimits{Rules: 100, Groups: 10, Requests: 10, ApproversTwo: false, NetworkShares: 2, StandingPublishes: true}
}

// A Community tier's: no groups, no shares, no standing publishes, publishes up to 7 days (§13.9, §20.4).
func aclTestCommunityLimits() *AclLimits {
	return &AclLimits{Rules: 20, Groups: 0, Requests: 4, NetworkShares: 0, PublishMaxExpiry: 7 * 24 * time.Hour}
}

// A network every case validates against: an owner and a member, tags db and router, group eng, a general repo, an
// owner's vault, the config and a directory, each labeled, and a member whose row the log no longer holds.
func newAclValidateWorld() *aclCompileWorld {
	world := newAclCompileWorld("validate")
	owner := world.member("owner@acme.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	world.member("dana@acme.example", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	world.resolve.Members = append(world.resolve.Members, &protocol.ConfigMemberResolution{Email: "gone@acme.example", MemberId: world.id("gone member").Bytes()})
	world.device("owner laptop", owner)
	world.tag("db")
	world.tag("router")
	world.group("eng")
	world.repo("notes", protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	world.repo("vault", protocol.RepoKind_REPO_KIND_VAULT, owner)
	world.repo("config", protocol.RepoKind_REPO_KIND_CONFIG, Id{})
	world.repo("directory", protocol.RepoKind_REPO_KIND_DIRECTORY, Id{})
	world.network("partner")
	return world
}

// The document with the world's defaults: tag db and router owned by admins, group eng of dana.
func aclValidateDocument(body string) string {
	return `{"tagOwners": {"tag:db": ["autogroup:admin"], "tag:router": ["autogroup:admin"]},
  "groups": {"group:eng": ["dana@acme.example"]}, ` + body + `}`
}

func aclValidate(world *aclCompileWorld, source string, limits *AclLimits, resolve func(text string) (Id, bool)) error {
	world.policy = []byte(source)
	return ValidateAclPolicy(&AclValidateInput{Compile: world.input(), Limits: limits, ResolveNetworkLabel: resolve})
}

// Each refusal of §8.8's list, and beside it the nearest document that passes.
func TestValidateAclPolicyRefusesExactlyTheSavingList(t *testing.T) {
	world := newAclValidateWorld()
	partnerId := world.id("other network partner")
	resolvePartner := func(text string) (Id, bool) { return partnerId, text == "partner" }
	resolveElsewhere := func(text string) (Id, bool) { return world.id("elsewhere"), true }
	cases := []struct {
		name     string
		want     string
		refused  string
		accepted string
		limits   *AclLimits
		resolve  func(text string) (Id, bool)
		// the resolver the refused document meets, nil unless the case says
		refusedResolve func(text string) (Id, bool)
	}{
		{
			name:     "a tag the tags file does not hold",
			want:     "tags file does not hold",
			refused:  `"grants": [{"src": ["tag:ghost"], "dst": ["*"], "allow": ["dial"]}]`,
			accepted: `"grants": [{"src": ["tag:db"], "dst": ["*"], "allow": ["dial"]}]`,
		},
		{
			name:     "a tag outside tagOwners",
			want:     "tagOwners does not list",
			refused:  `"grants": [{"src": ["tag:audit"], "dst": ["*"], "allow": ["dial"]}]`,
			accepted: `"grants": [{"src": ["tag:router"], "dst": ["*"], "allow": ["dial"]}]`,
		},
		{
			name:     "a group no groups entry defines",
			want:     "no groups entry defines",
			refused:  `"grants": [{"src": ["group:ops"], "dst": ["*"], "allow": ["dial"]}]`,
			accepted: `"grants": [{"src": ["group:eng"], "dst": ["*"], "allow": ["dial"]}]`,
		},
		{
			name:     "a user resolve does not hold",
			want:     "a user resolve does not hold",
			refused:  `"grants": [{"src": ["user:nobody@acme.example"], "dst": ["*"], "allow": ["dial"]}]`,
			accepted: `"grants": [{"src": ["user:dana@acme.example"], "dst": ["*"], "allow": ["dial"]}]`,
		},
		{
			name:     "a user whose member is gone",
			want:     "member the log no longer holds",
			refused:  `"grants": [{"src": ["user:gone@acme.example"], "dst": ["*"], "allow": ["dial"]}]`,
			accepted: `"grants": [{"src": ["user:owner@acme.example"], "dst": ["*"], "allow": ["dial"]}]`,
		},
		{
			name:     "an approver-only atom outside approver",
			want:     "position does not take",
			refused:  `"grants": [{"src": ["autogroup:sponsor"], "dst": ["*"], "allow": ["dial"]}]`,
			accepted: `"requests": [{"src": ["autogroup:tagged"], "dst": ["*"], "allow": ["dial"], "approver": ["autogroup:sponsor"]}]`,
		},
		{
			name:     "ports on a rule with nothing to dial",
			want:     "ports on a rule",
			refused:  `"grants": [{"src": ["autogroup:member"], "dst": ["evs:notes"], "allow": ["read"], "ip": ["tcp:443"]}]`,
			accepted: `"grants": [{"src": ["autogroup:member"], "dst": ["tag:db"], "allow": ["dial"], "ip": ["tcp:443"]}]`,
		},
		{
			name:     "a via on a rule that does not route",
			want:     "does not allow route",
			refused:  `"grants": [{"src": ["autogroup:member"], "dst": ["ip:192.0.2.0/24"], "via": ["tag:router"], "allow": ["dial"]}]`,
			accepted: `"grants": [{"src": ["autogroup:member"], "dst": ["ip:192.0.2.0/24"], "via": ["tag:router"], "allow": ["route"]}]`,
		},
		{
			name:     "an evs: path",
			want:     "a path",
			refused:  `"grants": [{"src": ["autogroup:member"], "dst": ["evs:notes/readme"], "allow": ["read"]}]`,
			accepted: `"grants": [{"src": ["autogroup:member"], "dst": ["evs:notes"], "allow": ["read"]}]`,
		},
		{
			name:     "an owner-bound repo's reader",
			want:     "owner-bound repo",
			refused:  `"grants": [{"src": ["tag:db"], "dst": ["evs:vault"], "allow": ["read"]}]`,
			accepted: `"grants": [{"src": ["tag:db"], "dst": ["evs:vault"], "allow": ["deposit"]}]`,
		},
		{
			name:     "a grant on the config",
			want:     "config or the directory",
			refused:  `"grants": [{"src": ["tag:db"], "dst": ["evs:config"], "allow": ["read"]}]`,
			accepted: `"grants": [{"src": ["tag:db"], "dst": ["evs:notes"], "allow": ["read"]}]`,
		},
		{
			name:     "a grant on the directory",
			want:     "config or the directory",
			refused:  `"grants": [{"src": ["tag:db"], "dst": ["evs:directory"], "allow": ["write"]}]`,
			accepted: `"grants": [{"src": ["tag:db"], "dst": ["evs:notes"], "allow": ["write"]}]`,
		},
		{
			name:     "an audit block without an AuditOptIn",
			want:     "AuditOptIn",
			refused:  `"audit": {"reader": "tag:db", "repos": ["kind:vault"]}`,
			accepted: `"grants": []`,
		},
		{
			name:     "a raw publish outside public and link",
			want:     "raw outside audience",
			refused:  `"grants": [{"src": ["tag:db"], "dst": ["dns:app"], "allow": ["publish"], "app_mode": "raw"}]`,
			accepted: `"grants": [{"src": ["tag:db"], "dst": ["dns:app"], "allow": ["publish"], "app_mode": "raw", "audience": "public"}]`,
		},
		{
			name:     "a raw link with no pin",
			want:     "raw link with no pin",
			refused:  `"grants": [{"src": ["tag:db"], "dst": ["dns:app"], "allow": ["publish"], "app_mode": "raw", "audience": "link"}]`,
			accepted: `"grants": [{"src": ["tag:db"], "dst": ["dns:app"], "allow": ["publish"], "app_mode": "raw", "audience": "link", "link_spki_sha256": "` + strings.Repeat("ab", 32) + `"}]`,
		},
		{
			name:     "a socket no policy names",
			want:     "namespace no policy names",
			refused:  `"grants": [{"src": ["autogroup:member"], "dst": ["sock:ur/dns"], "allow": ["dial"]}]`,
			accepted: `"grants": [{"src": ["autogroup:member"], "dst": ["sock:db"], "allow": ["dial"]}]`,
		},
		{
			name:     "network: before §12's labels",
			want:     "§12's labels",
			refused:  `"grants": [{"src": ["network:partner"], "dst": ["tag:db"], "allow": ["dial"]}]`,
			accepted: `"grants": [{"src": ["network:partner"], "dst": ["tag:db"], "allow": ["dial"]}]`,
			resolve:  resolvePartner,
		},
		{
			name:           "network: resolving elsewhere",
			want:           "no label or alias",
			refused:        `"grants": [{"src": ["network:partner"], "dst": ["tag:db"], "allow": ["dial"]}]`,
			accepted:       `"grants": [{"src": ["network:*"], "dst": ["tag:db"], "allow": ["dial"]}]`,
			resolve:        resolveElsewhere,
			refusedResolve: resolveElsewhere,
		},
		{
			name:     "a standing publish outside Pro and Team",
			want:     "standing publish",
			refused:  `"grants": [{"src": ["autogroup:member"], "dst": ["dns:app"], "allow": ["publish"]}]`,
			accepted: `"requests": [{"src": ["autogroup:member"], "dst": ["dns:app"], "allow": ["publish"], "maxExpiry": "7d"}]`,
			limits:   &AclLimits{Rules: 20, Groups: 1, Requests: 4, PublishMaxExpiry: 7 * 24 * time.Hour},
		},
		{
			name:     "a publish past §13.9's limit",
			want:     "past this tier's limit",
			refused:  `"requests": [{"src": ["autogroup:member"], "dst": ["dns:app"], "allow": ["publish"], "maxExpiry": "8d"}]`,
			accepted: `"requests": [{"src": ["autogroup:member"], "dst": ["dns:app"], "allow": ["publish"], "maxExpiry": "7d"}]`,
			limits:   &AclLimits{Rules: 20, Groups: 1, Requests: 4, PublishMaxExpiry: 7 * 24 * time.Hour},
		},
		{
			name:     "two approvers without acl_approvers_two",
			want:     "acl_approvers_two",
			refused:  `"requests": [{"src": ["autogroup:member"], "dst": ["*"], "allow": ["dial"], "approver": ["autogroup:admin"], "approvers": 2}]`,
			accepted: `"requests": [{"src": ["autogroup:member"], "dst": ["*"], "allow": ["dial"], "approver": ["autogroup:admin"], "approvers": 1}]`,
			limits:   aclTestProLimits(),
		},
		{
			name:     "more rules than acl_rules",
			want:     "acl_rules",
			refused:  `"grants": [{"src": ["tag:db"], "dst": ["*"], "allow": ["dial"]}, {"src": ["tag:router"], "dst": ["*"], "allow": ["dial"]}]`,
			accepted: `"grants": [{"src": ["tag:db"], "dst": ["*"], "allow": ["dial"]}]`,
			limits:   &AclLimits{Rules: 1, Groups: 1, Requests: 1},
		},
	}
	for _, c := range cases {
		limits := c.limits
		if limits == nil {
			limits = aclTestProLimits()
		}
		err := aclValidate(world, aclValidateDocument(c.refused), limits, c.refusedResolve)
		if !errors.Is(err, ErrAclPolicyInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: refused as %v", c.name, err)
		}
		var validationError *AclValidationError
		if errors.As(err, &validationError) {
			for _, refusal := range validationError.Refusals {
				if refusal.Rule == "" || refusal.Reason == "" {
					t.Errorf("%s: a refusal naming no rule: %+v", c.name, refusal)
				}
			}
		}
		if err := aclValidate(world, aclValidateDocument(c.accepted), limits, c.resolve); err != nil {
			t.Errorf("%s: the twin refused: %v", c.name, err)
		}
	}
}

// A Community document with group: refuses and a Pro one passes (owner decision 73, §20.4's acl_groups).
func TestValidateAclPolicyHoldsTheTiersFeatures(t *testing.T) {
	world := newAclValidateWorld()
	document := aclValidateDocument(`"grants": [{"src": ["group:eng"], "dst": ["tag:db"], "allow": ["dial"]}]`)
	if err := aclValidate(world, document, aclTestCommunityLimits(), nil); !errors.Is(err, ErrAclPolicyInvalid) || !strings.Contains(err.Error(), "acl_groups") {
		t.Errorf("Community: %v", err)
	}
	if err := aclValidate(world, document, aclTestProLimits(), nil); err != nil {
		t.Errorf("Pro: %v", err)
	}
}

// After a downgrade the next head must fit and the old one stands: validation refuses the same document under the new
// tier, while its rows, compiled under the old one, still build and evaluate (§20.7).
func TestValidateAclPolicyAfterADowngrade(t *testing.T) {
	world := newAclValidateWorld()
	dana := world.id("member dana@acme.example")
	laptop := world.device("dana laptop", dana)
	db := world.agent("db agent", world.id("member owner@acme.example"), "db")
	document := aclValidateDocument(`"grants": [{"src": ["group:eng"], "dst": ["tag:db"], "allow": ["dial"]}]`)
	if err := aclValidate(world, document, aclTestProLimits(), nil); err != nil {
		t.Fatalf("the Pro head: %v", err)
	}
	world.setPolicy(t, document)
	state := world.state(t)
	if err := aclValidate(world, document, aclTestCommunityLimits(), nil); !errors.Is(err, ErrAclPolicyInvalid) {
		t.Fatalf("the next head under Community: %v", err)
	}
	if decision := state.Reach(AclSidecarSubject(laptop), AclSidecarSubject(db), aclTestNow); !decision.Allowed {
		t.Errorf("the old head stopped evaluating: %s", decision.Reason)
	}
}

// §8.8's two format bounds at exactly their limits: 4,096 atoms and 4 MiB pass, one more of either refuses, as the
// tier's acl_rules does at its own.
func TestAclRowsCheckLimitsAtTheBounds(t *testing.T) {
	rows := &protocol.AclRows{}
	for i := range aclRowsMaxAtomCount {
		atom := make([]byte, aclAtomByteCount)
		atom[0], atom[1], atom[2] = 1, byte(i>>8), byte(i)
		rows.Atoms = append(rows.Atoms, &protocol.AclAtom{Atom: atom})
	}
	if err := AclRowsCheckLimits(rows, configRowsMaxByteCount, nil); err != nil {
		t.Fatalf("4,096 atoms and 4 MiB: %v", err)
	}
	if err := AclRowsCheckLimits(rows, configRowsMaxByteCount+1, nil); !errors.Is(err, ErrAclRowsTooLarge) {
		t.Errorf("4 MiB and a byte: %v", err)
	}
	rows.Atoms = append(rows.Atoms, &protocol.AclAtom{Atom: make([]byte, aclAtomByteCount)})
	if err := AclRowsCheckLimits(rows, 0, nil); !errors.Is(err, ErrAclRowsTooLarge) {
		t.Errorf("4,097 atoms: %v", err)
	}
	ruled := &protocol.AclRows{
		Rules:    []*protocol.AclRule{{RuleId: []byte{1}}, {RuleId: []byte{2}, SourceRuleId: []byte{3}}},
		Requests: []*protocol.AclRequestRule{{RuleId: []byte{3}}},
	}
	if err := AclRowsCheckLimits(ruled, 0, &AclLimits{Rules: 2, Requests: 1}); err != nil {
		t.Errorf("two rules at acl_rules 2, the activated grant uncounted: %v", err)
	}
	if err := AclRowsCheckLimits(ruled, 0, &AclLimits{Rules: 1, Requests: 1}); !errors.Is(err, ErrAclRowsTooLarge) {
		t.Errorf("two rules at acl_rules 1: %v", err)
	}
}
