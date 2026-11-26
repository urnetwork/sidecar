//go:build !sidecar_http && !ios_extension

package sidecar

// CACL-M11-05: acl.proto declares the repo kinds agents, agent and listeners and the inbox marker team, which
// DESIGN-COMPUTE.md's authorization features turn on (§16.6), and no reader takes one yet: until each feature's readers
// land (SKILL-M11-01, LSTN-M13-05) every reader refuses them as a reader that predates the values does, so a reader
// built with the values and one built before them agree on every entry and head that names one.

import (
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The kinds and the marker a feature turns on.
var testFeatureRepoKinds = []protocol.RepoKind{
	protocol.RepoKind_REPO_KIND_AGENTS, protocol.RepoKind_REPO_KIND_AGENT, protocol.RepoKind_REPO_KIND_LISTENERS,
}

// §11.12's nine are known and the feature kinds are not, to the ACL state, to evs and to a group's ur_group alike.
func TestFeatureRepoKindsUnknownToReaders(t *testing.T) {
	for kind := protocol.RepoKind_REPO_KIND_GENERAL; kind <= protocol.RepoKind_REPO_KIND_SECRET; kind++ {
		if !aclRepoKindKnown(kind) || !EvsRepoKindKnown(kind) {
			t.Errorf("%s is unknown", kind)
		}
	}
	for _, kind := range append([]protocol.RepoKind{protocol.RepoKind_REPO_KIND_UNSPECIFIED, 99}, testFeatureRepoKinds...) {
		if aclRepoKindKnown(kind) || EvsRepoKindKnown(kind) || mlsCheckUrGroup(&MlsUrGroup{Kind: kind}) == nil {
			t.Errorf("%s is known", kind)
		}
	}
	for _, kind := range []protocol.RepoKind{protocol.RepoKind_REPO_KIND_GENERAL, protocol.RepoKind_REPO_KIND_AGENTS} {
		if aclRepoInboxFits(kind, protocol.RepoInbox_REPO_INBOX_TEAM) {
			t.Errorf("the team marker fits %s", kind)
		}
	}
}

// A RepoCreate of a feature kind is refused by its member's consented device and by a config writer, and a general
// repo marked team is refused, as a reader that predates the values refuses both.
func TestFeatureRepoKindsRefusedAtRepoCreate(t *testing.T) {
	cast := newAclStatementCast()
	fixture := cast.fixture
	state := fixture.state(t)
	for _, kind := range testFeatureRepoKinds {
		for _, signer := range []Id{cast.laptop, cast.ownerDevice} {
			create := &protocol.RepoCreate{RepoId: NewId().Bytes(), Kind: kind}
			_, err := state.CheckStatement(fixture.statement(bridge.SignedType_SIGNED_REPO_CREATE, create, signer), nil)
			if aclTestRefusal(err) != ErrConfigRule {
				t.Errorf("%s by %s: %v", kind, signer, err)
			}
		}
	}
	team := &protocol.RepoCreate{RepoId: NewId().Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, Inbox: protocol.RepoInbox_REPO_INBOX_TEAM}
	if _, err := state.CheckStatement(fixture.statement(bridge.SignedType_SIGNED_REPO_CREATE, team, cast.ownerDevice), nil); aclTestRefusal(err) != ErrConfigRule {
		t.Errorf("a general repo marked team: %v", err)
	}
}

// A versioning rule naming a feature kind is malformed, so no head names one a reader that predates the value would
// refuse; 0 and §11.12's nine read as before.
func TestFeatureRepoKindsRefusedInVersioningRules(t *testing.T) {
	rules := func(kind uint32) *protocol.VersioningRules {
		return &protocol.VersioningRules{Rules: []*protocol.VersioningRule{
			{Kinds: []uint32{kind}, Versioning: protocol.VersioningMode_VERSIONING_MODE_OFF},
		}}
	}
	for kind := uint32(0); kind <= uint32(protocol.RepoKind_REPO_KIND_SECRET); kind++ {
		if err := CheckVersioningRules(rules(kind)); err != nil {
			t.Errorf("kind %d: %v", kind, err)
		}
	}
	for _, kind := range testFeatureRepoKinds {
		if err := CheckVersioningRules(rules(uint32(kind))); !errors.Is(err, ErrConfigVersioningMalformed) {
			t.Errorf("%s: %v", kind, err)
		}
	}
}
