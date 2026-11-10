// FuzzCompileAcl (§22.6): a document either refuses or compiles, twice to the same bytes, and where the reference
// models every selector and resource it holds, the compiled rows answer every check as the reference does. Its seeds
// in testdata/fuzz/FuzzCompileAcl run in every test.sh.

package sidecar

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// Gives every name a parsed document holds a table row, as a writer's save would, so the compile reads it: tags,
// groups, labels and rules; users, networks and clients resolve to ids the log does not hold, which grant nothing.
func aclFuzzFillTables(world *aclCompileWorld, policy *AclPolicy) {
	selector := func(selector AclSelector) {
		switch selector.Kind {
		case AclSelectorTag:
			world.tag(selector.Name)
		case AclSelectorGroup:
			world.group(selector.Name)
		case AclSelectorUser:
			if !slices.ContainsFunc(world.resolve.Members, func(row *protocol.ConfigMemberResolution) bool { return row.Email == selector.Name }) {
				world.resolve.Members = append(world.resolve.Members, &protocol.ConfigMemberResolution{Email: selector.Name, MemberId: world.id("fuzz member " + selector.Name).Bytes()})
			}
		case AclSelectorNetwork:
			if selector.Name != "*" && !slices.ContainsFunc(world.resolve.Networks, func(row *protocol.ConfigNetworkResolution) bool { return row.Text == selector.Name }) {
				world.network(selector.Name)
			}
		case AclSelectorClient:
			if !slices.ContainsFunc(world.resolve.Clients, func(row *protocol.ConfigClientResolution) bool { return Id(row.ClientId) == selector.Id }) {
				world.resolve.Clients = append(world.resolve.Clients, &protocol.ConfigClientResolution{ClientId: selector.Id.Bytes()})
			}
		}
	}
	resource := func(resource AclResource) {
		switch resource.Kind {
		case AclResourceSubject:
			selector(resource.Subject)
		case AclResourceRepo:
			labeled := slices.ContainsFunc(world.labels.Labels, func(row *protocol.ConfigRepoLabel) bool { return row.Label == resource.Name })
			if resource.RepoId == (Id{}) && !strings.Contains(resource.Name, "*") && !labeled {
				world.labels.Labels = append(world.labels.Labels, &protocol.ConfigRepoLabel{Label: resource.Name, RepoId: world.id("fuzz repo " + resource.Name).Bytes()})
			}
		}
	}
	for _, group := range policy.Groups {
		selector(group.Group)
		for _, member := range group.Members {
			selector(member)
		}
	}
	for _, tagOwner := range policy.TagOwners {
		selector(tagOwner.Tag)
		for _, owner := range tagOwner.Owners {
			selector(owner)
		}
	}
	for _, grant := range policy.Grants {
		for _, src := range grant.Src {
			selector(src)
		}
		for _, dst := range grant.Dst {
			resource(dst)
		}
		for _, via := range grant.Via {
			selector(via)
		}
	}
	for _, request := range policy.Requests {
		for _, src := range request.Src {
			selector(src)
		}
		for _, dst := range request.Dst {
			resource(dst)
		}
		for _, approver := range request.Approver {
			selector(approver)
		}
	}
}

// Whether the reference models every selector and resource a document holds, so its answers are the oracle: no
// network:, client:, role: or principal:, no ip: range, and no socket glob rows coarsen to a prefix.
func aclReferenceModels(policy *AclPolicy) bool {
	modeled := func(selector AclSelector) bool {
		switch selector.Kind {
		case AclSelectorNetwork, AclSelectorClient, AclSelectorRole, AclSelectorPrincipal:
			return false
		}
		return true
	}
	for _, grant := range policy.Grants {
		for _, src := range grant.Src {
			if !modeled(src) {
				return false
			}
		}
		for _, via := range grant.Via {
			if !modeled(via) {
				return false
			}
		}
		for _, dst := range grant.Dst {
			switch dst.Kind {
			case AclResourceIp:
				return false
			case AclResourceSubject:
				if !modeled(dst.Subject) {
					return false
				}
			case AclResourceSocket:
				segments := strings.Split(dst.Name, "/")
				for i, segment := range segments {
					last := i == len(segments)-1
					if strings.Contains(segment, "*") && !(last && segment == "*") && !(i == 0 && segment == "*") {
						return false
					}
				}
			}
		}
	}
	return true
}

func FuzzCompileAcl(f *testing.F) {
	for _, seed := range []string{
		string(AclImplicitPolicySource()),
		aclWorkedExampleSource,
		`{"grants": [{"src": ["autogroup:member"], "dst": ["autogroup:self"], "allow": ["dial", "route"]}]}`,
		`{"tagOwners": {"tag:a": ["autogroup:admin"]}, "grants": [{"src": ["tag:a"], "dst": ["evs:*", "sock:app/*"], "allow": ["read", "dial"]}]}`,
		`{"grants": [{"src": ["autogroup:ephemeral"], "dst": ["*"], "allow": ["write"], "expires": "2026-01-01T00:00:00Z"}]}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, source []byte) {
		property := newAclPropertyWorld()
		property.world.policy = source
		policy, err := ParseAclPolicy(source)
		if err != nil {
			if _, compileErr := CompileAcl(property.world.input()); compileErr == nil {
				t.Fatal("a document that does not parse compiled")
			}
			return
		}
		aclFuzzFillTables(property.world, policy)
		property.world.setPolicy(t, string(source))
		first, err := CompileAcl(property.world.input())
		if err != nil {
			if !errors.Is(err, ErrAclCompile) && !errors.Is(err, ErrAclRowsTooLarge) {
				t.Fatalf("refused with no compile refusal: %v", err)
			}
			return
		}
		second, err := CompileAcl(property.world.input())
		if err != nil || !bytes.Equal(aclEncodeRows(t, first), aclEncodeRows(t, second)) {
			t.Fatalf("a second compile differs: %v", err)
		}
		if !aclReferenceModels(policy) {
			return
		}
		if count := property.disagreements(t, aclReferenceExact); count != 0 {
			t.Fatalf("%d disagreements with the reference", count)
		}
	})
}
