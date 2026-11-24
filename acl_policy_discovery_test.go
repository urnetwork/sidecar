// §8.5's discovery block (owner decision 778): {"allow": [...], "deny": [...]}, each a DNS-SD service type, lowercased,
// refused where a name breaks RFC 6763 §7's rule, a key is unknown or a type is both allowed and denied; carried to the
// local policy alone, never to a row.

package sidecar

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A document's discovery block reads into its types, lowercased, and an absent one leaves none.
func TestAclPolicyReadsTheDiscoveryBlock(t *testing.T) {
	policy, err := ParseAclPolicy([]byte(`{
		// a network that adds AirPlay's type and keeps printers off
		"discovery": {"allow": ["_AirPlay._tcp", "_raop._tcp",], "deny": ["_ipp._tcp", "_ipps._tcp"]},
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if policy.Discovery == nil || !slices.Equal(policy.Discovery.Allow, []string{"_airplay._tcp", "_raop._tcp"}) ||
		!slices.Equal(policy.Discovery.Deny, []string{"_ipp._tcp", "_ipps._tcp"}) {
		t.Fatalf("read %+v", policy.Discovery)
	}
	empty, err := ParseAclPolicy([]byte(`{"discovery": {}}`))
	if err != nil || empty.Discovery == nil || len(empty.Discovery.Allow) != 0 || len(empty.Discovery.Deny) != 0 {
		t.Fatalf("an empty block read %+v, %v", empty.Discovery, err)
	}
	none, err := ParseAclPolicy([]byte(`{"grants": []}`))
	if err != nil || none.Discovery != nil {
		t.Fatalf("no block read %+v, %v", none.Discovery, err)
	}
}

// Each fault refuses the whole document, naming the block's path and no value.
func TestAclPolicyRefusesABadDiscoveryBlock(t *testing.T) {
	cases := []string{
		`{"discovery": {"allow": ["_ipp"]}}`,
		`{"discovery": {"allow": ["ipp._tcp"]}}`,
		`{"discovery": {"allow": ["_ipp._sctp"]}}`,
		`{"discovery": {"deny": ["_-ipp._tcp"]}}`,
		`{"discovery": {"deny": ["_ip--p._tcp"]}}`,
		`{"discovery": {"allow": [1]}}`,
		`{"discovery": {"allow": "_ipp._tcp"}}`,
		`{"discovery": {"also": []}}`,
		`{"discovery": {"allow": ["_ipp._tcp"], "deny": ["_IPP._tcp"]}}`,
		`{"discovery": {"allow": [], "allow": []}}`,
		`{"discovery": []}`,
	}
	for _, source := range cases {
		_, err := ParseAclPolicy([]byte(source))
		if !errors.Is(err, ErrAclPolicyInvalid) {
			t.Errorf("%s: %v", source, err)
			continue
		}
		if !strings.Contains(err.Error(), "discovery") || strings.Contains(err.Error(), "_ipp") {
			t.Errorf("%s: the refusal %q does not name the block's path, or names a value", source, err)
		}
	}
}

// The block rides the local policy, never a row: the same document with and without it compiles the same rows.
func TestCompileAclLocalCarriesTheDiscoveryBlock(t *testing.T) {
	compile := func(policy string) (*AclLocalPolicy, []byte) {
		world := newAclCompileWorld("discovery")
		owner := world.member("owner@acme.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
		world.device("laptop", owner)
		world.setPolicy(t, policy)
		local, err := CompileAclLocal(world.input())
		if err != nil {
			t.Fatal(err)
		}
		rows, err := proto.MarshalOptions{Deterministic: true}.Marshal(world.compile(t))
		if err != nil {
			t.Fatal(err)
		}
		return local, rows
	}
	grants := `"grants": [{ "src": ["autogroup:member"], "dst": ["autogroup:self"], "allow": ["dial"] }]`
	withBlock, withRows := compile(`{` + grants + `, "discovery": {"allow": ["_airplay._tcp"], "deny": ["_ssh._tcp"]}}`)
	withoutBlock, withoutRows := compile(`{` + grants + `}`)
	if withBlock.Discovery == nil || !slices.Equal(withBlock.Discovery.Allow, []string{"_airplay._tcp"}) ||
		!slices.Equal(withBlock.Discovery.Deny, []string{"_ssh._tcp"}) {
		t.Fatalf("the local policy holds %+v", withBlock.Discovery)
	}
	if withoutBlock.Discovery != nil {
		t.Fatalf("a document without the block holds %+v", withoutBlock.Discovery)
	}
	if !bytes.Equal(withRows, withoutRows) {
		t.Fatalf("the block changed the rows")
	}
}
