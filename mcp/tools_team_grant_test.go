//go:build !js && !ios && !android && !sdk_mobile_bind

// acl_check over an activated route grant (MCP-M3-14; owner decisions 220 and 679, QD-003, QD-1164): the engine the
// acl follower installs reads a surviving, unexpired activated route grant by its sealed detail, as the bridge compile
// serves it, so acl_check of a range the grant's prefixes hold is allowed and names the grant, a range they do not hold
// is refused, and once the grant has expired the range is refused too. The grant's rule is folded into a real
// admission net's rows, its detail opened through a test opener as the follower's would open it under the config
// keys. Synthetic values only.

package mcp

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A team network whose §8.9 check is a real engine's, as the daemon's network answers it (host.go's Allow).
type testMcpEngineNetwork struct {
	*fakeMcpTeamNetwork
	engine *sidecar.AclEngine
}

// AclEngine.Check for the network's sidecar, false before a state installs.
func (self *testMcpEngineNetwork) Allow(action protocol.AclAction, resource sidecar.AclResource, now time.Time) (sidecar.AclCheck, bool) {
	identity := self.Identity()
	if self.engine.State() == nil || identity == nil {
		return sidecar.AclCheck{}, false
	}
	return self.engine.Check(sidecar.AclSidecarSubject(identity.SidecarId), action, resource, now), true
}

// An opener holding one grant's detail.
type testMcpGrantDetails struct {
	grantId []byte
	detail  *protocol.CanonicalActionDetail
}

func (self *testMcpGrantDetails) GrantDetail(grantId []byte) (*protocol.CanonicalActionDetail, error) {
	if !bytes.Equal(grantId, self.grantId) {
		return nil, sidecar.ErrAclGrantActionNotHeld
	}
	return proto.Clone(self.detail).(*protocol.CanonicalActionDetail), nil
}

// A member's device holds an activated route grant through the owner's device, sealing 198.51.100.0/25 at tcp 22:
// acl_check of route on a range inside it is allowed, naming the grant, a wider range is refused, and a second past
// the grant's expiry the same range is refused.
func TestAclCheckAnswersAnActivatedRouteGrantByItsDetail(t *testing.T) {
	env := newTestTeamToolEnv(t)
	_, grantee := env.admission.ConsentedMember("route grantee")
	via := env.admission.Owner()
	state := env.admission.State()
	acl, err := state.Acl()
	if err != nil {
		t.Fatal(err)
	}

	// the grant alone opens a route: a document with no rule of its own but the requests rule the grant came from, which
	// a grant stands only beside, and the grant as a GrantActivate folds it
	grantId := bytes.Repeat([]byte{0x6b}, 32)
	requestRuleId := bytes.Repeat([]byte{0x6c}, 16)
	expiresMs := env.clock.Now().Add(time.Second).UnixMilli()
	rows := proto.Clone(acl.Rows()).(*protocol.AclRows)
	rows.HasDocument = true
	atom := sidecar.AclDerivedAtom(sidecar.AclDerivedAtomSidecar, grantee.SidecarId.Bytes())
	rows.Atoms = append(rows.Atoms, &protocol.AclAtom{Atom: atom.Bytes(), SidecarIds: [][]byte{grantee.SidecarId.Bytes()}})
	target := &protocol.AclTarget{SidecarId: via.SidecarId.Bytes()}
	rows.Requests = append(rows.Requests, &protocol.AclRequestRule{
		RuleId: requestRuleId, SrcAtoms: [][]byte{atom.Bytes()}, Targets: []*protocol.AclTarget{proto.Clone(target).(*protocol.AclTarget)},
		Actions: []uint32{uint32(protocol.AclAction_ACL_ACTION_ROUTE)},
	})
	rows.Rules = []*protocol.AclRule{{
		RuleId: grantId, SrcAtoms: [][]byte{atom.Bytes()}, Targets: []*protocol.AclTarget{target},
		Via: []*protocol.AclTarget{proto.Clone(target).(*protocol.AclTarget)}, Actions: []uint32{uint32(protocol.AclAction_ACL_ACTION_ROUTE)},
		PortsLimited: true, Expires: expiresMs, SourceRuleId: requestRuleId,
	}}
	grantAcl, err := sidecar.NewAclState(rows, state)
	if err != nil {
		t.Fatal(err)
	}
	engine := sidecar.NewAclEngine(grantee.SidecarId, nil, nil, &sidecar.AclEngineSettings{ClockSkew: 0})
	details := &testMcpGrantDetails{grantId: grantId, detail: &protocol.CanonicalActionDetail{
		Cidrs: []string{"198.51.100.0/25"}, GrantDst: []string{"sidecar:" + hex.EncodeToString(via.SidecarId.Bytes()) + ":tcp:22"},
	}}
	if err := engine.InstallWithGrants(grantAcl, nil, details); err != nil {
		t.Fatal(err)
	}
	env.tools.identity = &sidecar.SidecarIdentity{NetworkId: env.networkId, SidecarId: grantee.SidecarId}
	env.daemon.hostNetwork(env.networkId, &testMcpEngineNetwork{fakeMcpTeamNetwork: env.team, engine: engine})

	conn := env.conn("2025-11-25")
	checkRange := func(cidr string) *mcpAclCheckOut {
		t.Helper()
		out := &mcpAclCheckOut{}
		testViewData(t, env.callTool(conn, "2025-11-25", "acl_check", map[string]any{"action": "route", "resource": "ip:" + cidr}), out)
		return out
	}
	if inside := checkRange("198.51.100.0/26"); !inside.Allowed || inside.GrantId != hex.EncodeToString(grantId) {
		t.Errorf("a range the grant's detail holds: %+v", inside)
	}
	if wider := checkRange("198.51.100.0/24"); wider.Allowed || wider.Reason != "no_grant" {
		t.Errorf("a range wider than the grant's detail: %+v", wider)
	}

	env.clock.AdvanceTo(time.UnixMilli(expiresMs))
	if expired := checkRange("198.51.100.0/26"); expired.Allowed || expired.Reason != "no_grant" {
		t.Errorf("at the grant's expiry: %+v", expired)
	}
}
