package handler

// §9.10's rights (BAL-M12-06): who buys and who sees, by role, credential and device; the consented device the spend
// view asks for; compute:buy through CACL's grant; and a caller built from the verified state, never the request.

import (
	"errors"
	"testing"

	operator "github.com/urnetwork/operator-core"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// An untagged, consented member device of role.
func testComputeMemberDevice(role bridge.MemberRole) *ComputeApiCaller {
	sidecarId := operator.Id(sidecar.NewId())
	memberId := operator.Id(sidecar.NewId())
	return &ComputeApiCaller{
		Credential: ComputeApiCredentialSidecar, NetworkId: operator.Id(sidecar.NewId()), SidecarId: &sidecarId,
		MemberId: &memberId, Role: role, Consented: true,
	}
}

// §9.10's table row by row: who buys and who sees, from an untagged member device; agents' and MCP's credentials,
// tagged sidecars and enclaves never buying and seeing none, whatever role stands behind them.
func TestComputeCallerRolesMatchTheTable(t *testing.T) {
	type row struct {
		role        bridge.MemberRole
		mayBuy      bool
		seesNetwork bool
		seesOwn     bool
	}
	for _, r := range []row{
		{role: bridge.MemberRole_MEMBER_ROLE_OWNER, mayBuy: true, seesNetwork: true},
		{role: bridge.MemberRole_MEMBER_ROLE_BILLING_ADMIN, mayBuy: true, seesNetwork: true},
		{role: bridge.MemberRole_MEMBER_ROLE_ADMIN, seesNetwork: true},
		{role: bridge.MemberRole_MEMBER_ROLE_NETWORK_ADMIN, seesNetwork: true},
		{role: bridge.MemberRole_MEMBER_ROLE_IT_ADMIN, seesNetwork: true},
		{role: bridge.MemberRole_MEMBER_ROLE_AUDITOR, seesNetwork: true},
		{role: bridge.MemberRole_MEMBER_ROLE_MEMBER, seesOwn: true},
		{role: bridge.MemberRole_MEMBER_ROLE_UNSPECIFIED},
	} {
		caller := testComputeMemberDevice(r.role)
		member, seesOwn := caller.SeesMember()
		if caller.MayBuy() != r.mayBuy || caller.SeesNetwork() != r.seesNetwork || seesOwn != r.seesOwn {
			t.Errorf("%s: buys %v, sees the network %v, sees its own %v", r.role, caller.MayBuy(), caller.SeesNetwork(), seesOwn)
		}
		if seesOwn && member != *caller.MemberId {
			t.Errorf("%s sees another member's", r.role)
		}

		// the same role behind an agent's credential, a tagged sidecar or an enclave: never
		for label, other := range map[string]*ComputeApiCaller{
			"an agent's credential": func() *ComputeApiCaller {
				c := testComputeMemberDevice(r.role)
				c.Credential = ComputeApiCredentialAgent
				return c
			}(),
			"a tagged sidecar": func() *ComputeApiCaller {
				c := testComputeMemberDevice(r.role)
				c.Tagged = true
				return c
			}(),
			"an enclave": func() *ComputeApiCaller {
				c := testComputeMemberDevice(r.role)
				c.Enclave = true
				return c
			}(),
			"a Delegation's agent": func() *ComputeApiCaller {
				c := testComputeMemberDevice(r.role)
				c.DelegationAdmitted = true
				return c
			}(),
		} {
			if _, own := other.SeesMember(); other.MayBuy() || other.SeesNetwork() || own {
				t.Errorf("%s of %s buys %v or sees", label, r.role, other.MayBuy())
			}
		}
	}

	// the network's credential buys and sees by its user's role
	owner := &ComputeApiCaller{Credential: ComputeApiCredentialNetwork, Role: bridge.MemberRole_MEMBER_ROLE_OWNER}
	if !owner.MayBuy() || !owner.SeesNetwork() || owner.ConsentedDevice() {
		t.Error("the Owner's network credential")
	}
	auditor := &ComputeApiCaller{Credential: ComputeApiCredentialNetwork, Role: bridge.MemberRole_MEMBER_ROLE_AUDITOR}
	if auditor.MayBuy() || !auditor.SeesNetwork() {
		t.Error("an Auditor's network credential")
	}
	// no one
	if nobody := (&ComputeApiCaller{}); nobody.MayBuy() || nobody.SeesNetwork() || nobody.ConsentedDevice() {
		t.Error("the zero caller holds a right")
	}
}

// Buying asks for an untagged member device or the network's credential: an Owner's tagged sidecar, enclave,
// Delegation-admitted agent or agent's token never buys, and a device with no member never does.
func TestComputeBuyNeedsAnUntaggedMemberDevice(t *testing.T) {
	if !testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_OWNER).MayBuy() {
		t.Fatal("the Owner's untagged device")
	}
	// an ephemeral untagged device of the Owner is still a member device: buying asks no consent (§14.3)
	ephemeral := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	ephemeral.Ephemeral = true
	if !ephemeral.MayBuy() {
		t.Error("the Owner's ephemeral untagged device")
	}
	for label, adjust := range map[string]func(caller *ComputeApiCaller){
		"tagged":              func(caller *ComputeApiCaller) { caller.Tagged = true },
		"an enclave":          func(caller *ComputeApiCaller) { caller.Enclave = true },
		"Delegation-admitted": func(caller *ComputeApiCaller) { caller.DelegationAdmitted = true },
		"an agent's token":    func(caller *ComputeApiCaller) { caller.Credential = ComputeApiCredentialAgent },
		"no member":           func(caller *ComputeApiCaller) { caller.MemberId = nil },
		"no sidecar":          func(caller *ComputeApiCaller) { caller.SidecarId = nil },
	} {
		caller := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
		adjust(caller)
		if caller.MayBuy() {
			t.Errorf("the Owner's device %s buys", label)
		}
	}
}

// The spend view's device: untagged, consented for its member, neither ephemeral nor Delegation-admitted nor an
// enclave, never the network's credential or an agent's token.
func TestComputeConsentedDeviceRefusesTaggedEnclaveEphemeralAndDelegation(t *testing.T) {
	if !testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_MEMBER).ConsentedDevice() {
		t.Fatal("a member's consented device")
	}
	for label, adjust := range map[string]func(caller *ComputeApiCaller){
		"tagged":              func(caller *ComputeApiCaller) { caller.Tagged = true },
		"an enclave":          func(caller *ComputeApiCaller) { caller.Enclave = true },
		"ephemeral":           func(caller *ComputeApiCaller) { caller.Ephemeral = true },
		"Delegation-admitted": func(caller *ComputeApiCaller) { caller.DelegationAdmitted = true },
		"not consented":       func(caller *ComputeApiCaller) { caller.Consented = false },
		"the network's":       func(caller *ComputeApiCaller) { caller.Credential = ComputeApiCredentialNetwork },
		"an agent's token":    func(caller *ComputeApiCaller) { caller.Credential = ComputeApiCredentialAgent },
		"no member":           func(caller *ComputeApiCaller) { caller.MemberId = nil },
	} {
		caller := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
		adjust(caller)
		if caller.ConsentedDevice() {
			t.Errorf("a device %s is the person's consented device", label)
		}
	}
}

// A member the policy grants compute:buy buys, through CACL's check, once registered; the grant never lifts a tagged
// sidecar or an agent's token; and with no check registered, no Member buys.
func TestComputeMemberWithBuyGrantMayBuy(t *testing.T) {
	member := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	if member.MayBuy() {
		t.Fatal("a Member buys with no grant check registered")
	}
	granted := map[operator.Id]bool{*member.MemberId: true}
	saved := computeBuyGrant
	t.Cleanup(func() { computeBuyGrant = saved })
	computeBuyGrant = nil
	RegisterComputeBuyGrant(func(caller *ComputeApiCaller) bool {
		return caller.MemberId != nil && granted[*caller.MemberId]
	})
	if !member.MayBuy() {
		t.Error("a Member with the grant")
	}
	if other := testComputeMemberDevice(bridge.MemberRole_MEMBER_ROLE_MEMBER); other.MayBuy() {
		t.Error("a Member without the grant")
	}
	tagged := *member
	tagged.Tagged = true
	agent := *member
	agent.Credential = ComputeApiCredentialAgent
	if tagged.MayBuy() || agent.MayBuy() {
		t.Error("the grant lifted a tagged sidecar or an agent's token")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("a second grant check registered")
			}
		}()
		RegisterComputeBuyGrant(func(caller *ComputeApiCaller) bool { return true })
	}()
}

// A verified state as a test writes it.
type testComputeVerifiedState struct {
	sidecars  map[sidecar.Id]*bridge.SidecarRow
	members   map[sidecar.Id]*bridge.MemberRow
	consented map[sidecar.Id]bool
}

func (self *testComputeVerifiedState) SidecarRow(sidecarId sidecar.Id) *bridge.SidecarRow {
	return self.sidecars[sidecarId]
}

func (self *testComputeVerifiedState) Member(memberId sidecar.Id) *bridge.MemberRow {
	return self.members[memberId]
}

func (self *testComputeVerifiedState) Consented(sidecarId sidecar.Id) bool {
	return self.consented[sidecarId]
}

// A caller from the verified state: its member's role, tags, enclave capability, Delegation and ephemeral mark from
// the rows, its consent from the state; a revoked, parked or unknown sidecar is no caller.
func TestComputeCallerComesFromTheVerifiedState(t *testing.T) {
	networkId := operator.Id(sidecar.NewId())
	memberId := sidecar.NewId()
	device := sidecar.NewId()
	tagged := sidecar.NewId()
	enclave := sidecar.NewId()
	revoked := sidecar.NewId()
	state := &testComputeVerifiedState{
		sidecars: map[sidecar.Id]*bridge.SidecarRow{
			device:  {SidecarId: device.Bytes(), MemberId: memberId.Bytes()},
			tagged:  {SidecarId: tagged.Bytes(), TagIds: [][]byte{sidecar.NewId().Bytes()}, DelegationId: make([]byte, 32)},
			enclave: {SidecarId: enclave.Bytes(), MemberId: memberId.Bytes(), Capabilities: uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_ENCLAVE)},
			revoked: {SidecarId: revoked.Bytes(), MemberId: memberId.Bytes(), RevokedAt: 9},
		},
		members:   map[sidecar.Id]*bridge.MemberRow{memberId: {MemberId: memberId.Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_BILLING_ADMIN}},
		consented: map[sidecar.Id]bool{device: true},
	}
	caller, err := NewComputeApiSidecarCaller(state, networkId, device)
	if err != nil {
		t.Fatal(err)
	}
	if caller.Role != bridge.MemberRole_MEMBER_ROLE_BILLING_ADMIN || *caller.MemberId != memberId || !caller.Consented || !caller.MayBuy() || !caller.ConsentedDevice() {
		t.Errorf("the device's caller: %+v", caller)
	}
	caller, err = NewComputeApiSidecarCaller(state, networkId, tagged)
	if err != nil {
		t.Fatal(err)
	}
	if !caller.Tagged || !caller.DelegationAdmitted || caller.MemberId != nil || caller.MayBuy() {
		t.Errorf("the tagged sidecar's caller: %+v", caller)
	}
	caller, err = NewComputeApiSidecarCaller(state, networkId, enclave)
	if err != nil {
		t.Fatal(err)
	}
	if !caller.Enclave || caller.MayBuy() || caller.SeesNetwork() {
		t.Errorf("the enclave's caller: %+v", caller)
	}
	for _, sidecarId := range []sidecar.Id{revoked, sidecar.NewId()} {
		if _, err := NewComputeApiSidecarCaller(state, networkId, sidecarId); !errors.Is(err, ErrComputeApiCallerUnknown) {
			t.Errorf("a revoked or unknown sidecar: %v", err)
		}
	}
	if _, err := ComputeApiStateOf(nil); !errors.Is(err, ErrComputeApiCallerUnknown) {
		t.Errorf("no snapshot: %v", err)
	}
}
