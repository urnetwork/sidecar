// What the bridge's external state tests reach in this package's own tests: posture_fixture_test.go's synthetic network
// and its signed log, so a test drives a bridge through Pending, states and verified deltas as its sidecar role and the
// log would, with statements the owner's phone, an admin device, signs about any id.

package device

import (
	"testing"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The fixture network's log, positions 1 on, and its newest base.
type BridgeLogFixtureForTest struct {
	fixture  *postureFixture
	lastBase uint64
}

// A network with members and devices and no log yet.
func NewBridgeLogFixtureForTest(t testing.TB) *BridgeLogFixtureForTest {
	return &BridgeLogFixtureForTest{fixture: newPostureFixture(t)}
}

// The Pending this device's sidecar role sends.
func (self *BridgeLogFixtureForTest) Pending() *bridge.Pending {
	return self.fixture.pending()
}

// A base at the next position, with has_document, by the owner's phone.
func (self *BridgeLogFixtureForTest) Base(hasDocument bool) uint64 {
	self.lastBase = self.fixture.base(self.fixture.ownerPhone, hasDocument)
	return self.lastBase
}

// A tick at the next position.
func (self *BridgeLogFixtureForTest) Tick() uint64 {
	return self.fixture.tick()
}

// The newest position.
func (self *BridgeLogFixtureForTest) Tip() uint64 {
	return self.fixture.tip()
}

// A state at the newest position carrying rules, saying hasDocument, and the log from the newest base that vouches for
// it. A test sets its identities and listeners before passing it on.
func (self *BridgeLogFixtureForTest) State(rules []byte, hasDocument bool) (*bridge.BridgeState, *PostureLog) {
	state := self.fixture.state(self.fixture.tip(), hasDocument)
	state.Rules = rules
	return state, self.fixture.log(self.lastBase, self.fixture.tip())
}

// The entries from to through, both included: deltas after a pin.
func (self *BridgeLogFixtureForTest) Deltas(from uint64, through uint64) *PostureLog {
	return self.fixture.log(from, through)
}

// A SidecarRevoke of sidecarId, which the posture applies on its identity signature alone, covered.
func (self *BridgeLogFixtureForTest) SidecarRevoke(sidecarId []byte) uint64 {
	return self.fixture.statement(self.fixture.ownerPhone, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_SIDECAR_REVOKE,
		&bridge.SidecarRevoke{Header: self.fixture.header(), SidecarId: sidecarId, Reason: bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED})
}

// A MemberRevoke of memberId.
func (self *BridgeLogFixtureForTest) MemberRevoke(memberId []byte) uint64 {
	return self.fixture.statement(self.fixture.ownerPhone, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_MEMBER_REVOKE,
		&bridge.MemberRevoke{Header: self.fixture.header(), MemberId: memberId})
}

// A Suspend of subject under suspendId.
func (self *BridgeLogFixtureForTest) Suspend(subject []byte, suspendId []byte) uint64 {
	return self.fixture.suspend(self.fixture.ownerPhone, subject, suspendId)
}

// A GrantRevoke of grantId.
func (self *BridgeLogFixtureForTest) GrantRevoke(grantId []byte) uint64 {
	return self.fixture.statement(self.fixture.ownerPhone, bridge.SignedPurposeAcl, bridge.SignedType_SIGNED_GRANT_REVOKE,
		&bridge.GrantRevoke{Header: self.fixture.header(), GrantId: grantId})
}

// A BridgeWithdraw of ruleId in mode.
func (self *BridgeLogFixtureForTest) BridgeWithdraw(ruleId []byte, mode bridge.BridgeWithdrawMode) uint64 {
	return self.fixture.statement(self.fixture.ownerPhone, bridge.SignedPurposeBridge, bridge.SignedType_SIGNED_BRIDGE_WITHDRAW,
		&bridge.BridgeWithdraw{Header: self.fixture.header(), RuleId: ruleId, Mode: mode})
}

// A posture store holding nothing.
func (self *BridgeLogFixtureForTest) EmptyStore() PostureStore {
	return newMemoryPostureStore()
}

// The fixture's network_id, which its Pending anchors.
func (self *BridgeLogFixtureForTest) NetworkId() []byte {
	return self.fixture.networkId
}
