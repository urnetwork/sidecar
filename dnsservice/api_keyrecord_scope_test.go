package dnsservice

// POST /dns/key-record's gate on a Team scope's host (MAIL-M8-09; §22.7's unconsented-device row): with a resolver the
// host's listen is judged in the scope it names, its member included, so a member scope's key is taken only from that
// member's consented devices; with no resolver, or one that cannot name the scope, every scope's host is unavailable,
// and the network's own mx asks no scope. The consent rule itself is AclState's, tested in the root (acl_mail_test.go);
// here a view stands in that answers it as that rule does.

import (
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// A view answering MayReceive as §8.5's consent rule does: a member scope's listen only from its member's device.
type testScopeReceiveView struct {
	// each device's member
	deviceMemberIds map[sidecar.Id]sidecar.Id
	// what the gate asked, in order
	asked []sidecar.AclScope
}

func (self *testScopeReceiveView) MayReceive(networkId sidecar.Id, receiver sidecar.AclSubject, scope sidecar.AclScope, now time.Time) sidecar.AclDecision {
	self.asked = append(self.asked, scope)
	if scope.MemberId != (sidecar.Id{}) && self.deviceMemberIds[receiver.Id] != scope.MemberId {
		return sidecar.AclDecision{Reason: sidecar.AclReasonUnconsented}
	}
	return sidecar.AclDecision{Allowed: true}
}

func TestDnsKeyRecordGateJudgesAScopesHostInItsScope(t *testing.T) {
	networkId, member, memberDevice, otherDevice := sidecar.NewId(), sidecar.NewId(), sidecar.NewId(), sidecar.NewId()
	view := &testScopeReceiveView{deviceMemberIds: map[sidecar.Id]sidecar.Id{memberDevice: member, otherDevice: sidecar.NewId()}}
	scopeOf := func(id sidecar.Id, scope string) (sidecar.AclScope, bool) {
		if id != networkId || scope != "eng" {
			return sidecar.AclScope{}, false
		}
		return sidecar.AclScope{Label: "eng", MemberId: member}, true
	}
	now := time.Unix(1_800_000_000, 0)
	gate := &dnsAclKeyRecordGate{view: view, scopeOf: scopeOf}
	if verdict := gate.MayReceive(networkId, memberDevice, "eng", now); verdict != DnsGateAllowed {
		t.Errorf("the member's consented device: %v", verdict)
	}
	if verdict := gate.MayReceive(networkId, otherDevice, "eng", now); verdict != DnsGateDenied {
		t.Errorf("an unconsented device: %v, want denied", verdict)
	}
	if verdict := gate.MayReceive(networkId, memberDevice, "ops", now); verdict != DnsGateUnavailable {
		t.Errorf("a scope the state does not name: %v, want unavailable", verdict)
	}
	if verdict := gate.MayReceive(networkId, otherDevice, "", now); verdict != DnsGateAllowed {
		t.Errorf("the network's own mx: %v", verdict)
	}
	if len(view.asked) != 3 || view.asked[0].MemberId != member || view.asked[2] != (sidecar.AclScope{}) {
		t.Errorf("asked %+v", view.asked)
	}

	unscoped := &dnsAclKeyRecordGate{view: view}
	if verdict := unscoped.MayReceive(networkId, memberDevice, "eng", now); verdict != DnsGateUnavailable {
		t.Errorf("no resolver: %v, want unavailable", verdict)
	}
	if verdict := NewDnsAclScopedKeyRecordGate(nil, scopeOf).MayReceive(networkId, memberDevice, "eng", now); verdict != DnsGateUnavailable {
		t.Errorf("no view: %v, want unavailable", verdict)
	}
}
