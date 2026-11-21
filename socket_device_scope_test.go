//go:build !sidecar_http && !ios_extension && !js

package sidecar

import (
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A listener with broad grants for public hosts must still hold its signed member scope.
// Revoking that scope closes established TLS and SMTP streams and refuses an open that
// overlaps the update, even though the registration service already issued its ticket.
func TestSocketDeviceFollowsSignedPublicScope(t *testing.T) {
	net := newTestConfigNet(t)
	fixture := newTestListenFixtureIn(t, net.networkId)
	member := testConfigId("listener member")
	net.admitMember(net.owner, member, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	signer := newTestSocketSigner("listener")
	device := testConfigDevice{sidecarId: signer.sidecarId, key: signer.privateKey, memberId: member}
	net.admitDevice(net.owner, device, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
	second := net.device("unconsented listener", member)
	net.admitDevice(net.owner, second, 0)
	world := newAclCompileWorld("public sockets")
	world.setPolicy(t, `{"grants":[
		{"src":["autogroup:member"],"dst":["dns:app","dns:*.crew","dns:*.eng","dns:*.unknown"],"allow":["publish"]},
		{"src":["autogroup:member"],"dst":["sock:tls/443/app","sock:tls/443/*.crew","sock:tls/443/*.eng","sock:tls/443/*.unknown","sock:smtp/25/mx.crew"],"allow":["listen"]}
	]}`)
	encoded := testConfigMarshal(t, world.compile(t))
	engine := NewAclEngine(device.sidecarId, nil, nil, nil)
	policy := NewSocketEnginePolicy(engine)
	fixture.component.SetPolicy(policy)
	install := func(scopeMember Id) {
		t.Helper()
		state := net.log.State()
		rows := state.Rows()
		rows.TeamScopes = []*bridge.TeamScopeRow{
			{Label: "crew", Owner: &bridge.TeamScopeRow_MemberId{MemberId: scopeMember.Bytes()}},
			{Label: "eng", Owner: &bridge.TeamScopeRow_TagAtom{TagAtom: testConfigId("engineering tag").Bytes()}},
		}
		rows.Acl = encoded
		if verdict := net.pushBase(net.owner, rows, net.n, state.Base().GetConfigVersion()+1, 0); !verdict.Accepted() {
			t.Fatal(verdict.Refusal)
		}
		acl, err := net.log.State().Acl()
		if err != nil {
			t.Fatal(err)
		}
		if err := engine.Install(acl, nil); err != nil {
			t.Fatal(err)
		}
		fixture.component.PolicyChanged()
	}
	install(member)
	for _, check := range []struct {
		sidecar Id
		host    string
		want    bool
	}{
		{device.sidecarId, "app.crew", true}, {second.sidecarId, "app.crew", false},
		{net.owner.sidecarId, "app.crew", false}, {device.sidecarId, "app.unknown", false},
		{net.owner.sidecarId, "app.eng", true}, {device.sidecarId, "app", true},
	} {
		subject := AclSidecarSubject(check.sidecar)
		socket := AclSocketName{PublicName: "tls/443/" + check.host}
		listen, publish := policy.MayListen(subject, socket, fixture.clock.Now()), policy.MayPublish(subject, check.host, fixture.clock.Now())
		if listen.Allowed != check.want || publish.Allowed != check.want {
			t.Fatalf("device %s on %s: listen %+v, publish %+v, want %t", check.sidecar, check.host, listen, publish, check.want)
		}
	}
	edgeRequest := func(listener *SocketListener) *socketAdmissionRequest {
		ticket := fixture.ticket(t, listener, func(ticket *protocol.SocketTicket) {
			ticket.DialerNetworkId = fixture.service.urnetworkEdge.Bytes()
			ticket.PolicyVersion = policy.Position()
		})
		return &socketAdmissionRequest{ticketBytes: ticket, sourceId: fixture.dialerId, edge: true}
	}
	tls := fixture.listen(t, "tls/443/app.crew", nil)
	defer tls.Close()
	smtp := fixture.listen(t, "smtp/25/mx.crew", nil)
	defer smtp.Close()
	smtp.SetServing(true)
	live := map[*SocketListener]*socketPipeEnd{}
	for _, listener := range []*SocketListener{tls, smtp} {
		stream, err := fixture.open(listener, edgeRequest(listener))
		if err != nil {
			t.Fatalf("opening %s in its member's scope: %v", listener.name, err)
		}
		live[listener] = stream
	}

	// newStream runs after ticket admission and before the new stream is tracked.
	err := tls.acceptStream(t.Context(), fixture.generation, edgeRequest(tls), func() socketStream {
		install(net.ownerMemberId)
		_, stream := newSocketStreamPipe(1024)
		return stream
	}, nil)
	if testRejectCode(err) != protocol.StreamRejectCode_SR_DENIED {
		t.Fatalf("open during scope change: %v", err)
	}
	for listener, stream := range live {
		if count := listener.inflightCount(); count != 0 {
			t.Fatalf("%s: %d streams still live after scope change", listener.name, count)
		}
		var reset *socketStreamResetError
		if _, err := stream.Read(make([]byte, 1)); !errors.As(err, &reset) || reset.Code != protocol.StreamResetCode_RST_REVOKED {
			t.Fatalf("%s: live stream ended with %v", listener.name, err)
		}
		if _, err := fixture.open(listener, edgeRequest(listener)); testRejectCode(err) != protocol.StreamRejectCode_SR_DENIED {
			t.Fatalf("%s: new open after scope change: %v", listener.name, err)
		}
	}
}
