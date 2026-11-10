// §7.9's forwarding row on the test network (D-TEAM-33; owner decision 197; DESIGN-DETAILS 4.2.6): a forwarding
// Delegation's shape and its one signer, each refusal beside the same statement without its fault; its key admitting
// nothing; its revocation with since_n 0 alone; supersession keeping one live a sidecar; its ends with its sidecar; its
// key's drop while the sidecar is suspended or parked and its return; and its rows, the reader key as a digest, equal at
// a long-running reader, a new device and a rows-only gate across a fold (FS-14's shape).

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A forwarding Delegation's statement naming device at the tip: the keys its VPN component would hold, from label,
// and no host client.
func (self *testConfigNet) forwardingStatement(device testConfigDevice, label string) (*protocol.Delegation, ed25519.PrivateKey) {
	key := testConfigDeviceKey("forwarding " + label)
	return &protocol.Delegation{
		Header:               self.header(),
		Pubkey:               key.Public().(ed25519.PublicKey),
		ReaderXwingPublicKey: bytes.Repeat(testConfigId("forwarding reader "+label).Bytes(), configXwingPublicKeyByteCount/len(Id{})),
		Forward:              &bridge.ForwardScope{ForwardSidecarId: device.sidecarId.Bytes()},
	}, key
}

// Files device's forwarding Delegation, signed by device, failing the test unless it takes effect. The result signs
// as a Delegation's key does, for the statements its key must be refused on.
func (self *testConfigNet) forward(device testConfigDevice, label string) *testConfigDelegation {
	self.t.Helper()
	statement, key := self.forwardingStatement(device, label)
	verdict := self.mustPost(device, bridge.SignedType_SIGNED_DELEGATION, statement)
	return &testConfigDelegation{id: bytes.Clone(verdict.StatementId[:]), key: key}
}

// A DelegationRevoke of delegationId at the tip.
func (self *testConfigNet) delegationRevoke(delegationId []byte, sinceN uint64) *protocol.DelegationRevoke {
	return &protocol.DelegationRevoke{Header: self.header(), DelegationId: bytes.Clone(delegationId), SinceN: sinceN}
}

// How many forwarding Delegations of the sidecar are neither ended nor superseded at the reader's state.
func testConfigLiveForwardingCount(state *ConfigState, sidecarId Id) int {
	count := 0
	for _, row := range state.Delegations() {
		if bytes.Equal(row.GetForwardSidecarId(), sidecarId.Bytes()) && row.GetEndedAt() == 0 && row.GetSupersededAt() == 0 {
			count += 1
		}
	}
	return count
}

// A forwarding Delegation takes effect from a plain Member's device with no tag and no admin's signature, so none of
// D-TEAM-30's agent rules judged it, and its row is DESIGN-DETAILS 4.2.2's: the sidecar its signer, no tags, not_after
// or max_admits, the reader key's digest in field 16 and field 10 empty.
func TestAForwardingDelegationTakesEffectFromItsOwnSidecar(t *testing.T) {
	net := newTestConfigNet(t)
	_, laptop := net.consentedMember("m")
	statement, key := net.forwardingStatement(laptop, "laptop")
	hostClientId, hostClientKey := testConfigId("host client"), testConfigDeviceKey("host client").Public().(ed25519.PublicKey)
	statement.Forward.HostClientId, statement.Forward.HostClientPublicKey = hostClientId.Bytes(), hostClientKey
	verdict := net.mustPost(laptop, bridge.SignedType_SIGNED_DELEGATION, statement)

	state := net.log.State()
	row := state.Delegation(verdict.StatementId[:])
	if row == nil {
		t.Fatal("no row")
	}
	readerKeySha256 := sha256.Sum256(statement.GetReaderXwingPublicKey())
	want := &bridge.DelegationRow{
		DelegationId:        verdict.StatementId[:],
		Signer:              laptop.sidecarId.Bytes(),
		At:                  verdict.Pin.GetVersion(),
		Pubkey:              key.Public().(ed25519.PublicKey),
		ForwardSidecarId:    laptop.sidecarId.Bytes(),
		HostClientId:        hostClientId.Bytes(),
		HostClientPublicKey: hostClientKey,
		ReaderKeySha256:     readerKeySha256[:],
	}
	if !proto.Equal(row, want) {
		t.Errorf("the row is %v", row)
	}
	if len(row.GetReaderXwingPublicKey()) != 0 || len(row.GetReaderKeySha256()) != sha256.Size {
		t.Error("field 10 is not empty or field 16 is no digest")
	}
	if !ConfigDelegationRowForwards(row) || state.ForwardingDelegation(laptop.sidecarId) != row {
		t.Error("the row is not its sidecar's live forwarding Delegation")
	}
	delegationId, publicKey, ok := state.ForwardingKey(laptop.sidecarId)
	if !ok || !bytes.Equal(delegationId, verdict.StatementId[:]) || !bytes.Equal(publicKey, key.Public().(ed25519.PublicKey)) {
		t.Errorf("the forwarding key in force: %x %x %v", delegationId, publicKey, ok)
	}
	if state.ForwardingDelegation(net.owner.sidecarId) != nil {
		t.Error("a sidecar with no forwarding Delegation has one")
	}
	if _, _, ok := state.ForwardingKey(net.owner.sidecarId); ok {
		t.Error("a sidecar with no forwarding Delegation has a key in force")
	}
	if _, ended := state.DelegationEnded(row.GetDelegationId()); ended {
		t.Error("a new forwarding Delegation is ended")
	}
	net.everyReaderAgrees()
}

// Each refusal of the forwarding row beside its positive twin, the same statement without the fault: another sidecar's
// signature, an Owner's included; tags, max_admits or a not_after; a short forwarding or reader key; a malformed or
// missing forward_sidecar_id; and a host client's id and key that do not come together.
func TestAForwardingDelegationsRefusalsEachWithItsTwin(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	phone := net.device("m phone", member)
	net.admitDevice(laptop, phone, 0)
	hostClientKey := testConfigDeviceKey("host client").Public().(ed25519.PublicKey)

	cases := []struct {
		name   string
		signer testConfigDevice
		mutate func(delegation *protocol.Delegation)
		want   error
	}{
		{name: "signed by another device of its member", signer: laptop, want: ErrConfigAuthority},
		{name: "signed by an Owner's device", signer: net.owner, want: ErrConfigAuthority},
		{name: "with a tag", signer: phone, want: ErrConfigRule, mutate: func(delegation *protocol.Delegation) {
			delegation.TagIds = [][]byte{testConfigId("tag ci").Bytes()}
		}},
		{name: "with max_admits", signer: phone, want: ErrConfigRule, mutate: func(delegation *protocol.Delegation) {
			delegation.MaxAdmits = 1
		}},
		{name: "with a not_after", signer: phone, want: ErrConfigRule, mutate: func(delegation *protocol.Delegation) {
			delegation.NotAfter = net.timeMs + 24*60*60*1000
		}},
		{name: "a short reader key", signer: phone, want: ErrConfigRule, mutate: func(delegation *protocol.Delegation) {
			delegation.ReaderXwingPublicKey = delegation.ReaderXwingPublicKey[:configXwingPublicKeyByteCount-1]
		}},
		{name: "an X25519-sized reader key", signer: phone, want: ErrConfigRule, mutate: func(delegation *protocol.Delegation) {
			delegation.ReaderXwingPublicKey = delegation.ReaderXwingPublicKey[:32]
		}},
		{name: "no reader key", signer: phone, want: ErrConfigRule, mutate: func(delegation *protocol.Delegation) {
			delegation.ReaderXwingPublicKey = nil
		}},
		{name: "a short forwarding key", signer: phone, want: ErrConfigRule, mutate: func(delegation *protocol.Delegation) {
			delegation.Pubkey = delegation.Pubkey[:ed25519.PublicKeySize-1]
		}},
		{name: "a short forward_sidecar_id", signer: phone, want: ErrConfigRule, mutate: func(delegation *protocol.Delegation) {
			delegation.Forward.ForwardSidecarId = delegation.Forward.ForwardSidecarId[:8]
		}},
		{name: "a forward naming no sidecar", signer: phone, want: ErrConfigRule, mutate: func(delegation *protocol.Delegation) {
			delegation.Forward = &bridge.ForwardScope{}
		}},
		{name: "a host client with no key", signer: phone, want: ErrConfigRule, mutate: func(delegation *protocol.Delegation) {
			delegation.Forward.HostClientId = testConfigId("host client").Bytes()
		}},
		{name: "a host client key with no client", signer: phone, want: ErrConfigRule, mutate: func(delegation *protocol.Delegation) {
			delegation.Forward.HostClientPublicKey = hostClientKey
		}},
		{name: "a short host client id", signer: phone, want: ErrConfigRule, mutate: func(delegation *protocol.Delegation) {
			delegation.Forward.HostClientId, delegation.Forward.HostClientPublicKey = testConfigId("host client").Bytes()[:8], hostClientKey
		}},
		{name: "a short host client key", signer: phone, want: ErrConfigRule, mutate: func(delegation *protocol.Delegation) {
			delegation.Forward.HostClientId, delegation.Forward.HostClientPublicKey = testConfigId("host client").Bytes(), hostClientKey[:31]
		}},
	}
	for _, c := range cases {
		statement, _ := net.forwardingStatement(phone, c.name)
		if c.mutate != nil {
			c.mutate(statement)
		}
		verdict := net.post(c.signer, bridge.SignedType_SIGNED_DELEGATION, statement)
		if verdict.Accepted() || !errors.Is(verdict.Refusal, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, verdict.Refusal, c.want)
		}
		if net.log.State().Delegation(verdict.StatementId[:]) != nil {
			t.Errorf("%s: a refused Delegation left a row", c.name)
		}
		// the twin: the same statement, its sidecar's own signature and no fault
		twin, _ := net.forwardingStatement(phone, c.name)
		if accepted := net.post(phone, bridge.SignedType_SIGNED_DELEGATION, twin); !accepted.Accepted() {
			t.Errorf("%s: its twin was refused: %v", c.name, accepted.Refusal)
		}
	}
	if count := testConfigLiveForwardingCount(net.log.State(), phone.sidecarId); count != 1 {
		t.Errorf("%d live forwarding Delegations of the phone after its twins", count)
	}
	net.everyReaderAgrees()
}

// The sidecar must stand: a read_only device, a revoked one and one never admitted file no forwarding Delegation,
// where the same member's standing device does.
func TestAForwardingDelegationNeedsItsSidecarStanding(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	kiosk, gone, stranger := net.device("m kiosk", member), net.device("m gone", member), net.device("m stranger", member)
	net.admitDevice(laptop, kiosk, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY))
	net.admitDevice(laptop, gone, 0)
	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(gone, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED))

	statement, _ := net.forwardingStatement(kiosk, "kiosk")
	net.mustRefuse(kiosk, bridge.SignedType_SIGNED_DELEGATION, statement, ErrConfigReadOnly)
	statement, _ = net.forwardingStatement(gone, "gone")
	net.mustRefuse(gone, bridge.SignedType_SIGNED_DELEGATION, statement, ErrConfigAuthority)
	statement, _ = net.forwardingStatement(stranger, "stranger")
	net.mustRefuse(stranger, bridge.SignedType_SIGNED_DELEGATION, statement, ErrConfigSigner)
	net.forward(laptop, "laptop")
	for _, device := range []testConfigDevice{kiosk, gone, stranger} {
		if net.log.State().ForwardingDelegation(device.sidecarId) != nil {
			t.Errorf("%s holds a forwarding Delegation", device.sidecarId)
		}
	}
	net.everyReaderAgrees()
}

// A forwarding Delegation admits nothing: a SidecarAdmit or an AdmissionConfirm its key signs is refused at its
// signer, where an agent's Delegation's key admits and the sidecar's own identity key confirms; and its key signs no
// other statement of the log either.
func TestAForwardingKeyAdmitsNothing(t *testing.T) {
	net, ci, _ := newTestConfigTagNet(t)
	member, laptop := net.consentedMember("m")
	phone := net.device("m phone", member)
	net.admitDevice(laptop, phone, 0)
	forwarding := net.forward(laptop, "laptop")
	forwarding.tagIds = []Id{ci}
	notAfter := net.timeMs + 24*60*60*1000

	agent := net.device("forwarding-admitted agent", Id{})
	if verdict := net.postByDelegation(forwarding, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.agentAdmission(forwarding, agent, false, notAfter)); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigSigner) {
		t.Errorf("a tagged admission by a forwarding key: %v", verdict.Refusal)
	}
	tablet := net.device("m tablet", member)
	if verdict := net.postByDelegation(forwarding, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(tablet, nil, false, 0, 0)); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigSigner) {
		t.Errorf("a member device's admission by a forwarding key: %v", verdict.Refusal)
	}
	confirm := func() *protocol.AdmissionConfirm {
		return &protocol.AdmissionConfirm{Header: net.header(), SidecarId: phone.sidecarId.Bytes()}
	}
	if verdict := net.postByDelegation(forwarding, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, confirm()); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigSigner) {
		t.Errorf("an AdmissionConfirm by a forwarding key: %v", verdict.Refusal)
	}
	revoke := net.delegationRevoke(forwarding.id, 0)
	if verdict := net.postByDelegation(forwarding, bridge.SignedType_SIGNED_DELEGATION_REVOKE, revoke); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigSigner) {
		t.Errorf("a DelegationRevoke by a forwarding key: %v", verdict.Refusal)
	}
	state := net.log.State()
	if state.SidecarRow(agent.sidecarId) != nil || state.SidecarRow(tablet.sidecarId) != nil || state.Delegation(forwarding.id).GetAdmissions() != 0 {
		t.Error("a forwarding key admitted a sidecar")
	}

	// the twins: an agent's Delegation admits its agent, and the laptop's identity key admits and confirms
	agentDelegation := net.delegate(net.owner, "ci", []Id{ci}, 2, net.timeMs+7*24*60*60*1000)
	if verdict := net.postByDelegation(agentDelegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.agentAdmission(agentDelegation, agent, false, agentDelegation.notAfter)); !verdict.Accepted() {
		t.Errorf("an agent's Delegation's admission: %v", verdict.Refusal)
	}
	net.admitDevice(laptop, tablet, 0)
	net.mustPost(laptop, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, confirm())
	if net.log.State().ForwardingDelegation(laptop.sidecarId) == nil {
		t.Error("the refusals ended the forwarding Delegation")
	}
	net.everyReaderAgrees()
}

// A forwarding Delegation's revocation carries since_n 0 only, from its sidecar, a device allowed to revoke that
// sidecar or an admin; another member's device is refused. It ends the Delegation and drops its key at its position,
// and a repeat ends nothing twice.
func TestAForwardingRevokeTakesSinceNZeroFromItsSidecarOrAnAdmin(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	phone := net.device("m phone", member)
	net.admitDevice(laptop, phone, 0)
	_, otherLaptop := net.consentedMember("other")

	first := net.forward(phone, "first")
	net.mustRefuse(net.owner, bridge.SignedType_SIGNED_DELEGATION_REVOKE, net.delegationRevoke(first.id, first.at(net)), ErrConfigRule)
	net.mustRefuse(phone, bridge.SignedType_SIGNED_DELEGATION_REVOKE, net.delegationRevoke(first.id, 1), ErrConfigRule)
	if _, ended := net.log.State().DelegationEnded(first.id); ended {
		t.Fatal("a refused revocation ended the Delegation")
	}
	net.mustRefuse(otherLaptop, bridge.SignedType_SIGNED_DELEGATION_REVOKE, net.delegationRevoke(first.id, 0), ErrConfigAuthority)

	// since_n 0 from an admin
	revoked := net.mustPost(net.owner, bridge.SignedType_SIGNED_DELEGATION_REVOKE, net.delegationRevoke(first.id, 0))
	state := net.log.State()
	if endedAt, ended := state.DelegationEnded(first.id); !ended || endedAt != revoked.Pin.GetVersion() {
		t.Errorf("ended at %d, %v", endedAt, ended)
	}
	if droppedAt, dropped := state.DelegationKeyDropped(first.id); !dropped || droppedAt != revoked.Pin.GetVersion() {
		t.Errorf("key dropped at %d, %v", droppedAt, dropped)
	}
	if state.ForwardingDelegation(phone.sidecarId) != nil {
		t.Error("a revoked forwarding Delegation is live")
	}
	if _, _, ok := state.ForwardingKey(phone.sidecarId); ok {
		t.Error("a revoked forwarding Delegation's key is in force")
	}
	// a repeat takes effect and ends nothing twice
	net.mustPost(phone, bridge.SignedType_SIGNED_DELEGATION_REVOKE, net.delegationRevoke(first.id, 0))
	if endedAt, _ := net.log.State().DelegationEnded(first.id); endedAt != revoked.Pin.GetVersion() {
		t.Errorf("a repeat moved the end to %d", endedAt)
	}

	// from the sidecar itself, and from its member's consented device, which may revoke it (§5.6)
	second := net.forward(phone, "second")
	net.mustPost(phone, bridge.SignedType_SIGNED_DELEGATION_REVOKE, net.delegationRevoke(second.id, 0))
	third := net.forward(phone, "third")
	net.mustPost(laptop, bridge.SignedType_SIGNED_DELEGATION_REVOKE, net.delegationRevoke(third.id, 0))
	for _, forwarding := range []*testConfigDelegation{second, third} {
		if _, ended := net.log.State().DelegationEnded(forwarding.id); !ended {
			t.Error("a revocation by its sidecar or its member's device did not end it")
		}
	}
	// revoked, the sidecar files another, which is live
	fourth := net.forward(phone, "fourth")
	if row := net.log.State().ForwardingDelegation(phone.sidecarId); row == nil || !bytes.Equal(row.GetDelegationId(), fourth.id) {
		t.Error("a forwarding Delegation filed after a revocation is not live")
	}
	net.everyReaderAgrees()
}

// The position that carried a Delegation, from the reader's state.
func (self *testConfigDelegation) at(net *testConfigNet) uint64 {
	return net.log.State().Delegation(self.id).GetAt()
}

// A newer forwarding Delegation of a sidecar supersedes the one live before it at the newer one's position: one stays
// live, superseded_at is set, the older one is not ended and its key not dropped, and no repo's holders shrink. A
// DelegationRevoke naming the superseded one takes effect and changes nothing live. Another sidecar's is untouched.
func TestANewerForwardingDelegationSupersedesTheOlder(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	phone := net.device("m phone", member)
	net.admitDevice(laptop, phone, 0)
	repoId := testConfigId("general repo")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: net.header(), RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	laptops := net.forward(laptop, "laptop")

	first := net.forward(phone, "first")
	shrunkBefore := net.log.State().ShrunkAt(repoId)
	second := net.forward(phone, "second")
	state := net.log.State()
	firstRow, secondRow := state.Delegation(first.id), state.Delegation(second.id)
	if firstRow.GetSupersededAt() != secondRow.GetAt() || firstRow.GetEndedAt() != 0 || firstRow.GetKeyDroppedAt() != 0 {
		t.Errorf("the older one: superseded at %d, ended at %d, key dropped at %d", firstRow.GetSupersededAt(), firstRow.GetEndedAt(), firstRow.GetKeyDroppedAt())
	}
	if secondRow.GetSupersededAt() != 0 || state.ForwardingDelegation(phone.sidecarId) != secondRow {
		t.Error("the newer one is not the live one")
	}
	if testConfigLiveForwardingCount(state, phone.sidecarId) != 1 {
		t.Error("supersession left more than one live")
	}
	if state.ShrunkAt(repoId) != shrunkBefore {
		t.Errorf("supersession shrank a repo's holders at %d", state.ShrunkAt(repoId))
	}
	if row := state.ForwardingDelegation(laptop.sidecarId); row == nil || !bytes.Equal(row.GetDelegationId(), laptops.id) || row.GetSupersededAt() != 0 {
		t.Error("the phone's supersession reached the laptop's forwarding Delegation")
	}

	// a revocation of the superseded one takes effect and changes nothing live
	revoked := net.mustPost(phone, bridge.SignedType_SIGNED_DELEGATION_REVOKE, net.delegationRevoke(first.id, 0))
	state = net.log.State()
	if endedAt, ended := state.DelegationEnded(first.id); !ended || endedAt != revoked.Pin.GetVersion() {
		t.Error("the superseded one's revocation did not take effect")
	}
	if row := state.ForwardingDelegation(phone.sidecarId); row == nil || !bytes.Equal(row.GetDelegationId(), second.id) || row.GetKeyDroppedAt() != 0 {
		t.Error("the superseded one's revocation changed the live one")
	}
	if delegationId, _, ok := state.ForwardingKey(phone.sidecarId); !ok || !bytes.Equal(delegationId, second.id) {
		t.Error("the live one's key is not in force")
	}

	third := net.forward(phone, "third")
	state = net.log.State()
	if state.Delegation(second.id).GetSupersededAt() != state.Delegation(third.id).GetAt() || state.Delegation(first.id).GetSupersededAt() != secondRow.GetAt() {
		t.Error("a third one did not supersede the second at its own position alone")
	}
	if testConfigLiveForwardingCount(state, phone.sidecarId) != 1 {
		t.Error("more than one live after a third")
	}
	net.everyReaderAgrees()
}

// A forwarding Delegation ends with its sidecar, whatever revokes it: the sidecar's own sign-out, a lost or removed
// revocation by its member's device, a compromise revocation from before or after the Delegation, its member's
// removal, and an ephemeral device's reap. A superseded one ends there too.
func TestAForwardingDelegationEndsWithItsSidecar(t *testing.T) {
	cases := []struct {
		name      string
		ephemeral bool
		revoke    func(net *testConfigNet, member Id, laptop testConfigDevice, phone testConfigDevice, filedAt uint64) ConfigVerdict
	}{
		{name: "sign-out", revoke: func(net *testConfigNet, member Id, laptop testConfigDevice, phone testConfigDevice, filedAt uint64) ConfigVerdict {
			return net.mustPost(phone, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(phone, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
		}},
		{name: "lost", revoke: func(net *testConfigNet, member Id, laptop testConfigDevice, phone testConfigDevice, filedAt uint64) ConfigVerdict {
			return net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(phone, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
		}},
		{name: "removed", revoke: func(net *testConfigNet, member Id, laptop testConfigDevice, phone testConfigDevice, filedAt uint64) ConfigVerdict {
			return net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(phone, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED))
		}},
		{name: "compromise from before the Delegation", revoke: func(net *testConfigNet, member Id, laptop testConfigDevice, phone testConfigDevice, filedAt uint64) ConfigVerdict {
			return net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(phone, filedAt))
		}},
		{name: "compromise from after the Delegation", revoke: func(net *testConfigNet, member Id, laptop testConfigDevice, phone testConfigDevice, filedAt uint64) ConfigVerdict {
			return net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(phone, net.n))
		}},
		{name: "its member's removal", revoke: func(net *testConfigNet, member Id, laptop testConfigDevice, phone testConfigDevice, filedAt uint64) ConfigVerdict {
			return net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, &bridge.MemberRevoke{Header: net.header(), MemberId: member.Bytes()})
		}},
		{name: "an ephemeral device's reap", ephemeral: true, revoke: func(net *testConfigNet, member Id, laptop testConfigDevice, phone testConfigDevice, filedAt uint64) ConfigVerdict {
			verdict := net.tick(&bridge.ApiTick{ReapedSidecarIds: [][]byte{phone.sidecarId.Bytes()}})
			if !verdict.Accepted() {
				net.t.Fatalf("the reap: %v", verdict.Refusal)
			}
			return verdict
		}},
	}
	for _, c := range cases {
		net := newTestConfigNet(t)
		member, laptop := net.consentedMember("m")
		phone := net.device("m phone", member)
		if c.ephemeral {
			net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(phone, nil, true, net.timeMs+24*60*60*1000, 0))
		} else {
			net.admitDevice(laptop, phone, 0)
		}
		laptops := net.forward(laptop, "laptop")
		older := net.forward(phone, "older")
		live := net.forward(phone, "live")
		net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement(c.name))
		revoked := c.revoke(net, member, laptop, phone, live.at(net))

		state := net.log.State()
		for _, forwarding := range []*testConfigDelegation{older, live} {
			if endedAt, ended := state.DelegationEnded(forwarding.id); !ended || endedAt != revoked.Pin.GetVersion() {
				t.Errorf("%s: ended at %d, %v, want %d", c.name, endedAt, ended, revoked.Pin.GetVersion())
			}
			if _, dropped := state.DelegationKeyDropped(forwarding.id); !dropped {
				t.Errorf("%s: its key is not dropped", c.name)
			}
		}
		if state.ForwardingDelegation(phone.sidecarId) != nil {
			t.Errorf("%s: the revoked sidecar's forwarding Delegation is live", c.name)
		}
		if _, _, ok := state.ForwardingKey(phone.sidecarId); ok {
			t.Errorf("%s: the revoked sidecar's forwarding key is in force", c.name)
		}
		// the laptop's stands unless its member went with it
		_, laptopsEnded := state.DelegationEnded(laptops.id)
		if memberRemoved := state.Member(member) == nil; laptopsEnded != memberRemoved {
			t.Errorf("%s: the laptop's forwarding Delegation ended %v", c.name, laptopsEnded)
		}
		// revoked, the sidecar files no other
		statement, _ := net.forwardingStatement(phone, "after")
		if verdict := net.post(phone, bridge.SignedType_SIGNED_DELEGATION, statement); verdict.Accepted() {
			t.Errorf("%s: a revoked sidecar filed a forwarding Delegation", c.name)
		}
		net.everyReaderAgrees()
	}
}

// A forwarding Delegation's key drops while its sidecar is suspended and returns with it: at the Suspend's position,
// back at the Unsuspend that leaves no Suspend in force, the Delegation live throughout and never ended. One filed
// while its sidecar is suspended starts dropped.
func TestASuspendDropsAForwardingKeyUntilTheUnsuspend(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	phone := net.device("m phone", member)
	net.admitDevice(laptop, phone, 0)
	forwarding := net.forward(phone, "phone")
	laptops := net.forward(laptop, "laptop")
	suspend := func(label string) ConfigVerdict {
		return net.mustPost(net.owner, bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{Header: net.header(), Subject: phone.sidecarId.Bytes(), SuspendId: aclTestSuspendId(label)})
	}
	unsuspend := func(label string) ConfigVerdict {
		return net.mustPost(net.owner, bridge.SignedType_SIGNED_UNSUSPEND, &bridge.Unsuspend{Header: net.header(), Subject: phone.sidecarId.Bytes(), SuspendId: aclTestSuspendId(label)})
	}
	keyInForce := func() bool {
		_, _, ok := net.log.State().ForwardingKey(phone.sidecarId)
		return ok
	}

	suspended := suspend("one")
	state := net.log.State()
	if droppedAt, dropped := state.DelegationKeyDropped(forwarding.id); !dropped || droppedAt != suspended.Pin.GetVersion() {
		t.Errorf("key dropped at %d, %v", droppedAt, dropped)
	}
	if _, ended := state.DelegationEnded(forwarding.id); ended || state.ForwardingDelegation(phone.sidecarId) == nil || keyInForce() {
		t.Error("a Suspend ended the Delegation, or left its key in force")
	}
	if _, dropped := state.DelegationKeyDropped(laptops.id); dropped {
		t.Error("the phone's Suspend dropped the laptop's forwarding key")
	}
	// a second Suspend keeps the first drop's position, and one Unsuspend of two returns nothing
	suspend("two")
	unsuspend("one")
	if droppedAt, dropped := net.log.State().DelegationKeyDropped(forwarding.id); !dropped || droppedAt != suspended.Pin.GetVersion() || keyInForce() {
		t.Errorf("with one Suspend still in force: dropped at %d, %v", droppedAt, dropped)
	}
	// a newer one filed while suspended starts dropped
	newer, _ := net.forwardingStatement(phone, "while suspended")
	filed := net.mustPost(phone, bridge.SignedType_SIGNED_DELEGATION, newer)
	if droppedAt, dropped := net.log.State().DelegationKeyDropped(filed.StatementId[:]); !dropped || droppedAt != filed.Pin.GetVersion() || keyInForce() {
		t.Errorf("filed while suspended: dropped at %d, %v", droppedAt, dropped)
	}
	unsuspend("two")
	state = net.log.State()
	if _, dropped := state.DelegationKeyDropped(filed.StatementId[:]); dropped || !keyInForce() {
		t.Error("the key did not return with the Unsuspend")
	}
	if row := state.ForwardingDelegation(phone.sidecarId); row == nil || !bytes.Equal(row.GetDelegationId(), filed.StatementId[:]) || row.GetEndedAt() != 0 {
		t.Error("the live one after the Unsuspend is not the newer one")
	}
	// the superseded one keeps the drop it had: nothing returns to a Delegation that is not live
	if droppedAt, _ := state.DelegationKeyDropped(forwarding.id); droppedAt != suspended.Pin.GetVersion() {
		t.Errorf("the superseded one's drop moved to %d", droppedAt)
	}
	net.everyReaderAgrees()
}

// A park drops a forwarding key and a lift returns it: a device whose consent rests on a stolen phone's OwnerConfirm
// parks from that confirmation, after it filed its forwarding Delegation, so the Delegation is not void, its key
// drops at the revocation, and an admin's AdmissionConfirm returns it.
func TestAParkDropsAForwardingKeyUntilTheLift(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	phone, deviceG := net.device("m phone", member), net.device("m g", member)
	net.admitDevice(laptop, phone, 0)
	net.admitDevice(net.owner, deviceG, 0)
	forwarding := net.forward(deviceG, "g")
	sinceN := net.n + 1
	net.mustPost(phone, bridge.SignedType_SIGNED_OWNER_CONFIRM, net.ownerConfirm(deviceG))
	revoked := net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(phone, sinceN))

	state := net.log.State()
	if !state.Parked(deviceG.sidecarId) {
		t.Fatal("G is not parked")
	}
	if droppedAt, dropped := state.DelegationKeyDropped(forwarding.id); !dropped || droppedAt != revoked.Pin.GetVersion() {
		t.Errorf("key dropped at %d, %v", droppedAt, dropped)
	}
	if _, ended := state.DelegationEnded(forwarding.id); ended || state.ForwardingDelegation(deviceG.sidecarId) == nil {
		t.Error("a park ended a forwarding Delegation its sidecar signed before P held it")
	}
	if _, _, ok := state.ForwardingKey(deviceG.sidecarId); ok {
		t.Error("a parked sidecar's forwarding key is in force")
	}
	// parked, it files no other
	statement, _ := net.forwardingStatement(deviceG, "while parked")
	net.mustRefuse(deviceG, bridge.SignedType_SIGNED_DELEGATION, statement, ErrConfigAuthority)

	net.mustPost(net.owner, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, &protocol.AdmissionConfirm{Header: net.header(), SidecarId: deviceG.sidecarId.Bytes()})
	state = net.log.State()
	if state.Parked(deviceG.sidecarId) {
		t.Fatal("the admin's confirmation did not lift the park")
	}
	if _, dropped := state.DelegationKeyDropped(forwarding.id); dropped {
		t.Error("the key did not return with the lift")
	}
	if delegationId, _, ok := state.ForwardingKey(deviceG.sidecarId); !ok || !bytes.Equal(delegationId, forwarding.id) {
		t.Error("the lifted sidecar's forwarding key is not in force")
	}
	net.everyReaderAgrees()
}

// A forwarding Delegation a sidecar signed while a cascade's P held it is void: it ends at the revocation, a lift of
// the sidecar's park does not bring it back, and the sidecar, standing again, files a new one.
func TestAForwardingDelegationSignedInPIsVoid(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	phone, tablet := net.device("m phone", member), net.device("m tablet", member)
	net.admitDevice(laptop, phone, 0)
	sinceN := net.n + 1
	net.admitDevice(phone, tablet, 0)
	forwarding := net.forward(tablet, "tablet")
	revoked := net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(phone, sinceN))

	state := net.log.State()
	if !state.Parked(tablet.sidecarId) {
		t.Fatal("the tablet is not parked")
	}
	if endedAt, ended := state.DelegationEnded(forwarding.id); !ended || endedAt != revoked.Pin.GetVersion() {
		t.Errorf("a forwarding Delegation signed in P ended at %d, %v", endedAt, ended)
	}
	net.mustPost(laptop, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, &protocol.AdmissionConfirm{Header: net.header(), SidecarId: tablet.sidecarId.Bytes()})
	state = net.log.State()
	if state.Parked(tablet.sidecarId) || state.ForwardingDelegation(tablet.sidecarId) != nil {
		t.Error("a lift brought back what the tablet signed in P")
	}
	if _, dropped := state.DelegationKeyDropped(forwarding.id); !dropped {
		t.Error("a lift returned a void Delegation's key")
	}
	again := net.forward(tablet, "tablet again")
	if delegationId, _, ok := net.log.State().ForwardingKey(tablet.sidecarId); !ok || !bytes.Equal(delegationId, again.id) {
		t.Error("the one signed outside P is not in force")
	}
	net.everyReaderAgrees()
}

// A leaked bundle's DelegationRevoke with since_n parks the agents its Delegation admitted from there, and a
// forwarding Delegation such an agent signed since is void with it; from a since_n after the agent's admission the
// agent stands and its forwarding Delegation with it. A tagged agent files one as any standing sidecar does.
func TestALeakedBundlesParkVoidsItsAgentsForwardingDelegation(t *testing.T) {
	for _, late := range []bool{false, true} {
		net, ci, _ := newTestConfigTagNet(t)
		notAfter := net.timeMs + 7*24*60*60*1000
		agentDelegation := net.delegate(net.owner, "ci", []Id{ci}, 3, notAfter)
		agent := net.device("agent", Id{})
		admitted := net.postByDelegation(agentDelegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.agentAdmission(agentDelegation, agent, false, notAfter))
		if !admitted.Accepted() {
			t.Fatal(admitted.Refusal)
		}
		forwarding := net.forward(agent, "agent")
		sinceN := admitted.Pin.GetVersion()
		if late {
			sinceN = net.n
		}
		net.mustPost(net.owner, bridge.SignedType_SIGNED_DELEGATION_REVOKE, net.delegationRevoke(agentDelegation.id, sinceN))
		state := net.log.State()
		_, ended := state.DelegationEnded(forwarding.id)
		if state.Parked(agent.sidecarId) == late || ended == late {
			t.Errorf("late %v: the agent parked %v, its forwarding Delegation ended %v", late, state.Parked(agent.sidecarId), ended)
		}
		if _, _, ok := state.ForwardingKey(agent.sidecarId); ok != late {
			t.Errorf("late %v: the agent's forwarding key in force %v", late, ok)
		}
		net.everyReaderAgrees()
	}
}

// A compromise revocation's plan names the forwarding Delegations it ends: the revoked sidecar's own, and one a parked
// sidecar signed in P.
func TestACascadePlanNamesTheForwardingDelegationsItEnds(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	phone, tablet := net.device("m phone", member), net.device("m tablet", member)
	net.admitDevice(laptop, phone, 0)
	phones := net.forward(phone, "phone")
	laptops := net.forward(laptop, "laptop")
	sinceN := net.n + 1
	net.admitDevice(phone, tablet, 0)
	tablets := net.forward(tablet, "tablet")
	plan, err := net.log.State().CascadePlan(phone.sidecarId, sinceN)
	if err != nil {
		t.Fatal(err)
	}
	holds := func(delegationId []byte) bool {
		for _, endedId := range plan.EndedDelegationIds {
			if bytes.Equal(endedId, delegationId) {
				return true
			}
		}
		return false
	}
	if !holds(phones.id) || !holds(tablets.id) || holds(laptops.id) {
		t.Errorf("the plan ends the phone's %v, the tablet's %v, the laptop's %v", holds(phones.id), holds(tablets.id), holds(laptops.id))
	}
	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(phone, sinceN))
	state := net.log.State()
	for _, delegation := range state.Delegations() {
		_, ended := state.DelegationEnded(delegation.GetDelegationId())
		if ended != holds(delegation.GetDelegationId()) {
			t.Errorf("Delegation %x ended %v, the plan said %v", delegation.GetDelegationId()[:4], ended, holds(delegation.GetDelegationId()))
		}
	}
	net.everyReaderAgrees()
}

// FS-14's shape for the forwarding row: a base folds below a supersession, a Suspend, an Unsuspend and a revocation,
// and a long-running reader, a new device and a rows-only gate reach the same rows, each forwarding row with field 10
// empty and field 16 its reader key's digest; then a base folds through the tip and they agree again.
func TestForwardingRowsAreEqualAcrossAFoldAtEveryReader(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	phone := net.device("m phone", member)
	net.admitDevice(laptop, phone, 0)
	first := net.forward(phone, "first")
	laptops := net.forward(laptop, "laptop")
	foldedThrough := net.n
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{Header: net.header(), Subject: phone.sidecarId.Bytes(), SuspendId: aclTestSuspendId("fold")})
	second := net.forward(phone, "second")
	if verdict := net.fold(net.owner, foldedThrough, 2); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_UNSUSPEND, &bridge.Unsuspend{Header: net.header(), Subject: phone.sidecarId.Bytes(), SuspendId: aclTestSuspendId("fold")})
	net.mustPost(net.owner, bridge.SignedType_SIGNED_DELEGATION_REVOKE, net.delegationRevoke(laptops.id, 0))
	third := net.forward(phone, "third")

	check := func() {
		t.Helper()
		net.everyReaderAgrees()
		for i, reader := range append(net.everyReader(), net.log) {
			state := reader.State()
			forwardingRows := 0
			for _, row := range state.Rows().GetDelegations() {
				if !ConfigDelegationRowForwards(row) {
					continue
				}
				forwardingRows += 1
				if len(row.GetReaderXwingPublicKey()) != 0 || len(row.GetReaderKeySha256()) != sha256.Size || row.GetNotAfter() != 0 || len(row.GetTagAtoms()) != 0 {
					t.Errorf("reader %d: a forwarding row with a key, no digest, a not_after or tags: %v", i, row)
				}
			}
			if forwardingRows != 4 {
				t.Errorf("reader %d holds %d forwarding rows", i, forwardingRows)
			}
			live := state.ForwardingDelegation(phone.sidecarId)
			if live == nil || !bytes.Equal(live.GetDelegationId(), third.id) || live.GetKeyDroppedAt() != 0 {
				t.Errorf("reader %d: the phone's live forwarding Delegation is %v", i, live)
			}
			if state.Delegation(first.id).GetSupersededAt() != state.Delegation(second.id).GetAt() ||
				state.Delegation(second.id).GetSupersededAt() != state.Delegation(third.id).GetAt() {
				t.Errorf("reader %d: the supersession positions differ", i)
			}
			if _, ended := state.DelegationEnded(laptops.id); !ended || state.ForwardingDelegation(laptop.sidecarId) != nil {
				t.Errorf("reader %d: the laptop's revoked forwarding Delegation stands", i)
			}
		}
	}
	check()
	if verdict := net.fold(net.owner, net.n, 3); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	check()
}

// `ur admin delegations` tells a forwarding Delegation from an agent's: its state names the sidecar it forwards for
// and where a newer one superseded it, with no tags, agents or admissions left; and its revocation is built with no
// since_n, --leaked refused, since the log refuses one that carries it.
func TestDelegationStatesTellAForwardingDelegationApart(t *testing.T) {
	net, ci, _ := newTestConfigTagNet(t)
	_, laptop := net.consentedMember("m")
	agents := net.delegate(net.owner, "ci", []Id{ci}, 2, net.timeMs+7*24*60*60*1000)
	first := net.forward(laptop, "first")
	second := net.forward(laptop, "second")

	state := net.log.State()
	states := map[string]*DelegationState{}
	for _, delegationState := range state.DelegationStates() {
		states[string(delegationState.DelegationId)] = delegationState
	}
	if len(states) != 3 {
		t.Fatalf("%d Delegations listed", len(states))
	}
	if agent := states[string(agents.id)]; agent.ForwardSidecarId != nil || agent.SupersededAt != 0 || len(agent.TagIds) != 1 || agent.AdmissionsLeft != 2 {
		t.Errorf("the agent's Delegation: %+v", agent)
	}
	for _, forwarding := range []*testConfigDelegation{first, second} {
		listed := states[string(forwarding.id)]
		if !bytes.Equal(listed.ForwardSidecarId, laptop.sidecarId.Bytes()) || len(listed.TagIds) != 0 || len(listed.AgentIds) != 0 ||
			listed.AdmissionsLeft != 0 || !listed.NotAfter.IsZero() || listed.EndedAt != 0 {
			t.Errorf("a forwarding Delegation: %+v", listed)
		}
	}
	if states[string(first.id)].SupersededAt != second.at(net) || states[string(second.id)].SupersededAt != 0 {
		t.Error("the listing does not say which one was superseded, and where")
	}

	if _, err := state.DelegationRevokeStatement(second.id, true, 1); err == nil {
		t.Error("a leaked revocation of a forwarding Delegation was built")
	}
	revoke, err := state.DelegationRevokeStatement(second.id, false, 0)
	if err != nil || revoke.GetSinceN() != 0 {
		t.Fatalf("a forwarding Delegation's revocation: %v %v", revoke, err)
	}
	revoke.Header = net.header()
	net.mustPost(net.owner, bridge.SignedType_SIGNED_DELEGATION_REVOKE, revoke)
	if _, ended := net.log.State().DelegationEnded(second.id); !ended {
		t.Error("the built revocation did not end it")
	}
	// the agent's Delegation still takes --leaked
	if leaked, err := state.DelegationRevokeStatement(agents.id, true, 1); err != nil || leaked.GetSinceN() == 0 {
		t.Errorf("a leaked revocation of an agent's Delegation: %v %v", leaked, err)
	}
}
