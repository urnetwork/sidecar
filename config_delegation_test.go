// §7.9's Delegations on the test network: a Delegation's shape and signers, its key's admissions with exactly its tags
// and its max_admits for life, its end and its key's drops (FS-18's log cases), and FS-102's copied whole bundle: a
// compromise revocation of an agent it admitted ending it, a removed agent leaving it admitting until a DelegationRevoke
// with since_n parks the thief's agent, max_admits holding across a fold, and a repost of the same revocation bytes
// landing once. Every refusal holds at a new device and a rows-only gate as at a long-running reader.

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

// One Delegation of the test network: its id, its signing key and what it declared.
type testConfigDelegation struct {
	id       []byte
	key      ed25519.PrivateKey
	tagIds   []Id
	notAfter int64
}

// A Delegation's statement by signer at the tip: its tags, max_admits and not_after, its keys from label.
func (self *testConfigNet) delegationStatement(label string, tagIds []Id, maxAdmits uint32, notAfter int64) (*protocol.Delegation, ed25519.PrivateKey) {
	key := testConfigDeviceKey("delegation " + label)
	delegation := &protocol.Delegation{
		Header:               self.header(),
		Pubkey:               key.Public().(ed25519.PublicKey),
		ReaderXwingPublicKey: bytes.Repeat([]byte{0x5a}, configXwingPublicKeyByteCount),
		MaxAdmits:            maxAdmits,
		NotAfter:             notAfter,
	}
	for _, tagId := range tagIds {
		delegation.TagIds = append(delegation.TagIds, tagId.Bytes())
	}
	return delegation, key
}

// Declares a Delegation, signed by signer, failing the test unless it takes effect.
func (self *testConfigNet) delegate(signer testConfigDevice, label string, tagIds []Id, maxAdmits uint32, notAfter int64) *testConfigDelegation {
	self.t.Helper()
	statement, key := self.delegationStatement(label, tagIds, maxAdmits, notAfter)
	verdict := self.mustPost(signer, bridge.SignedType_SIGNED_DELEGATION, statement)
	return &testConfigDelegation{id: bytes.Clone(verdict.StatementId[:]), key: key, tagIds: tagIds, notAfter: notAfter}
}

// body signed by the Delegation's key, as §6.9's Signers name it: signer_id its delegation_id, key_id its key's hash.
func (self *testConfigNet) signByDelegation(delegation *testConfigDelegation, signedType bridge.SignedType, body proto.Message) []byte {
	bodyBytes := testConfigMarshal(self.t, body)
	purpose, _ := ConfigStatementPurpose(signedType)
	pubkeySha256 := sha256.Sum256(delegation.key.Public().(ed25519.PublicKey))
	return testConfigMarshal(self.t, &bridge.Signed{
		Body:      bodyBytes,
		SignerId:  bytes.Clone(delegation.id),
		KeyId:     pubkeySha256[:],
		Signature: ed25519.Sign(delegation.key, bridge.SignedBytes(purpose, signedType, bodyBytes)),
		Type:      uint32(signedType),
	})
}

// Signs by the Delegation's key, sequences and applies.
func (self *testConfigNet) postByDelegation(delegation *testConfigDelegation, signedType bridge.SignedType, body proto.Message) ConfigVerdict {
	self.t.Helper()
	return self.push(self.makeEntry(bridge.AuthEntryKindStatement, self.signByDelegation(delegation, signedType, body)))
}

// An agent's SidecarAdmit carrying the Delegation's tags, ephemeral or not, with notAfter.
func (self *testConfigNet) agentAdmission(delegation *testConfigDelegation, agent testConfigDevice, ephemeral bool, notAfter int64) *protocol.SidecarAdmit {
	return self.admission(agent, delegation.tagIds, ephemeral, notAfter, 0)
}

// Every kind of reader of the log as it stands, beside the net's own: another long-running reader, and a new device
// and a rows-only gate each started at the newest base from what the net's reader retains.
func (self *testConfigNet) everyReader() []*ConfigLog {
	self.t.Helper()
	retained := self.log.Retained()
	restored, err := RestoreConfigLog(testConfigLogSettings(), retained, self.source)
	if err != nil {
		self.t.Fatal(err)
	}
	gate, err := RestoreConfigLogRowsOnly(testConfigLogSettings(), retained, self.rowsOnlySource(), nil)
	if err != nil {
		self.t.Fatal(err)
	}
	return []*ConfigLog{self.newReader(), restored, gate}
}

// Whether every reader holds the net's verdict at each position after the newest base, and its state.
func (self *testConfigNet) everyReaderAgrees() {
	self.t.Helper()
	from := self.log.State().Base().GetVersion() + 1
	for i, reader := range self.everyReader() {
		for n := from; n <= self.n; n += 1 {
			want, got := self.log.keptEntry(n), reader.keptEntry(n)
			if want == nil || got == nil {
				self.t.Fatalf("reader %d: no verdict at %d", i, n)
			}
			if want.verdict.Accepted() != got.verdict.Accepted() ||
				testConfigRefusalClass(want.verdict.Refusal) != testConfigRefusalClass(got.verdict.Refusal) {
				self.t.Errorf("reader %d at %d: %v, the net's reader %v", i, n, got.verdict.Refusal, want.verdict.Refusal)
			}
		}
		testConfigStatesEqual(self.t, reader.State(), self.log.State())
	}
}

// A network whose owner owns tags ci and deploy, so its devices may delegate them.
func newTestConfigTagNet(t *testing.T) (*testConfigNet, Id, Id) {
	net := newTestConfigNet(t)
	ci, deploy := testConfigId("tag ci"), testConfigId("tag deploy")
	net.withTagOwner(ci, net.ownerMemberId)
	net.withTagOwner(deploy, net.ownerMemberId)
	return net, ci, deploy
}

// A Delegation's shape: tags, keys, max_admits and a not_after within 90 days; an Owner's, Admin's or Network admin's
// device that owns each tag; a device, never a Delegation, so a Delegation never re-delegates.
func TestADelegationsShapeAndSigners(t *testing.T) {
	net, ci, deploy := newTestConfigTagNet(t)
	day := int64(24 * 60 * 60 * 1000)
	member, first := net.consentedMember("m")
	net.withTagOwner(testConfigId("tag m"), member)

	cases := []struct {
		name   string
		edit   func(delegation *protocol.Delegation)
		signer testConfigDevice
		want   error
	}{
		{name: "no tag", edit: func(delegation *protocol.Delegation) { delegation.TagIds = nil }, signer: net.owner, want: ErrConfigRule},
		{name: "a short signing key", edit: func(delegation *protocol.Delegation) { delegation.Pubkey = delegation.Pubkey[:31] }, signer: net.owner, want: ErrConfigRule},
		{name: "a short reader key", edit: func(delegation *protocol.Delegation) {
			delegation.ReaderXwingPublicKey = delegation.ReaderXwingPublicKey[:32]
		}, signer: net.owner, want: ErrConfigRule},
		{name: "no admits", edit: func(delegation *protocol.Delegation) { delegation.MaxAdmits = 0 }, signer: net.owner, want: ErrConfigRule},
		{name: "a past not_after", edit: func(delegation *protocol.Delegation) { delegation.NotAfter = net.timeMs }, signer: net.owner, want: ErrConfigRule},
		{name: "past 90 days", edit: func(delegation *protocol.Delegation) { delegation.NotAfter = net.timeMs + 91*day }, signer: net.owner, want: ErrConfigRule},
		{name: "a repeated tag", edit: func(delegation *protocol.Delegation) { delegation.TagIds = append(delegation.TagIds, ci.Bytes()) }, signer: net.owner, want: ErrConfigRule},
		{name: "a tag its signer does not own", edit: func(delegation *protocol.Delegation) {
			delegation.TagIds = [][]byte{testConfigId("tag nobody's").Bytes()}
		}, signer: net.owner, want: ErrConfigAuthority},
		{name: "a plain member's device", edit: func(delegation *protocol.Delegation) { delegation.TagIds = [][]byte{testConfigId("tag m").Bytes()} }, signer: first, want: ErrConfigAuthority},
	}
	for _, c := range cases {
		statement, _ := net.delegationStatement(c.name, []Id{ci}, 2, net.timeMs+30*day)
		c.edit(statement)
		verdict := net.post(c.signer, bridge.SignedType_SIGNED_DELEGATION, statement)
		if verdict.Accepted() || !errors.Is(verdict.Refusal, c.want) {
			t.Errorf("%s: %v, want %v", c.name, verdict.Refusal, c.want)
		}
	}

	delegation := net.delegate(net.owner, "d", []Id{ci, deploy}, 2, net.timeMs+30*day)
	row := net.log.State().Delegation(delegation.id)
	if row == nil || row.GetAt() != net.n || !bytes.Equal(row.GetSigner(), net.owner.sidecarId.Bytes()) || row.GetMaxAdmits() != 2 ||
		len(row.GetTagAtoms()) != 2 || row.GetEndedAt() != 0 || row.GetAdmissions() != 0 {
		t.Fatalf("the Delegation's row: %v", row)
	}
	// its key declares nothing
	again, _ := net.delegationStatement("re-delegated", []Id{ci}, 1, net.timeMs+day)
	if verdict := net.postByDelegation(delegation, bridge.SignedType_SIGNED_DELEGATION, again); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigSigner) {
		t.Errorf("a re-delegation: %v", verdict.Refusal)
	}
	// nor does a key that is not its own
	forged := &testConfigDelegation{id: delegation.id, key: testConfigDeviceKey("forged"), tagIds: delegation.tagIds}
	agent := net.device("forged agent", Id{})
	if verdict := net.postByDelegation(forged, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.agentAdmission(forged, agent, true, net.timeMs+day)); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigSigner) {
		t.Errorf("another key: %v", verdict.Refusal)
	}
	net.everyReaderAgrees()
}

// FS-18: a Delegation's key admits only agents carrying exactly its tags and, unless ephemeral, a not_after no earlier
// than its own, up to max_admits; every reader, a new device included, refuses the rest.
func TestADelegationAdmitsExactlyItsTagsUpToMaxAdmits(t *testing.T) {
	net, ci, deploy := newTestConfigTagNet(t)
	day := int64(24 * 60 * 60 * 1000)
	delegation := net.delegate(net.owner, "d", []Id{ci}, 2, net.timeMs+30*day)
	net.fold(net.owner, net.n, net.log.State().Base().GetConfigVersion()+1)

	refused := []struct {
		name  string
		admit *protocol.SidecarAdmit
		want  error
	}{
		{name: "other tags", admit: net.admission(net.device("other tags", Id{}), []Id{deploy}, false, delegation.notAfter, 0), want: ErrConfigRule},
		{name: "more tags", admit: net.admission(net.device("more tags", Id{}), []Id{ci, deploy}, false, delegation.notAfter, 0), want: ErrConfigRule},
		{name: "untagged", admit: net.admission(net.device("untagged", net.ownerMemberId), nil, false, 0, 0), want: ErrConfigRule},
		{name: "an early not_after", admit: net.agentAdmission(delegation, net.device("early", Id{}), false, delegation.notAfter-1), want: ErrConfigRule},
	}
	for _, c := range refused {
		if verdict := net.postByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, c.admit); verdict.Accepted() || !errors.Is(verdict.Refusal, c.want) {
			t.Errorf("%s: %v, want %v", c.name, verdict.Refusal, c.want)
		}
	}
	agent := net.device("agent", Id{})
	if verdict := net.postByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.agentAdmission(delegation, agent, false, delegation.notAfter)); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	worker := net.device("worker", Id{})
	if verdict := net.postByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.agentAdmission(delegation, worker, true, net.timeMs+60*60*1000)); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	third := net.agentAdmission(delegation, net.device("third", Id{}), true, net.timeMs+60*60*1000)
	if verdict := net.postByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, third); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigAuthority) {
		t.Errorf("a third admission of two: %v", verdict.Refusal)
	}

	state := net.log.State()
	row := state.SidecarRow(agent.sidecarId)
	if !bytes.Equal(row.GetDelegationId(), delegation.id) || !bytes.Equal(row.GetSponsor(), net.ownerMemberId.Bytes()) ||
		len(row.GetAdmissionSigners()) != 1 || !bytes.Equal(row.GetAdmissionSigners()[0], delegation.id) {
		t.Errorf("the agent's row: %v", row)
	}
	if state.Delegation(delegation.id).GetAdmissions() != 2 {
		t.Errorf("%d admissions", state.Delegation(delegation.id).GetAdmissions())
	}
	net.everyReaderAgrees()
}

// FS-102 (1) and (5): a copied whole bundle. A, an agent D admitted, revoked for compromise from a since_n after C's
// admission, ends D there and parks the agent D admitted after since_n until an AdmissionConfirm; B, which the thief
// admits with the copied signing seed, is refused by every reader, a new device included, as is D's confirmation; C
// reads on; and a repost of the revocation's same bytes lands nothing more, D ending once.
func TestACompromiseRevocationOfAnAgentEndsItsDelegation(t *testing.T) {
	net, ci, _ := newTestConfigTagNet(t)
	day := int64(24 * 60 * 60 * 1000)
	delegation := net.delegate(net.owner, "d", []Id{ci}, 10, net.timeMs+30*day)
	agentA, agentC, agentE := net.device("agent a", Id{}), net.device("agent c", Id{}), net.device("agent e", Id{})
	for _, agent := range []testConfigDevice{agentA, agentC} {
		if verdict := net.postByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.agentAdmission(delegation, agent, false, delegation.notAfter)); !verdict.Accepted() {
			t.Fatal(verdict.Refusal)
		}
	}
	sinceN := net.n + 1
	if verdict := net.postByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.agentAdmission(delegation, agentE, false, delegation.notAfter)); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}

	compromise := net.revocation(agentA, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE)
	compromise.SinceN = sinceN
	revokedBytes := net.sign(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, compromise)
	revoked := net.push(net.makeEntry(bridge.AuthEntryKindStatement, revokedBytes))
	if !revoked.Accepted() {
		t.Fatal(revoked.Refusal)
	}
	position := revoked.Pin.GetVersion()
	state := net.log.State()
	if at, ended := state.DelegationEnded(delegation.id); !ended || at != position {
		t.Errorf("D ended at %d (%v), the revocation at %d", at, ended, position)
	}
	if at, dropped := state.DelegationKeyDropped(delegation.id); !dropped || at != position {
		t.Errorf("D's key dropped at %d (%v)", at, dropped)
	}
	if state.SidecarRow(agentA.sidecarId).GetRevokedAt() != position || !state.Parked(agentE.sidecarId) || state.Parked(agentC.sidecarId) {
		t.Errorf("A revoked at %d, E parked %v, C parked %v", state.SidecarRow(agentA.sidecarId).GetRevokedAt(), state.Parked(agentE.sidecarId), state.Parked(agentC.sidecarId))
	}

	// (5): the same bytes again are the entry that landed, which api answers a retry with
	statementId, err := StatementId(revokedBytes)
	if err != nil {
		t.Fatal(err)
	}
	if verdict := net.log.Check(revokedBytes, net.timeMs+1000); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigReplay) {
		t.Errorf("a repost: %v", verdict.Refusal)
	}
	if pin, found := net.log.FindStatement(statementId); !found || pin.GetVersion() != position {
		t.Errorf("the retry finds %v", pin)
	}

	net.fold(net.owner, net.n, net.log.State().Base().GetConfigVersion()+1)
	agentB := net.device("agent b", Id{})
	thief := net.postByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.agentAdmission(delegation, agentB, false, delegation.notAfter))
	if thief.Accepted() || !errors.Is(thief.Refusal, ErrConfigAuthority) {
		t.Errorf("the thief's admission: %v", thief.Refusal)
	}
	confirmByD := net.postByDelegation(delegation, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, &protocol.AdmissionConfirm{Header: net.header(), SidecarId: agentE.sidecarId.Bytes()})
	if confirmByD.Accepted() {
		t.Error("an ended Delegation confirmed its agent")
	}
	lift := net.mustPost(net.owner, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, &protocol.AdmissionConfirm{Header: net.header(), SidecarId: agentE.sidecarId.Bytes()})
	row := net.log.State().SidecarRow(agentE.sidecarId)
	confirmations := row.GetConfirmations()
	if row.GetParkedAt() != 0 || len(confirmations) != 1 || !confirmations[0].GetLiftedPark() || confirmations[0].GetAt() != lift.Pin.GetVersion() {
		t.Errorf("the lift: parked at %d, confirmations %v", row.GetParkedAt(), confirmations)
	}
	if _, ended := net.log.State().DelegationEnded(delegation.id); !ended || net.log.State().Delegation(delegation.id).GetEndedAt() != position {
		t.Error("D ended twice")
	}
	net.everyReaderAgrees()
}

// FS-102 (2): A revoked as removed instead drops D's key and leaves D admitting, so B's admission lands; a later
// DelegationRevoke with a since_n before B's admission parks B, ends D, refuses every admission after it and keeps B
// parked against an AdmissionConfirm by D's copied key, while an admin's lifts it.
func TestARemovedAgentLeavesItsDelegationAdmittingUntilARevokeWithSinceN(t *testing.T) {
	net, ci, _ := newTestConfigTagNet(t)
	day := int64(24 * 60 * 60 * 1000)
	delegation := net.delegate(net.owner, "d", []Id{ci}, 10, net.timeMs+30*day)
	agentA, agentB := net.device("agent a", Id{}), net.device("agent b", Id{})
	if verdict := net.postByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.agentAdmission(delegation, agentA, false, delegation.notAfter)); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	removed := net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(agentA, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED))
	if at, dropped := net.log.State().DelegationKeyDropped(delegation.id); !dropped || at != removed.Pin.GetVersion() {
		t.Errorf("D's key dropped at %d (%v)", at, dropped)
	}
	if _, ended := net.log.State().DelegationEnded(delegation.id); ended {
		t.Error("a removal ended D")
	}
	sinceN := net.n + 1
	if verdict := net.postByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.agentAdmission(delegation, agentB, false, delegation.notAfter)); !verdict.Accepted() {
		t.Fatalf("D admits on after its key dropped: %v", verdict.Refusal)
	}

	revoke := &protocol.DelegationRevoke{Header: net.header(), DelegationId: delegation.id, SinceN: net.n + 1}
	net.mustRefuse(net.owner, bridge.SignedType_SIGNED_DELEGATION_REVOKE, revoke, ErrConfigRule)
	member, first := net.consentedMember("m")
	revoke = &protocol.DelegationRevoke{Header: net.header(), DelegationId: delegation.id, SinceN: sinceN}
	net.mustRefuse(first, bridge.SignedType_SIGNED_DELEGATION_REVOKE, revoke, ErrConfigAuthority)
	_ = member
	revoke = &protocol.DelegationRevoke{Header: net.header(), DelegationId: delegation.id, SinceN: sinceN}
	ended := net.mustPost(net.owner, bridge.SignedType_SIGNED_DELEGATION_REVOKE, revoke)
	state := net.log.State()
	if at, isEnded := state.DelegationEnded(delegation.id); !isEnded || at != ended.Pin.GetVersion() {
		t.Errorf("D ended at %d (%v)", at, isEnded)
	}
	if !state.Parked(agentB.sidecarId) || state.SidecarRow(agentA.sidecarId).GetParkedAt() != 0 {
		t.Error("the revocation parked the wrong agents")
	}
	if !state.CascadeVoids(agentB.sidecarId.Bytes(), state.SidecarRow(agentB.sidecarId).GetAdmittedAt()) {
		t.Error("the thief's agent's span is not held")
	}

	net.fold(net.owner, net.n, net.log.State().Base().GetConfigVersion()+1)
	late := net.postByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.agentAdmission(delegation, net.device("late", Id{}), false, delegation.notAfter))
	if late.Accepted() || !errors.Is(late.Refusal, ErrConfigAuthority) {
		t.Errorf("an admission after the end: %v", late.Refusal)
	}
	confirmByD := net.postByDelegation(delegation, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, &protocol.AdmissionConfirm{Header: net.header(), SidecarId: agentB.sidecarId.Bytes()})
	if confirmByD.Accepted() || !net.log.State().Parked(agentB.sidecarId) {
		t.Errorf("D's copied key lifted B's park: %v", confirmByD.Refusal)
	}
	// a repeat ends nothing twice
	net.mustPost(net.owner, bridge.SignedType_SIGNED_DELEGATION_REVOKE, &protocol.DelegationRevoke{Header: net.header(), DelegationId: delegation.id})
	if net.log.State().Delegation(delegation.id).GetEndedAt() != ended.Pin.GetVersion() {
		t.Error("a repeated revocation moved D's end")
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, &protocol.AdmissionConfirm{Header: net.header(), SidecarId: agentB.sidecarId.Bytes()})
	if net.log.State().Parked(agentB.sidecarId) {
		t.Error("an admin's confirmation left B parked")
	}
	net.everyReaderAgrees()
}

// FS-102 (4): ten admissions, a fold and every earlier agent's not_after later, an eleventh SidecarAdmit by D's key is
// still refused: rows keep the count for the Delegation's life.
func TestMaxAdmitsHoldForTheDelegationsLife(t *testing.T) {
	net, ci, _ := newTestConfigTagNet(t)
	day := int64(24 * 60 * 60 * 1000)
	delegation := net.delegate(net.owner, "d", []Id{ci}, 10, net.timeMs+30*day)
	for i := range 10 {
		agent := net.device("agent "+string(rune('a'+i)), Id{})
		if verdict := net.postByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.agentAdmission(delegation, agent, true, net.timeMs+60*60*1000)); !verdict.Accepted() {
			t.Fatal(verdict.Refusal)
		}
	}
	net.fold(net.owner, net.n, net.log.State().Base().GetConfigVersion()+1)
	net.timeMs += 2 * day
	eleventh := net.postByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.agentAdmission(delegation, net.device("eleventh", Id{}), true, net.timeMs+60*60*1000))
	if eleventh.Accepted() || !errors.Is(eleventh.Refusal, ErrConfigAuthority) {
		t.Errorf("an eleventh admission: %v", eleventh.Refusal)
	}
	net.everyReaderAgrees()
}

// FS-18: a lost or removed revocation of an already reaped covered agent drops D's key; the reap alone did not.
func TestALostRevocationOfAReapedAgentDropsItsDelegationsKey(t *testing.T) {
	net, ci, _ := newTestConfigTagNet(t)
	day := int64(24 * 60 * 60 * 1000)
	delegation := net.delegate(net.owner, "d", []Id{ci}, 2, net.timeMs+30*day)
	agent := net.device("agent", Id{})
	if verdict := net.postByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.agentAdmission(delegation, agent, true, net.timeMs+60*60*1000)); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	if verdict := net.tick(&bridge.ApiTick{ReapedSidecarIds: [][]byte{agent.sidecarId.Bytes()}}); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	if _, dropped := net.log.State().DelegationKeyDropped(delegation.id); dropped {
		t.Error("a reap dropped D's key")
	}
	lost := net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(agent, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	if at, dropped := net.log.State().DelegationKeyDropped(delegation.id); !dropped || at != lost.Pin.GetVersion() {
		t.Errorf("D's key dropped at %d (%v)", at, dropped)
	}
	net.everyReaderAgrees()
}
