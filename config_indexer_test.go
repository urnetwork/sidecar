// §7.9's IndexerSet and SponsorSet on the test network, FS-82's statement cases: accepted and refused signers at each
// scope, an ephemeral or read_only subject, retirement by the subject itself, the subject's revocation and park ending
// what it serves, no key or grant added, and the designation surviving a fold at every reader; a SponsorSet by an admin
// naming a tagged sidecar's member.

package sidecar

import (
	"bytes"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// An IndexerSet at the tip.
func (self *testConfigNet) indexerSet(subject testConfigDevice, scope protocol.IndexerScope, retire bool) *protocol.IndexerSet {
	designation := &protocol.IndexerSet{Header: self.header(), SidecarId: subject.sidecarId.Bytes(), Scope: scope, Retire: retire}
	if !retire {
		designation.SealedServices = []byte("sealed services: opened only by a config reader")
	}
	return designation
}

// FS-82: a network designation by an Owner's device, a member designation by a consented device of the subject's
// member, each refused from any other; no ephemeral or read_only subject; retire by the subject; and nothing beyond the
// designation changes.
func TestAnIndexerSetsSignersAndSubjects(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	desktop := net.device("m desktop", member)
	net.admitDevice(laptop, desktop, 0)
	_, otherLaptop := net.consentedMember("other")
	worker := net.device("m worker", member)
	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(worker, nil, true, net.timeMs+testConfigHourMs, 0))
	page := net.device("m page", member)
	net.admitDevice(laptop, page, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY))

	network, member_ := protocol.IndexerScope_INDEXER_SCOPE_NETWORK, protocol.IndexerScope_INDEXER_SCOPE_MEMBER
	net.mustRefuse(laptop, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(desktop, network, false), ErrConfigAuthority)
	net.mustRefuse(otherLaptop, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(desktop, member_, false), ErrConfigAuthority)
	net.mustRefuse(net.owner, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(worker, network, false), ErrConfigRule)
	net.mustRefuse(net.owner, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(page, network, false), ErrConfigRule)
	net.mustRefuse(net.owner, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(desktop, protocol.IndexerScope_INDEXER_SCOPE_UNSPECIFIED, false), ErrConfigRule)
	before := net.log.State()
	net.mustPost(net.owner, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(desktop, network, false))
	net.mustPost(laptop, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(desktop, member_, false))
	state := net.log.State()
	indexers := state.Indexers()
	if len(indexers) != 2 || indexers[0].SidecarId != desktop.sidecarId || indexers[0].Scope != network || indexers[0].Signer != net.owner.sidecarId ||
		indexers[1].Scope != member_ || indexers[1].Signer != laptop.sidecarId {
		t.Fatalf("the designations: %+v", indexers)
	}
	if designations := state.IndexerDesignations(desktop.sidecarId); len(designations) != 2 {
		t.Errorf("the desktop's designations: %v", designations)
	}
	// a designation grants no key, grant or read
	if !bytes.Equal(testConfigMarshal(t, before.aclRows), testConfigMarshal(t, state.aclRows)) || len(state.keys) != len(before.keys) {
		t.Error("a designation changed the acl rows or the keys")
	}
	net.fold(net.owner, net.n, 2)
	net.everyReaderAgrees()

	net.mustPost(desktop, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(desktop, network, true))
	if indexers := net.log.State().Indexers(); len(indexers) != 1 || indexers[0].Scope != member_ {
		t.Errorf("after the subject's retirement: %+v", indexers)
	}
	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(desktop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	if indexers := net.log.State().Indexers(); len(indexers) != 0 {
		t.Errorf("a revoked subject serves: %+v", indexers)
	}
	net.everyReaderAgrees()
}

// A parked subject serves nothing until a confirmation lifts it.
func TestAParkedIndexerServesNothing(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	phone, desktop := net.device("m phone", member), net.device("m desktop", member)
	net.admitDevice(laptop, phone, 0)
	sinceN := net.n + 1
	net.admitDevice(phone, desktop, 0)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(desktop, protocol.IndexerScope_INDEXER_SCOPE_NETWORK, false))
	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(phone, sinceN))
	if len(net.log.State().Indexers()) != 0 {
		t.Error("a parked subject serves")
	}
	net.mustPost(laptop, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, &protocol.AdmissionConfirm{Header: net.header(), SidecarId: desktop.sidecarId.Bytes()})
	if len(net.log.State().Indexers()) != 1 {
		t.Error("the lift did not restore the designation")
	}
}

// A SponsorSet: an admin's device names a member as a tagged sidecar's sponsor; another member's device, an untagged
// sidecar or a sponsor that is no member is refused.
func TestASponsorSetNamesATaggedSidecarsSponsor(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	other, _ := net.consentedMember("other")
	tagId := testConfigId("tag")
	net.withTagOwner(tagId, member)
	agent := net.device("agent", Id{})
	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(agent, []Id{tagId}, false, net.timeMs+testConfigHourMs, 0))
	sponsorSet := func(subject testConfigDevice, sponsor Id) *protocol.SponsorSet {
		return &protocol.SponsorSet{Header: net.header(), SidecarId: subject.sidecarId.Bytes(), SponsorMemberId: sponsor.Bytes()}
	}
	net.mustRefuse(laptop, bridge.SignedType_SIGNED_SPONSOR_SET, sponsorSet(agent, other), ErrConfigAuthority)
	net.mustRefuse(net.owner, bridge.SignedType_SIGNED_SPONSOR_SET, sponsorSet(laptop, other), ErrConfigRule)
	net.mustRefuse(net.owner, bridge.SignedType_SIGNED_SPONSOR_SET, sponsorSet(agent, testConfigId("nobody")), ErrConfigRule)
	if sponsor, ok := net.log.State().Sponsor(agent.sidecarId); !ok || sponsor != member {
		t.Fatalf("the admitting member sponsors: %s %v", sponsor, ok)
	}
	verdict := net.post(net.owner, bridge.SignedType_SIGNED_SPONSOR_SET, sponsorSet(agent, other))
	if !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	if sponsor, ok := net.log.State().Sponsor(agent.sidecarId); !ok || sponsor != other {
		t.Errorf("the sponsor: %s %v", sponsor, ok)
	}
	if _, err := net.log.State().Acl(); errors.Is(err, ErrConfigRule) {
		t.Fatal(err)
	}
	net.everyReaderAgrees()
}
