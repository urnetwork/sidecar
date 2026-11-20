// §7.9's IndexerSet and SponsorSet on the test network, FS-82's statement cases: accepted and refused signers at each
// scope, an ephemeral or read_only subject, retirement by the subject itself, the subject's revocation and park ending
// what it serves, no key or grant added, and the designation surviving a fold at every reader; a SponsorSet by an admin
// naming a tagged sidecar's member.
//
// QD-1096 (owner decision 634): a designation's row carries its IndexerSet header's nonce, so a designation folded past
// its entry opens its sealed services at a new device started at a base and at a rows-only gate as at the long-running
// reader, a re-designation's row its own header's; and the services open under no other nonce or network, and wait for
// a generation the reader does not hold.
//
// TEAM-M10-02: SearchIndexersFor as DESIGN-DETAILS 7.2.2's E1 to E6, the rows of 7.6's TestEligibleTable this function
// decides, over a Team with two members, an EvsShare'd vault, a tagged indexer and an audit reader, and over a personal
// network. SEARCH-M10-32's verdict table has its own tests of the same names, so these carry the function's.

package sidecar

import (
	"bytes"
	"errors"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

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

// An IndexerSet at the tip whose services are sealed to key under the statement's own header, as
// Sidecar.DesignateIndexer files one.
func (self *testConfigNet) sealedIndexerSet(subject testConfigDevice, scope protocol.IndexerScope, key *EvsRepoKey, services ...protocol.IndexerService) *protocol.IndexerSet {
	self.t.Helper()
	header := self.header()
	sealed, err := SealConfigBody(key, NewConfigSealContext(bridge.SignedType_SIGNED_INDEXER_SET, header), &protocol.IndexerServices{Services: services}, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	return &protocol.IndexerSet{Header: header, SidecarId: subject.sidecarId.Bytes(), Scope: scope, SealedServices: sealed}
}

// Two bases folding the tip at its config version, the second folding the first, so the retention point passes every
// entry through at: no reader started from what the net's reader retains holds those entries, only the rows.
func (self *testConfigNet) foldPast(at uint64) {
	self.t.Helper()
	configVersion := self.log.State().Base().GetConfigVersion()
	for range 2 {
		if verdict := self.fold(self.owner, self.n, configVersion); !verdict.Accepted() {
			self.t.Fatalf("the base at %d: %v", verdict.Pin.GetVersion(), verdict.Refusal)
		}
	}
	for _, entryBytes := range self.log.Retained().Entries {
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(entryBytes, entry); err != nil {
			self.t.Fatal(err)
		}
		if entry.GetN() <= at {
			self.t.Fatalf("the reader still retains entry %d", entry.GetN())
		}
	}
}

// A new device and a rows-only gate, each started from what the net's reader retains, as everyReaderAgrees starts them.
func (self *testConfigNet) startedReaders() (*ConfigLog, *ConfigLog) {
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
	return restored, gate
}

// QD-1096: the designation's row carries its IndexerSet header's nonce, so once its entry is folded past every reader,
// the long-running one, a new device started at the newest base and a rows-only gate open its sealed services alike
// with the config key; a newer designation of the subject at the scope holds with its own header's nonce.
func TestAFoldedIndexerDesignationOpensAtEveryReader(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	desktop := net.device("m desktop", member)
	net.admitDevice(laptop, desktop, 0)
	key := testConfigSealKey(3)
	mail, search := protocol.IndexerService_INDEXER_SERVICE_MAIL, protocol.IndexerService_INDEXER_SERVICE_SEARCH
	designation := net.sealedIndexerSet(desktop, protocol.IndexerScope_INDEXER_SCOPE_MEMBER, key, mail, search)
	at := net.mustPost(laptop, bridge.SignedType_SIGNED_INDEXER_SET, designation).Pin.GetVersion()
	if rows := net.log.State().Rows().GetIndexers(); len(rows) != 1 || !bytes.Equal(rows[0].GetNonce(), designation.GetHeader().GetNonce()) {
		t.Fatalf("the folded row: %v", rows)
	}
	net.foldPast(at)

	expectOpens := func(label string, state *ConfigState, nonce []byte, want ...protocol.IndexerService) {
		t.Helper()
		indexers := state.Indexers()
		if len(indexers) != 1 || indexers[0].SidecarId != desktop.sidecarId || indexers[0].NetworkId != net.networkId || !bytes.Equal(indexers[0].Nonce, nonce) {
			t.Fatalf("%s: the designations %+v", label, indexers)
		}
		services, err := indexers[0].OpenServices(testConfigSealKeyAt(key))
		if err != nil || !slices.Equal(services, want) {
			t.Errorf("%s: services %v, err %v", label, services, err)
		}
		if offered, opened := ConfigIndexerServicesOpener(testConfigSealKeyAt(key))(indexers[0]); !opened || !slices.Equal(offered, want) {
			t.Errorf("%s: the opener's services %v, opened %t", label, offered, opened)
		}
	}
	type testReader struct {
		label string
		log   *ConfigLog
	}
	readers := func() []testReader {
		restored, gate := net.startedReaders()
		return []testReader{{label: "the long-running reader", log: net.log}, {label: "a new device", log: restored}, {label: "a rows-only gate", log: gate}}
	}
	for _, reader := range readers() {
		if reader.log.keptEntry(at) != nil {
			t.Fatalf("%s holds the designation's entry", reader.label)
		}
		expectOpens(reader.label, reader.log.State(), designation.GetHeader().GetNonce(), mail, search)
	}
	net.everyReaderAgrees()

	// the newest designation of (sidecar_id, scope) holds, its row with its own header's nonce
	redesignation := net.sealedIndexerSet(desktop, protocol.IndexerScope_INDEXER_SCOPE_MEMBER, key, search)
	at = net.mustPost(laptop, bridge.SignedType_SIGNED_INDEXER_SET, redesignation).Pin.GetVersion()
	if bytes.Equal(redesignation.GetHeader().GetNonce(), designation.GetHeader().GetNonce()) {
		t.Fatal("two headers with one nonce")
	}
	net.foldPast(at)
	for _, reader := range readers() {
		expectOpens(reader.label+" after the re-designation", reader.log.State(), redesignation.GetHeader().GetNonce(), search)
	}
	net.everyReaderAgrees()
}

// A designation's services open only under the network id and nonce its seal is bound to, and only with the key of the
// generation the seal names: a tampered nonce, another network's id, a nonce of the wrong length and a key of another
// generation each open nothing, and the opener reads each as unopened.
func TestADesignationsServicesOpenUnderNoOtherNonce(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	desktop := net.device("m desktop", member)
	net.admitDevice(laptop, desktop, 0)
	key := testConfigSealKey(3)
	net.mustPost(laptop, bridge.SignedType_SIGNED_INDEXER_SET, net.sealedIndexerSet(desktop, protocol.IndexerScope_INDEXER_SCOPE_MEMBER, key, protocol.IndexerService_INDEXER_SERVICE_MAIL))
	indexers := net.log.State().Indexers()
	if len(indexers) != 1 {
		t.Fatalf("the designations %+v", indexers)
	}
	indexer := indexers[0]
	if services, err := indexer.OpenServices(testConfigSealKeyAt(key)); err != nil || !slices.Equal(services, []protocol.IndexerService{protocol.IndexerService_INDEXER_SERVICE_MAIL}) {
		t.Fatalf("the designation as folded: %v, %v", services, err)
	}

	tamperedNonce := indexer
	tamperedNonce.Nonce = bytes.Clone(indexer.Nonce)
	tamperedNonce.Nonce[0] ^= 0x01
	otherNetwork := indexer
	otherNetwork.NetworkId = testConfigId("another network")
	shortNonce := indexer
	shortNonce.Nonce = indexer.Nonce[:configNonceByteCount-1]
	noNonce := indexer
	noNonce.Nonce = nil
	cases := []struct {
		label   string
		indexer ConfigIndexer
	}{
		{label: "a tampered nonce", indexer: tamperedNonce},
		{label: "another network", indexer: otherNetwork},
		{label: "a short nonce", indexer: shortNonce},
		{label: "no nonce", indexer: noNonce},
	}
	for _, c := range cases {
		if services, err := c.indexer.OpenServices(testConfigSealKeyAt(key)); !errors.Is(err, ErrConfigSealInvalid) || services != nil {
			t.Errorf("%s: services %v, err %v", c.label, services, err)
		}
		if _, opened := ConfigIndexerServicesOpener(testConfigSealKeyAt(key))(c.indexer); opened {
			t.Errorf("%s: the opener opened it", c.label)
		}
	}
	// a reader that holds another generation, or none, waits for the seal's
	if _, err := indexer.OpenServices(testConfigSealKeyAt(testConfigSealKey(2))); !errors.Is(err, ErrConfigSealGenerationMissing) {
		t.Errorf("another generation's key: %v", err)
	}
	if _, err := indexer.OpenServices(nil); !errors.Is(err, ErrConfigSealGenerationMissing) {
		t.Errorf("no keys: %v", err)
	}
	if ConfigIndexerServicesOpener(nil) != nil {
		t.Error("an opener over no keys")
	}
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

// Every designation opens and offers search.
func testConfigSearchServices(indexer ConfigIndexer) ([]protocol.IndexerService, bool) {
	return []protocol.IndexerService{protocol.IndexerService_INDEXER_SERVICE_SEARCH}, true
}

// A Team for 7.2.2's rows: Dana and Ben, each with a laptop, a phone and a NAS that is its member's search indexer;
// an auditor with a laptop and a NAS, its member's indexer too, whom an audit block lets read every vault; the
// network Owner's device and a tagged agent as network-scope indexers; Dana's vault, shared by EvsShare with Ben's
// phone and NAS, the Owner's device and the agent; Dana's mailbox and secret, Ben's vault, and a team repo every device
// named here reads but the laptops of Dana and Ben and the auditor's NAS.
type testConfigSearchTeam struct {
	net *testConfigNet

	dana, ben, auditor                 Id
	danaLaptop, danaPhone, danaNas     testConfigDevice
	benLaptop, benPhone, benNas        testConfigDevice
	auditorLaptop, auditorNas          testConfigDevice
	agent                              testConfigDevice
	danaVault, danaMailbox, danaSecret Id
	benVault, teamRepo                 Id
}

func newTestConfigSearchTeam(t *testing.T) *testConfigSearchTeam {
	t.Helper()
	net := newTestConfigNet(t)
	self := &testConfigSearchTeam{net: net}
	self.dana, self.danaLaptop = net.consentedMember("dana")
	self.ben, self.benLaptop = net.consentedMember("ben")
	self.auditor, self.auditorLaptop = net.consentedMember("auditor")
	self.danaPhone, self.danaNas = net.device("dana phone", self.dana), net.device("dana nas", self.dana)
	self.benPhone, self.benNas = net.device("ben phone", self.ben), net.device("ben nas", self.ben)
	self.auditorNas = net.device("auditor nas", self.auditor)
	net.admitDevice(self.danaLaptop, self.danaPhone, 0)
	net.admitDevice(self.danaLaptop, self.danaNas, 0)
	net.admitDevice(self.benLaptop, self.benPhone, 0)
	net.admitDevice(self.benLaptop, self.benNas, 0)
	net.admitDevice(self.auditorLaptop, self.auditorNas, 0)

	// the Owner's tag for the agent, and an audit block naming the auditor's member over every vault
	tagId, auditAtom := testConfigId("tag indexer"), testConfigId("audit readers")
	optIn, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.AuditOptIn{
		ReaderAtoms: [][]byte{auditAtom.Bytes()}, NotAfter: net.timeMs + 24*testConfigHourMs,
	})
	if err != nil {
		t.Fatal(err)
	}
	net.withAclRows(func(rows *protocol.AclRows) {
		rows.Atoms = append(rows.Atoms,
			&protocol.AclAtom{Atom: tagId.Bytes(), TagOwnerMemberIds: [][]byte{net.ownerMemberId.Bytes()}},
			&protocol.AclAtom{Atom: auditAtom.Bytes(), MemberIds: [][]byte{self.auditor.Bytes()}},
		)
		rows.Audit = &protocol.AclAudit{
			ReaderAtoms: [][]byte{auditAtom.Bytes()},
			RepoKinds:   []uint32{uint32(protocol.RepoKind_REPO_KIND_VAULT)},
			AuditOptIn:  optIn,
		}
	})
	self.agent = net.device("agent indexer", Id{})
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(self.agent, []Id{tagId}, false, net.timeMs+testConfigHourMs, 0))

	create := func(signer testConfigDevice, label string, kind protocol.RepoKind) Id {
		repoId := testConfigId(label)
		net.mustPost(signer, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: net.header(), RepoId: repoId.Bytes(), Kind: kind})
		return repoId
	}
	self.danaVault = create(self.danaLaptop, "dana vault", protocol.RepoKind_REPO_KIND_VAULT)
	self.danaMailbox = create(self.danaLaptop, "dana mailbox", protocol.RepoKind_REPO_KIND_MAILBOX)
	self.danaSecret = create(self.danaLaptop, "dana secret", protocol.RepoKind_REPO_KIND_SECRET)
	self.benVault = create(self.benLaptop, "ben vault", protocol.RepoKind_REPO_KIND_VAULT)
	self.teamRepo = create(net.owner, "team repo", protocol.RepoKind_REPO_KIND_GENERAL)
	for _, subject := range []testConfigDevice{self.benPhone, self.benNas, net.owner, self.agent} {
		net.mustPost(self.danaLaptop, bridge.SignedType_SIGNED_EVS_SHARE, &protocol.EvsShare{
			Header: net.header(), RepoId: self.danaVault.Bytes(), Subject: subject.sidecarId.Bytes(),
		})
	}
	for _, reader := range []testConfigDevice{self.danaPhone, self.danaNas, self.benPhone, self.benNas, self.auditorLaptop, self.agent} {
		self.grantTeamRepo(reader)
	}

	network, member := protocol.IndexerScope_INDEXER_SCOPE_NETWORK, protocol.IndexerScope_INDEXER_SCOPE_MEMBER
	net.mustPost(net.owner, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(net.owner, network, false))
	net.mustPost(net.owner, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(self.agent, network, false))
	net.mustPost(self.danaLaptop, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(self.danaNas, member, false))
	net.mustPost(self.benLaptop, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(self.benNas, member, false))
	net.mustPost(self.auditorLaptop, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(self.auditorNas, member, false))

	// what makes each refusal below the predicate's own: the devices it refuses do read the repo
	self.mustRead(self.danaVault, self.danaPhone, self.danaNas, self.benPhone, self.benNas, net.owner, self.agent, self.auditorLaptop, self.auditorNas)
	self.mustRead(self.danaMailbox, self.danaPhone, self.danaNas)
	self.mustRead(self.danaSecret, self.danaPhone, self.danaNas)
	self.mustRead(self.teamRepo, self.danaPhone, self.danaNas, self.benPhone, self.benNas, net.owner, self.agent, self.auditorLaptop)
	return self
}

// Grants a device reading of the team repo, by its creator.
func (self *testConfigSearchTeam) grantTeamRepo(reader testConfigDevice) {
	self.net.t.Helper()
	self.net.mustPost(self.net.owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
		Header: self.net.header(), RepoId: self.teamRepo.Bytes(), Subject: reader.sidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
	})
}

// Fails the test unless every device is among the repo's readers at the tip.
func (self *testConfigSearchTeam) mustRead(repoId Id, devices ...testConfigDevice) {
	self.net.t.Helper()
	readers := self.net.log.State().RepoReaders(repoId)
	for _, device := range devices {
		if !slices.Contains(readers, device.sidecarId) {
			self.net.t.Fatalf("%s does not read %s", device.sidecarId, repoId)
		}
	}
}

// The indexers that answer searcher over the repo at the net's tip must be exactly want.
func testConfigExpectSearchIndexers(t *testing.T, net *testConfigNet, label string, searcher testConfigDevice, repoId Id,
	services func(indexer ConfigIndexer) ([]protocol.IndexerService, bool), want ...testConfigDevice) {
	t.Helper()
	wantIds := []Id{}
	for _, device := range want {
		wantIds = append(wantIds, device.sidecarId)
	}
	slices.SortFunc(wantIds, Id.Cmp)
	got := slices.Clone(net.log.State().SearchIndexersFor(searcher.sidecarId, repoId, services))
	slices.SortFunc(got, Id.Cmp)
	if !slices.Equal(got, wantIds) {
		t.Errorf("%s: answered by %v, want %v", label, got, wantIds)
	}
}

// 7.2.2's E4 to E6 over the Team, each row a searcher and a repo: an owner-bound repo goes only to its owner's
// consented member-scope indexers, whoever else reads it and at whatever scope; a team repo to every network-scope
// indexer and the searcher's own member's; a barred kind and a repo the searcher does not read to none.
func TestSearchIndexersForEligibleTable(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	net := team.net
	configRepoId := Id(net.log.State().Genesis().GetConfigRepoId())
	cases := []struct {
		label    string
		searcher testConfigDevice
		repoId   Id
		want     []testConfigDevice
	}{
		{label: "a member's own vault", searcher: team.danaPhone, repoId: team.danaVault, want: []testConfigDevice{team.danaNas}},
		{label: "a member's own mailbox", searcher: team.danaPhone, repoId: team.danaMailbox, want: []testConfigDevice{team.danaNas}},
		{label: "another member's own vault", searcher: team.benPhone, repoId: team.benVault, want: []testConfigDevice{team.benNas}},
		// 7.1's A: Ben's NAS reads Dana's vault and is Ben's indexer, and Dana never consented it
		{label: "a vault shared with the searcher", searcher: team.benPhone, repoId: team.danaVault, want: []testConfigDevice{team.danaNas}},
		{label: "a vault the searcher does not read", searcher: team.danaPhone, repoId: team.benVault},
		// the audit reader is neither a device of the owner nor a share's subject, though its own indexer reads too
		{label: "the audit reader", searcher: team.auditorLaptop, repoId: team.danaVault},
		// the Owner's device and the agent read by a share and index the network, and answer none of the rows above; as
		// a share's subject the Owner's device is itself answered by the vault owner's indexer
		{label: "another share's subject", searcher: net.owner, repoId: team.danaVault, want: []testConfigDevice{team.danaNas}},
		{label: "an indexer is not asked of itself", searcher: team.danaNas, repoId: team.danaVault},
		{label: "the owner's laptop", searcher: team.danaLaptop, repoId: team.danaVault, want: []testConfigDevice{team.danaNas}},
		{label: "a secret", searcher: team.danaPhone, repoId: team.danaSecret},
		{label: "the config", searcher: team.danaPhone, repoId: configRepoId},
		{label: "an unknown repo", searcher: team.danaPhone, repoId: testConfigId("no such repo")},
		{label: "a team repo, Dana", searcher: team.danaPhone, repoId: team.teamRepo, want: []testConfigDevice{net.owner, team.agent, team.danaNas}},
		{label: "a team repo, Ben", searcher: team.benPhone, repoId: team.teamRepo, want: []testConfigDevice{net.owner, team.agent, team.benNas}},
		{label: "a team repo, the auditor, whose indexer does not read it", searcher: team.auditorLaptop, repoId: team.teamRepo, want: []testConfigDevice{net.owner, team.agent}},
		{label: "a team repo the searcher does not read", searcher: team.danaLaptop, repoId: team.teamRepo},
		{label: "a tagged searcher", searcher: team.agent, repoId: team.teamRepo},
		{label: "an unknown searcher", searcher: net.device("never admitted", team.dana), repoId: team.teamRepo},
	}
	for _, c := range cases {
		testConfigExpectSearchIndexers(t, net, c.label, c.searcher, c.repoId, testConfigSearchServices, c.want...)
	}
	net.everyReaderAgrees()
}

// 7.1's A on the function alone: Dana shares her vault with Ben's phone and Ben's NAS, Ben's search indexer. Ben's
// search of it goes to Dana's indexer and never to his own, and to none once Dana has no indexer; a share that names
// Ben's member, not a device, reads the same; and a share revoked ends it.
func TestSearchIndexersForAnOwnerBoundRepoNeedsItsOwnersDevice(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	net := team.net
	testConfigExpectSearchIndexers(t, net, "the shared vault", team.benPhone, team.danaVault, testConfigSearchServices, team.danaNas)
	// the indexer's side: Ben's NAS, asked by Ben's phone, does not find itself in the answer
	if slices.Contains(net.log.State().SearchIndexersFor(team.benPhone.sidecarId, team.danaVault, testConfigSearchServices), team.benNas.sidecarId) {
		t.Fatal("a device the vault's owner never consented answers searches of it")
	}
	net.mustPost(team.danaNas, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(team.danaNas, protocol.IndexerScope_INDEXER_SCOPE_MEMBER, true))
	testConfigExpectSearchIndexers(t, net, "the owner has no indexer", team.benPhone, team.danaVault, testConfigSearchServices)
	testConfigExpectSearchIndexers(t, net, "the owner itself then", team.danaPhone, team.danaVault, testConfigSearchServices)
	net.mustPost(team.danaLaptop, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(team.danaNas, protocol.IndexerScope_INDEXER_SCOPE_MEMBER, false))

	// Ben's laptop reads only once a share names Ben's member
	testConfigExpectSearchIndexers(t, net, "a device no share names", team.benLaptop, team.danaVault, testConfigSearchServices)
	net.mustPost(team.danaLaptop, bridge.SignedType_SIGNED_EVS_SHARE, &protocol.EvsShare{Header: net.header(), RepoId: team.danaVault.Bytes(), Subject: team.ben.Bytes()})
	testConfigExpectSearchIndexers(t, net, "a share of the member", team.benLaptop, team.danaVault, testConfigSearchServices, team.danaNas)

	// a share that expires ends with no device online
	expires := net.timeMs + testConfigHourMs
	net.mustPost(team.danaLaptop, bridge.SignedType_SIGNED_EVS_SHARE, &protocol.EvsShare{
		Header: net.header(), RepoId: team.danaMailbox.Bytes(), Subject: team.benPhone.sidecarId.Bytes(), Expires: expires,
	})
	testConfigExpectSearchIndexers(t, net, "a share with an expiry ahead", team.benPhone, team.danaMailbox, testConfigSearchServices, team.danaNas)
	net.tickAt(expires + 1000)
	testConfigExpectSearchIndexers(t, net, "a share past its expiry", team.benPhone, team.danaMailbox, testConfigSearchServices)
	testConfigExpectSearchIndexers(t, net, "its owner past the share's expiry", team.danaPhone, team.danaMailbox, testConfigSearchServices, team.danaNas)
	net.everyReaderAgrees()
}

// E1 and E3: an indexer an active Suspend names serves nothing and is in no listing until its Unsuspend, a suspended
// searcher is answered by none, an ephemeral searcher by none though it reads the repo and its member has an indexer,
// and a tagged indexer past its not_after drops out.
func TestSearchIndexersForStandingDevicesOnly(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	net := team.net
	suspend := func(device testConfigDevice, label string) {
		net.mustPost(net.owner, bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{Header: net.header(), Subject: device.sidecarId.Bytes(), SuspendId: aclTestSuspendId(label)})
	}
	unsuspend := func(device testConfigDevice, label string) {
		net.mustPost(net.owner, bridge.SignedType_SIGNED_UNSUSPEND, &bridge.Unsuspend{Header: net.header(), Subject: device.sidecarId.Bytes(), SuspendId: aclTestSuspendId(label)})
	}
	listed := func(device testConfigDevice) bool {
		return slices.ContainsFunc(net.log.State().Indexers(), func(indexer ConfigIndexer) bool { return indexer.SidecarId == device.sidecarId })
	}

	suspend(team.danaNas, "indexer")
	if listed(team.danaNas) || len(net.log.State().IndexerDesignations(team.danaNas.sidecarId)) != 0 {
		t.Error("a suspended subject is still listed as serving")
	}
	testConfigExpectSearchIndexers(t, net, "a suspended indexer, the vault", team.danaPhone, team.danaVault, testConfigSearchServices)
	testConfigExpectSearchIndexers(t, net, "a suspended indexer, the team repo", team.danaPhone, team.teamRepo, testConfigSearchServices, net.owner, team.agent)
	unsuspend(team.danaNas, "indexer")
	if !listed(team.danaNas) {
		t.Error("the Unsuspend did not restore the designation")
	}
	testConfigExpectSearchIndexers(t, net, "after the Unsuspend", team.danaPhone, team.danaVault, testConfigSearchServices, team.danaNas)

	suspend(team.benPhone, "searcher")
	testConfigExpectSearchIndexers(t, net, "a suspended searcher, the team repo", team.benPhone, team.teamRepo, testConfigSearchServices)
	testConfigExpectSearchIndexers(t, net, "a suspended searcher, its vault", team.benPhone, team.benVault, testConfigSearchServices)
	unsuspend(team.benPhone, "searcher")
	testConfigExpectSearchIndexers(t, net, "the searcher after its Unsuspend", team.benPhone, team.benVault, testConfigSearchServices, team.benNas)

	// an ephemeral device of Dana that a grant lets read the team repo
	worker := net.device("dana worker", team.dana)
	net.mustPost(team.danaLaptop, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(worker, nil, true, net.timeMs+testConfigHourMs, 0))
	team.grantTeamRepo(worker)
	team.mustRead(team.teamRepo, worker)
	testConfigExpectSearchIndexers(t, net, "an ephemeral searcher", worker, team.teamRepo, testConfigSearchServices)

	// a revoked indexer, which Indexers leaves out
	net.mustPost(team.benLaptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(team.benNas, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	testConfigExpectSearchIndexers(t, net, "a revoked indexer", team.benPhone, team.benVault, testConfigSearchServices)

	// the tagged indexer's admission runs out
	notAfter := net.log.State().SidecarRow(team.agent.sidecarId).GetNotAfter()
	net.tickAt(notAfter + 1000)
	if !listed(team.agent) {
		t.Fatal("the designation's row went with the admission's not_after")
	}
	testConfigExpectSearchIndexers(t, net, "a tagged indexer past not_after", team.danaPhone, team.teamRepo, testConfigSearchServices, net.owner, team.danaNas)
	net.everyReaderAgrees()
}

// E2: only a designation whose services open and name search counts, scope by scope, so a device designated at both
// scopes answers by the scopes that offer search.
func TestSearchIndexersForCountOnlyScopesThatOfferSearch(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	net := team.net
	network, member := protocol.IndexerScope_INDEXER_SCOPE_NETWORK, protocol.IndexerScope_INDEXER_SCOPE_MEMBER
	// Dana's NAS at network scope too
	net.mustPost(net.owner, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(team.danaNas, network, false))
	only := func(scope protocol.IndexerScope) func(indexer ConfigIndexer) ([]protocol.IndexerService, bool) {
		return func(indexer ConfigIndexer) ([]protocol.IndexerService, bool) {
			if indexer.Scope == scope {
				return []protocol.IndexerService{protocol.IndexerService_INDEXER_SERVICE_SEARCH}, true
			}
			return []protocol.IndexerService{protocol.IndexerService_INDEXER_SERVICE_MAIL}, true
		}
	}
	// in a network of several members a network designation covers no member's own repo
	testConfigExpectSearchIndexers(t, net, "search at network scope alone, the vault", team.danaPhone, team.danaVault, only(network))
	testConfigExpectSearchIndexers(t, net, "search at network scope alone, the team repo", team.benPhone, team.teamRepo, only(network), net.owner, team.agent, team.danaNas)
	testConfigExpectSearchIndexers(t, net, "search at member scope alone, the vault", team.danaPhone, team.danaVault, only(member), team.danaNas)
	testConfigExpectSearchIndexers(t, net, "search at member scope alone, the team repo", team.benPhone, team.teamRepo, only(member), team.benNas)
	unopened := func(indexer ConfigIndexer) ([]protocol.IndexerService, bool) {
		return []protocol.IndexerService{protocol.IndexerService_INDEXER_SERVICE_SEARCH}, false
	}
	testConfigExpectSearchIndexers(t, net, "services that do not open", team.danaPhone, team.danaVault, unopened)
	testConfigExpectSearchIndexers(t, net, "no services given", team.danaPhone, team.danaVault, nil)
}

// E5's second line: a personal network's designations are network scope and cover its owner's repos, read as a state
// that holds one member. Its tagged indexer, consented for no one, answers no owner-bound repo though a share lets it
// read; and once a second member joins, the network designation covers the team repos alone.
func TestSearchIndexersForAPersonalNetworksIndexerAnswersItsOwner(t *testing.T) {
	net := newTestConfigNet(t)
	phone, nas := net.device("owner phone", net.ownerMemberId), net.device("owner nas", net.ownerMemberId)
	net.admitDevice(net.owner, phone, 0)
	net.admitDevice(net.owner, nas, 0)
	tagId := testConfigId("tag indexer")
	net.withTagOwner(tagId, net.ownerMemberId)
	agent := net.device("agent indexer", Id{})
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(agent, []Id{tagId}, false, net.timeMs+testConfigHourMs, 0))
	mailbox, notes := testConfigId("owner mailbox"), testConfigId("notes")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: net.header(), RepoId: mailbox.Bytes(), Kind: protocol.RepoKind_REPO_KIND_MAILBOX})
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: net.header(), RepoId: notes.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	net.mustPost(net.owner, bridge.SignedType_SIGNED_EVS_SHARE, &protocol.EvsShare{Header: net.header(), RepoId: mailbox.Bytes(), Subject: agent.sidecarId.Bytes()})
	for _, reader := range []testConfigDevice{phone, nas, agent} {
		net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
			Header: net.header(), RepoId: notes.Bytes(), Subject: reader.sidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
		})
	}
	network := protocol.IndexerScope_INDEXER_SCOPE_NETWORK
	net.mustPost(net.owner, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(nas, network, false))
	net.mustPost(net.owner, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(agent, network, false))
	readers := net.log.State().RepoReadersAt(mailbox, time.UnixMilli(net.timeMs))
	for _, device := range []testConfigDevice{phone, nas, agent} {
		if !slices.Contains(readers, device.sidecarId) {
			t.Fatalf("%s does not read the mailbox", device.sidecarId)
		}
	}

	testConfigExpectSearchIndexers(t, net, "the owner's mailbox", phone, mailbox, testConfigSearchServices, nas)
	testConfigExpectSearchIndexers(t, net, "the owner's mailbox from its first device", net.owner, mailbox, testConfigSearchServices, nas)
	testConfigExpectSearchIndexers(t, net, "a general repo", phone, notes, testConfigSearchServices, nas, agent)

	// a second member: the state holds two, and a network designation covers no member's own repo
	net.consentedMember("second")
	testConfigExpectSearchIndexers(t, net, "the mailbox in a network of two", phone, mailbox, testConfigSearchServices)
	testConfigExpectSearchIndexers(t, net, "a general repo in a network of two", phone, notes, testConfigSearchServices, nas, agent)
	// a member designation then covers it again
	net.mustPost(net.owner, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(nas, protocol.IndexerScope_INDEXER_SCOPE_MEMBER, false))
	testConfigExpectSearchIndexers(t, net, "the mailbox by a member designation", phone, mailbox, testConfigSearchServices, nas)
	net.everyReaderAgrees()
}
