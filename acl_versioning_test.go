//go:build !sidecar_http && !ios_extension

// RepoVersioning's lock, drops and rules (ACL-M10-01; FS-95's ACL cases): a locked repo refuses a version-1 write and
// a drop and never the index's version 2 or a cancel; a lock filed through the log stands at once for the job's start;
// D-ACL-25's drop signer, an owner-bound repo's admin who is not its owner's consented device refused as unconsented
// and the owner's page Worker too; the rules sealed to the repo's own generation in an owner-bound repo, which another
// generation's key cannot open; and the control class's remote search, which the gate never reads. Pure, T1.

package sidecar

import (
	"bytes"
	"errors"
	"testing"

	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A network for drops: an Owner with an invited first device, an admin of another member, the owner's read_only page
// Worker, a general repo and a vault of the owner's.
type aclDropWorld struct {
	world   *aclCompileWorld
	owner   Id
	device  Id
	worker  Id
	admin   Id
	member  Id
	general Id
	vault   Id
	config  Id
}

func newAclDropWorld(t testing.TB) *aclDropWorld {
	world := newAclCompileWorld("drops")
	self := &aclDropWorld{world: world}
	self.owner = world.member("owner@drops.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	self.device = world.device("owner device", self.owner)
	self.worker = world.device("owner page worker", self.owner)
	adminMember := world.member("admin@drops.example", bridge.MemberRole_MEMBER_ROLE_ADMIN)
	self.admin = world.device("admin device", adminMember)
	plainMember := world.member("plain@drops.example", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	self.member = world.device("plain device", plainMember)
	for _, row := range world.sidecars {
		switch Id(row.SidecarId) {
		case self.device:
			// the owner's invited first device, admitted by an Owner's signature outside every cascade
			row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED)
			row.AdmissionSigners = [][]byte{self.device.Bytes()}
		case self.worker:
			row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
		}
	}
	self.general = world.repo("general", protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	self.vault = world.repo("vault", protocol.RepoKind_REPO_KIND_VAULT, self.owner)
	// the config's row is the state's own, from the Genesis (QD-719)
	self.config = world.configRepo()
	admins := func(sidecarIds ...Id) []*protocol.AclRepoAdminRow {
		rows := []*protocol.AclRepoAdminRow{}
		for _, sidecarId := range sidecarIds {
			rows = append(rows, &protocol.AclRepoAdminRow{SidecarId: sidecarId.Bytes(), Signer: sidecarId.Bytes(), At: 1})
		}
		return rows
	}
	for _, repo := range world.statements.Repos {
		switch Id(repo.RepoId) {
		case self.general:
			repo.Admins = admins(self.admin)
		case self.vault:
			repo.Admins = admins(self.device, self.admin, self.worker)
			repo.ConsentedSidecarIds = [][]byte{self.device.Bytes(), self.worker.Bytes()}
		}
	}
	world.setPolicy(t, `{ "grants": [ { "src": ["autogroup:admin"], "dst": ["*"], "allow": ["dial"] } ] }`)
	return self
}

// Sets the repo's folded lock in the log's rows.
func (self *aclDropWorld) lock(repoId Id, lock protocol.RepoVersioningLock) {
	for _, repo := range self.world.statements.Repos {
		if Id(repo.RepoId) == repoId {
			repo.Lock = lock
		}
	}
}

// A locked repo refuses versioning 1 and a drop; the index's versioning 2, a kept version and a cancel pass; an
// unlocked or never-locked repo refuses nothing.
func TestAclRepoLockRefusesVersionlessWritesAndDrops(t *testing.T) {
	drops := newAclDropWorld(t)
	drops.lock(drops.general, protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED)
	drops.lock(drops.vault, protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_UNLOCKED)
	state := drops.world.state(t)
	if !state.RepoLocked(drops.general) || state.RepoLocked(drops.vault) || state.RepoLocked(drops.config) || state.RepoLocked(drops.world.id("no repo")) {
		t.Fatal("RepoLocked")
	}
	for _, c := range []struct {
		repoId     Id
		versioning uint32
		want       bool
	}{
		{repoId: drops.general, versioning: 1, want: false},
		{repoId: drops.general, versioning: 0, want: true},
		{repoId: drops.general, versioning: 2, want: true},
		{repoId: drops.vault, versioning: 1, want: true},
	} {
		if got := state.RepoLockAllowsVersioning(c.repoId, c.versioning); got != c.want {
			t.Errorf("versioning %d on %v: %v", c.versioning, c.repoId, got)
		}
	}
	if state.RepoLockAllowsDrop(drops.general, false) || !state.RepoLockAllowsDrop(drops.general, true) || !state.RepoLockAllowsDrop(drops.vault, false) {
		t.Error("a drop or a cancel under the lock")
	}
}

// D-ACL-25 (FS-95): a repo admin drops; an owner-bound repo's drops are only its owner's consented, not-read-only
// device's, an admin who is not refused as unconsented and the owner's page Worker too; no admin is refused; the config
// takes no drop.
func TestAclMayDropIsARepoAdminsAndTheOwnersConsentedDevice(t *testing.T) {
	drops := newAclDropWorld(t)
	state := drops.world.state(t)
	cases := []struct {
		name    string
		subject Id
		repoId  Id
		reason  AclReason
	}{
		{name: "the general repo's admin", subject: drops.admin, repoId: drops.general},
		{name: "a member who is no admin", subject: drops.member, repoId: drops.general, reason: AclReasonNoGrant},
		{name: "the owner's consented device", subject: drops.device, repoId: drops.vault},
		{name: "an admin not the owner's", subject: drops.admin, repoId: drops.vault, reason: AclReasonUnconsented},
		{name: "the owner's page Worker", subject: drops.worker, repoId: drops.vault, reason: AclReasonUnconsented},
		{name: "a member of the vault's network", subject: drops.member, repoId: drops.vault, reason: AclReasonNoGrant},
		{name: "the config", subject: drops.device, repoId: drops.config, reason: AclReasonNoGrant},
		{name: "an unadmitted sidecar", subject: drops.world.id("stranger"), repoId: drops.general, reason: AclReasonUnadmitted},
	}
	for _, c := range cases {
		decision := state.MayDrop(c.subject, c.repoId, aclTestNow)
		if c.reason == 0 && !decision.Allowed || c.reason != 0 && (decision.Allowed || decision.Reason != c.reason) {
			t.Errorf("%s: %+v", c.name, decision)
		}
	}
}

// A lock filed through the log stands at the entry that carries it, so a drop job starting after it voids its drop
// (§11.13), and an unlock lifts it.
func TestAclRepoLockFiledThroughTheLogStandsAtOnce(t *testing.T) {
	net := newTestConfigNet(t)
	repoId := testConfigId("locked repo")
	net.withAclRows(func(rows *protocol.AclRows) {
		rows.Repos = append(rows.Repos, &protocol.AclRepo{
			RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
			Admins: []*protocol.AclRepoAdminRow{{SidecarId: net.owner.sidecarId.Bytes(), Signer: net.owner.sidecarId.Bytes(), At: 1}},
		})
	})
	locked := func() bool {
		acl, err := net.log.State().Acl()
		if err != nil {
			t.Fatal(err)
		}
		return acl.RepoLocked(repoId)
	}
	if locked() {
		t.Fatal("locked before any RepoVersioning")
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_VERSIONING, &protocol.RepoVersioning{Header: net.header(), RepoId: repoId.Bytes(), Lock: protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED})
	if !locked() {
		t.Fatal("the lock does not stand at its entry")
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_VERSIONING, &protocol.RepoVersioning{Header: net.header(), RepoId: repoId.Bytes(), Lock: protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_UNLOCKED})
	if locked() {
		t.Error("the unlock does not lift it")
	}
	statement, err := AclNewestRepoVersioning(nil, net.log.State(), repoId)
	if err != nil || statement.GetLock() != protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_UNLOCKED {
		t.Errorf("the newest RepoVersioning: %v, %v", statement, err)
	}
}

// An owner-bound repo's rules are sealed to its own generation and open only with it; another repo's are the config's.
func TestAclRepoVersioningRulesOpenOnlyWithTheirRepositorysGeneration(t *testing.T) {
	net := newTestConfigNet(t)
	vaultId, generalId := testConfigId("rules vault"), testConfigId("rules general")
	net.withAclRows(func(rows *protocol.AclRows) {
		rows.Repos = append(rows.Repos,
			&protocol.AclRepo{RepoId: vaultId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_VAULT, OwnerMemberId: net.ownerMemberId.Bytes()},
			&protocol.AclRepo{RepoId: generalId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL},
		)
	})
	state := net.log.State()
	if keyRepoId, ok := AclRepoVersioningKeyRepo(state, vaultId); !ok || keyRepoId != vaultId {
		t.Errorf("the vault's rules seal to %v", keyRepoId)
	}
	if keyRepoId, ok := AclRepoVersioningKeyRepo(state, generalId); !ok || keyRepoId != testConfigId("config repo") {
		t.Errorf("a general repo's rules seal to %v", keyRepoId)
	}
	rules := &protocol.VersioningRules{Rules: []*protocol.VersioningRule{{PathGlob: "build/**", Versioning: protocol.VersioningMode_VERSIONING_MODE_OFF}}}
	vaultKey := &EvsRepoKey{repoId: vaultId, generation: 3, repoKey: bytes.Repeat([]byte{0x33}, gkmRepoKeyByteCount)}
	configKey := &EvsRepoKey{repoId: testConfigId("config repo"), generation: 3, repoKey: bytes.Repeat([]byte{0x44}, gkmRepoKeyByteCount)}
	statement := &protocol.RepoVersioning{Header: net.header(), RepoId: vaultId.Bytes(), Lock: protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_UNLOCKED}
	sealed, err := SealConfigBody(vaultKey, NewConfigSealContext(bridge.SignedType_SIGNED_REPO_VERSIONING, statement.Header), rules, nil)
	if err != nil {
		t.Fatal(err)
	}
	statement.SealedRules = sealed
	opened, err := AclRepoVersioningRules(statement, func(generation uint64) *EvsRepoKey { return vaultKey })
	if err != nil || len(opened.GetRules()) != 1 || opened.GetRules()[0].GetPathGlob() != "build/**" {
		t.Fatalf("a reader of the vault: %v, %v", opened, err)
	}
	if _, err := AclRepoVersioningRules(statement, func(generation uint64) *EvsRepoKey { return configKey }); !errors.Is(err, ErrConfigSealInvalid) {
		t.Errorf("the config's generation opened the vault's rules: %v", err)
	}
	if _, err := AclRepoVersioningRules(statement, func(generation uint64) *EvsRepoKey { return nil }); !errors.Is(err, ErrConfigSealGenerationMissing) {
		t.Errorf("a non-reader with no key: %v", err)
	}
	if none, err := AclRepoVersioningRules(&protocol.RepoVersioning{RepoId: vaultId.Bytes()}, nil); none != nil || err != nil {
		t.Errorf("a statement with no rules: %v, %v", none, err)
	}
}

// The control class's remote search needs no gate change (D-PROTO-21): the contract gate gives two admitted sidecars
// a control contract with no reach and reads no feature bit, and the receiver alone takes SEARCH on it, at Hello
// feature bit 0, refusing it without.
func TestAclControlContractCarriesSearchOnlyAtFeatureBitZero(t *testing.T) {
	net := newAclContractTestNet()
	a := net.fixture.device(net.owner)
	b := net.fixture.device(net.owner)
	gate := net.gate(t)
	verdict := aclContractDecide(gate, net.sidecarEnd(a), net.sidecarEnd(b), false)
	if verdict.Outcome != AclContractAllow || verdict.Class != AclContractClassControl || verdict.Reason != AclContractReasonWitness {
		t.Fatalf("the witness pair's verdict: %+v", verdict)
	}
	search := uint32(protocol.MessageType_SEARCH)
	if got := contractClassAdmits(connectprotocol.ContractClass_ContractClassControl, search, 0, true); got != contractClassPass {
		t.Errorf("SEARCH at bit 0: %d", got)
	}
	if got := contractClassAdmits(connectprotocol.ContractClass_ContractClassControl, search, 0, false); got != contractClassRefuse {
		t.Errorf("SEARCH without bit 0: %d", got)
	}
}
