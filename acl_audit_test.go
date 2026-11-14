// Owner decision 63's audit reader (ACL-M6-02): a block with no AuditOptIn refused at validation and ignored by a
// reader's compile; one signer's opt-in refused, k of n's taken; the reader among a repo's readers only for the kinds
// the block names, by AuditReaders and RepoReaders alike; an AuditOptOut a shrink; past not_after an expiry; FS-30's
// audit reader reading under receipts; and an admin's EvsShare of an owner-bound repo still refused. Pure, on every
// leg.

package sidecar

import (
	"errors"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A Team with an owner's vault and mailbox, an admin's tagged audit agent, and a document whose audit block names the
// agent's tag and the vault kind.
type aclAuditWorld struct {
	world       *aclCompileWorld
	owner       Id
	laptop      Id
	adminDevice Id
	auditor     Id
	vault       Id
	mailbox     Id
	notAfter    time.Time
}

const aclAuditTestPolicy = `{
  "tagOwners": { "tag:audit": ["autogroup:admin"] },
  "audit": { "reader": "tag:audit", "repos": ["kind:vault"] },
}`

func newAclAuditWorld(t *testing.T) *aclAuditWorld {
	world := newAclCompileWorld("audit")
	owner := world.member("owner@acme.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	admin := world.member("admin@acme.example", bridge.MemberRole_MEMBER_ROLE_ADMIN)
	self := &aclAuditWorld{
		world:       world,
		owner:       owner,
		laptop:      world.device("laptop", owner),
		adminDevice: world.device("admin laptop", admin),
		auditor:     world.agent("auditor", admin, "audit"),
		vault:       world.repo("vault-a", protocol.RepoKind_REPO_KIND_VAULT, owner),
		mailbox:     world.repo("mailbox-a", protocol.RepoKind_REPO_KIND_MAILBOX, owner),
		notAfter:    aclTestNow.Add(24 * time.Hour),
	}
	world.setPolicy(t, aclAuditTestPolicy)
	return self
}

// The opt-in the admins file for the audit tag.
func (self *aclAuditWorld) optIn() *protocol.AuditOptIn {
	return &protocol.AuditOptIn{ReaderAtoms: [][]byte{self.world.tag("audit").Bytes()}, NotAfter: self.notAfter.UnixMilli()}
}

// An AuditOptIn's record as rows carry it, naming readers until notAfter.
func aclTestAuditOptInRecord(t testing.TB, notAfter time.Time, readers ...Id) []byte {
	t.Helper()
	optIn := &protocol.AuditOptIn{NotAfter: notAfter.UnixMilli()}
	for _, reader := range readers {
		optIn.ReaderAtoms = append(optIn.ReaderAtoms, reader.Bytes())
	}
	record, err := proto.MarshalOptions{Deterministic: true}.Marshal(optIn)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

// Puts the opt-in's record in the log's rows, as its fold leaves it.
func (self *aclAuditWorld) standOptIn(t *testing.T) {
	record, err := proto.MarshalOptions{Deterministic: true}.Marshal(self.optIn())
	if err != nil {
		t.Fatal(err)
	}
	self.world.statements.Audit = &protocol.AclAudit{ReaderAtoms: self.optIn().GetReaderAtoms(), AuditOptIn: record}
}

// One statement as its verifier takes it, by the admin's device, k of n where authority is set.
func (self *aclAuditWorld) statement(signedType bridge.SignedType, body proto.Message, authority bool) *AclStatement {
	return &AclStatement{
		Type:      signedType,
		Body:      body,
		Signers:   []ConfigSigner{{Kind: ConfigSignerSidecar, SidecarId: self.adminDevice}},
		Authority: authority,
		N:         self.world.position + 100,
		TimeMs:    aclTestNow.UnixMilli(),
	}
}

// With no opt-in the block is refused at validation, and every reader's compile names no reader with it.
func TestAclAuditBlockCountsOnlyUnderAnOptIn(t *testing.T) {
	world := newAclAuditWorld(t)
	err := ValidateAclPolicy(&AclValidateInput{Compile: world.world.input()})
	refusals := &AclValidationError{}
	if !errors.As(err, &refusals) || !slices.ContainsFunc(refusals.Refusals, func(refusal AclValidationRefusal) bool { return refusal.Rule == "audit" }) {
		t.Fatalf("a block with no opt-in: %v", err)
	}
	state := world.world.state(t)
	if state.Rows().GetAudit() != nil {
		t.Errorf("the rows hold an audit with no opt-in: %v", state.Rows().GetAudit())
	}
	if readers := state.AuditReaders(world.vault, aclTestNow); len(readers) != 0 {
		t.Errorf("audit readers with no opt-in: %v", readers)
	}
	if slices.Contains(state.RepoReaders(world.vault, aclTestNow), world.auditor) {
		t.Error("the agent reads the vault with no opt-in")
	}

	world.standOptIn(t)
	if err := ValidateAclPolicy(&AclValidateInput{Compile: world.world.input()}); err != nil && errors.As(err, &refusals) &&
		slices.ContainsFunc(refusals.Refusals, func(refusal AclValidationRefusal) bool { return refusal.Rule == "audit" }) {
		t.Errorf("a block under a standing opt-in: %v", err)
	}
}

// Under a standing opt-in the reader reads the kinds the block names and no other, members see it among those
// repos' readers, and it reads under read receipts (FS-30).
func TestAclAuditReaderReadsOnlyWhatTheBlockNames(t *testing.T) {
	world := newAclAuditWorld(t)
	world.standOptIn(t)
	state := world.world.state(t)
	audit := state.Rows().GetAudit()
	if audit == nil || len(audit.GetReaderAtoms()) != 1 || !slices.Equal(audit.GetRepoKinds(), []uint32{uint32(protocol.RepoKind_REPO_KIND_VAULT)}) ||
		len(audit.GetAuditOptIn()) == 0 {
		t.Fatalf("the compiled audit: %v", audit)
	}
	if readers := state.AuditReaders(world.vault, aclTestNow); !slices.Equal(readers, []Id{world.auditor}) {
		t.Errorf("the vault's audit readers: %v", readers)
	}
	if !slices.Contains(state.RepoReaders(world.vault, aclTestNow), world.auditor) {
		t.Error("the vault's readers leave out the audit reader")
	}
	if readers := state.AuditReaders(world.mailbox, aclTestNow); len(readers) != 0 {
		t.Errorf("the mailbox, which the block does not name: %v", readers)
	}
	if slices.Contains(state.RepoReaders(world.mailbox, aclTestNow), world.auditor) {
		t.Error("the audit reader reads a kind the block does not name")
	}
	engine := NewAclEngine(world.auditor, nil, nil, nil)
	if err := engine.Install(state, nil); err != nil {
		t.Fatal(err)
	}
	read := engine.ReadRequiresReceipt(world.vault, aclTestNow)
	if !read.Allowed || !read.RequiresReceipt || read.Reason != AclReasonAudit {
		t.Errorf("the audit reader's read: %+v", read)
	}
	// past not_after, an expiry
	if readers := state.AuditReaders(world.vault, world.notAfter); len(readers) != 0 {
		t.Errorf("readers past not_after: %v", readers)
	}
	if state.EvsAccess(AclSidecarSubject(world.auditor), world.vault, AclTokenAudienceEvs, world.notAfter).Rights.Has(AclEvsRead) {
		t.Error("the audit reader reads past not_after")
	}
	// a head past not_after compiles no reader
	world.world.headTimeMs = world.notAfter.UnixMilli()
	if expired := world.world.state(t); expired.Rows().GetAudit() != nil {
		t.Errorf("a head past not_after: %v", expired.Rows().GetAudit())
	}
}

// One signer's opt-in is refused, k of n's is taken and folds its record into the rows; an AuditOptOut, k of n too,
// takes the reader away, a shrink, and one with no opt-in standing is refused.
func TestAclAuditOptInAndOutAreKOfN(t *testing.T) {
	world := newAclAuditWorld(t)
	world.standOptIn(t)
	state := world.world.state(t)
	optIn := world.optIn()
	if _, err := state.CheckStatement(world.statement(bridge.SignedType_SIGNED_AUDIT_OPT_IN, optIn, false), nil); !errors.Is(err, ErrConfigAuthority) {
		t.Errorf("one signer's opt-in: %v", err)
	}
	ended := proto.Clone(optIn).(*protocol.AuditOptIn)
	ended.NotAfter = aclTestNow.UnixMilli()
	if _, err := state.CheckStatement(world.statement(bridge.SignedType_SIGNED_AUDIT_OPT_IN, ended, true), nil); !errors.Is(err, ErrConfigRule) {
		t.Errorf("an opt-in that has ended: %v", err)
	}
	if _, err := state.CheckStatement(world.statement(bridge.SignedType_SIGNED_AUDIT_OPT_IN, &protocol.AuditOptIn{NotAfter: world.notAfter.UnixMilli()}, true), nil); !errors.Is(err, ErrConfigRule) {
		t.Errorf("an opt-in naming no reader: %v", err)
	}
	renewal := world.statement(bridge.SignedType_SIGNED_AUDIT_OPT_IN, optIn, true)
	verdict, err := state.CheckStatement(renewal, nil)
	if err != nil {
		t.Fatalf("k of n's opt-in: %v", err)
	}
	rows, _, err := state.ApplyStatement(renewal, verdict)
	if err != nil || len(rows.GetAudit().GetAuditOptIn()) == 0 || !slices.Equal(rows.GetAudit().GetRepoKinds(), state.Rows().GetAudit().GetRepoKinds()) {
		t.Fatalf("the opt-in's fold: %v %v", rows.GetAudit(), err)
	}

	optOut := world.statement(bridge.SignedType_SIGNED_AUDIT_OPT_OUT, &protocol.AuditOptOut{}, true)
	if _, err := state.CheckStatement(world.statement(bridge.SignedType_SIGNED_AUDIT_OPT_OUT, &protocol.AuditOptOut{}, false), nil); !errors.Is(err, ErrConfigAuthority) {
		t.Errorf("one signer's opt-out: %v", err)
	}
	verdict, err = state.CheckStatement(optOut, nil)
	if err != nil {
		t.Fatalf("k of n's opt-out: %v", err)
	}
	rows, _, err = state.ApplyStatement(optOut, verdict)
	if err != nil || rows.GetAudit() != nil {
		t.Fatalf("the opt-out's fold: %v %v", rows.GetAudit(), err)
	}
	shrunk, err := NewAclState(rows, world.world.view())
	if err != nil {
		t.Fatal(err)
	}
	if readers := shrunk.AuditReaders(world.vault, aclTestNow); len(readers) != 0 || slices.Contains(shrunk.RepoReaders(world.vault, aclTestNow), world.auditor) {
		t.Errorf("readers after the opt-out: %v", readers)
	}
	if _, err := shrunk.CheckStatement(optOut, nil); !errors.Is(err, ErrConfigRule) {
		t.Errorf("an opt-out with none standing: %v", err)
	}
}

// The audit block is the only reader an admin adds to an owner-bound repo: an admin's EvsShare of the owner's vault is
// still refused under a standing opt-in.
func TestAclAuditLeavesAdminSharesRefused(t *testing.T) {
	world := newAclAuditWorld(t)
	world.standOptIn(t)
	state := world.world.state(t)
	share := &AclStatement{
		Type:    bridge.SignedType_SIGNED_EVS_SHARE,
		Body:    &protocol.EvsShare{RepoId: world.vault.Bytes(), Subject: world.auditor.Bytes()},
		Signers: []ConfigSigner{{Kind: ConfigSignerSidecar, SidecarId: world.adminDevice}},
		N:       world.world.position + 100,
		TimeMs:  aclTestNow.UnixMilli(),
	}
	if _, err := state.CheckStatement(share, nil); !errors.Is(err, ErrConfigAuthority) {
		t.Errorf("an admin's EvsShare of the owner's vault: %v", err)
	}
}
