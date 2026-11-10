// §8.5's kind defaults, which compile ahead of every document and which no document narrows (D-ACL-13,
// plan-ACL-small-readings #2). The binary holds them: AclState evaluates each kind's own rows from AclRepo and the
// state (acl_evs.go), so an admission between bases reads at once and a head never moves them
// (acl-m2-02-state-readings #3). This table says, kind by kind, what that evaluation gives and what a document may add,
// and acl_kind_test.go holds EvsAccess to it.
//
// One part of the table needs the head: the tag:mail mail indexers' read of mailcfg and deposit to vault and mailbox
// (owner decision 150), since only the head's tags file holds tag:mail's atom. CompileAcl writes that part as two
// rules over the repos the log's rows hold, with fixed ids (aclKindRuleId), whenever the tags file holds mail.
//
// On every leg, the sidecar_http page Worker's included: root Id, no connect type.

package sidecar

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/urnetwork/sidecar/protocol"
)

// Who a kind default names, as §8.5's table writes it.
type AclKindAudience int

const (
	// nobody
	AclKindAudienceNone AclKindAudience = iota
	// every admitted sidecar, ephemeral ones included (owner decision 6)
	AclKindAudienceAdmitted
	// every admitted sidecar that is not read_only
	AclKindAudienceNotReadOnly
	// config writers, member devices that are not read_only (§8.8)
	AclKindAudienceConfigWriters
	// the owner member's consented devices (§8.5, owner decision 126)
	AclKindAudienceOwnerConsented
	// autogroup:admin and autogroup:auditor
	AclKindAudienceAdminsAuditors
	// autogroup:member and tagged subjects
	AclKindAudienceMembersTagged
	// member devices, or a Team scope's member's consented devices where its row names an owner (§15.8)
	AclKindAudienceMemberDevices
	// readers that do not write: the receipt deposit (§16.8); in vault and mailbox also the owner's other untagged
	// subjects and the tagged subjects it sponsors
	AclKindAudienceReceiptsAndOwner
	// readers that do not write: the receipt deposit (§16.8)
	AclKindAudienceReceipts
)

// One kind's row of §8.5's table and the rules around it.
type AclKindDefault struct {
	Kind protocol.RepoKind
	// Who reads and who writes by the kind alone, and who deposits.
	Read    AclKindAudience
	Write   AclKindAudience
	Deposit AclKindAudience
	// Whether * and evs:* reach it: general and record only (§8.4).
	Wildcard bool
	// What a rule naming a repo of the kind outright may add: everything for general and record, readers too for
	// team_record and mailcfg, deposit alone for vault and mailbox, nothing for config, directory and secret.
	DocumentRights AclEvsRights
	// Whether only its owner's consent adds a reader (§8.5).
	OwnerBound bool
	// What the tag:mail mail indexers hold by the kind (owner decision 150), which compiles as a rule.
	MailIndexers AclEvsRights
}

// §8.5's table, a fresh copy, in RepoKind order. A kind not here grants nothing.
func AclKindDefaults() []AclKindDefault {
	everything := AclEvsDeposit | AclEvsRead | AclEvsWrite | AclEvsAdmin
	return []AclKindDefault{
		{
			Kind:           protocol.RepoKind_REPO_KIND_GENERAL,
			Wildcard:       true,
			DocumentRights: everything,
		},
		{
			Kind:           protocol.RepoKind_REPO_KIND_RECORD,
			Wildcard:       true,
			DocumentRights: everything,
		},
		{
			Kind:  protocol.RepoKind_REPO_KIND_CONFIG,
			Read:  AclKindAudienceAdmitted,
			Write: AclKindAudienceConfigWriters,
		},
		{
			Kind:  protocol.RepoKind_REPO_KIND_DIRECTORY,
			Read:  AclKindAudienceAdmitted,
			Write: AclKindAudienceNotReadOnly,
		},
		{
			Kind:           protocol.RepoKind_REPO_KIND_TEAM_RECORD,
			Read:           AclKindAudienceAdminsAuditors,
			Deposit:        AclKindAudienceMembersTagged,
			DocumentRights: everything,
		},
		{
			Kind:           protocol.RepoKind_REPO_KIND_MAILCFG,
			Write:          AclKindAudienceMemberDevices,
			DocumentRights: everything,
			MailIndexers:   AclEvsRead,
		},
		{
			Kind:           protocol.RepoKind_REPO_KIND_VAULT,
			Read:           AclKindAudienceOwnerConsented,
			Write:          AclKindAudienceOwnerConsented,
			Deposit:        AclKindAudienceReceiptsAndOwner,
			DocumentRights: AclEvsDeposit,
			OwnerBound:     true,
			MailIndexers:   AclEvsDeposit,
		},
		{
			Kind:           protocol.RepoKind_REPO_KIND_MAILBOX,
			Read:           AclKindAudienceOwnerConsented,
			Write:          AclKindAudienceOwnerConsented,
			Deposit:        AclKindAudienceReceiptsAndOwner,
			DocumentRights: AclEvsDeposit,
			OwnerBound:     true,
			MailIndexers:   AclEvsDeposit,
		},
		{
			Kind:       protocol.RepoKind_REPO_KIND_SECRET,
			Read:       AclKindAudienceOwnerConsented,
			Write:      AclKindAudienceOwnerConsented,
			Deposit:    AclKindAudienceReceipts,
			OwnerBound: true,
		},
	}
}

// One kind's row, false for a kind the table does not hold.
func aclKindDefault(kind protocol.RepoKind) (AclKindDefault, bool) {
	for _, row := range AclKindDefaults() {
		if row.Kind == kind {
			return row, true
		}
	}
	return AclKindDefault{}, false
}

// The tag a kind default's mail indexers carry, as a policy and the tags file name it (owner decision 150).
const aclMailIndexerTag = "mail"

// A kind default rule's id: the first 16 bytes of SHA-256("urnetwork-sidecar-v1/acl-kind-rule" || 0x00 ||
// u32be(index)), with no table, as an implicit-document rule's is (plan-ACL-atom-and-rule-ids #3). Index 0 is the mail
// indexers' read, 1 their deposit.
func aclKindRuleId(index uint32) Id {
	return aclConstantRuleId("urnetwork-sidecar-v1/acl-kind-rule", index)
}

// A rule id fixed by its domain and index, with no table.
func aclConstantRuleId(domain string, index uint32) Id {
	hash := sha256.New()
	hash.Write([]byte(domain))
	hash.Write([]byte{0})
	hash.Write(binary.BigEndian.AppendUint32(nil, index))
	var digest [sha256.Size]byte
	hash.Sum(digest[:0])
	return Id(digest[:aclAtomByteCount])
}
