// Owner decision 63's visible audit member (ACL-M6-02; R-ACL-11, D-ACL-13, I-4, FS-30): a Team's document may name one
// audit reader, a tag, and the repo kinds and repos it reads, in its audit block (§8.5's example 6). The block counts
// only while a k-of-n AuditOptIn stands:
//
//	opt in    AuditOptIn{reader atoms, not_after}, a k-of-n authority statement, an AuthorityProposal completed by
//	          its cosigns under §7.9's authority rows and never one signer's; the fold keeps its record in
//	          AclRows.audit.audit_opt_in, so api and every reader hold the record the rows came from
//	opt out   AuditOptOut, k of n as well: the record leaves the rows at its position, a shrink, so the next generation
//	          of each affected repo wraps to no audit reader (§10.8)
//	compile   CompileAcl writes AclAudit from the head's block and the record its log's rows hold: the block's reader
//	          atom where the record names it, its kinds and repos, and the record itself; with no record standing, or
//	          one past its not_after at the head's time, a block names no reader, and validation refuses it
//	readers   AuditReaders: the sidecars the block makes readers of a repo, which members see in each affected reader
//	          list before the reader gets a key (§10.8's check, KEYS'), whose wrap waits until every member's config
//	          holds the block; it reads owner-bound repos under read receipts (ACL-M3-01), as it writes none
//	expiry    past not_after the reader drops as an expiry (§7.9), at each check's own time (acl_evs.go)
//
// Between bases a fold keeps the rows' kinds and repos, so an opt-in that lands after a base names nothing until the
// next base compiles its block: the reader never gets ahead of what every member's config holds. It is the only reader
// an admin may add to an owner-bound repo, and only for the kinds or repos the block names (owner decision 126).
//
// On every leg, the sidecar_http page Worker's included: root Id, no connect type. Nothing here creates, derives or
// unwraps a key.

package sidecar

import (
	"bytes"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// §8.8's rule for an AuditOptIn: k of n, a reader atom of an id's form, and a not_after after the statement's time.
func (self *AclState) checkAuditOptIn(statement *AclStatement, optIn *protocol.AuditOptIn) (*AclStatementVerdict, error) {
	if !statement.Authority {
		return nil, fmt.Errorf("%w: an AuditOptIn takes k of n signers, never one", ErrConfigAuthority)
	}
	if len(optIn.GetReaderAtoms()) == 0 {
		return nil, fmt.Errorf("%w: an AuditOptIn names no reader", ErrConfigRule)
	}
	for i, readerBytes := range optIn.GetReaderAtoms() {
		reader, err := IdFromBytes(readerBytes)
		if err != nil || aclAtomHasAutogroupForm(reader) {
			return nil, fmt.Errorf("%w: reader_atoms[%d] is no tag's atom", ErrConfigRule, i)
		}
	}
	if optIn.GetNotAfter() <= statement.TimeMs {
		return nil, fmt.Errorf("%w: an AuditOptIn that has ended", ErrConfigRule)
	}
	return &AclStatementVerdict{Signer: statement.Signers[0].SidecarId}, nil
}

// §8.8's rule for an AuditOptOut: k of n, and an opt-in standing to end.
func (self *AclState) checkAuditOptOut(statement *AclStatement) (*AclStatementVerdict, error) {
	if !statement.Authority {
		return nil, fmt.Errorf("%w: an AuditOptOut takes k of n signers, never one", ErrConfigAuthority)
	}
	if len(self.rows.GetAudit().GetAuditOptIn()) == 0 {
		return nil, fmt.Errorf("%w: no AuditOptIn stands", ErrConfigRule)
	}
	return &AclStatementVerdict{Signer: statement.Signers[0].SidecarId}, nil
}

// An AuditOptIn's fold: its record and reader atoms in the rows' audit, the rows' kinds and repos kept, so the block's
// reach waits for the next base's compile.
func aclFoldAuditOptIn(rows *protocol.AclRows, optIn *protocol.AuditOptIn) (*protocol.AclRows, error) {
	record, err := proto.MarshalOptions{Deterministic: true}.Marshal(optIn)
	if err != nil {
		return nil, err
	}
	audit := &protocol.AclAudit{
		ReaderAtoms: aclSortBytesList(optIn.GetReaderAtoms()),
		AuditOptIn:  record,
	}
	if previous := rows.GetAudit(); previous != nil {
		audit.RepoKinds = slices.Clone(previous.GetRepoKinds())
		audit.RepoIds = aclSortBytesList(previous.GetRepoIds())
		// the block's reader stays only where the new record names it
		audit.ReaderAtoms = slices.DeleteFunc(slices.Clone(previous.GetReaderAtoms()), func(reader []byte) bool {
			return !slices.ContainsFunc(optIn.GetReaderAtoms(), func(named []byte) bool { return bytes.Equal(named, reader) })
		})
		if len(previous.GetReaderAtoms()) == 0 {
			audit.ReaderAtoms = aclSortBytesList(optIn.GetReaderAtoms())
		}
	}
	next := aclRowsCopy(rows)
	next.Audit = audit
	return next, nil
}

// An AuditOptOut's fold: the audit leaves the rows.
func aclFoldAuditOptOut(rows *protocol.AclRows) *protocol.AclRows {
	next := aclRowsCopy(rows)
	next.Audit = nil
	return next
}

// The audit block compile writes (§8.5, owner decision 63): with a record standing at the head's time, the record, and
// with the document's block, the block's reader atom where the record names it, its kinds and its repos; nil with no
// record standing, so a block alone names no reader.
func (self *aclCompiler) compileAudit() (*protocol.AclAudit, error) {
	record := self.input.Statements.GetAudit().GetAuditOptIn()
	if len(record) == 0 {
		return nil, nil
	}
	optIn := &protocol.AuditOptIn{}
	if err := proto.Unmarshal(record, optIn); err != nil {
		return nil, aclCompileRefusal("the log's AuditOptIn record does not parse")
	}
	if optIn.GetNotAfter() <= self.input.HeadTimeMs {
		// the reader dropped at its not_after, an expiry (§7.9)
		return nil, nil
	}
	audit := &protocol.AclAudit{AuditOptIn: bytes.Clone(record)}
	block := self.policy.Audit
	if block == nil {
		return audit, nil
	}
	reader, err := self.atom(block.Reader)
	if err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(optIn.GetReaderAtoms(), func(named []byte) bool { return bytes.Equal(named, reader.Bytes()) }) {
		// the record consented to another reader than the block names
		return audit, nil
	}
	audit.ReaderAtoms = [][]byte{reader.Bytes()}
	for _, kind := range block.RepoKinds {
		audit.RepoKinds = append(audit.RepoKinds, uint32(kind))
	}
	slices.Sort(audit.RepoKinds)
	audit.RepoKinds = slices.Compact(audit.RepoKinds)
	for _, repo := range block.Repos {
		targets, err := self.repoTargets(repo)
		if err != nil {
			return nil, err
		}
		for _, target := range targets {
			audit.RepoIds = append(audit.RepoIds, bytes.Clone(target.GetRepoId()))
		}
	}
	audit.RepoIds = aclSortBytesList(audit.RepoIds)
	return audit, nil
}

// An AuditOptIn record's not_after, read in place so a check allocates nothing: 0 for a record with none, false for
// bytes that are no AuditOptIn this build reads, which every check takes as no opt-in.
func aclAuditNotAfter(record []byte) (int64, bool) {
	notAfter := int64(0)
	for 0 < len(record) {
		number, wireType, n := protowire.ConsumeTag(record)
		if n < 0 {
			return 0, false
		}
		record = record[n:]
		if number == 3 && wireType == protowire.VarintType {
			value, n := protowire.ConsumeVarint(record)
			if n < 0 {
				return 0, false
			}
			notAfter = int64(value)
			record = record[n:]
			continue
		}
		n = protowire.ConsumeFieldValue(number, wireType, record)
		if n < 0 {
			return 0, false
		}
		record = record[n:]
	}
	return notAfter, true
}

// Whether the rows' audit stands at nowMs: a record whose not_after is still ahead.
func (self *AclState) auditStands(nowMs int64) bool {
	notAfter, ok := aclAuditNotAfter(self.rows.GetAudit().GetAuditOptIn())
	return ok && nowMs < notAfter
}

// The sidecars the audit block makes readers of a repo at now, sorted: what §10.8's reader-list check shows every
// member before the reader gets a key, and none once the opt-in ends or past its not_after.
func (self *AclState) AuditReaders(repoId Id, now time.Time) []Id {
	nowMs := now.UnixMilli()
	readers := []Id{}
	repo := self.repos[repoId]
	if repo == nil || repo.deleted || !self.auditStands(nowMs) {
		return readers
	}
	for i := range self.sidecars {
		sidecar := &self.sidecars[i]
		if sidecar.hardDeny(nowMs) != 0 {
			continue
		}
		accumulator := aclEvsAccumulator{}
		self.addAuditRights(&accumulator, sidecar, repoId, repo, nowMs)
		if accumulator.rights.Has(AclEvsRead) {
			readers = append(readers, sidecar.id)
		}
	}
	return readers
}
