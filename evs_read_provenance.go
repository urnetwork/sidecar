//go:build !ios_extension

// A version's push provenance as ReadHead, ReadVersion and History give it (§11.6's Records, §16.6's taint row;
// QD-042, QD-851; plan-MCP-format1-tainted-files, mcp-m3-16-format1-tainted-bit-owner): the writing run's tainted bit,
// the agent the push names and how that reads, and whether a signed EvsImport brought the version in.
//
//	fetch    a path read carries its version's statement and entry, never the push's sealed metadata, so the push's
//	         record is read by its push id and version (evs_push_record.go) and checked against the statement the
//	         read verified: one more round for a one-part push. Within one read each push is read once
//	         (evsProvenanceReads), so a History whose versions share a push reads it once. Nothing evs stores or is
//	         asked changes: the request is the one export and replay send (I-18)
//	open     the sealed metadata under manifest_g of the push's generation; one that does not open is tampering,
//	         alarmed, and fails the read
//	check    EvsCheckPushProvenance under the signer's identity key at the statement's own pin (evs_provenance.go): a
//	         subkey signature that does not hold is alarmed and reads unattributed with Refused set, its tainted bit
//	         and import label still said
//	unknown  nil, where evs serves no record of the push any more (ErrEvsObjectMissing), or the sealed metadata
//	         holds no provenance at all, a push from before the field: a caller reads nil as unknown, never as an
//	         untainted run's word, so §16's tools read such a version untrusted
//
// Only a read that asks pays the round (EvsReadArgs.Provenance): Lookup's walk, WriteAtTip's check and the planner
// read without it.
//
// On every leg but the ios_extension legs, whose reads give no provenance (evs_read.go's seam). Safe for concurrent
// use.

package sidecar

import (
	"context"
	"errors"

	"github.com/urnetwork/sidecar/protocol"
)

// Registers the provenance reader a read's EvsFileInfo.Provenance comes from (evs_read.go's seam).
func init() {
	evsProvenanceRead = func(ctx context.Context, repo *EvsRepo, result *evsReadResult, verified *EvsVerifiedPath) (*EvsPushProvenance, error) {
		commitVersion := verified.CommitVersion
		if verified.Removal != nil {
			commitVersion = verified.Removal.GetRemovalVersion()
		}
		reads := newEvsProvenanceReads(repo, result.refId, result.head, result.keys)
		return reads.of(ctx, &EvsVerifiedStatement{Version: commitVersion, Statement: verified.Statement})
	}
}

// One read's provenance reads: each push read once, on the head and with the keys the read verified.
type evsProvenanceReads struct {
	repo  *EvsRepo
	refId Id
	head  *EvsVerifiedHead
	keys  *evsReadKeys
	// each push's answer by its id, a nil one among them
	pushIdReads map[Id]*EvsPushProvenance
}

// The provenance reads of one read of refId at head.
func newEvsProvenanceReads(repo *EvsRepo, refId Id, head *EvsVerifiedHead, keys *evsReadKeys) *evsProvenanceReads {
	return &evsProvenanceReads{repo: repo, refId: refId, head: head, keys: keys, pushIdReads: map[Id]*EvsPushProvenance{}}
}

// The provenance of the push a verified statement is: see the file header. Nil with no error is unknown.
func (self *evsProvenanceReads) of(ctx context.Context, statement *EvsVerifiedStatement) (*EvsPushProvenance, error) {
	pushId, err := IdFromBytes(statement.Statement.Push.GetPushId())
	if err != nil {
		return nil, err
	}
	if read, ok := self.pushIdReads[pushId]; ok {
		return read, nil
	}
	read, err := self.read(ctx, statement)
	if err != nil {
		return nil, err
	}
	self.pushIdReads[pushId] = read
	return read, nil
}

// One push's record read, opened and checked.
func (self *evsProvenanceReads) read(ctx context.Context, statement *EvsVerifiedStatement) (*EvsPushProvenance, error) {
	payload, err := self.repo.pushContent(ctx, self.head, statement)
	if errors.Is(err, ErrEvsObjectMissing) {
		// evs keeps no record of the push to serve: unknown
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	manifest, err := self.keys.manifest(ctx, statement.Statement.Push.GetGeneration())
	if err != nil {
		return nil, err
	}
	metadata, err := EvsOpenMetadata(manifest, payload.SealedMetadata)
	if err != nil {
		self.repo.client.alarm(self.repo.repoId, self.refId, SidecarEvsAlarmTamper, "", evsSignerOf(statement.Statement.Bytes))
		return nil, err
	}
	return self.repo.client.versionProvenance(self.repo.repoId, self.refId, statement.Statement, metadata)
}

// A version's provenance from its push's opened sealed metadata: nil where the push sealed none, else
// checkPushProvenance's answer.
func (self *EvsClient) versionProvenance(repoId Id, refId Id, statement *EvsStatement, metadata *protocol.EvsSealedMetadata) (*EvsPushProvenance, error) {
	if metadata.GetProvenance() == nil {
		// a push from before the field says nothing of its run: unknown, never an untainted run's word
		return nil, nil
	}
	return self.checkPushProvenance(repoId, refId, statement, metadata)
}
