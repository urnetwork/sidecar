// A write over a version whose key a committed ERASE destroyed (§11.7's checkpoint rule (3), §11.12's after row): the
// planner reads a standing file's newest version as the base its next version diffs against, and a version an ERASE
// emptied reads as erased (ErrEvsErased, judged on the ERASEs read after its slot, evs_read_erased.go), its content
// gone for good. Nothing of it is left to diff against, so the next version is a checkpoint, the file new to this
// push (EvsCheckpointNewFile: its previous version stands for nothing this push can diff against), under a fresh key
// in a new slot, never the destroyed key a versionless path would otherwise reuse. The write keeps the file's id and
// mode from the erased version's sealed fields, which the manifest key opens and no ERASE touches, and its
// base_entry_version and prev_push_id stay the erased version's, so evs's path CAS holds it to the head it read.
//
// An older version whose key still stands is not taken as the base: in a slot-keyed repo a chain's versions share
// their chain's key, so an ERASE of the newest's takes them all, and a checkpoint is always a version every reader
// opens. A git-mode ref's rekey over an erased blob is refused as before, its blob gone with the key. A key gone that no ERASE names is evs withholding it, which alarms
// tamper and refuses the write as any read refuses it.
//
// On every leg; the forwarding role's legs register no judge, so there no read answers ErrEvsErased.

package sidecar

import (
	"context"

	"github.com/urnetwork/sidecar/protocol"
)

// The sealed fields of verified, a standing version whose key a committed ERASE destroyed: what a checkpoint over it
// keeps (see the file header). Fields that do not open alarm tamper, as reconstruction's do.
func (self *EvsRepo) erasedBaseFields(ctx context.Context, result *evsReadResult, verified *EvsVerifiedPath) (*protocol.EvsSealedFields, error) {
	manifest, err := result.keys.manifest(ctx, verified.Statement.Push.GetGeneration())
	if err != nil {
		return nil, err
	}
	entry := verified.Entry
	var fields *protocol.EvsSealedFields
	if entry.GetVersioning() == 0 {
		fields, err = EvsOpenFields(manifest, entry.GetSealedFields())
	} else {
		fields, err = EvsOpenFieldsFormat2(manifest, entry.GetSealedFields(), entry.GetVersioning())
	}
	if err != nil {
		self.client.alarm(self.repoId, result.refId, SidecarEvsAlarmTamper, "", nil)
		return nil, err
	}
	return fields, nil
}
