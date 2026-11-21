//go:build !ios_extension

// A file write whose verified base reads ErrEvsErased starts a checkpoint. Its signed file id, mode and base
// version still identify the file for the path CAS. The replacement has a fresh slot and key even on a versionless
// path. A git-mode rekey requires the original blob to preserve its oid.

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
