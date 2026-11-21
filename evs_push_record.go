// A push's record as a replaying reader takes it (§11.8's replay row, §11.6's checks row; QD-806, QD-818): the record
// of one verified statement, read by its push id and version and checked against that statement, a one-part push's
// payload or a sealed push's parts, and the key a replayed tree names a path by. Export, history, provenance, the
// local tier's sync and the config head reader all read a push through these, so they stand apart from the git export
// machinery (evs_export.go, evs_export_file.go), which only a desktop host runs.
//
// On every leg, the ios_extension leg included: a VPN component's config head reader replays the config repo's main
// ref through them (QD-839; DESIGN-DETAILS 4.2.3, 4.2.5's Compile, step 3). Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/urnetwork/sidecar/protocol"
)

// A replayed tree's key for a path: its names joined with a NUL, which no name holds.
func evsExportKey(names [][]byte) string {
	return string(bytes.Join(names, []byte{0}))
}

// Whether names is prefix or a path below it.
func evsNamesHavePrefix(names [][]byte, prefix [][]byte) bool {
	if len(names) < len(prefix) {
		return false
	}
	for i, name := range prefix {
		if !bytes.Equal(names[i], name) {
			return false
		}
	}
	return true
}

// The push record of one verified statement, read by its push id and version, its statement equal to the one
// verified and its payload checked against it (§11.6's checks row): a one-part push's payload, or a sealed push's
// parts, read in rounds and checked whole as its stored seal is.
func (self *EvsRepo) pushContent(ctx context.Context, head *EvsVerifiedHead, statement *EvsVerifiedStatement) (*EvsCheckedPayload, error) {
	push := statement.Statement.Push
	if push.GetPartCount() == 0 {
		return self.pushPayload(ctx, head, statement)
	}
	parts := make([][]byte, push.GetPartCount())
	// a count the settings leave non-positive reads a part a round
	partCount := uint64(push.GetPartCount())
	readCount := min(uint64(max(1, self.client.settings.PushPartReadCount)), partCount)
	for start := uint64(1); start <= partCount; start += readCount {
		request := &protocol.EvsReadRequest{RefId: head.RefId.Bytes(), PinVersion: head.Version}
		for part := start; part <= min(partCount, start+readCount-1); part += 1 {
			request.Pushes = append(request.Pushes, &protocol.EvsReadPush{PushId: push.GetPushId(), Version: statement.Version, Part: uint32(part)})
		}
		if err := func() error {
			_, objects, err := self.client.postRead(ctx, self.repoId, request)
			if err != nil {
				return err
			}
			defer objects.close()
			for key, spill := range objects.objects {
				if key.kind != protocol.EvsReadObjectKind_EVS_READ_OBJECT_BATCH_RECORD || key.number == 0 || uint64(push.GetPartCount()) < key.number {
					continue
				}
				recordBytes, err := io.ReadAll(spill.reader())
				if err != nil {
					return err
				}
				record, _, err := self.parseReadBatchRecord(recordBytes)
				if err != nil {
					return fmt.Errorf("%w: a part record that is not one part's", ErrEvsEntryRefused)
				}
				// a part record, or a re-seeded push's part, a reseed record holding a part's body (QD-818)
				statementBytes, partBytes, _, _, err := ParseEvsSealPartRecord(record)
				if err != nil {
					return fmt.Errorf("%w: a part record that is not one part's", ErrEvsEntryRefused)
				}
				if !bytes.Equal(statementBytes, statement.Statement.Bytes) {
					return fmt.Errorf("%w: a part record of another statement", ErrEvsEntryRefused)
				}
				parts[key.number-1] = partBytes
			}
			return nil
		}(); err != nil {
			return nil, err
		}
	}
	for part, partBytes := range parts {
		if partBytes == nil {
			return nil, fmt.Errorf("%w: part %d evs did not serve", ErrEvsObjectMissing, part+1)
		}
	}
	return self.checkReadSeal(statement.Statement, parts)
}

// A stored seal and its parts under the reader's admitted format. Their signed hashes cover the original parts.
func (self *EvsRepo) checkReadSeal(statement *EvsStatement, parts [][]byte) (*EvsCheckedPayload, error) {
	check := EvsCheckRecordSeal
	if self.client.format2Reader() != nil {
		check = EvsCheckStoredSeal
	}
	checked, _, err := check(statement, parts)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEvsEntryRefused, err)
	}
	return checked, nil
}

// A one-part push's record, read by its push id and version, its statement equal to the one verified and its payload
// checked against it.
func (self *EvsRepo) pushPayload(ctx context.Context, head *EvsVerifiedHead, statement *EvsVerifiedStatement) (*EvsCheckedPayload, error) {
	request := &protocol.EvsReadRequest{
		RefId:      head.RefId.Bytes(),
		PinVersion: head.Version,
		Pushes:     []*protocol.EvsReadPush{{PushId: statement.Statement.Push.GetPushId(), Version: statement.Version}},
	}
	_, objects, err := self.client.postRead(ctx, self.repoId, request)
	if err != nil {
		return nil, err
	}
	defer objects.close()
	var record []byte
	for key, spill := range objects.objects {
		if key.kind == protocol.EvsReadObjectKind_EVS_READ_OBJECT_BATCH_RECORD && key.number == 0 {
			record, err = io.ReadAll(spill.reader())
			if err != nil {
				return nil, err
			}
		}
	}
	if record == nil {
		return nil, fmt.Errorf("%w: a push record evs did not serve", ErrEvsObjectMissing)
	}
	batchRecord, tail, err := self.parseReadBatchRecord(record)
	if err != nil {
		return nil, fmt.Errorf("%w: a push record that does not parse", ErrEvsEntryRefused)
	}
	return self.checkReadPushPayload(statement.Statement, batchRecord, tail)
}

// Both record read modes use the admitted format and preserve the stored tail when present.
func (self *EvsRepo) parseReadBatchRecord(record []byte) (*EvsBatchRecord, *EvsBatchRecordTail, error) {
	if self.client.format2Reader() != nil {
		return ParseEvsBatchRecordFormat2(record)
	}
	parsed, err := ParseEvsBatchRecord(record)
	return parsed, nil, err
}

// A one-part push or reseed record bound to its verified statement, with any staged tail checked against
// its signed new objects. An evacuated record's tail can be absent.
func (self *EvsRepo) checkReadPushPayload(statement *EvsStatement, batchRecord *EvsBatchRecord, tail *EvsBatchRecordTail) (*EvsCheckedPayload, error) {
	if batchRecord.Type != protocol.EvsBatchRecordType_EVS_BATCH_PUSH && batchRecord.Type != protocol.EvsBatchRecordType_EVS_BATCH_RESEED {
		return nil, fmt.Errorf("%w: a push record that is not one push's", ErrEvsEntryRefused)
	}
	statementBytes, payload, err := ParseEvsPushRecordBody(batchRecord.Body)
	if err != nil || !bytes.Equal(statementBytes, statement.Bytes) {
		return nil, fmt.Errorf("%w: a push record of another statement", ErrEvsEntryRefused)
	}
	if self.client.format2Reader() == nil {
		// as evs keeps it, with no slot body: keys come from slot reads alone (QD-806)
		return EvsCheckRecordPayload(statement, payload)
	}
	checked, err := EvsCheckStoredPayload(statement, payload)
	if err != nil {
		return nil, err
	}
	if tail != nil && len(tail.Staged) != 0 {
		segments, err := tail.StagedSegments()
		if err != nil {
			return nil, err
		}
		if checked.Staged, err = evsMatchStaged(statement.Push, checked.NewObjects, segments); err != nil {
			return nil, err
		}
	}
	return checked, nil
}
