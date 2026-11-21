//go:build !ios_extension

// Enforces signed mail tombstones at the verified plaintext boundary. A body or
// raw index segment may still have a usable slot after a racing ingest or while
// a CLOSURE is waiting. A reader may only release content after checking the
// erasure ref against that version. An export does the same before writing a blob.

package sidecar

import (
	"context"
	"io"

	"github.com/urnetwork/sidecar/protocol"
)

// Checks only canonical mailbox message and segment paths on the main ref.
func (self *EvsRepo) checkMailRead(ctx context.Context, result *evsReadResult, verified *EvsVerifiedPath, content *evsSpill) error {
	path := result.exportPath
	if read := result.pathOf(verified); read != nil {
		path = read.path
	}
	_, id, body := parseMailMessagePath(path)
	_, _, segment := parseMailIndexPath(path)
	if !body && (!segment || result.mailSegment) {
		return nil
	}
	kind, err := self.repoKind()
	if err != nil {
		return err
	}
	if kind != protocol.RepoKind_REPO_KIND_MAILBOX && kind != protocol.RepoKind_REPO_KIND_GENERAL {
		return nil
	}
	main, err := self.resolveRefId(ctx, nil, nil)
	if err != nil || main != result.refId {
		return err
	}
	mask := newMailErasedView()
	if _, err := mask.refresh(ctx, self.ReadErasures); err != nil {
		return err
	}
	if body {
		if _, erased := mask.erased(id); erased {
			return ErrEvsErased
		}
		return nil
	}
	if !mask.hasMessages() {
		return nil
	}
	if content.Size() > int64(mailIndexSegmentReadMaxByteCount) {
		return ErrMailStoreTooLarge
	}
	data, err := io.ReadAll(content.reader())
	if err != nil {
		return err
	}
	return mailSegmentRecords(data, func(_ int, record []byte) error {
		id, _, ok := mailIndexRecordKey(record)
		if ok {
			if _, erased := mask.erased(id); erased {
				return ErrEvsErased
			}
		}
		return nil
	})
}
