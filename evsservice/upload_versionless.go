// Versionless uploads (§11.13's receipt row, §11.7's kind 5 row; D-EVS-36, R-EVS-20, FS-64; EVS2-M10-06), at EVSB-M2-09's
// seam in the segment route: at a format-2 instance a segment whose public header is format 2's 48 B kind-5 header
// is read through its push_id, and:
//
//	push     a header naming another push than ?push= gets 409 VERSIONING, so equal bytes are only ever the same
//	         push's retry and no push adopts another's segment as its own upload
//	gate     a network outside §19.11's format2 gate gets 409 VERSIONING, as 5c answers its push
//	mark     the receipt is marked versionless, the mark inside its MAC; an equal re-upload carries an equal header,
//	         so it takes the same mark with no extra read
//
// A format-1 instance refuses a kind-5 header FORMAT_UNSUPPORTED {needs_format: 2}, as before. Nothing here reads or
// writes the metadata cluster.
//
// Package-level functions are safe for concurrent use.

package evsservice

import (
	"errors"
	"io"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The rest of a kind-5 header past format 1's 32 B: its 16 B push_id (EVS-FORMAT.md's kind-5 segments).
const evsKind5HeaderTailByteCount = 16

// A kind-5 header's tail, read from body after its first 32 B (header), held with them to the root's kind-5 upload
// check (sidecar.EvsCheckSegmentUploadFormat2: this repo, a generation, a Padmé size of at most 8 MiB, and the
// upload's push) and to the format2 gate: the tail's bytes, which the stored segment carries after the header, or the
// refusal to answer.
func (self *EvsEngine) readUploadKind5Header(body io.Reader, header []byte, byteCount int64, repoId sidecar.Id, pushId sidecar.Id, networkId sidecar.Id) ([]byte, *protocol.EvsRefusalReply) {
	tail := make([]byte, evsKind5HeaderTailByteCount)
	if _, err := io.ReadFull(body, tail); err != nil {
		return nil, &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_INVALID}
	}
	_, versionless, err := sidecar.EvsCheckSegmentUploadFormat2(append(append([]byte{}, header...), tail...), uint64(byteCount), repoId, pushId)
	switch {
	case errors.Is(err, sidecar.ErrEvsVersioning):
		// another push's segment: never this push's upload
		return nil, &protocol.EvsRefusalReply{PushId: pushId.Bytes(), Code: protocol.EvsRefusalCode_EVS_REFUSAL_VERSIONING}
	case err != nil || !versionless:
		return nil, &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_INVALID}
	}
	if !self.format2.Admits(networkId) {
		return nil, &protocol.EvsRefusalReply{PushId: pushId.Bytes(), Code: protocol.EvsRefusalCode_EVS_REFUSAL_VERSIONING}
	}
	return tail, nil
}
