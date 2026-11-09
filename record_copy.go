// RECORD.md section 4.2's copies row and section 6.4's CopyBody, on every leg (RECORD-M6-01): what an author keeps of
// each entry its sidecar deposits to the team record, so a team-record erasure, which destroys T's key, does not reach
// the author's own account of it (section 8; §16.8's "authors keep copies").
//
//	copy      one entry of kind copy in the author's vault, sealed under its own key like any entry, whose body is a
//	          CopyBody of Openings: T's entry's header, its whole Signed as stored, with the salt and body that open
//	          its body_commitment; the requester's record of a directory decision is the same form
//	          (plan-RECORD-small-readings #6), and its writer fills it from the decision entries it read
//	caps      at most 64 Openings (section 6.4); an Opening's salt is 32 bytes, or empty with an empty body, the header
//	          alone
//	verify    VerifyRecordOpening holds an Opening to its header: the Signed parses as a record header, and the salt
//	          and body recompute its commitment; the header's signature is a reader's to check against its writer's
//	          key at the header's pin, as for any entry (RECORD.md section 5.5)
//
// A copy names T's entry and opens it, so it never leaves the vault for T, and no projection or erasure of T touches it.
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One entry as a copy holds it: its header as stored, and the salt and body that open it.
type RecordOpened struct {
	// The header's Signed as stored.
	SignedBytes []byte
	Header      *StoredRecordHeader
	Salt        []byte
	Body        []byte
}

// A CopyBody of the entries given, each its sealed entry's Signed with the salt and body it was sealed with.
func NewRecordCopyBody(entries []*RecordOpened) (*protocol.CopyBody, error) {
	if len(entries) == 0 || recordCopyEntryCount < len(entries) {
		return nil, fmt.Errorf("%w: a copy of %d entries", ErrRecordBodyOverCap, len(entries))
	}
	body := &protocol.CopyBody{}
	for _, entry := range entries {
		opening := &protocol.Opening{Header: bytes.Clone(entry.SignedBytes), Salt: bytes.Clone(entry.Salt), Body: bytes.Clone(entry.Body)}
		if _, err := VerifyRecordOpening(opening); err != nil {
			return nil, err
		}
		body.Entries = append(body.Entries, opening)
	}
	return body, nil
}

// The entry an Opening holds: its header parsed from the Signed as stored, and, unless the Opening holds the header
// alone, its salt and body recomputing the header's body_commitment. ErrRecordBodyInvalid otherwise.
func VerifyRecordOpening(opening *protocol.Opening) (*RecordOpened, error) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(opening.GetHeader(), signed); err != nil || signed.GetType() != uint32(bridge.SignedType_SIGNED_RECORD_HEADER) {
		return nil, fmt.Errorf("%w: an opening's header is no record header's Signed", ErrRecordBodyInvalid)
	}
	header, err := ParseStoredRecordHeader(signed.GetBody())
	if err != nil {
		return nil, fmt.Errorf("%w: an opening's header: %v", ErrRecordBodyInvalid, err)
	}
	opened := &RecordOpened{SignedBytes: bytes.Clone(opening.GetHeader()), Header: header}
	if len(opening.GetSalt()) == 0 && len(opening.GetBody()) == 0 {
		return opened, nil
	}
	if len(opening.GetSalt()) != recordHashByteCount {
		return nil, fmt.Errorf("%w: an opening's salt of %d bytes", ErrRecordBodyInvalid, len(opening.GetSalt()))
	}
	commitment, err := RecordBodyCommitment(opening.GetSalt(), opening.GetBody())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecordBodyInvalid, err)
	}
	if !bytes.Equal(commitment[:], header.Header.GetBodyCommitment()) {
		return nil, fmt.Errorf("%w: an opening's body does not open its header's commitment", ErrRecordBodyInvalid)
	}
	opened.Salt = bytes.Clone(opening.GetSalt())
	opened.Body = bytes.Clone(opening.GetBody())
	return opened, nil
}
