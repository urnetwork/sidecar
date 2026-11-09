// §22.6's directory.proto decoders for M6's carriers, on every leg: an announce entry's Announcement, a request,
// decision and erasure request entry's body, and a notice under the cards ref. Each is total and memory-bounded: it
// refuses bytes past its bound before it parses them, so what a writer sends costs a reader at most a fixed multiple
// of that bound; it never panics; and it holds what it parsed to directory_fields.go's checks, so a version past its
// caps is refused rather than shown. Signatures and hashes cover the bytes as received, never a re-marshal: a request's
// approval is kept as its own bytes in the body, and a decision's ApprovalDecision is the Signed it carries, parsed in
// place (record_hash.go).
//
// A reader that is refused here ignores the version and alarms over_cap: the record reader does so for every entry
// (RecordBodyValidateStored, record_reader.go), and a notice's reader for each notice it reads (RECORD-M6-18).
// Cards and repo files, from format 2, are RECORD-M10-02's.
//
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The largest directory entry body a reader parses. An item rides its announce entry under the card rules, so a card's
// 16,208 B of items bounds one, and every request, decision and erasure request within its caps is smaller still. A
// format value, so every reader refuses alike.
const DirectoryEntryBodyMaxByteCount = DirectoryCardItemsByteCount

// DirectoryRequest.approval's field number, whose bytes a request's approval is parsed from as stored.
const directoryRequestApprovalField protowire.Number = 14

// A request entry's body as stored.
type StoredDirectoryRequest struct {
	Request *protocol.DirectoryRequest
	// As received, never re-encoded.
	Bytes []byte
	// Reach only: the approval's own bytes as they sit in Bytes, which an ApprovalDecision's request_sha256 covers.
	ApprovalBytes []byte
}

// The approval, parsed from its bytes as stored, for the approver who renders it and the requester who spends its
// decision: ParseStoredApprovalRequest's rules, a CanonicalAction version this build's approvers know among them, and
// kind access_request (16.11's endorse row). A reader that only lists the request never needs this, so an action
// version it does not know refuses the approval, never the request.
func (self *StoredDirectoryRequest) Approval() (*StoredApprovalRequest, error) {
	if len(self.ApprovalBytes) == 0 {
		return nil, directoryRefusal("a request with no approval")
	}
	approval, err := ParseStoredApprovalRequest(self.ApprovalBytes)
	if err != nil {
		return nil, err
	}
	if protocol.SidecarActionKind(approval.Action.Action.GetKind()) != protocol.SidecarActionKind_SIDECAR_ACTION_KIND_ACCESS_REQUEST {
		return nil, directoryRefusal("an approval of action kind %d", approval.Action.Action.GetKind())
	}
	return approval, nil
}

// A decision entry's body as stored.
type StoredDirectoryDecision struct {
	Decision *protocol.DirectoryDecision
	// As received, never re-encoded.
	Bytes []byte
	// An approved reach only: the Signed ApprovalDecision it carries, whose signature covers its body as received.
	ApprovalDecision *StoredApprovalDecision
}

// Refuses body past maxByteCount, before anything parses it.
func directoryBound(name string, body []byte, maxByteCount int) error {
	if maxByteCount < len(body) {
		return directoryRefusal("%s of %d bytes, past %d", name, len(body), maxByteCount)
	}
	return nil
}

// An announce entry's rule beside DirectoryCheckItem's (§16.11's M6 carrier row): the body within its bound, and a
// repo item's marshaled Announcement a whole number of 2,048 B steps, an announcement and a private marker alike
// (plan-RECORD-m6-carrier#2). byteCount is the marshaled size, which a reader takes as the canonical encoding's.
func directoryCheckAnnounceEntry(item *protocol.Announcement, byteCount int) error {
	if DirectoryEntryBodyMaxByteCount < byteCount {
		return directoryRefusal("an announce entry of %d bytes", byteCount)
	}
	if err := DirectoryCheckItem(item); err != nil {
		return err
	}
	if DirectoryAnnouncementKind(item.GetKind()) == DirectoryAnnouncementKindRepo &&
		(byteCount == 0 || byteCount%DirectoryRepoEntryStepByteCount != 0) {
		return directoryRefusal("a repo announce entry of %d bytes, off its 2,048 B steps", byteCount)
	}
	return nil
}

// An announce entry's body, the M6 carrier of every run, worker and repo item: within DirectoryEntryBodyMaxByteCount,
// parsing as an Announcement that passes DirectoryCheckItem, a repo item padded to its steps.
func DirectoryDecodeAnnouncement(body []byte) (*protocol.Announcement, error) {
	if err := directoryBound("an announce entry", body, DirectoryEntryBodyMaxByteCount); err != nil {
		return nil, err
	}
	item := &protocol.Announcement{}
	if err := proto.Unmarshal(body, item); err != nil {
		return nil, directoryRefusal("an announce entry that does not parse: %v", err)
	}
	if err := directoryCheckAnnounceEntry(item, proto.Size(item)); err != nil {
		return nil, err
	}
	return item, nil
}

// A request entry's body: within DirectoryEntryBodyMaxByteCount, parsing as a DirectoryRequest that passes
// DirectoryCheckRequest, and for reach, its approval's bytes kept as they sit in body, which must hold field 14
// exactly once, so what those bytes hash is the approval this request carries, with its payload_sha256 the SHA-256 of
// its action as stored. The rest of the approval's rules are StoredDirectoryRequest.Approval's.
func DirectoryDecodeRequest(body []byte) (*StoredDirectoryRequest, error) {
	if err := directoryBound("a request", body, DirectoryEntryBodyMaxByteCount); err != nil {
		return nil, err
	}
	request := &protocol.DirectoryRequest{}
	if err := proto.Unmarshal(body, request); err != nil {
		return nil, directoryRefusal("a request that does not parse: %v", err)
	}
	if err := DirectoryCheckRequest(request); err != nil {
		return nil, err
	}
	stored := &StoredDirectoryRequest{Request: request, Bytes: bytes.Clone(body)}
	approvalBytes, count, err := directoryFieldBytes(body, directoryRequestApprovalField)
	if err != nil {
		return nil, err
	}
	switch {
	case count == 0 && request.GetApproval() == nil:
		return stored, nil
	case count != 1:
		return nil, directoryRefusal("a request holding its approval %d times", count)
	}
	payloadSha256 := ApprovalPayloadSha256(request.GetApproval().GetCanonicalAction())
	if !bytes.Equal(request.GetApproval().GetPayloadSha256(), payloadSha256[:]) {
		return nil, directoryRefusal("an approval whose payload_sha256 is not its action's")
	}
	stored.ApprovalBytes = approvalBytes
	return stored, nil
}

// A decision entry's body: within DirectoryEntryBodyMaxByteCount, parsing as a DirectoryDecision that passes
// DirectoryCheckDecision, with an approved reach's Signed ApprovalDecision parsed from its bytes as received.
func DirectoryDecodeDecision(body []byte) (*StoredDirectoryDecision, error) {
	if err := directoryBound("a decision", body, DirectoryEntryBodyMaxByteCount); err != nil {
		return nil, err
	}
	decision := &protocol.DirectoryDecision{}
	if err := proto.Unmarshal(body, decision); err != nil {
		return nil, directoryRefusal("a decision that does not parse: %v", err)
	}
	approvalDecision, err := directoryCheckDecision(decision)
	if err != nil {
		return nil, err
	}
	return &StoredDirectoryDecision{Decision: decision, Bytes: bytes.Clone(body), ApprovalDecision: approvalDecision}, nil
}

// A notice's content under q/<h>/<tgt>/: within its 256 B, parsing as a DirectoryNotice that passes
// DirectoryCheckNotice.
func DirectoryDecodeNotice(content []byte) (*protocol.DirectoryNotice, error) {
	if err := directoryBound("a notice", content, DirectoryNoticeByteCount); err != nil {
		return nil, err
	}
	notice := &protocol.DirectoryNotice{}
	if err := proto.Unmarshal(content, notice); err != nil {
		return nil, directoryRefusal("a notice that does not parse: %v", err)
	}
	if err := DirectoryCheckNotice(notice); err != nil {
		return nil, err
	}
	return notice, nil
}

// An erasure request entry's body: within DirectoryEntryBodyMaxByteCount, parsing as a DirectoryErasureRequest that
// passes DirectoryCheckErasureRequest.
func DirectoryDecodeErasureRequest(body []byte) (*protocol.DirectoryErasureRequest, error) {
	if err := directoryBound("an erasure request", body, DirectoryEntryBodyMaxByteCount); err != nil {
		return nil, err
	}
	request := &protocol.DirectoryErasureRequest{}
	if err := proto.Unmarshal(body, request); err != nil {
		return nil, directoryRefusal("an erasure request that does not parse: %v", err)
	}
	if err := DirectoryCheckErasureRequest(request); err != nil {
		return nil, err
	}
	return request, nil
}

// The value of the top-level length-delimited field number in message's bytes, as they sit there, and how many times
// it appears; a message that does not split into fields is refused. The value is the last occurrence's, cloned.
func directoryFieldBytes(message []byte, number protowire.Number) ([]byte, int, error) {
	var value []byte
	count := 0
	for 0 < len(message) {
		fieldNumber, wireType, tagByteCount := protowire.ConsumeTag(message)
		if tagByteCount < 0 {
			return nil, 0, directoryRefusal("a field tag that does not parse")
		}
		valueByteCount := protowire.ConsumeFieldValue(fieldNumber, wireType, message[tagByteCount:])
		if valueByteCount < 0 {
			return nil, 0, directoryRefusal("field %d's value does not parse", fieldNumber)
		}
		if fieldNumber == number {
			if wireType != protowire.BytesType {
				return nil, 0, directoryRefusal("field %d of wire type %d", fieldNumber, wireType)
			}
			fieldValue, _ := protowire.ConsumeBytes(message[tagByteCount:])
			value = bytes.Clone(fieldValue)
			count += 1
		}
		message = message[tagByteCount+valueByteCount:]
	}
	return value, count, nil
}

// For RecordBodyValidate: whether body is a directory kind's, and its refusal by that kind's checks, wrapping
// ErrRecordBodyOverCap as record_body.go's callers look for.
func directoryValidateBody(kind RecordKind, body proto.Message) (bool, error) {
	var err error
	switch typed := body.(type) {
	case *protocol.Announcement:
		err = directoryCheckAnnounceEntry(typed, proto.Size(typed))
	case *protocol.DirectoryRequest:
		err = directoryCheckEntryByteCount(proto.Size(typed))
		if err == nil {
			err = DirectoryCheckRequest(typed)
		}
	case *protocol.DirectoryDecision:
		err = directoryCheckEntryByteCount(proto.Size(typed))
		if err == nil {
			err = DirectoryCheckDecision(typed)
		}
	case *protocol.DirectoryErasureRequest:
		err = directoryCheckEntryByteCount(proto.Size(typed))
		if err == nil {
			err = DirectoryCheckErasureRequest(typed)
		}
	default:
		return false, nil
	}
	if err != nil {
		return true, fmt.Errorf("%w: %s: %w", ErrRecordBodyOverCap, kind, err)
	}
	return true, nil
}

// For RecordBodyValidateStored: whether kind is a directory kind, and its stored body's refusal by that kind's decoder,
// as a reader takes it.
func directoryValidateStoredBody(kind RecordKind, stored []byte) (bool, error) {
	var err error
	switch kind {
	case RecordKindAnnounce:
		_, err = DirectoryDecodeAnnouncement(stored)
	case RecordKindRequest:
		_, err = DirectoryDecodeRequest(stored)
	case RecordKindDecision:
		_, err = DirectoryDecodeDecision(stored)
	case RecordKindErasureRequest:
		_, err = DirectoryDecodeErasureRequest(stored)
	default:
		return false, nil
	}
	if err != nil {
		return true, fmt.Errorf("%w: %s: %w", ErrRecordBodyOverCap, kind, err)
	}
	return true, nil
}

// Refuses an entry body past DirectoryEntryBodyMaxByteCount.
func directoryCheckEntryByteCount(byteCount int) error {
	if DirectoryEntryBodyMaxByteCount < byteCount {
		return directoryRefusal("an entry body of %d bytes", byteCount)
	}
	return nil
}

// For the record writer: refuses a directory kind's body, given as a message or as stored, whose fields §16.11's
// redaction row covers still hold what DirectoryRedact replaces, so a writer that skipped it seals nothing
// (directoryUnredactedField). Every other kind passes.
func directoryRefuseUnredacted(kind RecordKind, body proto.Message, stored []byte) error {
	switch kind {
	case RecordKindAnnounce, RecordKindRequest, RecordKindDecision, RecordKindErasureRequest:
	default:
		return nil
	}
	if body == nil {
		parsed, _ := kind.NewBody()
		if err := proto.Unmarshal(stored, parsed); err != nil {
			return directoryRefusal("a %s body that does not parse", kind)
		}
		body = parsed
	}
	if field, unredacted := directoryUnredactedField(body); unredacted {
		return directoryRefusal("%s holds a secret or a marker, which DirectoryRedact replaces before signing", field)
	}
	return nil
}
