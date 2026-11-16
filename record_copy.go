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
//	version   an Opening states the RecordEntry.version of the entry it was made from, an absent one reading 1
//	          (QD-864), so its reader knows what the bytes that open the commitment are: the kind's own message at 1,
//	          and at 2 the AgentSignedBody holding it (RECORD.md section 5.3's agent key row). An opener writes it
//	          only above 1, so a version-1 Opening is the bytes it always was. It is the opener's word, which nothing
//	          signs: the commitment binds the body whatever it says, and a wrong one only makes the body fail to read
//	          as its kind or its agent signature fail. KindBody reads a body by it, and nothing is inferred from how
//	          bytes happen to parse
//
// A copy names T's entry and opens it, so it never leaves the vault for T, and no projection or erasure of T touches it.
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// An opened body whose version this build does not read: one after 2, and 2 on a leg that links no agent subkeys.
// The body stands on its commitment and is shown generically, never parsed as its kind.
var ErrRecordOpeningVersion = errors.New("record opening version not read")

// One entry as a copy holds it: its header as stored, and the salt and body that open it.
type RecordOpened struct {
	// The header's Signed as stored.
	SignedBytes []byte
	Header      *StoredRecordHeader
	Salt        []byte
	// The bytes the header's commitment opens with, which Version says how to read.
	Body []byte
	// Opening.version: RecordEntry.version of the entry the opening was made from, 0 and 1 both reading 1. The
	// opener's word, which nothing signs.
	Version uint32
}

// What an Opening states for an entry of version: nothing for 1, so a version-1 Opening stays as it was written
// before the field.
func recordOpeningVersion(version uint32) uint32 {
	if version <= recordEntryVersion {
		return 0
	}
	return version
}

// The kind's own message the opened body holds, read as Version says and never by how the bytes parse (QD-864), with
// what a version-2 entry's agent signature came to under identityPublicKey, the header's writer's identity key as
// the caller admits it; a nil settings takes the defaults.
//
//	1      Body is the message, held to its kind's rules as the reader holds an opened body
//	2      Body is an AgentSignedBody, whose body is the message, held the same way; a signature that does not
//	       verify is no error but RecordAgentProvenanceInvalid, which the caller reports and never attributes
//	other  ErrRecordOpeningVersion, as is 2 on a leg that links no agent subkeys
//
// ErrRecordBodyInvalid for a header alone, for bytes that are not what the version says, and for a message that
// breaks its kind's rules. The message is the opened entry's own bytes at version 1: a caller copies before it keeps
// them.
func (self *RecordOpened) KindBody(identityPublicKey []byte, settings *SidecarAgentSubkeySettings) ([]byte, RecordAgentProvenance, error) {
	if self.Header == nil || len(self.Salt) == 0 {
		return nil, "", fmt.Errorf("%w: an opening of the header alone holds no body", ErrRecordBodyInvalid)
	}
	body := self.Body
	var provenance RecordAgentProvenance
	switch version := max(self.Version, recordEntryVersion); {
	case version == recordEntryVersion:
	case version == recordEntryVersionAgent && recordAgentBodyOpener != nil:
		if settings == nil {
			settings = DefaultSidecarAgentSubkeySettings()
		}
		inner, opened, err := recordAgentBodyOpener(&recordAgentBodyOpenArgs{
			header: self.Header, sealed: self.Body, identityPublicKey: identityPublicKey, settings: settings,
		})
		if err != nil {
			return nil, "", err
		}
		body, provenance = inner, opened
	default:
		return nil, "", fmt.Errorf("%w: version %d", ErrRecordOpeningVersion, version)
	}
	if err := RecordBodyValidateStored(self.Header.Kind(), body); err != nil {
		return nil, "", fmt.Errorf("%w: an opening's version-%d body: %v", ErrRecordBodyInvalid, max(self.Version, recordEntryVersion), err)
	}
	if body == nil {
		body = []byte{}
	}
	return body, provenance, nil
}

// A CopyBody of the entries given, each its sealed entry's Signed with the salt and body it was sealed with, and
// its entry's version where that is above 1.
func NewRecordCopyBody(entries []*RecordOpened) (*protocol.CopyBody, error) {
	if len(entries) == 0 || recordCopyEntryCount < len(entries) {
		return nil, fmt.Errorf("%w: a copy of %d entries", ErrRecordBodyOverCap, len(entries))
	}
	body := &protocol.CopyBody{}
	for _, entry := range entries {
		opening := &protocol.Opening{
			Header: bytes.Clone(entry.SignedBytes), Salt: bytes.Clone(entry.Salt), Body: bytes.Clone(entry.Body),
			Version: recordOpeningVersion(entry.Version),
		}
		if _, err := VerifyRecordOpening(opening); err != nil {
			return nil, err
		}
		body.Entries = append(body.Entries, opening)
	}
	return body, nil
}

// The entry an Opening holds: its header parsed from the Signed as stored, and, unless the Opening holds the header
// alone, its salt and body recomputing the header's body_commitment. ErrRecordBodyInvalid otherwise. The version is
// carried as stated, an absent one as 1, and nothing here reads the body by it: KindBody does.
func VerifyRecordOpening(opening *protocol.Opening) (*RecordOpened, error) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(opening.GetHeader(), signed); err != nil || signed.GetType() != uint32(bridge.SignedType_SIGNED_RECORD_HEADER) {
		return nil, fmt.Errorf("%w: an opening's header is no record header's Signed", ErrRecordBodyInvalid)
	}
	header, err := ParseStoredRecordHeader(signed.GetBody())
	if err != nil {
		return nil, fmt.Errorf("%w: an opening's header: %v", ErrRecordBodyInvalid, err)
	}
	opened := &RecordOpened{SignedBytes: bytes.Clone(opening.GetHeader()), Header: header, Version: max(opening.GetVersion(), recordEntryVersion)}
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
